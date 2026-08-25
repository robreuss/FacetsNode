package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/robreuss/FacetsNode/internal/relay"
)

// DeviceSyncMigrationStateReader is intentionally transaction-shaped. A
// production export must pass one repeatable-read or serializable transaction;
// a pool is rejected by the isolation check even though it implements these
// methods.
type DeviceSyncMigrationStateReader interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

// DeviceSyncMigrationStateImportTransaction is a caller-owned transaction.
// The caller must install target deployment authority in this same transaction
// after inserting logical state and before commit. InsertDeviceSyncMigrationState
// uses a savepoint so decode, digest, ordering, or insertion failures leave no
// partial logical state behind.
type DeviceSyncMigrationStateImportTransaction interface {
	DeviceSyncMigrationStateReader
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

// ExportDeviceSyncMigrationState is a low-level artifact seam, not a migration
// readiness or authority operation. It neither creates nor validates a source
// write fence and it persists no migration evidence. A trusted coordinator must
// call it while holding the exact scope lock and atomically persist/fence the
// resulting commitment in that same transaction. It writes two unbounded
// streams without materializing aggregate Space history; the caller
// owns/discards destination staging files on error. Active resumable uploads
// are rejected because this first slice does not transfer partial staging bytes.
func ExportDeviceSyncMigrationState(
	ctx context.Context,
	tx DeviceSyncMigrationStateReader,
	principalID uuid.UUID,
	stateDestination io.Writer,
	blobInventoryDestination io.Writer,
) (DeviceSyncMigrationArtifactDigests, error) {
	if principalID == uuid.Nil {
		return DeviceSyncMigrationArtifactDigests{}, errors.New("Device Sync migration principal is missing")
	}
	if stateDestination == nil || blobInventoryDestination == nil {
		return DeviceSyncMigrationArtifactDigests{}, errors.New("Device Sync migration destination is missing")
	}
	if err := ValidateDeviceSyncMigrationStateSchema(ctx, tx); err != nil {
		return DeviceSyncMigrationArtifactDigests{}, err
	}
	var isolation string
	if err := tx.QueryRow(ctx,
		"SELECT current_setting('transaction_isolation')",
	).Scan(&isolation); err != nil {
		return DeviceSyncMigrationArtifactDigests{}, fmt.Errorf("read Device Sync migration transaction isolation: %w", err)
	}
	if isolation != "repeatable read" && isolation != "serializable" {
		return DeviceSyncMigrationArtifactDigests{}, fmt.Errorf(
			"Device Sync migration export requires repeatable read or serializable isolation, got %q",
			isolation,
		)
	}
	var hasNonQuiescentUploadState bool
	if err := tx.QueryRow(ctx, `
		SELECT
			EXISTS (
				SELECT 1 FROM relay_blob_uploads
				WHERE tenant_id=$1 AND state='active'
			) OR EXISTS (
				SELECT 1 FROM relay_tenants
				WHERE tenant_id=$1 AND
					(reserved_blob_count <> 0 OR reserved_blob_byte_count <> 0)
			) OR EXISTS (
				SELECT 1 FROM relay_domains
				WHERE tenant_id=$1 AND
					(reserved_blob_count <> 0 OR reserved_blob_byte_count <> 0)
			)
	`, principalID).Scan(&hasNonQuiescentUploadState); err != nil {
		return DeviceSyncMigrationArtifactDigests{}, fmt.Errorf("inspect Device Sync partial blob uploads: %w", err)
	}
	if hasNonQuiescentUploadState {
		return DeviceSyncMigrationArtifactDigests{}, errors.New(
			"Device Sync migration cannot export while blob uploads or quota reservations are active",
		)
	}

	stateWriter := newDeviceSyncMigrationArtifactWriter(stateDestination)
	if err := writeDeviceSyncMigrationStateHeader(stateWriter.bodyWriter, principalID); err != nil {
		return DeviceSyncMigrationArtifactDigests{}, fmt.Errorf("write Device Sync migration header: %w", err)
	}
	for _, spec := range deviceSyncMigrationTableSpecs {
		if err := exportDeviceSyncMigrationTable(ctx, tx, principalID, stateWriter.bodyWriter, spec); err != nil {
			return DeviceSyncMigrationArtifactDigests{}, err
		}
	}
	stateDigest, err := stateWriter.finish()
	if err != nil {
		return DeviceSyncMigrationArtifactDigests{}, fmt.Errorf("finish Device Sync migration state artifact: %w", err)
	}
	blobDigest, blobByteCount, err := exportDeviceSyncMigrationBlobInventory(
		ctx, tx, principalID, blobInventoryDestination,
	)
	if err != nil {
		return DeviceSyncMigrationArtifactDigests{}, err
	}
	return DeviceSyncMigrationArtifactDigests{
		StateArtifactSHA256:    stateDigest,
		StateArtifactByteCount: stateWriter.byteCount(),
		BlobInventorySHA256:    blobDigest,
		BlobInventoryByteCount: blobByteCount,
		StateCommitment:        DeviceSyncMigrationStateCommitment(stateDigest, blobDigest),
	}, nil
}

func exportDeviceSyncMigrationTable(
	ctx context.Context,
	tx DeviceSyncMigrationStateReader,
	principalID uuid.UUID,
	writer io.Writer,
	spec deviceSyncMigrationTableSpec,
) error {
	predicate := deviceSyncMigrationScopePredicate(spec)
	var rowCount int64
	if err := tx.QueryRow(ctx,
		"SELECT COUNT(*) FROM "+quoteDeviceSyncMigrationIdentifier(spec.name)+" WHERE "+predicate,
		principalID,
	).Scan(&rowCount); err != nil {
		return fmt.Errorf("count Device Sync migration table %s: %w", spec.name, err)
	}
	if rowCount < 0 {
		return fmt.Errorf("Device Sync migration table %s returned a negative row count", spec.name)
	}
	if deviceSyncMigrationRequiresOneRow(spec.name) && rowCount != 1 {
		return fmt.Errorf("Device Sync migration table %s must contain exactly one principal row, found %d",
			spec.name, rowCount)
	}
	if err := writeDeviceSyncMigrationSectionHeader(writer, spec, uint64(rowCount)); err != nil {
		return fmt.Errorf("write Device Sync migration table %s header: %w", spec.name, err)
	}
	query := deviceSyncMigrationSelectQuery(spec, predicate)
	rows, err := tx.Query(ctx, query, principalID)
	if err != nil {
		return fmt.Errorf("query Device Sync migration table %s: %w", spec.name, err)
	}
	defer rows.Close()
	var previous []deviceSyncMigrationScalar
	var occurrence uint64
	var exported int64
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return err
		}
		values, destinations, err := newDeviceSyncMigrationScanRow(spec)
		if err != nil {
			return err
		}
		if err := rows.Scan(destinations...); err != nil {
			return fmt.Errorf("scan Device Sync migration table %s: %w", spec.name, err)
		}
		if err := values.resolve(spec); err != nil {
			return fmt.Errorf("resolve Device Sync migration table %s: %w", spec.name, err)
		}
		row := values.scalars()
		if err := validateDeviceSyncMigrationScope(spec, row, principalID); err != nil {
			return err
		}
		if err := rejectNonQuiescentDeviceSyncMigrationState(spec, row); err != nil {
			return err
		}
		if previous != nil {
			comparison := compareDeviceSyncMigrationRows(spec, previous, row)
			if comparison > 0 {
				return fmt.Errorf("Device Sync migration table %s query returned non-canonical row order", spec.name)
			}
			if comparison == 0 {
				if !spec.allowMultiplicity {
					return fmt.Errorf("Device Sync migration table %s returned a duplicate logical key", spec.name)
				}
				occurrence++
			} else {
				occurrence = 0
			}
		}
		if err := writeDeviceSyncMigrationRow(writer, spec, occurrence, row); err != nil {
			return fmt.Errorf("write Device Sync migration table %s row: %w", spec.name, err)
		}
		previous = cloneDeviceSyncMigrationRow(row)
		exported++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate Device Sync migration table %s: %w", spec.name, err)
	}
	if exported != rowCount {
		return fmt.Errorf("Device Sync migration table %s changed within snapshot: counted %d, read %d",
			spec.name, rowCount, exported)
	}
	return nil
}

func deviceSyncMigrationRequiresOneRow(tableName string) bool {
	return tableName == "device_sync_account_admissions" ||
		tableName == "relay_tenants" || tableName == "device_sync_principals"
}

func deviceSyncMigrationScopePredicate(spec deviceSyncMigrationTableSpec) string {
	column := quoteDeviceSyncMigrationIdentifier(spec.columns[spec.scopeColumnIndex].name)
	return column + "=$1"
}

func quoteDeviceSyncMigrationIdentifier(value string) string {
	return pgx.Identifier{value}.Sanitize()
}

func deviceSyncMigrationSelectQuery(
	spec deviceSyncMigrationTableSpec,
	predicate string,
) string {
	selected := make([]string, len(spec.columns))
	for index, column := range spec.columns {
		identifier := quoteDeviceSyncMigrationIdentifier(column.name)
		if column.virtual {
			selected[index] = column.sourceExpression + " AS " + identifier
			continue
		}
		switch column.kind {
		case deviceSyncMigrationScalarInt:
			selected[index] = identifier + "::bigint"
		case deviceSyncMigrationScalarCanonicalJSON:
			selected[index] = identifier + "::text"
		default:
			selected[index] = identifier
		}
	}
	ordered := make([]string, len(spec.keyColumnIndexes))
	for index, columnIndex := range spec.keyColumnIndexes {
		column := spec.columns[columnIndex]
		expression := quoteDeviceSyncMigrationIdentifier(column.name)
		if !column.virtual && (column.kind == deviceSyncMigrationScalarText ||
			column.kind == deviceSyncMigrationScalarCanonicalJSON) {
			expression += ` COLLATE "C"`
		}
		ordered[index] = expression + " ASC NULLS FIRST"
	}
	return "SELECT " + strings.Join(selected, ",") + " FROM " +
		quoteDeviceSyncMigrationIdentifier(spec.name) + " WHERE " + predicate +
		" ORDER BY " + strings.Join(ordered, ",")
}

type deviceSyncMigrationScanValue struct {
	kind       deviceSyncMigrationScalarKind
	nullable   bool
	uuidValue  *uuid.UUID
	textValue  *string
	intValue   *int64
	boolValue  *bool
	arrayValue *[]string
	bytesValue *[]byte
	resolved   deviceSyncMigrationScalar
}

type deviceSyncMigrationScanRow []deviceSyncMigrationScanValue

func newDeviceSyncMigrationScanRow(
	spec deviceSyncMigrationTableSpec,
) (deviceSyncMigrationScanRow, []any, error) {
	values := make(deviceSyncMigrationScanRow, len(spec.columns))
	destinations := make([]any, len(spec.columns))
	for index, column := range spec.columns {
		values[index].kind = column.kind
		values[index].nullable = column.nullable
		switch column.kind {
		case deviceSyncMigrationScalarUUID:
			destinations[index] = &values[index].uuidValue
		case deviceSyncMigrationScalarText, deviceSyncMigrationScalarCanonicalJSON:
			destinations[index] = &values[index].textValue
		case deviceSyncMigrationScalarInt:
			destinations[index] = &values[index].intValue
		case deviceSyncMigrationScalarBool:
			destinations[index] = &values[index].boolValue
		case deviceSyncMigrationScalarTextArray:
			destinations[index] = &values[index].arrayValue
		case deviceSyncMigrationScalarBytes:
			destinations[index] = &values[index].bytesValue
		default:
			return nil, nil, fmt.Errorf("unsupported Device Sync migration column kind %d", column.kind)
		}
	}
	return values, destinations, nil
}

func (values deviceSyncMigrationScanRow) resolve(spec deviceSyncMigrationTableSpec) error {
	for index := range values {
		value := &values[index]
		column := spec.columns[index]
		value.resolved.kind = value.kind
		isNull := false
		switch value.kind {
		case deviceSyncMigrationScalarUUID:
			isNull = value.uuidValue == nil
			if !isNull {
				value.resolved.uuidValue = *value.uuidValue
			}
		case deviceSyncMigrationScalarText:
			isNull = value.textValue == nil
			if !isNull {
				value.resolved.textValue = *value.textValue
			}
		case deviceSyncMigrationScalarCanonicalJSON:
			isNull = value.textValue == nil
			if !isNull {
				canonical, err := canonicalizeDeviceSyncMigrationJSON([]byte(*value.textValue))
				if err != nil {
					return fmt.Errorf("%s.%s: %w", spec.name, column.name, err)
				}
				value.resolved.textValue = canonical
			}
		case deviceSyncMigrationScalarInt:
			isNull = value.intValue == nil
			if !isNull {
				value.resolved.intValue = *value.intValue
			}
		case deviceSyncMigrationScalarBool:
			isNull = value.boolValue == nil
			if !isNull {
				value.resolved.boolValue = *value.boolValue
			}
		case deviceSyncMigrationScalarTextArray:
			isNull = value.arrayValue == nil
			if !isNull {
				value.resolved.arrayValue = append([]string(nil), (*value.arrayValue)...)
			}
		case deviceSyncMigrationScalarBytes:
			isNull = value.bytesValue == nil
			if !isNull {
				value.resolved.bytesValue = append([]byte(nil), (*value.bytesValue)...)
			}
		}
		if isNull && !value.nullable {
			return fmt.Errorf("%s.%s is unexpectedly null", spec.name, column.name)
		}
		value.resolved.isNull = isNull
	}
	return nil
}

func (values deviceSyncMigrationScanRow) scalars() []deviceSyncMigrationScalar {
	result := make([]deviceSyncMigrationScalar, len(values))
	for index := range values {
		result[index] = values[index].resolved
	}
	return result
}

func validateDeviceSyncMigrationScope(
	spec deviceSyncMigrationTableSpec,
	row []deviceSyncMigrationScalar,
	principalID uuid.UUID,
) error {
	scope := row[spec.scopeColumnIndex]
	if scope.isNull || scope.kind != deviceSyncMigrationScalarUUID || scope.uuidValue != principalID {
		return fmt.Errorf("Device Sync migration table %s contains a row outside principal %s",
			spec.name, principalID)
	}
	return nil
}

func rejectNonQuiescentDeviceSyncMigrationState(
	spec deviceSyncMigrationTableSpec,
	row []deviceSyncMigrationScalar,
) error {
	for index, column := range spec.columns {
		if spec.name == "relay_blob_uploads" && column.name == "state" &&
			!row[index].isNull && row[index].textValue == "active" {
			return errors.New("Device Sync migration artifact contains an active partial blob upload")
		}
		if (spec.name == "relay_tenants" || spec.name == "relay_domains") &&
			(column.name == "reserved_blob_count" || column.name == "reserved_blob_byte_count") &&
			(!row[index].isNull && row[index].intValue != 0) {
			return errors.New("Device Sync migration artifact contains active blob quota reservations")
		}
	}
	return nil
}

func exportDeviceSyncMigrationBlobInventory(
	ctx context.Context,
	tx DeviceSyncMigrationStateReader,
	principalID uuid.UUID,
	destination io.Writer,
) (DeviceSyncMigrationDigest, int64, error) {
	var rowCount int64
	if err := tx.QueryRow(ctx,
		"SELECT COUNT(*) FROM relay_blobs WHERE tenant_id=$1", principalID,
	).Scan(&rowCount); err != nil {
		return DeviceSyncMigrationDigest{}, 0, fmt.Errorf("count Device Sync migration blob inventory: %w", err)
	}
	if rowCount < 0 {
		return DeviceSyncMigrationDigest{}, 0, errors.New("Device Sync migration blob inventory has negative count")
	}
	artifactWriter := newDeviceSyncMigrationArtifactWriter(destination)
	if err := writeMigrationBytes(artifactWriter.bodyWriter, deviceSyncMigrationBlobMagic); err != nil {
		return DeviceSyncMigrationDigest{}, 0, err
	}
	if err := writeMigrationUint16(artifactWriter.bodyWriter, deviceSyncMigrationArtifactVersion); err != nil {
		return DeviceSyncMigrationDigest{}, 0, err
	}
	if err := writeMigrationBytes(artifactWriter.bodyWriter, principalID[:]); err != nil {
		return DeviceSyncMigrationDigest{}, 0, err
	}
	if err := writeMigrationUint64(artifactWriter.bodyWriter, uint64(rowCount)); err != nil {
		return DeviceSyncMigrationDigest{}, 0, err
	}
	rows, err := tx.Query(ctx, `
		SELECT domain_id, blob_id, byte_count::bigint
		FROM relay_blobs WHERE tenant_id=$1
		ORDER BY domain_id ASC, blob_id COLLATE "C" ASC
	`, principalID)
	if err != nil {
		return DeviceSyncMigrationDigest{}, 0, fmt.Errorf("query Device Sync migration blob inventory: %w", err)
	}
	defer rows.Close()
	var previous *DeviceSyncMigrationBlobInventoryEntry
	var exported int64
	for rows.Next() {
		var entry DeviceSyncMigrationBlobInventoryEntry
		if err := rows.Scan(&entry.DomainID, &entry.BlobID, &entry.ByteCount); err != nil {
			return DeviceSyncMigrationDigest{}, 0, fmt.Errorf("scan Device Sync migration blob inventory: %w", err)
		}
		if err := validateDeviceSyncMigrationBlobEntry(entry); err != nil {
			return DeviceSyncMigrationDigest{}, 0, err
		}
		if previous != nil && compareDeviceSyncMigrationBlobEntries(*previous, entry) >= 0 {
			return DeviceSyncMigrationDigest{}, 0, errors.New("Device Sync migration blob inventory is duplicate or unordered")
		}
		if err := writeMigrationBytes(artifactWriter.bodyWriter, entry.DomainID[:]); err != nil {
			return DeviceSyncMigrationDigest{}, 0, err
		}
		if err := writeMigrationString(artifactWriter.bodyWriter, entry.BlobID); err != nil {
			return DeviceSyncMigrationDigest{}, 0, err
		}
		if err := writeMigrationUint64(artifactWriter.bodyWriter, uint64(entry.ByteCount)); err != nil {
			return DeviceSyncMigrationDigest{}, 0, err
		}
		entryCopy := entry
		previous = &entryCopy
		exported++
	}
	if err := rows.Err(); err != nil {
		return DeviceSyncMigrationDigest{}, 0, fmt.Errorf("iterate Device Sync migration blob inventory: %w", err)
	}
	if exported != rowCount {
		return DeviceSyncMigrationDigest{}, 0, fmt.Errorf(
			"Device Sync migration blob inventory changed within snapshot: counted %d, read %d",
			rowCount, exported,
		)
	}
	digest, err := artifactWriter.finish()
	if err != nil {
		return DeviceSyncMigrationDigest{}, 0, fmt.Errorf("finish Device Sync migration blob inventory: %w", err)
	}
	return digest, artifactWriter.byteCount(), nil
}

func validateDeviceSyncMigrationBlobEntry(entry DeviceSyncMigrationBlobInventoryEntry) error {
	if entry.DomainID == uuid.Nil || entry.ByteCount < 0 {
		return errors.New("Device Sync migration blob inventory entry is invalid")
	}
	if err := relay.ValidateBlobID(entry.BlobID); err != nil {
		return fmt.Errorf("Device Sync migration blob inventory ID: %w", err)
	}
	return nil
}

func compareDeviceSyncMigrationBlobEntries(
	left DeviceSyncMigrationBlobInventoryEntry,
	right DeviceSyncMigrationBlobInventoryEntry,
) int {
	if comparison := bytes.Compare(left.DomainID[:], right.DomainID[:]); comparison != 0 {
		return comparison
	}
	return strings.Compare(left.BlobID, right.BlobID)
}

// ValidateDeviceSyncMigrationStateArtifact performs strict canonical schema,
// ordering, multiplicity, body-checksum, and expected-transfer-digest checks.
func ValidateDeviceSyncMigrationStateArtifact(
	ctx context.Context,
	source io.ReadSeeker,
	expectedPrincipalID uuid.UUID,
	expectedSHA256 DeviceSyncMigrationDigest,
) error {
	if err := verifyDeviceSyncMigrationTransferDigest(ctx, source, expectedSHA256); err != nil {
		return err
	}
	return decodeDeviceSyncMigrationState(
		ctx, source, expectedPrincipalID, expectedSHA256, nil,
	)
}

// ValidateDeviceSyncMigrationBlobInventory validates a blob inventory without
// retaining it in memory. A future coordinator can reopen the staged file to
// walk entries after this gate.
func ValidateDeviceSyncMigrationBlobInventory(
	ctx context.Context,
	source io.ReadSeeker,
	expectedPrincipalID uuid.UUID,
	expectedSHA256 DeviceSyncMigrationDigest,
) error {
	if err := verifyDeviceSyncMigrationTransferDigest(ctx, source, expectedSHA256); err != nil {
		return err
	}
	reader := newDeviceSyncMigrationArtifactReader(source)
	if err := expectMigrationBytes(reader.bodyReader, deviceSyncMigrationBlobMagic, "blob inventory magic"); err != nil {
		return err
	}
	version, err := readMigrationUint16(reader.bodyReader)
	if err != nil || version != deviceSyncMigrationArtifactVersion {
		return fmt.Errorf("Device Sync migration blob inventory version %d is unsupported: %w", version, err)
	}
	var principalID uuid.UUID
	if _, err := io.ReadFull(reader.bodyReader, principalID[:]); err != nil {
		return err
	}
	if principalID != expectedPrincipalID {
		return fmt.Errorf("Device Sync migration blob inventory principal %s does not match expected %s",
			principalID, expectedPrincipalID)
	}
	count, err := readMigrationUint64(reader.bodyReader)
	if err != nil {
		return err
	}
	var previous *DeviceSyncMigrationBlobInventoryEntry
	for index := uint64(0); index < count; index++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		var entry DeviceSyncMigrationBlobInventoryEntry
		if _, err := io.ReadFull(reader.bodyReader, entry.DomainID[:]); err != nil {
			return err
		}
		entry.BlobID, err = readMigrationString(reader.bodyReader)
		if err != nil {
			return err
		}
		encodedByteCount, err := readMigrationUint64(reader.bodyReader)
		if err != nil {
			return err
		}
		if encodedByteCount > uint64(mathMaxInt64) {
			return errors.New("Device Sync migration blob inventory byte count overflows int64")
		}
		entry.ByteCount = int64(encodedByteCount)
		if err := validateDeviceSyncMigrationBlobEntry(entry); err != nil {
			return err
		}
		if previous != nil && compareDeviceSyncMigrationBlobEntries(*previous, entry) >= 0 {
			return errors.New("Device Sync migration blob inventory is duplicate or unordered")
		}
		entryCopy := entry
		previous = &entryCopy
	}
	return reader.finish(expectedSHA256)
}

const mathMaxInt64 = int64(^uint64(0) >> 1)

func decodeDeviceSyncMigrationState(
	ctx context.Context,
	source io.Reader,
	expectedPrincipalID uuid.UUID,
	expectedSHA256 DeviceSyncMigrationDigest,
	consume func(deviceSyncMigrationTableSpec, []deviceSyncMigrationScalar) error,
) error {
	if source == nil || expectedPrincipalID == uuid.Nil {
		return errors.New("Device Sync migration artifact input is invalid")
	}
	reader := newDeviceSyncMigrationArtifactReader(source)
	if err := expectMigrationBytes(reader.bodyReader, deviceSyncMigrationStateMagic, "state magic"); err != nil {
		return err
	}
	version, err := readMigrationUint16(reader.bodyReader)
	if err != nil || version != deviceSyncMigrationArtifactVersion {
		return fmt.Errorf("Device Sync migration state version %d is unsupported: %w", version, err)
	}
	var principalID uuid.UUID
	if _, err := io.ReadFull(reader.bodyReader, principalID[:]); err != nil {
		return err
	}
	if principalID != expectedPrincipalID {
		return fmt.Errorf("Device Sync migration state principal %s does not match expected %s",
			principalID, expectedPrincipalID)
	}
	sectionCount, err := readMigrationUint32(reader.bodyReader)
	if err != nil {
		return err
	}
	if int(sectionCount) != len(deviceSyncMigrationTableSpecs) {
		return fmt.Errorf("Device Sync migration state has %d sections, expected %d",
			sectionCount, len(deviceSyncMigrationTableSpecs))
	}
	for _, spec := range deviceSyncMigrationTableSpecs {
		rowCount, err := readAndValidateDeviceSyncMigrationSectionHeader(reader.bodyReader, spec)
		if err != nil {
			return err
		}
		if deviceSyncMigrationRequiresOneRow(spec.name) && rowCount != 1 {
			return fmt.Errorf("Device Sync migration table %s must have exactly one row", spec.name)
		}
		var previous []deviceSyncMigrationScalar
		var expectedOccurrence uint64
		for rowIndex := uint64(0); rowIndex < rowCount; rowIndex++ {
			if err := ctx.Err(); err != nil {
				return err
			}
			occurrence, err := readMigrationUint64(reader.bodyReader)
			if err != nil {
				return err
			}
			row := make([]deviceSyncMigrationScalar, len(spec.columns))
			for columnIndex, column := range spec.columns {
				row[columnIndex], err = readDeviceSyncMigrationScalar(reader.bodyReader, column)
				if err != nil {
					return fmt.Errorf("decode Device Sync migration %s.%s: %w", spec.name, column.name, err)
				}
			}
			if err := validateDeviceSyncMigrationScope(spec, row, expectedPrincipalID); err != nil {
				return err
			}
			if err := rejectNonQuiescentDeviceSyncMigrationState(spec, row); err != nil {
				return err
			}
			if spec.name == "relay_audit_events" {
				ordinal := row[spec.keyColumnIndexes[0]]
				if ordinal.isNull || ordinal.intValue != int64(rowIndex) {
					return fmt.Errorf("Device Sync migration audit ordinal %d is not canonical", ordinal.intValue)
				}
			}
			if previous == nil {
				expectedOccurrence = 0
			} else {
				comparison := compareDeviceSyncMigrationRows(spec, previous, row)
				if comparison > 0 {
					return fmt.Errorf("Device Sync migration table %s rows are not canonical", spec.name)
				}
				if comparison == 0 {
					if !spec.allowMultiplicity {
						return fmt.Errorf("Device Sync migration table %s has duplicate logical key", spec.name)
					}
					expectedOccurrence++
				} else {
					expectedOccurrence = 0
				}
			}
			if occurrence != expectedOccurrence {
				return fmt.Errorf("Device Sync migration table %s occurrence %d, expected %d",
					spec.name, occurrence, expectedOccurrence)
			}
			if consume != nil {
				if err := consume(spec, row); err != nil {
					return err
				}
			}
			previous = cloneDeviceSyncMigrationRow(row)
		}
	}
	return reader.finish(expectedSHA256)
}

func expectMigrationBytes(reader io.Reader, expected []byte, label string) error {
	actual := make([]byte, len(expected))
	if _, err := io.ReadFull(reader, actual); err != nil {
		return fmt.Errorf("read Device Sync migration %s: %w", label, err)
	}
	if !bytes.Equal(actual, expected) {
		return fmt.Errorf("Device Sync migration %s is invalid", label)
	}
	return nil
}

func readAndValidateDeviceSyncMigrationSectionHeader(
	reader io.Reader,
	spec deviceSyncMigrationTableSpec,
) (uint64, error) {
	tableName, err := readMigrationString(reader)
	if err != nil || tableName != spec.name {
		return 0, fmt.Errorf("Device Sync migration section %q, expected %q: %w", tableName, spec.name, err)
	}
	columnCount, err := readMigrationUint16(reader)
	if err != nil || int(columnCount) != len(spec.columns) {
		return 0, fmt.Errorf("Device Sync migration table %s column count %d is invalid: %w",
			spec.name, columnCount, err)
	}
	for _, expected := range spec.columns {
		name, err := readMigrationString(reader)
		if err != nil || name != expected.name {
			return 0, fmt.Errorf("Device Sync migration table %s column %q, expected %q: %w",
				spec.name, name, expected.name, err)
		}
		var kind [1]byte
		if _, err := io.ReadFull(reader, kind[:]); err != nil || deviceSyncMigrationScalarKind(kind[0]) != expected.kind {
			return 0, fmt.Errorf("Device Sync migration table %s column %s kind is invalid: %w",
				spec.name, expected.name, err)
		}
		databaseType, err := readMigrationString(reader)
		if err != nil || databaseType != expected.databaseType {
			return 0, fmt.Errorf("Device Sync migration table %s column %s database type %q is invalid: %w",
				spec.name, expected.name, databaseType, err)
		}
		var nullable [1]byte
		if _, err := io.ReadFull(reader, nullable[:]); err != nil || nullable[0] > 1 || (nullable[0] == 1) != expected.nullable {
			return 0, fmt.Errorf("Device Sync migration table %s column %s nullability is invalid: %w",
				spec.name, expected.name, err)
		}
	}
	keyCount, err := readMigrationUint16(reader)
	if err != nil || int(keyCount) != len(spec.keyColumnIndexes) {
		return 0, fmt.Errorf("Device Sync migration table %s key count is invalid: %w", spec.name, err)
	}
	for _, expected := range spec.keyColumnIndexes {
		index, err := readMigrationUint16(reader)
		if err != nil || int(index) != expected {
			return 0, fmt.Errorf("Device Sync migration table %s key index is invalid: %w", spec.name, err)
		}
	}
	var multiplicity [1]byte
	if _, err := io.ReadFull(reader, multiplicity[:]); err != nil || multiplicity[0] > 1 ||
		(multiplicity[0] == 1) != spec.allowMultiplicity {
		return 0, fmt.Errorf("Device Sync migration table %s multiplicity is invalid: %w", spec.name, err)
	}
	rowCount, err := readMigrationUint64(reader)
	if err != nil {
		return 0, err
	}
	return rowCount, nil
}

// InsertDeviceSyncMigrationState is likewise a low-level artifact seam, not a
// target activation operation. It strictly validates and inserts an exact
// logical-state artifact. The caller must compare/copy the separately validated
// blob inventory and create the excluded target enforcement/import evidence in
// the same transaction before commit. This function never reconstructs or
// activates deployment authority from logical state.
func InsertDeviceSyncMigrationState(
	ctx context.Context,
	tx DeviceSyncMigrationStateImportTransaction,
	expectedPrincipalID uuid.UUID,
	expectedSHA256 DeviceSyncMigrationDigest,
	source io.ReadSeeker,
) (returnErr error) {
	// Authenticate the staged stream before parsing attacker-controlled lengths
	// or issuing any database statement. Requiring a seekable staged artifact
	// keeps this two-pass gate disk-streaming rather than all-in-memory.
	if err := verifyDeviceSyncMigrationTransferDigest(ctx, source, expectedSHA256); err != nil {
		return err
	}
	if err := ValidateDeviceSyncMigrationStateSchema(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, "SAVEPOINT facets_device_sync_migration_state_insert"); err != nil {
		return fmt.Errorf("create Device Sync migration state savepoint: %w", err)
	}
	rollback := func(cause error) error {
		cleanupContext, cancelCleanup := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancelCleanup()
		_, rollbackErr := tx.Exec(cleanupContext, "ROLLBACK TO SAVEPOINT facets_device_sync_migration_state_insert")
		_, releaseErr := tx.Exec(cleanupContext, "RELEASE SAVEPOINT facets_device_sync_migration_state_insert")
		if rollbackErr != nil {
			return errors.Join(cause, fmt.Errorf("rollback Device Sync migration state: %w", rollbackErr))
		}
		if releaseErr != nil {
			return errors.Join(cause, fmt.Errorf("release Device Sync migration state rollback: %w", releaseErr))
		}
		return cause
	}
	if _, err := tx.Exec(ctx, "SET CONSTRAINTS ALL DEFERRED"); err != nil {
		return rollback(fmt.Errorf("defer Device Sync migration constraints: %w", err))
	}
	for _, spec := range deviceSyncMigrationTableSpecs {
		var exists bool
		if err := tx.QueryRow(ctx,
			"SELECT EXISTS (SELECT 1 FROM "+quoteDeviceSyncMigrationIdentifier(spec.name)+
				" WHERE "+deviceSyncMigrationScopePredicate(spec)+")",
			expectedPrincipalID,
		).Scan(&exists); err != nil {
			return rollback(fmt.Errorf("inspect Device Sync migration target table %s: %w", spec.name, err))
		}
		if exists {
			return rollback(fmt.Errorf("Device Sync migration target table %s already contains principal state", spec.name))
		}
	}
	insertQueries := make(map[string]string, len(deviceSyncMigrationTableSpecs))
	err := decodeDeviceSyncMigrationState(
		ctx, source, expectedPrincipalID, expectedSHA256,
		func(spec deviceSyncMigrationTableSpec, row []deviceSyncMigrationScalar) error {
			query, exists := insertQueries[spec.name]
			if !exists {
				query = deviceSyncMigrationInsertQuery(spec)
				insertQueries[spec.name] = query
			}
			arguments := make([]any, 0, len(row))
			for index, value := range row {
				if !spec.columns[index].virtual {
					arguments = append(arguments, deviceSyncMigrationScalarArgument(value))
				}
			}
			tag, err := tx.Exec(ctx, query, arguments...)
			if err != nil {
				return fmt.Errorf("insert Device Sync migration table %s: %w", spec.name, err)
			}
			if tag.RowsAffected() != 1 {
				return fmt.Errorf("insert Device Sync migration table %s affected %d rows",
					spec.name, tag.RowsAffected())
			}
			return nil
		},
	)
	if err != nil {
		return rollback(err)
	}
	if _, err := tx.Exec(ctx, "RELEASE SAVEPOINT facets_device_sync_migration_state_insert"); err != nil {
		return fmt.Errorf("release Device Sync migration state savepoint: %w", err)
	}
	return nil
}

func verifyDeviceSyncMigrationTransferDigest(
	ctx context.Context,
	source io.ReadSeeker,
	expected DeviceSyncMigrationDigest,
) error {
	if source == nil {
		return errors.New("Device Sync migration staged artifact is missing")
	}
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek Device Sync migration staged artifact: %w", err)
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, deviceSyncMigrationContextReader{ctx: ctx, reader: source}); err != nil {
		return fmt.Errorf("hash Device Sync migration staged artifact: %w", err)
	}
	var actual DeviceSyncMigrationDigest
	copy(actual[:], hasher.Sum(nil))
	if actual != expected {
		return fmt.Errorf("Device Sync migration artifact SHA-256 %s does not match expected %s",
			actual, expected)
	}
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind Device Sync migration staged artifact: %w", err)
	}
	return nil
}

type deviceSyncMigrationContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader deviceSyncMigrationContextReader) Read(destination []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(destination)
}

func deviceSyncMigrationInsertQuery(spec deviceSyncMigrationTableSpec) string {
	columns := make([]string, 0, len(spec.columns))
	parameters := make([]string, 0, len(spec.columns))
	for _, column := range spec.columns {
		if column.virtual {
			continue
		}
		columns = append(columns, quoteDeviceSyncMigrationIdentifier(column.name))
		parameters = append(parameters, fmt.Sprintf("$%d::%s", len(parameters)+1, column.databaseType))
	}
	return "INSERT INTO " + quoteDeviceSyncMigrationIdentifier(spec.name) + " (" +
		strings.Join(columns, ",") + ") VALUES (" + strings.Join(parameters, ",") + ")"
}

func deviceSyncMigrationScalarArgument(value deviceSyncMigrationScalar) any {
	if value.isNull {
		return nil
	}
	switch value.kind {
	case deviceSyncMigrationScalarUUID:
		return value.uuidValue
	case deviceSyncMigrationScalarText, deviceSyncMigrationScalarCanonicalJSON:
		return value.textValue
	case deviceSyncMigrationScalarInt:
		return value.intValue
	case deviceSyncMigrationScalarBool:
		return value.boolValue
	case deviceSyncMigrationScalarTextArray:
		return value.arrayValue
	case deviceSyncMigrationScalarBytes:
		return value.bytesValue
	default:
		return nil
	}
}

type deviceSyncMigrationSchemaColumn struct {
	name         string
	databaseType string
	nullable     bool
}

// ValidateDeviceSyncMigrationStateSchema is the fail-closed inventory gate.
// Every relay_/device_sync_ table must be either included or explicitly
// authority/bookkeeping-excluded, and every non-storage-metadata column of an
// included table must match the canonical spec.
func ValidateDeviceSyncMigrationStateSchema(
	ctx context.Context,
	reader DeviceSyncMigrationStateReader,
) error {
	rows, err := reader.Query(ctx, `
		SELECT table_name, column_name, udt_name, is_nullable
		FROM information_schema.columns
		WHERE table_schema=current_schema()
		  AND (table_name LIKE 'relay\_%' ESCAPE '\' OR
		       table_name LIKE 'device\_sync\_%' ESCAPE '\')
		ORDER BY table_name, ordinal_position
	`)
	if err != nil {
		return fmt.Errorf("inspect Device Sync migration schema: %w", err)
	}
	defer rows.Close()
	actual := make(map[string][]deviceSyncMigrationSchemaColumn)
	for rows.Next() {
		var tableName, columnName, databaseType, nullableText string
		if err := rows.Scan(&tableName, &columnName, &databaseType, &nullableText); err != nil {
			return fmt.Errorf("scan Device Sync migration schema: %w", err)
		}
		actual[tableName] = append(actual[tableName], deviceSyncMigrationSchemaColumn{
			name: columnName, databaseType: databaseType, nullable: nullableText == "YES",
		})
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate Device Sync migration schema: %w", err)
	}
	return validateDeviceSyncMigrationSchemaInventory(actual)
}

func validateDeviceSyncMigrationSchemaInventory(
	actual map[string][]deviceSyncMigrationSchemaColumn,
) error {
	expectedTables := make(map[string]deviceSyncMigrationTableSpec, len(deviceSyncMigrationTableSpecs))
	for _, spec := range deviceSyncMigrationTableSpecs {
		expectedTables[spec.name] = spec
	}
	for tableName := range actual {
		if _, included := expectedTables[tableName]; included {
			continue
		}
		if _, excluded := deviceSyncMigrationExcludedTables[tableName]; excluded {
			continue
		}
		return fmt.Errorf("Device Sync migration schema table %s is unclassified", tableName)
	}
	for tableName := range deviceSyncMigrationExcludedTables {
		if _, exists := actual[tableName]; !exists {
			return fmt.Errorf("Device Sync migration excluded table %s is missing", tableName)
		}
	}
	for _, spec := range deviceSyncMigrationTableSpecs {
		columns, exists := actual[spec.name]
		if !exists {
			return fmt.Errorf("Device Sync migration table %s is missing", spec.name)
		}
		expected := make(map[string]deviceSyncMigrationColumnSpec, len(spec.columns))
		for _, column := range spec.columns {
			if column.virtual {
				continue
			}
			expected[column.name] = column
		}
		seen := make([]string, 0, len(columns))
		for _, column := range columns {
			if omitted, exists := deviceSyncMigrationOmittedColumns[spec.name][column.name]; exists {
				if column.databaseType != omitted || column.nullable {
					return fmt.Errorf("Device Sync migration omitted column %s.%s has changed type",
						spec.name, column.name)
				}
				continue
			}
			expectedColumn, exists := expected[column.name]
			if !exists {
				return fmt.Errorf("Device Sync migration table %s has unclassified column %s",
					spec.name, column.name)
			}
			if column.databaseType != expectedColumn.databaseType || column.nullable != expectedColumn.nullable {
				return fmt.Errorf("Device Sync migration column %s.%s type/nullability changed",
					spec.name, column.name)
			}
			seen = append(seen, column.name)
		}
		for columnName := range expected {
			if !slices.Contains(seen, columnName) {
				return fmt.Errorf("Device Sync migration column %s.%s is missing", spec.name, columnName)
			}
		}
	}
	return nil
}
