package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"testing"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/relay"
)

type deviceSyncMigrationTestRow struct {
	values     []deviceSyncMigrationScalar
	occurrence uint64
}

func TestDeviceSyncMigrationStateArtifactIsDeterministicAndStrict(t *testing.T) {
	principalID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	first, firstDigest := encodeDeviceSyncMigrationTestState(t, principalID, nil)
	second, secondDigest := encodeDeviceSyncMigrationTestState(t, principalID, nil)
	if !bytes.Equal(first, second) || firstDigest != secondDigest {
		t.Fatal("identical logical state did not produce identical artifact bytes")
	}
	if err := ValidateDeviceSyncMigrationStateArtifact(
		context.Background(), bytes.NewReader(first), principalID, firstDigest,
	); err != nil {
		t.Fatal(err)
	}

	tampered := append([]byte(nil), first...)
	tampered[len(deviceSyncMigrationStateMagic)+2] ^= 0x01
	if err := ValidateDeviceSyncMigrationStateArtifact(
		context.Background(), bytes.NewReader(tampered), principalID, firstDigest,
	); err == nil {
		t.Fatal("tampered artifact was accepted")
	}

	otherRows := map[string][]deviceSyncMigrationTestRow{
		"device_sync_account_admissions": {{
			values: deviceSyncMigrationTestRowValues(
				t, deviceSyncMigrationSpec(t, "device_sync_account_admissions"), principalID,
				map[string]deviceSyncMigrationScalar{
					"entitlement_plan_id": migrationTestText("different"),
				},
			),
		}},
	}
	changed, changedDigest := encodeDeviceSyncMigrationTestState(t, principalID, otherRows)
	if changedDigest == firstDigest {
		t.Fatal("changed artifact retained its transfer digest")
	}
	if err := ValidateDeviceSyncMigrationStateArtifact(
		context.Background(), bytes.NewReader(changed), principalID, firstDigest,
	); err == nil {
		t.Fatal("self-consistent artifact with the wrong expected transfer digest was accepted")
	}
}

func TestDeviceSyncMigrationStateRejectsOrderDuplicatesAndActiveUploads(t *testing.T) {
	principalID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	deviceSpec := deviceSyncMigrationSpec(t, "device_sync_devices")
	deviceA := uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	deviceB := uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
	rowA := deviceSyncMigrationTestRowValues(t, deviceSpec, principalID,
		map[string]deviceSyncMigrationScalar{"device_id": migrationTestUUID(deviceA)})
	rowB := deviceSyncMigrationTestRowValues(t, deviceSpec, principalID,
		map[string]deviceSyncMigrationScalar{"device_id": migrationTestUUID(deviceB)})

	unordered, unorderedDigest := encodeDeviceSyncMigrationTestState(t, principalID,
		map[string][]deviceSyncMigrationTestRow{
			"device_sync_devices": {{values: rowB}, {values: rowA}},
		})
	if err := ValidateDeviceSyncMigrationStateArtifact(
		context.Background(), bytes.NewReader(unordered), principalID, unorderedDigest,
	); err == nil {
		t.Fatal("unordered logical keys were accepted")
	}

	duplicate, duplicateDigest := encodeDeviceSyncMigrationTestState(t, principalID,
		map[string][]deviceSyncMigrationTestRow{
			"device_sync_devices": {{values: rowA}, {values: rowA}},
		})
	if err := ValidateDeviceSyncMigrationStateArtifact(
		context.Background(), bytes.NewReader(duplicate), principalID, duplicateDigest,
	); err == nil {
		t.Fatal("duplicate logical key was accepted")
	}

	uploadSpec := deviceSyncMigrationSpec(t, "relay_blob_uploads")
	activeUpload := deviceSyncMigrationTestRowValues(t, uploadSpec, principalID,
		map[string]deviceSyncMigrationScalar{"state": migrationTestText("active")})
	active, activeDigest := encodeDeviceSyncMigrationTestState(t, principalID,
		map[string][]deviceSyncMigrationTestRow{
			"relay_blob_uploads": {{values: activeUpload}},
		})
	if err := ValidateDeviceSyncMigrationStateArtifact(
		context.Background(), bytes.NewReader(active), principalID, activeDigest,
	); err == nil {
		t.Fatal("active partial upload was accepted")
	}

	tenantSpec := deviceSyncMigrationSpec(t, "relay_tenants")
	reservedTenant := deviceSyncMigrationTestRowValues(t, tenantSpec, principalID,
		map[string]deviceSyncMigrationScalar{
			"reserved_blob_count": {kind: deviceSyncMigrationScalarInt, intValue: 1},
		})
	reserved, reservedDigest := encodeDeviceSyncMigrationTestState(t, principalID,
		map[string][]deviceSyncMigrationTestRow{
			"relay_tenants": {{values: reservedTenant}},
		})
	if err := ValidateDeviceSyncMigrationStateArtifact(
		context.Background(), bytes.NewReader(reserved), principalID, reservedDigest,
	); err == nil {
		t.Fatal("active blob quota reservation was accepted")
	}
}

func TestDeviceSyncMigrationAuditTimelineOrdinalIsCanonical(t *testing.T) {
	principalID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	auditSpec := deviceSyncMigrationSpec(t, "relay_audit_events")
	auditRow0 := deviceSyncMigrationTestRowValues(t, auditSpec, principalID,
		map[string]deviceSyncMigrationScalar{
			"source_event_ordinal": {kind: deviceSyncMigrationScalarInt, intValue: 0},
		})
	auditRow1 := deviceSyncMigrationTestRowValues(t, auditSpec, principalID,
		map[string]deviceSyncMigrationScalar{
			"source_event_ordinal": {kind: deviceSyncMigrationScalarInt, intValue: 1},
		})
	artifact, digest := encodeDeviceSyncMigrationTestState(t, principalID,
		map[string][]deviceSyncMigrationTestRow{
			"relay_audit_events": {
				{values: auditRow0},
				{values: auditRow1},
			},
		})
	if err := ValidateDeviceSyncMigrationStateArtifact(
		context.Background(), bytes.NewReader(artifact), principalID, digest,
	); err != nil {
		t.Fatal(err)
	}

	nonCanonical, nonCanonicalDigest := encodeDeviceSyncMigrationTestState(t, principalID,
		map[string][]deviceSyncMigrationTestRow{
			"relay_audit_events": {
				{values: auditRow0},
				{values: deviceSyncMigrationTestRowValues(t, auditSpec, principalID,
					map[string]deviceSyncMigrationScalar{
						"source_event_ordinal": {kind: deviceSyncMigrationScalarInt, intValue: 2},
					})},
			},
		})
	if err := ValidateDeviceSyncMigrationStateArtifact(
		context.Background(), bytes.NewReader(nonCanonical), principalID, nonCanonicalDigest,
	); err == nil {
		t.Fatal("non-contiguous audit timeline ordinal was accepted")
	}
}

func TestDeviceSyncMigrationStateRejectsMalformedUTF8(t *testing.T) {
	principalID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	accountSpec := deviceSyncMigrationSpec(t, "device_sync_account_admissions")
	row := deviceSyncMigrationTestRowValues(t, accountSpec, principalID,
		map[string]deviceSyncMigrationScalar{
			"entitlement_plan_id": migrationTestText(string([]byte{0xff})),
		})
	artifact, digest := encodeDeviceSyncMigrationTestState(t, principalID,
		map[string][]deviceSyncMigrationTestRow{
			"device_sync_account_admissions": {{values: row}},
		})
	if err := ValidateDeviceSyncMigrationStateArtifact(
		context.Background(), bytes.NewReader(artifact), principalID, digest,
	); err == nil {
		t.Fatal("malformed UTF-8 was accepted")
	}
}

func TestDeviceSyncMigrationScalarLengthFailsBeforeLargeAllocation(t *testing.T) {
	var oversized bytes.Buffer
	if err := writeMigrationUint64(
		&oversized, deviceSyncMigrationMaximumScalarLength+1,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := readMigrationString(&oversized); err == nil {
		t.Fatal("oversized declared scalar was accepted")
	}

	var truncated bytes.Buffer
	if err := writeMigrationUint64(&truncated, deviceSyncMigrationMaximumScalarLength); err != nil {
		t.Fatal(err)
	}
	truncated.WriteByte('x')
	if _, err := readMigrationString(&truncated); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated declared scalar error=%v", err)
	}
}

func TestDeviceSyncMigrationBlobInventoryCanonicality(t *testing.T) {
	principalID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	domainA := uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	domainB := uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
	blobA := relay.BlobID([]byte("a"))
	blobB := relay.BlobID([]byte("b"))
	entries := []DeviceSyncMigrationBlobInventoryEntry{
		{DomainID: domainA, BlobID: blobA, ByteCount: 1},
		{DomainID: domainB, BlobID: blobB, ByteCount: 2},
	}
	artifact, digest := encodeDeviceSyncMigrationTestBlobInventory(t, principalID, entries)
	if err := ValidateDeviceSyncMigrationBlobInventory(
		context.Background(), bytes.NewReader(artifact), principalID, digest,
	); err != nil {
		t.Fatal(err)
	}
	duplicate, duplicateDigest := encodeDeviceSyncMigrationTestBlobInventory(t, principalID,
		[]DeviceSyncMigrationBlobInventoryEntry{entries[0], entries[0]})
	if err := ValidateDeviceSyncMigrationBlobInventory(
		context.Background(), bytes.NewReader(duplicate), principalID, duplicateDigest,
	); err == nil {
		t.Fatal("duplicate blob inventory entry was accepted")
	}
	unordered, unorderedDigest := encodeDeviceSyncMigrationTestBlobInventory(t, principalID,
		[]DeviceSyncMigrationBlobInventoryEntry{entries[1], entries[0]})
	if err := ValidateDeviceSyncMigrationBlobInventory(
		context.Background(), bytes.NewReader(unordered), principalID, unorderedDigest,
	); err == nil {
		t.Fatal("unordered blob inventory was accepted")
	}
	tampered := append([]byte(nil), artifact...)
	tampered[len(tampered)-sha256.Size-1] ^= 0x01
	if err := ValidateDeviceSyncMigrationBlobInventory(
		context.Background(), bytes.NewReader(tampered), principalID, digest,
	); err == nil {
		t.Fatal("tampered blob inventory was accepted")
	}
}

func TestDeviceSyncMigrationStateCommitmentIsDomainSeparatedAndOrdered(t *testing.T) {
	left := DeviceSyncMigrationDigest(sha256.Sum256([]byte("left")))
	right := DeviceSyncMigrationDigest(sha256.Sum256([]byte("right")))
	commitment := DeviceSyncMigrationStateCommitment(left, right)
	if commitment == left || commitment == right ||
		commitment == DeviceSyncMigrationStateCommitment(right, left) {
		t.Fatal("state commitment did not bind domain and digest positions")
	}
}

func TestDeviceSyncMigrationStagedArtifactBindsExactByteCount(t *testing.T) {
	artifact := []byte("authenticated artifact")
	digest := DeviceSyncMigrationDigest(sha256.Sum256(artifact))
	if err := verifyDeviceSyncMigrationStagedArtifact(
		context.Background(), bytes.NewReader(artifact), int64(len(artifact)), digest,
	); err != nil {
		t.Fatal(err)
	}
	if err := verifyDeviceSyncMigrationStagedArtifact(
		context.Background(), bytes.NewReader(artifact), int64(len(artifact)+1), digest,
	); err == nil {
		t.Fatal("signed descriptor with wrong byte count was accepted")
	}
	tampered := append([]byte(nil), artifact...)
	tampered[0] ^= 0x01
	if err := verifyDeviceSyncMigrationStagedArtifact(
		context.Background(), bytes.NewReader(tampered), int64(len(tampered)), digest,
	); err == nil {
		t.Fatal("staged artifact with wrong signed digest was accepted")
	}
}

func TestDeviceSyncMigrationSchemaInventoryFailsClosed(t *testing.T) {
	inventory := make(map[string][]deviceSyncMigrationSchemaColumn)
	for _, spec := range deviceSyncMigrationTableSpecs {
		for _, column := range spec.columns {
			if column.virtual {
				continue
			}
			inventory[spec.name] = append(inventory[spec.name], deviceSyncMigrationSchemaColumn{
				name: column.name, databaseType: column.databaseType, nullable: column.nullable,
			})
		}
		for name, databaseType := range deviceSyncMigrationOmittedColumns[spec.name] {
			inventory[spec.name] = append(inventory[spec.name], deviceSyncMigrationSchemaColumn{
				name: name, databaseType: databaseType,
			})
		}
	}
	for tableName := range deviceSyncMigrationExcludedTables {
		inventory[tableName] = []deviceSyncMigrationSchemaColumn{}
	}
	if err := validateDeviceSyncMigrationSchemaInventory(inventory); err != nil {
		t.Fatal(err)
	}

	inventory["device_sync_future_scoped_state"] = []deviceSyncMigrationSchemaColumn{{
		name: "principal_id", databaseType: "uuid",
	}}
	if err := validateDeviceSyncMigrationSchemaInventory(inventory); err == nil {
		t.Fatal("unclassified future table was accepted")
	}
	delete(inventory, "device_sync_future_scoped_state")

	first := deviceSyncMigrationTableSpecs[0]
	inventory[first.name][0].databaseType = "text"
	if err := validateDeviceSyncMigrationSchemaInventory(inventory); err == nil {
		t.Fatal("changed column type was accepted")
	}
}

func encodeDeviceSyncMigrationTestState(
	t *testing.T,
	principalID uuid.UUID,
	rowsByTable map[string][]deviceSyncMigrationTestRow,
) ([]byte, DeviceSyncMigrationDigest) {
	t.Helper()
	var destination bytes.Buffer
	writer := newDeviceSyncMigrationArtifactWriter(&destination)
	if err := writeDeviceSyncMigrationStateHeader(writer.bodyWriter, principalID); err != nil {
		t.Fatal(err)
	}
	for _, spec := range deviceSyncMigrationTableSpecs {
		rows, provided := rowsByTable[spec.name]
		if !provided && deviceSyncMigrationRequiresOneRow(spec.name) {
			rows = []deviceSyncMigrationTestRow{{
				values: deviceSyncMigrationTestRowValues(t, spec, principalID, nil),
			}}
		}
		if err := writeDeviceSyncMigrationSectionHeader(writer.bodyWriter, spec, uint64(len(rows))); err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			if err := writeDeviceSyncMigrationRow(
				writer.bodyWriter, spec, row.occurrence, row.values,
			); err != nil {
				t.Fatal(err)
			}
		}
	}
	digest, err := writer.finish()
	if err != nil {
		t.Fatal(err)
	}
	return destination.Bytes(), digest
}

func deviceSyncMigrationTestRowValues(
	t *testing.T,
	spec deviceSyncMigrationTableSpec,
	principalID uuid.UUID,
	overrides map[string]deviceSyncMigrationScalar,
) []deviceSyncMigrationScalar {
	t.Helper()
	values := make([]deviceSyncMigrationScalar, len(spec.columns))
	for index, column := range spec.columns {
		switch column.kind {
		case deviceSyncMigrationScalarUUID:
			values[index] = migrationTestUUID(principalID)
		case deviceSyncMigrationScalarText:
			values[index] = migrationTestText("x")
		case deviceSyncMigrationScalarInt:
			values[index] = deviceSyncMigrationScalar{kind: column.kind, intValue: 1}
		case deviceSyncMigrationScalarBool:
			values[index] = deviceSyncMigrationScalar{kind: column.kind}
		case deviceSyncMigrationScalarTextArray:
			values[index] = deviceSyncMigrationScalar{kind: column.kind, arrayValue: []string{"x"}}
		case deviceSyncMigrationScalarBytes:
			values[index] = deviceSyncMigrationScalar{kind: column.kind, bytesValue: []byte("x")}
		case deviceSyncMigrationScalarCanonicalJSON:
			values[index] = deviceSyncMigrationScalar{kind: column.kind, textValue: "{}"}
		default:
			t.Fatalf("unsupported test scalar kind %d", column.kind)
		}
		if column.name == "reserved_blob_count" || column.name == "reserved_blob_byte_count" {
			values[index] = deviceSyncMigrationScalar{kind: column.kind, intValue: 0}
		}
		if override, exists := overrides[column.name]; exists {
			values[index] = override
		}
	}
	values[spec.scopeColumnIndex] = migrationTestUUID(principalID)
	return values
}

func migrationTestUUID(value uuid.UUID) deviceSyncMigrationScalar {
	return deviceSyncMigrationScalar{kind: deviceSyncMigrationScalarUUID, uuidValue: value}
}

func migrationTestText(value string) deviceSyncMigrationScalar {
	return deviceSyncMigrationScalar{kind: deviceSyncMigrationScalarText, textValue: value}
}

func deviceSyncMigrationSpec(t *testing.T, name string) deviceSyncMigrationTableSpec {
	t.Helper()
	for _, spec := range deviceSyncMigrationTableSpecs {
		if spec.name == name {
			return spec
		}
	}
	t.Fatalf("missing Device Sync migration spec %s", name)
	return deviceSyncMigrationTableSpec{}
}

func encodeDeviceSyncMigrationTestBlobInventory(
	t *testing.T,
	principalID uuid.UUID,
	entries []DeviceSyncMigrationBlobInventoryEntry,
) ([]byte, DeviceSyncMigrationDigest) {
	t.Helper()
	var destination bytes.Buffer
	writer := newDeviceSyncMigrationArtifactWriter(&destination)
	if err := writeMigrationBytes(writer.bodyWriter, deviceSyncMigrationBlobMagic); err != nil {
		t.Fatal(err)
	}
	if err := writeMigrationUint16(writer.bodyWriter, deviceSyncMigrationArtifactVersion); err != nil {
		t.Fatal(err)
	}
	if err := writeMigrationBytes(writer.bodyWriter, principalID[:]); err != nil {
		t.Fatal(err)
	}
	if err := writeMigrationUint64(writer.bodyWriter, uint64(len(entries))); err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if err := writeMigrationBytes(writer.bodyWriter, entry.DomainID[:]); err != nil {
			t.Fatal(err)
		}
		if err := writeMigrationString(writer.bodyWriter, entry.BlobID); err != nil {
			t.Fatal(err)
		}
		if err := writeMigrationUint64(writer.bodyWriter, uint64(entry.ByteCount)); err != nil {
			t.Fatal(err)
		}
	}
	digest, err := writer.finish()
	if err != nil {
		t.Fatal(err)
	}
	return destination.Bytes(), digest
}
