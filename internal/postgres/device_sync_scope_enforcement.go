package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/robreuss/FacetsNode/internal/devicesync"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

const maximumDeviceSyncAuthorityRecordByteCount = 1024 * 1024
const maximumDeviceSyncSnapshotPayloadByteCount = 262_144

type DeviceSyncScopeEnforcementState string

const (
	DeviceSyncScopeStandby      DeviceSyncScopeEnforcementState = "standby"
	DeviceSyncScopeWritable     DeviceSyncScopeEnforcementState = "writable"
	DeviceSyncScopeExportFenced DeviceSyncScopeEnforcementState = "export_fenced"
	DeviceSyncScopeRetired      DeviceSyncScopeEnforcementState = "retired"
)

func (state DeviceSyncScopeEnforcementState) valid() bool {
	return state == DeviceSyncScopeStandby || state == DeviceSyncScopeWritable ||
		state == DeviceSyncScopeExportFenced || state == DeviceSyncScopeRetired
}

// DeviceSyncScopeAuthority is the exact authority record committed beside the
// durable write state. ManifestRecord is canonical JSON for the signed
// service-authority Manifest, not just its payload. The store verifies the
// signature and reference digest, but its caller remains responsible for first
// authorizing successor evidence against the Facets authority chain.
type DeviceSyncScopeAuthority struct {
	Revision                 uint64
	ManifestDigest           string
	ManifestRecord           []byte
	ActiveDeploymentID       uuid.UUID
	TransitionEvidenceDigest *string
	ValidatedAtMilliseconds  int64
}

type DeviceSyncScopeEnforcement struct {
	PrincipalID              uuid.UUID
	TenantID                 uuid.UUID
	State                    DeviceSyncScopeEnforcementState
	LocalDeploymentID        *uuid.UUID
	Authority                *DeviceSyncScopeAuthority
	ActiveExportWriteFenceID *uuid.UUID
}

// DeviceSyncMigrationExportRecord is the validated immutable database record
// whose exact canonical payload may be signed after the export-fence
// transaction commits. Returned payload bytes are defensive copies.
type DeviceSyncMigrationExportRecord struct {
	PrincipalID              uuid.UUID
	TenantID                 uuid.UUID
	MigrationID              uuid.UUID
	ExportWriteFenceID       uuid.UUID
	SnapshotID               uuid.UUID
	AuthorityRevision        uint64
	AuthorityManifestDigest  string
	ExportingDeploymentID    uuid.UUID
	ImportingDeploymentID    uuid.UUID
	CanonicalSnapshotPayload []byte
	SnapshotPayloadSHA256    string
	StateCommitmentDigest    string
	CapturedAtMilliseconds   int64
	ExpiresAtMilliseconds    int64
}

// DeviceSyncSnapshotReadTransaction narrows the trusted materializer to the
// already-open PostgreSQL transaction. Query and QueryRow can technically run
// data-modifying SQL, so this is an internal trusted-code seam rather than a
// hard database capability sandbox.
type DeviceSyncSnapshotReadTransaction interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

// DeviceSyncSnapshotMaterializer is invoked only after the scope-enforcement
// row has been locked FOR UPDATE. It must read/materialize the service snapshot
// while that transaction remains open and return the exact canonical
// MigrationSnapshotPayload bytes that will be stored and later signed.
type DeviceSyncSnapshotMaterializer func(
	context.Context,
	DeviceSyncSnapshotReadTransaction,
	DeviceSyncScopeEnforcement,
) ([]byte, error)

type deviceSyncSnapshotReadTransaction struct {
	tx pgx.Tx
}

func (transaction deviceSyncSnapshotReadTransaction) Query(
	ctx context.Context,
	query string,
	arguments ...any,
) (pgx.Rows, error) {
	return transaction.tx.Query(ctx, query, arguments...)
}

func (transaction deviceSyncSnapshotReadTransaction) QueryRow(
	ctx context.Context,
	query string,
	arguments ...any,
) pgx.Row {
	return transaction.tx.QueryRow(ctx, query, arguments...)
}

type deviceSyncScopeWriteFenceError struct {
	state DeviceSyncScopeEnforcementState
}

func (err *deviceSyncScopeWriteFenceError) Error() string {
	return fmt.Sprintf("Device Sync scope state %q rejects writes", err.state)
}

func (err *deviceSyncScopeWriteFenceError) Unwrap() error {
	return devicesync.ErrScopeWriteFenced
}

// DeviceSyncScopeAuthorityFromManifest creates exact database authority facts
// for a Manifest whose chain evidence was authenticated by the caller. It also
// enforces the same transition-evidence presence rule as BindingRegistry.
func DeviceSyncScopeAuthorityFromManifest(
	manifest serviceauthority.Manifest,
	transitionEvidenceDigest *string,
	validatedAtMilliseconds int64,
) (DeviceSyncScopeAuthority, error) {
	payload, err := manifest.VerifiedPayload()
	if err != nil || payload.Scope.Kind != serviceauthority.ScopeDeviceSync ||
		payload.Revision > math.MaxInt64 || validatedAtMilliseconds < 0 {
		return DeviceSyncScopeAuthority{}, serviceauthority.ErrInvalid
	}
	manifestDigest, err := manifest.ReferenceDigest()
	if err != nil {
		return DeviceSyncScopeAuthority{}, serviceauthority.ErrInvalid
	}
	requiresEvidence := payload.Transition == serviceauthority.TransitionMigrationPreparation ||
		payload.Transition == serviceauthority.TransitionMigrationCancellation ||
		payload.Transition == serviceauthority.TransitionMigrationActivation ||
		payload.Transition == serviceauthority.TransitionMigrationRollback
	if requiresEvidence != (transitionEvidenceDigest != nil) ||
		(transitionEvidenceDigest != nil &&
			!validDeviceSyncDigest(*transitionEvidenceDigest)) {
		return DeviceSyncScopeAuthority{}, serviceauthority.ErrInvalid
	}
	manifestRecord, err := json.Marshal(manifest)
	if err != nil || len(manifestRecord) == 0 ||
		len(manifestRecord) > maximumDeviceSyncAuthorityRecordByteCount {
		return DeviceSyncScopeAuthority{}, serviceauthority.ErrInvalid
	}
	return DeviceSyncScopeAuthority{
		Revision:                 payload.Revision,
		ManifestDigest:           manifestDigest,
		ManifestRecord:           manifestRecord,
		ActiveDeploymentID:       payload.ActiveDeployment.DeploymentID,
		TransitionEvidenceDigest: cloneStringPointer(transitionEvidenceDigest),
		ValidatedAtMilliseconds:  validatedAtMilliseconds,
	}, nil
}

// GetDeviceSyncScopeEnforcement returns the durable state and revalidates its
// signed authority record. A corrupt or internally inconsistent row fails
// closed rather than being presented as writable.
func (s *RelayStore) GetDeviceSyncScopeEnforcement(
	ctx context.Context,
	principalID uuid.UUID,
) (DeviceSyncScopeEnforcement, error) {
	if principalID == uuid.Nil {
		return DeviceSyncScopeEnforcement{}, serviceauthority.ErrInvalid
	}
	return loadDeviceSyncScopeEnforcement(ctx, s.pool, principalID, "")
}

// ActivateBoundDeviceSyncScope changes only the state of an exact authority
// record previously authenticated and committed by the account-claim
// transaction. The coordinator installs that same record in BindingRegistry
// first, then invokes this method. It cannot introduce or replace authority and
// therefore cannot activate an imported migration target.
func (s *RelayStore) ActivateBoundDeviceSyncScope(
	ctx context.Context,
	principalID uuid.UUID,
	localDeploymentID uuid.UUID,
	expectedAuthorityRevision uint64,
	expectedAuthorityManifestDigest string,
	nowMilliseconds int64,
) error {
	if principalID == uuid.Nil || localDeploymentID == uuid.Nil ||
		expectedAuthorityRevision != 1 ||
		!validDeviceSyncDigest(expectedAuthorityManifestDigest) ||
		nowMilliseconds < 0 {
		return serviceauthority.ErrInvalid
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin bound Device Sync scope activation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	current, err := loadDeviceSyncScopeEnforcement(ctx, tx, principalID, "FOR UPDATE")
	if err != nil {
		return err
	}
	if current.State == DeviceSyncScopeWritable {
		if validateDeviceSyncAuthorityIdentity(
			current, localDeploymentID, expectedAuthorityRevision,
			expectedAuthorityManifestDigest,
		) == nil && validateBoundInitialDeviceSyncAuthority(current) == nil {
			return nil
		}
		return devicesync.ErrInitialServiceAuthorityConflict
	}
	if current.State != DeviceSyncScopeStandby {
		return &deviceSyncScopeWriteFenceError{state: current.State}
	}
	if err := validateDeviceSyncAuthorityIdentity(
		current, localDeploymentID, expectedAuthorityRevision,
		expectedAuthorityManifestDigest,
	); err != nil {
		return devicesync.ErrInitialServiceAuthorityConflict
	}
	if err := validateBoundInitialDeviceSyncAuthority(current); err != nil {
		return devicesync.ErrInitialServiceAuthorityConflict
	}
	result, err := tx.Exec(ctx, `
		UPDATE device_sync_scope_enforcement
		SET state='writable', updated_at=now()
		WHERE principal_id=$1 AND tenant_id=$1 AND state='standby'
		  AND local_deployment_id=$2 AND authority_revision=$3
		  AND authority_manifest_digest=$4
	`, principalID, localDeploymentID, int64(expectedAuthorityRevision),
		expectedAuthorityManifestDigest)
	if err != nil {
		return fmt.Errorf("activate bound Device Sync scope: %w", err)
	}
	if result.RowsAffected() != 1 {
		return errors.New("bound Device Sync activation affected an unexpected row count")
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit bound Device Sync scope activation: %w", err)
	}
	return nil
}

func validateBoundInitialDeviceSyncAuthority(
	current DeviceSyncScopeEnforcement,
) error {
	if current.Authority == nil || current.Authority.Revision != 1 ||
		current.Authority.TransitionEvidenceDigest != nil {
		return serviceauthority.ErrInvalid
	}
	manifest, err := decodeCanonicalDeviceSyncAuthorityManifest(
		current.Authority.ManifestRecord,
	)
	if err != nil {
		return err
	}
	payload, err := manifest.VerifiedPayload()
	if err != nil || payload.Transition !=
		serviceauthority.TransitionInitialActivation || payload.Migration != nil ||
		len(payload.PreparedDeployments) != 0 {
		return serviceauthority.ErrInvalid
	}
	return nil
}

// AdvanceDeviceSyncWritableAuthority stores an exact immediate successor that
// is current at nowMilliseconds and leaves this local deployment writable.
// Deployment-changing activation, rollback, retirement, and recovery remain
// exclusive to the future migration coordinator. An exact installed retry is
// recognized before temporal validation and therefore remains idempotent.
func (s *RelayStore) AdvanceDeviceSyncWritableAuthority(
	ctx context.Context,
	principalID uuid.UUID,
	localDeploymentID uuid.UUID,
	manifest serviceauthority.Manifest,
	transitionEvidenceDigest *string,
	nowMilliseconds int64,
) error {
	nextAuthority, err := DeviceSyncScopeAuthorityFromManifest(
		manifest, transitionEvidenceDigest, nowMilliseconds,
	)
	if err != nil {
		return err
	}
	nextPayload, err := manifest.VerifiedPayload()
	if err != nil || principalID == uuid.Nil || localDeploymentID == uuid.Nil ||
		nowMilliseconds < 0 || nextPayload.Scope.ScopeID != principalID ||
		nextPayload.ActiveDeployment.DeploymentID != localDeploymentID {
		return serviceauthority.ErrInvalid
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin Device Sync writable authority update: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	current, err := loadDeviceSyncScopeEnforcement(ctx, tx, principalID, "FOR UPDATE")
	if err != nil {
		return err
	}
	if current.State == DeviceSyncScopeWritable &&
		uuidPointerEqual(current.LocalDeploymentID, localDeploymentID) &&
		deviceSyncScopeAuthorityEqual(current.Authority, &nextAuthority) {
		return nil
	}
	if current.State != DeviceSyncScopeWritable {
		return &deviceSyncScopeWriteFenceError{state: current.State}
	}
	if !uuidPointerEqual(current.LocalDeploymentID, localDeploymentID) ||
		current.Authority == nil {
		return errors.New("Device Sync writable authority belongs to another deployment")
	}
	currentManifest, err := decodeCanonicalDeviceSyncAuthorityManifest(
		current.Authority.ManifestRecord,
	)
	if err != nil {
		return err
	}
	validatedNext, err := manifest.ValidateSuccessor(currentManifest)
	if err != nil || validatedNext.Validate(&nowMilliseconds) != nil ||
		validatedNext.ActiveDeployment.DeploymentID != localDeploymentID ||
		!deviceSyncWritableAuthorityTransition(validatedNext.Transition) {
		return errors.New(
			"Device Sync writable authority update requires a current exact non-deployment-changing successor",
		)
	}
	if err := persistDeviceSyncScopeAuthority(
		ctx, tx, principalID, DeviceSyncScopeWritable, localDeploymentID,
		nextAuthority, nil,
	); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit Device Sync writable authority update: %w", err)
	}
	return nil
}

// MaterializeAndFenceDeviceSyncMigrationExport acquires the durable scope row
// FOR UPDATE before invoking materializer. The callback reads/materializes the
// snapshot while that transaction is open; only then does the same transaction
// persist the canonical bytes and change the scope to export_fenced. This
// method does not sign the snapshot or publish BindingRegistry fence evidence.
//
// An already-fenced exact retry validates and returns the durable record before
// considering materializer. This recovery path remains available after
// snapshot expiry and never rebuilds potentially changed service state.
func (s *RelayStore) MaterializeAndFenceDeviceSyncMigrationExport(
	ctx context.Context,
	principalID uuid.UUID,
	localDeploymentID uuid.UUID,
	expectedAuthorityRevision uint64,
	expectedAuthorityManifestDigest string,
	expectedMigrationID uuid.UUID,
	expectedExportWriteFenceID uuid.UUID,
	nowMilliseconds int64,
	materializer DeviceSyncSnapshotMaterializer,
) (DeviceSyncMigrationExportRecord, error) {
	if principalID == uuid.Nil || localDeploymentID == uuid.Nil ||
		expectedAuthorityRevision == 0 || expectedAuthorityRevision > math.MaxInt64 ||
		!validDeviceSyncDigest(expectedAuthorityManifestDigest) ||
		expectedMigrationID == uuid.Nil || expectedExportWriteFenceID == uuid.Nil ||
		nowMilliseconds < 0 {
		return DeviceSyncMigrationExportRecord{}, serviceauthority.ErrInvalid
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return DeviceSyncMigrationExportRecord{}, fmt.Errorf(
			"begin Device Sync migration export materialization: %w", err,
		)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	current, err := loadDeviceSyncScopeEnforcement(ctx, tx, principalID, "FOR UPDATE")
	if err != nil {
		return DeviceSyncMigrationExportRecord{}, err
	}
	if current.State != DeviceSyncScopeWritable &&
		current.State != DeviceSyncScopeExportFenced {
		return DeviceSyncMigrationExportRecord{},
			&deviceSyncScopeWriteFenceError{state: current.State}
	}
	if err := validateDeviceSyncAuthorityIdentity(
		current, localDeploymentID, expectedAuthorityRevision,
		expectedAuthorityManifestDigest,
	); err != nil {
		return DeviceSyncMigrationExportRecord{}, err
	}
	if current.State == DeviceSyncScopeExportFenced {
		if current.ActiveExportWriteFenceID == nil ||
			*current.ActiveExportWriteFenceID != expectedExportWriteFenceID {
			return DeviceSyncMigrationExportRecord{},
				&deviceSyncScopeWriteFenceError{state: current.State}
		}
		existing, found, err := loadDeviceSyncMigrationExport(
			ctx, tx, principalID, expectedExportWriteFenceID, "FOR SHARE",
		)
		if err != nil {
			return DeviceSyncMigrationExportRecord{}, err
		}
		if !found || existing.MigrationID != expectedMigrationID ||
			existing.AuthorityRevision != expectedAuthorityRevision ||
			existing.AuthorityManifestDigest != expectedAuthorityManifestDigest ||
			existing.ExportingDeploymentID != localDeploymentID {
			return DeviceSyncMigrationExportRecord{}, errors.New(
				"Device Sync migration export retry conflicts with stored fence",
			)
		}
		return cloneDeviceSyncMigrationExportRecord(existing), nil
	}
	if err := validateDeviceSyncMutationExpectation(
		current, localDeploymentID, expectedAuthorityRevision,
		expectedAuthorityManifestDigest, nowMilliseconds,
	); err != nil {
		return DeviceSyncMigrationExportRecord{}, err
	}
	if err := validatePreparedDeviceSyncMigrationIdentity(
		current, expectedMigrationID,
	); err != nil {
		return DeviceSyncMigrationExportRecord{}, err
	}
	if materializer == nil {
		return DeviceSyncMigrationExportRecord{}, serviceauthority.ErrInvalid
	}
	canonicalPayload, err := materializer(
		ctx,
		deviceSyncSnapshotReadTransaction{tx: tx},
		cloneDeviceSyncScopeEnforcement(current),
	)
	if err != nil {
		return DeviceSyncMigrationExportRecord{}, fmt.Errorf(
			"materialize Device Sync migration snapshot: %w", err,
		)
	}
	payload, snapshotPayloadSHA256, err :=
		decodeCanonicalDeviceSyncSnapshotPayload(canonicalPayload, nil)
	if err != nil || payload.Scope.ScopeID != principalID ||
		payload.MigrationID != expectedMigrationID ||
		payload.ExportWriteFenceID != expectedExportWriteFenceID {
		return DeviceSyncMigrationExportRecord{}, serviceauthority.ErrInvalid
	}
	if payload.Validate(&nowMilliseconds) != nil {
		return DeviceSyncMigrationExportRecord{}, serviceauthority.ErrInvalid
	}
	if err := validatePreparedDeviceSyncExport(current, payload); err != nil {
		return DeviceSyncMigrationExportRecord{}, err
	}
	result, err := tx.Exec(ctx, `
		INSERT INTO device_sync_migration_exports (
			principal_id,tenant_id,migration_id,export_write_fence_id,
			snapshot_id,authority_revision,authority_manifest_digest,
			exporting_deployment_id,importing_deployment_id,
			canonical_snapshot_payload,snapshot_payload_sha256,
			state_commitment_digest,captured_at_milliseconds,
			expires_at_milliseconds
		) VALUES ($1,$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
	`, principalID, payload.MigrationID, payload.ExportWriteFenceID,
		payload.SnapshotID, int64(expectedAuthorityRevision),
		payload.AuthorityManifestDigest, payload.ExportingDeploymentID,
		payload.ImportingDeploymentID, canonicalPayload,
		snapshotPayloadSHA256, payload.StateCommitmentDigest,
		payload.CapturedAtMilliseconds, payload.ExpiresAtMilliseconds)
	if err != nil {
		return DeviceSyncMigrationExportRecord{}, fmt.Errorf(
			"insert Device Sync migration export: %w", err,
		)
	}
	if result.RowsAffected() != 1 {
		return DeviceSyncMigrationExportRecord{}, errors.New(
			"Device Sync migration export insert affected an unexpected row count",
		)
	}
	result, err = tx.Exec(ctx, `
		UPDATE device_sync_scope_enforcement
		SET state='export_fenced', active_export_write_fence_id=$2,
			updated_at=now()
		WHERE principal_id=$1 AND tenant_id=$1 AND state='writable'
	`, principalID, payload.ExportWriteFenceID)
	if err != nil {
		return DeviceSyncMigrationExportRecord{}, fmt.Errorf(
			"install Device Sync export write fence: %w", err,
		)
	}
	if result.RowsAffected() != 1 {
		return DeviceSyncMigrationExportRecord{}, errors.New(
			"Device Sync export write fence affected an unexpected row count",
		)
	}
	stored, found, err := loadDeviceSyncMigrationExport(
		ctx, tx, principalID, expectedExportWriteFenceID, "FOR SHARE",
	)
	if err != nil {
		return DeviceSyncMigrationExportRecord{}, err
	}
	if !found || stored.MigrationID != expectedMigrationID ||
		stored.AuthorityRevision != expectedAuthorityRevision ||
		stored.AuthorityManifestDigest != expectedAuthorityManifestDigest ||
		stored.ExportingDeploymentID != localDeploymentID ||
		!bytes.Equal(stored.CanonicalSnapshotPayload, canonicalPayload) {
		return DeviceSyncMigrationExportRecord{}, errors.New(
			"persisted Device Sync migration export differs from materialized record",
		)
	}
	if err := tx.Commit(ctx); err != nil {
		return DeviceSyncMigrationExportRecord{}, fmt.Errorf(
			"commit Device Sync migration export fence: %w", err,
		)
	}
	return cloneDeviceSyncMigrationExportRecord(stored), nil
}

// lockDeviceSyncScopeForMutation is the store-level seam that every durable
// Device Sync mutator will adopt. Call it as the first row lock inside the same
// PostgreSQL transaction as the mutation and retain that transaction through
// commit. All authority expectations are mandatory. The FOR SHARE lock
// conflicts with migration's FOR UPDATE lock, draining cross-process writers.
func lockDeviceSyncScopeForMutation(
	ctx context.Context,
	tx pgx.Tx,
	principalID uuid.UUID,
	localDeploymentID uuid.UUID,
	expectedAuthorityRevision uint64,
	expectedAuthorityManifestDigest string,
	nowMilliseconds int64,
) (DeviceSyncScopeEnforcement, error) {
	if principalID == uuid.Nil || localDeploymentID == uuid.Nil ||
		expectedAuthorityRevision == 0 || expectedAuthorityRevision > math.MaxInt64 ||
		!validDeviceSyncDigest(expectedAuthorityManifestDigest) ||
		nowMilliseconds < 0 {
		return DeviceSyncScopeEnforcement{}, serviceauthority.ErrInvalid
	}
	current, err := loadDeviceSyncScopeEnforcement(ctx, tx, principalID, "FOR SHARE")
	if err != nil {
		return DeviceSyncScopeEnforcement{}, err
	}
	if err := validateDeviceSyncMutationExpectation(
		current, localDeploymentID, expectedAuthorityRevision,
		expectedAuthorityManifestDigest, nowMilliseconds,
	); err != nil {
		return DeviceSyncScopeEnforcement{}, err
	}
	return current, nil
}

func validateDeviceSyncMutationExpectation(
	current DeviceSyncScopeEnforcement,
	localDeploymentID uuid.UUID,
	expectedAuthorityRevision uint64,
	expectedAuthorityManifestDigest string,
	nowMilliseconds int64,
) error {
	if current.State != DeviceSyncScopeWritable {
		return &deviceSyncScopeWriteFenceError{state: current.State}
	}
	if err := validateDeviceSyncAuthorityIdentity(
		current, localDeploymentID, expectedAuthorityRevision,
		expectedAuthorityManifestDigest,
	); err != nil {
		return err
	}
	manifest, err := decodeCanonicalDeviceSyncAuthorityManifest(
		current.Authority.ManifestRecord,
	)
	if err != nil {
		return err
	}
	payload, err := manifest.VerifiedPayload()
	if err != nil || payload.Scope.ScopeID != current.PrincipalID ||
		payload.ActiveDeployment.DeploymentID != localDeploymentID ||
		payload.Validate(&nowMilliseconds) != nil {
		return errors.New("Device Sync mutation authority is stale, future, or inconsistent")
	}
	return nil
}

func validateDeviceSyncAuthorityIdentity(
	current DeviceSyncScopeEnforcement,
	localDeploymentID uuid.UUID,
	expectedAuthorityRevision uint64,
	expectedAuthorityManifestDigest string,
) error {
	if localDeploymentID == uuid.Nil || expectedAuthorityRevision == 0 ||
		expectedAuthorityRevision > math.MaxInt64 ||
		!validDeviceSyncDigest(expectedAuthorityManifestDigest) ||
		current.LocalDeploymentID == nil ||
		*current.LocalDeploymentID != localDeploymentID ||
		current.Authority == nil ||
		current.Authority.ActiveDeploymentID != localDeploymentID ||
		current.Authority.Revision != expectedAuthorityRevision ||
		current.Authority.ManifestDigest != expectedAuthorityManifestDigest {
		return errors.New("Device Sync mutation authority expectation does not match durable authority")
	}
	return nil
}

func validatePreparedDeviceSyncExport(
	current DeviceSyncScopeEnforcement,
	payload serviceauthority.MigrationSnapshotPayload,
) error {
	if current.Authority == nil {
		return errors.New("Device Sync migration export lacks durable authority")
	}
	authorityManifest, err := decodeCanonicalDeviceSyncAuthorityManifest(
		current.Authority.ManifestRecord,
	)
	if err != nil {
		return err
	}
	authorityPayload, err := authorityManifest.VerifiedPayload()
	if err != nil || authorityPayload.Transition !=
		serviceauthority.TransitionMigrationPreparation ||
		authorityPayload.Migration == nil ||
		len(authorityPayload.PreparedDeployments) != 1 ||
		payload.MigrationID != authorityPayload.Migration.MigrationID ||
		payload.Scope != authorityPayload.Scope ||
		payload.AuthorityManifestDigest != current.Authority.ManifestDigest ||
		payload.ExportingDeploymentID != authorityPayload.ActiveDeployment.DeploymentID ||
		payload.ExportingDeploymentID != authorityPayload.Migration.SourceDeploymentID ||
		payload.ImportingDeploymentID != authorityPayload.Migration.TargetDeploymentID ||
		payload.ImportingDeploymentID != authorityPayload.PreparedDeployments[0].DeploymentID ||
		payload.CapturedAtMilliseconds < authorityPayload.ValidFromMilliseconds {
		return errors.New("Device Sync migration export does not match the prepared migration")
	}
	return nil
}

func validatePreparedDeviceSyncMigrationIdentity(
	current DeviceSyncScopeEnforcement,
	expectedMigrationID uuid.UUID,
) error {
	if expectedMigrationID == uuid.Nil || current.Authority == nil {
		return serviceauthority.ErrInvalid
	}
	manifest, err := decodeCanonicalDeviceSyncAuthorityManifest(
		current.Authority.ManifestRecord,
	)
	if err != nil {
		return err
	}
	payload, err := manifest.VerifiedPayload()
	if err != nil || payload.Transition !=
		serviceauthority.TransitionMigrationPreparation || payload.Migration == nil ||
		payload.Migration.MigrationID != expectedMigrationID {
		return errors.New(
			"Device Sync migration export does not match prepared migration identity",
		)
	}
	return nil
}

func decodeCanonicalDeviceSyncSnapshotPayload(
	canonicalPayload []byte,
	nowMilliseconds *int64,
) (serviceauthority.MigrationSnapshotPayload, string, error) {
	var payload serviceauthority.MigrationSnapshotPayload
	if len(canonicalPayload) == 0 ||
		len(canonicalPayload) > maximumDeviceSyncSnapshotPayloadByteCount {
		return payload, "", serviceauthority.ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(canonicalPayload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return payload, "", serviceauthority.ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return payload, "", serviceauthority.ErrInvalid
	}
	canonical, err := json.Marshal(payload)
	if err != nil || !bytes.Equal(canonical, canonicalPayload) ||
		payload.Validate(nowMilliseconds) != nil ||
		payload.Scope.Kind != serviceauthority.ScopeDeviceSync {
		return payload, "", serviceauthority.ErrInvalid
	}
	digest := sha256.Sum256(canonicalPayload)
	return payload, hex.EncodeToString(digest[:]), nil
}

func loadDeviceSyncScopeEnforcement(
	ctx context.Context,
	querier relayQuerier,
	principalID uuid.UUID,
	lockClause string,
) (DeviceSyncScopeEnforcement, error) {
	query := `
		SELECT tenant_id,state,local_deployment_id,authority_revision,
			authority_manifest_digest,authority_manifest_record,
			active_deployment_id,transition_evidence_digest,
			authority_validated_at_milliseconds,
			active_export_write_fence_id
		FROM device_sync_scope_enforcement
		WHERE principal_id=$1 AND tenant_id=$1
	`
	if lockClause != "" {
		query += " " + lockClause
	}
	current := DeviceSyncScopeEnforcement{PrincipalID: principalID}
	var revision *int64
	var manifestDigest *string
	var manifestRecord []byte
	var activeDeploymentID *uuid.UUID
	var transitionEvidenceDigest *string
	var authorityValidatedAtMilliseconds *int64
	err := querier.QueryRow(ctx, query, principalID).Scan(
		&current.TenantID, &current.State, &current.LocalDeploymentID,
		&revision, &manifestDigest, &manifestRecord, &activeDeploymentID,
		&transitionEvidenceDigest, &authorityValidatedAtMilliseconds,
		&current.ActiveExportWriteFenceID,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return DeviceSyncScopeEnforcement{}, errors.New(
			"Device Sync scope enforcement row was not found",
		)
	}
	if err != nil {
		return DeviceSyncScopeEnforcement{}, fmt.Errorf(
			"load Device Sync scope enforcement: %w", err,
		)
	}
	if current.TenantID != principalID || !current.State.valid() {
		return DeviceSyncScopeEnforcement{}, errors.New(
			"stored Device Sync scope enforcement is invalid",
		)
	}
	allAuthorityNil := current.LocalDeploymentID == nil && revision == nil &&
		manifestDigest == nil && len(manifestRecord) == 0 &&
		activeDeploymentID == nil && transitionEvidenceDigest == nil &&
		authorityValidatedAtMilliseconds == nil
	if allAuthorityNil {
		if current.State != DeviceSyncScopeStandby ||
			current.ActiveExportWriteFenceID != nil {
			return DeviceSyncScopeEnforcement{}, errors.New(
				"stored Device Sync scope lacks required authority",
			)
		}
		return current, nil
	}
	if current.LocalDeploymentID == nil || revision == nil || *revision <= 0 ||
		manifestDigest == nil || len(manifestRecord) == 0 || activeDeploymentID == nil {
		return DeviceSyncScopeEnforcement{}, errors.New(
			"stored Device Sync scope authority is incomplete",
		)
	}
	manifest, err := decodeCanonicalDeviceSyncAuthorityManifest(manifestRecord)
	if err != nil {
		return DeviceSyncScopeEnforcement{}, err
	}
	payload, err := manifest.VerifiedPayload()
	if err != nil || authorityValidatedAtMilliseconds == nil ||
		*authorityValidatedAtMilliseconds < 0 ||
		payload.Scope.Kind != serviceauthority.ScopeDeviceSync ||
		payload.Scope.ScopeID != principalID ||
		payload.Validate(authorityValidatedAtMilliseconds) != nil {
		return DeviceSyncScopeEnforcement{}, errors.New(
			"stored Device Sync scope authority names another scope",
		)
	}
	authority, err := DeviceSyncScopeAuthorityFromManifest(
		manifest, transitionEvidenceDigest, *authorityValidatedAtMilliseconds,
	)
	if err != nil || authority.Revision != uint64(*revision) ||
		authority.ManifestDigest != *manifestDigest ||
		authority.ActiveDeploymentID != *activeDeploymentID ||
		!bytes.Equal(authority.ManifestRecord, manifestRecord) {
		return DeviceSyncScopeEnforcement{}, errors.New(
			"stored Device Sync scope authority is inconsistent",
		)
	}
	current.Authority = &authority
	if ((current.State == DeviceSyncScopeStandby ||
		current.State == DeviceSyncScopeWritable ||
		current.State == DeviceSyncScopeExportFenced) &&
		*current.LocalDeploymentID != authority.ActiveDeploymentID) ||
		((current.State == DeviceSyncScopeExportFenced) !=
			(current.ActiveExportWriteFenceID != nil)) {
		return DeviceSyncScopeEnforcement{}, errors.New(
			"stored Device Sync deployment or export fence state is inconsistent",
		)
	}
	return current, nil
}

func decodeCanonicalDeviceSyncAuthorityManifest(
	record []byte,
) (serviceauthority.Manifest, error) {
	var manifest serviceauthority.Manifest
	if len(record) == 0 || len(record) > maximumDeviceSyncAuthorityRecordByteCount {
		return manifest, serviceauthority.ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(record))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return manifest, serviceauthority.ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return manifest, serviceauthority.ErrInvalid
	}
	canonical, err := json.Marshal(manifest)
	if err != nil || !bytes.Equal(canonical, record) {
		return manifest, serviceauthority.ErrInvalid
	}
	return manifest, nil
}

func persistDeviceSyncScopeAuthority(
	ctx context.Context,
	tx pgx.Tx,
	principalID uuid.UUID,
	state DeviceSyncScopeEnforcementState,
	localDeploymentID uuid.UUID,
	authority DeviceSyncScopeAuthority,
	activeExportWriteFenceID *uuid.UUID,
) error {
	result, err := tx.Exec(ctx, `
		UPDATE device_sync_scope_enforcement
		SET state=$2, local_deployment_id=$3,
			authority_validated_at_milliseconds=$4,
			authority_revision=$5,
			authority_manifest_digest=$6, authority_manifest_record=$7,
			active_deployment_id=$8, transition_evidence_digest=$9,
			active_export_write_fence_id=$10, updated_at=now()
		WHERE principal_id=$1 AND tenant_id=$1
	`, principalID, state, localDeploymentID,
		authority.ValidatedAtMilliseconds, int64(authority.Revision),
		authority.ManifestDigest, authority.ManifestRecord,
		authority.ActiveDeploymentID, authority.TransitionEvidenceDigest,
		activeExportWriteFenceID)
	if err != nil {
		return fmt.Errorf("persist Device Sync scope authority: %w", err)
	}
	if result.RowsAffected() != 1 {
		return errors.New("Device Sync scope authority update affected an unexpected row count")
	}
	return nil
}

func loadDeviceSyncMigrationExport(
	ctx context.Context,
	querier relayQuerier,
	principalID uuid.UUID,
	fenceID uuid.UUID,
	lockClause string,
) (DeviceSyncMigrationExportRecord, bool, error) {
	query := `
		SELECT migration_id,snapshot_id,authority_revision,
			authority_manifest_digest,exporting_deployment_id,
			importing_deployment_id,canonical_snapshot_payload,
			snapshot_payload_sha256,state_commitment_digest,
			captured_at_milliseconds,expires_at_milliseconds
		FROM device_sync_migration_exports
		WHERE principal_id=$1 AND tenant_id=$1 AND export_write_fence_id=$2
	`
	if lockClause != "" {
		query += " " + lockClause
	}
	stored := DeviceSyncMigrationExportRecord{
		PrincipalID: principalID, TenantID: principalID,
		ExportWriteFenceID: fenceID,
	}
	var authorityRevision int64
	err := querier.QueryRow(ctx, query, principalID, fenceID).Scan(
		&stored.MigrationID, &stored.SnapshotID, &authorityRevision,
		&stored.AuthorityManifestDigest, &stored.ExportingDeploymentID,
		&stored.ImportingDeploymentID, &stored.CanonicalSnapshotPayload,
		&stored.SnapshotPayloadSHA256, &stored.StateCommitmentDigest,
		&stored.CapturedAtMilliseconds, &stored.ExpiresAtMilliseconds,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return DeviceSyncMigrationExportRecord{}, false, nil
	}
	if err != nil {
		return DeviceSyncMigrationExportRecord{}, false, fmt.Errorf(
			"load Device Sync migration export: %w", err,
		)
	}
	payload, digest, err := decodeCanonicalDeviceSyncSnapshotPayload(
		stored.CanonicalSnapshotPayload, nil,
	)
	if err != nil || authorityRevision <= 0 ||
		digest != stored.SnapshotPayloadSHA256 ||
		payload.Scope.ScopeID != principalID ||
		payload.MigrationID != stored.MigrationID ||
		payload.ExportWriteFenceID != fenceID ||
		payload.SnapshotID != stored.SnapshotID ||
		payload.AuthorityManifestDigest != stored.AuthorityManifestDigest ||
		payload.ExportingDeploymentID != stored.ExportingDeploymentID ||
		payload.ImportingDeploymentID != stored.ImportingDeploymentID ||
		payload.StateCommitmentDigest != stored.StateCommitmentDigest ||
		payload.CapturedAtMilliseconds != stored.CapturedAtMilliseconds ||
		payload.ExpiresAtMilliseconds != stored.ExpiresAtMilliseconds {
		return DeviceSyncMigrationExportRecord{}, false, errors.New(
			"stored Device Sync migration export is invalid",
		)
	}
	stored.AuthorityRevision = uint64(authorityRevision)
	return cloneDeviceSyncMigrationExportRecord(stored), true, nil
}

func cloneDeviceSyncMigrationExportRecord(
	record DeviceSyncMigrationExportRecord,
) DeviceSyncMigrationExportRecord {
	cloned := record
	cloned.CanonicalSnapshotPayload = append(
		[]byte(nil), record.CanonicalSnapshotPayload...,
	)
	return cloned
}

func deviceSyncScopeAuthorityEqual(
	left *DeviceSyncScopeAuthority,
	right *DeviceSyncScopeAuthority,
) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Revision == right.Revision &&
		left.ManifestDigest == right.ManifestDigest &&
		bytes.Equal(left.ManifestRecord, right.ManifestRecord) &&
		left.ActiveDeploymentID == right.ActiveDeploymentID &&
		stringPointersEqual(
			left.TransitionEvidenceDigest,
			right.TransitionEvidenceDigest,
		)
}

func cloneDeviceSyncScopeEnforcement(
	value DeviceSyncScopeEnforcement,
) DeviceSyncScopeEnforcement {
	cloned := value
	cloned.LocalDeploymentID = cloneUUIDPointer(value.LocalDeploymentID)
	cloned.ActiveExportWriteFenceID = cloneUUIDPointer(value.ActiveExportWriteFenceID)
	if value.Authority != nil {
		authority := *value.Authority
		authority.ManifestRecord = append([]byte(nil), value.Authority.ManifestRecord...)
		authority.TransitionEvidenceDigest = cloneStringPointer(
			value.Authority.TransitionEvidenceDigest,
		)
		cloned.Authority = &authority
	}
	return cloned
}

func validDeviceSyncDigest(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func cloneStringPointer(value *string) *string {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneUUIDPointer(value *uuid.UUID) *uuid.UUID {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func stringPointersEqual(left *string, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func uuidPointerEqual(value *uuid.UUID, expected uuid.UUID) bool {
	return value != nil && *value == expected
}

func deviceSyncWritableAuthorityTransition(transition string) bool {
	return transition == serviceauthority.TransitionRouteRotation ||
		transition == serviceauthority.TransitionPolicyUpdate ||
		transition == serviceauthority.TransitionMigrationPreparation ||
		transition == serviceauthority.TransitionMigrationCancellation
}
