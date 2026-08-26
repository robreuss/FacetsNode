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
	"reflect"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/robreuss/FacetsNode/internal/devicesync"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

const maximumDeviceSyncAuthorityRecordByteCount = 1024 * 1024
const maximumDeviceSyncSnapshotPayloadByteCount = 262_144
const maximumDeviceSyncMigrationEvidenceRecordByteCount = 8 * 1024 * 1024

var ErrDeviceSyncMigrationImportConflict = errors.New(
	"Device Sync migration import conflicts with durable state",
)

var ErrDeviceSyncScopeEnforcementNotFound = errors.New(
	"Device Sync scope enforcement row was not found",
)

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
	ActiveMigrationImportID  *uuid.UUID
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

// DeviceSyncInitialAuthorityEvidence preserves the exact historically
// authenticated revision-1 authority when a principal moves to a new
// deployment. ValidatedAtMilliseconds is the original acceptance instant, not
// the import instant.
type DeviceSyncInitialAuthorityEvidence struct {
	Manifest                serviceauthority.Manifest
	ValidatedAtMilliseconds int64
}

// DeviceSyncMigrationImportRecord is immutable evidence that one exact signed
// snapshot and preparation populated a target-local standby scope and that the
// imported semantic rows independently reproduced StateCommitmentDigest. It
// does not assert custody of the opaque blob bytes named by the inventory.
type DeviceSyncMigrationImportRecord struct {
	PrincipalID                             uuid.UUID
	TenantID                                uuid.UUID
	MigrationID                             uuid.UUID
	SnapshotID                              uuid.UUID
	ExportWriteFenceID                      uuid.UUID
	AuthorityRevision                       uint64
	AuthorityManifestDigest                 string
	PreparationReferenceDigest              string
	ExportingDeploymentID                   uuid.UUID
	ImportingDeploymentID                   uuid.UUID
	CanonicalPreparationRecord              []byte
	PreparationRecordSHA256                 string
	PreparationManifestRecord               []byte
	CanonicalSnapshotRecord                 []byte
	SnapshotRecordSHA256                    string
	SnapshotReferenceDigest                 string
	SnapshotPayloadSHA256                   string
	StateCommitmentDigest                   string
	CanonicalArtifactDescriptors            []byte
	ArtifactDescriptorsSHA256               string
	ArtifactCount                           int
	ServiceStateArtifactID                  uuid.UUID
	ServiceStateArtifactByteCount           int64
	ServiceStateArtifactTransferDigest      string
	CapturedAtMilliseconds                  int64
	ExpiresAtMilliseconds                   int64
	ImportedAtMilliseconds                  int64
	InitialDeploymentID                     uuid.UUID
	InitialAuthorityValidatedAtMilliseconds int64
	InitialAuthorityManifestDigest          string
	InitialAuthorityManifestRecord          []byte
}

// DeviceSyncStandbyImportTransaction is an internal trusted-code seam, not a
// SQL capability sandbox. Exec, Query, and QueryRow can run arbitrary SQL.
// A materializer must insert only the authenticated principal's semantic relay
// and Device Sync rows; this store owns the import/enforcement evidence rows.
type DeviceSyncStandbyImportTransaction interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

// deviceSyncStandbyImportMaterializer populates semantic service rows inside
// the same transaction that later installs immutable import evidence and the
// prepared-target standby enforcement row. It is never invoked for an exact
// durable retry.
type deviceSyncStandbyImportMaterializer func(
	context.Context,
	DeviceSyncStandbyImportTransaction,
	serviceauthority.ValidatedMigrationTransfer,
) error

type deviceSyncStandbyImportTransaction struct {
	tx pgx.Tx
}

func (transaction deviceSyncStandbyImportTransaction) Exec(
	ctx context.Context,
	query string,
	arguments ...any,
) (pgconn.CommandTag, error) {
	return transaction.tx.Exec(ctx, query, arguments...)
}

func (transaction deviceSyncStandbyImportTransaction) Query(
	ctx context.Context,
	query string,
	arguments ...any,
) (pgx.Rows, error) {
	return transaction.tx.Query(ctx, query, arguments...)
}

func (transaction deviceSyncStandbyImportTransaction) QueryRow(
	ctx context.Context,
	query string,
	arguments ...any,
) pgx.Row {
	return transaction.tx.QueryRow(ctx, query, arguments...)
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

// ApplyDeviceSyncMigrationActivation consumes the complete Facets-authorized
// activation evidence and atomically moves one local database side of the
// migration across cutover. The imported target becomes writable; the fenced
// source becomes retired and remains non-writable. BindingRegistry must be
// advanced first by the local coordinator, making a database failure a
// restart-repairable fail-closed state rather than a split-brain window.
//
// An exact already-applied retry is accepted before temporal validation. A
// first application still requires a live terminal activation manifest and
// historically valid signed prerequisites.
func (s *RelayStore) ApplyDeviceSyncMigrationActivation(
	ctx context.Context,
	localDeploymentID uuid.UUID,
	evidence serviceauthority.MigrationActivationEvidence,
	anchor serviceauthority.TrustAnchor,
	nowMilliseconds int64,
) error {
	if ctx == nil || localDeploymentID == uuid.Nil || nowMilliseconds < 0 {
		return serviceauthority.ErrInvalid
	}
	activation, err := evidence.ActivationManifest.VerifiedPayload()
	if err != nil || activation.Scope.Kind != serviceauthority.ScopeDeviceSync ||
		activation.Transition != serviceauthority.TransitionMigrationActivation ||
		activation.Migration == nil ||
		(localDeploymentID != activation.Migration.SourceDeploymentID &&
			localDeploymentID != activation.Migration.TargetDeploymentID) {
		return serviceauthority.ErrInvalid
	}
	evidenceDigest, err := evidence.ReferenceDigest()
	if err != nil || !validDeviceSyncDigest(evidenceDigest) {
		return serviceauthority.ErrInvalid
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return fmt.Errorf("begin Device Sync migration activation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	current, err := loadDeviceSyncScopeEnforcement(
		ctx, tx, activation.Scope.ScopeID, "FOR UPDATE",
	)
	if err != nil {
		return err
	}
	targetSide := localDeploymentID == activation.Migration.TargetDeploymentID
	terminalState := DeviceSyncScopeRetired
	if targetSide {
		terminalState = DeviceSyncScopeWritable
	}
	if current.State == terminalState &&
		current.LocalDeploymentID != nil &&
		*current.LocalDeploymentID == localDeploymentID &&
		deviceSyncAuthorityMatchesExactManifest(
			current.Authority, evidence.ActivationManifest, evidenceDigest,
		) {
		return nil
	}

	validatedActivation, err := evidence.ValidateHistoricalCatchUp(
		anchor, nowMilliseconds,
	)
	if err != nil || validatedActivation.Scope != activation.Scope ||
		validatedActivation.Revision != activation.Revision ||
		validatedActivation.ActiveDeployment.DeploymentID !=
			activation.Migration.TargetDeploymentID {
		return serviceauthority.ErrInvalid
	}
	nextAuthority, err := DeviceSyncScopeAuthorityFromManifest(
		evidence.ActivationManifest, &evidenceDigest, nowMilliseconds,
	)
	if err != nil {
		return err
	}
	preparationDigest, err := evidence.Preparation.ReferenceDigest()
	if err != nil || current.Authority == nil ||
		current.LocalDeploymentID == nil ||
		*current.LocalDeploymentID != localDeploymentID ||
		!deviceSyncAuthorityMatchesExactManifest(
			current.Authority,
			evidence.Preparation.PreparationManifest,
			preparationDigest,
		) {
		return ErrDeviceSyncMigrationImportConflict
	}
	snapshot, err := evidence.Snapshot.VerifiedPayload(nil)
	if err != nil || snapshot.Scope != activation.Scope ||
		snapshot.MigrationID != activation.Migration.MigrationID ||
		snapshot.ExportingDeploymentID != activation.Migration.SourceDeploymentID ||
		snapshot.ImportingDeploymentID != activation.Migration.TargetDeploymentID {
		return serviceauthority.ErrInvalid
	}
	if targetSide {
		if err := validateDeviceSyncActivationTarget(
			ctx, tx, current, evidence, snapshot,
		); err != nil {
			return err
		}
	} else if err := validateDeviceSyncActivationSource(
		ctx, tx, current, evidence, snapshot,
	); err != nil {
		return err
	}

	result, err := tx.Exec(ctx, `
		UPDATE device_sync_scope_enforcement
		SET state=$2, authority_validated_at_milliseconds=$3,
			authority_revision=$4, authority_manifest_digest=$5,
			authority_manifest_record=$6, active_deployment_id=$7,
			transition_evidence_digest=$8,
			active_export_write_fence_id=NULL,
			active_migration_import_id=NULL, updated_at=now()
		WHERE principal_id=$1 AND tenant_id=$1
	`, activation.Scope.ScopeID, terminalState,
		nextAuthority.ValidatedAtMilliseconds, int64(nextAuthority.Revision),
		nextAuthority.ManifestDigest, nextAuthority.ManifestRecord,
		nextAuthority.ActiveDeploymentID,
		nextAuthority.TransitionEvidenceDigest)
	if err != nil {
		return fmt.Errorf("persist Device Sync migration activation: %w", err)
	}
	if result.RowsAffected() != 1 {
		return errors.New("Device Sync migration activation affected an unexpected row count")
	}
	stored, err := loadDeviceSyncScopeEnforcement(
		ctx, tx, activation.Scope.ScopeID, "FOR SHARE",
	)
	if err != nil || stored.State != terminalState ||
		stored.LocalDeploymentID == nil ||
		*stored.LocalDeploymentID != localDeploymentID ||
		!deviceSyncScopeAuthorityEqual(stored.Authority, &nextAuthority) ||
		stored.ActiveExportWriteFenceID != nil ||
		stored.ActiveMigrationImportID != nil {
		if err != nil {
			return err
		}
		return errors.New("persisted Device Sync migration activation is inconsistent")
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit Device Sync migration activation: %w", err)
	}
	return nil
}

// ApplyDeviceSyncMigrationCancellation consumes the exact authority-signed
// cancellation of one migration preparation and atomically unwinds the local
// database side. The source becomes writable again whether cancellation
// arrives before or after export. An imported target becomes retired and can
// never serve the copied state. Immutable export/import records remain as
// audit evidence, while their active pointers are cleared.
//
// An exact already-applied retry is accepted before temporal validation. A
// first application still requires a live cancellation manifest and an exact
// prepared predecessor in this database.
func (s *RelayStore) ApplyDeviceSyncMigrationCancellation(
	ctx context.Context,
	localDeploymentID uuid.UUID,
	evidence serviceauthority.MigrationCancellationEvidence,
	anchor serviceauthority.TrustAnchor,
	nowMilliseconds int64,
) error {
	if ctx == nil || localDeploymentID == uuid.Nil || nowMilliseconds < 0 {
		return serviceauthority.ErrInvalid
	}
	cancellation, err := evidence.CancellationManifest.VerifiedPayload()
	if err != nil || cancellation.Scope.Kind != serviceauthority.ScopeDeviceSync ||
		cancellation.Transition != serviceauthority.TransitionMigrationCancellation ||
		cancellation.Migration == nil ||
		(localDeploymentID != cancellation.Migration.SourceDeploymentID &&
			localDeploymentID != cancellation.Migration.TargetDeploymentID) {
		return serviceauthority.ErrInvalid
	}
	evidenceDigest, err := evidence.ReferenceDigest()
	if err != nil || !validDeviceSyncDigest(evidenceDigest) {
		return serviceauthority.ErrInvalid
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return fmt.Errorf("begin Device Sync migration cancellation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	current, err := loadDeviceSyncScopeEnforcement(
		ctx, tx, cancellation.Scope.ScopeID, "FOR UPDATE",
	)
	if err != nil {
		return err
	}
	targetSide := localDeploymentID == cancellation.Migration.TargetDeploymentID
	terminalState := DeviceSyncScopeWritable
	if targetSide {
		terminalState = DeviceSyncScopeRetired
	}
	if current.State == terminalState &&
		current.LocalDeploymentID != nil &&
		*current.LocalDeploymentID == localDeploymentID &&
		deviceSyncAuthorityMatchesExactManifest(
			current.Authority, evidence.CancellationManifest, evidenceDigest,
		) && current.ActiveExportWriteFenceID == nil &&
		current.ActiveMigrationImportID == nil {
		return nil
	}

	validatedCancellation, err := evidence.ValidateHistoricalCatchUp(
		anchor, nowMilliseconds,
	)
	if err != nil || validatedCancellation.Scope != cancellation.Scope ||
		validatedCancellation.Revision != cancellation.Revision ||
		validatedCancellation.ActiveDeployment.DeploymentID !=
			cancellation.Migration.SourceDeploymentID {
		return serviceauthority.ErrInvalid
	}
	nextAuthority, err := DeviceSyncScopeAuthorityFromManifest(
		evidence.CancellationManifest, &evidenceDigest, nowMilliseconds,
	)
	if err != nil {
		return err
	}
	preparationDigest, err := evidence.Preparation.ReferenceDigest()
	if err != nil || current.Authority == nil ||
		current.LocalDeploymentID == nil ||
		*current.LocalDeploymentID != localDeploymentID ||
		!deviceSyncAuthorityMatchesExactManifest(
			current.Authority,
			evidence.Preparation.PreparationManifest,
			preparationDigest,
		) {
		return ErrDeviceSyncMigrationImportConflict
	}
	if targetSide {
		if err := validateDeviceSyncCancellationTarget(
			ctx, tx, current, evidence,
		); err != nil {
			return err
		}
	} else if err := validateDeviceSyncCancellationSource(
		ctx, tx, current, evidence,
	); err != nil {
		return err
	}

	result, err := tx.Exec(ctx, `
		UPDATE device_sync_scope_enforcement
		SET state=$2, authority_validated_at_milliseconds=$3,
			authority_revision=$4, authority_manifest_digest=$5,
			authority_manifest_record=$6, active_deployment_id=$7,
			transition_evidence_digest=$8,
			active_export_write_fence_id=NULL,
			active_migration_import_id=NULL, updated_at=now()
		WHERE principal_id=$1 AND tenant_id=$1
	`, cancellation.Scope.ScopeID, terminalState,
		nextAuthority.ValidatedAtMilliseconds, int64(nextAuthority.Revision),
		nextAuthority.ManifestDigest, nextAuthority.ManifestRecord,
		nextAuthority.ActiveDeploymentID,
		nextAuthority.TransitionEvidenceDigest)
	if err != nil {
		return fmt.Errorf("persist Device Sync migration cancellation: %w", err)
	}
	if result.RowsAffected() != 1 {
		return errors.New("Device Sync migration cancellation affected an unexpected row count")
	}
	stored, err := loadDeviceSyncScopeEnforcement(
		ctx, tx, cancellation.Scope.ScopeID, "FOR SHARE",
	)
	if err != nil || stored.State != terminalState ||
		stored.LocalDeploymentID == nil ||
		*stored.LocalDeploymentID != localDeploymentID ||
		!deviceSyncScopeAuthorityEqual(stored.Authority, &nextAuthority) ||
		stored.ActiveExportWriteFenceID != nil ||
		stored.ActiveMigrationImportID != nil {
		if err != nil {
			return err
		}
		return errors.New("persisted Device Sync migration cancellation is inconsistent")
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit Device Sync migration cancellation: %w", err)
	}
	return nil
}

func validateDeviceSyncCancellationSource(
	ctx context.Context,
	tx pgx.Tx,
	current DeviceSyncScopeEnforcement,
	evidence serviceauthority.MigrationCancellationEvidence,
) error {
	prepared, err := evidence.Preparation.PreparationManifest.VerifiedPayload()
	if err != nil || prepared.Migration == nil ||
		current.ActiveMigrationImportID != nil {
		return ErrDeviceSyncMigrationImportConflict
	}
	if current.State == DeviceSyncScopeWritable &&
		current.ActiveExportWriteFenceID == nil {
		return nil
	}
	if current.State != DeviceSyncScopeExportFenced ||
		current.ActiveExportWriteFenceID == nil {
		return ErrDeviceSyncMigrationImportConflict
	}
	exported, found, err := loadDeviceSyncMigrationExport(
		ctx, tx, current.PrincipalID, *current.ActiveExportWriteFenceID, "FOR SHARE",
	)
	if err != nil {
		return err
	}
	if !found || !deviceSyncCancellationSourceRecordMatches(
		current, exported, evidence, prepared,
	) {
		return ErrDeviceSyncMigrationImportConflict
	}
	return nil
}

func deviceSyncCancellationSourceRecordMatches(
	current DeviceSyncScopeEnforcement,
	exported DeviceSyncMigrationExportRecord,
	evidence serviceauthority.MigrationCancellationEvidence,
	prepared serviceauthority.ManifestPayload,
) bool {
	preparationManifestDigest, err := evidence.Preparation.PreparationManifest.ReferenceDigest()
	return err == nil && prepared.Migration != nil &&
		current.State == DeviceSyncScopeExportFenced &&
		current.ActiveMigrationImportID == nil &&
		current.ActiveExportWriteFenceID != nil &&
		exported.PrincipalID == current.PrincipalID &&
		exported.TenantID == current.TenantID &&
		exported.ExportWriteFenceID == *current.ActiveExportWriteFenceID &&
		exported.MigrationID == prepared.Migration.MigrationID &&
		exported.ExportingDeploymentID == prepared.Migration.SourceDeploymentID &&
		exported.ImportingDeploymentID == prepared.Migration.TargetDeploymentID &&
		exported.AuthorityRevision == prepared.Revision &&
		exported.AuthorityManifestDigest == preparationManifestDigest
}

func validateDeviceSyncCancellationTarget(
	ctx context.Context,
	tx pgx.Tx,
	current DeviceSyncScopeEnforcement,
	evidence serviceauthority.MigrationCancellationEvidence,
) error {
	prepared, err := evidence.Preparation.PreparationManifest.VerifiedPayload()
	if err != nil || prepared.Migration == nil ||
		current.State != DeviceSyncScopeStandby ||
		current.ActiveExportWriteFenceID != nil ||
		current.ActiveMigrationImportID == nil ||
		*current.ActiveMigrationImportID != prepared.Migration.MigrationID {
		return ErrDeviceSyncMigrationImportConflict
	}
	imported, found, err := loadDeviceSyncMigrationImport(
		ctx, tx, current.PrincipalID, prepared.Migration.MigrationID,
		prepared.Migration.TargetDeploymentID, "FOR SHARE",
	)
	if err != nil {
		return err
	}
	if !found || !deviceSyncCancellationTargetRecordMatches(
		current, imported, evidence, prepared,
	) {
		return ErrDeviceSyncMigrationImportConflict
	}
	return nil
}

func deviceSyncCancellationTargetRecordMatches(
	current DeviceSyncScopeEnforcement,
	imported DeviceSyncMigrationImportRecord,
	evidence serviceauthority.MigrationCancellationEvidence,
	prepared serviceauthority.ManifestPayload,
) bool {
	canonicalPreparation, err := json.Marshal(evidence.Preparation)
	return err == nil && prepared.Migration != nil &&
		current.State == DeviceSyncScopeStandby &&
		current.ActiveExportWriteFenceID == nil &&
		current.ActiveMigrationImportID != nil &&
		*current.ActiveMigrationImportID == prepared.Migration.MigrationID &&
		imported.PrincipalID == current.PrincipalID &&
		imported.TenantID == current.TenantID &&
		imported.MigrationID == prepared.Migration.MigrationID &&
		imported.ExportingDeploymentID == prepared.Migration.SourceDeploymentID &&
		imported.ImportingDeploymentID == prepared.Migration.TargetDeploymentID &&
		bytes.Equal(imported.CanonicalPreparationRecord, canonicalPreparation)
}

func validateDeviceSyncActivationTarget(
	ctx context.Context,
	tx pgx.Tx,
	current DeviceSyncScopeEnforcement,
	evidence serviceauthority.MigrationActivationEvidence,
	snapshot serviceauthority.MigrationSnapshotPayload,
) error {
	if current.State != DeviceSyncScopeStandby ||
		current.ActiveExportWriteFenceID != nil ||
		current.ActiveMigrationImportID == nil ||
		*current.ActiveMigrationImportID != snapshot.MigrationID {
		return ErrDeviceSyncMigrationImportConflict
	}
	imported, found, err := loadDeviceSyncMigrationImport(
		ctx, tx, current.PrincipalID, snapshot.MigrationID,
		snapshot.ImportingDeploymentID, "FOR SHARE",
	)
	if err != nil {
		return err
	}
	if !found || !deviceSyncActivationTargetRecordMatches(
		current, imported, evidence, snapshot,
	) {
		return ErrDeviceSyncMigrationImportConflict
	}
	return nil
}

func deviceSyncActivationTargetRecordMatches(
	current DeviceSyncScopeEnforcement,
	imported DeviceSyncMigrationImportRecord,
	evidence serviceauthority.MigrationActivationEvidence,
	snapshot serviceauthority.MigrationSnapshotPayload,
) bool {
	preparationRecord, preparationErr := json.Marshal(evidence.Preparation)
	snapshotRecord, snapshotErr := json.Marshal(evidence.Snapshot)
	return preparationErr == nil && snapshotErr == nil &&
		current.State == DeviceSyncScopeStandby &&
		current.ActiveExportWriteFenceID == nil &&
		current.ActiveMigrationImportID != nil &&
		*current.ActiveMigrationImportID == snapshot.MigrationID &&
		imported.PrincipalID == current.PrincipalID &&
		imported.TenantID == current.TenantID &&
		imported.MigrationID == snapshot.MigrationID &&
		imported.ImportingDeploymentID == snapshot.ImportingDeploymentID &&
		bytes.Equal(imported.CanonicalPreparationRecord, preparationRecord) &&
		bytes.Equal(imported.CanonicalSnapshotRecord, snapshotRecord) &&
		imported.SnapshotID == snapshot.SnapshotID &&
		imported.ExportWriteFenceID == snapshot.ExportWriteFenceID &&
		imported.StateCommitmentDigest == snapshot.StateCommitmentDigest
}

func validateDeviceSyncActivationSource(
	ctx context.Context,
	tx pgx.Tx,
	current DeviceSyncScopeEnforcement,
	evidence serviceauthority.MigrationActivationEvidence,
	snapshot serviceauthority.MigrationSnapshotPayload,
) error {
	if current.State != DeviceSyncScopeExportFenced ||
		current.ActiveMigrationImportID != nil ||
		current.ActiveExportWriteFenceID == nil ||
		*current.ActiveExportWriteFenceID != snapshot.ExportWriteFenceID {
		return ErrDeviceSyncMigrationImportConflict
	}
	exported, found, err := loadDeviceSyncMigrationExport(
		ctx, tx, current.PrincipalID, snapshot.ExportWriteFenceID, "FOR SHARE",
	)
	if err != nil {
		return err
	}
	if !found || !deviceSyncActivationSourceRecordMatches(
		current, exported, evidence, snapshot,
	) {
		return ErrDeviceSyncMigrationImportConflict
	}
	return nil
}

func deviceSyncActivationSourceRecordMatches(
	current DeviceSyncScopeEnforcement,
	exported DeviceSyncMigrationExportRecord,
	evidence serviceauthority.MigrationActivationEvidence,
	snapshot serviceauthority.MigrationSnapshotPayload,
) bool {
	return current.State == DeviceSyncScopeExportFenced &&
		current.ActiveMigrationImportID == nil &&
		current.ActiveExportWriteFenceID != nil &&
		*current.ActiveExportWriteFenceID == snapshot.ExportWriteFenceID &&
		exported.PrincipalID == current.PrincipalID &&
		exported.TenantID == current.TenantID &&
		exported.MigrationID == snapshot.MigrationID &&
		exported.SnapshotID == snapshot.SnapshotID &&
		exported.ExportWriteFenceID == snapshot.ExportWriteFenceID &&
		exported.ExportingDeploymentID == snapshot.ExportingDeploymentID &&
		exported.ImportingDeploymentID == snapshot.ImportingDeploymentID &&
		bytes.Equal(exported.CanonicalSnapshotPayload, evidence.Snapshot.Payload) &&
		exported.StateCommitmentDigest == snapshot.StateCommitmentDigest
}

func deviceSyncAuthorityMatchesExactManifest(
	authority *DeviceSyncScopeAuthority,
	manifest serviceauthority.Manifest,
	evidenceDigest string,
) bool {
	if authority == nil || authority.ValidatedAtMilliseconds < 0 {
		return false
	}
	expected, err := DeviceSyncScopeAuthorityFromManifest(
		manifest, &evidenceDigest, authority.ValidatedAtMilliseconds,
	)
	return err == nil && deviceSyncScopeAuthorityEqual(authority, &expected)
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
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel: pgx.RepeatableRead,
	})
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

// ImportPreparedDeviceSyncMigrationStandby authenticates one complete prepared
// transfer, invokes the trusted semantic-row materializer, and atomically
// installs immutable import evidence plus a target-local standby enforcement
// row. The target remains non-writable because the signed preparation continues
// to name the source deployment as active.
//
// This is a headless store primitive. It does not copy artifact bytes,
// independently re-materialize StateCommitmentDigest, sign readiness, activate
// the target, or expose an HTTP/operator route. An exact already-committed retry
// is returned before temporal validation and never invokes materializer.
func (s *RelayStore) importPreparedDeviceSyncMigrationStandby(
	ctx context.Context,
	localDeploymentID uuid.UUID,
	preparation serviceauthority.MigrationPreparation,
	snapshot serviceauthority.MigrationSnapshot,
	anchor serviceauthority.TrustAnchor,
	initial DeviceSyncInitialAuthorityEvidence,
	nowMilliseconds int64,
	materializer deviceSyncStandbyImportMaterializer,
) (DeviceSyncMigrationImportRecord, error) {
	candidate, initialAuthority, err := buildDeviceSyncMigrationImportCandidate(
		localDeploymentID, preparation, snapshot, anchor, initial, nowMilliseconds,
	)
	if err != nil {
		return DeviceSyncMigrationImportRecord{}, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return DeviceSyncMigrationImportRecord{}, fmt.Errorf(
			"begin Device Sync migration import: %w", err,
		)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
		SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))
	`, candidate.PrincipalID); err != nil {
		return DeviceSyncMigrationImportRecord{}, fmt.Errorf(
			"lock Device Sync migration import scope: %w", err,
		)
	}

	existing, found, err := loadDeviceSyncMigrationImport(
		ctx, tx, candidate.PrincipalID, candidate.MigrationID,
		candidate.ImportingDeploymentID, "FOR SHARE",
	)
	if err != nil {
		return DeviceSyncMigrationImportRecord{}, err
	}
	if found {
		if !sameDeviceSyncMigrationImportIdentity(existing, candidate) {
			return DeviceSyncMigrationImportRecord{}, ErrDeviceSyncMigrationImportConflict
		}
		return cloneDeviceSyncMigrationImportRecord(existing), nil
	}

	validated, err := snapshot.ValidatePreparedTransfer(
		preparation, anchor, nowMilliseconds,
	)
	if err != nil || !validatedDeviceSyncMigrationTransferMatchesCandidate(
		validated, candidate, localDeploymentID,
	) {
		return DeviceSyncMigrationImportRecord{}, serviceauthority.ErrInvalid
	}
	if materializer == nil {
		return DeviceSyncMigrationImportRecord{}, serviceauthority.ErrInvalid
	}
	var collision bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM device_sync_principals WHERE principal_id=$1
			UNION ALL
			SELECT 1 FROM relay_tenants WHERE tenant_id=$1
			UNION ALL
			SELECT 1 FROM device_sync_scope_enforcement
			WHERE principal_id=$1 OR tenant_id=$1
			UNION ALL
			SELECT 1 FROM device_sync_migration_imports
			WHERE principal_id=$1 OR tenant_id=$1
		)
	`, candidate.PrincipalID).Scan(&collision); err != nil {
		return DeviceSyncMigrationImportRecord{}, fmt.Errorf(
			"check Device Sync migration import collision: %w", err,
		)
	}
	if collision {
		return DeviceSyncMigrationImportRecord{}, ErrDeviceSyncMigrationImportConflict
	}
	if err := materializer(
		ctx, deviceSyncStandbyImportTransaction{tx: tx}, validated,
	); err != nil {
		return DeviceSyncMigrationImportRecord{}, fmt.Errorf(
			"materialize Device Sync standby import: %w", err,
		)
	}
	var semanticParentsExist bool
	var authorityRowsExist bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM device_sync_principals AS principal
			JOIN relay_tenants AS tenant
			  ON tenant.tenant_id=principal.tenant_id
			WHERE principal.principal_id=$1 AND principal.tenant_id=$1
		), EXISTS (
			SELECT 1 FROM device_sync_scope_enforcement
			WHERE principal_id=$1 OR tenant_id=$1
			UNION ALL
			SELECT 1 FROM device_sync_migration_imports
			WHERE principal_id=$1 OR tenant_id=$1
		)
	`, candidate.PrincipalID).Scan(
		&semanticParentsExist, &authorityRowsExist,
	); err != nil {
		return DeviceSyncMigrationImportRecord{}, fmt.Errorf(
			"validate Device Sync standby materialization: %w", err,
		)
	}
	if !semanticParentsExist || authorityRowsExist {
		return DeviceSyncMigrationImportRecord{}, errors.New(
			"Device Sync standby materializer did not create exact semantic parents",
		)
	}

	preparationAuthority, err := DeviceSyncScopeAuthorityFromManifest(
		preparation.PreparationManifest,
		&candidate.PreparationReferenceDigest,
		nowMilliseconds,
	)
	if err != nil || preparationAuthority.Revision != candidate.AuthorityRevision ||
		preparationAuthority.ManifestDigest != candidate.AuthorityManifestDigest ||
		preparationAuthority.ActiveDeploymentID != candidate.ExportingDeploymentID {
		return DeviceSyncMigrationImportRecord{}, serviceauthority.ErrInvalid
	}
	result, err := tx.Exec(ctx, `
		INSERT INTO device_sync_migration_imports (
			principal_id,tenant_id,migration_id,snapshot_id,
			export_write_fence_id,authority_revision,
			authority_manifest_digest,preparation_reference_digest,
			exporting_deployment_id,importing_deployment_id,
			canonical_preparation_record,preparation_record_sha256,
			canonical_snapshot_record,snapshot_record_sha256,
			snapshot_reference_digest,snapshot_payload_sha256,
			state_commitment_digest,canonical_artifact_descriptors,
			artifact_descriptors_sha256,artifact_count,
			service_state_artifact_id,service_state_artifact_byte_count,
			service_state_artifact_transfer_digest,captured_at_milliseconds,
			expires_at_milliseconds,imported_at_milliseconds,
			initial_deployment_id,
			initial_authority_validated_at_milliseconds,
			initial_authority_manifest_digest,
			initial_authority_manifest_record
		) VALUES (
			$1,$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,
			$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29
		)
	`, candidate.PrincipalID, candidate.MigrationID, candidate.SnapshotID,
		candidate.ExportWriteFenceID, int64(candidate.AuthorityRevision),
		candidate.AuthorityManifestDigest, candidate.PreparationReferenceDigest,
		candidate.ExportingDeploymentID, candidate.ImportingDeploymentID,
		candidate.CanonicalPreparationRecord, candidate.PreparationRecordSHA256,
		candidate.CanonicalSnapshotRecord, candidate.SnapshotRecordSHA256,
		candidate.SnapshotReferenceDigest, candidate.SnapshotPayloadSHA256,
		candidate.StateCommitmentDigest, candidate.CanonicalArtifactDescriptors,
		candidate.ArtifactDescriptorsSHA256, candidate.ArtifactCount,
		candidate.ServiceStateArtifactID, candidate.ServiceStateArtifactByteCount,
		candidate.ServiceStateArtifactTransferDigest,
		candidate.CapturedAtMilliseconds, candidate.ExpiresAtMilliseconds,
		candidate.ImportedAtMilliseconds, candidate.InitialDeploymentID,
		candidate.InitialAuthorityValidatedAtMilliseconds,
		candidate.InitialAuthorityManifestDigest,
		candidate.InitialAuthorityManifestRecord)
	if err != nil {
		return DeviceSyncMigrationImportRecord{}, fmt.Errorf(
			"insert Device Sync migration import evidence: %w", err,
		)
	}
	if result.RowsAffected() != 1 {
		return DeviceSyncMigrationImportRecord{}, errors.New(
			"Device Sync migration import insert affected an unexpected row count",
		)
	}
	result, err = tx.Exec(ctx, `
		INSERT INTO device_sync_scope_enforcement (
			principal_id,tenant_id,state,local_deployment_id,
			initial_deployment_id,
			initial_authority_validated_at_milliseconds,
			initial_authority_manifest_digest,
			initial_authority_manifest_record,
			authority_validated_at_milliseconds,authority_revision,
			authority_manifest_digest,authority_manifest_record,
			active_deployment_id,transition_evidence_digest,
			active_migration_import_id
		) VALUES (
			$1,$1,'standby',$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13
		)
	`, candidate.PrincipalID, candidate.ImportingDeploymentID,
		initialAuthority.ActiveDeploymentID,
		initialAuthority.ValidatedAtMilliseconds,
		initialAuthority.ManifestDigest, initialAuthority.ManifestRecord,
		preparationAuthority.ValidatedAtMilliseconds,
		int64(preparationAuthority.Revision), preparationAuthority.ManifestDigest,
		preparationAuthority.ManifestRecord,
		preparationAuthority.ActiveDeploymentID,
		preparationAuthority.TransitionEvidenceDigest, candidate.MigrationID)
	if err != nil {
		return DeviceSyncMigrationImportRecord{}, fmt.Errorf(
			"insert Device Sync prepared-target standby authority: %w", err,
		)
	}
	if result.RowsAffected() != 1 {
		return DeviceSyncMigrationImportRecord{}, errors.New(
			"Device Sync prepared-target standby insert affected an unexpected row count",
		)
	}

	stored, found, err := loadDeviceSyncMigrationImport(
		ctx, tx, candidate.PrincipalID, candidate.MigrationID,
		candidate.ImportingDeploymentID, "FOR SHARE",
	)
	if err != nil || !found ||
		!sameDeviceSyncMigrationImportIdentity(stored, candidate) {
		if err != nil {
			return DeviceSyncMigrationImportRecord{}, err
		}
		return DeviceSyncMigrationImportRecord{}, errors.New(
			"persisted Device Sync migration import differs from authenticated evidence",
		)
	}
	standby, err := loadDeviceSyncScopeEnforcement(
		ctx, tx, candidate.PrincipalID, "FOR SHARE",
	)
	if err != nil || standby.State != DeviceSyncScopeStandby ||
		standby.LocalDeploymentID == nil ||
		*standby.LocalDeploymentID != candidate.ImportingDeploymentID ||
		standby.Authority == nil ||
		standby.Authority.ActiveDeploymentID != candidate.ExportingDeploymentID ||
		standby.ActiveMigrationImportID == nil ||
		*standby.ActiveMigrationImportID != candidate.MigrationID {
		if err != nil {
			return DeviceSyncMigrationImportRecord{}, err
		}
		return DeviceSyncMigrationImportRecord{}, errors.New(
			"persisted Device Sync prepared-target standby is inconsistent",
		)
	}
	if err := tx.Commit(ctx); err != nil {
		return DeviceSyncMigrationImportRecord{}, fmt.Errorf(
			"commit Device Sync migration import: %w", err,
		)
	}
	return cloneDeviceSyncMigrationImportRecord(stored), nil
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

func buildDeviceSyncMigrationImportCandidate(
	localDeploymentID uuid.UUID,
	preparation serviceauthority.MigrationPreparation,
	snapshot serviceauthority.MigrationSnapshot,
	anchor serviceauthority.TrustAnchor,
	initial DeviceSyncInitialAuthorityEvidence,
	nowMilliseconds int64,
) (DeviceSyncMigrationImportRecord, DeviceSyncScopeAuthority, error) {
	if localDeploymentID == uuid.Nil || nowMilliseconds < 0 ||
		initial.ValidatedAtMilliseconds < 0 {
		return DeviceSyncMigrationImportRecord{}, DeviceSyncScopeAuthority{},
			serviceauthority.ErrInvalid
	}
	snapshotPayload, err := snapshot.VerifiedPayload(nil)
	if err != nil || snapshotPayload.Scope.Kind != serviceauthority.ScopeDeviceSync ||
		snapshotPayload.ImportingDeploymentID != localDeploymentID {
		return DeviceSyncMigrationImportRecord{}, DeviceSyncScopeAuthority{},
			serviceauthority.ErrInvalid
	}
	historical, err := snapshot.ValidatePreparedTransfer(
		preparation, anchor, snapshotPayload.CapturedAtMilliseconds,
	)
	if err != nil || historical.Snapshot.Scope != snapshotPayload.Scope ||
		historical.Snapshot.SnapshotID != snapshotPayload.SnapshotID ||
		historical.TargetDeploymentOffer.Deployment.DeploymentID != localDeploymentID {
		return DeviceSyncMigrationImportRecord{}, DeviceSyncScopeAuthority{},
			serviceauthority.ErrInvalid
	}
	preparedPayload := historical.PreparationManifest
	preparationManifestDigest, preparationManifestDigestErr :=
		preparation.PreparationManifest.ReferenceDigest()
	preparationReferenceDigest, preparationReferenceDigestErr :=
		preparation.ReferenceDigest()
	snapshotReferenceDigest, snapshotReferenceDigestErr := snapshot.ReferenceDigest()
	if preparationManifestDigestErr != nil ||
		preparationReferenceDigestErr != nil || snapshotReferenceDigestErr != nil ||
		preparedPayload.Revision == 0 || preparedPayload.Revision > math.MaxInt64 ||
		snapshotPayload.AuthorityManifestDigest != preparationManifestDigest {
		return DeviceSyncMigrationImportRecord{}, DeviceSyncScopeAuthority{},
			serviceauthority.ErrInvalid
	}
	initialPayload, err := initial.Manifest.Authorize(
		anchor, initial.ValidatedAtMilliseconds,
	)
	if err != nil || initialPayload.Scope != snapshotPayload.Scope ||
		initialPayload.Revision != 1 ||
		initialPayload.Transition != serviceauthority.TransitionInitialActivation {
		return DeviceSyncMigrationImportRecord{}, DeviceSyncScopeAuthority{},
			serviceauthority.ErrInvalid
	}
	initialAuthority, err := DeviceSyncScopeAuthorityFromManifest(
		initial.Manifest, nil, initial.ValidatedAtMilliseconds,
	)
	if err != nil || initialAuthority.ActiveDeploymentID !=
		initialPayload.ActiveDeployment.DeploymentID {
		return DeviceSyncMigrationImportRecord{}, DeviceSyncScopeAuthority{},
			serviceauthority.ErrInvalid
	}
	canonicalPreparation, preparationRecordSHA256, err :=
		encodeCanonicalDeviceSyncEvidenceRecord(
			preparation, maximumDeviceSyncMigrationEvidenceRecordByteCount,
		)
	if err != nil {
		return DeviceSyncMigrationImportRecord{}, DeviceSyncScopeAuthority{}, err
	}
	preparationManifestRecord, _, err := encodeCanonicalDeviceSyncEvidenceRecord(
		preparation.PreparationManifest,
		maximumDeviceSyncAuthorityRecordByteCount,
	)
	if err != nil {
		return DeviceSyncMigrationImportRecord{}, DeviceSyncScopeAuthority{}, err
	}
	canonicalSnapshot, snapshotRecordSHA256, err :=
		encodeCanonicalDeviceSyncEvidenceRecord(
			snapshot, maximumDeviceSyncMigrationEvidenceRecordByteCount,
		)
	if err != nil {
		return DeviceSyncMigrationImportRecord{}, DeviceSyncScopeAuthority{}, err
	}
	canonicalArtifacts, artifactDescriptorsSHA256, err :=
		encodeCanonicalDeviceSyncEvidenceRecord(
			snapshotPayload.Artifacts, maximumDeviceSyncSnapshotPayloadByteCount,
		)
	if err != nil {
		return DeviceSyncMigrationImportRecord{}, DeviceSyncScopeAuthority{}, err
	}
	var serviceStateArtifact *serviceauthority.MigrationArtifactDescriptor
	for index := range snapshotPayload.Artifacts {
		if snapshotPayload.Artifacts[index].Kind ==
			serviceauthority.ArtifactServiceStateSnapshot {
			candidate := snapshotPayload.Artifacts[index]
			serviceStateArtifact = &candidate
			break
		}
	}
	if serviceStateArtifact == nil {
		return DeviceSyncMigrationImportRecord{}, DeviceSyncScopeAuthority{},
			serviceauthority.ErrInvalid
	}
	snapshotPayloadDigest := sha256.Sum256(snapshot.Payload)
	candidate := DeviceSyncMigrationImportRecord{
		PrincipalID:                             snapshotPayload.Scope.ScopeID,
		TenantID:                                snapshotPayload.Scope.ScopeID,
		MigrationID:                             snapshotPayload.MigrationID,
		SnapshotID:                              snapshotPayload.SnapshotID,
		ExportWriteFenceID:                      snapshotPayload.ExportWriteFenceID,
		AuthorityRevision:                       preparedPayload.Revision,
		AuthorityManifestDigest:                 preparationManifestDigest,
		PreparationReferenceDigest:              preparationReferenceDigest,
		ExportingDeploymentID:                   snapshotPayload.ExportingDeploymentID,
		ImportingDeploymentID:                   snapshotPayload.ImportingDeploymentID,
		CanonicalPreparationRecord:              canonicalPreparation,
		PreparationRecordSHA256:                 preparationRecordSHA256,
		PreparationManifestRecord:               preparationManifestRecord,
		CanonicalSnapshotRecord:                 canonicalSnapshot,
		SnapshotRecordSHA256:                    snapshotRecordSHA256,
		SnapshotReferenceDigest:                 snapshotReferenceDigest,
		SnapshotPayloadSHA256:                   hex.EncodeToString(snapshotPayloadDigest[:]),
		StateCommitmentDigest:                   snapshotPayload.StateCommitmentDigest,
		CanonicalArtifactDescriptors:            canonicalArtifacts,
		ArtifactDescriptorsSHA256:               artifactDescriptorsSHA256,
		ArtifactCount:                           len(snapshotPayload.Artifacts),
		ServiceStateArtifactID:                  serviceStateArtifact.ArtifactID,
		ServiceStateArtifactByteCount:           serviceStateArtifact.ByteCount,
		ServiceStateArtifactTransferDigest:      serviceStateArtifact.TransferDigest,
		CapturedAtMilliseconds:                  snapshotPayload.CapturedAtMilliseconds,
		ExpiresAtMilliseconds:                   snapshotPayload.ExpiresAtMilliseconds,
		ImportedAtMilliseconds:                  nowMilliseconds,
		InitialDeploymentID:                     initialAuthority.ActiveDeploymentID,
		InitialAuthorityValidatedAtMilliseconds: initialAuthority.ValidatedAtMilliseconds,
		InitialAuthorityManifestDigest:          initialAuthority.ManifestDigest,
		InitialAuthorityManifestRecord:          initialAuthority.ManifestRecord,
	}
	return candidate, initialAuthority, nil
}

func validatedDeviceSyncMigrationTransferMatchesCandidate(
	validated serviceauthority.ValidatedMigrationTransfer,
	candidate DeviceSyncMigrationImportRecord,
	localDeploymentID uuid.UUID,
) bool {
	return validated.Snapshot.Scope.Kind == serviceauthority.ScopeDeviceSync &&
		validated.Snapshot.Scope.ScopeID == candidate.PrincipalID &&
		validated.Migration.MigrationID == candidate.MigrationID &&
		validated.Migration.SourceDeploymentID == candidate.ExportingDeploymentID &&
		validated.Migration.TargetDeploymentID == candidate.ImportingDeploymentID &&
		validated.PreparationManifest.Revision == candidate.AuthorityRevision &&
		validated.Snapshot.SnapshotID == candidate.SnapshotID &&
		validated.Snapshot.ExportWriteFenceID == candidate.ExportWriteFenceID &&
		validated.Snapshot.StateCommitmentDigest == candidate.StateCommitmentDigest &&
		validated.Snapshot.ExportingDeploymentID == candidate.ExportingDeploymentID &&
		validated.Snapshot.ImportingDeploymentID == candidate.ImportingDeploymentID &&
		validated.TargetDeploymentOffer.Deployment.DeploymentID == localDeploymentID &&
		candidate.ImportingDeploymentID == localDeploymentID &&
		candidate.ImportedAtMilliseconds >= candidate.CapturedAtMilliseconds &&
		candidate.ImportedAtMilliseconds < candidate.ExpiresAtMilliseconds
}

func encodeCanonicalDeviceSyncEvidenceRecord(
	value any,
	maximumByteCount int,
) ([]byte, string, error) {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) == 0 || maximumByteCount <= 0 ||
		len(encoded) > maximumByteCount {
		return nil, "", serviceauthority.ErrInvalid
	}
	digest := sha256.Sum256(encoded)
	return encoded, hex.EncodeToString(digest[:]), nil
}

func sameDeviceSyncMigrationImportIdentity(
	left DeviceSyncMigrationImportRecord,
	right DeviceSyncMigrationImportRecord,
) bool {
	return left.PrincipalID == right.PrincipalID && left.TenantID == right.TenantID &&
		left.MigrationID == right.MigrationID && left.SnapshotID == right.SnapshotID &&
		left.ExportWriteFenceID == right.ExportWriteFenceID &&
		left.AuthorityRevision == right.AuthorityRevision &&
		left.AuthorityManifestDigest == right.AuthorityManifestDigest &&
		left.PreparationReferenceDigest == right.PreparationReferenceDigest &&
		left.ExportingDeploymentID == right.ExportingDeploymentID &&
		left.ImportingDeploymentID == right.ImportingDeploymentID &&
		bytes.Equal(left.CanonicalPreparationRecord, right.CanonicalPreparationRecord) &&
		left.PreparationRecordSHA256 == right.PreparationRecordSHA256 &&
		bytes.Equal(left.PreparationManifestRecord, right.PreparationManifestRecord) &&
		bytes.Equal(left.CanonicalSnapshotRecord, right.CanonicalSnapshotRecord) &&
		left.SnapshotRecordSHA256 == right.SnapshotRecordSHA256 &&
		left.SnapshotReferenceDigest == right.SnapshotReferenceDigest &&
		left.SnapshotPayloadSHA256 == right.SnapshotPayloadSHA256 &&
		left.StateCommitmentDigest == right.StateCommitmentDigest &&
		bytes.Equal(
			left.CanonicalArtifactDescriptors,
			right.CanonicalArtifactDescriptors,
		) &&
		left.ArtifactDescriptorsSHA256 == right.ArtifactDescriptorsSHA256 &&
		left.ArtifactCount == right.ArtifactCount &&
		left.ServiceStateArtifactID == right.ServiceStateArtifactID &&
		left.ServiceStateArtifactByteCount == right.ServiceStateArtifactByteCount &&
		left.ServiceStateArtifactTransferDigest ==
			right.ServiceStateArtifactTransferDigest &&
		left.CapturedAtMilliseconds == right.CapturedAtMilliseconds &&
		left.ExpiresAtMilliseconds == right.ExpiresAtMilliseconds &&
		left.InitialDeploymentID == right.InitialDeploymentID &&
		left.InitialAuthorityValidatedAtMilliseconds ==
			right.InitialAuthorityValidatedAtMilliseconds &&
		left.InitialAuthorityManifestDigest == right.InitialAuthorityManifestDigest &&
		bytes.Equal(
			left.InitialAuthorityManifestRecord,
			right.InitialAuthorityManifestRecord,
		)
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
		SELECT tenant_id,state,local_deployment_id,
			initial_deployment_id,
			initial_authority_validated_at_milliseconds,
			initial_authority_manifest_digest,
			initial_authority_manifest_record,authority_revision,
			authority_manifest_digest,authority_manifest_record,
			active_deployment_id,transition_evidence_digest,
			authority_validated_at_milliseconds,
			active_export_write_fence_id,active_migration_import_id
		FROM device_sync_scope_enforcement
		WHERE principal_id=$1 AND tenant_id=$1
	`
	if lockClause != "" {
		query += " " + lockClause
	}
	current := DeviceSyncScopeEnforcement{PrincipalID: principalID}
	var revision *int64
	var initialDeploymentID *uuid.UUID
	var initialAuthorityValidatedAtMilliseconds *int64
	var initialAuthorityManifestDigest *string
	var initialAuthorityManifestRecord []byte
	var manifestDigest *string
	var manifestRecord []byte
	var activeDeploymentID *uuid.UUID
	var transitionEvidenceDigest *string
	var authorityValidatedAtMilliseconds *int64
	err := querier.QueryRow(ctx, query, principalID).Scan(
		&current.TenantID, &current.State, &current.LocalDeploymentID,
		&initialDeploymentID, &initialAuthorityValidatedAtMilliseconds,
		&initialAuthorityManifestDigest, &initialAuthorityManifestRecord,
		&revision, &manifestDigest, &manifestRecord, &activeDeploymentID,
		&transitionEvidenceDigest, &authorityValidatedAtMilliseconds,
		&current.ActiveExportWriteFenceID, &current.ActiveMigrationImportID,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return DeviceSyncScopeEnforcement{}, ErrDeviceSyncScopeEnforcementNotFound
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
	allAuthorityNil := current.LocalDeploymentID == nil &&
		initialDeploymentID == nil &&
		initialAuthorityValidatedAtMilliseconds == nil &&
		initialAuthorityManifestDigest == nil &&
		len(initialAuthorityManifestRecord) == 0 && revision == nil &&
		manifestDigest == nil && len(manifestRecord) == 0 &&
		activeDeploymentID == nil && transitionEvidenceDigest == nil &&
		authorityValidatedAtMilliseconds == nil &&
		current.ActiveMigrationImportID == nil
	if allAuthorityNil {
		if current.State != DeviceSyncScopeStandby ||
			current.ActiveExportWriteFenceID != nil {
			return DeviceSyncScopeEnforcement{}, errors.New(
				"stored Device Sync scope lacks required authority",
			)
		}
		return current, nil
	}
	if current.LocalDeploymentID == nil || initialDeploymentID == nil ||
		initialAuthorityValidatedAtMilliseconds == nil ||
		initialAuthorityManifestDigest == nil ||
		len(initialAuthorityManifestRecord) == 0 ||
		revision == nil || *revision <= 0 ||
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
	initialManifest, err := decodeCanonicalDeviceSyncAuthorityManifest(
		initialAuthorityManifestRecord,
	)
	if err != nil {
		return DeviceSyncScopeEnforcement{}, err
	}
	initialPayload, err := initialManifest.VerifiedPayload()
	initialDigest, digestErr := initialManifest.ReferenceDigest()
	if err != nil || digestErr != nil ||
		*initialAuthorityValidatedAtMilliseconds < 0 ||
		initialPayload.Validate(initialAuthorityValidatedAtMilliseconds) != nil ||
		initialPayload.Scope.Kind != serviceauthority.ScopeDeviceSync ||
		initialPayload.Scope.ScopeID != principalID || initialPayload.Revision != 1 ||
		initialPayload.Transition != serviceauthority.TransitionInitialActivation ||
		initialPayload.ActiveDeployment.DeploymentID != *initialDeploymentID ||
		initialDigest != *initialAuthorityManifestDigest {
		return DeviceSyncScopeEnforcement{}, errors.New(
			"stored Device Sync initial authority is inconsistent",
		)
	}
	localMatchesActive := *current.LocalDeploymentID == authority.ActiveDeploymentID
	preparedTargetStandby := current.State == DeviceSyncScopeStandby &&
		!localMatchesActive && current.ActiveMigrationImportID != nil
	if current.State == DeviceSyncScopeStandby && !localMatchesActive &&
		!preparedTargetStandby ||
		(current.State == DeviceSyncScopeWritable ||
			current.State == DeviceSyncScopeExportFenced) && !localMatchesActive ||
		((current.State == DeviceSyncScopeExportFenced) !=
			(current.ActiveExportWriteFenceID != nil)) ||
		!preparedTargetStandby && current.ActiveMigrationImportID != nil {
		return DeviceSyncScopeEnforcement{}, errors.New(
			"stored Device Sync deployment or export fence state is inconsistent",
		)
	}
	if preparedTargetStandby {
		imported, found, err := loadDeviceSyncMigrationImport(
			ctx, querier, principalID, *current.ActiveMigrationImportID,
			*current.LocalDeploymentID, "",
		)
		if err != nil {
			return DeviceSyncScopeEnforcement{}, err
		}
		if !found || imported.ExportingDeploymentID != authority.ActiveDeploymentID ||
			imported.AuthorityRevision != authority.Revision ||
			imported.AuthorityManifestDigest != authority.ManifestDigest ||
			authority.TransitionEvidenceDigest == nil ||
			imported.PreparationReferenceDigest !=
				*authority.TransitionEvidenceDigest ||
			imported.InitialDeploymentID != *initialDeploymentID ||
			imported.InitialAuthorityValidatedAtMilliseconds !=
				*initialAuthorityValidatedAtMilliseconds ||
			imported.InitialAuthorityManifestDigest !=
				*initialAuthorityManifestDigest ||
			!bytes.Equal(
				imported.InitialAuthorityManifestRecord,
				initialAuthorityManifestRecord,
			) ||
			!bytes.Equal(imported.PreparationManifestRecord, manifestRecord) {
			return DeviceSyncScopeEnforcement{}, errors.New(
				"stored Device Sync prepared-target standby lacks exact import evidence",
			)
		}
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

func loadDeviceSyncMigrationImport(
	ctx context.Context,
	querier relayQuerier,
	principalID uuid.UUID,
	migrationID uuid.UUID,
	importingDeploymentID uuid.UUID,
	lockClause string,
) (DeviceSyncMigrationImportRecord, bool, error) {
	query := `
		SELECT snapshot_id,export_write_fence_id,authority_revision,
			authority_manifest_digest,preparation_reference_digest,
			exporting_deployment_id,canonical_preparation_record,
			preparation_record_sha256,canonical_snapshot_record,
			snapshot_record_sha256,snapshot_reference_digest,
			snapshot_payload_sha256,state_commitment_digest,
			canonical_artifact_descriptors,artifact_descriptors_sha256,
			artifact_count,service_state_artifact_id,
			service_state_artifact_byte_count,
			service_state_artifact_transfer_digest,
			captured_at_milliseconds,expires_at_milliseconds,
			imported_at_milliseconds,initial_deployment_id,
			initial_authority_validated_at_milliseconds,
			initial_authority_manifest_digest,
			initial_authority_manifest_record
		FROM device_sync_migration_imports
		WHERE principal_id=$1 AND tenant_id=$1 AND migration_id=$2
		  AND importing_deployment_id=$3
	`
	if lockClause != "" {
		query += " " + lockClause
	}
	stored := DeviceSyncMigrationImportRecord{
		PrincipalID: principalID, TenantID: principalID,
		MigrationID: migrationID, ImportingDeploymentID: importingDeploymentID,
	}
	var authorityRevision int64
	err := querier.QueryRow(
		ctx, query, principalID, migrationID, importingDeploymentID,
	).Scan(
		&stored.SnapshotID, &stored.ExportWriteFenceID, &authorityRevision,
		&stored.AuthorityManifestDigest, &stored.PreparationReferenceDigest,
		&stored.ExportingDeploymentID, &stored.CanonicalPreparationRecord,
		&stored.PreparationRecordSHA256, &stored.CanonicalSnapshotRecord,
		&stored.SnapshotRecordSHA256, &stored.SnapshotReferenceDigest,
		&stored.SnapshotPayloadSHA256, &stored.StateCommitmentDigest,
		&stored.CanonicalArtifactDescriptors, &stored.ArtifactDescriptorsSHA256,
		&stored.ArtifactCount, &stored.ServiceStateArtifactID,
		&stored.ServiceStateArtifactByteCount,
		&stored.ServiceStateArtifactTransferDigest,
		&stored.CapturedAtMilliseconds, &stored.ExpiresAtMilliseconds,
		&stored.ImportedAtMilliseconds, &stored.InitialDeploymentID,
		&stored.InitialAuthorityValidatedAtMilliseconds,
		&stored.InitialAuthorityManifestDigest,
		&stored.InitialAuthorityManifestRecord,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return DeviceSyncMigrationImportRecord{}, false, nil
	}
	if err != nil {
		return DeviceSyncMigrationImportRecord{}, false, fmt.Errorf(
			"load Device Sync migration import: %w", err,
		)
	}
	if authorityRevision <= 0 ||
		!validDeviceSyncDigest(stored.AuthorityManifestDigest) ||
		!validDeviceSyncDigest(stored.PreparationReferenceDigest) ||
		!validDeviceSyncDigest(stored.PreparationRecordSHA256) ||
		!validDeviceSyncDigest(stored.SnapshotRecordSHA256) ||
		!validDeviceSyncDigest(stored.SnapshotReferenceDigest) ||
		!validDeviceSyncDigest(stored.SnapshotPayloadSHA256) ||
		!validDeviceSyncDigest(stored.StateCommitmentDigest) ||
		!validDeviceSyncDigest(stored.ArtifactDescriptorsSHA256) ||
		!validDeviceSyncDigest(stored.ServiceStateArtifactTransferDigest) ||
		stored.ExportingDeploymentID == uuid.Nil ||
		stored.ImportingDeploymentID == uuid.Nil ||
		stored.ExportingDeploymentID == stored.ImportingDeploymentID ||
		stored.SnapshotID == uuid.Nil || stored.ExportWriteFenceID == uuid.Nil ||
		stored.ArtifactCount <= 0 || stored.ServiceStateArtifactID == uuid.Nil ||
		stored.ServiceStateArtifactByteCount < 0 ||
		stored.CapturedAtMilliseconds < 0 ||
		stored.ExpiresAtMilliseconds <= stored.CapturedAtMilliseconds ||
		stored.ImportedAtMilliseconds < stored.CapturedAtMilliseconds ||
		stored.ImportedAtMilliseconds >= stored.ExpiresAtMilliseconds {
		return DeviceSyncMigrationImportRecord{}, false, errors.New(
			"stored Device Sync migration import has invalid scalar evidence",
		)
	}
	var preparation serviceauthority.MigrationPreparation
	if err := decodeCanonicalDeviceSyncEvidenceRecord(
		stored.CanonicalPreparationRecord,
		maximumDeviceSyncMigrationEvidenceRecordByteCount,
		&preparation,
	); err != nil {
		return DeviceSyncMigrationImportRecord{}, false, err
	}
	preparationRecordDigest := sha256.Sum256(stored.CanonicalPreparationRecord)
	preparationReferenceDigest, referenceErr := preparation.ReferenceDigest()
	currentPayload, currentErr := preparation.CurrentManifest.VerifiedPayload()
	preparedPayload, preparedErr := preparation.PreparationManifest.VerifiedPayload()
	_, successorErr := preparation.PreparationManifest.ValidateSuccessor(
		preparation.CurrentManifest,
	)
	targetOffer, targetErr := preparation.TargetOffer.VerifiedPayload(nil)
	targetDeployment, deploymentErr := targetOffer.DeploymentOffer.VerifiedPayload(nil)
	currentDigest, currentDigestErr := preparation.CurrentManifest.ReferenceDigest()
	targetOfferDigest, targetOfferDigestErr := preparation.TargetOffer.ReferenceDigest()
	preparationManifestDigest, preparationManifestDigestErr :=
		preparation.PreparationManifest.ReferenceDigest()
	preparationManifestRecord, _, preparationManifestRecordErr :=
		encodeCanonicalDeviceSyncEvidenceRecord(
			preparation.PreparationManifest,
			maximumDeviceSyncAuthorityRecordByteCount,
		)
	if referenceErr != nil || currentErr != nil || preparedErr != nil ||
		successorErr != nil || targetErr != nil || deploymentErr != nil ||
		currentDigestErr != nil || targetOfferDigestErr != nil ||
		preparationManifestDigestErr != nil || preparationManifestRecordErr != nil ||
		hex.EncodeToString(preparationRecordDigest[:]) !=
			stored.PreparationRecordSHA256 ||
		preparationReferenceDigest != stored.PreparationReferenceDigest ||
		preparedPayload.Scope.Kind != serviceauthority.ScopeDeviceSync ||
		preparedPayload.Scope.ScopeID != principalID ||
		preparedPayload.Revision != uint64(authorityRevision) ||
		preparedPayload.Transition != serviceauthority.TransitionMigrationPreparation ||
		preparedPayload.Migration == nil || len(preparedPayload.PreparedDeployments) != 1 ||
		currentPayload.Scope != preparedPayload.Scope ||
		targetOffer.Scope != preparedPayload.Scope ||
		targetOffer.SourceManifestDigest != currentDigest ||
		targetOffer.MigrationID != migrationID ||
		targetOfferDigest != preparedPayload.Migration.TargetMigrationOfferDigest ||
		preparedPayload.Migration.MigrationID != migrationID ||
		preparedPayload.Migration.SourceDeploymentID !=
			stored.ExportingDeploymentID ||
		preparedPayload.Migration.TargetDeploymentID != importingDeploymentID ||
		preparedPayload.ActiveDeployment.DeploymentID !=
			stored.ExportingDeploymentID ||
		targetDeployment.Deployment.DeploymentID != importingDeploymentID ||
		!reflect.DeepEqual(
			preparedPayload.PreparedDeployments[0], targetDeployment.Deployment,
		) ||
		preparationManifestDigest != stored.AuthorityManifestDigest {
		return DeviceSyncMigrationImportRecord{}, false, errors.New(
			"stored Device Sync migration preparation evidence is inconsistent",
		)
	}
	stored.PreparationManifestRecord = preparationManifestRecord

	var snapshot serviceauthority.MigrationSnapshot
	if err := decodeCanonicalDeviceSyncEvidenceRecord(
		stored.CanonicalSnapshotRecord,
		maximumDeviceSyncMigrationEvidenceRecordByteCount,
		&snapshot,
	); err != nil {
		return DeviceSyncMigrationImportRecord{}, false, err
	}
	snapshotRecordDigest := sha256.Sum256(stored.CanonicalSnapshotRecord)
	snapshotPayloadDigest := sha256.Sum256(snapshot.Payload)
	snapshotReferenceDigest, snapshotReferenceErr := snapshot.ReferenceDigest()
	snapshotPayload, snapshotErr := snapshot.VerifiedPayload(nil)
	if snapshotReferenceErr != nil || snapshotErr != nil ||
		hex.EncodeToString(snapshotRecordDigest[:]) != stored.SnapshotRecordSHA256 ||
		hex.EncodeToString(snapshotPayloadDigest[:]) != stored.SnapshotPayloadSHA256 ||
		snapshotReferenceDigest != stored.SnapshotReferenceDigest ||
		snapshotPayload.Scope != preparedPayload.Scope ||
		snapshotPayload.MigrationID != migrationID ||
		snapshotPayload.SnapshotID != stored.SnapshotID ||
		snapshotPayload.ExportWriteFenceID != stored.ExportWriteFenceID ||
		snapshotPayload.AuthorityManifestDigest != stored.AuthorityManifestDigest ||
		snapshotPayload.ExportingDeploymentID != stored.ExportingDeploymentID ||
		snapshotPayload.ImportingDeploymentID != importingDeploymentID ||
		snapshotPayload.StateCommitmentDigest != stored.StateCommitmentDigest ||
		snapshotPayload.CapturedAtMilliseconds != stored.CapturedAtMilliseconds ||
		snapshotPayload.ExpiresAtMilliseconds != stored.ExpiresAtMilliseconds ||
		snapshot.Signature.SignerID != preparedPayload.ActiveDeployment.DeploymentID ||
		snapshot.Signature.PublicSigningKeyX963 !=
			preparedPayload.ActiveDeployment.PublicSigningKeyX963 ||
		snapshot.Signature.SigningKeyFingerprint !=
			preparedPayload.ActiveDeployment.SigningKeyFingerprint {
		return DeviceSyncMigrationImportRecord{}, false, errors.New(
			"stored Device Sync signed migration snapshot is inconsistent",
		)
	}
	var artifacts []serviceauthority.MigrationArtifactDescriptor
	if err := decodeCanonicalDeviceSyncEvidenceRecord(
		stored.CanonicalArtifactDescriptors,
		maximumDeviceSyncSnapshotPayloadByteCount,
		&artifacts,
	); err != nil {
		return DeviceSyncMigrationImportRecord{}, false, err
	}
	artifactDigest := sha256.Sum256(stored.CanonicalArtifactDescriptors)
	var serviceStateArtifact *serviceauthority.MigrationArtifactDescriptor
	for index := range artifacts {
		if artifacts[index].Kind == serviceauthority.ArtifactServiceStateSnapshot {
			candidate := artifacts[index]
			serviceStateArtifact = &candidate
			break
		}
	}
	if len(artifacts) != stored.ArtifactCount ||
		!reflect.DeepEqual(artifacts, snapshotPayload.Artifacts) ||
		hex.EncodeToString(artifactDigest[:]) != stored.ArtifactDescriptorsSHA256 ||
		serviceStateArtifact == nil ||
		serviceStateArtifact.ArtifactID != stored.ServiceStateArtifactID ||
		serviceStateArtifact.ByteCount != stored.ServiceStateArtifactByteCount ||
		serviceStateArtifact.TransferDigest !=
			stored.ServiceStateArtifactTransferDigest {
		return DeviceSyncMigrationImportRecord{}, false, errors.New(
			"stored Device Sync migration artifact evidence is inconsistent",
		)
	}
	initialManifest, err := decodeCanonicalDeviceSyncAuthorityManifest(
		stored.InitialAuthorityManifestRecord,
	)
	if err != nil {
		return DeviceSyncMigrationImportRecord{}, false, err
	}
	initialPayload, initialErr := initialManifest.VerifiedPayload()
	initialDigest, initialDigestErr := initialManifest.ReferenceDigest()
	if initialErr != nil || initialDigestErr != nil ||
		initialPayload.Validate(
			&stored.InitialAuthorityValidatedAtMilliseconds,
		) != nil || initialPayload.Scope != preparedPayload.Scope ||
		initialPayload.Revision != 1 ||
		initialPayload.Transition != serviceauthority.TransitionInitialActivation ||
		initialPayload.ActiveDeployment.DeploymentID != stored.InitialDeploymentID ||
		initialDigest != stored.InitialAuthorityManifestDigest {
		return DeviceSyncMigrationImportRecord{}, false, errors.New(
			"stored Device Sync migration initial authority is inconsistent",
		)
	}
	stored.AuthorityRevision = uint64(authorityRevision)
	return cloneDeviceSyncMigrationImportRecord(stored), true, nil
}

func decodeCanonicalDeviceSyncEvidenceRecord(
	record []byte,
	maximumByteCount int,
	value any,
) error {
	if len(record) == 0 || maximumByteCount <= 0 || len(record) > maximumByteCount {
		return serviceauthority.ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(record))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return serviceauthority.ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return serviceauthority.ErrInvalid
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, record) {
		return serviceauthority.ErrInvalid
	}
	return nil
}

func cloneDeviceSyncMigrationImportRecord(
	record DeviceSyncMigrationImportRecord,
) DeviceSyncMigrationImportRecord {
	cloned := record
	cloned.CanonicalPreparationRecord = append(
		[]byte(nil), record.CanonicalPreparationRecord...,
	)
	cloned.PreparationManifestRecord = append(
		[]byte(nil), record.PreparationManifestRecord...,
	)
	cloned.CanonicalSnapshotRecord = append(
		[]byte(nil), record.CanonicalSnapshotRecord...,
	)
	cloned.CanonicalArtifactDescriptors = append(
		[]byte(nil), record.CanonicalArtifactDescriptors...,
	)
	cloned.InitialAuthorityManifestRecord = append(
		[]byte(nil), record.InitialAuthorityManifestRecord...,
	)
	return cloned
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
	cloned.ActiveMigrationImportID = cloneUUIDPointer(value.ActiveMigrationImportID)
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
