package postgres

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

// DeviceSyncMigrationStagedArtifacts are seekable, locally staged artifact
// files. Their expected byte counts and transfer digests come only from the
// authenticated migration snapshot; caller-supplied metadata is not trusted.
type DeviceSyncMigrationStagedArtifacts struct {
	ServiceState  io.ReadSeeker
	BlobInventory io.ReadSeeker
}

// ImportPreparedDeviceSyncMigrationStandby is the canonical prepared-target
// import seam. It authenticates the complete signed transfer, binds exact
// staged artifact bytes to the signed descriptors and state commitment,
// independently reproduces the imported logical state, and atomically installs
// immutable import evidence plus non-writable standby authority.
//
// It does not copy or verify the opaque blob bytes named by BlobInventory and
// therefore does not establish target readiness.
func (s *RelayStore) ImportPreparedDeviceSyncMigrationStandby(
	ctx context.Context,
	localDeploymentID uuid.UUID,
	preparation serviceauthority.MigrationPreparation,
	snapshot serviceauthority.MigrationSnapshot,
	anchor serviceauthority.TrustAnchor,
	initial DeviceSyncInitialAuthorityEvidence,
	nowMilliseconds int64,
	staged DeviceSyncMigrationStagedArtifacts,
) (DeviceSyncMigrationImportRecord, error) {
	return s.importPreparedDeviceSyncMigrationStandby(
		ctx, localDeploymentID, preparation, snapshot, anchor, initial,
		nowMilliseconds,
		func(
			ctx context.Context,
			tx DeviceSyncStandbyImportTransaction,
			validated serviceauthority.ValidatedMigrationTransfer,
		) error {
			return MaterializeValidatedDeviceSyncMigrationState(
				ctx, tx, validated, staged,
			)
		},
	)
}

// MaterializeValidatedDeviceSyncMigrationState verifies exact signed artifact
// descriptors before parsing, inserts the canonical logical state, and then
// independently re-exports the inserted rows in the same serializable target
// transaction. Both reproduced transfer digests, byte counts, and the domain-
// separated commitment must match the source-signed snapshot.
//
// Deployment authority, immutable import evidence, and standby enforcement
// remain owned by ImportPreparedDeviceSyncMigrationStandby. Blob bytes remain a
// later coordinator responsibility, so this operation alone is not readiness.
func MaterializeValidatedDeviceSyncMigrationState(
	ctx context.Context,
	tx DeviceSyncMigrationStateImportTransaction,
	validated serviceauthority.ValidatedMigrationTransfer,
	staged DeviceSyncMigrationStagedArtifacts,
) error {
	principalID := validated.Snapshot.Scope.ScopeID
	if validated.Snapshot.Scope.Kind != serviceauthority.ScopeDeviceSync ||
		principalID == uuid.Nil || staged.ServiceState == nil || staged.BlobInventory == nil {
		return serviceauthority.ErrInvalid
	}
	stateDescriptor, inventoryDescriptor, err :=
		deviceSyncMigrationRequiredArtifactDescriptors(validated.Snapshot)
	if err != nil {
		return err
	}
	stateDigest, err := parseDeviceSyncMigrationDigest(stateDescriptor.TransferDigest)
	if err != nil {
		return err
	}
	inventoryDigest, err := parseDeviceSyncMigrationDigest(inventoryDescriptor.TransferDigest)
	if err != nil {
		return err
	}
	expectedCommitment := DeviceSyncMigrationStateCommitment(stateDigest, inventoryDigest)
	if expectedCommitment.String() != validated.Snapshot.StateCommitmentDigest {
		return errors.New("Device Sync migration artifact descriptors do not reproduce signed state commitment")
	}
	if err := verifyDeviceSyncMigrationStagedArtifact(
		ctx, staged.ServiceState, stateDescriptor.ByteCount, stateDigest,
	); err != nil {
		return fmt.Errorf("verify Device Sync migration service-state descriptor: %w", err)
	}
	if err := verifyDeviceSyncMigrationStagedArtifact(
		ctx, staged.BlobInventory, inventoryDescriptor.ByteCount, inventoryDigest,
	); err != nil {
		return fmt.Errorf("verify Device Sync migration blob-inventory descriptor: %w", err)
	}
	if err := ValidateDeviceSyncMigrationBlobInventory(
		ctx, staged.BlobInventory, principalID, inventoryDigest,
	); err != nil {
		return fmt.Errorf("validate Device Sync migration blob inventory: %w", err)
	}
	if _, err := tx.Exec(ctx, "SAVEPOINT facets_device_sync_migration_materialize"); err != nil {
		return fmt.Errorf("create Device Sync migration materialization savepoint: %w", err)
	}
	rollback := func(cause error) error {
		cleanupContext, cancelCleanup := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancelCleanup()
		_, rollbackErr := tx.Exec(cleanupContext, "ROLLBACK TO SAVEPOINT facets_device_sync_migration_materialize")
		_, releaseErr := tx.Exec(cleanupContext, "RELEASE SAVEPOINT facets_device_sync_migration_materialize")
		if rollbackErr != nil {
			return errors.Join(cause, fmt.Errorf("rollback Device Sync migration materialization: %w", rollbackErr))
		}
		if releaseErr != nil {
			return errors.Join(cause, fmt.Errorf("release Device Sync migration materialization rollback: %w", releaseErr))
		}
		return cause
	}
	if err := InsertDeviceSyncMigrationState(
		ctx, tx, principalID, stateDigest, staged.ServiceState,
	); err != nil {
		return rollback(err)
	}
	reproduced, err := ExportDeviceSyncMigrationState(
		ctx, tx, principalID, io.Discard, io.Discard,
	)
	if err != nil {
		return rollback(fmt.Errorf("reproduce Device Sync migration target state: %w", err))
	}
	if reproduced.StateArtifactSHA256 != stateDigest ||
		reproduced.StateArtifactByteCount != stateDescriptor.ByteCount ||
		reproduced.BlobInventorySHA256 != inventoryDigest ||
		reproduced.BlobInventoryByteCount != inventoryDescriptor.ByteCount ||
		reproduced.StateCommitment != expectedCommitment {
		return rollback(errors.New("materialized Device Sync target state does not reproduce signed artifact commitment"))
	}
	if _, err := tx.Exec(ctx, "RELEASE SAVEPOINT facets_device_sync_migration_materialize"); err != nil {
		return fmt.Errorf("release Device Sync migration materialization savepoint: %w", err)
	}
	return nil
}

// MaterializeValidatedDeviceSyncMigrationRollbackState verifies a reverse
// transfer and replaces the retired source's semantic rows exactly. The
// caller owns the serializable transaction and must install non-writable
// rollback-standby evidence before commit.
func MaterializeValidatedDeviceSyncMigrationRollbackState(
	ctx context.Context,
	tx DeviceSyncMigrationStateImportTransaction,
	validated serviceauthority.ValidatedMigrationRollbackTransfer,
	staged DeviceSyncMigrationStagedArtifacts,
) error {
	principalID := validated.Snapshot.Scope.ScopeID
	if validated.Snapshot.Scope.Kind != serviceauthority.ScopeDeviceSync ||
		principalID == uuid.Nil || staged.ServiceState == nil || staged.BlobInventory == nil {
		return serviceauthority.ErrInvalid
	}
	stateDescriptor, inventoryDescriptor, err :=
		deviceSyncMigrationRequiredArtifactDescriptors(validated.Snapshot)
	if err != nil {
		return err
	}
	stateDigest, err := parseDeviceSyncMigrationDigest(stateDescriptor.TransferDigest)
	if err != nil {
		return err
	}
	inventoryDigest, err := parseDeviceSyncMigrationDigest(inventoryDescriptor.TransferDigest)
	if err != nil {
		return err
	}
	expectedCommitment := DeviceSyncMigrationStateCommitment(stateDigest, inventoryDigest)
	if expectedCommitment.String() != validated.Snapshot.StateCommitmentDigest {
		return errors.New("Device Sync rollback descriptors do not reproduce signed state commitment")
	}
	if err := verifyDeviceSyncMigrationStagedArtifact(
		ctx, staged.ServiceState, stateDescriptor.ByteCount, stateDigest,
	); err != nil {
		return fmt.Errorf("verify Device Sync rollback service-state descriptor: %w", err)
	}
	if err := verifyDeviceSyncMigrationStagedArtifact(
		ctx, staged.BlobInventory, inventoryDescriptor.ByteCount, inventoryDigest,
	); err != nil {
		return fmt.Errorf("verify Device Sync rollback blob-inventory descriptor: %w", err)
	}
	if err := ValidateDeviceSyncMigrationBlobInventory(
		ctx, staged.BlobInventory, principalID, inventoryDigest,
	); err != nil {
		return fmt.Errorf("validate Device Sync rollback blob inventory: %w", err)
	}
	if _, err := tx.Exec(ctx, "SAVEPOINT facets_device_sync_migration_rollback_materialize"); err != nil {
		return fmt.Errorf("create Device Sync rollback materialization savepoint: %w", err)
	}
	rollback := func(cause error) error {
		cleanupContext, cancelCleanup := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancelCleanup()
		_, rollbackErr := tx.Exec(cleanupContext, "ROLLBACK TO SAVEPOINT facets_device_sync_migration_rollback_materialize")
		_, releaseErr := tx.Exec(cleanupContext, "RELEASE SAVEPOINT facets_device_sync_migration_rollback_materialize")
		if rollbackErr != nil {
			return errors.Join(cause, fmt.Errorf("rollback Device Sync rollback materialization: %w", rollbackErr))
		}
		if releaseErr != nil {
			return errors.Join(cause, fmt.Errorf("release Device Sync rollback materialization rollback: %w", releaseErr))
		}
		return cause
	}
	if err := ReplaceDeviceSyncMigrationState(
		ctx, tx, principalID, stateDigest, staged.ServiceState,
	); err != nil {
		return rollback(err)
	}
	reproduced, err := ExportDeviceSyncMigrationState(
		ctx, tx, principalID, io.Discard, io.Discard,
	)
	if err != nil {
		return rollback(fmt.Errorf("reproduce Device Sync rollback state: %w", err))
	}
	if reproduced.StateArtifactSHA256 != stateDigest ||
		reproduced.StateArtifactByteCount != stateDescriptor.ByteCount ||
		reproduced.BlobInventorySHA256 != inventoryDigest ||
		reproduced.BlobInventoryByteCount != inventoryDescriptor.ByteCount ||
		reproduced.StateCommitment != expectedCommitment {
		return rollback(errors.New("materialized Device Sync rollback state does not reproduce signed artifact commitment"))
	}
	if _, err := tx.Exec(ctx, "RELEASE SAVEPOINT facets_device_sync_migration_rollback_materialize"); err != nil {
		return fmt.Errorf("release Device Sync rollback materialization savepoint: %w", err)
	}
	return nil
}

func deviceSyncMigrationRequiredArtifactDescriptors(
	snapshot serviceauthority.MigrationSnapshotPayload,
) (serviceauthority.MigrationArtifactDescriptor, serviceauthority.MigrationArtifactDescriptor, error) {
	var state *serviceauthority.MigrationArtifactDescriptor
	var inventory *serviceauthority.MigrationArtifactDescriptor
	for index := range snapshot.Artifacts {
		descriptor := &snapshot.Artifacts[index]
		switch descriptor.Kind {
		case serviceauthority.ArtifactServiceStateSnapshot:
			if state != nil {
				return serviceauthority.MigrationArtifactDescriptor{}, serviceauthority.MigrationArtifactDescriptor{},
					serviceauthority.ErrInvalid
			}
			state = descriptor
		case serviceauthority.ArtifactBlobInventory:
			if inventory != nil {
				return serviceauthority.MigrationArtifactDescriptor{}, serviceauthority.MigrationArtifactDescriptor{},
					serviceauthority.ErrInvalid
			}
			inventory = descriptor
		}
	}
	if state == nil || inventory == nil || state.Validate() != nil || inventory.Validate() != nil {
		return serviceauthority.MigrationArtifactDescriptor{}, serviceauthority.MigrationArtifactDescriptor{},
			serviceauthority.ErrInvalid
	}
	return *state, *inventory, nil
}

func parseDeviceSyncMigrationDigest(value string) (DeviceSyncMigrationDigest, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(DeviceSyncMigrationDigest{}) ||
		hex.EncodeToString(decoded) != value {
		return DeviceSyncMigrationDigest{}, serviceauthority.ErrInvalid
	}
	var digest DeviceSyncMigrationDigest
	copy(digest[:], decoded)
	return digest, nil
}

func verifyDeviceSyncMigrationStagedArtifact(
	ctx context.Context,
	source io.ReadSeeker,
	expectedByteCount int64,
	expectedDigest DeviceSyncMigrationDigest,
) error {
	if source == nil || expectedByteCount < 0 {
		return serviceauthority.ErrInvalid
	}
	actualByteCount, err := source.Seek(0, io.SeekEnd)
	if err != nil {
		return fmt.Errorf("measure staged artifact: %w", err)
	}
	if actualByteCount != expectedByteCount {
		return fmt.Errorf("staged artifact byte count %d does not match signed descriptor %d",
			actualByteCount, expectedByteCount)
	}
	return verifyDeviceSyncMigrationTransferDigest(ctx, source, expectedDigest)
}
