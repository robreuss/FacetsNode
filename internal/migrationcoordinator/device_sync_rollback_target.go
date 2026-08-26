package migrationcoordinator

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

type DeviceSyncRollbackStandbyImporter interface {
	PrepareDeviceSyncMigrationRollbackStandby(
		context.Context,
		uuid.UUID,
		serviceauthority.MigrationActivationEvidence,
		serviceauthority.MigrationSnapshot,
		serviceauthority.TrustAnchor,
		int64,
		postgres.DeviceSyncMigrationStagedArtifacts,
	) (postgres.DeviceSyncMigrationRollbackImportRecord, error)
}

type DeviceSyncRollbackTargetPreparationRequest struct {
	ActivationEvidence serviceauthority.MigrationActivationEvidence
	Snapshot           serviceauthority.MigrationSnapshot
	Anchor             serviceauthority.TrustAnchor
	ServiceState       io.Reader
	BlobInventory      io.Reader
	BlobSource         relay.BlobContentStore
	Now                time.Time
}

type DeviceSyncRollbackTargetPreparationResult struct {
	ImportRecord postgres.DeviceSyncMigrationRollbackImportRecord
	Readiness    serviceauthority.MigrationReadiness
	Transfer     DeviceSyncBlobTransferReport
}

// DeviceSyncRollbackTargetCoordinator restores the retired source as a
// non-writable exact standby. Readiness is signed only after state replacement
// and two-pass blob verification; it never grants authority on its own.
type DeviceSyncRollbackTargetCoordinator struct {
	Importer  DeviceSyncRollbackStandbyImporter
	Custody   *FileArtifactCustody
	BlobStore relay.BlobContentStore
	Bindings  *serviceauthority.BindingRegistry
	Signer    *serviceauthority.DeploymentSigner
}

func (coordinator *DeviceSyncRollbackTargetCoordinator) Prepare(
	ctx context.Context,
	request DeviceSyncRollbackTargetPreparationRequest,
) (DeviceSyncRollbackTargetPreparationResult, error) {
	if coordinator == nil || coordinator.Importer == nil || coordinator.Custody == nil ||
		coordinator.BlobStore == nil || coordinator.Bindings == nil ||
		coordinator.Signer == nil || ctx == nil || request.ServiceState == nil ||
		request.BlobInventory == nil || request.BlobSource == nil || request.Now.IsZero() {
		return DeviceSyncRollbackTargetPreparationResult{}, serviceauthority.ErrInvalid
	}
	nowMilliseconds := request.Now.UnixMilli()
	validated, err := request.Snapshot.ValidateRollbackTransfer(
		request.ActivationEvidence, request.Anchor, nowMilliseconds,
	)
	if err != nil || validated.Snapshot.Scope.Kind != serviceauthority.ScopeDeviceSync ||
		validated.Snapshot.ImportingDeploymentID != coordinator.Signer.DeploymentID() {
		return DeviceSyncRollbackTargetPreparationResult{}, serviceauthority.ErrInvalid
	}
	staged, err := coordinator.Custody.stagePreparedDeviceSyncRollbackTransfer(
		ctx, validated, request.ActivationEvidence, request.Snapshot,
		request.ServiceState, request.BlobInventory,
	)
	if err != nil {
		return DeviceSyncRollbackTargetPreparationResult{}, fmt.Errorf(
			"stage Device Sync rollback artifacts: %w", err,
		)
	}
	copyBlobs := func() (DeviceSyncBlobTransferReport, error) {
		inventory, err := staged.OpenBlobInventory()
		if err != nil {
			return DeviceSyncBlobTransferReport{}, err
		}
		report, copyErr := CopyDeviceSyncMigrationBlobs(
			ctx, inventory, validated.Snapshot.Scope.ScopeID,
			staged.BlobInventoryDigest(), request.BlobSource, coordinator.BlobStore,
		)
		return report, errors.Join(copyErr, inventory.Close())
	}
	report, err := copyBlobs()
	if err != nil {
		return DeviceSyncRollbackTargetPreparationResult{}, err
	}
	artifacts, closeArtifacts, err := staged.OpenArtifacts()
	if err != nil {
		return DeviceSyncRollbackTargetPreparationResult{}, err
	}
	imported, importErr := coordinator.Importer.PrepareDeviceSyncMigrationRollbackStandby(
		ctx, coordinator.Signer.DeploymentID(), request.ActivationEvidence,
		request.Snapshot, request.Anchor, nowMilliseconds, artifacts,
	)
	closeErr := closeArtifacts()
	if importErr != nil || closeErr != nil {
		return DeviceSyncRollbackTargetPreparationResult{},
			errors.Join(importErr, closeErr)
	}
	if imported.PrincipalID != validated.Snapshot.Scope.ScopeID ||
		imported.MigrationID != validated.Migration.MigrationID ||
		imported.ImportingDeploymentID != coordinator.Signer.DeploymentID() ||
		imported.StateCommitmentDigest != validated.Snapshot.StateCommitmentDigest {
		return DeviceSyncRollbackTargetPreparationResult{}, errors.New(
			"Device Sync rollback import differs from authenticated transfer",
		)
	}
	confirmed, err := copyBlobs()
	if err != nil {
		return DeviceSyncRollbackTargetPreparationResult{}, err
	}
	if confirmed != report {
		return DeviceSyncRollbackTargetPreparationResult{}, errors.New(
			"Device Sync rollback post-import blob inventory changed",
		)
	}
	inventory, err := staged.OpenBlobInventory()
	if err != nil {
		return DeviceSyncRollbackTargetPreparationResult{}, err
	}
	verified, verifyErr := VerifyDeviceSyncMigrationBlobs(
		ctx, inventory, validated.Snapshot.Scope.ScopeID,
		staged.BlobInventoryDigest(), coordinator.BlobStore,
	)
	closeErr = inventory.Close()
	if verifyErr != nil || closeErr != nil {
		return DeviceSyncRollbackTargetPreparationResult{},
			errors.Join(verifyErr, closeErr)
	}
	if verified != report {
		return DeviceSyncRollbackTargetPreparationResult{}, errors.New(
			"Device Sync rollback verified blob inventory changed",
		)
	}
	identities, err := coordinator.Bindings.CurrentBindingIdentitiesAt(
		serviceauthority.ScopeDeviceSync, request.Now,
	)
	if err != nil {
		return DeviceSyncRollbackTargetPreparationResult{}, err
	}
	foundActivation := false
	for _, identity := range identities {
		if identity.Scope == validated.Snapshot.Scope {
			foundActivation = identity.Revision == validated.ActivationManifest.Revision &&
				identity.Digest == validated.Snapshot.AuthorityManifestDigest &&
				identity.DeploymentID == validated.Migration.TargetDeploymentID
			break
		}
	}
	if !foundActivation {
		return DeviceSyncRollbackTargetPreparationResult{}, errors.New(
			"Device Sync rollback source lacks exact activation binding",
		)
	}
	if existing, found, err := coordinator.Custody.loadLiveReadiness(
		staged, request.Snapshot, nowMilliseconds,
	); err != nil {
		return DeviceSyncRollbackTargetPreparationResult{}, err
	} else if found {
		return DeviceSyncRollbackTargetPreparationResult{
			ImportRecord: imported, Readiness: existing, Transfer: report,
		}, nil
	}
	snapshotDigest, err := request.Snapshot.ReferenceDigest()
	if err != nil {
		return DeviceSyncRollbackTargetPreparationResult{}, err
	}
	expiresAt := nowMilliseconds +
		serviceauthority.MaximumMigrationReadinessLifetime.Milliseconds()
	if expiresAt < nowMilliseconds || expiresAt > validated.Snapshot.ExpiresAtMilliseconds {
		expiresAt = validated.Snapshot.ExpiresAtMilliseconds
	}
	readiness, err := coordinator.Signer.SignMigrationReadiness(
		serviceauthority.MigrationReadinessPayload{
			AppliedStateCommitmentDigest: validated.Snapshot.StateCommitmentDigest,
			AuthorityManifestDigest:      validated.Snapshot.AuthorityManifestDigest,
			ExpiresAtMilliseconds:        expiresAt,
			ImportingDeploymentID:        coordinator.Signer.DeploymentID(),
			MigrationID:                  validated.Migration.MigrationID,
			ReadyAtMilliseconds:          nowMilliseconds,
			Scope:                        validated.Snapshot.Scope,
			SnapshotReferenceDigest:      snapshotDigest,
			Version:                      serviceauthority.SchemaVersion,
		},
	)
	if err != nil {
		return DeviceSyncRollbackTargetPreparationResult{}, err
	}
	readiness, err = coordinator.Custody.storeReadiness(
		staged, request.Snapshot, readiness,
	)
	if err != nil {
		return DeviceSyncRollbackTargetPreparationResult{}, err
	}
	return DeviceSyncRollbackTargetPreparationResult{
		ImportRecord: imported, Readiness: readiness, Transfer: report,
	}, nil
}
