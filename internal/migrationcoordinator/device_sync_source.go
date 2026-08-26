package migrationcoordinator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

type DeviceSyncSourceExportStore interface {
	MaterializeAndFenceDeviceSyncMigrationExport(
		context.Context,
		uuid.UUID,
		uuid.UUID,
		uint64,
		string,
		uuid.UUID,
		uuid.UUID,
		int64,
		postgres.DeviceSyncSnapshotMaterializer,
	) (postgres.DeviceSyncMigrationExportRecord, error)
}

type DeviceSyncLogicalStateExporter func(
	context.Context,
	postgres.DeviceSyncSnapshotReadTransaction,
	uuid.UUID,
	io.Writer,
	io.Writer,
) (postgres.DeviceSyncMigrationArtifactDigests, error)

type DeviceSyncSourcePreparationRequest struct {
	Preparation             serviceauthority.MigrationPreparation
	Anchor                  serviceauthority.TrustAnchor
	ExportWriteFenceID      uuid.UUID
	SnapshotID              uuid.UUID
	ServiceStateArtifactID  uuid.UUID
	BlobInventoryArtifactID uuid.UUID
	Now                     time.Time
}

type DeviceSyncSourcePreparationResult struct {
	ExportRecord postgres.DeviceSyncMigrationExportRecord
	Snapshot     serviceauthority.MigrationSnapshot
	Transfer     PreparedDeviceSyncTransfer
}

// DeviceSyncSourceCoordinator durably materializes exact logical artifacts in
// the same callback that commits the database write fence, then stages and
// signs only that stored snapshot payload. Caller-supplied UUIDs are operation
// journal identities and must be persisted by the eventual attended workflow.
type DeviceSyncSourceCoordinator struct {
	Exporter        DeviceSyncSourceExportStore
	Custody         *FileArtifactCustody
	Bindings        *serviceauthority.BindingRegistry
	Signer          *serviceauthority.DeploymentSigner
	LogicalExporter DeviceSyncLogicalStateExporter
}

func (coordinator *DeviceSyncSourceCoordinator) Prepare(
	ctx context.Context,
	request DeviceSyncSourcePreparationRequest,
) (DeviceSyncSourcePreparationResult, error) {
	if coordinator == nil || coordinator.Exporter == nil || coordinator.Custody == nil ||
		coordinator.Bindings == nil || coordinator.Signer == nil || ctx == nil ||
		request.ExportWriteFenceID == uuid.Nil || request.SnapshotID == uuid.Nil ||
		request.ServiceStateArtifactID == uuid.Nil || request.BlobInventoryArtifactID == uuid.Nil ||
		request.ServiceStateArtifactID == request.BlobInventoryArtifactID || request.Now.IsZero() {
		return DeviceSyncSourcePreparationResult{}, serviceauthority.ErrInvalid
	}
	nowMilliseconds := request.Now.UnixMilli()
	migration, targetOffer, livePreparationErr := request.Preparation.Validate(
		request.Anchor, nowMilliseconds,
	)
	preparationIsLive := livePreparationErr == nil
	var target serviceauthority.DeploymentOfferPayload
	if preparationIsLive {
		target, livePreparationErr = targetOffer.DeploymentOffer.VerifiedPayload(&nowMilliseconds)
		preparationIsLive = livePreparationErr == nil
	}
	if !preparationIsLive {
		var historicalErr error
		migration, targetOffer, historicalErr = validateSourcePreparationHistorically(
			request.Preparation, request.Anchor,
		)
		if historicalErr != nil {
			return DeviceSyncSourcePreparationResult{}, livePreparationErr
		}
		target, historicalErr = targetOffer.DeploymentOffer.VerifiedPayload(nil)
		if historicalErr != nil {
			return DeviceSyncSourcePreparationResult{}, serviceauthority.ErrInvalid
		}
	}
	prepared, err := request.Preparation.PreparationManifest.VerifiedPayload()
	if err != nil || prepared.ActiveDeployment.DeploymentID != coordinator.Signer.DeploymentID() ||
		prepared.Scope.Kind != serviceauthority.ScopeDeviceSync ||
		migration.SourceDeploymentID != coordinator.Signer.DeploymentID() {
		return DeviceSyncSourcePreparationResult{}, serviceauthority.ErrInvalid
	}
	if target.Deployment.DeploymentID != migration.TargetDeploymentID {
		return DeviceSyncSourcePreparationResult{}, serviceauthority.ErrInvalid
	}
	manifestDigest, err := request.Preparation.PreparationManifest.ReferenceDigest()
	if err != nil {
		return DeviceSyncSourcePreparationResult{}, err
	}
	logicalExporter := coordinator.LogicalExporter
	if logicalExporter == nil {
		logicalExporter = func(
			ctx context.Context,
			tx postgres.DeviceSyncSnapshotReadTransaction,
			principalID uuid.UUID,
			stateDestination io.Writer,
			blobInventoryDestination io.Writer,
		) (postgres.DeviceSyncMigrationArtifactDigests, error) {
			return postgres.ExportDeviceSyncMigrationState(
				ctx, tx, principalID, stateDestination, blobInventoryDestination,
			)
		}
	}
	exportRecord, err := coordinator.Exporter.MaterializeAndFenceDeviceSyncMigrationExport(
		ctx,
		prepared.Scope.ScopeID,
		coordinator.Signer.DeploymentID(),
		prepared.Revision,
		manifestDigest,
		migration.MigrationID,
		request.ExportWriteFenceID,
		nowMilliseconds,
		func(
			ctx context.Context,
			tx postgres.DeviceSyncSnapshotReadTransaction,
			_ postgres.DeviceSyncScopeEnforcement,
		) ([]byte, error) {
			// The store skips this callback for an exact durable retry. Historical
			// evidence may recover that retry, but can never materialize a fresh
			// export after the authority or target-offer window closes.
			if !preparationIsLive {
				return nil, serviceauthority.ErrInvalid
			}
			scratch, err := coordinator.Custody.newSourceScratch()
			if err != nil {
				return nil, err
			}
			defer scratch.Remove()
			digests, err := logicalExporter(
				ctx, tx, prepared.Scope.ScopeID, scratch.ServiceState, scratch.BlobInventory,
			)
			if err != nil {
				return nil, err
			}
			expectedCommitment := postgres.DeviceSyncMigrationStateCommitment(
				digests.StateArtifactSHA256, digests.BlobInventorySHA256,
			)
			if digests.StateCommitment != expectedCommitment {
				return nil, errors.New("Device Sync source exporter returned a conflicting state commitment")
			}
			if err := scratch.SyncAndClose(); err != nil {
				return nil, err
			}
			expiresAt := nowMilliseconds + serviceauthority.MaximumMigrationSnapshotLifetime.Milliseconds()
			if expiresAt < nowMilliseconds || expiresAt > targetOffer.ExpiresAtMilliseconds {
				expiresAt = targetOffer.ExpiresAtMilliseconds
			}
			if expiresAt > target.ExpiresAtMilliseconds {
				expiresAt = target.ExpiresAtMilliseconds
			}
			if prepared.ValidUntilMilliseconds != nil && expiresAt > *prepared.ValidUntilMilliseconds {
				expiresAt = *prepared.ValidUntilMilliseconds
			}
			artifacts := []serviceauthority.MigrationArtifactDescriptor{
				{
					ArtifactID: request.ServiceStateArtifactID, ByteCount: digests.StateArtifactByteCount,
					Kind:           serviceauthority.ArtifactServiceStateSnapshot,
					TransferDigest: digests.StateArtifactSHA256.String(),
				},
				{
					ArtifactID: request.BlobInventoryArtifactID, ByteCount: digests.BlobInventoryByteCount,
					Kind:           serviceauthority.ArtifactBlobInventory,
					TransferDigest: digests.BlobInventorySHA256.String(),
				},
			}
			sort.Slice(artifacts, func(left, right int) bool {
				return bytes.Compare(artifacts[left].ArtifactID[:], artifacts[right].ArtifactID[:]) < 0
			})
			payload := serviceauthority.MigrationSnapshotPayload{
				Artifacts: artifacts, AuthorityManifestDigest: manifestDigest,
				CapturedAtMilliseconds: nowMilliseconds, ExpiresAtMilliseconds: expiresAt,
				ExportWriteFenceID:    request.ExportWriteFenceID,
				ExportingDeploymentID: coordinator.Signer.DeploymentID(),
				ImportingDeploymentID: target.Deployment.DeploymentID,
				MigrationID:           migration.MigrationID, Scope: prepared.Scope,
				SnapshotID:            request.SnapshotID,
				StateCommitmentDigest: digests.StateCommitment.String(),
				Version:               serviceauthority.SchemaVersion,
			}
			if payload.Validate(&nowMilliseconds) != nil {
				return nil, serviceauthority.ErrInvalid
			}
			canonicalPayload, err := json.Marshal(payload)
			if err != nil {
				return nil, err
			}
			_, err = coordinator.Custody.stageSourceDeviceSyncDraft(
				ctx, request.Preparation, payload, canonicalPayload,
				scratch.ServiceStatePath, scratch.BlobInventoryPath,
			)
			if err != nil {
				return nil, err
			}
			return canonicalPayload, nil
		},
	)
	if err != nil {
		return DeviceSyncSourcePreparationResult{}, err
	}
	var payload serviceauthority.MigrationSnapshotPayload
	decoder := json.NewDecoder(bytes.NewReader(exportRecord.CanonicalSnapshotPayload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil || payload.Validate(nil) != nil ||
		payload.Scope != prepared.Scope || payload.MigrationID != migration.MigrationID ||
		payload.ExportWriteFenceID != request.ExportWriteFenceID ||
		nowMilliseconds < payload.CapturedAtMilliseconds ||
		ensureJSONEOF(decoder) != nil ||
		validateDeviceSyncSourceExportRecord(exportRecord, payload, request, prepared.Revision) != nil {
		return DeviceSyncSourcePreparationResult{}, serviceauthority.ErrInvalid
	}
	draft, draftErr := coordinator.Custody.openSourceDeviceSyncDraft(
		ctx, request.Preparation, payload, exportRecord.CanonicalSnapshotPayload,
	)
	if draftErr != nil {
		// A completed promotion intentionally removes the unsigned draft. Recover
		// only an already-confirmed signature; never create one while source
		// artifact custody is absent or corrupted.
		snapshot, recoveryErr := coordinator.Bindings.LoadConfirmedMigrationSnapshot(
			prepared.Scope, coordinator.Signer,
		)
		if recoveryErr != nil || !bytes.Equal(snapshot.Payload, exportRecord.CanonicalSnapshotPayload) {
			return DeviceSyncSourcePreparationResult{}, draftErr
		}
		validated, validationErr := validateSourceSnapshotAt(
			snapshot, request.Preparation, request.Anchor, nowMilliseconds, preparationIsLive,
		)
		if validationErr != nil {
			return DeviceSyncSourcePreparationResult{}, validationErr
		}
		transfer, found, openErr := coordinator.Custody.openPreparedDeviceSyncTransfer(
			ctx, validated, request.Preparation, snapshot,
		)
		if openErr != nil {
			return DeviceSyncSourcePreparationResult{}, openErr
		}
		if !found {
			return DeviceSyncSourcePreparationResult{}, draftErr
		}
		return DeviceSyncSourcePreparationResult{
			ExportRecord: exportRecord, Snapshot: snapshot, Transfer: transfer,
		}, nil
	}
	if err := coordinator.Bindings.StageMigrationWriteFence(
		request.Preparation.PreparationManifest, payload, request.Anchor, nowMilliseconds,
	); err != nil {
		return DeviceSyncSourcePreparationResult{}, err
	}
	snapshot, err := coordinator.Bindings.SignStagedMigrationSnapshotAt(
		prepared.Scope, coordinator.Signer, nowMilliseconds,
	)
	if err != nil || !bytes.Equal(snapshot.Payload, exportRecord.CanonicalSnapshotPayload) {
		return DeviceSyncSourcePreparationResult{}, serviceauthority.ErrInvalid
	}
	validated, err := validateSourceSnapshotAt(
		snapshot, request.Preparation, request.Anchor, nowMilliseconds, preparationIsLive,
	)
	if err != nil {
		return DeviceSyncSourcePreparationResult{}, err
	}
	if transfer, found, err := coordinator.Custody.openPreparedDeviceSyncTransfer(
		ctx, validated, request.Preparation, snapshot,
	); err != nil {
		return DeviceSyncSourcePreparationResult{}, err
	} else if found {
		return DeviceSyncSourcePreparationResult{
			ExportRecord: exportRecord, Snapshot: snapshot, Transfer: transfer,
		}, nil
	}
	transfer, err := coordinator.Custody.promoteSourceDeviceSyncDraft(
		ctx, draft, validated, request.Preparation, snapshot,
	)
	if err != nil {
		return DeviceSyncSourcePreparationResult{}, err
	}
	return DeviceSyncSourcePreparationResult{
		ExportRecord: exportRecord, Snapshot: snapshot, Transfer: transfer,
	}, nil
}

// validateSourcePreparationHistorically reconstructs the instant where every
// signed component overlapped. It provides facts for exact local recovery only;
// it does not establish current authority or authorize a new export.
func validateSourcePreparationHistorically(
	preparation serviceauthority.MigrationPreparation,
	anchor serviceauthority.TrustAnchor,
) (serviceauthority.MigrationAuthority, serviceauthority.MigrationTargetOfferPayload, error) {
	current, currentErr := preparation.CurrentManifest.VerifiedPayload()
	prepared, preparedErr := preparation.PreparationManifest.VerifiedPayload()
	target, targetErr := preparation.TargetOffer.VerifiedPayload(nil)
	deployment, deploymentErr := target.DeploymentOffer.VerifiedPayload(nil)
	if currentErr != nil || preparedErr != nil || targetErr != nil || deploymentErr != nil {
		return serviceauthority.MigrationAuthority{},
			serviceauthority.MigrationTargetOfferPayload{}, serviceauthority.ErrInvalid
	}
	validationTime := current.ValidFromMilliseconds
	for _, candidate := range []int64{
		prepared.ValidFromMilliseconds,
		target.IssuedAtMilliseconds,
		deployment.IssuedAtMilliseconds,
	} {
		if candidate > validationTime {
			validationTime = candidate
		}
	}
	if _, err := target.DeploymentOffer.VerifiedPayload(&validationTime); err != nil {
		return serviceauthority.MigrationAuthority{},
			serviceauthority.MigrationTargetOfferPayload{}, serviceauthority.ErrInvalid
	}
	return preparation.Validate(anchor, validationTime)
}

func validateSourceSnapshotAt(
	snapshot serviceauthority.MigrationSnapshot,
	preparation serviceauthority.MigrationPreparation,
	anchor serviceauthority.TrustAnchor,
	nowMilliseconds int64,
	preparationIsLive bool,
) (serviceauthority.ValidatedMigrationTransfer, error) {
	if preparationIsLive {
		return snapshot.ValidatePreparedTransfer(preparation, anchor, nowMilliseconds)
	}
	return validateHistoricalSourceTransfer(snapshot, preparation, anchor)
}

// validateHistoricalSourceTransfer proves that an already-durable source
// signature was valid for the exact prepared migration. Targets must continue
// to use ValidatePreparedTransfer at receipt time; this helper cannot authorize
// an expired transfer or any service capability.
func validateHistoricalSourceTransfer(
	snapshot serviceauthority.MigrationSnapshot,
	preparation serviceauthority.MigrationPreparation,
	anchor serviceauthority.TrustAnchor,
) (serviceauthority.ValidatedMigrationTransfer, error) {
	migration, targetOffer, err := validateSourcePreparationHistorically(preparation, anchor)
	if err != nil {
		return serviceauthority.ValidatedMigrationTransfer{}, serviceauthority.ErrInvalid
	}
	prepared, preparedErr := preparation.PreparationManifest.VerifiedPayload()
	targetDeployment, targetErr := targetOffer.DeploymentOffer.VerifiedPayload(nil)
	payload, snapshotErr := snapshot.VerifiedPayload(nil)
	manifestDigest, digestErr := preparation.PreparationManifest.ReferenceDigest()
	if preparedErr != nil || targetErr != nil || snapshotErr != nil || digestErr != nil ||
		prepared.Migration == nil || payload.MigrationID != migration.MigrationID ||
		payload.Scope != prepared.Scope || payload.AuthorityManifestDigest != manifestDigest ||
		payload.CapturedAtMilliseconds < prepared.ValidFromMilliseconds ||
		(prepared.ValidUntilMilliseconds != nil &&
			payload.CapturedAtMilliseconds >= *prepared.ValidUntilMilliseconds) ||
		(prepared.ValidUntilMilliseconds != nil &&
			payload.ExpiresAtMilliseconds > *prepared.ValidUntilMilliseconds) ||
		payload.CapturedAtMilliseconds < targetOffer.IssuedAtMilliseconds ||
		payload.ExpiresAtMilliseconds > targetOffer.ExpiresAtMilliseconds ||
		payload.CapturedAtMilliseconds < targetDeployment.IssuedAtMilliseconds ||
		payload.ExpiresAtMilliseconds > targetDeployment.ExpiresAtMilliseconds ||
		payload.ExportingDeploymentID != prepared.ActiveDeployment.DeploymentID ||
		payload.ImportingDeploymentID != targetDeployment.Deployment.DeploymentID ||
		snapshot.Signature.SignerID != prepared.ActiveDeployment.DeploymentID ||
		snapshot.Signature.PublicSigningKeyX963 != prepared.ActiveDeployment.PublicSigningKeyX963 ||
		snapshot.Signature.SigningKeyFingerprint != prepared.ActiveDeployment.SigningKeyFingerprint {
		return serviceauthority.ValidatedMigrationTransfer{}, serviceauthority.ErrInvalid
	}
	return serviceauthority.ValidatedMigrationTransfer{
		Migration: migration, PreparationManifest: prepared, Snapshot: payload,
		TargetDeploymentOffer: targetDeployment, TargetOffer: targetOffer,
	}, nil
}

func validateDeviceSyncSourceExportRecord(
	record postgres.DeviceSyncMigrationExportRecord,
	payload serviceauthority.MigrationSnapshotPayload,
	request DeviceSyncSourcePreparationRequest,
	expectedAuthorityRevision uint64,
) error {
	state, inventory, err := migrationArtifactDescriptors(payload)
	if err != nil {
		return err
	}
	stateDigest, stateDigestErr := migrationDigest(state.TransferDigest)
	inventoryDigest, inventoryDigestErr := migrationDigest(inventory.TransferDigest)
	if stateDigestErr != nil || inventoryDigestErr != nil ||
		postgres.DeviceSyncMigrationStateCommitment(stateDigest, inventoryDigest).String() !=
			payload.StateCommitmentDigest {
		return errors.New("Device Sync source export state commitment conflicts with its artifacts")
	}
	payloadDigest := sha256.Sum256(record.CanonicalSnapshotPayload)
	if record.PrincipalID != payload.Scope.ScopeID || record.TenantID != payload.Scope.ScopeID ||
		record.MigrationID != payload.MigrationID ||
		record.ExportWriteFenceID != payload.ExportWriteFenceID ||
		record.SnapshotID != payload.SnapshotID ||
		record.AuthorityRevision != expectedAuthorityRevision ||
		record.AuthorityManifestDigest != payload.AuthorityManifestDigest ||
		record.ExportingDeploymentID != payload.ExportingDeploymentID ||
		record.ImportingDeploymentID != payload.ImportingDeploymentID ||
		record.SnapshotPayloadSHA256 != hex.EncodeToString(payloadDigest[:]) ||
		record.StateCommitmentDigest != payload.StateCommitmentDigest ||
		record.CapturedAtMilliseconds != payload.CapturedAtMilliseconds ||
		record.ExpiresAtMilliseconds != payload.ExpiresAtMilliseconds ||
		payload.SnapshotID != request.SnapshotID ||
		state.ArtifactID != request.ServiceStateArtifactID ||
		inventory.ArtifactID != request.BlobInventoryArtifactID {
		return errors.New("Device Sync source export record conflicts with requested operation")
	}
	return nil
}
