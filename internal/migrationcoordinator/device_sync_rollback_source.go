package migrationcoordinator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

type DeviceSyncRollbackSourcePreparationRequest struct {
	ActivationEvidence      serviceauthority.MigrationActivationEvidence
	Anchor                  serviceauthority.TrustAnchor
	ExportWriteFenceID      uuid.UUID
	SnapshotID              uuid.UUID
	ServiceStateArtifactID  uuid.UUID
	BlobInventoryArtifactID uuid.UUID
	Now                     time.Time
}

type DeviceSyncRollbackSourcePreparationResult struct {
	ExportRecord postgres.DeviceSyncMigrationExportRecord
	Snapshot     serviceauthority.MigrationSnapshot
	Transfer     PreparedDeviceSyncTransfer
}

// PrepareRollback exports the active target back to the retired source while
// activation is still authoritative. It commits the target write fence before
// signing and retains exact reverse-transfer custody for restart recovery.
func (coordinator *DeviceSyncSourceCoordinator) PrepareRollback(
	ctx context.Context,
	request DeviceSyncRollbackSourcePreparationRequest,
) (DeviceSyncRollbackSourcePreparationResult, error) {
	if coordinator == nil || coordinator.Exporter == nil || coordinator.Custody == nil ||
		coordinator.Bindings == nil || coordinator.Signer == nil || ctx == nil ||
		request.ExportWriteFenceID == uuid.Nil || request.SnapshotID == uuid.Nil ||
		request.ServiceStateArtifactID == uuid.Nil ||
		request.BlobInventoryArtifactID == uuid.Nil ||
		request.ServiceStateArtifactID == request.BlobInventoryArtifactID ||
		request.Now.IsZero() {
		return DeviceSyncRollbackSourcePreparationResult{}, serviceauthority.ErrInvalid
	}
	nowMilliseconds := request.Now.UnixMilli()
	activation, err := request.ActivationEvidence.ActivationManifest.Authorize(
		request.Anchor, nowMilliseconds,
	)
	if err != nil || activation.Transition !=
		serviceauthority.TransitionMigrationActivation || activation.Migration == nil ||
		activation.Migration.RollbackUntilMilliseconds == nil ||
		nowMilliseconds >= *activation.Migration.RollbackUntilMilliseconds ||
		len(activation.PreparedDeployments) != 1 ||
		activation.ActiveDeployment.DeploymentID != coordinator.Signer.DeploymentID() ||
		activation.Migration.TargetDeploymentID != coordinator.Signer.DeploymentID() ||
		activation.PreparedDeployments[0].DeploymentID !=
			activation.Migration.SourceDeploymentID {
		return DeviceSyncRollbackSourcePreparationResult{}, serviceauthority.ErrInvalid
	}
	if _, err := request.ActivationEvidence.Validate(
		request.Anchor, activation.ValidFromMilliseconds,
	); err != nil {
		return DeviceSyncRollbackSourcePreparationResult{}, serviceauthority.ErrInvalid
	}
	manifestDigest, err := request.ActivationEvidence.ActivationManifest.ReferenceDigest()
	if err != nil {
		return DeviceSyncRollbackSourcePreparationResult{}, err
	}
	logicalExporter := coordinator.LogicalExporter
	if logicalExporter == nil {
		logicalExporter = func(
			ctx context.Context,
			tx postgres.DeviceSyncSnapshotReadTransaction,
			principalID uuid.UUID,
			stateDestination io.Writer,
			inventoryDestination io.Writer,
		) (postgres.DeviceSyncMigrationArtifactDigests, error) {
			return postgres.ExportDeviceSyncMigrationState(
				ctx, tx, principalID, stateDestination, inventoryDestination,
			)
		}
	}
	exportRecord, err := coordinator.Exporter.MaterializeAndFenceDeviceSyncMigrationExport(
		ctx, activation.Scope.ScopeID, coordinator.Signer.DeploymentID(),
		activation.Revision, manifestDigest, activation.Migration.MigrationID,
		request.ExportWriteFenceID, nowMilliseconds,
		func(
			ctx context.Context,
			tx postgres.DeviceSyncSnapshotReadTransaction,
			_ postgres.DeviceSyncScopeEnforcement,
		) ([]byte, error) {
			scratch, err := coordinator.Custody.newSourceScratch()
			if err != nil {
				return nil, err
			}
			defer scratch.Remove()
			digests, err := logicalExporter(
				ctx, tx, activation.Scope.ScopeID,
				scratch.ServiceState, scratch.BlobInventory,
			)
			if err != nil {
				return nil, err
			}
			expected := postgres.DeviceSyncMigrationStateCommitment(
				digests.StateArtifactSHA256, digests.BlobInventorySHA256,
			)
			if digests.StateCommitment != expected {
				return nil, errors.New(
					"Device Sync rollback exporter returned a conflicting commitment",
				)
			}
			if err := scratch.SyncAndClose(); err != nil {
				return nil, err
			}
			expiresAt := nowMilliseconds +
				serviceauthority.MaximumMigrationSnapshotLifetime.Milliseconds()
			if expiresAt < nowMilliseconds || expiresAt >
				*activation.Migration.RollbackUntilMilliseconds {
				expiresAt = *activation.Migration.RollbackUntilMilliseconds
			}
			if activation.ValidUntilMilliseconds != nil &&
				expiresAt > *activation.ValidUntilMilliseconds {
				expiresAt = *activation.ValidUntilMilliseconds
			}
			artifacts := []serviceauthority.MigrationArtifactDescriptor{
				{
					ArtifactID:     request.ServiceStateArtifactID,
					ByteCount:      digests.StateArtifactByteCount,
					Kind:           serviceauthority.ArtifactServiceStateSnapshot,
					TransferDigest: digests.StateArtifactSHA256.String(),
				},
				{
					ArtifactID:     request.BlobInventoryArtifactID,
					ByteCount:      digests.BlobInventoryByteCount,
					Kind:           serviceauthority.ArtifactBlobInventory,
					TransferDigest: digests.BlobInventorySHA256.String(),
				},
			}
			sort.Slice(artifacts, func(left, right int) bool {
				return bytes.Compare(
					artifacts[left].ArtifactID[:], artifacts[right].ArtifactID[:],
				) < 0
			})
			payload := serviceauthority.MigrationSnapshotPayload{
				Artifacts: artifacts, AuthorityManifestDigest: manifestDigest,
				CapturedAtMilliseconds: nowMilliseconds, ExpiresAtMilliseconds: expiresAt,
				ExportWriteFenceID:    request.ExportWriteFenceID,
				ExportingDeploymentID: coordinator.Signer.DeploymentID(),
				ImportingDeploymentID: activation.Migration.SourceDeploymentID,
				MigrationID:           activation.Migration.MigrationID, Scope: activation.Scope,
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
			if _, err := coordinator.Custody.stageSourceDeviceSyncRollbackDraft(
				ctx, request.ActivationEvidence, payload, canonicalPayload,
				scratch.ServiceStatePath, scratch.BlobInventoryPath,
			); err != nil {
				return nil, err
			}
			return canonicalPayload, nil
		},
	)
	if err != nil {
		return DeviceSyncRollbackSourcePreparationResult{}, err
	}
	var payload serviceauthority.MigrationSnapshotPayload
	decoder := json.NewDecoder(bytes.NewReader(exportRecord.CanonicalSnapshotPayload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil || ensureJSONEOF(decoder) != nil ||
		payload.Validate(nil) != nil || payload.Scope != activation.Scope ||
		payload.MigrationID != activation.Migration.MigrationID ||
		payload.ExportWriteFenceID != request.ExportWriteFenceID ||
		validateDeviceSyncRollbackSourceExportRecord(
			exportRecord, payload, request, activation.Revision,
		) != nil {
		return DeviceSyncRollbackSourcePreparationResult{}, serviceauthority.ErrInvalid
	}
	draft, err := coordinator.Custody.openSourceDeviceSyncRollbackDraft(
		ctx, request.ActivationEvidence, payload, exportRecord.CanonicalSnapshotPayload,
	)
	if err != nil {
		return DeviceSyncRollbackSourcePreparationResult{}, err
	}
	if err := coordinator.Bindings.StageMigrationWriteFence(
		request.ActivationEvidence.ActivationManifest, payload,
		request.Anchor, nowMilliseconds,
	); err != nil {
		return DeviceSyncRollbackSourcePreparationResult{}, err
	}
	snapshot, err := coordinator.Bindings.SignStagedMigrationSnapshotAt(
		activation.Scope, coordinator.Signer, nowMilliseconds,
	)
	if err != nil || !bytes.Equal(snapshot.Payload, exportRecord.CanonicalSnapshotPayload) {
		return DeviceSyncRollbackSourcePreparationResult{}, serviceauthority.ErrInvalid
	}
	validated, err := snapshot.ValidateRollbackTransfer(
		request.ActivationEvidence, request.Anchor, nowMilliseconds,
	)
	if err != nil {
		return DeviceSyncRollbackSourcePreparationResult{}, err
	}
	if transfer, found, err := coordinator.Custody.openPreparedDeviceSyncRollbackTransfer(
		ctx, validated, request.ActivationEvidence, snapshot,
	); err != nil {
		return DeviceSyncRollbackSourcePreparationResult{}, err
	} else if found {
		return DeviceSyncRollbackSourcePreparationResult{
			ExportRecord: exportRecord, Snapshot: snapshot, Transfer: transfer,
		}, nil
	}
	transfer, err := coordinator.Custody.promoteSourceDeviceSyncRollbackDraft(
		ctx, draft, validated, request.ActivationEvidence, snapshot,
	)
	if err != nil {
		return DeviceSyncRollbackSourcePreparationResult{}, err
	}
	return DeviceSyncRollbackSourcePreparationResult{
		ExportRecord: exportRecord, Snapshot: snapshot, Transfer: transfer,
	}, nil
}

func validateDeviceSyncRollbackSourceExportRecord(
	record postgres.DeviceSyncMigrationExportRecord,
	payload serviceauthority.MigrationSnapshotPayload,
	request DeviceSyncRollbackSourcePreparationRequest,
	expectedAuthorityRevision uint64,
) error {
	forwardRequest := DeviceSyncSourcePreparationRequest{
		ExportWriteFenceID:      request.ExportWriteFenceID,
		SnapshotID:              request.SnapshotID,
		ServiceStateArtifactID:  request.ServiceStateArtifactID,
		BlobInventoryArtifactID: request.BlobInventoryArtifactID,
	}
	return validateDeviceSyncSourceExportRecord(
		record, payload, forwardRequest, expectedAuthorityRevision,
	)
}
