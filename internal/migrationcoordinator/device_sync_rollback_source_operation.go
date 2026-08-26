package migrationcoordinator

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

type DeviceSyncRollbackSourceOperationResult struct {
	Preparation DeviceSyncRollbackSourcePreparationResult
	Recovered   bool
}

// DeviceSyncRollbackSourceHandoff is the exact authenticated reverse transfer
// a later transport adapter may serve. Transfer exposes protected readers, not
// local paths; this value neither selects a route nor authorizes rollback.
type DeviceSyncRollbackSourceHandoff struct {
	ActivationEvidence serviceauthority.MigrationActivationEvidence
	Snapshot           serviceauthority.MigrationSnapshot
	Transfer           PreparedDeviceSyncTransfer
}

type DeviceSyncRollbackSourceOperationState string

const (
	DeviceSyncRollbackSourceOperationAccepted DeviceSyncRollbackSourceOperationState = "accepted"
	DeviceSyncRollbackSourceOperationPrepared DeviceSyncRollbackSourceOperationState = "prepared"
)

type DeviceSyncRollbackSourceOperationStatus struct {
	AcceptedAtMilliseconds   int64                                  `json:"acceptedAtMilliseconds"`
	ActivationEvidenceDigest string                                 `json:"activationEvidenceDigest"`
	ExportWriteFenceID       uuid.UUID                              `json:"exportWriteFenceID"`
	MigrationID              uuid.UUID                              `json:"migrationID"`
	PrincipalID              uuid.UUID                              `json:"principalID"`
	SnapshotID               uuid.UUID                              `json:"snapshotID"`
	SnapshotReferenceDigest  *string                                `json:"snapshotReferenceDigest,omitempty"`
	State                    DeviceSyncRollbackSourceOperationState `json:"state"`
	StateCommitmentDigest    *string                                `json:"stateCommitmentDigest,omitempty"`
}

// DeviceSyncRollbackSourceOperationCoordinator persists the exact reverse
// export operation before DeviceSyncSourceCoordinator may fence PostgreSQL.
// It is a headless attended-control primitive: no public route or automatic
// service-readiness exception is implied.
type DeviceSyncRollbackSourceOperationCoordinator struct {
	Source *DeviceSyncSourceCoordinator
}

func (coordinator *DeviceSyncRollbackSourceOperationCoordinator) ListStatus(
	ctx context.Context,
	now time.Time,
) ([]DeviceSyncRollbackSourceOperationStatus, error) {
	if err := coordinator.validateIdentity(ctx, now); err != nil {
		return nil, err
	}
	operations, err := coordinator.Source.Custody.
		listDeviceSyncRollbackSourceOperations(ctx)
	if err != nil {
		return nil, fmt.Errorf(
			"list Device Sync rollback source operation status: %w", err,
		)
	}
	statuses := make([]DeviceSyncRollbackSourceOperationStatus, 0, len(operations))
	for _, operation := range operations {
		acceptance, err := operation.record.Acceptance.VerifiedPayload()
		if err != nil || !coordinator.owns(operation) {
			return nil, errors.New(
				"Device Sync rollback source operation belongs to another deployment",
			)
		}
		status := DeviceSyncRollbackSourceOperationStatus{
			AcceptedAtMilliseconds:   acceptance.AcceptedAtMilliseconds,
			ActivationEvidenceDigest: acceptance.ActivationEvidenceDigest,
			ExportWriteFenceID:       acceptance.ExportWriteFenceID,
			MigrationID:              acceptance.MigrationID,
			PrincipalID:              acceptance.Scope.ScopeID,
			SnapshotID:               acceptance.SnapshotID,
			State:                    DeviceSyncRollbackSourceOperationAccepted,
		}
		if operation.completed {
			prepared, err := operation.record.Prepared.VerifiedPayload()
			if err != nil {
				return nil, err
			}
			status.State = DeviceSyncRollbackSourceOperationPrepared
			status.SnapshotReferenceDigest = &prepared.SnapshotReferenceDigest
			status.StateCommitmentDigest = &prepared.StateCommitmentDigest
		}
		statuses = append(statuses, status)
	}
	return statuses, nil
}

func (coordinator *DeviceSyncRollbackSourceOperationCoordinator) Begin(
	ctx context.Context,
	request DeviceSyncRollbackSourcePreparationRequest,
) (DeviceSyncRollbackSourceOperationResult, error) {
	if err := coordinator.validate(ctx, request.Now); err != nil {
		return DeviceSyncRollbackSourceOperationResult{}, err
	}
	operation, err := coordinator.Source.Custody.stageDeviceSyncRollbackSourceOperation(
		ctx, coordinator.Source.Signer, request,
	)
	if err != nil {
		return DeviceSyncRollbackSourceOperationResult{}, fmt.Errorf(
			"stage Device Sync rollback source operation: %w", err,
		)
	}
	return coordinator.apply(ctx, operation, request.Now, false)
}

func (coordinator *DeviceSyncRollbackSourceOperationCoordinator) OpenPrepared(
	ctx context.Context,
	principalID uuid.UUID,
	migrationID uuid.UUID,
	snapshotID uuid.UUID,
	now time.Time,
) (DeviceSyncRollbackSourceHandoff, error) {
	if err := coordinator.validateIdentity(ctx, now); err != nil ||
		principalID == uuid.Nil || migrationID == uuid.Nil || snapshotID == uuid.Nil {
		return DeviceSyncRollbackSourceHandoff{}, serviceauthority.ErrInvalid
	}
	operations, err := coordinator.Source.Custody.
		listDeviceSyncRollbackSourceOperations(ctx)
	if err != nil {
		return DeviceSyncRollbackSourceHandoff{}, fmt.Errorf(
			"list Device Sync rollback source handoff: %w", err,
		)
	}
	for _, operation := range operations {
		acceptance, err := operation.record.Acceptance.VerifiedPayload()
		if err != nil {
			return DeviceSyncRollbackSourceHandoff{}, err
		}
		if acceptance.Scope.ScopeID != principalID ||
			acceptance.MigrationID != migrationID ||
			acceptance.SnapshotID != snapshotID {
			continue
		}
		if !operation.completed || !coordinator.owns(operation) ||
			now.UnixMilli() < acceptance.AcceptedAtMilliseconds {
			return DeviceSyncRollbackSourceHandoff{}, errors.New(
				"Device Sync rollback source handoff is not prepared",
			)
		}
		handoff, err := coordinator.Source.Custody.
			openPreparedDeviceSyncRollbackSourceHandoff(ctx, operation, now)
		if err != nil {
			return DeviceSyncRollbackSourceHandoff{}, fmt.Errorf(
				"open Device Sync rollback source handoff: %w", err,
			)
		}
		return handoff, nil
	}
	return DeviceSyncRollbackSourceHandoff{}, errors.New(
		"Device Sync rollback source handoff was not found",
	)
}

func (coordinator *DeviceSyncRollbackSourceOperationCoordinator) Recover(
	ctx context.Context,
	now time.Time,
) ([]DeviceSyncRollbackSourceOperationResult, error) {
	if err := coordinator.validate(ctx, now); err != nil {
		return nil, err
	}
	operations, err := coordinator.Source.Custody.
		listDeviceSyncRollbackSourceOperations(ctx)
	if err != nil {
		return nil, fmt.Errorf(
			"list Device Sync rollback source operation recovery: %w", err,
		)
	}
	results := make([]DeviceSyncRollbackSourceOperationResult, 0, len(operations))
	for _, operation := range operations {
		if operation.completed {
			continue
		}
		acceptance, err := operation.record.Acceptance.VerifiedPayload()
		if err != nil || !coordinator.owns(operation) {
			return nil, errors.New(
				"Device Sync rollback source operation belongs to another deployment",
			)
		}
		if now.UnixMilli() < acceptance.AcceptedAtMilliseconds {
			return nil, errors.New(
				"Device Sync rollback source recovery clock precedes acceptance",
			)
		}
		result, err := coordinator.apply(ctx, operation, now, true)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}
	return results, nil
}

func (coordinator *DeviceSyncRollbackSourceOperationCoordinator) apply(
	ctx context.Context,
	operation deviceSyncRollbackSourceOperation,
	now time.Time,
	recovered bool,
) (DeviceSyncRollbackSourceOperationResult, error) {
	request := operation.request
	request.Now = now
	preparation, err := coordinator.Source.PrepareRollback(ctx, request)
	if err != nil {
		return DeviceSyncRollbackSourceOperationResult{}, fmt.Errorf(
			"prepare journaled Device Sync rollback source: %w", err,
		)
	}
	if err := coordinator.Source.Custody.
		completeDeviceSyncRollbackSourceOperation(
			operation, coordinator.Source.Signer, preparation,
		); err != nil {
		return DeviceSyncRollbackSourceOperationResult{}, fmt.Errorf(
			"complete Device Sync rollback source operation: %w", err,
		)
	}
	return DeviceSyncRollbackSourceOperationResult{
		Preparation: preparation, Recovered: recovered,
	}, nil
}

func (coordinator *DeviceSyncRollbackSourceOperationCoordinator) validate(
	ctx context.Context,
	now time.Time,
) error {
	if err := coordinator.validateIdentity(ctx, now); err != nil ||
		coordinator.Source.Exporter == nil || coordinator.Source.Bindings == nil {
		return serviceauthority.ErrInvalid
	}
	return nil
}

func (coordinator *DeviceSyncRollbackSourceOperationCoordinator) validateIdentity(
	ctx context.Context,
	now time.Time,
) error {
	if coordinator == nil || coordinator.Source == nil ||
		coordinator.Source.Custody == nil || coordinator.Source.Signer == nil ||
		ctx == nil || now.IsZero() || now.UnixMilli() < 0 {
		return serviceauthority.ErrInvalid
	}
	resolvedRoot, err := filepath.Abs(coordinator.Source.Custody.root)
	if err != nil || filepath.Clean(resolvedRoot) != coordinator.Source.Custody.root {
		return serviceauthority.ErrInvalid
	}
	return nil
}

func (coordinator *DeviceSyncRollbackSourceOperationCoordinator) owns(
	operation deviceSyncRollbackSourceOperation,
) bool {
	acceptance, err := operation.record.Acceptance.VerifiedPayload()
	return err == nil &&
		acceptance.LocalDeploymentID == coordinator.Source.Signer.DeploymentID() &&
		operation.record.Acceptance.Signature.PublicSigningKeyX963 ==
			coordinator.Source.Signer.PublicSigningKeyX963() &&
		operation.record.Acceptance.Signature.SigningKeyFingerprint ==
			coordinator.Source.Signer.SigningKeyFingerprint()
}
