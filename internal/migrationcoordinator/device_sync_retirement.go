package migrationcoordinator

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

type DeviceSyncMigrationRetirementStore interface {
	ApplyDeviceSyncMigrationRetirement(
		context.Context,
		uuid.UUID,
		serviceauthority.MigrationRetirementEvidence,
		serviceauthority.TrustAnchor,
		int64,
	) error
	GetDeviceSyncScopeEnforcement(
		context.Context,
		uuid.UUID,
	) (postgres.DeviceSyncScopeEnforcement, error)
}

type DeviceSyncRetirementResult struct {
	Binding serviceauthority.BindingIdentity
	State   postgres.DeviceSyncScopeEnforcement
}

type DeviceSyncRetirementCoordinator struct {
	Store    DeviceSyncMigrationRetirementStore
	Custody  *FileArtifactCustody
	Bindings *serviceauthority.BindingRegistry
	Signer   *serviceauthority.DeploymentSigner
}

func (coordinator *DeviceSyncRetirementCoordinator) Retire(
	ctx context.Context,
	evidence serviceauthority.MigrationRetirementEvidence,
	anchor serviceauthority.TrustAnchor,
	now time.Time,
) (DeviceSyncRetirementResult, error) {
	if coordinator == nil || coordinator.Store == nil || coordinator.Custody == nil ||
		coordinator.Bindings == nil || coordinator.Signer == nil || ctx == nil ||
		now.IsZero() || now.UnixMilli() < 0 {
		return DeviceSyncRetirementResult{}, serviceauthority.ErrInvalid
	}
	journal, err := coordinator.Custody.stageDeviceSyncRetirementJournal(
		ctx, coordinator.Signer, evidence, anchor, now.UnixMilli(),
	)
	if err != nil {
		return DeviceSyncRetirementResult{}, fmt.Errorf(
			"stage Device Sync migration retirement: %w", err,
		)
	}
	return coordinator.applyJournal(ctx, journal, now.UnixMilli())
}

func (coordinator *DeviceSyncRetirementCoordinator) Recover(
	ctx context.Context,
	now time.Time,
) ([]DeviceSyncRetirementResult, error) {
	if coordinator == nil || coordinator.Store == nil || coordinator.Custody == nil ||
		coordinator.Bindings == nil || coordinator.Signer == nil || ctx == nil ||
		now.IsZero() || now.UnixMilli() < 0 {
		return nil, serviceauthority.ErrInvalid
	}
	journals, err := coordinator.Custody.listDeviceSyncRetirementJournals(ctx)
	if err != nil {
		return nil, fmt.Errorf("list Device Sync migration retirement recovery: %w", err)
	}
	results := make([]DeviceSyncRetirementResult, 0, len(journals))
	for _, journal := range journals {
		acceptance, acceptanceErr := journal.record.Acceptance.VerifiedPayload()
		if acceptanceErr != nil ||
			acceptance.LocalDeploymentID != coordinator.Signer.DeploymentID() ||
			journal.record.Acceptance.Signature.PublicSigningKeyX963 !=
				coordinator.Signer.PublicSigningKeyX963() ||
			journal.record.Acceptance.Signature.SigningKeyFingerprint !=
				coordinator.Signer.SigningKeyFingerprint() {
			return nil, errors.New(
				"Device Sync retirement custody belongs to another local deployment",
			)
		}
		if journal.completed {
			superseded, err := coordinator.completedRetirementSuperseded(journal)
			if err != nil {
				return nil, err
			}
			if superseded {
				continue
			}
			needsRepair, err := coordinator.completedRetirementNeedsDatabaseRepair(
				ctx, journal,
			)
			if err != nil {
				return nil, err
			}
			if !needsRepair {
				continue
			}
		}
		result, err := coordinator.applyJournal(ctx, journal, now.UnixMilli())
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}
	return results, nil
}

func (coordinator *DeviceSyncRetirementCoordinator) completedRetirementSuperseded(
	journal deviceSyncRetirementJournal,
) (bool, error) {
	retirement, err := journal.record.Evidence.RetirementManifest.VerifiedPayload()
	if err != nil {
		return false, serviceauthority.ErrInvalid
	}
	manifestDigest, err := journal.record.Evidence.RetirementManifest.ReferenceDigest()
	if err != nil {
		return false, err
	}
	evidenceDigest, err := journal.record.Evidence.ReferenceDigest()
	if err != nil {
		return false, err
	}
	identities, err := coordinator.Bindings.CurrentBindingIdentities(
		serviceauthority.ScopeDeviceSync,
	)
	if err != nil {
		return false, err
	}
	for _, identity := range identities {
		if identity.Scope != retirement.Scope {
			continue
		}
		if identity.Revision > retirement.Revision {
			return true, nil
		}
		if identity.Revision == retirement.Revision &&
			identity.Digest == manifestDigest &&
			identity.TransitionEvidenceDigest != nil &&
			*identity.TransitionEvidenceDigest == evidenceDigest {
			return false, nil
		}
		return false, errors.New(
			"completed Device Sync retirement conflicts with current registry authority",
		)
	}
	return false, errors.New(
		"completed Device Sync retirement lost its registry authority",
	)
}

func (coordinator *DeviceSyncRetirementCoordinator) completedRetirementNeedsDatabaseRepair(
	ctx context.Context,
	journal deviceSyncRetirementJournal,
) (bool, error) {
	retirement, err := journal.record.Evidence.RetirementManifest.VerifiedPayload()
	if err != nil || retirement.Migration == nil {
		return false, serviceauthority.ErrInvalid
	}
	state, err := coordinator.Store.GetDeviceSyncScopeEnforcement(
		ctx, retirement.Scope.ScopeID,
	)
	if err != nil {
		return false, err
	}
	evidenceDigest, err := journal.record.Evidence.ReferenceDigest()
	if err != nil {
		return false, err
	}
	manifestDigest, err := journal.record.Evidence.RetirementManifest.ReferenceDigest()
	if err != nil {
		return false, err
	}
	targetSide := coordinator.Signer.DeploymentID() ==
		retirement.Migration.TargetDeploymentID
	expectedState := postgres.DeviceSyncScopeRetired
	if targetSide {
		expectedState = postgres.DeviceSyncScopeWritable
	}
	if state.State == expectedState && state.LocalDeploymentID != nil &&
		*state.LocalDeploymentID == coordinator.Signer.DeploymentID() &&
		state.Authority != nil && state.Authority.Revision == retirement.Revision &&
		state.Authority.ManifestDigest == manifestDigest &&
		state.Authority.TransitionEvidenceDigest != nil &&
		*state.Authority.TransitionEvidenceDigest == evidenceDigest &&
		state.ActiveExportWriteFenceID == nil && state.ActiveMigrationImportID == nil {
		return false, nil
	}
	return true, nil
}

func (coordinator *DeviceSyncRetirementCoordinator) applyJournal(
	ctx context.Context,
	journal deviceSyncRetirementJournal,
	nowMilliseconds int64,
) (DeviceSyncRetirementResult, error) {
	acceptance, err := journal.record.Acceptance.VerifiedPayload()
	if err != nil || nowMilliseconds < acceptance.AcceptedAtMilliseconds {
		return DeviceSyncRetirementResult{}, errors.New(
			"Device Sync retirement clock moved before durable evidence acceptance",
		)
	}
	evidence := journal.record.Evidence
	if err := coordinator.Bindings.ApplyMigrationRetirement(
		evidence, journal.anchor, acceptance.AcceptedAtMilliseconds,
	); err != nil {
		return DeviceSyncRetirementResult{}, fmt.Errorf(
			"apply Device Sync registry migration retirement: %w", err,
		)
	}
	retirement, err := evidence.RetirementManifest.VerifiedPayload()
	if err != nil || retirement.Migration == nil {
		return DeviceSyncRetirementResult{}, serviceauthority.ErrInvalid
	}
	if err := coordinator.Store.ApplyDeviceSyncMigrationRetirement(
		ctx, coordinator.Signer.DeploymentID(), evidence, journal.anchor,
		acceptance.AcceptedAtMilliseconds,
	); err != nil {
		return DeviceSyncRetirementResult{}, fmt.Errorf(
			"apply Device Sync database migration retirement: %w", err,
		)
	}
	state, err := coordinator.Store.GetDeviceSyncScopeEnforcement(
		ctx, retirement.Scope.ScopeID,
	)
	if err != nil {
		return DeviceSyncRetirementResult{}, fmt.Errorf(
			"verify Device Sync database migration retirement: %w", err,
		)
	}
	identities, err := coordinator.Bindings.CurrentBindingIdentities(
		serviceauthority.ScopeDeviceSync,
	)
	if err != nil {
		return DeviceSyncRetirementResult{}, err
	}
	var binding *serviceauthority.BindingIdentity
	for index := range identities {
		if identities[index].Scope == retirement.Scope {
			copy := identities[index]
			binding = &copy
			break
		}
	}
	targetSide := coordinator.Signer.DeploymentID() ==
		retirement.Migration.TargetDeploymentID
	expectedState := postgres.DeviceSyncScopeRetired
	expectedFence := true
	if targetSide {
		expectedState = postgres.DeviceSyncScopeWritable
		expectedFence = false
	}
	if binding == nil || binding.WriteFenced != expectedFence ||
		state.State != expectedState || state.Authority == nil ||
		state.LocalDeploymentID == nil ||
		*state.LocalDeploymentID != coordinator.Signer.DeploymentID() ||
		state.Authority.ActiveDeploymentID != binding.DeploymentID ||
		state.Authority.Revision != binding.Revision ||
		state.Authority.ManifestDigest != binding.Digest ||
		!sameOptionalDigest(
			state.Authority.TransitionEvidenceDigest,
			binding.TransitionEvidenceDigest,
		) || state.ActiveExportWriteFenceID != nil ||
		state.ActiveMigrationImportID != nil {
		return DeviceSyncRetirementResult{}, errors.New(
			"Device Sync registry and database retirement states conflict",
		)
	}
	if err := coordinator.Custody.completeDeviceSyncRetirementJournal(journal); err != nil {
		return DeviceSyncRetirementResult{}, fmt.Errorf(
			"complete Device Sync migration retirement journal: %w", err,
		)
	}
	return DeviceSyncRetirementResult{Binding: *binding, State: state}, nil
}
