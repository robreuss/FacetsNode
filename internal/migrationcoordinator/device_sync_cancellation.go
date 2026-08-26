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

type DeviceSyncMigrationCancellationStore interface {
	ApplyDeviceSyncMigrationCancellation(
		context.Context,
		uuid.UUID,
		serviceauthority.MigrationCancellationEvidence,
		serviceauthority.TrustAnchor,
		int64,
	) error
	GetDeviceSyncScopeEnforcement(
		context.Context,
		uuid.UUID,
	) (postgres.DeviceSyncScopeEnforcement, error)
}

type DeviceSyncCancellationResult struct {
	Binding         serviceauthority.BindingIdentity
	DatabasePresent bool
	State           postgres.DeviceSyncScopeEnforcement
}

// DeviceSyncCancellationCoordinator advances both local durable authority
// stores from one exact cancellation. A deployment-signed acceptance journal
// is committed first, BindingRegistry second, and PostgreSQL last. A target
// cancelled before import legitimately has no database principal to retire;
// the registry terminal state is still persisted and verified.
type DeviceSyncCancellationCoordinator struct {
	Store    DeviceSyncMigrationCancellationStore
	Custody  *FileArtifactCustody
	Bindings *serviceauthority.BindingRegistry
	Signer   *serviceauthority.DeploymentSigner
}

func (coordinator *DeviceSyncCancellationCoordinator) Cancel(
	ctx context.Context,
	evidence serviceauthority.MigrationCancellationEvidence,
	anchor serviceauthority.TrustAnchor,
	now time.Time,
) (DeviceSyncCancellationResult, error) {
	if coordinator == nil || coordinator.Store == nil || coordinator.Custody == nil ||
		coordinator.Bindings == nil || coordinator.Signer == nil ||
		ctx == nil || now.IsZero() || now.UnixMilli() < 0 {
		return DeviceSyncCancellationResult{}, serviceauthority.ErrInvalid
	}
	journal, err := coordinator.Custody.stageDeviceSyncCancellationJournal(
		ctx, coordinator.Signer, evidence, anchor, now.UnixMilli(),
	)
	if err != nil {
		return DeviceSyncCancellationResult{}, fmt.Errorf(
			"stage Device Sync migration cancellation: %w", err,
		)
	}
	return coordinator.applyJournal(ctx, journal, now.UnixMilli())
}

func (coordinator *DeviceSyncCancellationCoordinator) Recover(
	ctx context.Context,
	now time.Time,
) ([]DeviceSyncCancellationResult, error) {
	if coordinator == nil || coordinator.Store == nil || coordinator.Custody == nil ||
		coordinator.Bindings == nil || coordinator.Signer == nil ||
		ctx == nil || now.IsZero() || now.UnixMilli() < 0 {
		return nil, serviceauthority.ErrInvalid
	}
	journals, err := coordinator.Custody.listDeviceSyncCancellationJournals(ctx)
	if err != nil {
		return nil, fmt.Errorf("list Device Sync migration cancellation recovery: %w", err)
	}
	results := make([]DeviceSyncCancellationResult, 0, len(journals))
	for _, journal := range journals {
		acceptance, acceptanceErr := journal.record.Acceptance.VerifiedPayload()
		if acceptanceErr != nil ||
			acceptance.LocalDeploymentID != coordinator.Signer.DeploymentID() ||
			journal.record.Acceptance.Signature.PublicSigningKeyX963 !=
				coordinator.Signer.PublicSigningKeyX963() ||
			journal.record.Acceptance.Signature.SigningKeyFingerprint !=
				coordinator.Signer.SigningKeyFingerprint() {
			return nil, errors.New(
				"Device Sync cancellation custody belongs to another local deployment",
			)
		}
		if journal.completed {
			superseded, err := coordinator.completedCancellationSuperseded(journal)
			if err != nil {
				return nil, err
			}
			if superseded {
				continue
			}
			needsRepair, err := coordinator.completedCancellationNeedsDatabaseRepair(
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

func (coordinator *DeviceSyncCancellationCoordinator) completedCancellationNeedsDatabaseRepair(
	ctx context.Context,
	journal deviceSyncCancellationJournal,
) (bool, error) {
	cancellation, err := journal.record.Evidence.CancellationManifest.VerifiedPayload()
	if err != nil || cancellation.Migration == nil {
		return false, serviceauthority.ErrInvalid
	}
	state, err := coordinator.Store.GetDeviceSyncScopeEnforcement(
		ctx, cancellation.Scope.ScopeID,
	)
	targetSide := coordinator.Signer.DeploymentID() ==
		cancellation.Migration.TargetDeploymentID
	if errors.Is(err, postgres.ErrDeviceSyncScopeEnforcementNotFound) && targetSide {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	evidenceDigest, err := journal.record.Evidence.ReferenceDigest()
	if err != nil {
		return false, err
	}
	manifestDigest, err := journal.record.Evidence.CancellationManifest.ReferenceDigest()
	if err != nil {
		return false, err
	}
	expectedState := postgres.DeviceSyncScopeWritable
	if targetSide {
		expectedState = postgres.DeviceSyncScopeRetired
	}
	if state.State == expectedState && state.LocalDeploymentID != nil &&
		*state.LocalDeploymentID == coordinator.Signer.DeploymentID() &&
		state.Authority != nil && state.Authority.Revision == cancellation.Revision &&
		state.Authority.ManifestDigest == manifestDigest &&
		state.Authority.TransitionEvidenceDigest != nil &&
		*state.Authority.TransitionEvidenceDigest == evidenceDigest &&
		state.ActiveExportWriteFenceID == nil && state.ActiveMigrationImportID == nil {
		return false, nil
	}
	return true, nil
}

func (coordinator *DeviceSyncCancellationCoordinator) completedCancellationSuperseded(
	journal deviceSyncCancellationJournal,
) (bool, error) {
	cancellation, err := journal.record.Evidence.CancellationManifest.VerifiedPayload()
	if err != nil {
		return false, serviceauthority.ErrInvalid
	}
	manifestDigest, err := journal.record.Evidence.CancellationManifest.ReferenceDigest()
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
		if identity.Scope != cancellation.Scope {
			continue
		}
		if identity.Revision > cancellation.Revision {
			return true, nil
		}
		if identity.Revision == cancellation.Revision &&
			identity.Digest == manifestDigest && !identity.WriteFenced &&
			identity.TransitionEvidenceDigest != nil &&
			*identity.TransitionEvidenceDigest == evidenceDigest {
			return false, nil
		}
		return false, errors.New(
			"completed Device Sync cancellation conflicts with current registry authority",
		)
	}
	return false, errors.New(
		"completed Device Sync cancellation lost its registry authority",
	)
}

func (coordinator *DeviceSyncCancellationCoordinator) applyJournal(
	ctx context.Context,
	journal deviceSyncCancellationJournal,
	nowMilliseconds int64,
) (DeviceSyncCancellationResult, error) {
	acceptance, err := journal.record.Acceptance.VerifiedPayload()
	if err != nil || nowMilliseconds < acceptance.AcceptedAtMilliseconds {
		return DeviceSyncCancellationResult{}, errors.New(
			"Device Sync cancellation clock moved before durable evidence acceptance",
		)
	}
	evidence := journal.record.Evidence
	if err := coordinator.Bindings.ApplyMigrationCancellation(
		evidence, journal.anchor, acceptance.AcceptedAtMilliseconds,
	); err != nil {
		return DeviceSyncCancellationResult{}, fmt.Errorf(
			"apply Device Sync registry migration cancellation: %w", err,
		)
	}
	cancellation, err := evidence.CancellationManifest.VerifiedPayload()
	if err != nil || cancellation.Migration == nil {
		return DeviceSyncCancellationResult{}, serviceauthority.ErrInvalid
	}
	targetSide := coordinator.Signer.DeploymentID() ==
		cancellation.Migration.TargetDeploymentID
	databasePresent := true
	state, stateErr := coordinator.Store.GetDeviceSyncScopeEnforcement(
		ctx, cancellation.Scope.ScopeID,
	)
	if errors.Is(stateErr, postgres.ErrDeviceSyncScopeEnforcementNotFound) && targetSide {
		databasePresent = false
	} else if stateErr != nil {
		return DeviceSyncCancellationResult{}, fmt.Errorf(
			"inspect Device Sync database migration cancellation: %w", stateErr,
		)
	}
	if databasePresent {
		if err := coordinator.Store.ApplyDeviceSyncMigrationCancellation(
			ctx,
			coordinator.Signer.DeploymentID(),
			evidence,
			journal.anchor,
			acceptance.AcceptedAtMilliseconds,
		); err != nil {
			return DeviceSyncCancellationResult{}, fmt.Errorf(
				"apply Device Sync database migration cancellation: %w", err,
			)
		}
		state, err = coordinator.Store.GetDeviceSyncScopeEnforcement(
			ctx, cancellation.Scope.ScopeID,
		)
		if err != nil {
			return DeviceSyncCancellationResult{}, fmt.Errorf(
				"verify Device Sync database migration cancellation: %w", err,
			)
		}
	}
	identities, err := coordinator.Bindings.CurrentBindingIdentities(
		serviceauthority.ScopeDeviceSync,
	)
	if err != nil {
		return DeviceSyncCancellationResult{}, fmt.Errorf(
			"verify Device Sync registry migration cancellation: %w", err,
		)
	}
	var binding *serviceauthority.BindingIdentity
	for index := range identities {
		if identities[index].Scope == cancellation.Scope {
			copy := identities[index]
			binding = &copy
			break
		}
	}
	evidenceDigest, err := evidence.ReferenceDigest()
	if err != nil {
		return DeviceSyncCancellationResult{}, err
	}
	manifestDigest, err := evidence.CancellationManifest.ReferenceDigest()
	if err != nil || binding == nil || binding.WriteFenced ||
		binding.DeploymentID != cancellation.Migration.SourceDeploymentID ||
		binding.Revision != cancellation.Revision || binding.Digest != manifestDigest ||
		binding.TransitionEvidenceDigest == nil ||
		*binding.TransitionEvidenceDigest != evidenceDigest {
		return DeviceSyncCancellationResult{}, errors.New(
			"Device Sync registry cancellation identity conflicts with evidence",
		)
	}
	if databasePresent {
		expectedState := postgres.DeviceSyncScopeWritable
		if targetSide {
			expectedState = postgres.DeviceSyncScopeRetired
		}
		if state.State != expectedState || state.Authority == nil ||
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
			return DeviceSyncCancellationResult{}, errors.New(
				"Device Sync registry and database cancellation states conflict",
			)
		}
	}
	if err := coordinator.Custody.completeDeviceSyncCancellationJournal(journal); err != nil {
		return DeviceSyncCancellationResult{}, fmt.Errorf(
			"complete Device Sync migration cancellation journal: %w", err,
		)
	}
	return DeviceSyncCancellationResult{
		Binding: *binding, DatabasePresent: databasePresent, State: state,
	}, nil
}
