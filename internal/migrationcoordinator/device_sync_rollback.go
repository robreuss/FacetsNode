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

type DeviceSyncMigrationRollbackStore interface {
	ApplyDeviceSyncMigrationRollback(
		context.Context,
		uuid.UUID,
		serviceauthority.MigrationRollbackEvidence,
		serviceauthority.TrustAnchor,
		int64,
	) error
	GetDeviceSyncScopeEnforcement(
		context.Context,
		uuid.UUID,
	) (postgres.DeviceSyncScopeEnforcement, error)
}

type DeviceSyncRollbackResult struct {
	Binding serviceauthority.BindingIdentity
	State   postgres.DeviceSyncScopeEnforcement
}

// DeviceSyncRollbackCoordinator advances BindingRegistry and PostgreSQL from
// activation to one exact authority-signed rollback. A deployment-signed local
// acceptance journal makes the two-store cutover restart-safe.
type DeviceSyncRollbackCoordinator struct {
	Store    DeviceSyncMigrationRollbackStore
	Custody  *FileArtifactCustody
	Bindings *serviceauthority.BindingRegistry
	Signer   *serviceauthority.DeploymentSigner
}

func (coordinator *DeviceSyncRollbackCoordinator) Rollback(
	ctx context.Context,
	evidence serviceauthority.MigrationRollbackEvidence,
	anchor serviceauthority.TrustAnchor,
	now time.Time,
) (DeviceSyncRollbackResult, error) {
	if coordinator == nil || coordinator.Store == nil || coordinator.Custody == nil ||
		coordinator.Bindings == nil || coordinator.Signer == nil || ctx == nil ||
		now.IsZero() || now.UnixMilli() < 0 {
		return DeviceSyncRollbackResult{}, serviceauthority.ErrInvalid
	}
	journal, err := coordinator.Custody.stageDeviceSyncRollbackJournal(
		ctx, coordinator.Signer, evidence, anchor, now.UnixMilli(),
	)
	if err != nil {
		return DeviceSyncRollbackResult{}, fmt.Errorf(
			"stage Device Sync migration rollback: %w", err,
		)
	}
	return coordinator.applyJournal(ctx, journal, now.UnixMilli())
}

func (coordinator *DeviceSyncRollbackCoordinator) Recover(
	ctx context.Context,
	now time.Time,
) ([]DeviceSyncRollbackResult, error) {
	if coordinator == nil || coordinator.Store == nil || coordinator.Custody == nil ||
		coordinator.Bindings == nil || coordinator.Signer == nil || ctx == nil ||
		now.IsZero() || now.UnixMilli() < 0 {
		return nil, serviceauthority.ErrInvalid
	}
	journals, err := coordinator.Custody.listDeviceSyncRollbackJournals(ctx)
	if err != nil {
		return nil, fmt.Errorf("list Device Sync rollback recovery: %w", err)
	}
	results := make([]DeviceSyncRollbackResult, 0, len(journals))
	for _, journal := range journals {
		acceptance, err := journal.record.Acceptance.VerifiedPayload()
		if err != nil || acceptance.LocalDeploymentID != coordinator.Signer.DeploymentID() ||
			journal.record.Acceptance.Signature.PublicSigningKeyX963 !=
				coordinator.Signer.PublicSigningKeyX963() ||
			journal.record.Acceptance.Signature.SigningKeyFingerprint !=
				coordinator.Signer.SigningKeyFingerprint() {
			return nil, errors.New(
				"Device Sync rollback custody belongs to another deployment",
			)
		}
		if journal.completed {
			superseded, err := coordinator.completedJournalSuperseded(journal)
			if err != nil {
				return nil, err
			}
			if superseded {
				continue
			}
			needsRepair, err := coordinator.completedJournalNeedsDatabaseRepair(
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

func (coordinator *DeviceSyncRollbackCoordinator) completedJournalNeedsDatabaseRepair(
	ctx context.Context,
	journal deviceSyncRollbackJournal,
) (bool, error) {
	rolledBack, err := journal.record.Evidence.RollbackManifest.VerifiedPayload()
	if err != nil || rolledBack.Migration == nil {
		return false, serviceauthority.ErrInvalid
	}
	state, err := coordinator.Store.GetDeviceSyncScopeEnforcement(
		ctx, rolledBack.Scope.ScopeID,
	)
	if err != nil {
		return false, err
	}
	digest, err := journal.record.Evidence.ReferenceDigest()
	if err != nil {
		return false, err
	}
	manifestDigest, err := journal.record.Evidence.RollbackManifest.ReferenceDigest()
	if err != nil {
		return false, err
	}
	sourceSide := coordinator.Signer.DeploymentID() ==
		rolledBack.Migration.SourceDeploymentID
	expectedState := postgres.DeviceSyncScopeRetired
	if sourceSide {
		expectedState = postgres.DeviceSyncScopeWritable
	}
	if state.State == expectedState && state.LocalDeploymentID != nil &&
		*state.LocalDeploymentID == coordinator.Signer.DeploymentID() &&
		state.Authority != nil && state.Authority.Revision == rolledBack.Revision &&
		state.Authority.ManifestDigest == manifestDigest &&
		state.Authority.TransitionEvidenceDigest != nil &&
		*state.Authority.TransitionEvidenceDigest == digest &&
		state.ActiveExportWriteFenceID == nil && state.ActiveMigrationImportID == nil &&
		state.ActiveRollbackImportID == nil {
		return false, nil
	}
	return true, nil
}

func (coordinator *DeviceSyncRollbackCoordinator) completedJournalSuperseded(
	journal deviceSyncRollbackJournal,
) (bool, error) {
	rolledBack, err := journal.record.Evidence.RollbackManifest.VerifiedPayload()
	if err != nil {
		return false, err
	}
	manifestDigest, err := journal.record.Evidence.RollbackManifest.ReferenceDigest()
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
		if identity.Scope != rolledBack.Scope {
			continue
		}
		if identity.Revision > rolledBack.Revision {
			return true, nil
		}
		if identity.Revision == rolledBack.Revision && identity.Digest == manifestDigest &&
			identity.TransitionEvidenceDigest != nil &&
			*identity.TransitionEvidenceDigest == evidenceDigest {
			return false, nil
		}
		return false, errors.New(
			"completed Device Sync rollback conflicts with current authority",
		)
	}
	return false, errors.New("completed Device Sync rollback lost current authority")
}

func (coordinator *DeviceSyncRollbackCoordinator) applyJournal(
	ctx context.Context,
	journal deviceSyncRollbackJournal,
	nowMilliseconds int64,
) (DeviceSyncRollbackResult, error) {
	acceptance, err := journal.record.Acceptance.VerifiedPayload()
	if err != nil || nowMilliseconds < acceptance.AcceptedAtMilliseconds {
		return DeviceSyncRollbackResult{}, errors.New(
			"Device Sync rollback clock moved before durable acceptance",
		)
	}
	evidence := journal.record.Evidence
	if err := coordinator.Bindings.ApplyMigrationRollback(
		evidence, journal.anchor, acceptance.AcceptedAtMilliseconds,
	); err != nil {
		return DeviceSyncRollbackResult{}, fmt.Errorf(
			"apply Device Sync registry rollback: %w", err,
		)
	}
	if err := coordinator.Store.ApplyDeviceSyncMigrationRollback(
		ctx, coordinator.Signer.DeploymentID(), evidence, journal.anchor,
		acceptance.AcceptedAtMilliseconds,
	); err != nil {
		return DeviceSyncRollbackResult{}, fmt.Errorf(
			"apply Device Sync database rollback: %w", err,
		)
	}
	rolledBack, err := evidence.RollbackManifest.VerifiedPayload()
	if err != nil || rolledBack.Migration == nil {
		return DeviceSyncRollbackResult{}, serviceauthority.ErrInvalid
	}
	state, err := coordinator.Store.GetDeviceSyncScopeEnforcement(
		ctx, rolledBack.Scope.ScopeID,
	)
	if err != nil {
		return DeviceSyncRollbackResult{}, err
	}
	identities, err := coordinator.Bindings.CurrentBindingIdentities(
		serviceauthority.ScopeDeviceSync,
	)
	if err != nil {
		return DeviceSyncRollbackResult{}, err
	}
	var binding *serviceauthority.BindingIdentity
	for index := range identities {
		if identities[index].Scope == rolledBack.Scope {
			copy := identities[index]
			binding = &copy
			break
		}
	}
	if binding == nil || state.Authority == nil || state.LocalDeploymentID == nil ||
		*state.LocalDeploymentID != coordinator.Signer.DeploymentID() ||
		state.Authority.ActiveDeploymentID != binding.DeploymentID ||
		state.Authority.Revision != binding.Revision ||
		state.Authority.ManifestDigest != binding.Digest ||
		!sameOptionalDigest(
			state.Authority.TransitionEvidenceDigest,
			binding.TransitionEvidenceDigest,
		) || state.ActiveExportWriteFenceID != nil ||
		state.ActiveMigrationImportID != nil || state.ActiveRollbackImportID != nil {
		return DeviceSyncRollbackResult{}, errors.New(
			"Device Sync registry and database rollback identities conflict",
		)
	}
	sourceSide := coordinator.Signer.DeploymentID() ==
		rolledBack.Migration.SourceDeploymentID
	if sourceSide && (state.State != postgres.DeviceSyncScopeWritable || binding.WriteFenced) ||
		!sourceSide && (state.State != postgres.DeviceSyncScopeRetired || !binding.WriteFenced) {
		return DeviceSyncRollbackResult{}, errors.New(
			"Device Sync registry and database rollback write states conflict",
		)
	}
	if err := coordinator.Custody.completeDeviceSyncRollbackJournal(journal); err != nil {
		return DeviceSyncRollbackResult{}, err
	}
	return DeviceSyncRollbackResult{Binding: *binding, State: state}, nil
}
