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

type DeviceSyncMigrationActivationStore interface {
	ApplyDeviceSyncMigrationActivation(
		context.Context,
		uuid.UUID,
		serviceauthority.MigrationActivationEvidence,
		serviceauthority.TrustAnchor,
		int64,
	) error
	GetDeviceSyncScopeEnforcement(
		context.Context,
		uuid.UUID,
	) (postgres.DeviceSyncScopeEnforcement, error)
}

type DeviceSyncActivationResult struct {
	Binding serviceauthority.BindingIdentity
	State   postgres.DeviceSyncScopeEnforcement
}

// DeviceSyncActivationCoordinator advances the two local durable authority
// stores from one exact, previously prepared transfer. It records accepted
// evidence first, applies BindingRegistry second, and commits PostgreSQL last.
// Every step is exact and idempotent, so Recover can finish a cross-store crash
// without asking a deployment to reinterpret expired operational evidence.
type DeviceSyncActivationCoordinator struct {
	Store    DeviceSyncMigrationActivationStore
	Custody  *FileArtifactCustody
	Bindings *serviceauthority.BindingRegistry
	Signer   *serviceauthority.DeploymentSigner
}

func (coordinator *DeviceSyncActivationCoordinator) Activate(
	ctx context.Context,
	evidence serviceauthority.MigrationActivationEvidence,
	anchor serviceauthority.TrustAnchor,
	now time.Time,
) (DeviceSyncActivationResult, error) {
	if coordinator == nil || coordinator.Store == nil || coordinator.Custody == nil ||
		coordinator.Bindings == nil || coordinator.Signer == nil ||
		ctx == nil || now.IsZero() || now.UnixMilli() < 0 {
		return DeviceSyncActivationResult{}, serviceauthority.ErrInvalid
	}
	journal, err := coordinator.Custody.stageDeviceSyncActivationJournal(
		ctx, coordinator.Signer, evidence, anchor, now.UnixMilli(),
	)
	if err != nil {
		return DeviceSyncActivationResult{}, fmt.Errorf(
			"stage Device Sync migration activation: %w", err,
		)
	}
	return coordinator.applyJournal(ctx, journal, now.UnixMilli())
}

// Recover validates all retained activation journals and completes only those
// belonging to this deployment. Journals for another local deployment are a
// configuration/custody conflict rather than ignorable work.
func (coordinator *DeviceSyncActivationCoordinator) Recover(
	ctx context.Context,
	now time.Time,
) ([]DeviceSyncActivationResult, error) {
	if coordinator == nil || coordinator.Store == nil || coordinator.Custody == nil ||
		coordinator.Bindings == nil || coordinator.Signer == nil ||
		ctx == nil || now.IsZero() || now.UnixMilli() < 0 {
		return nil, serviceauthority.ErrInvalid
	}
	journals, err := coordinator.Custody.listDeviceSyncActivationJournals(ctx)
	if err != nil {
		return nil, fmt.Errorf("list Device Sync migration activation recovery: %w", err)
	}
	results := make([]DeviceSyncActivationResult, 0, len(journals))
	for _, journal := range journals {
		acceptance, acceptanceErr := journal.record.Acceptance.VerifiedPayload()
		if acceptanceErr != nil ||
			acceptance.LocalDeploymentID != coordinator.Signer.DeploymentID() ||
			journal.record.Acceptance.Signature.PublicSigningKeyX963 !=
				coordinator.Signer.PublicSigningKeyX963() ||
			journal.record.Acceptance.Signature.SigningKeyFingerprint !=
				coordinator.Signer.SigningKeyFingerprint() {
			return nil, errors.New(
				"Device Sync activation custody belongs to another local deployment",
			)
		}
		result, err := coordinator.applyJournal(ctx, journal, now.UnixMilli())
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}
	return results, nil
}

func (coordinator *DeviceSyncActivationCoordinator) applyJournal(
	ctx context.Context,
	journal deviceSyncActivationJournal,
	nowMilliseconds int64,
) (DeviceSyncActivationResult, error) {
	acceptance, err := journal.record.Acceptance.VerifiedPayload()
	if err != nil || nowMilliseconds < acceptance.AcceptedAtMilliseconds {
		return DeviceSyncActivationResult{}, errors.New(
			"Device Sync activation clock moved before durable evidence acceptance",
		)
	}
	evidence := journal.record.Evidence
	// Use the immutable acceptance instant for a first post-crash application.
	// The journal itself was written only after full live validation.
	if err := coordinator.Bindings.ApplyMigrationActivation(
		evidence,
		journal.anchor,
		acceptance.AcceptedAtMilliseconds,
	); err != nil {
		return DeviceSyncActivationResult{}, fmt.Errorf(
			"apply Device Sync registry migration activation: %w", err,
		)
	}
	if err := coordinator.Store.ApplyDeviceSyncMigrationActivation(
		ctx,
		coordinator.Signer.DeploymentID(),
		evidence,
		journal.anchor,
		acceptance.AcceptedAtMilliseconds,
	); err != nil {
		return DeviceSyncActivationResult{}, fmt.Errorf(
			"apply Device Sync database migration activation: %w", err,
		)
	}
	activation, err := evidence.ActivationManifest.VerifiedPayload()
	if err != nil || activation.Migration == nil {
		return DeviceSyncActivationResult{}, serviceauthority.ErrInvalid
	}
	state, err := coordinator.Store.GetDeviceSyncScopeEnforcement(
		ctx, activation.Scope.ScopeID,
	)
	if err != nil {
		return DeviceSyncActivationResult{}, fmt.Errorf(
			"verify Device Sync database migration activation: %w", err,
		)
	}
	identities, err := coordinator.Bindings.CurrentBindingIdentities(
		serviceauthority.ScopeDeviceSync,
	)
	if err != nil {
		return DeviceSyncActivationResult{}, fmt.Errorf(
			"verify Device Sync registry migration activation: %w", err,
		)
	}
	var binding *serviceauthority.BindingIdentity
	for index := range identities {
		if identities[index].Scope == activation.Scope {
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
		) {
		return DeviceSyncActivationResult{}, errors.New(
			"Device Sync registry and database activation identities conflict",
		)
	}
	targetSide := coordinator.Signer.DeploymentID() ==
		activation.Migration.TargetDeploymentID
	if targetSide && (state.State != postgres.DeviceSyncScopeWritable ||
		binding.WriteFenced) ||
		!targetSide && (state.State != postgres.DeviceSyncScopeRetired ||
			!binding.WriteFenced) {
		return DeviceSyncActivationResult{}, errors.New(
			"Device Sync registry and database activation write states conflict",
		)
	}
	if err := coordinator.Custody.completeDeviceSyncActivationJournal(journal); err != nil {
		return DeviceSyncActivationResult{}, fmt.Errorf(
			"complete Device Sync migration activation journal: %w", err,
		)
	}
	return DeviceSyncActivationResult{Binding: *binding, State: state}, nil
}

func sameOptionalDigest(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
