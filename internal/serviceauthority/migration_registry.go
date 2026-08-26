package serviceauthority

import (
	"bytes"
	"time"

	"github.com/google/uuid"
)

const (
	migrationPreparationEvidenceReferenceDomain  = "Facets service migration preparation evidence reference v1\x00"
	migrationCancellationEvidenceReferenceDomain = "Facets service migration cancellation evidence reference v1\x00"
	migrationActivationEvidenceReferenceDomain   = "Facets service migration activation evidence reference v1\x00"
	migrationRollbackEvidenceReferenceDomain     = "Facets service migration rollback evidence reference v1\x00"
)

// ApplyMigrationPreparation installs an authority-signed preparation only
// after validating the exact target offer it names. It does not create a
// target, copy state, sign a snapshot, or activate either deployment.
func (registry *BindingRegistry) ApplyMigrationPreparation(
	preparation MigrationPreparation,
	anchor TrustAnchor,
	nowMilliseconds int64,
) error {
	if registry == nil || registry.expectedDeploymentID == uuid.Nil {
		return ErrInvalid
	}
	evidenceDigest, err := migrationEvidenceDigest(
		migrationPreparationEvidenceReferenceDomain,
		preparation,
	)
	if err != nil {
		return ErrInvalid
	}
	if registry.acceptsExactManifestRetry(
		preparation.PreparationManifest,
		&evidenceDigest,
	) {
		return nil
	}
	if _, _, err := preparation.Validate(anchor, nowMilliseconds); err != nil {
		return ErrInvalid
	}
	current, err := preparation.CurrentManifest.VerifiedPayload()
	if err != nil {
		return ErrInvalid
	}
	next, err := preparation.PreparationManifest.VerifiedPayload()
	if err != nil || next.Migration == nil {
		return ErrInvalid
	}
	currentDigest, err := preparation.CurrentManifest.ReferenceDigest()
	nextDigest, nextDigestErr := preparation.PreparationManifest.ReferenceDigest()
	if err != nil || nextDigestErr != nil {
		return ErrInvalid
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	existing, exists := registry.bindings[current.Scope]
	if exists && (!bindingMatchesManifest(
		existing,
		preparation.CurrentManifest,
		current,
		currentDigest,
	) || existing.WriteFence != nil) {
		return ErrInvalid
	}
	if !exists && registry.expectedDeploymentID != next.Migration.TargetDeploymentID {
		return ErrInvalid
	}
	manifestCopy := preparation.PreparationManifest
	binding := CurrentBinding{
		Revision:                 next.Revision,
		Digest:                   nextDigest,
		DeploymentID:             next.ActiveDeployment.DeploymentID,
		Manifest:                 &manifestCopy,
		TransitionEvidenceDigest: &evidenceDigest,
	}
	if validateCurrentBinding(next.Scope, binding, registry.expectedDeploymentID) != nil {
		return ErrInvalid
	}
	return registry.installBindingLocked(next.Scope, binding)
}

// ApplyMigrationCancellation installs the authority-signed terminal successor
// for one exact preparation. The source atomically clears only its local
// forward fence; the target records the same cancellation manifest while its
// binding continues to name the remote source as active and therefore cannot
// authorize local capability requests.
func (registry *BindingRegistry) ApplyMigrationCancellation(
	evidence MigrationCancellationEvidence,
	anchor TrustAnchor,
	nowMilliseconds int64,
) error {
	if registry == nil || registry.expectedDeploymentID == uuid.Nil {
		return ErrInvalid
	}
	evidenceDigest, err := migrationEvidenceDigest(
		migrationCancellationEvidenceReferenceDomain,
		evidence,
	)
	if err != nil {
		return ErrInvalid
	}
	if registry.acceptsExactManifestRetry(
		evidence.CancellationManifest,
		&evidenceDigest,
	) {
		return nil
	}
	next, err := evidence.ValidateHistoricalCatchUp(anchor, nowMilliseconds)
	if err != nil {
		return ErrInvalid
	}
	preparationEvidenceDigest, err := migrationEvidenceDigest(
		migrationPreparationEvidenceReferenceDomain,
		evidence.Preparation,
	)
	if err != nil {
		return ErrInvalid
	}
	current, err := evidence.Preparation.PreparationManifest.VerifiedPayload()
	if err != nil || current.Migration == nil {
		return ErrInvalid
	}
	return registry.installVerifiedSuccessor(
		evidence.Preparation.PreparationManifest,
		current,
		evidence.CancellationManifest,
		next,
		&preparationEvidenceDigest,
		&evidenceDigest,
		func(binding CurrentBinding) (*MigrationWriteFence, error) {
			switch registry.expectedDeploymentID {
			case current.Migration.SourceDeploymentID:
				// A nil fence means cancellation happened before export. A
				// non-nil fence is already validated against this exact
				// preparation binding and can now be atomically cleared.
				return nil, nil
			case current.Migration.TargetDeploymentID:
				if binding.WriteFence != nil {
					return nil, ErrInvalid
				}
				return nil, nil
			default:
				return nil, ErrInvalid
			}
		},
	)
}

// StageMigrationWriteFence persists the exact canonical snapshot payload after
// the service state store has atomically committed the named write fence and
// state commitment. It runs before deployment signing and immediately makes
// subsequent HTTP writes fail closed.
func (registry *BindingRegistry) StageMigrationWriteFence(
	authorityManifest Manifest,
	payload MigrationSnapshotPayload,
	anchor TrustAnchor,
	nowMilliseconds int64,
) error {
	if registry == nil || registry.expectedDeploymentID == uuid.Nil {
		return ErrInvalid
	}
	authority, err := authorityManifest.VerifiedPayload()
	manifestDigest, digestErr := authorityManifest.ReferenceDigest()
	encodedPayload, encodeErr := canonicalJSON(payload)
	if err != nil || digestErr != nil || encodeErr != nil || payload.Validate(nil) != nil {
		return ErrInvalid
	}
	registry.mu.RLock()
	current, exists := registry.bindings[authority.Scope]
	exactFence := !registry.poisoned && exists && bindingMatchesManifest(
		current, authorityManifest, authority, manifestDigest,
	) && current.WriteFence != nil &&
		bytes.Equal(current.WriteFence.SnapshotPayload, encodedPayload)
	registry.mu.RUnlock()
	if exactFence {
		return nil
	}
	authority, err = authorityManifest.Authorize(anchor, nowMilliseconds)
	if err != nil || authority.Migration == nil ||
		(authority.Transition != TransitionMigrationPreparation &&
			authority.Transition != TransitionMigrationActivation) ||
		len(authority.PreparedDeployments) != 1 ||
		authority.ActiveDeployment.DeploymentID != registry.expectedDeploymentID {
		return ErrInvalid
	}
	if payload.Validate(&nowMilliseconds) != nil ||
		payload.MigrationID != authority.Migration.MigrationID ||
		payload.Scope != authority.Scope || payload.AuthorityManifestDigest != manifestDigest ||
		payload.ExportingDeploymentID != authority.ActiveDeployment.DeploymentID ||
		payload.ImportingDeploymentID != authority.PreparedDeployments[0].DeploymentID {
		return ErrInvalid
	}
	fence := &MigrationWriteFence{
		AuthorityManifestDigest:        manifestDigest,
		AuthorityRevision:              authority.Revision,
		ExportingPublicSigningKeyX963:  authority.ActiveDeployment.PublicSigningKeyX963,
		ExportingSigningKeyFingerprint: authority.ActiveDeployment.SigningKeyFingerprint,
		SnapshotPayload:                encodedPayload,
	}

	registry.mu.Lock()
	defer registry.mu.Unlock()
	current, exists = registry.bindings[authority.Scope]
	if !exists || !bindingMatchesManifest(current, authorityManifest, authority, manifestDigest) {
		return ErrInvalid
	}
	if current.WriteFence != nil {
		if canonicalEqual(current.WriteFence, fence) {
			return nil
		}
		return ErrInvalid
	}
	if fence.validate(authority.Scope, current, registry.expectedDeploymentID) != nil {
		return ErrInvalid
	}
	next := current
	next.WriteFence = fence
	return registry.installBindingLocked(authority.Scope, next)
}

// ConfirmMigrationWriteFenceSnapshot accepts the deployment signature only
// after the exact unsigned payload is already durably fenced. This ordering
// prevents the deployment from producing apparently safe snapshot evidence
// while its HTTP authority boundary remains writable.
func (registry *BindingRegistry) ConfirmMigrationWriteFenceSnapshot(
	scope Scope,
	snapshot MigrationSnapshot,
) error {
	return registry.ConfirmMigrationWriteFenceSnapshotAt(
		scope,
		snapshot,
		time.Now().UnixMilli(),
	)
}

func (registry *BindingRegistry) ConfirmMigrationWriteFenceSnapshotAt(
	scope Scope,
	snapshot MigrationSnapshot,
	nowMilliseconds int64,
) error {
	if registry == nil || registry.expectedDeploymentID == uuid.Nil || scope.Validate() != nil {
		return ErrInvalid
	}
	// Verify the canonical signature before consulting persisted state, but defer
	// the temporal check until after the exact-retry branch. Once this exact
	// snapshot is durably confirmed, its expiry must not turn a lost-response
	// retry into a false failure.
	payload, err := snapshot.VerifiedPayload(nil)
	digest, digestErr := snapshot.ReferenceDigest()
	if err != nil || digestErr != nil || payload.Scope != scope ||
		payload.ExportingDeploymentID != registry.expectedDeploymentID {
		return ErrInvalid
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	current, exists := registry.bindings[scope]
	if registry.poisoned || !exists || current.WriteFence == nil ||
		!bytes.Equal(current.WriteFence.SnapshotPayload, snapshot.Payload) ||
		snapshot.Signature.PublicSigningKeyX963 !=
			current.WriteFence.ExportingPublicSigningKeyX963 ||
		snapshot.Signature.SigningKeyFingerprint !=
			current.WriteFence.ExportingSigningKeyFingerprint {
		return ErrInvalid
	}
	if current.WriteFence.Snapshot != nil {
		if current.WriteFence.matchesSnapshot(snapshot) {
			return nil
		}
		return ErrInvalid
	}
	if payload.Validate(&nowMilliseconds) != nil {
		return ErrInvalid
	}
	nextFence := *current.WriteFence
	snapshotCopy := snapshot
	nextFence.Snapshot = &snapshotCopy
	nextFence.SnapshotReferenceDigest = &digest
	next := current
	next.WriteFence = &nextFence
	if nextFence.validate(scope, next, registry.expectedDeploymentID) != nil {
		return ErrInvalid
	}
	return registry.installBindingLocked(scope, next)
}

// SignStagedMigrationSnapshot is the only FacetsNode snapshot-signing seam. It
// refuses any payload that was not already persisted as a local write fence.
func (registry *BindingRegistry) SignStagedMigrationSnapshot(
	scope Scope,
	signer *DeploymentSigner,
) (MigrationSnapshot, error) {
	return registry.SignStagedMigrationSnapshotAt(
		scope,
		signer,
		time.Now().UnixMilli(),
	)
}

// LoadConfirmedMigrationSnapshot returns only an already-persisted deployment
// signature for the exact write fence. It never signs. Source recovery uses it
// to distinguish a promoted/lost-response operation from an unsigned fence
// whose artifact custody is missing.
func (registry *BindingRegistry) LoadConfirmedMigrationSnapshot(
	scope Scope,
	signer *DeploymentSigner,
) (MigrationSnapshot, error) {
	if registry == nil || signer == nil || registry.expectedDeploymentID == uuid.Nil ||
		signer.DeploymentID() != registry.expectedDeploymentID || scope.Validate() != nil {
		return MigrationSnapshot{}, ErrInvalid
	}
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	binding, exists := registry.bindings[scope]
	if registry.poisoned || !exists || binding.WriteFence == nil ||
		binding.WriteFence.Snapshot == nil ||
		signer.PublicSigningKeyX963() != binding.WriteFence.ExportingPublicSigningKeyX963 ||
		signer.SigningKeyFingerprint() !=
			binding.WriteFence.ExportingSigningKeyFingerprint {
		return MigrationSnapshot{}, ErrInvalid
	}
	snapshot := *binding.WriteFence.Snapshot
	snapshot.Payload = append([]byte(nil), snapshot.Payload...)
	return snapshot, nil
}

func (registry *BindingRegistry) SignStagedMigrationSnapshotAt(
	scope Scope,
	signer *DeploymentSigner,
	nowMilliseconds int64,
) (MigrationSnapshot, error) {
	if registry == nil || signer == nil || registry.expectedDeploymentID == uuid.Nil ||
		signer.DeploymentID() != registry.expectedDeploymentID || scope.Validate() != nil {
		return MigrationSnapshot{}, ErrInvalid
	}
	registry.mu.RLock()
	binding, exists := registry.bindings[scope]
	if registry.poisoned || !exists || binding.WriteFence == nil {
		registry.mu.RUnlock()
		return MigrationSnapshot{}, ErrInvalid
	}
	if signer.PublicSigningKeyX963() != binding.WriteFence.ExportingPublicSigningKeyX963 ||
		signer.SigningKeyFingerprint() !=
			binding.WriteFence.ExportingSigningKeyFingerprint {
		registry.mu.RUnlock()
		return MigrationSnapshot{}, ErrInvalid
	}
	if binding.WriteFence.Snapshot != nil {
		// A crash or lost response after confirmation must return the one
		// persisted signature, never produce another ECDSA signature over the
		// same payload. The binding was independently revalidated on load.
		existing := *binding.WriteFence.Snapshot
		existing.Payload = append([]byte(nil), existing.Payload...)
		registry.mu.RUnlock()
		return existing, nil
	}
	payload := append([]byte(nil), binding.WriteFence.SnapshotPayload...)
	registry.mu.RUnlock()

	var decoded MigrationSnapshotPayload
	if decodeCanonical(payload, &decoded) != nil || decoded.Validate(&nowMilliseconds) != nil ||
		decoded.ExportingDeploymentID != signer.DeploymentID() {
		return MigrationSnapshot{}, ErrInvalid
	}
	signature, err := signer.signRecord(migrationSnapshotSignatureDomain, payload)
	if err != nil {
		return MigrationSnapshot{}, ErrInvalid
	}
	snapshot := MigrationSnapshot{Payload: payload, Signature: signature}
	if err := registry.ConfirmMigrationWriteFenceSnapshotAt(
		scope,
		snapshot,
		nowMilliseconds,
	); err != nil {
		return MigrationSnapshot{}, ErrInvalid
	}
	return snapshot, nil
}

// ApplyMigrationActivation accepts no bare activation manifest. The source
// must already retain the exact forward fence; the target must present the
// complete preparation, snapshot, and readiness evidence.
func (registry *BindingRegistry) ApplyMigrationActivation(
	evidence MigrationActivationEvidence,
	anchor TrustAnchor,
	nowMilliseconds int64,
) error {
	if registry == nil || registry.expectedDeploymentID == uuid.Nil {
		return ErrInvalid
	}
	evidenceDigest, err := evidence.ReferenceDigest()
	if err != nil {
		return ErrInvalid
	}
	if registry.acceptsExactManifestRetry(
		evidence.ActivationManifest,
		&evidenceDigest,
	) {
		return nil
	}
	next, err := evidence.ValidateHistoricalCatchUp(anchor, nowMilliseconds)
	if err != nil {
		return ErrInvalid
	}
	preparationEvidenceDigest, err := migrationEvidenceDigest(
		migrationPreparationEvidenceReferenceDomain,
		evidence.Preparation,
	)
	if err != nil {
		return ErrInvalid
	}
	current, err := evidence.Preparation.PreparationManifest.VerifiedPayload()
	if err != nil || current.Migration == nil {
		return ErrInvalid
	}
	return registry.installVerifiedSuccessor(
		evidence.Preparation.PreparationManifest,
		current,
		evidence.ActivationManifest,
		next,
		&preparationEvidenceDigest,
		&evidenceDigest,
		func(binding CurrentBinding) (*MigrationWriteFence, error) {
			switch registry.expectedDeploymentID {
			case current.Migration.SourceDeploymentID:
				if binding.WriteFence == nil ||
					!binding.WriteFence.matchesSnapshot(evidence.Snapshot) {
					return nil, ErrInvalid
				}
				return binding.WriteFence, nil
			case current.Migration.TargetDeploymentID:
				if binding.WriteFence != nil {
					return nil, ErrInvalid
				}
				return nil, nil
			default:
				return nil, ErrInvalid
			}
		},
	)
}

// ApplyMigrationRollback performs the reverse evidence gate. The active target
// must already retain the exact reverse-transfer fence. The former source may
// clear its forward fence only while atomically installing the validated
// rollback successor that names it active again.
func (registry *BindingRegistry) ApplyMigrationRollback(
	evidence MigrationRollbackEvidence,
	anchor TrustAnchor,
	nowMilliseconds int64,
) error {
	if registry == nil || registry.expectedDeploymentID == uuid.Nil {
		return ErrInvalid
	}
	evidenceDigest, err := evidence.ReferenceDigest()
	if err != nil {
		return ErrInvalid
	}
	if registry.acceptsExactManifestRetry(
		evidence.RollbackManifest,
		&evidenceDigest,
	) {
		return nil
	}
	next, err := evidence.ValidateHistoricalCatchUp(anchor, nowMilliseconds)
	if err != nil {
		return ErrInvalid
	}
	activationEvidenceDigest, err := evidence.ActivationEvidence.ReferenceDigest()
	if err != nil {
		return ErrInvalid
	}
	current, err := evidence.ActivationEvidence.ActivationManifest.VerifiedPayload()
	if err != nil || current.Migration == nil {
		return ErrInvalid
	}
	return registry.installVerifiedSuccessor(
		evidence.ActivationEvidence.ActivationManifest,
		current,
		evidence.RollbackManifest,
		next,
		&activationEvidenceDigest,
		&evidenceDigest,
		func(binding CurrentBinding) (*MigrationWriteFence, error) {
			switch registry.expectedDeploymentID {
			case current.Migration.TargetDeploymentID:
				if binding.WriteFence == nil ||
					!binding.WriteFence.matchesSnapshot(evidence.TargetSnapshot) {
					return nil, ErrInvalid
				}
				return binding.WriteFence, nil
			case current.Migration.SourceDeploymentID:
				// The source readiness record proves application of the reverse
				// snapshot. Installing the rollback successor is the authority
				// boundary at which this deployment may accept writes again.
				return nil, nil
			default:
				return nil, ErrInvalid
			}
		},
	)
}

// ApplyServiceAuthoritySuccessor installs ordinary route/policy successors or
// migration retirement. Preparation, activation, rollback, and recovery each
// require their dedicated evidence path or remain unsupported.
func (registry *BindingRegistry) ApplyServiceAuthoritySuccessor(
	currentManifest Manifest,
	successor Manifest,
	anchor TrustAnchor,
	nowMilliseconds int64,
) error {
	if registry == nil || registry.expectedDeploymentID == uuid.Nil {
		return ErrInvalid
	}
	next, err := successor.VerifiedPayload()
	if err != nil {
		return ErrInvalid
	}
	switch next.Transition {
	case TransitionPolicyUpdate, TransitionRouteRotation, TransitionMigrationRetirement:
	default:
		return ErrInvalid
	}
	if registry.acceptsExactManifestRetry(successor, nil) {
		return nil
	}
	next, err = successor.Authorize(anchor, nowMilliseconds)
	if err != nil {
		return ErrInvalid
	}
	current, err := currentManifest.VerifiedPayload()
	if err != nil {
		return ErrInvalid
	}
	if _, err := successor.ValidateSuccessor(currentManifest); err != nil {
		return ErrInvalid
	}
	fenceForNext := func(binding CurrentBinding) (*MigrationWriteFence, error) {
		if next.Transition != TransitionMigrationRetirement || current.Migration == nil {
			return binding.WriteFence, nil
		}
		switch registry.expectedDeploymentID {
		case current.Migration.SourceDeploymentID:
			// The retired source remains durably fenced even after the target is
			// final. It cannot install a later manifest that no longer names it.
			return binding.WriteFence, nil
		case current.Migration.TargetDeploymentID:
			// Once the rollback deadline has passed, retirement is the terminal
			// evidence that makes an abandoned reverse fence safe to clear.
			return nil, nil
		default:
			return nil, ErrInvalid
		}
	}
	return registry.installVerifiedSuccessor(
		currentManifest,
		current,
		successor,
		next,
		nil,
		nil,
		fenceForNext,
	)
}

func (registry *BindingRegistry) installVerifiedSuccessor(
	currentManifest Manifest,
	currentPayload ManifestPayload,
	nextManifest Manifest,
	nextPayload ManifestPayload,
	requiredCurrentEvidenceDigest *string,
	evidenceDigest *string,
	fenceForNext func(CurrentBinding) (*MigrationWriteFence, error),
) error {
	currentDigest, err := currentManifest.ReferenceDigest()
	if err != nil {
		return ErrInvalid
	}
	nextDigest, err := nextManifest.ReferenceDigest()
	if err != nil {
		return ErrInvalid
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.poisoned {
		return ErrInvalid
	}
	current, exists := registry.bindings[currentPayload.Scope]
	if exists && bindingMatchesManifest(current, nextManifest, nextPayload, nextDigest) {
		expectedFence, fenceErr := fenceForNext(current)
		if fenceErr == nil && canonicalEqual(current.WriteFence, expectedFence) &&
			canonicalEqual(current.TransitionEvidenceDigest, evidenceDigest) {
			return nil
		}
		return ErrInvalid
	}
	if !exists || !bindingMatchesManifest(current, currentManifest, currentPayload, currentDigest) {
		return ErrInvalid
	}
	if requiredCurrentEvidenceDigest != nil &&
		!canonicalEqual(current.TransitionEvidenceDigest, requiredCurrentEvidenceDigest) {
		return ErrInvalid
	}
	fence, err := fenceForNext(current)
	if err != nil {
		return ErrInvalid
	}
	manifestCopy := nextManifest
	next := CurrentBinding{
		Revision:                 nextPayload.Revision,
		Digest:                   nextDigest,
		DeploymentID:             nextPayload.ActiveDeployment.DeploymentID,
		Manifest:                 &manifestCopy,
		TransitionEvidenceDigest: evidenceDigest,
		WriteFence:               fence,
	}
	if validateCurrentBinding(currentPayload.Scope, next, registry.expectedDeploymentID) != nil {
		return ErrInvalid
	}
	return registry.installBindingLocked(currentPayload.Scope, next)
}

func bindingMatchesManifest(
	binding CurrentBinding,
	manifest Manifest,
	payload ManifestPayload,
	digest string,
) bool {
	if binding.Revision != payload.Revision || binding.Digest != digest ||
		binding.DeploymentID != payload.ActiveDeployment.DeploymentID {
		return false
	}
	return binding.Manifest == nil || canonicalEqual(binding.Manifest, &manifest)
}

func (registry *BindingRegistry) acceptsExactManifestRetry(
	manifest Manifest,
	evidenceDigest *string,
) bool {
	payload, err := manifest.VerifiedPayload()
	digest, digestErr := manifest.ReferenceDigest()
	if err != nil || digestErr != nil {
		return false
	}
	registry.mu.RLock()
	binding, exists := registry.bindings[payload.Scope]
	poisoned := registry.poisoned
	registry.mu.RUnlock()
	return !poisoned && exists && bindingMatchesManifest(binding, manifest, payload, digest) &&
		canonicalEqual(binding.TransitionEvidenceDigest, evidenceDigest)
}

func (registry *BindingRegistry) installBindingLocked(scope Scope, binding CurrentBinding) error {
	if registry.poisoned {
		return ErrInvalid
	}
	nextBindings := make(map[Scope]CurrentBinding, len(registry.bindings)+1)
	for existingScope, existing := range registry.bindings {
		nextBindings[existingScope] = existing
	}
	nextBindings[scope] = binding
	if err := registry.persistBindingsLocked(nextBindings); err != nil {
		return err
	}
	registry.bindings = nextBindings
	return nil
}

func (fence MigrationWriteFence) matchesSnapshot(snapshot MigrationSnapshot) bool {
	digest, err := snapshot.ReferenceDigest()
	return err == nil && fence.Snapshot != nil && fence.SnapshotReferenceDigest != nil &&
		digest == *fence.SnapshotReferenceDigest &&
		canonicalEqual(*fence.Snapshot, snapshot)
}
