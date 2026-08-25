package serviceauthority

import (
	"time"

	"github.com/google/uuid"
)

// MutationAuthorization is a sealed result of checking one exact request
// binding against the current BindingRegistry. Callers can inspect it, but
// cannot construct or alter its authority facts outside this package.
//
// It is intentionally distinct from RequestBinding: request headers are
// untrusted input, while this value records a successful registry decision at
// one explicit time and can be passed to a durable state-store fence.
type MutationAuthorization struct {
	scope                    Scope
	authorityRevision        uint64
	authorityManifestDigest  string
	deploymentID             uuid.UUID
	authorizedAtMilliseconds int64
}

// AuthorizeMutationAt validates an exact mutation request and returns sealed
// facts suitable for the service state store's independent durable check.
func (registry *BindingRegistry) AuthorizeMutationAt(
	binding RequestBinding,
	now time.Time,
) (MutationAuthorization, error) {
	if err := registry.AuthorizeRequestAt(binding, RequestMutation, now); err != nil {
		return MutationAuthorization{}, err
	}
	return MutationAuthorization{
		scope:                    binding.Scope,
		authorityRevision:        binding.AuthorityRevision,
		authorityManifestDigest:  binding.AuthorityDigest,
		deploymentID:             binding.DeploymentID,
		authorizedAtMilliseconds: now.UnixMilli(),
	}, nil
}

// AuthorizeInternalDeviceSyncMutationAt seals the exact current Device Sync
// authority for a trusted background mutation that has no client request
// headers. The caller must already hold this registry's mutation lease for the
// scope and retain it until the durable mutation fence and mutation complete.
//
// Only a deployment-scoped persistent registry can issue this evidence. The
// current signed Manifest must be active at the explicit time, name this local
// deployment as active, and remain unfenced.
func (registry *BindingRegistry) AuthorizeInternalDeviceSyncMutationAt(
	scope Scope,
	now time.Time,
) (MutationAuthorization, error) {
	nowMilliseconds := now.UnixMilli()
	if registry == nil || scope.Validate() != nil ||
		scope.Kind != ScopeDeviceSync || nowMilliseconds < 0 {
		return MutationAuthorization{}, ErrInvalid
	}
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	if registry.poisoned {
		return MutationAuthorization{}, ErrBindingUnavailable
	}
	localDeploymentID := registry.expectedDeploymentID
	if localDeploymentID == uuid.Nil {
		return MutationAuthorization{}, ErrInvalid
	}
	current, exists := registry.bindings[scope]
	if !exists || current.Manifest == nil || current.WriteFence != nil ||
		current.DeploymentID != localDeploymentID ||
		validateCurrentBinding(
			scope,
			current,
			localDeploymentID,
		) != nil {
		return MutationAuthorization{}, ErrInvalid
	}
	payload, err := current.Manifest.VerifiedPayload()
	if err != nil || payload.Validate(&nowMilliseconds) != nil ||
		payload.Scope != scope ||
		payload.ActiveDeployment.DeploymentID != localDeploymentID {
		return MutationAuthorization{}, ErrInvalid
	}
	return MutationAuthorization{
		scope:                    scope,
		authorityRevision:        current.Revision,
		authorityManifestDigest:  current.Digest,
		deploymentID:             localDeploymentID,
		authorizedAtMilliseconds: nowMilliseconds,
	}, nil
}

func (authorization MutationAuthorization) Scope() Scope {
	return authorization.scope
}

func (authorization MutationAuthorization) AuthorityRevision() uint64 {
	return authorization.authorityRevision
}

func (authorization MutationAuthorization) AuthorityManifestDigest() string {
	return authorization.authorityManifestDigest
}

func (authorization MutationAuthorization) DeploymentID() uuid.UUID {
	return authorization.deploymentID
}

func (authorization MutationAuthorization) AuthorizedAtMilliseconds() int64 {
	return authorization.authorizedAtMilliseconds
}

// ValidateFor rejects a zero, fabricated, wrong-service, or wrong-deployment
// authorization before a durable store trusts its facts.
func (authorization MutationAuthorization) ValidateFor(
	expectedScopeKind ScopeKind,
	expectedDeploymentID uuid.UUID,
) error {
	if !expectedScopeKind.Valid() || expectedDeploymentID == uuid.Nil ||
		authorization.scope.Validate() != nil ||
		authorization.scope.Kind != expectedScopeKind ||
		authorization.authorityRevision == 0 ||
		!validDigest(authorization.authorityManifestDigest) ||
		authorization.deploymentID != expectedDeploymentID ||
		authorization.authorizedAtMilliseconds < 0 {
		return ErrInvalid
	}
	return nil
}
