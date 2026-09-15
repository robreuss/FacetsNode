package serviceauthority

import "time"

// CurrentCustodyPeerIdentityAt is a defensive projection for the receiver's
// independently provisioned registry. It is not a client/link grant or a bearer.
// Unlike general readiness snapshots, bare in-memory bindings are forbidden.
// The caller retains its scope lease through durable reconciliation/effect.
func (registry *BindingRegistry) CurrentCustodyPeerIdentityAt(scope Scope, now time.Time) (BindingIdentity, error) {
	if registry == nil || scope.Validate() != nil || now.UnixMilli() < 0 ||
		(scope.Kind != ScopeDeviceSync && scope.Kind != ScopeBackupCustody) {
		return BindingIdentity{}, ErrInvalid
	}
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	current, exists := registry.bindings[scope]
	if registry.poisoned || !exists || registry.persistencePath == "" || current.Manifest == nil ||
		validateCurrentBinding(scope, current, registry.expectedDeploymentID) != nil ||
		current.DeploymentID != registry.expectedDeploymentID {
		return BindingIdentity{}, ErrInvalid
	}
	payload, err := current.Manifest.VerifiedPayload()
	nowMilliseconds := now.UnixMilli()
	if err != nil || payload.Validate(&nowMilliseconds) != nil {
		return BindingIdentity{}, ErrInvalid
	}
	return BindingIdentity{Scope: scope, Revision: current.Revision, Digest: current.Digest,
		DeploymentID: current.DeploymentID, WriteFenced: current.WriteFence != nil}, nil
}
