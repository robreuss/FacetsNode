package serviceauthority

import (
	"bytes"
	"sort"
	"time"

	"github.com/google/uuid"
)

// BindingIdentity is a defensive, read-only projection of the exact authority
// facts needed by a service-state readiness gate. It does not expose a mutable
// Manifest or migration fence owned by BindingRegistry.
type BindingIdentity struct {
	Scope                    Scope
	Revision                 uint64
	Digest                   string
	DeploymentID             uuid.UUID
	TransitionEvidenceDigest *string
	WriteFenced              bool
}

// CurrentBindingIdentities returns the registry's validated current bindings
// for one service kind in deterministic scope order.
func (registry *BindingRegistry) CurrentBindingIdentities(
	kind ScopeKind,
) ([]BindingIdentity, error) {
	return registry.currentBindingIdentities(kind, nil)
}

// CurrentBindingIdentitiesAt additionally requires every signed Manifest to
// be current at the explicit readiness instant. Persistent deployment
// registries always contain signed Manifests; bare in-memory test bindings
// retain their existing structural-only behavior.
func (registry *BindingRegistry) CurrentBindingIdentitiesAt(
	kind ScopeKind,
	now time.Time,
) ([]BindingIdentity, error) {
	nowMilliseconds := now.UnixMilli()
	if nowMilliseconds < 0 {
		return nil, ErrInvalid
	}
	return registry.currentBindingIdentities(kind, &nowMilliseconds)
}

func (registry *BindingRegistry) currentBindingIdentities(
	kind ScopeKind,
	nowMilliseconds *int64,
) ([]BindingIdentity, error) {
	if registry == nil || !kind.Valid() {
		return nil, ErrInvalid
	}
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	if registry.poisoned {
		return nil, ErrBindingUnavailable
	}
	identities := make([]BindingIdentity, 0)
	for scope, binding := range registry.bindings {
		if scope.Kind != kind {
			continue
		}
		if validateCurrentBinding(
			scope, binding, registry.expectedDeploymentID,
		) != nil {
			return nil, ErrBindingUnavailable
		}
		if nowMilliseconds != nil && binding.Manifest != nil {
			payload, err := binding.Manifest.VerifiedPayload()
			if err != nil || payload.Validate(nowMilliseconds) != nil {
				return nil, ErrBindingUnavailable
			}
		}
		identity := BindingIdentity{
			Scope:        scope,
			Revision:     binding.Revision,
			Digest:       binding.Digest,
			DeploymentID: binding.DeploymentID,
			WriteFenced:  binding.WriteFence != nil,
		}
		if binding.TransitionEvidenceDigest != nil {
			evidence := *binding.TransitionEvidenceDigest
			identity.TransitionEvidenceDigest = &evidence
		}
		identities = append(identities, identity)
	}
	sort.Slice(identities, func(left, right int) bool {
		return bytes.Compare(
			identities[left].Scope.ScopeID[:],
			identities[right].Scope.ScopeID[:],
		) < 0
	})
	return identities, nil
}
