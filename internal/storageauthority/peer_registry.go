package storageauthority

import (
	"time"

	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

const MaximumCapacityPeers = 64

// CapacityPeerRegistry is the authority's immutable, owner-provisioned set of
// service deployment identities. It has no network mutation route. A caller's
// self-described service identity is never sufficient for lookup or binding;
// every candidate is cryptographically verified against this set.
type CapacityPeerRegistry struct {
	identities []serviceauthority.CapacityPeerIdentity
}

func NewCapacityPeerRegistry(
	identities []serviceauthority.CapacityPeerIdentity,
) (*CapacityPeerRegistry, error) {
	if len(identities) == 0 || len(identities) > MaximumCapacityPeers {
		return nil, ErrInvalid
	}
	seenServices := make(map[string]struct{}, len(identities))
	seenKeys := make(map[string]struct{}, len(identities))
	copyOfIdentities := make([]serviceauthority.CapacityPeerIdentity, len(identities))
	for index, identity := range identities {
		if identity.Validate() != nil {
			return nil, ErrInvalid
		}
		serviceKey := string(identity.Service.Kind) + "\x00" + identity.Service.InstanceID.String()
		if _, exists := seenServices[serviceKey]; exists {
			return nil, ErrInvalid
		}
		if _, exists := seenKeys[identity.SigningKeyFingerprint]; exists {
			return nil, ErrInvalid
		}
		seenServices[serviceKey] = struct{}{}
		seenKeys[identity.SigningKeyFingerprint] = struct{}{}
		copyOfIdentities[index] = identity
	}
	return &CapacityPeerRegistry{identities: copyOfIdentities}, nil
}

func (registry *CapacityPeerRegistry) VerifyAt(
	proof serviceauthority.CapacityPeerProof,
	expected serviceauthority.CapacityPeerRequest,
	body []byte,
	now time.Time,
) (serviceauthority.VerifiedCapacityPeerRequest, error) {
	if registry == nil || len(registry.identities) == 0 {
		return serviceauthority.VerifiedCapacityPeerRequest{}, ErrInvalid
	}
	for _, identity := range registry.identities {
		verified, err := serviceauthority.VerifyCapacityPeerRequestAt(
			identity,
			proof,
			expected,
			body,
			now,
		)
		if err == nil {
			return verified, nil
		}
	}
	return serviceauthority.VerifiedCapacityPeerRequest{}, ErrRejected
}
