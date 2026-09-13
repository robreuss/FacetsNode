package devicesync

import (
	"context"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/relay"
)

// s.mu is held across this operation and issuance/claim. Relay snapshots are
// current registrations, never the historical cached provisioning response.
func (s *MemoryStore) sponsorMembers(ctx context.Context, principalID, spaceID, sponsorID, targetID uuid.UUID) (control, member, target relay.SubscriptionMemberRegistration, err error) {
	principal, ok := s.principals[principalID]
	space, spaceOK := s.spaces[spaceID]
	_, sponsorOK := s.principalDevice(principalID, sponsorID)
	_, targetOK := s.principalDevice(principalID, targetID)
	if !ok || !spaceOK || space.provisioning.PrincipalID != principalID || !sponsorOK || !targetOK {
		err = NewProtocolError(CodeUnauthorized, "sponsor or target membership unavailable")
		return
	}
	controlDomainID := principal.provisioning.ControlDomain.Registration.DomainID
	control, err = s.relay.GetMemberAuthority(ctx, principalID, controlDomainID, sponsorID)
	if err != nil {
		return
	}
	member, err = s.relay.GetMemberAuthority(ctx, principalID, space.provisioning.Domain.Registration.DomainID, sponsorID)
	if err != nil {
		return
	}
	if member.SubscriptionID != space.devices[sponsorID] {
		err = NewProtocolError(CodeUnauthorized, "sponsor Space incarnation changed")
		return
	}
	target, err = s.relay.GetMemberAuthority(ctx, principalID, controlDomainID, targetID)
	return
}
