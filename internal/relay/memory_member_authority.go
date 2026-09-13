package relay

import (
	"context"

	"github.com/google/uuid"
)

func (s *MemoryStore) GetMemberAuthority(_ context.Context, tenantID, domainID, memberID uuid.UUID) (SubscriptionMemberRegistration, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	domain, found := s.domains[domainKey{tenantID: tenantID, domainID: domainID}]
	if !found || domain.registration.TenantID != tenantID {
		return SubscriptionMemberRegistration{}, protocolError(CodeUnauthorized, "member authority unavailable")
	}
	member, found := domain.members[memberID]
	subscriptionID := domain.memberSubscriptions[memberID]
	subscription, present := domain.subscriptions[subscriptionID]
	if !found || !present || subscription.Status != SubscriptionActive {
		return SubscriptionMemberRegistration{}, protocolError(CodeUnauthorized, "member authority unavailable")
	}
	return SubscriptionMemberRegistration{SubscriptionID: subscriptionID, MemberRegistration: member}, nil
}
