package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/robreuss/FacetsNode/internal/devicesync"
	"github.com/robreuss/FacetsNode/internal/relay"
)

func (s *RelayStore) GetMemberAuthority(ctx context.Context, tenantID, domainID, memberID uuid.UUID) (relay.SubscriptionMemberRegistration, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return relay.SubscriptionMemberRegistration{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	return loadDeviceSyncMemberAuthority(ctx, tx, tenantID, domainID, memberID)
}

func loadDeviceSyncMemberAuthority(ctx context.Context, q relayQuerier, tenantID, domainID, memberID uuid.UUID) (relay.SubscriptionMemberRegistration, error) {
	member, found, err := loadRelayMember(ctx, q, tenantID, domainID, memberID, "FOR SHARE")
	if err != nil {
		return relay.SubscriptionMemberRegistration{}, err
	}
	if !found {
		return relay.SubscriptionMemberRegistration{}, devicesync.NewProtocolError(devicesync.CodeUnauthorized, "member authority unavailable")
	}
	subscriptionID, err := loadActiveMemberSubscription(ctx, q, tenantID, domainID, memberID, "FOR SHARE")
	if err != nil {
		if relay.ErrorHasCode(err, relay.CodeInvalidSubscription) {
			return relay.SubscriptionMemberRegistration{}, devicesync.NewProtocolError(devicesync.CodeUnauthorized, "member subscription is not current")
		}
		return relay.SubscriptionMemberRegistration{}, err
	}
	return relay.SubscriptionMemberRegistration{SubscriptionID: subscriptionID, MemberRegistration: member}, nil
}

// Called under the principal -> Space locks, also used by claim. The
// authenticated principal bindings, not caller IDs, choose both domains.
func loadDeviceSyncSponsorMembers(ctx context.Context, tx pgx.Tx, principalID, spaceID, sponsorID, targetID uuid.UUID) (control, space, target relay.SubscriptionMemberRegistration, err error) {
	var controlDomainID, spaceDomainID, spaceSub uuid.UUID
	err = tx.QueryRow(ctx, `SELECT p.control_domain_id,s.domain_id,ss.subscription_id
	 FROM device_sync_principals p
	 JOIN device_sync_spaces s ON s.principal_id=p.principal_id
	 JOIN device_sync_devices sc ON sc.principal_id=p.principal_id AND sc.device_id=$3
	 JOIN device_sync_space_devices ss ON ss.principal_id=p.principal_id AND ss.space_id=s.space_id AND ss.device_id=$3
	 JOIN device_sync_devices tc ON tc.principal_id=p.principal_id AND tc.device_id=$4
	 WHERE p.principal_id=$1 AND s.space_id=$2`, principalID, spaceID, sponsorID, targetID).Scan(&controlDomainID, &spaceDomainID, &spaceSub)
	if err == pgx.ErrNoRows {
		err = devicesync.NewProtocolError(devicesync.CodeUnauthorized, "sponsor or target membership unavailable")
	}
	if err != nil {
		return
	}
	control, err = loadDeviceSyncMemberAuthority(ctx, tx, principalID, controlDomainID, sponsorID)
	if err != nil {
		return
	}
	space, err = loadDeviceSyncMemberAuthority(ctx, tx, principalID, spaceDomainID, sponsorID)
	if err != nil {
		return
	}
	target, err = loadDeviceSyncMemberAuthority(ctx, tx, principalID, controlDomainID, targetID)
	if err == nil && space.SubscriptionID != spaceSub {
		err = devicesync.NewProtocolError(devicesync.CodeUnauthorized, "membership incarnation changed")
	}
	return
}
