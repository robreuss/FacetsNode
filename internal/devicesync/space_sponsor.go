package devicesync

import (
	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/relay"
)

// SpaceSponsorCredential is transient request authority, never persisted.
// Shared administration custody alone cannot identify a current participant.
type SpaceSponsorCredential struct {
	Administration relay.AdministrationCredential
	Control        relay.Credential
	Space          relay.Credential
}

// SpaceSponsorBinding pins the exact sponsor and target credential
// incarnations checked at issuance. Claim rechecks these against current
// memberships; a device ID by itself is not continuing authority.
type SpaceSponsorBinding struct {
	DeviceID                         uuid.UUID `json:"deviceID"`
	ControlSubscriptionID            uuid.UUID `json:"controlSubscriptionID"`
	SpaceSubscriptionID              uuid.UUID `json:"spaceSubscriptionID"`
	TargetControlSubscriptionID      uuid.UUID `json:"targetControlSubscriptionID"`
	ControlAuthorizationDigest       string    `json:"controlAuthorizationDigest"`
	SpaceAuthorizationDigest         string    `json:"spaceAuthorizationDigest"`
	TargetControlAuthorizationDigest string    `json:"targetControlAuthorizationDigest"`
}

// The admission credential may live longer for offline delivery, but its
// unclaimed ownership can be replaced after this server-timed interval.
const SpaceSponsorshipLeaseMilliseconds int64 = 2 * 60 * 1000

func (a SpaceDeviceAdmission) CanReplacePending(nowMilliseconds int64) bool {
	return nowMilliseconds >= a.CreatedAtMilliseconds &&
		(nowMilliseconds-a.CreatedAtMilliseconds >= SpaceSponsorshipLeaseMilliseconds ||
			nowMilliseconds >= a.RelayAdmission.ExpiresAtMilliseconds)
}

func BindSpaceSponsor(
	credential SpaceSponsorCredential,
	control, space, target relay.SubscriptionMemberRegistration,
	nowMilliseconds int64,
) (SpaceSponsorBinding, error) {
	if err := AuthenticateSpaceSponsor(credential, control, space, nowMilliseconds); err != nil {
		return SpaceSponsorBinding{}, err
	}
	if target.MemberRegistration.TenantID != control.MemberRegistration.TenantID ||
		target.MemberRegistration.DomainID != control.MemberRegistration.DomainID ||
		target.MemberRegistration.MemberID == control.MemberRegistration.MemberID {
		return SpaceSponsorBinding{}, NewProtocolError(CodeWrongScope, "Space sponsor and target scopes differ")
	}
	if !CurrentSpaceSponsorMember(target.MemberRegistration, nowMilliseconds) {
		return SpaceSponsorBinding{}, NewProtocolError(CodeUnauthorized, "target control membership is not current")
	}
	return SpaceSponsorBinding{
		DeviceID:                         control.MemberRegistration.MemberID,
		ControlSubscriptionID:            control.SubscriptionID,
		SpaceSubscriptionID:              space.SubscriptionID,
		TargetControlSubscriptionID:      target.SubscriptionID,
		ControlAuthorizationDigest:       control.MemberRegistration.AuthorizationDigest,
		SpaceAuthorizationDigest:         space.MemberRegistration.AuthorizationDigest,
		TargetControlAuthorizationDigest: target.MemberRegistration.AuthorizationDigest,
	}, nil
}

func AuthenticateSpaceSponsor(credential SpaceSponsorCredential, control, space relay.SubscriptionMemberRegistration, now int64) error {
	if control.MemberRegistration.TenantID != credential.Administration.TenantID ||
		space.MemberRegistration.TenantID != credential.Administration.TenantID ||
		space.MemberRegistration.DomainID != credential.Administration.DomainID ||
		control.MemberRegistration.DomainID == space.MemberRegistration.DomainID ||
		control.MemberRegistration.MemberID != space.MemberRegistration.MemberID {
		return NewProtocolError(CodeWrongScope, "Space sponsor scopes differ")
	}
	if err := control.MemberRegistration.Authorize(credential.Control, relay.CapabilityPublishMessage, now); err != nil {
		return err
	}
	return space.MemberRegistration.Authorize(credential.Space, relay.CapabilityPublishMessage, now)
}

type SpaceDeviceAdmissionCancellation struct {
	PrincipalID     uuid.UUID `json:"principalID"`
	SpaceID         uuid.UUID `json:"spaceID"`
	DeviceID        uuid.UUID `json:"deviceID"`
	AdmissionID     uuid.UUID `json:"admissionID"`
	RetryID         uuid.UUID `json:"retryID"`
	SponsorDeviceID uuid.UUID `json:"sponsorDeviceID"`
}

func (c SpaceDeviceAdmissionCancellation) Validate(sponsor SpaceSponsorCredential) error {
	if c.PrincipalID == uuid.Nil || c.SpaceID == uuid.Nil || c.DeviceID == uuid.Nil || c.AdmissionID == uuid.Nil || c.RetryID == uuid.Nil ||
		c.SponsorDeviceID != sponsor.Control.MemberID || c.SponsorDeviceID == uuid.Nil || c.SponsorDeviceID == c.DeviceID || c.PrincipalID != sponsor.Administration.TenantID {
		return NewProtocolError(CodeWrongScope, "Space admission cancellation scope is invalid")
	}
	return nil
}

type SpaceDeviceAdmissionCancellationResult struct {
	AdmissionID uuid.UUID `json:"admissionID"`
	Cancelled   bool      `json:"cancelled"`
}

func CurrentSpaceSponsorMember(member relay.MemberRegistration, nowMilliseconds int64) bool {
	return member.Validate() == nil && member.CreatedAtMilliseconds <= nowMilliseconds &&
		member.RevokedAtMilliseconds == nil &&
		(member.ExpiresAtMilliseconds == nil || nowMilliseconds < *member.ExpiresAtMilliseconds)
}

func (b SpaceSponsorBinding) IsCurrent(control, space, target relay.SubscriptionMemberRegistration, nowMilliseconds int64) bool {
	return b.DeviceID != uuid.Nil && control.MemberRegistration.MemberID == b.DeviceID &&
		space.MemberRegistration.MemberID == b.DeviceID &&
		control.SubscriptionID == b.ControlSubscriptionID && space.SubscriptionID == b.SpaceSubscriptionID &&
		target.SubscriptionID == b.TargetControlSubscriptionID &&
		control.MemberRegistration.AuthorizationDigest == b.ControlAuthorizationDigest &&
		space.MemberRegistration.AuthorizationDigest == b.SpaceAuthorizationDigest &&
		target.MemberRegistration.AuthorizationDigest == b.TargetControlAuthorizationDigest &&
		CurrentSpaceSponsorMember(control.MemberRegistration, nowMilliseconds) &&
		CurrentSpaceSponsorMember(space.MemberRegistration, nowMilliseconds) &&
		CurrentSpaceSponsorMember(target.MemberRegistration, nowMilliseconds)
}
