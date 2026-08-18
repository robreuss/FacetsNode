package sharedspaces

import (
	"sort"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/relay"
)

const (
	SchemaVersion   = 1
	InitialKeyEpoch = uint64(1)
)

type SecurityMode string

const (
	SecurityModeE2EE    SecurityMode = "e2ee"
	SecurityModeManaged SecurityMode = "managed"
)

func (m SecurityMode) Valid() bool {
	return m == SecurityModeE2EE || m == SecurityModeManaged
}

type ParticipantKind string

const (
	ParticipantPerson   ParticipantKind = "person"
	ParticipantNonhuman ParticipantKind = "nonhuman"
)

func (k ParticipantKind) Valid() bool {
	return k == ParticipantPerson || k == ParticipantNonhuman
}

type Role string

const (
	RoleHost        Role = "host"
	RoleModerator   Role = "moderator"
	RoleParticipant Role = "participant"
	RoleReader      Role = "reader"
)

func (r Role) Valid() bool {
	switch r {
	case RoleHost, RoleModerator, RoleParticipant, RoleReader:
		return true
	default:
		return false
	}
}

func (r Role) Capabilities() []relay.Capability {
	var capabilities []relay.Capability
	if r == RoleReader {
		capabilities = []relay.Capability{
			relay.CapabilityAcknowledgeMessage,
			relay.CapabilityFetchBlob,
			relay.CapabilityFetchMessage,
		}
	} else {
		capabilities = []relay.Capability{
			relay.CapabilityAcknowledgeMessage,
			relay.CapabilityFetchBlob,
			relay.CapabilityFetchMessage,
			relay.CapabilityPublishBlob,
			relay.CapabilityPublishCheckpoint,
			relay.CapabilityPublishMessage,
		}
	}
	sort.Slice(capabilities, func(i, j int) bool { return capabilities[i] < capabilities[j] })
	return capabilities
}

type SpaceProvisioning struct {
	Version                int                      `json:"version"`
	RetryID                uuid.UUID                `json:"retryID"`
	SpaceID                uuid.UUID                `json:"spaceID"`
	SecurityMode           SecurityMode             `json:"securityMode"`
	InitialParticipantID   uuid.UUID                `json:"initialParticipantID"`
	InitialParticipantKind ParticipantKind          `json:"initialParticipantKind"`
	Tenant                 relay.TenantRegistration `json:"tenant"`
	Domain                 relay.DomainProvisioning `json:"-"`
	CreatedAtMilliseconds  int64                    `json:"createdAtMilliseconds"`
}

func (p SpaceProvisioning) Validate() error {
	if p.Version != SchemaVersion || p.RetryID == uuid.Nil || p.SpaceID == uuid.Nil ||
		!p.SecurityMode.Valid() || p.InitialParticipantID == uuid.Nil ||
		!p.InitialParticipantKind.Valid() || p.CreatedAtMilliseconds < 0 {
		return NewProtocolError(CodeInvalidSpace, "Shared Space provisioning fields are invalid")
	}
	if err := p.Tenant.Validate(); err != nil {
		return err
	}
	if err := p.Domain.Validate(); err != nil {
		return err
	}
	if p.SpaceID != p.Tenant.TenantID ||
		p.SpaceID != p.Domain.Registration.TenantID ||
		p.InitialParticipantID != p.Domain.InitialMember.MemberID ||
		p.CreatedAtMilliseconds != p.Tenant.CreatedAtMilliseconds ||
		p.CreatedAtMilliseconds != p.Domain.Registration.CreatedAtMilliseconds {
		return NewProtocolError(CodeWrongScope, "Shared Space, relay tenant, domain, and initial host scopes differ")
	}
	if !sameCapabilities(p.Domain.InitialMember.Capabilities, RoleHost.Capabilities()) {
		return NewProtocolError(CodeWrongScope, "initial host relay capabilities are invalid")
	}
	return nil
}

type Participant struct {
	Version               int             `json:"version"`
	SpaceID               uuid.UUID       `json:"spaceID"`
	ParticipantID         uuid.UUID       `json:"participantID"`
	SubscriptionID        uuid.UUID       `json:"subscriptionID"`
	Kind                  ParticipantKind `json:"kind"`
	Role                  Role            `json:"role"`
	CreatedAtMilliseconds int64           `json:"createdAtMilliseconds"`
	RevokedAtMilliseconds *int64          `json:"revokedAtMilliseconds,omitempty"`
}

func (p Participant) Validate() error {
	if p.Version != SchemaVersion || p.SpaceID == uuid.Nil || p.ParticipantID == uuid.Nil ||
		p.SubscriptionID == uuid.Nil || !p.Kind.Valid() || !p.Role.Valid() ||
		p.CreatedAtMilliseconds < 0 ||
		(p.RevokedAtMilliseconds != nil && *p.RevokedAtMilliseconds < p.CreatedAtMilliseconds) {
		return NewProtocolError(CodeInvalidParticipant, "Shared Space participant fields are invalid")
	}
	return nil
}

type SpaceProvisioningResult struct {
	Acceptance         relay.Acceptance               `json:"acceptance"`
	RetryID            uuid.UUID                      `json:"retryID"`
	SpaceID            uuid.UUID                      `json:"spaceID"`
	SecurityMode       SecurityMode                   `json:"securityMode"`
	CurrentKeyEpoch    uint64                         `json:"currentKeyEpoch"`
	InitialParticipant Participant                    `json:"initialParticipant"`
	Relay              relay.TenantProvisioningResult `json:"relay"`
}

type Invitation struct {
	Version               int                   `json:"version"`
	RetryID               uuid.UUID             `json:"retryID"`
	SpaceID               uuid.UUID             `json:"spaceID"`
	InvitationID          uuid.UUID             `json:"invitationID"`
	ParticipantID         uuid.UUID             `json:"participantID"`
	SubscriptionID        uuid.UUID             `json:"subscriptionID"`
	Kind                  ParticipantKind       `json:"kind"`
	Role                  Role                  `json:"role"`
	RelayAdmission        relay.MemberAdmission `json:"relayAdmission"`
	CreatedAtMilliseconds int64                 `json:"createdAtMilliseconds"`
}

func (i Invitation) Validate() error {
	if i.Version != SchemaVersion || i.RetryID == uuid.Nil || i.SpaceID == uuid.Nil ||
		i.InvitationID == uuid.Nil || i.ParticipantID == uuid.Nil || i.SubscriptionID == uuid.Nil ||
		!i.Kind.Valid() || !i.Role.Valid() || i.CreatedAtMilliseconds < 0 {
		return NewProtocolError(CodeInvalidInvitation, "Shared Space invitation fields are invalid")
	}
	if err := i.RelayAdmission.Validate(); err != nil {
		return err
	}
	if i.SpaceID != i.RelayAdmission.TenantID || i.InvitationID != i.RelayAdmission.AdmissionID ||
		i.CreatedAtMilliseconds != i.RelayAdmission.CreatedAtMilliseconds ||
		i.RelayAdmission.ClaimedAtMilliseconds != nil || i.RelayAdmission.ClaimedMemberID != nil ||
		i.RelayAdmission.RevokedAtMilliseconds != nil ||
		!sameCapabilities(i.RelayAdmission.Capabilities, i.Role.Capabilities()) {
		return NewProtocolError(CodeWrongScope, "Shared Space invitation and relay admission scopes differ")
	}
	return nil
}

type InvitationCreateResult struct {
	Acceptance relay.Acceptance `json:"acceptance"`
	Invitation Invitation       `json:"invitation"`
}

type InvitationCredential struct {
	SpaceID      uuid.UUID
	DomainID     uuid.UUID
	InvitationID uuid.UUID
	Token        string
}

type InvitationClaim struct {
	Version               int                        `json:"version"`
	SpaceID               uuid.UUID                  `json:"spaceID"`
	ParticipantID         uuid.UUID                  `json:"participantID"`
	RelayClaim            relay.MemberAdmissionClaim `json:"relayClaim"`
	ClaimedAtMilliseconds int64                      `json:"claimedAtMilliseconds"`
}

func (c InvitationClaim) Validate() error {
	if c.Version != SchemaVersion || c.SpaceID == uuid.Nil || c.ParticipantID == uuid.Nil ||
		c.ClaimedAtMilliseconds < 0 {
		return NewProtocolError(CodeInvalidInvitation, "Shared Space invitation claim fields are invalid")
	}
	if err := c.RelayClaim.Validate(); err != nil {
		return err
	}
	if c.ParticipantID != c.RelayClaim.MemberID {
		return NewProtocolError(CodeWrongScope, "participant and relay member scopes differ")
	}
	return nil
}

type InvitationClaimResult struct {
	Acceptance      relay.Acceptance                     `json:"acceptance"`
	CurrentKeyEpoch uint64                               `json:"currentKeyEpoch"`
	Participant     Participant                          `json:"participant"`
	Member          relay.SubscriptionMemberRegistration `json:"member"`
}

type ParticipantRevocation struct {
	Version          int       `json:"version"`
	RetryID          uuid.UUID `json:"retryID"`
	SpaceID          uuid.UUID `json:"spaceID"`
	ParticipantID    uuid.UUID `json:"participantID"`
	PreviousKeyEpoch uint64    `json:"previousKeyEpoch"`
	NextKeyEpoch     uint64    `json:"nextKeyEpoch"`
}

func (r ParticipantRevocation) Validate() error {
	if r.Version != SchemaVersion || r.RetryID == uuid.Nil || r.SpaceID == uuid.Nil ||
		r.ParticipantID == uuid.Nil || r.PreviousKeyEpoch < InitialKeyEpoch ||
		r.NextKeyEpoch != r.PreviousKeyEpoch+1 {
		return NewProtocolError(CodeInvalidParticipant, "Shared Space participant revocation fields are invalid")
	}
	return nil
}

type ParticipantRevocationResult struct {
	Acceptance            relay.Acceptance `json:"acceptance"`
	RetryID               uuid.UUID        `json:"retryID"`
	SpaceID               uuid.UUID        `json:"spaceID"`
	ParticipantID         uuid.UUID        `json:"participantID"`
	PreviousKeyEpoch      uint64           `json:"previousKeyEpoch"`
	CurrentKeyEpoch       uint64           `json:"currentKeyEpoch"`
	RevokedAtMilliseconds int64            `json:"revokedAtMilliseconds"`
}

type SpaceStatus struct {
	Version               int                `json:"version"`
	SpaceID               uuid.UUID          `json:"spaceID"`
	SecurityMode          SecurityMode       `json:"securityMode"`
	CurrentKeyEpoch       uint64             `json:"currentKeyEpoch"`
	BootstrapReady        bool               `json:"bootstrapReady"`
	ActiveCheckpointEpoch *uint64            `json:"activeCheckpointEpoch,omitempty"`
	DomainID              uuid.UUID          `json:"domainID"`
	InitialParticipantID  uuid.UUID          `json:"initialParticipantID"`
	Participants          []Participant      `json:"participants"`
	Relay                 relay.DomainStatus `json:"relay"`
	CreatedAtMilliseconds int64              `json:"createdAtMilliseconds"`
}

func sameCapabilities(left, right []relay.Capability) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
