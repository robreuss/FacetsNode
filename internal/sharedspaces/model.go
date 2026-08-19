package sharedspaces

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/relay"
)

const (
	SchemaVersion                                 = 1
	InitialKeyEpoch                               = uint64(1)
	ParticipantKeyGrantAlgorithm                  = "P256-HKDF-SHA256+A256GCM"
	ParticipantKeyGrantSignatureAlgorithm         = "ES256"
	ManagedContentKeyAlgorithm                    = "A256GCM"
	MaximumParticipantKeyGrantCiphertextByteCount = 16 * 1_024
	MaximumAuthorityEventPageSize                 = 100
)

type AuthorityEventType string

const (
	AuthorityEventSpaceProvisioned       AuthorityEventType = "space_provisioned"
	AuthorityEventInvitationCreated      AuthorityEventType = "invitation_created"
	AuthorityEventInvitationClaimed      AuthorityEventType = "invitation_claimed"
	AuthorityEventInvitationCancelled    AuthorityEventType = "invitation_cancelled"
	AuthorityEventParticipantRoleChanged AuthorityEventType = "participant_role_changed"
	AuthorityEventParticipantRevoked     AuthorityEventType = "participant_revoked"
)

func (t AuthorityEventType) Valid() bool {
	switch t {
	case AuthorityEventSpaceProvisioned, AuthorityEventInvitationCreated,
		AuthorityEventInvitationClaimed, AuthorityEventInvitationCancelled,
		AuthorityEventParticipantRoleChanged, AuthorityEventParticipantRevoked:
		return true
	default:
		return false
	}
}

// AuthorityEvent is a content-blind record of an accepted Shared Space
// authority transition. It deliberately excludes credentials, key material,
// encrypted content, payment state, contact attributes, and Persona claims.
type AuthorityEvent struct {
	Version                int                `json:"version"`
	Sequence               uint64             `json:"sequence"`
	EventID                uuid.UUID          `json:"eventID"`
	SpaceID                uuid.UUID          `json:"spaceID"`
	DomainID               uuid.UUID          `json:"domainID"`
	EventType              AuthorityEventType `json:"eventType"`
	SubjectParticipantID   *uuid.UUID         `json:"subjectParticipantID,omitempty"`
	InvitationID           *uuid.UUID         `json:"invitationID,omitempty"`
	PreviousRole           *Role              `json:"previousRole,omitempty"`
	CurrentRole            *Role              `json:"currentRole,omitempty"`
	PreviousKeyEpoch       *uint64            `json:"previousKeyEpoch,omitempty"`
	CurrentKeyEpoch        *uint64            `json:"currentKeyEpoch,omitempty"`
	OccurredAtMilliseconds int64              `json:"occurredAtMilliseconds"`
}

func (e AuthorityEvent) Validate() error {
	if e.Version != SchemaVersion || e.Sequence == 0 || e.EventID == uuid.Nil ||
		e.SpaceID == uuid.Nil || e.DomainID == uuid.Nil || !e.EventType.Valid() ||
		e.OccurredAtMilliseconds < 0 ||
		(e.SubjectParticipantID != nil && *e.SubjectParticipantID == uuid.Nil) ||
		(e.InvitationID != nil && *e.InvitationID == uuid.Nil) ||
		(e.PreviousRole != nil && !e.PreviousRole.Valid()) ||
		(e.CurrentRole != nil && !e.CurrentRole.Valid()) ||
		(e.PreviousKeyEpoch != nil && *e.PreviousKeyEpoch == 0) ||
		(e.CurrentKeyEpoch != nil && *e.CurrentKeyEpoch == 0) {
		return NewProtocolError(CodeInvalidAuthorityEvent, "Shared Space authority event fields are invalid")
	}
	if !e.validTransitionShape() {
		return NewProtocolError(CodeInvalidAuthorityEvent, "Shared Space authority event transition fields are invalid")
	}
	return nil
}

func (e AuthorityEvent) validTransitionShape() bool {
	switch e.EventType {
	case AuthorityEventSpaceProvisioned:
		return e.SubjectParticipantID != nil && e.InvitationID == nil &&
			e.PreviousRole == nil && e.CurrentRole != nil && *e.CurrentRole == RoleHost &&
			e.PreviousKeyEpoch == nil && e.CurrentKeyEpoch != nil
	case AuthorityEventInvitationCreated, AuthorityEventInvitationClaimed:
		return e.SubjectParticipantID != nil && e.InvitationID != nil &&
			e.PreviousRole == nil && e.CurrentRole != nil &&
			e.PreviousKeyEpoch == nil && e.CurrentKeyEpoch != nil
	case AuthorityEventInvitationCancelled:
		return e.SubjectParticipantID != nil && e.InvitationID != nil &&
			e.PreviousRole == nil && e.CurrentRole == nil &&
			e.PreviousKeyEpoch == nil && e.CurrentKeyEpoch == nil
	case AuthorityEventParticipantRoleChanged:
		return e.SubjectParticipantID != nil && e.InvitationID == nil &&
			e.PreviousRole != nil && e.CurrentRole != nil &&
			e.PreviousKeyEpoch == nil && e.CurrentKeyEpoch == nil
	case AuthorityEventParticipantRevoked:
		return e.SubjectParticipantID != nil && e.InvitationID == nil &&
			e.PreviousRole == nil && e.CurrentRole == nil &&
			e.PreviousKeyEpoch != nil && e.CurrentKeyEpoch != nil
	default:
		return false
	}
}

type AuthorityEventPage struct {
	Version      int              `json:"version"`
	SpaceID      uuid.UUID        `json:"spaceID"`
	Events       []AuthorityEvent `json:"events"`
	NextSequence uint64           `json:"nextSequence"`
}

type SecurityMode string

const (
	SecurityModeE2EE    SecurityMode = "e2ee"
	SecurityModeManaged SecurityMode = "managed"
)

func (m SecurityMode) Valid() bool {
	return m == SecurityModeE2EE || m == SecurityModeManaged
}

// InteractionMode defines which participant roles may publish into a Shared
// Space. It is immutable for the lifetime of a v1 Space. Relay capabilities
// are derived from this mode and a participant role rather than accepted as
// caller-selected authority.
type InteractionMode string

const (
	InteractionModeBroadcast     InteractionMode = "broadcast"
	InteractionModeCommunity     InteractionMode = "community"
	InteractionModeCollaborative InteractionMode = "collaborative"
)

func (m InteractionMode) Valid() bool {
	switch m {
	case InteractionModeBroadcast, InteractionModeCommunity, InteractionModeCollaborative:
		return true
	default:
		return false
	}
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

func (r Role) Capabilities(mode InteractionMode) []relay.Capability {
	readCapabilities := []relay.Capability{
		relay.CapabilityAcknowledgeMessage,
		relay.CapabilityFetchBlob,
		relay.CapabilityFetchMessage,
	}
	allCapabilities := append([]relay.Capability{}, readCapabilities...)
	allCapabilities = append(allCapabilities,
		relay.CapabilityPublishBlob,
		relay.CapabilityPublishCheckpoint,
		relay.CapabilityPublishMessage,
	)

	var capabilities []relay.Capability
	switch {
	case !r.Valid() || !mode.Valid():
		return nil
	case r == RoleHost || r == RoleModerator:
		capabilities = allCapabilities
	case r == RoleReader || mode == InteractionModeBroadcast:
		capabilities = readCapabilities
	case mode == InteractionModeCommunity:
		capabilities = append([]relay.Capability{}, readCapabilities...)
		capabilities = append(capabilities,
			relay.CapabilityPublishBlob,
			relay.CapabilityPublishMessage,
		)
	case mode == InteractionModeCollaborative:
		capabilities = allCapabilities
	}
	sort.Slice(capabilities, func(i, j int) bool { return capabilities[i] < capabilities[j] })
	return capabilities
}

type SpaceProvisioning struct {
	Version                int                      `json:"version"`
	RetryID                uuid.UUID                `json:"retryID"`
	SpaceID                uuid.UUID                `json:"spaceID"`
	SecurityMode           SecurityMode             `json:"securityMode"`
	InteractionMode        InteractionMode          `json:"interactionMode"`
	InitialParticipantID   uuid.UUID                `json:"initialParticipantID"`
	InitialParticipantKind ParticipantKind          `json:"initialParticipantKind"`
	Tenant                 relay.TenantRegistration `json:"tenant"`
	Domain                 relay.DomainProvisioning `json:"-"`
	CreatedAtMilliseconds  int64                    `json:"createdAtMilliseconds"`
}

func (p SpaceProvisioning) Validate() error {
	if p.Version != SchemaVersion || p.RetryID == uuid.Nil || p.SpaceID == uuid.Nil ||
		!p.SecurityMode.Valid() || !p.InteractionMode.Valid() || p.InitialParticipantID == uuid.Nil ||
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
	if !sameCapabilities(p.Domain.InitialMember.Capabilities, RoleHost.Capabilities(p.InteractionMode)) {
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
	InteractionMode    InteractionMode                `json:"interactionMode"`
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
	InteractionMode       InteractionMode       `json:"interactionMode"`
	KeyGrant              *ParticipantKeyGrant  `json:"keyGrant,omitempty"`
	RelayAdmission        relay.MemberAdmission `json:"relayAdmission"`
	CreatedAtMilliseconds int64                 `json:"createdAtMilliseconds"`
}

func (i Invitation) Validate() error {
	if i.Version != SchemaVersion || i.RetryID == uuid.Nil || i.SpaceID == uuid.Nil ||
		i.InvitationID == uuid.Nil || i.ParticipantID == uuid.Nil || i.SubscriptionID == uuid.Nil ||
		!i.Kind.Valid() || !i.Role.Valid() || !i.InteractionMode.Valid() || i.CreatedAtMilliseconds < 0 {
		return NewProtocolError(CodeInvalidInvitation, "Shared Space invitation fields are invalid")
	}
	if err := i.RelayAdmission.Validate(); err != nil {
		return err
	}
	if i.KeyGrant != nil {
		if err := i.KeyGrant.Validate(); err != nil {
			return err
		}
	}
	if i.SpaceID != i.RelayAdmission.TenantID || i.InvitationID != i.RelayAdmission.AdmissionID ||
		i.CreatedAtMilliseconds != i.RelayAdmission.CreatedAtMilliseconds ||
		i.RelayAdmission.ClaimedAtMilliseconds != nil || i.RelayAdmission.ClaimedMemberID != nil ||
		i.RelayAdmission.RevokedAtMilliseconds != nil ||
		!sameCapabilities(i.RelayAdmission.Capabilities, i.Role.Capabilities(i.InteractionMode)) {
		return NewProtocolError(CodeWrongScope, "Shared Space invitation and relay admission scopes differ")
	}
	return nil
}

// ParticipantKeyGrant is an opaque, recipient-bound package for one Shared
// Space content-key epoch. The server verifies self-authentication and routing
// scope, but only a participant client can bind the signing key to the
// encrypted participant authority and decrypt the wrapped key material.
type ParticipantKeyGrant struct {
	Version                          int                          `json:"version"`
	SpaceID                          uuid.UUID                    `json:"spaceID"`
	ParticipantID                    uuid.UUID                    `json:"participantID"`
	IssuerParticipantID              uuid.UUID                    `json:"issuerParticipantID"`
	KeyEpoch                         uint64                       `json:"keyEpoch"`
	Algorithm                        string                       `json:"algorithm"`
	RecipientAgreementKeyFingerprint string                       `json:"recipientAgreementKeyFingerprint"`
	EphemeralAgreementPublicKeyX963  string                       `json:"ephemeralAgreementPublicKeyX963"`
	Nonce                            string                       `json:"nonce"`
	Ciphertext                       string                       `json:"ciphertext"`
	AuthenticationTag                string                       `json:"authenticationTag"`
	CreatedAtMilliseconds            int64                        `json:"createdAtMilliseconds"`
	Signature                        ParticipantKeyGrantSignature `json:"signature"`
}

type ParticipantKeyGrantSignature struct {
	Algorithm             string `json:"algorithm"`
	PublicSigningKeyX963  string `json:"publicSigningKeyX963"`
	SigningKeyFingerprint string `json:"signingKeyFingerprint"`
	Signature             string `json:"signature"`
}

type participantKeyGrantSigningFields struct {
	Version                          int       `json:"version"`
	SpaceID                          uuid.UUID `json:"spaceID"`
	ParticipantID                    uuid.UUID `json:"participantID"`
	IssuerParticipantID              uuid.UUID `json:"issuerParticipantID"`
	KeyEpoch                         uint64    `json:"keyEpoch"`
	Algorithm                        string    `json:"algorithm"`
	RecipientAgreementKeyFingerprint string    `json:"recipientAgreementKeyFingerprint"`
	EphemeralAgreementPublicKeyX963  string    `json:"ephemeralAgreementPublicKeyX963"`
	Nonce                            string    `json:"nonce"`
	Ciphertext                       string    `json:"ciphertext"`
	AuthenticationTag                string    `json:"authenticationTag"`
	CreatedAtMilliseconds            int64     `json:"createdAtMilliseconds"`
}

func (g ParticipantKeyGrant) signingPayload() ([]byte, error) {
	return json.Marshal(participantKeyGrantSigningFields{
		Version: g.Version, SpaceID: g.SpaceID, ParticipantID: g.ParticipantID,
		IssuerParticipantID: g.IssuerParticipantID, KeyEpoch: g.KeyEpoch,
		Algorithm:                        g.Algorithm,
		RecipientAgreementKeyFingerprint: g.RecipientAgreementKeyFingerprint,
		EphemeralAgreementPublicKeyX963:  g.EphemeralAgreementPublicKeyX963,
		Nonce:                            g.Nonce, Ciphertext: g.Ciphertext, AuthenticationTag: g.AuthenticationTag,
		CreatedAtMilliseconds: g.CreatedAtMilliseconds,
	})
}

// SigningPayload returns the canonical bytes covered by Signature. Clients
// use this exact representation so Go and Swift implementations sign the same
// recipient-bound grant without relying on map-key ordering.
func (g ParticipantKeyGrant) SigningPayload() ([]byte, error) {
	return g.signingPayload()
}

func (g ParticipantKeyGrant) Validate() error {
	if g.Version != SchemaVersion || g.SpaceID == uuid.Nil || g.ParticipantID == uuid.Nil ||
		g.IssuerParticipantID == uuid.Nil || g.KeyEpoch == 0 ||
		g.Algorithm != ParticipantKeyGrantAlgorithm || g.CreatedAtMilliseconds < 0 ||
		!validFingerprint(g.RecipientAgreementKeyFingerprint) ||
		!validBase64URLSize(g.EphemeralAgreementPublicKeyX963, 65, 65) ||
		!validBase64URLSize(g.Nonce, 12, 12) ||
		!validBase64URLSize(g.Ciphertext, 1, MaximumParticipantKeyGrantCiphertextByteCount) ||
		!validBase64URLSize(g.AuthenticationTag, 16, 16) ||
		g.Signature.Algorithm != ParticipantKeyGrantSignatureAlgorithm ||
		!validFingerprint(g.Signature.SigningKeyFingerprint) ||
		!validBase64URLSize(g.Signature.PublicSigningKeyX963, 65, 65) ||
		!validBase64URLSize(g.Signature.Signature, 64, 64) {
		return NewProtocolError(CodeInvalidInvitation, "Shared Space participant key grant fields are invalid")
	}
	publicKeyBytes, _ := base64.RawURLEncoding.Strict().DecodeString(g.Signature.PublicSigningKeyX963)
	fingerprint := sha256.Sum256(publicKeyBytes)
	if hex.EncodeToString(fingerprint[:]) != g.Signature.SigningKeyFingerprint {
		return NewProtocolError(CodeInvalidInvitation, "Shared Space participant key grant signing-key fingerprint differs")
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), publicKeyBytes)
	if x == nil || y == nil {
		return NewProtocolError(CodeInvalidInvitation, "Shared Space participant key grant signing key is invalid")
	}
	signatureBytes, _ := base64.RawURLEncoding.Strict().DecodeString(g.Signature.Signature)
	payload, err := g.signingPayload()
	if err != nil {
		return NewProtocolError(CodeInvalidInvitation, "Shared Space participant key grant cannot be encoded")
	}
	digest := sha256.Sum256(payload)
	if !ecdsa.Verify(
		&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, digest[:],
		new(big.Int).SetBytes(signatureBytes[:32]), new(big.Int).SetBytes(signatureBytes[32:]),
	) {
		return NewProtocolError(CodeInvalidInvitation, "Shared Space participant key grant signature is invalid")
	}
	return nil
}

func (i Invitation) ValidateKeyGrant(mode SecurityMode, currentKeyEpoch uint64) error {
	if mode == SecurityModeManaged {
		if i.KeyGrant != nil {
			return NewProtocolError(CodeInvalidInvitation, "managed Shared Space invitations cannot carry E2EE key grants")
		}
		return nil
	}
	if i.KeyGrant == nil {
		return NewProtocolError(CodeInvalidInvitation, "E2EE Shared Space invitation is missing its participant key grant")
	}
	grant := i.KeyGrant
	if grant.SpaceID != i.SpaceID || grant.ParticipantID != i.ParticipantID ||
		grant.CreatedAtMilliseconds != i.CreatedAtMilliseconds {
		return NewProtocolError(CodeWrongScope, "Shared Space invitation and participant key grant scopes differ")
	}
	if grant.KeyEpoch != currentKeyEpoch {
		return NewProtocolError(CodeWrongKeyEpoch, "Shared Space participant key grant is not for the current key epoch")
	}
	return nil
}

func validFingerprint(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func validBase64URLSize(value string, minimum, maximum int) bool {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(decoded) >= minimum && len(decoded) <= maximum &&
		base64.RawURLEncoding.EncodeToString(decoded) == value
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
	KeyGrant        *ParticipantKeyGrant                 `json:"keyGrant,omitempty"`
	Participant     Participant                          `json:"participant"`
	Member          relay.SubscriptionMemberRegistration `json:"member"`
}

type InvitationCancellation struct {
	Version                 int       `json:"version"`
	RetryID                 uuid.UUID `json:"retryID"`
	SpaceID                 uuid.UUID `json:"spaceID"`
	InvitationID            uuid.UUID `json:"invitationID"`
	CancelledAtMilliseconds int64     `json:"cancelledAtMilliseconds"`
}

func (c InvitationCancellation) Validate() error {
	if c.Version != SchemaVersion || c.RetryID == uuid.Nil || c.SpaceID == uuid.Nil ||
		c.InvitationID == uuid.Nil || c.CancelledAtMilliseconds < 0 {
		return NewProtocolError(CodeInvalidInvitation, "Shared Space invitation cancellation fields are invalid")
	}
	return nil
}

type InvitationCancellationResult struct {
	Acceptance              relay.Acceptance `json:"acceptance"`
	RetryID                 uuid.UUID        `json:"retryID"`
	SpaceID                 uuid.UUID        `json:"spaceID"`
	InvitationID            uuid.UUID        `json:"invitationID"`
	CancelledAtMilliseconds int64            `json:"cancelledAtMilliseconds"`
}

type InvitationState string

const (
	InvitationPending   InvitationState = "pending"
	InvitationClaimed   InvitationState = "claimed"
	InvitationCancelled InvitationState = "cancelled"
	InvitationExpired   InvitationState = "expired"
)

type InvitationStatus struct {
	Version                 int             `json:"version"`
	SpaceID                 uuid.UUID       `json:"spaceID"`
	InvitationID            uuid.UUID       `json:"invitationID"`
	ParticipantID           uuid.UUID       `json:"participantID"`
	SubscriptionID          uuid.UUID       `json:"subscriptionID"`
	Kind                    ParticipantKind `json:"kind"`
	Role                    Role            `json:"role"`
	InteractionMode         InteractionMode `json:"interactionMode"`
	State                   InvitationState `json:"state"`
	CreatedAtMilliseconds   int64           `json:"createdAtMilliseconds"`
	ExpiresAtMilliseconds   int64           `json:"expiresAtMilliseconds"`
	ClaimedAtMilliseconds   *int64          `json:"claimedAtMilliseconds,omitempty"`
	CancelledAtMilliseconds *int64          `json:"cancelledAtMilliseconds,omitempty"`
}

type InvitationList struct {
	Version     int                `json:"version"`
	SpaceID     uuid.UUID          `json:"spaceID"`
	Invitations []InvitationStatus `json:"invitations"`
}

type ParticipantRevocation struct {
	Version          int                   `json:"version"`
	RetryID          uuid.UUID             `json:"retryID"`
	SpaceID          uuid.UUID             `json:"spaceID"`
	ParticipantID    uuid.UUID             `json:"participantID"`
	PreviousKeyEpoch uint64                `json:"previousKeyEpoch"`
	NextKeyEpoch     uint64                `json:"nextKeyEpoch"`
	KeyGrants        []ParticipantKeyGrant `json:"keyGrants,omitempty"`
}

func (r ParticipantRevocation) Validate() error {
	if r.Version != SchemaVersion || r.RetryID == uuid.Nil || r.SpaceID == uuid.Nil ||
		r.ParticipantID == uuid.Nil || r.PreviousKeyEpoch < InitialKeyEpoch ||
		r.NextKeyEpoch != r.PreviousKeyEpoch+1 {
		return NewProtocolError(CodeInvalidParticipant, "Shared Space participant revocation fields are invalid")
	}
	return nil
}

// ValidateKeyGrants enforces an atomic E2EE epoch rotation. A revocation may
// advance the Space epoch only when every participant that remains active has
// one valid opaque grant for the next epoch. The server validates authority
// and coverage without learning the wrapped content key.
func (r ParticipantRevocation) ValidateKeyGrants(
	mode SecurityMode,
	participants []Participant,
	nowMilliseconds int64,
) error {
	if mode == SecurityModeManaged {
		if len(r.KeyGrants) != 0 {
			return NewProtocolError(CodeInvalidParticipant, "managed Shared Space revocations cannot carry E2EE key grants")
		}
		return nil
	}
	if mode != SecurityModeE2EE {
		return NewProtocolError(CodeInvalidSpace, "Shared Space security mode is invalid")
	}

	active := make(map[uuid.UUID]Participant)
	authorizedIssuers := make(map[uuid.UUID]struct{})
	for _, participant := range participants {
		if participant.SpaceID != r.SpaceID {
			return NewProtocolError(CodeWrongScope, "Shared Space participant belongs to another Space")
		}
		if participant.RevokedAtMilliseconds != nil || participant.ParticipantID == r.ParticipantID {
			continue
		}
		active[participant.ParticipantID] = participant
		if participant.Role == RoleHost || participant.Role == RoleModerator {
			authorizedIssuers[participant.ParticipantID] = struct{}{}
		}
	}
	if len(r.KeyGrants) != len(active) {
		return NewProtocolError(CodeInvalidParticipant, "E2EE participant revocation does not grant the next key epoch to every remaining participant")
	}

	seen := make(map[uuid.UUID]struct{}, len(r.KeyGrants))
	for _, grant := range r.KeyGrants {
		if err := grant.Validate(); err != nil {
			return err
		}
		if grant.SpaceID != r.SpaceID || grant.ParticipantID == r.ParticipantID {
			return NewProtocolError(CodeWrongScope, "Shared Space revocation key grant scope differs")
		}
		if grant.KeyEpoch != r.NextKeyEpoch {
			return NewProtocolError(CodeWrongKeyEpoch, "Shared Space revocation key grant is not for the next key epoch")
		}
		if grant.CreatedAtMilliseconds > nowMilliseconds {
			return NewProtocolError(CodeInvalidParticipant, "Shared Space revocation key grant was created in the future")
		}
		if _, found := active[grant.ParticipantID]; !found {
			return NewProtocolError(CodeWrongScope, "Shared Space revocation key grant targets an inactive participant")
		}
		if _, found := authorizedIssuers[grant.IssuerParticipantID]; !found {
			return NewProtocolError(CodeUnauthorized, "Shared Space revocation key grant issuer is not an active host or moderator")
		}
		if _, found := seen[grant.ParticipantID]; found {
			return NewProtocolError(CodeInvalidParticipant, "Shared Space revocation contains duplicate participant key grants")
		}
		seen[grant.ParticipantID] = struct{}{}
	}
	return nil
}

// Equivalent compares a retry request independently of grant ordering. A
// caller may safely resend the same atomic rotation with canonical or original
// participant order without creating a retry collision.
func (r ParticipantRevocation) Equivalent(other ParticipantRevocation) bool {
	if r.Version != other.Version || r.RetryID != other.RetryID || r.SpaceID != other.SpaceID ||
		r.ParticipantID != other.ParticipantID || r.PreviousKeyEpoch != other.PreviousKeyEpoch ||
		r.NextKeyEpoch != other.NextKeyEpoch || len(r.KeyGrants) != len(other.KeyGrants) {
		return false
	}
	grants := make(map[uuid.UUID]ParticipantKeyGrant, len(r.KeyGrants))
	for _, grant := range r.KeyGrants {
		if _, found := grants[grant.ParticipantID]; found {
			return false
		}
		grants[grant.ParticipantID] = grant
	}
	for _, grant := range other.KeyGrants {
		if existing, found := grants[grant.ParticipantID]; !found || existing != grant {
			return false
		}
	}
	return true
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

type ParticipantKeyGrantResult struct {
	Version         int                 `json:"version"`
	SpaceID         uuid.UUID           `json:"spaceID"`
	ParticipantID   uuid.UUID           `json:"participantID"`
	CurrentKeyEpoch uint64              `json:"currentKeyEpoch"`
	KeyGrant        ParticipantKeyGrant `json:"keyGrant"`
}

// ParticipantStatus is the participant-scoped recovery view of Shared Space
// authority. It intentionally excludes the participant roster, invitations,
// administration authority, and content key material. The relay credential is
// the sole authorization for retrieving this record.
type ParticipantStatus struct {
	Version               int                `json:"version"`
	SpaceID               uuid.UUID          `json:"spaceID"`
	DomainID              uuid.UUID          `json:"domainID"`
	SecurityMode          SecurityMode       `json:"securityMode"`
	InteractionMode       InteractionMode    `json:"interactionMode"`
	CurrentKeyEpoch       uint64             `json:"currentKeyEpoch"`
	BootstrapReady        bool               `json:"bootstrapReady"`
	ActiveCheckpointEpoch *uint64            `json:"activeCheckpointEpoch,omitempty"`
	Participant           Participant        `json:"participant"`
	Capabilities          []relay.Capability `json:"capabilities"`
	CreatedAtMilliseconds int64              `json:"createdAtMilliseconds"`
}

func (s ParticipantStatus) Validate() error {
	if s.Version != SchemaVersion || s.SpaceID == uuid.Nil || s.DomainID == uuid.Nil ||
		!s.SecurityMode.Valid() || !s.InteractionMode.Valid() || s.CurrentKeyEpoch == 0 ||
		s.CreatedAtMilliseconds < 0 || s.Participant.SpaceID != s.SpaceID ||
		s.Participant.RevokedAtMilliseconds != nil {
		return NewProtocolError(CodeInvalidParticipant, "Shared Space participant status fields are invalid")
	}
	if err := s.Participant.Validate(); err != nil {
		return err
	}
	if !sameCapabilities(s.Capabilities, s.Participant.Role.Capabilities(s.InteractionMode)) {
		return NewProtocolError(CodeInvalidParticipant, "Shared Space participant status capabilities are invalid")
	}
	if s.BootstrapReady != (s.ActiveCheckpointEpoch != nil && *s.ActiveCheckpointEpoch == s.CurrentKeyEpoch) {
		return NewProtocolError(CodeInvalidParticipant, "Shared Space participant bootstrap status is invalid")
	}
	return nil
}

// ManagedContentKey is a server-owned managed-Space content key delivered only
// to an authenticated, active participant. It is not participant authority and
// it is never used by E2EE Spaces.
type ManagedContentKey struct {
	Version       int       `json:"version"`
	SpaceID       uuid.UUID `json:"spaceID"`
	ParticipantID uuid.UUID `json:"participantID"`
	KeyEpoch      uint64    `json:"keyEpoch"`
	Algorithm     string    `json:"algorithm"`
	KeyMaterial   string    `json:"keyMaterial"`
}

func (k ManagedContentKey) Validate() error {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(k.KeyMaterial)
	if k.Version != SchemaVersion || k.SpaceID == uuid.Nil || k.ParticipantID == uuid.Nil ||
		k.KeyEpoch == 0 || k.Algorithm != ManagedContentKeyAlgorithm || err != nil ||
		len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != k.KeyMaterial {
		return NewProtocolError(CodeInvalidParticipant, "managed Shared Space content key is invalid")
	}
	return nil
}

// ParticipantBootstrap is an atomic participant-scoped recovery snapshot. An
// E2EE Space includes the caller's opaque participant grant. A managed Space
// includes the service-owned content key. Exactly one key form must match the
// security mode and key epoch reported by Status.
type ParticipantBootstrap struct {
	Version           int                        `json:"version"`
	Status            ParticipantStatus          `json:"status"`
	KeyGrant          *ParticipantKeyGrantResult `json:"keyGrant,omitempty"`
	ManagedContentKey *ManagedContentKey         `json:"managedContentKey,omitempty"`
}

func (b ParticipantBootstrap) Validate() error {
	if b.Version != SchemaVersion {
		return NewProtocolError(CodeInvalidParticipant, "Shared Space participant bootstrap version is invalid")
	}
	if err := b.Status.Validate(); err != nil {
		return err
	}
	if b.Status.SecurityMode == SecurityModeManaged {
		if b.KeyGrant != nil || b.ManagedContentKey == nil ||
			b.ManagedContentKey.SpaceID != b.Status.SpaceID ||
			b.ManagedContentKey.ParticipantID != b.Status.Participant.ParticipantID ||
			b.ManagedContentKey.KeyEpoch != b.Status.CurrentKeyEpoch {
			return NewProtocolError(CodeInvalidParticipant, "managed Shared Space participant bootstrap key is inconsistent")
		}
		return b.ManagedContentKey.Validate()
	}
	if b.ManagedContentKey != nil || b.KeyGrant == nil || b.KeyGrant.Version != SchemaVersion ||
		b.KeyGrant.SpaceID != b.Status.SpaceID ||
		b.KeyGrant.ParticipantID != b.Status.Participant.ParticipantID ||
		b.KeyGrant.CurrentKeyEpoch != b.Status.CurrentKeyEpoch ||
		b.KeyGrant.KeyGrant.SpaceID != b.Status.SpaceID ||
		b.KeyGrant.KeyGrant.ParticipantID != b.Status.Participant.ParticipantID ||
		b.KeyGrant.KeyGrant.KeyEpoch != b.Status.CurrentKeyEpoch {
		return NewProtocolError(CodeInvalidParticipant, "E2EE Shared Space participant bootstrap key grant is inconsistent")
	}
	if err := b.KeyGrant.KeyGrant.Validate(); err != nil {
		return err
	}
	return nil
}

type ParticipantRoleChange struct {
	Version               int       `json:"version"`
	RetryID               uuid.UUID `json:"retryID"`
	SpaceID               uuid.UUID `json:"spaceID"`
	ParticipantID         uuid.UUID `json:"participantID"`
	PreviousRole          Role      `json:"previousRole"`
	NextRole              Role      `json:"nextRole"`
	ChangedAtMilliseconds int64     `json:"changedAtMilliseconds"`
}

func (c ParticipantRoleChange) Validate() error {
	if c.Version != SchemaVersion || c.RetryID == uuid.Nil || c.SpaceID == uuid.Nil ||
		c.ParticipantID == uuid.Nil || !c.PreviousRole.Valid() || !c.NextRole.Valid() ||
		c.PreviousRole == c.NextRole || c.ChangedAtMilliseconds < 0 {
		return NewProtocolError(CodeInvalidParticipant, "Shared Space participant role change fields are invalid")
	}
	return nil
}

type ParticipantRoleChangeResult struct {
	Acceptance            relay.Acceptance `json:"acceptance"`
	RetryID               uuid.UUID        `json:"retryID"`
	SpaceID               uuid.UUID        `json:"spaceID"`
	ParticipantID         uuid.UUID        `json:"participantID"`
	PreviousRole          Role             `json:"previousRole"`
	CurrentRole           Role             `json:"currentRole"`
	ChangedAtMilliseconds int64            `json:"changedAtMilliseconds"`
}

type SpaceStatus struct {
	Version               int                `json:"version"`
	SpaceID               uuid.UUID          `json:"spaceID"`
	SecurityMode          SecurityMode       `json:"securityMode"`
	InteractionMode       InteractionMode    `json:"interactionMode"`
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
