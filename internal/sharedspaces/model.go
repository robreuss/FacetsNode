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
	MaximumParticipantKeyGrantCiphertextByteCount = 16 * 1_024
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
	KeyGrant              *ParticipantKeyGrant  `json:"keyGrant,omitempty"`
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
	if i.KeyGrant != nil {
		if err := i.KeyGrant.Validate(); err != nil {
			return err
		}
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
