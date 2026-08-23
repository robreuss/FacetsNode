package sharedspaces

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"reflect"
	"sort"
	"strings"
	"unicode/utf8"

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
	// MaximumSecureRosterAttestationPageSize bounds the amount of historic
	// membership authority a Secure participant may fetch in one request. The
	// records are public to active Secure participants, but never to a revoked
	// participant or an unauthenticated client.
	MaximumSecureRosterAttestationPageSize = 100
	MaximumParticipantDisplayNameBytes     = 512
	MaximumParticipantDisplayNameRunes     = 128
)

// ParticipantSigningKey is the public, long-lived signing identity bound to a
// Shared Space participant. It is deliberately public metadata: binding a
// key-grant issuer to this value lets the service reject substituted signing
// keys while leaving the wrapped content key opaque.
type ParticipantSigningKey struct {
	Algorithm             string `json:"algorithm"`
	PublicKeyX963         string `json:"publicKeyX963"`
	SigningKeyFingerprint string `json:"signingKeyFingerprint"`
}

// ParticipantDeviceKey binds a participant-owned agreement key to one physical
// Facets device. Its signature is made by the participant signing key, while
// the enclosing Secure roster makes that binding part of the durable authority
// history. The service stores only this public metadata, never agreement
// private keys or unwrapped Space keys.
type ParticipantDeviceKey struct {
	Version                 int                          `json:"version"`
	SpaceID                 uuid.UUID                    `json:"spaceID"`
	ParticipantID           uuid.UUID                    `json:"participantID"`
	DeviceID                uuid.UUID                    `json:"deviceID"`
	Algorithm               string                       `json:"algorithm"`
	AgreementPublicKeyX963  string                       `json:"agreementPublicKeyX963"`
	AgreementKeyFingerprint string                       `json:"agreementKeyFingerprint"`
	CreatedAtMilliseconds   int64                        `json:"createdAtMilliseconds"`
	RevokedAtMilliseconds   *int64                       `json:"revokedAtMilliseconds,omitempty"`
	Signature               ParticipantKeyGrantSignature `json:"signature"`
}

type participantDeviceKeySigningFields struct {
	Version                 int       `json:"version"`
	SpaceID                 uuid.UUID `json:"spaceID"`
	ParticipantID           uuid.UUID `json:"participantID"`
	DeviceID                uuid.UUID `json:"deviceID"`
	Algorithm               string    `json:"algorithm"`
	AgreementPublicKeyX963  string    `json:"agreementPublicKeyX963"`
	AgreementKeyFingerprint string    `json:"agreementKeyFingerprint"`
	CreatedAtMilliseconds   int64     `json:"createdAtMilliseconds"`
	RevokedAtMilliseconds   *int64    `json:"revokedAtMilliseconds,omitempty"`
}

// SigningPayload returns the exact portable JSON bytes signed by the
// participant signing key. Swift emits the same declared-field order.
func (k ParticipantDeviceKey) SigningPayload() ([]byte, error) {
	return json.Marshal(participantDeviceKeySigningFields{
		Version: k.Version, SpaceID: k.SpaceID, ParticipantID: k.ParticipantID,
		DeviceID: k.DeviceID, Algorithm: k.Algorithm,
		AgreementPublicKeyX963:  k.AgreementPublicKeyX963,
		AgreementKeyFingerprint: k.AgreementKeyFingerprint,
		CreatedAtMilliseconds:   k.CreatedAtMilliseconds,
		RevokedAtMilliseconds:   k.RevokedAtMilliseconds,
	})
}

func (k ParticipantDeviceKey) Validate(participant Participant) error {
	if k.Version != SchemaVersion || k.SpaceID != participant.SpaceID ||
		k.ParticipantID != participant.ParticipantID || k.DeviceID == uuid.Nil ||
		k.Algorithm != "P256" || k.CreatedAtMilliseconds < 0 ||
		(k.RevokedAtMilliseconds != nil && *k.RevokedAtMilliseconds < k.CreatedAtMilliseconds) ||
		!validFingerprint(k.AgreementKeyFingerprint) ||
		!validBase64URLSize(k.AgreementPublicKeyX963, 65, 65) ||
		!participant.SigningKey.MatchesGrantSignature(k.Signature) ||
		k.Signature.Algorithm != ParticipantKeyGrantSignatureAlgorithm ||
		!validBase64URLSize(k.Signature.Signature, 64, 64) {
		return NewProtocolError(CodeInvalidParticipant, "Shared Space participant device-key fields are invalid")
	}
	agreementPublicKeyBytes, _ := base64.RawURLEncoding.Strict().DecodeString(k.AgreementPublicKeyX963)
	fingerprint := sha256.Sum256(agreementPublicKeyBytes)
	if hex.EncodeToString(fingerprint[:]) != k.AgreementKeyFingerprint {
		return NewProtocolError(CodeInvalidParticipant, "Shared Space participant agreement-key fingerprint differs")
	}
	if x, y := elliptic.Unmarshal(elliptic.P256(), agreementPublicKeyBytes); x == nil || y == nil {
		return NewProtocolError(CodeInvalidParticipant, "Shared Space participant agreement key is invalid")
	}
	signingPublicKeyBytes, _ := base64.RawURLEncoding.Strict().DecodeString(participant.SigningKey.PublicKeyX963)
	x, y := elliptic.Unmarshal(elliptic.P256(), signingPublicKeyBytes)
	signatureBytes, _ := base64.RawURLEncoding.Strict().DecodeString(k.Signature.Signature)
	payload, err := k.SigningPayload()
	if err != nil {
		return NewProtocolError(CodeInvalidParticipant, "Shared Space participant device-key payload cannot be encoded")
	}
	digest := sha256.Sum256(payload)
	if x == nil || y == nil || !ecdsa.Verify(
		&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, digest[:],
		new(big.Int).SetBytes(signatureBytes[:32]), new(big.Int).SetBytes(signatureBytes[32:]),
	) {
		return NewProtocolError(CodeInvalidParticipant, "Shared Space participant device-key signature is invalid")
	}
	return nil
}

func (k ParticipantSigningKey) Validate() error {
	if k.Algorithm != ParticipantKeyGrantSignatureAlgorithm ||
		!validFingerprint(k.SigningKeyFingerprint) ||
		!validBase64URLSize(k.PublicKeyX963, 65, 65) {
		return NewProtocolError(CodeInvalidParticipant, "Shared Space participant signing key fields are invalid")
	}
	publicKeyBytes, _ := base64.RawURLEncoding.Strict().DecodeString(k.PublicKeyX963)
	fingerprint := sha256.Sum256(publicKeyBytes)
	if hex.EncodeToString(fingerprint[:]) != k.SigningKeyFingerprint {
		return NewProtocolError(CodeInvalidParticipant, "Shared Space participant signing-key fingerprint differs")
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), publicKeyBytes)
	if x == nil || y == nil {
		return NewProtocolError(CodeInvalidParticipant, "Shared Space participant signing key is invalid")
	}
	return nil
}

func (k ParticipantSigningKey) MatchesGrantSignature(signature ParticipantKeyGrantSignature) bool {
	return k.Algorithm == signature.Algorithm &&
		k.PublicKeyX963 == signature.PublicSigningKeyX963 &&
		k.SigningKeyFingerprint == signature.SigningKeyFingerprint
}

type AuthorityEventType string

const (
	AuthorityEventSpaceProvisioned           AuthorityEventType = "space_provisioned"
	AuthorityEventInvitationCreated          AuthorityEventType = "invitation_created"
	AuthorityEventInvitationClaimed          AuthorityEventType = "invitation_claimed"
	AuthorityEventInvitationCancelled        AuthorityEventType = "invitation_cancelled"
	AuthorityEventParticipantRoleChanged     AuthorityEventType = "participant_role_changed"
	AuthorityEventParticipantDeviceEnrolled  AuthorityEventType = "participant_device_enrolled"
	AuthorityEventParticipantDeviceRevoked   AuthorityEventType = "participant_device_revoked"
	AuthorityEventParticipantRevoked         AuthorityEventType = "participant_revoked"
	AuthorityEventSpaceComputeBindingChanged AuthorityEventType = "space_compute_binding_changed"
)

func (t AuthorityEventType) Valid() bool {
	switch t {
	case AuthorityEventSpaceProvisioned, AuthorityEventInvitationCreated,
		AuthorityEventInvitationClaimed, AuthorityEventInvitationCancelled,
		AuthorityEventParticipantRoleChanged, AuthorityEventParticipantDeviceEnrolled,
		AuthorityEventParticipantDeviceRevoked,
		AuthorityEventParticipantRevoked,
		AuthorityEventSpaceComputeBindingChanged:
		return true
	default:
		return false
	}
}

// AuthorityEvent is a content-blind record of an accepted Shared Space
// authority transition. It deliberately excludes credentials, key material,
// encrypted content, payment state, contact attributes, and Persona claims.
type AuthorityEvent struct {
	Version                 int                `json:"version"`
	Sequence                uint64             `json:"sequence"`
	EventID                 uuid.UUID          `json:"eventID"`
	SpaceID                 uuid.UUID          `json:"spaceID"`
	DomainID                uuid.UUID          `json:"domainID"`
	EventType               AuthorityEventType `json:"eventType"`
	SubjectParticipantID    *uuid.UUID         `json:"subjectParticipantID,omitempty"`
	SubjectDeviceID         *uuid.UUID         `json:"subjectDeviceID,omitempty"`
	InvitationID            *uuid.UUID         `json:"invitationID,omitempty"`
	PreviousRole            *Role              `json:"previousRole,omitempty"`
	CurrentRole             *Role              `json:"currentRole,omitempty"`
	PreviousKeyEpoch        *uint64            `json:"previousKeyEpoch,omitempty"`
	CurrentKeyEpoch         *uint64            `json:"currentKeyEpoch,omitempty"`
	ComputeBindingID        *uuid.UUID         `json:"computeBindingID,omitempty"`
	ComputePoolID           *uuid.UUID         `json:"computePoolID,omitempty"`
	PreviousBindingRevision *uint64            `json:"previousBindingRevision,omitempty"`
	CurrentBindingRevision  *uint64            `json:"currentBindingRevision,omitempty"`
	// SecureRosterDigest binds a security-relevant Secure Space authority
	// transition to the signed roster attestation that authorized it. It is
	// non-content integrity metadata, never content or key material.
	SecureRosterDigest     *string `json:"secureRosterDigest,omitempty"`
	OccurredAtMilliseconds int64   `json:"occurredAtMilliseconds"`
}

func (e AuthorityEvent) Validate() error {
	if e.Version != SchemaVersion || e.Sequence == 0 || e.EventID == uuid.Nil ||
		e.SpaceID == uuid.Nil || e.DomainID == uuid.Nil || !e.EventType.Valid() ||
		e.OccurredAtMilliseconds < 0 ||
		(e.SubjectParticipantID != nil && *e.SubjectParticipantID == uuid.Nil) ||
		(e.SubjectDeviceID != nil && *e.SubjectDeviceID == uuid.Nil) ||
		(e.InvitationID != nil && *e.InvitationID == uuid.Nil) ||
		(e.PreviousRole != nil && !e.PreviousRole.Valid()) ||
		(e.CurrentRole != nil && !e.CurrentRole.Valid()) ||
		(e.PreviousKeyEpoch != nil && *e.PreviousKeyEpoch == 0) ||
		(e.CurrentKeyEpoch != nil && *e.CurrentKeyEpoch == 0) ||
		(e.ComputeBindingID != nil && *e.ComputeBindingID == uuid.Nil) ||
		(e.ComputePoolID != nil && *e.ComputePoolID == uuid.Nil) ||
		(e.CurrentBindingRevision != nil && *e.CurrentBindingRevision == 0) ||
		(e.SecureRosterDigest != nil && !validFingerprint(*e.SecureRosterDigest)) {
		return NewProtocolError(CodeInvalidAuthorityEvent, "Shared Space authority event fields are invalid")
	}
	if !e.validTransitionShape() {
		return NewProtocolError(CodeInvalidAuthorityEvent, "Shared Space authority event transition fields are invalid")
	}
	return nil
}

func (e AuthorityEvent) validTransitionShape() bool {
	computeFieldsAbsent := e.ComputeBindingID == nil && e.ComputePoolID == nil &&
		e.PreviousBindingRevision == nil &&
		e.CurrentBindingRevision == nil
	switch e.EventType {
	case AuthorityEventSpaceProvisioned:
		return e.SubjectParticipantID != nil && e.SubjectDeviceID == nil && e.InvitationID == nil &&
			e.PreviousRole == nil && e.CurrentRole != nil && *e.CurrentRole == RoleHost &&
			e.PreviousKeyEpoch == nil && e.CurrentKeyEpoch != nil && computeFieldsAbsent
	case AuthorityEventInvitationCreated, AuthorityEventInvitationClaimed:
		return e.SubjectParticipantID != nil && e.SubjectDeviceID == nil && e.InvitationID != nil &&
			e.PreviousRole == nil && e.CurrentRole != nil &&
			e.PreviousKeyEpoch == nil && e.CurrentKeyEpoch != nil && computeFieldsAbsent
	case AuthorityEventInvitationCancelled:
		return e.SubjectParticipantID != nil && e.SubjectDeviceID == nil && e.InvitationID != nil &&
			e.PreviousRole == nil && e.CurrentRole == nil &&
			e.PreviousKeyEpoch == nil && e.CurrentKeyEpoch == nil && computeFieldsAbsent
	case AuthorityEventParticipantRoleChanged:
		return e.SubjectParticipantID != nil && e.SubjectDeviceID == nil && e.InvitationID == nil &&
			e.PreviousRole != nil && e.CurrentRole != nil &&
			e.PreviousKeyEpoch == nil && e.CurrentKeyEpoch == nil && computeFieldsAbsent
	case AuthorityEventParticipantDeviceEnrolled:
		return e.SubjectParticipantID != nil && e.SubjectDeviceID != nil && e.InvitationID == nil &&
			e.PreviousRole == nil && e.CurrentRole == nil &&
			e.PreviousKeyEpoch == nil && e.CurrentKeyEpoch != nil && computeFieldsAbsent
	case AuthorityEventParticipantDeviceRevoked:
		return e.SubjectParticipantID != nil && e.SubjectDeviceID != nil && e.InvitationID == nil &&
			e.PreviousRole == nil && e.CurrentRole == nil &&
			e.PreviousKeyEpoch != nil && e.CurrentKeyEpoch != nil && computeFieldsAbsent
	case AuthorityEventParticipantRevoked:
		return e.SubjectParticipantID != nil && e.SubjectDeviceID == nil && e.InvitationID == nil &&
			e.PreviousRole == nil && e.CurrentRole == nil &&
			e.PreviousKeyEpoch != nil && e.CurrentKeyEpoch != nil && computeFieldsAbsent
	case AuthorityEventSpaceComputeBindingChanged:
		return e.SubjectParticipantID == nil && e.SubjectDeviceID == nil && e.InvitationID == nil &&
			e.PreviousRole == nil && e.CurrentRole == nil &&
			e.PreviousKeyEpoch == nil && e.CurrentKeyEpoch == nil &&
			e.ComputeBindingID != nil && e.ComputePoolID != nil &&
			e.PreviousBindingRevision != nil &&
			e.CurrentBindingRevision != nil &&
			*e.CurrentBindingRevision == *e.PreviousBindingRevision+1
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
	// SecurityModePrivate is content-blind E2EE for a closed, trusted group.
	// It uses a stable group-key epoch. Revoking a participant stops future
	// delivery, but does not revoke material that participant already received.
	SecurityModePrivate SecurityMode = "private"
	// SecurityModeSecure is content-blind E2EE for high-assurance groups.
	// Every participant revocation advances the key epoch and atomically grants
	// the new epoch to every remaining active participant.
	SecurityModeSecure SecurityMode = "secure"
	// SecurityModeManaged is reserved for the server-readable public profile.
	// It is not a substitute for either content-blind E2EE profile.
	SecurityModeManaged SecurityMode = "managed"
)

func (m SecurityMode) Valid() bool {
	return m == SecurityModePrivate || m == SecurityModeSecure || m == SecurityModeManaged
}

// ContentBlind reports whether the service must handle only opaque encrypted
// content and participant-wrapped key material.
func (m SecurityMode) ContentBlind() bool {
	return m == SecurityModePrivate || m == SecurityModeSecure
}

// RotatesKeyEpochOnRevocation reports whether a participant revocation must
// establish a fresh content-key epoch. Private Spaces deliberately retain their
// static group-key epoch; Secure and managed Spaces rotate.
func (m SecurityMode) RotatesKeyEpochOnRevocation() bool {
	return m == SecurityModeSecure || m == SecurityModeManaged
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
	Version                        int                      `json:"version"`
	RetryID                        uuid.UUID                `json:"retryID"`
	SpaceID                        uuid.UUID                `json:"spaceID"`
	SecurityMode                   SecurityMode             `json:"securityMode"`
	InteractionMode                InteractionMode          `json:"interactionMode"`
	InitialParticipantID           uuid.UUID                `json:"initialParticipantID"`
	InitialParticipantKind         ParticipantKind          `json:"initialParticipantKind"`
	InitialParticipantSigningKey   ParticipantSigningKey    `json:"initialParticipantSigningKey"`
	InitialParticipantDeviceKeys   []ParticipantDeviceKey   `json:"initialParticipantDeviceKeys"`
	InitialSecureRosterAttestation *SecureRosterAttestation `json:"initialSecureRosterAttestation,omitempty"`
	Tenant                         relay.TenantRegistration `json:"tenant"`
	Domain                         relay.DomainProvisioning `json:"-"`
	CreatedAtMilliseconds          int64                    `json:"createdAtMilliseconds"`
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
	if err := p.InitialParticipantSigningKey.Validate(); err != nil {
		return err
	}
	host := Participant{
		Version: SchemaVersion, SpaceID: p.SpaceID, ParticipantID: p.InitialParticipantID,
		SubscriptionID: p.Domain.Subscription.SubscriptionID, Kind: p.InitialParticipantKind,
		Role: RoleHost, SigningKey: p.InitialParticipantSigningKey,
		DeviceKeys:            p.InitialParticipantDeviceKeys,
		CreatedAtMilliseconds: p.CreatedAtMilliseconds,
	}
	if err := host.Validate(); err != nil {
		return err
	}
	if p.SecurityMode == SecurityModeSecure {
		if p.InitialSecureRosterAttestation == nil {
			return NewProtocolError(CodeInvalidSpace, "Secure Shared Space provisioning is missing its initial roster attestation")
		}
		if err := p.InitialSecureRosterAttestation.ValidateInitial(host); err != nil {
			return err
		}
	} else if p.InitialSecureRosterAttestation != nil {
		return NewProtocolError(CodeInvalidSpace, "only Secure Shared Space provisioning may carry a roster attestation")
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
	Version               int                    `json:"version"`
	SpaceID               uuid.UUID              `json:"spaceID"`
	ParticipantID         uuid.UUID              `json:"participantID"`
	SubscriptionID        uuid.UUID              `json:"subscriptionID"`
	Kind                  ParticipantKind        `json:"kind"`
	Role                  Role                   `json:"role"`
	SigningKey            ParticipantSigningKey  `json:"signingKey"`
	DeviceKeys            []ParticipantDeviceKey `json:"deviceKeys"`
	CreatedAtMilliseconds int64                  `json:"createdAtMilliseconds"`
	RevokedAtMilliseconds *int64                 `json:"revokedAtMilliseconds,omitempty"`
}

func (p Participant) Validate() error {
	if p.Version != SchemaVersion || p.SpaceID == uuid.Nil || p.ParticipantID == uuid.Nil ||
		p.SubscriptionID == uuid.Nil || !p.Kind.Valid() || !p.Role.Valid() ||
		p.CreatedAtMilliseconds < 0 ||
		(p.RevokedAtMilliseconds != nil && *p.RevokedAtMilliseconds < p.CreatedAtMilliseconds) {
		return NewProtocolError(CodeInvalidParticipant, "Shared Space participant fields are invalid")
	}
	if err := p.SigningKey.Validate(); err != nil {
		return err
	}
	previousDeviceID := ""
	for _, deviceKey := range p.DeviceKeys {
		if deviceKey.SpaceID != p.SpaceID || deviceKey.ParticipantID != p.ParticipantID {
			return NewProtocolError(CodeWrongScope, "Shared Space participant device key has the wrong scope")
		}
		if err := deviceKey.Validate(p); err != nil {
			return err
		}
		if previousDeviceID != "" && previousDeviceID >= deviceKey.DeviceID.String() {
			return NewProtocolError(CodeInvalidParticipant, "Shared Space participant device keys are invalid")
		}
		previousDeviceID = deviceKey.DeviceID.String()
	}
	return nil
}

// HasActiveDeviceKey reports whether the participant's signed authority binds
// the exact agreement-key recipient. It deliberately compares both the device
// identifier and fingerprint so a stale or substituted key cannot select a
// stored opaque grant.
func (p Participant) HasActiveDeviceKey(deviceID uuid.UUID, fingerprint string) bool {
	return hasActiveParticipantDeviceKey(p.DeviceKeys, deviceID, fingerprint)
}

// ParticipantPresentation is mutable recognition metadata for one participant.
// It is deliberately separate from membership authority: relay credentials,
// participant IDs, roles, and revocation remain the only access controls.
type ParticipantPresentation struct {
	Version               int       `json:"version"`
	SpaceID               uuid.UUID `json:"spaceID"`
	ParticipantID         uuid.UUID `json:"participantID"`
	DisplayName           string    `json:"displayName"`
	Revision              uint64    `json:"revision"`
	UpdatedAtMilliseconds int64     `json:"updatedAtMilliseconds"`
}

func (p ParticipantPresentation) Validate() error {
	if p.Version != SchemaVersion || p.SpaceID == uuid.Nil || p.ParticipantID == uuid.Nil ||
		p.Revision == 0 || p.UpdatedAtMilliseconds < 0 ||
		!validParticipantDisplayName(p.DisplayName) {
		return NewProtocolError(
			CodeInvalidParticipantPresentation,
			"Shared Space participant presentation fields are invalid",
		)
	}
	return nil
}

type ParticipantPresentationUpdate struct {
	Version               int       `json:"version"`
	RetryID               uuid.UUID `json:"retryID"`
	SpaceID               uuid.UUID `json:"spaceID"`
	ParticipantID         uuid.UUID `json:"participantID"`
	PreviousRevision      uint64    `json:"previousRevision"`
	DisplayName           string    `json:"displayName"`
	UpdatedAtMilliseconds int64     `json:"updatedAtMilliseconds"`
}

func (u ParticipantPresentationUpdate) Validate() error {
	if u.Version != SchemaVersion || u.RetryID == uuid.Nil || u.SpaceID == uuid.Nil ||
		u.ParticipantID == uuid.Nil || u.UpdatedAtMilliseconds < 0 ||
		!validParticipantDisplayName(u.DisplayName) {
		return NewProtocolError(
			CodeInvalidParticipantPresentation,
			"Shared Space participant presentation update fields are invalid",
		)
	}
	return nil
}

type ParticipantPresentationUpdateResult struct {
	Acceptance   relay.Acceptance        `json:"acceptance"`
	RetryID      uuid.UUID               `json:"retryID"`
	Presentation ParticipantPresentation `json:"presentation"`
}

func validParticipantDisplayName(value string) bool {
	trimmed := strings.TrimSpace(value)
	return utf8.ValidString(value) && trimmed == value && trimmed != "" &&
		len(value) <= MaximumParticipantDisplayNameBytes &&
		utf8.RuneCountInString(value) <= MaximumParticipantDisplayNameRunes
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
	Version                           int                      `json:"version"`
	RetryID                           uuid.UUID                `json:"retryID"`
	SpaceID                           uuid.UUID                `json:"spaceID"`
	InvitationID                      uuid.UUID                `json:"invitationID"`
	ParticipantID                     uuid.UUID                `json:"participantID"`
	SubscriptionID                    uuid.UUID                `json:"subscriptionID"`
	Kind                              ParticipantKind          `json:"kind"`
	Role                              Role                     `json:"role"`
	InteractionMode                   InteractionMode          `json:"interactionMode"`
	ParticipantSigningKey             ParticipantSigningKey    `json:"participantSigningKey"`
	ParticipantDeviceKeys             []ParticipantDeviceKey   `json:"participantDeviceKeys"`
	KeyGrant                          *ParticipantKeyGrant     `json:"keyGrant,omitempty"`
	ActivationSecureRosterAttestation *SecureRosterAttestation `json:"activationSecureRosterAttestation,omitempty"`
	RelayAdmission                    relay.MemberAdmission    `json:"relayAdmission"`
	CreatedAtMilliseconds             int64                    `json:"createdAtMilliseconds"`
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
	if err := i.ParticipantSigningKey.Validate(); err != nil {
		return err
	}
	participant := Participant{
		Version: SchemaVersion, SpaceID: i.SpaceID, ParticipantID: i.ParticipantID,
		SubscriptionID: i.SubscriptionID, Kind: i.Kind, Role: i.Role,
		SigningKey: i.ParticipantSigningKey, DeviceKeys: i.ParticipantDeviceKeys,
		CreatedAtMilliseconds: i.CreatedAtMilliseconds,
	}
	if err := participant.Validate(); err != nil {
		return err
	}
	if i.KeyGrant != nil {
		if err := i.KeyGrant.Validate(); err != nil {
			return err
		}
	}
	if i.ActivationSecureRosterAttestation != nil && i.ActivationSecureRosterAttestation.SpaceID != i.SpaceID {
		return NewProtocolError(CodeWrongScope, "Shared Space invitation roster attestation belongs to another Space")
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
// Space content-key epoch. The server verifies signature, routing scope, and
// that the signature uses the issuer's registered public signing key. Only a
// participant client decrypts the wrapped key material.
type ParticipantKeyGrant struct {
	Version                          int                          `json:"version"`
	SpaceID                          uuid.UUID                    `json:"spaceID"`
	ParticipantID                    uuid.UUID                    `json:"participantID"`
	RecipientDeviceID                uuid.UUID                    `json:"recipientDeviceID"`
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

// SecureRosterAttestation is the client-signed, hash-linked authority view for
// a Secure Shared Space. It contains only public membership authority: active
// participants, their public signing identities, roles, and the current
// content-key epoch. It deliberately excludes content, wrapped keys, relay
// credentials, invitation records, and recognition metadata.
//
// The first record is signed by the initial host. Each later record names the
// digest of its predecessor and is signed by an active host or moderator from
// that predecessor. A client can therefore detect a server-substituted roster
// or an equivocated transition after it has observed a prior attestation.
type SecureRosterAttestation struct {
	Version               int                          `json:"version"`
	SpaceID               uuid.UUID                    `json:"spaceID"`
	DomainID              uuid.UUID                    `json:"domainID"`
	Revision              uint64                       `json:"revision"`
	PreviousDigest        string                       `json:"previousDigest,omitempty"`
	CurrentKeyEpoch       uint64                       `json:"currentKeyEpoch"`
	Participants          []Participant                `json:"participants"`
	IssuerParticipantID   uuid.UUID                    `json:"issuerParticipantID"`
	CreatedAtMilliseconds int64                        `json:"createdAtMilliseconds"`
	Signature             ParticipantKeyGrantSignature `json:"signature"`
}

type secureRosterAttestationSigningFields struct {
	Version               int           `json:"version"`
	SpaceID               uuid.UUID     `json:"spaceID"`
	DomainID              uuid.UUID     `json:"domainID"`
	Revision              uint64        `json:"revision"`
	PreviousDigest        string        `json:"previousDigest,omitempty"`
	CurrentKeyEpoch       uint64        `json:"currentKeyEpoch"`
	Participants          []Participant `json:"participants"`
	IssuerParticipantID   uuid.UUID     `json:"issuerParticipantID"`
	CreatedAtMilliseconds int64         `json:"createdAtMilliseconds"`
}

func (a SecureRosterAttestation) signingPayload() ([]byte, error) {
	return json.Marshal(secureRosterAttestationSigningFields{
		Version: a.Version, SpaceID: a.SpaceID, DomainID: a.DomainID,
		Revision: a.Revision, PreviousDigest: a.PreviousDigest,
		CurrentKeyEpoch: a.CurrentKeyEpoch, Participants: a.Participants,
		IssuerParticipantID:   a.IssuerParticipantID,
		CreatedAtMilliseconds: a.CreatedAtMilliseconds,
	})
}

// SigningPayload returns the canonical bytes covered by Signature. Swift
// clients must use this representation rather than a map encoding so secure
// roster authority is portable across implementations.
func (a SecureRosterAttestation) SigningPayload() ([]byte, error) {
	return a.signingPayload()
}

// Digest is the predecessor reference used by a successor attestation. It
// includes the signature, so changing either authority data or its signer
// changes the chain.
func (a SecureRosterAttestation) Digest() (string, error) {
	encoded, err := json.Marshal(a)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func (a SecureRosterAttestation) Validate() error {
	if a.Version != SchemaVersion || a.SpaceID == uuid.Nil || a.DomainID == uuid.Nil ||
		a.Revision == 0 || a.CurrentKeyEpoch == 0 || a.IssuerParticipantID == uuid.Nil ||
		a.CreatedAtMilliseconds < 0 ||
		(a.Revision == 1 && a.PreviousDigest != "") ||
		(a.Revision > 1 && !validFingerprint(a.PreviousDigest)) {
		return NewProtocolError(CodeInvalidParticipant, "Secure Shared Space roster attestation fields are invalid")
	}
	participantIDs := make(map[uuid.UUID]struct{}, len(a.Participants))
	for index, participant := range a.Participants {
		if err := participant.Validate(); err != nil {
			return err
		}
		if len(participant.DeviceKeys) == 0 {
			return NewProtocolError(CodeInvalidParticipant, "Secure Shared Space roster participant has no device key")
		}
		activeDeviceKeys := 0
		previousDeviceID := ""
		for _, deviceKey := range participant.DeviceKeys {
			if err := deviceKey.Validate(participant); err != nil ||
				(previousDeviceID != "" && previousDeviceID >= deviceKey.DeviceID.String()) {
				return NewProtocolError(CodeInvalidParticipant, "Secure Shared Space roster participant device keys are invalid")
			}
			previousDeviceID = deviceKey.DeviceID.String()
			if deviceKey.RevokedAtMilliseconds == nil {
				activeDeviceKeys++
			}
		}
		if activeDeviceKeys == 0 {
			return NewProtocolError(CodeInvalidParticipant, "Secure Shared Space roster participant has no active device key")
		}
		if participant.SpaceID != a.SpaceID || participant.RevokedAtMilliseconds != nil ||
			(index > 0 && a.Participants[index-1].ParticipantID.String() >= participant.ParticipantID.String()) {
			return NewProtocolError(CodeInvalidParticipant, "Secure Shared Space roster attestation participants are invalid")
		}
		if _, found := participantIDs[participant.ParticipantID]; found {
			return NewProtocolError(CodeInvalidParticipant, "Secure Shared Space roster attestation contains duplicate participants")
		}
		participantIDs[participant.ParticipantID] = struct{}{}
	}
	if _, found := participantIDs[a.IssuerParticipantID]; !found ||
		a.Signature.Algorithm != ParticipantKeyGrantSignatureAlgorithm ||
		!validFingerprint(a.Signature.SigningKeyFingerprint) ||
		!validBase64URLSize(a.Signature.PublicSigningKeyX963, 65, 65) ||
		!validBase64URLSize(a.Signature.Signature, 64, 64) {
		return NewProtocolError(CodeInvalidParticipant, "Secure Shared Space roster attestation issuer or signature is invalid")
	}
	publicKeyBytes, _ := base64.RawURLEncoding.Strict().DecodeString(a.Signature.PublicSigningKeyX963)
	fingerprint := sha256.Sum256(publicKeyBytes)
	if hex.EncodeToString(fingerprint[:]) != a.Signature.SigningKeyFingerprint {
		return NewProtocolError(CodeInvalidParticipant, "Secure Shared Space roster attestation signing-key fingerprint differs")
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), publicKeyBytes)
	if x == nil || y == nil {
		return NewProtocolError(CodeInvalidParticipant, "Secure Shared Space roster attestation signing key is invalid")
	}
	payload, err := a.signingPayload()
	if err != nil {
		return NewProtocolError(CodeInvalidParticipant, "Secure Shared Space roster attestation cannot be encoded")
	}
	signatureBytes, _ := base64.RawURLEncoding.Strict().DecodeString(a.Signature.Signature)
	digest := sha256.Sum256(payload)
	if !ecdsa.Verify(
		&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, digest[:],
		new(big.Int).SetBytes(signatureBytes[:32]), new(big.Int).SetBytes(signatureBytes[32:]),
	) {
		return NewProtocolError(CodeInvalidParticipant, "Secure Shared Space roster attestation signature is invalid")
	}
	return nil
}

// ValidateInitial verifies the first authority record against the initial host
// pinned in the provisioning record.
func (a SecureRosterAttestation) ValidateInitial(host Participant) error {
	if err := a.Validate(); err != nil {
		return err
	}
	if a.Revision != 1 || a.PreviousDigest != "" || a.CurrentKeyEpoch != InitialKeyEpoch ||
		a.IssuerParticipantID != host.ParticipantID || host.Role != RoleHost ||
		!host.SigningKey.MatchesGrantSignature(a.Signature) || len(a.Participants) != 1 ||
		!reflect.DeepEqual(a.Participants[0], host) {
		return NewProtocolError(CodeUnauthorized, "Secure Shared Space initial roster attestation is not bound to its host")
	}
	return nil
}

// ValidateSuccessor verifies that the new roster is the immediate signed
// successor to previous and that its issuer was authorized in that prior
// roster. expectedParticipants is the exact active authority state the server
// is about to persist; the server cannot silently add, remove, or retitle a
// participant while retaining a valid client attestation.
func (a SecureRosterAttestation) ValidateSuccessor(
	previous SecureRosterAttestation,
	expectedParticipants []Participant,
	expectedKeyEpoch uint64,
) error {
	if err := a.Validate(); err != nil {
		return err
	}
	if err := previous.Validate(); err != nil {
		return err
	}
	previousDigest, err := previous.Digest()
	if err != nil {
		return NewProtocolError(CodeInvalidParticipant, "Secure Shared Space prior roster attestation cannot be encoded")
	}
	if a.SpaceID != previous.SpaceID || a.DomainID != previous.DomainID ||
		a.Revision != previous.Revision+1 || a.PreviousDigest != previousDigest ||
		a.CurrentKeyEpoch != expectedKeyEpoch ||
		!sameParticipants(a.Participants, expectedParticipants) {
		return NewProtocolError(CodeWrongScope, "Secure Shared Space roster attestation transition differs from authority state")
	}
	var issuer *Participant
	for index := range previous.Participants {
		candidate := &previous.Participants[index]
		if candidate.ParticipantID == a.IssuerParticipantID {
			issuer = candidate
			break
		}
	}
	if issuer == nil || (issuer.Role != RoleHost && issuer.Role != RoleModerator) ||
		!issuer.SigningKey.MatchesGrantSignature(a.Signature) {
		return NewProtocolError(CodeUnauthorized, "Secure Shared Space roster attestation issuer is not an authorized prior member")
	}
	return nil
}

func sameParticipants(left, right []Participant) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !reflect.DeepEqual(left[index], right[index]) {
			return false
		}
	}
	return true
}

type participantKeyGrantSigningFields struct {
	Version                          int       `json:"version"`
	SpaceID                          uuid.UUID `json:"spaceID"`
	ParticipantID                    uuid.UUID `json:"participantID"`
	RecipientDeviceID                uuid.UUID `json:"recipientDeviceID"`
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
		RecipientDeviceID:   g.RecipientDeviceID,
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
	if g.Version != SchemaVersion || g.SpaceID == uuid.Nil || g.ParticipantID == uuid.Nil || g.RecipientDeviceID == uuid.Nil ||
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
	if !mode.Valid() {
		return NewProtocolError(CodeInvalidSpace, "Shared Space security mode is invalid")
	}
	if mode == SecurityModeManaged {
		if i.KeyGrant != nil {
			return NewProtocolError(CodeInvalidInvitation, "managed Shared Space invitations cannot carry participant key grants")
		}
		return nil
	}
	if i.KeyGrant == nil {
		return NewProtocolError(CodeInvalidInvitation, "content-blind Shared Space invitation is missing its participant key grant")
	}
	activeDeviceKeys := 0
	for _, deviceKey := range i.ParticipantDeviceKeys {
		if deviceKey.RevokedAtMilliseconds == nil {
			activeDeviceKeys++
		}
	}
	if activeDeviceKeys != 1 {
		return NewProtocolError(CodeInvalidInvitation, "content-blind Shared Space invitation must admit exactly one active participant device")
	}
	grant := i.KeyGrant
	if grant.SpaceID != i.SpaceID || grant.ParticipantID != i.ParticipantID ||
		grant.CreatedAtMilliseconds != i.CreatedAtMilliseconds {
		return NewProtocolError(CodeWrongScope, "Shared Space invitation and participant key grant scopes differ")
	}
	if grant.KeyEpoch != currentKeyEpoch {
		return NewProtocolError(CodeWrongKeyEpoch, "Shared Space participant key grant is not for the current key epoch")
	}
	if !hasActiveParticipantDeviceKey(
		i.ParticipantDeviceKeys,
		grant.RecipientDeviceID,
		grant.RecipientAgreementKeyFingerprint,
	) {
		return NewProtocolError(CodeWrongScope, "Shared Space participant key grant does not target an active invited device key")
	}
	return nil
}

func hasActiveParticipantDeviceKey(keys []ParticipantDeviceKey, deviceID uuid.UUID, fingerprint string) bool {
	for _, key := range keys {
		if key.DeviceID == deviceID && key.RevokedAtMilliseconds == nil &&
			key.AgreementKeyFingerprint == fingerprint {
			return true
		}
	}
	return false
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
	Acceptance      relay.Acceptance     `json:"acceptance"`
	CurrentKeyEpoch uint64               `json:"currentKeyEpoch"`
	KeyGrant        *ParticipantKeyGrant `json:"keyGrant,omitempty"`
	// SecureRosterAttestation is the signed authority record that admitted the
	// participant. A newly enrolled Secure client persists and verifies this
	// before accepting subsequent roster changes. It is absent for Private and
	// Managed Spaces.
	SecureRosterAttestation *SecureRosterAttestation             `json:"secureRosterAttestation,omitempty"`
	Participant             Participant                          `json:"participant"`
	Member                  relay.SubscriptionMemberRegistration `json:"member"`
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

// ParticipantDeviceEnrollment atomically extends one active participant's
// device authority. The participant signs DeviceKey, while an active host or
// moderator signs the opaque current-epoch KeyGrant. Secure Spaces additionally
// carry the immediate signed roster successor. The Node validates those public
// authority bindings without receiving the content key.
type ParticipantDeviceEnrollment struct {
	Version                 int                      `json:"version"`
	RetryID                 uuid.UUID                `json:"retryID"`
	SpaceID                 uuid.UUID                `json:"spaceID"`
	ParticipantID           uuid.UUID                `json:"participantID"`
	DeviceKey               ParticipantDeviceKey     `json:"deviceKey"`
	KeyGrant                *ParticipantKeyGrant     `json:"keyGrant,omitempty"`
	EnrolledAtMilliseconds  int64                    `json:"enrolledAtMilliseconds"`
	SecureRosterAttestation *SecureRosterAttestation `json:"secureRosterAttestation,omitempty"`
}

func (e ParticipantDeviceEnrollment) Validate() error {
	if e.Version != SchemaVersion || e.RetryID == uuid.Nil || e.SpaceID == uuid.Nil ||
		e.ParticipantID == uuid.Nil || e.DeviceKey.DeviceID == uuid.Nil ||
		e.EnrolledAtMilliseconds < 0 || e.DeviceKey.CreatedAtMilliseconds < 0 ||
		e.DeviceKey.CreatedAtMilliseconds > e.EnrolledAtMilliseconds ||
		e.DeviceKey.RevokedAtMilliseconds != nil {
		return NewProtocolError(CodeInvalidParticipant, "Shared Space participant device enrollment fields are invalid")
	}
	if e.DeviceKey.SpaceID != e.SpaceID || e.DeviceKey.ParticipantID != e.ParticipantID {
		return NewProtocolError(CodeWrongScope, "Shared Space participant device enrollment key has the wrong scope")
	}
	if e.KeyGrant != nil {
		if err := e.KeyGrant.Validate(); err != nil {
			return err
		}
		if e.KeyGrant.SpaceID != e.SpaceID || e.KeyGrant.ParticipantID != e.ParticipantID ||
			e.KeyGrant.RecipientDeviceID != e.DeviceKey.DeviceID ||
			e.KeyGrant.RecipientAgreementKeyFingerprint != e.DeviceKey.AgreementKeyFingerprint ||
			e.KeyGrant.CreatedAtMilliseconds < e.DeviceKey.CreatedAtMilliseconds ||
			e.KeyGrant.CreatedAtMilliseconds > e.EnrolledAtMilliseconds {
			return NewProtocolError(CodeWrongScope, "Shared Space participant device enrollment grant has the wrong scope")
		}
	}
	if e.SecureRosterAttestation != nil {
		if e.SecureRosterAttestation.SpaceID != e.SpaceID {
			return NewProtocolError(CodeWrongScope, "Shared Space participant device enrollment roster has the wrong scope")
		}
		if e.SecureRosterAttestation.CreatedAtMilliseconds != e.EnrolledAtMilliseconds {
			return NewProtocolError(CodeInvalidParticipant, "Shared Space participant device enrollment roster time is invalid")
		}
	}
	return nil
}

// ValidateKeyGrant applies the profile and current authority rules that need
// the stored participant roster. Device enrollment is intentionally limited to
// content-blind profiles: Managed Spaces do not distribute participant grants.
func (e ParticipantDeviceEnrollment) ValidateKeyGrant(
	mode SecurityMode,
	currentKeyEpoch uint64,
	participants []Participant,
	nowMilliseconds int64,
) error {
	if mode != SecurityModePrivate && mode != SecurityModeSecure {
		return NewProtocolError(CodeInvalidParticipant, "managed Shared Spaces do not enroll participant agreement-key devices")
	}
	if e.KeyGrant == nil {
		return NewProtocolError(CodeInvalidParticipant, "content-blind Shared Space device enrollment is missing its key grant")
	}
	grant := *e.KeyGrant
	if grant.KeyEpoch != currentKeyEpoch {
		return NewProtocolError(CodeWrongKeyEpoch, "Shared Space participant device enrollment grant is not current")
	}
	if grant.CreatedAtMilliseconds > nowMilliseconds {
		return NewProtocolError(CodeInvalidParticipant, "Shared Space participant device enrollment grant was created in the future")
	}
	var issuer *Participant
	for index := range participants {
		candidate := &participants[index]
		if candidate.ParticipantID == grant.IssuerParticipantID &&
			candidate.RevokedAtMilliseconds == nil {
			issuer = candidate
			break
		}
	}
	if issuer == nil || (issuer.Role != RoleHost && issuer.Role != RoleModerator) ||
		!issuer.SigningKey.MatchesGrantSignature(grant.Signature) {
		return NewProtocolError(CodeUnauthorized, "Shared Space participant device enrollment grant issuer is not an active host or moderator")
	}
	return nil
}

type ParticipantDeviceEnrollmentResult struct {
	Acceptance             relay.Acceptance `json:"acceptance"`
	RetryID                uuid.UUID        `json:"retryID"`
	SpaceID                uuid.UUID        `json:"spaceID"`
	ParticipantID          uuid.UUID        `json:"participantID"`
	DeviceID               uuid.UUID        `json:"deviceID"`
	CurrentKeyEpoch        uint64           `json:"currentKeyEpoch"`
	EnrolledAtMilliseconds int64            `json:"enrolledAtMilliseconds"`
}

// ParticipantDeviceRevocation removes one agreement-key device from an active
// participant without revoking that participant's relay membership. Private
// Spaces retain their static epoch. Secure Spaces advance one epoch and grant
// it to every remaining active device, while the Node validates coverage and
// signatures without learning the content key.
type ParticipantDeviceRevocation struct {
	Version                 int                      `json:"version"`
	RetryID                 uuid.UUID                `json:"retryID"`
	SpaceID                 uuid.UUID                `json:"spaceID"`
	ParticipantID           uuid.UUID                `json:"participantID"`
	DeviceID                uuid.UUID                `json:"deviceID"`
	DeviceKey               ParticipantDeviceKey     `json:"deviceKey"`
	PreviousKeyEpoch        uint64                   `json:"previousKeyEpoch"`
	NextKeyEpoch            uint64                   `json:"nextKeyEpoch"`
	KeyGrants               []ParticipantKeyGrant    `json:"keyGrants,omitempty"`
	SecureRosterAttestation *SecureRosterAttestation `json:"secureRosterAttestation,omitempty"`
}

func (r ParticipantDeviceRevocation) Validate() error {
	if r.Version != SchemaVersion || r.RetryID == uuid.Nil || r.SpaceID == uuid.Nil ||
		r.ParticipantID == uuid.Nil || r.DeviceID == uuid.Nil ||
		r.DeviceKey.SpaceID != r.SpaceID || r.DeviceKey.ParticipantID != r.ParticipantID ||
		r.DeviceKey.DeviceID != r.DeviceID || r.DeviceKey.RevokedAtMilliseconds == nil ||
		r.PreviousKeyEpoch < InitialKeyEpoch || r.NextKeyEpoch < r.PreviousKeyEpoch ||
		r.NextKeyEpoch > r.PreviousKeyEpoch+1 {
		return NewProtocolError(CodeInvalidParticipant, "Shared Space participant device revocation fields are invalid")
	}
	if r.SecureRosterAttestation != nil &&
		r.SecureRosterAttestation.CreatedAtMilliseconds != *r.DeviceKey.RevokedAtMilliseconds {
		return NewProtocolError(CodeInvalidParticipant, "Shared Space participant device revocation roster time is invalid")
	}
	return nil
}

func (r ParticipantDeviceRevocation) ValidateDeviceKey(
	participant Participant,
	current ParticipantDeviceKey,
	nowMilliseconds int64,
) error {
	if current.RevokedAtMilliseconds != nil || r.DeviceKey.RevokedAtMilliseconds == nil ||
		*r.DeviceKey.RevokedAtMilliseconds > nowMilliseconds ||
		r.DeviceKey.Version != current.Version || r.DeviceKey.SpaceID != current.SpaceID ||
		r.DeviceKey.ParticipantID != current.ParticipantID || r.DeviceKey.DeviceID != current.DeviceID ||
		r.DeviceKey.Algorithm != current.Algorithm ||
		r.DeviceKey.AgreementPublicKeyX963 != current.AgreementPublicKeyX963 ||
		r.DeviceKey.AgreementKeyFingerprint != current.AgreementKeyFingerprint ||
		r.DeviceKey.CreatedAtMilliseconds != current.CreatedAtMilliseconds {
		return NewProtocolError(CodeWrongScope, "Shared Space participant device revocation key differs from the enrolled device")
	}
	if err := r.DeviceKey.Validate(participant); err != nil {
		return err
	}
	return nil
}

func (r ParticipantDeviceRevocation) ValidateKeyGrants(
	mode SecurityMode,
	participants []Participant,
	nowMilliseconds int64,
) error {
	if mode == SecurityModeManaged {
		return NewProtocolError(CodeInvalidParticipant, "managed Shared Spaces do not revoke participant agreement-key devices")
	}
	if mode == SecurityModePrivate {
		if r.NextKeyEpoch != r.PreviousKeyEpoch || len(r.KeyGrants) != 0 {
			return NewProtocolError(CodeInvalidParticipant, "private Shared Space device revocation must retain its static key epoch without key grants")
		}
		return nil
	}
	if mode != SecurityModeSecure || r.NextKeyEpoch != r.PreviousKeyEpoch+1 {
		return NewProtocolError(CodeInvalidParticipant, "secure Shared Space device revocation must advance its key epoch")
	}

	type grantTarget struct {
		participantID uuid.UUID
		deviceID      uuid.UUID
	}
	expectedTargets := make(map[grantTarget]string)
	authorizedIssuers := make(map[uuid.UUID]ParticipantSigningKey)
	targetFound := false
	for _, participant := range participants {
		if participant.SpaceID != r.SpaceID {
			return NewProtocolError(CodeWrongScope, "Shared Space participant belongs to another Space")
		}
		if participant.RevokedAtMilliseconds != nil {
			continue
		}
		if participant.Role == RoleHost || participant.Role == RoleModerator {
			authorizedIssuers[participant.ParticipantID] = participant.SigningKey
		}
		for _, deviceKey := range participant.DeviceKeys {
			if participant.ParticipantID == r.ParticipantID && deviceKey.DeviceID == r.DeviceID {
				targetFound = deviceKey.RevokedAtMilliseconds == nil
				continue
			}
			if deviceKey.RevokedAtMilliseconds == nil {
				expectedTargets[grantTarget{participantID: participant.ParticipantID, deviceID: deviceKey.DeviceID}] = deviceKey.AgreementKeyFingerprint
			}
		}
	}
	if !targetFound {
		return NewProtocolError(CodeParticipantNotFound, "active participant device was not found")
	}
	if len(r.KeyGrants) != len(expectedTargets) {
		return NewProtocolError(CodeInvalidParticipant, "secure Shared Space device revocation does not grant the next key epoch to every remaining device")
	}
	seen := make(map[grantTarget]struct{}, len(r.KeyGrants))
	for _, grant := range r.KeyGrants {
		if err := grant.Validate(); err != nil {
			return err
		}
		target := grantTarget{participantID: grant.ParticipantID, deviceID: grant.RecipientDeviceID}
		expectedFingerprint, found := expectedTargets[target]
		if grant.SpaceID != r.SpaceID || !found ||
			grant.RecipientAgreementKeyFingerprint != expectedFingerprint {
			return NewProtocolError(CodeWrongScope, "Shared Space device revocation key grant does not target a remaining active device")
		}
		if grant.KeyEpoch != r.NextKeyEpoch {
			return NewProtocolError(CodeWrongKeyEpoch, "Shared Space device revocation key grant is not for the next key epoch")
		}
		if grant.CreatedAtMilliseconds > nowMilliseconds {
			return NewProtocolError(CodeInvalidParticipant, "Shared Space device revocation key grant was created in the future")
		}
		if grant.CreatedAtMilliseconds > *r.DeviceKey.RevokedAtMilliseconds {
			return NewProtocolError(CodeInvalidParticipant, "Shared Space device revocation key grant postdates revocation")
		}
		issuerKey, found := authorizedIssuers[grant.IssuerParticipantID]
		if !found || !issuerKey.MatchesGrantSignature(grant.Signature) {
			return NewProtocolError(CodeUnauthorized, "Shared Space device revocation key grant issuer is not an active host or moderator")
		}
		if _, found := seen[target]; found {
			return NewProtocolError(CodeInvalidParticipant, "Shared Space device revocation contains duplicate device key grants")
		}
		seen[target] = struct{}{}
	}
	return nil
}

func (r ParticipantDeviceRevocation) Equivalent(other ParticipantDeviceRevocation) bool {
	if r.Version != other.Version || r.RetryID != other.RetryID || r.SpaceID != other.SpaceID ||
		r.ParticipantID != other.ParticipantID || r.DeviceID != other.DeviceID ||
		!reflect.DeepEqual(r.DeviceKey, other.DeviceKey) ||
		r.PreviousKeyEpoch != other.PreviousKeyEpoch || r.NextKeyEpoch != other.NextKeyEpoch ||
		len(r.KeyGrants) != len(other.KeyGrants) ||
		!sameOptionalSecureRosterAttestation(r.SecureRosterAttestation, other.SecureRosterAttestation) {
		return false
	}
	type grantTarget struct {
		participantID uuid.UUID
		deviceID      uuid.UUID
	}
	grants := make(map[grantTarget]ParticipantKeyGrant, len(r.KeyGrants))
	for _, grant := range r.KeyGrants {
		target := grantTarget{participantID: grant.ParticipantID, deviceID: grant.RecipientDeviceID}
		if _, found := grants[target]; found {
			return false
		}
		grants[target] = grant
	}
	for _, grant := range other.KeyGrants {
		target := grantTarget{participantID: grant.ParticipantID, deviceID: grant.RecipientDeviceID}
		if existing, found := grants[target]; !found || existing != grant {
			return false
		}
	}
	return true
}

type ParticipantDeviceRevocationResult struct {
	Acceptance            relay.Acceptance `json:"acceptance"`
	RetryID               uuid.UUID        `json:"retryID"`
	SpaceID               uuid.UUID        `json:"spaceID"`
	ParticipantID         uuid.UUID        `json:"participantID"`
	DeviceID              uuid.UUID        `json:"deviceID"`
	PreviousKeyEpoch      uint64           `json:"previousKeyEpoch"`
	CurrentKeyEpoch       uint64           `json:"currentKeyEpoch"`
	RevokedAtMilliseconds int64            `json:"revokedAtMilliseconds"`
}

type ParticipantRevocation struct {
	Version                 int                      `json:"version"`
	RetryID                 uuid.UUID                `json:"retryID"`
	SpaceID                 uuid.UUID                `json:"spaceID"`
	ParticipantID           uuid.UUID                `json:"participantID"`
	PreviousKeyEpoch        uint64                   `json:"previousKeyEpoch"`
	NextKeyEpoch            uint64                   `json:"nextKeyEpoch"`
	KeyGrants               []ParticipantKeyGrant    `json:"keyGrants,omitempty"`
	SecureRosterAttestation *SecureRosterAttestation `json:"secureRosterAttestation,omitempty"`
}

func (r ParticipantRevocation) Validate() error {
	if r.Version != SchemaVersion || r.RetryID == uuid.Nil || r.SpaceID == uuid.Nil ||
		r.ParticipantID == uuid.Nil || r.PreviousKeyEpoch < InitialKeyEpoch ||
		r.NextKeyEpoch < r.PreviousKeyEpoch || r.NextKeyEpoch > r.PreviousKeyEpoch+1 {
		return NewProtocolError(CodeInvalidParticipant, "Shared Space participant revocation fields are invalid")
	}
	return nil
}

// ValidateKeyGrants enforces the security profile's revocation rule. Secure
// Spaces rotate atomically: every active device of every remaining active
// participant must receive a valid opaque grant for the next epoch. Private
// Spaces retain their static epoch and carry no rotation grants. The server
// validates authority and coverage without learning a content key in either
// content-blind profile.
func (r ParticipantRevocation) ValidateKeyGrants(
	mode SecurityMode,
	participants []Participant,
	nowMilliseconds int64,
) error {
	if !mode.Valid() {
		return NewProtocolError(CodeInvalidSpace, "Shared Space security mode is invalid")
	}
	if mode == SecurityModePrivate {
		if r.NextKeyEpoch != r.PreviousKeyEpoch || len(r.KeyGrants) != 0 {
			return NewProtocolError(CodeInvalidParticipant, "private Shared Space revocation must retain its static key epoch without key grants")
		}
		return nil
	}
	if mode == SecurityModeManaged {
		if r.NextKeyEpoch != r.PreviousKeyEpoch+1 || len(r.KeyGrants) != 0 {
			return NewProtocolError(CodeInvalidParticipant, "managed Shared Space revocation must rotate its key epoch without participant key grants")
		}
		return nil
	}
	if r.NextKeyEpoch != r.PreviousKeyEpoch+1 {
		return NewProtocolError(CodeInvalidParticipant, "secure Shared Space revocation must advance its key epoch")
	}

	type grantTarget struct {
		participantID uuid.UUID
		deviceID      uuid.UUID
	}
	active := make(map[uuid.UUID]Participant)
	expectedTargets := make(map[grantTarget]string)
	authorizedIssuers := make(map[uuid.UUID]ParticipantSigningKey)
	for _, participant := range participants {
		if participant.SpaceID != r.SpaceID {
			return NewProtocolError(CodeWrongScope, "Shared Space participant belongs to another Space")
		}
		if participant.RevokedAtMilliseconds != nil || participant.ParticipantID == r.ParticipantID {
			continue
		}
		active[participant.ParticipantID] = participant
		for _, deviceKey := range participant.DeviceKeys {
			if deviceKey.RevokedAtMilliseconds == nil {
				expectedTargets[grantTarget{
					participantID: participant.ParticipantID,
					deviceID:      deviceKey.DeviceID,
				}] = deviceKey.AgreementKeyFingerprint
			}
		}
		if participant.Role == RoleHost || participant.Role == RoleModerator {
			authorizedIssuers[participant.ParticipantID] = participant.SigningKey
		}
	}
	if len(r.KeyGrants) != len(expectedTargets) {
		return NewProtocolError(CodeInvalidParticipant, "secure Shared Space revocation does not grant the next key epoch to every remaining participant device")
	}

	seen := make(map[grantTarget]struct{}, len(r.KeyGrants))
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
		target := grantTarget{participantID: grant.ParticipantID, deviceID: grant.RecipientDeviceID}
		if expectedFingerprint, found := expectedTargets[target]; !found || expectedFingerprint != grant.RecipientAgreementKeyFingerprint {
			return NewProtocolError(CodeWrongScope, "Shared Space revocation key grant does not target an active participant device key")
		}
		issuerKey, found := authorizedIssuers[grant.IssuerParticipantID]
		if !found {
			return NewProtocolError(CodeUnauthorized, "Shared Space revocation key grant issuer is not an active host or moderator")
		}
		if !issuerKey.MatchesGrantSignature(grant.Signature) {
			return NewProtocolError(CodeUnauthorized, "Shared Space revocation key grant signature is not bound to its issuer")
		}
		if _, found := seen[target]; found {
			return NewProtocolError(CodeInvalidParticipant, "Shared Space revocation contains duplicate participant device key grants")
		}
		seen[target] = struct{}{}
	}
	return nil
}

// Equivalent compares a retry request independently of grant ordering. A
// caller may safely resend the same atomic rotation with canonical or original
// participant order without creating a retry collision.
func (r ParticipantRevocation) Equivalent(other ParticipantRevocation) bool {
	if r.Version != other.Version || r.RetryID != other.RetryID || r.SpaceID != other.SpaceID ||
		r.ParticipantID != other.ParticipantID || r.PreviousKeyEpoch != other.PreviousKeyEpoch ||
		r.NextKeyEpoch != other.NextKeyEpoch || len(r.KeyGrants) != len(other.KeyGrants) ||
		!sameOptionalSecureRosterAttestation(r.SecureRosterAttestation, other.SecureRosterAttestation) {
		return false
	}
	type grantTarget struct {
		participantID uuid.UUID
		deviceID      uuid.UUID
	}
	grants := make(map[grantTarget]ParticipantKeyGrant, len(r.KeyGrants))
	for _, grant := range r.KeyGrants {
		target := grantTarget{participantID: grant.ParticipantID, deviceID: grant.RecipientDeviceID}
		if _, found := grants[target]; found {
			return false
		}
		grants[target] = grant
	}
	for _, grant := range other.KeyGrants {
		target := grantTarget{participantID: grant.ParticipantID, deviceID: grant.RecipientDeviceID}
		if existing, found := grants[target]; !found || existing != grant {
			return false
		}
	}
	return true
}

func sameOptionalSecureRosterAttestation(left, right *SecureRosterAttestation) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return reflect.DeepEqual(*left, *right)
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
	Version               int                      `json:"version"`
	SpaceID               uuid.UUID                `json:"spaceID"`
	DomainID              uuid.UUID                `json:"domainID"`
	SecurityMode          SecurityMode             `json:"securityMode"`
	InteractionMode       InteractionMode          `json:"interactionMode"`
	CurrentKeyEpoch       uint64                   `json:"currentKeyEpoch"`
	BootstrapReady        bool                     `json:"bootstrapReady"`
	ActiveCheckpointEpoch *uint64                  `json:"activeCheckpointEpoch,omitempty"`
	Participant           Participant              `json:"participant"`
	Presentation          *ParticipantPresentation `json:"presentation,omitempty"`
	Capabilities          []relay.Capability       `json:"capabilities"`
	CreatedAtMilliseconds int64                    `json:"createdAtMilliseconds"`
}

// ParticipantRoster is the active membership view available to an enrolled
// participant of a Secure Shared Space. It deliberately carries recognition
// metadata and membership roles only: it does not disclose invitations,
// revoked members, relay credentials, or content-key material.
//
// Private Spaces intentionally do not expose this roster. Their closed-group
// operator can use the administrative status view, while Secure Spaces make
// current membership visible to every participant as an operational safety
// control.
type ParticipantRoster struct {
	Version      int          `json:"version"`
	SpaceID      uuid.UUID    `json:"spaceID"`
	DomainID     uuid.UUID    `json:"domainID"`
	SecurityMode SecurityMode `json:"securityMode"`
	// AuthoritySequence is the newest accepted authority transition for this
	// Space. A client can compare it with its last observed value to discover
	// that active membership or role state changed, without the service
	// disclosing historical authority events or revoked participants.
	AuthoritySequence     uint64                    `json:"authoritySequence"`
	CurrentKeyEpoch       uint64                    `json:"currentKeyEpoch"`
	Participants          []Participant             `json:"participants"`
	Presentations         []ParticipantPresentation `json:"presentations"`
	AuthorityAttestation  SecureRosterAttestation   `json:"authorityAttestation"`
	CreatedAtMilliseconds int64                     `json:"createdAtMilliseconds"`
}

// SecureRosterAttestationPage lets an active Secure participant recover a
// missed portion of the signed roster chain after being offline. It is not a
// participant presentation: callers render only the current ParticipantRoster
// and use these records solely to validate continuity. Historic records may
// describe members who are no longer active, so the server never serves this
// endpoint to a revoked participant.
type SecureRosterAttestationPage struct {
	Version      int                       `json:"version"`
	SpaceID      uuid.UUID                 `json:"spaceID"`
	DomainID     uuid.UUID                 `json:"domainID"`
	Attestations []SecureRosterAttestation `json:"attestations"`
	NextRevision uint64                    `json:"nextRevision"`
}

func (p SecureRosterAttestationPage) Validate() error {
	if p.Version != SchemaVersion || p.SpaceID == uuid.Nil || p.DomainID == uuid.Nil ||
		len(p.Attestations) > MaximumSecureRosterAttestationPageSize {
		return NewProtocolError(CodeInvalidParticipant, "Secure Shared Space roster authority page fields are invalid")
	}
	for index, attestation := range p.Attestations {
		if err := attestation.Validate(); err != nil {
			return err
		}
		if attestation.SpaceID != p.SpaceID || attestation.DomainID != p.DomainID ||
			(index > 0 && p.Attestations[index-1].Revision >= attestation.Revision) {
			return NewProtocolError(CodeInvalidParticipant, "Secure Shared Space roster authority page order is invalid")
		}
		if index > 0 {
			previous := p.Attestations[index-1]
			if err := attestation.ValidateSuccessor(previous, attestation.Participants, attestation.CurrentKeyEpoch); err != nil {
				return NewProtocolError(CodeInvalidParticipant, "Secure Shared Space roster authority page is discontinuous")
			}
		}
	}
	if len(p.Attestations) > 0 && p.NextRevision != p.Attestations[len(p.Attestations)-1].Revision {
		return NewProtocolError(CodeInvalidParticipant, "Secure Shared Space roster authority page continuation is invalid")
	}
	return nil
}

func (r ParticipantRoster) Validate() error {
	if r.Version != SchemaVersion || r.SpaceID == uuid.Nil || r.DomainID == uuid.Nil ||
		r.SecurityMode != SecurityModeSecure || r.AuthoritySequence == 0 || r.CurrentKeyEpoch == 0 ||
		r.CreatedAtMilliseconds < 0 {
		return NewProtocolError(CodeInvalidParticipant, "Shared Space participant roster fields are invalid")
	}
	participantIDs := make(map[uuid.UUID]struct{}, len(r.Participants))
	for index, participant := range r.Participants {
		if err := participant.Validate(); err != nil {
			return err
		}
		if participant.SpaceID != r.SpaceID || participant.RevokedAtMilliseconds != nil {
			return NewProtocolError(CodeInvalidParticipant, "Shared Space participant roster includes an invalid member")
		}
		if _, exists := participantIDs[participant.ParticipantID]; exists ||
			(index > 0 && r.Participants[index-1].ParticipantID.String() >= participant.ParticipantID.String()) {
			return NewProtocolError(CodeInvalidParticipant, "Shared Space participant roster order is invalid")
		}
		participantIDs[participant.ParticipantID] = struct{}{}
	}
	for index, presentation := range r.Presentations {
		if err := presentation.Validate(); err != nil {
			return err
		}
		if presentation.SpaceID != r.SpaceID {
			return NewProtocolError(CodeInvalidParticipantPresentation, "Shared Space participant roster presentation scope is invalid")
		}
		if _, found := participantIDs[presentation.ParticipantID]; !found ||
			(index > 0 && r.Presentations[index-1].ParticipantID.String() >= presentation.ParticipantID.String()) {
			return NewProtocolError(CodeInvalidParticipantPresentation, "Shared Space participant roster presentation is invalid")
		}
	}
	if err := r.AuthorityAttestation.Validate(); err != nil {
		return err
	}
	if r.AuthorityAttestation.SpaceID != r.SpaceID || r.AuthorityAttestation.DomainID != r.DomainID ||
		r.AuthorityAttestation.CurrentKeyEpoch != r.CurrentKeyEpoch ||
		!sameParticipants(r.AuthorityAttestation.Participants, r.Participants) {
		return NewProtocolError(CodeInvalidParticipant, "Shared Space participant roster authority attestation differs from roster state")
	}
	return nil
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
	if s.Presentation != nil {
		if err := s.Presentation.Validate(); err != nil {
			return err
		}
		if s.Presentation.SpaceID != s.SpaceID ||
			s.Presentation.ParticipantID != s.Participant.ParticipantID {
			return NewProtocolError(
				CodeInvalidParticipantPresentation,
				"Shared Space participant presentation scope is invalid",
			)
		}
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
// it is never used by content-blind Private or Secure Spaces.
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

// ParticipantBootstrap is an atomic participant-scoped recovery snapshot. A
// content-blind Private or Secure Space includes the caller's opaque
// participant grant. A managed Space includes the service-owned content key.
// A Secure Space also includes its currently attested participant roster, so a
// newly admitted device does not need to combine an independently timed roster
// request with its key-epoch bootstrap. Exactly one key form must match the
// security mode and key epoch reported by Status.
type ParticipantBootstrap struct {
	Version           int                        `json:"version"`
	Status            ParticipantStatus          `json:"status"`
	KeyGrant          *ParticipantKeyGrantResult `json:"keyGrant,omitempty"`
	ManagedContentKey *ManagedContentKey         `json:"managedContentKey,omitempty"`
	Roster            *ParticipantRoster         `json:"roster,omitempty"`
}

func (b ParticipantBootstrap) Validate() error {
	if b.Version != SchemaVersion {
		return NewProtocolError(CodeInvalidParticipant, "Shared Space participant bootstrap version is invalid")
	}
	if err := b.Status.Validate(); err != nil {
		return err
	}
	if b.Status.SecurityMode == SecurityModeManaged {
		if b.KeyGrant != nil || b.ManagedContentKey == nil || b.Roster != nil ||
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
		b.KeyGrant.KeyGrant.KeyEpoch != b.Status.CurrentKeyEpoch ||
		!hasActiveParticipantDeviceKey(
			b.Status.Participant.DeviceKeys,
			b.KeyGrant.KeyGrant.RecipientDeviceID,
			b.KeyGrant.KeyGrant.RecipientAgreementKeyFingerprint,
		) {
		return NewProtocolError(CodeInvalidParticipant, "content-blind Shared Space participant bootstrap key grant is inconsistent")
	}
	if err := b.KeyGrant.KeyGrant.Validate(); err != nil {
		return err
	}
	if b.Status.SecurityMode != SecurityModeSecure {
		if b.Roster != nil {
			return NewProtocolError(CodeInvalidParticipant, "Private Shared Space participant bootstrap must not include a roster")
		}
		return nil
	}
	if b.Roster == nil {
		return NewProtocolError(CodeInvalidParticipant, "Secure Shared Space participant bootstrap roster is missing")
	}
	if err := b.Roster.Validate(); err != nil {
		return err
	}
	if b.Roster.SpaceID != b.Status.SpaceID || b.Roster.DomainID != b.Status.DomainID ||
		b.Roster.SecurityMode != b.Status.SecurityMode ||
		b.Roster.CurrentKeyEpoch != b.Status.CurrentKeyEpoch {
		return NewProtocolError(CodeInvalidParticipant, "Secure Shared Space participant bootstrap roster is inconsistent")
	}
	return nil
}

type ParticipantRoleChange struct {
	Version                 int                      `json:"version"`
	RetryID                 uuid.UUID                `json:"retryID"`
	SpaceID                 uuid.UUID                `json:"spaceID"`
	ParticipantID           uuid.UUID                `json:"participantID"`
	PreviousRole            Role                     `json:"previousRole"`
	NextRole                Role                     `json:"nextRole"`
	ChangedAtMilliseconds   int64                    `json:"changedAtMilliseconds"`
	SecureRosterAttestation *SecureRosterAttestation `json:"secureRosterAttestation,omitempty"`
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
	Version               int                       `json:"version"`
	SpaceID               uuid.UUID                 `json:"spaceID"`
	SecurityMode          SecurityMode              `json:"securityMode"`
	InteractionMode       InteractionMode           `json:"interactionMode"`
	CurrentKeyEpoch       uint64                    `json:"currentKeyEpoch"`
	BootstrapReady        bool                      `json:"bootstrapReady"`
	ActiveCheckpointEpoch *uint64                   `json:"activeCheckpointEpoch,omitempty"`
	DomainID              uuid.UUID                 `json:"domainID"`
	InitialParticipantID  uuid.UUID                 `json:"initialParticipantID"`
	Participants          []Participant             `json:"participants"`
	Presentations         []ParticipantPresentation `json:"presentations"`
	ComputeBindings       []SpaceComputeBinding     `json:"computeBindings"`
	Relay                 relay.DomainStatus        `json:"relay"`
	CreatedAtMilliseconds int64                     `json:"createdAtMilliseconds"`
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
