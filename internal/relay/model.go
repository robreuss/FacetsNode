package relay

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
)

const (
	SchemaVersion                  = 1
	EnvelopeAlgorithm              = "HKDF-SHA256+A256GCM"
	MaximumCiphertextByteCount     = 16 * 1_024 * 1_024
	MaximumPageSize                = 100
	DefaultMaximumMessageCount     = 10_000
	AbsoluteMaximumMessageCount    = 1_000_000
	DefaultMaximumStoredByteCount  = int64(1 * 1_024 * 1_024 * 1_024)
	AbsoluteMaximumStoredByteCount = int64(1 * 1_024 * 1_024 * 1_024 * 1_024)
	MinimumAuthorizationTokenSize  = 32
	MaximumSequence                = uint64(1<<63 - 1)
)

var (
	memberAuthorizationDomain = []byte("Facets replica relay member authorization v1\x00")
	domainAuthorizationDomain = []byte("Facets replica relay domain administration v1\x00")
	envelopeReferenceDomain   = []byte("Facets replica relay envelope reference v1\x00")
)

type Capability string

const (
	CapabilityPublishMessage     Capability = "message_publish"
	CapabilityFetchMessage       Capability = "message_fetch"
	CapabilityAcknowledgeMessage Capability = "message_acknowledge"
	CapabilityPublishBlob        Capability = "blob_publish"
	CapabilityFetchBlob          Capability = "blob_fetch"
	CapabilityPublishCheckpoint  Capability = "checkpoint_publish"
)

func (c Capability) Valid() bool {
	switch c {
	case CapabilityPublishMessage, CapabilityFetchMessage,
		CapabilityAcknowledgeMessage, CapabilityPublishBlob,
		CapabilityFetchBlob, CapabilityPublishCheckpoint:
		return true
	default:
		return false
	}
}

type Credential struct {
	TenantID uuid.UUID
	DomainID uuid.UUID
	MemberID uuid.UUID
	Token    string
}

type AdministrationCredential struct {
	TenantID uuid.UUID
	DomainID uuid.UUID
	Token    string
}

type DomainRegistration struct {
	Version                int       `json:"version"`
	TenantID               uuid.UUID `json:"tenantID"`
	DomainID               uuid.UUID `json:"domainID"`
	AdministrationDigest   string    `json:"administrationDigest"`
	CreatedAtMilliseconds  int64     `json:"createdAtMilliseconds"`
	MaximumMessageCount    int       `json:"maximumMessageCount"`
	MaximumStoredByteCount int64     `json:"maximumStoredByteCount"`
}

func (r DomainRegistration) Validate() error {
	if r.Version != SchemaVersion || r.TenantID == uuid.Nil ||
		r.DomainID == uuid.Nil || !validDigest(r.AdministrationDigest) ||
		r.CreatedAtMilliseconds < 0 || r.MaximumMessageCount <= 0 ||
		r.MaximumMessageCount > AbsoluteMaximumMessageCount ||
		r.MaximumStoredByteCount <= 0 ||
		r.MaximumStoredByteCount > AbsoluteMaximumStoredByteCount {
		return protocolError(CodeInvalidDomain, "domain fields are invalid")
	}
	return nil
}

func (r DomainRegistration) Authorize(credential AdministrationCredential) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if credential.TenantID != r.TenantID || credential.DomainID != r.DomainID {
		return protocolError(CodeWrongScope, "administration credential belongs to another domain")
	}
	actual, err := AdministrationDigest(credential)
	if err != nil || !constantTimeDigestEqual(actual, r.AdministrationDigest) {
		return protocolError(CodeUnauthorized, "administration credential is invalid")
	}
	return nil
}

type MemberRegistration struct {
	Version               int          `json:"version"`
	TenantID              uuid.UUID    `json:"tenantID"`
	DomainID              uuid.UUID    `json:"domainID"`
	MemberID              uuid.UUID    `json:"memberID"`
	AuthorizationDigest   string       `json:"authorizationDigest"`
	Capabilities          []Capability `json:"capabilities"`
	CreatedAtMilliseconds int64        `json:"createdAtMilliseconds"`
	ExpiresAtMilliseconds *int64       `json:"expiresAtMilliseconds,omitempty"`
	RevokedAtMilliseconds *int64       `json:"revokedAtMilliseconds,omitempty"`
}

func (r MemberRegistration) Validate() error {
	if r.Version != SchemaVersion || r.TenantID == uuid.Nil ||
		r.DomainID == uuid.Nil || r.MemberID == uuid.Nil ||
		!validDigest(r.AuthorizationDigest) || r.CreatedAtMilliseconds < 0 ||
		len(r.Capabilities) == 0 {
		return protocolError(CodeInvalidMember, "member fields are invalid")
	}
	for index, capability := range r.Capabilities {
		if !capability.Valid() ||
			(index > 0 && r.Capabilities[index-1] >= capability) {
			return protocolError(CodeInvalidMember, "member capabilities are invalid")
		}
	}
	if r.ExpiresAtMilliseconds != nil &&
		*r.ExpiresAtMilliseconds <= r.CreatedAtMilliseconds {
		return protocolError(CodeInvalidMember, "member expiry is invalid")
	}
	if r.RevokedAtMilliseconds != nil &&
		*r.RevokedAtMilliseconds < r.CreatedAtMilliseconds {
		return protocolError(CodeInvalidMember, "member revocation is invalid")
	}
	return nil
}

func (r MemberRegistration) Authorize(
	credential Credential,
	capability Capability,
	nowMilliseconds int64,
) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if credential.TenantID != r.TenantID || credential.DomainID != r.DomainID ||
		credential.MemberID != r.MemberID {
		return protocolError(CodeWrongScope, "member credential belongs to another scope")
	}
	if nowMilliseconds < r.CreatedAtMilliseconds ||
		(r.ExpiresAtMilliseconds != nil && nowMilliseconds >= *r.ExpiresAtMilliseconds) {
		return protocolError(CodeMemberExpired, "member is not active")
	}
	if r.RevokedAtMilliseconds != nil && nowMilliseconds >= *r.RevokedAtMilliseconds {
		return protocolError(CodeMemberRevoked, "member is revoked")
	}
	index := sort.Search(len(r.Capabilities), func(index int) bool {
		return r.Capabilities[index] >= capability
	})
	if index == len(r.Capabilities) || r.Capabilities[index] != capability {
		return protocolError(CodeMissingCapability, "member lacks the required capability")
	}
	actual, err := AuthorizationDigest(credential)
	if err != nil || !constantTimeDigestEqual(actual, r.AuthorizationDigest) {
		return protocolError(CodeUnauthorized, "member credential is invalid")
	}
	return nil
}

type Envelope struct {
	Version               int       `json:"version"`
	Algorithm             string    `json:"algorithm"`
	TenantID              uuid.UUID `json:"tenantID"`
	DomainID              uuid.UUID `json:"domainID"`
	MessageID             uuid.UUID `json:"messageID"`
	PublisherMemberID     uuid.UUID `json:"publisherMemberID"`
	KeyEpoch              uint64    `json:"keyEpoch"`
	CreatedAtMilliseconds int64     `json:"createdAtMilliseconds"`
	Nonce                 string    `json:"nonce"`
	Ciphertext            string    `json:"ciphertext"`
	AuthenticationTag     string    `json:"authenticationTag"`
}

func (e Envelope) Validate() error {
	if e.Version != SchemaVersion || e.Algorithm != EnvelopeAlgorithm ||
		e.TenantID == uuid.Nil || e.DomainID == uuid.Nil || e.MessageID == uuid.Nil ||
		e.PublisherMemberID == uuid.Nil || e.KeyEpoch == 0 ||
		e.KeyEpoch > MaximumSequence ||
		e.CreatedAtMilliseconds < 0 {
		return protocolError(CodeInvalidEnvelope, "envelope fields are invalid")
	}
	if !validBase64URLSize(e.Nonce, 12, 12) ||
		!validBase64URLSize(e.AuthenticationTag, 16, 16) ||
		!validBase64URLSize(e.Ciphertext, 1, MaximumCiphertextByteCount) {
		return protocolError(CodeInvalidEnvelope, "envelope binary fields are invalid")
	}
	return nil
}

func (e Envelope) ValidateForPublish(credential Credential) error {
	if err := e.Validate(); err != nil {
		return err
	}
	if e.TenantID != credential.TenantID || e.DomainID != credential.DomainID ||
		e.PublisherMemberID != credential.MemberID {
		return protocolError(CodeWrongScope, "envelope and publisher scopes differ")
	}
	return nil
}

func (e Envelope) CiphertextByteCount() (int64, error) {
	if err := e.Validate(); err != nil {
		return 0, err
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(e.Ciphertext)
	if err != nil {
		return 0, protocolError(CodeInvalidEnvelope, "ciphertext encoding is invalid")
	}
	return int64(len(decoded)), nil
}

func (e Envelope) ReferenceDigest() (string, error) {
	if err := e.Validate(); err != nil {
		return "", err
	}
	canonical, err := json.Marshal(map[string]any{
		"algorithm":             e.Algorithm,
		"authenticationTag":     e.AuthenticationTag,
		"ciphertext":            e.Ciphertext,
		"createdAtMilliseconds": e.CreatedAtMilliseconds,
		"domainID":              e.DomainID,
		"keyEpoch":              e.KeyEpoch,
		"messageID":             e.MessageID,
		"nonce":                 e.Nonce,
		"publisherMemberID":     e.PublisherMemberID,
		"tenantID":              e.TenantID,
		"version":               e.Version,
	})
	if err != nil {
		return "", fmt.Errorf("encode envelope reference: %w", err)
	}
	digest := sha256.Sum256(append(append([]byte{}, envelopeReferenceDomain...), canonical...))
	return hex.EncodeToString(digest[:]), nil
}

type Acceptance string

const (
	AcceptanceAccepted  Acceptance = "accepted"
	AcceptanceDuplicate Acceptance = "duplicate"
)

type AcknowledgmentStage string

const (
	AcknowledgmentAccepted AcknowledgmentStage = "accepted"
	AcknowledgmentApplied  AcknowledgmentStage = "applied"
)

func (s AcknowledgmentStage) Valid() bool {
	return s == AcknowledgmentAccepted || s == AcknowledgmentApplied
}

type Message struct {
	Sequence uint64   `json:"sequence"`
	Envelope Envelope `json:"envelope"`
}

type PublishResult struct {
	Acceptance Acceptance `json:"acceptance"`
	Sequence   uint64     `json:"sequence"`
}

type FetchResult struct {
	Messages     []Message `json:"messages"`
	NextSequence uint64    `json:"-"`
}

type AcknowledgmentResult struct {
	Acceptance Acceptance          `json:"acceptance"`
	Stage      AcknowledgmentStage `json:"stage"`
}

func AuthorizationDigest(credential Credential) (string, error) {
	if credential.TenantID == uuid.Nil || credential.DomainID == uuid.Nil ||
		credential.MemberID == uuid.Nil {
		return "", fmt.Errorf("member scope is invalid")
	}
	if err := validateToken(credential.Token); err != nil {
		return "", err
	}
	return scopedDigest(
		memberAuthorizationDomain,
		credential.TenantID.String(),
		credential.DomainID.String(),
		credential.MemberID.String(),
		credential.Token,
	), nil
}

func AdministrationDigest(credential AdministrationCredential) (string, error) {
	if credential.TenantID == uuid.Nil || credential.DomainID == uuid.Nil {
		return "", fmt.Errorf("domain scope is invalid")
	}
	if err := validateToken(credential.Token); err != nil {
		return "", err
	}
	return scopedDigest(
		domainAuthorizationDomain,
		credential.TenantID.String(),
		credential.DomainID.String(),
		credential.Token,
	), nil
}

func EncodeCursor(sequence uint64) string {
	bytes := make([]byte, 8)
	binary.BigEndian.PutUint64(bytes, sequence)
	return base64.RawURLEncoding.EncodeToString(bytes)
}

func DecodeCursor(cursor string) (uint64, error) {
	if cursor == "" {
		return 0, nil
	}
	bytes, err := base64.RawURLEncoding.Strict().DecodeString(cursor)
	if err != nil || len(bytes) != 8 ||
		base64.RawURLEncoding.EncodeToString(bytes) != cursor {
		return 0, protocolError(CodeInvalidCursor, "cursor is invalid")
	}
	sequence := binary.BigEndian.Uint64(bytes)
	if sequence > MaximumSequence {
		return 0, protocolError(CodeInvalidCursor, "cursor is outside the supported range")
	}
	return sequence, nil
}

func scopedDigest(domain []byte, fields ...string) string {
	material := append([]byte{}, domain...)
	for index, field := range fields {
		if index > 0 {
			material = append(material, 0)
		}
		if index < len(fields)-1 {
			field = strings.ToLower(field)
		}
		material = append(material, field...)
	}
	digest := sha256.Sum256(material)
	return hex.EncodeToString(digest[:])
}

func validateToken(value string) error {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != MinimumAuthorizationTokenSize ||
		base64.RawURLEncoding.EncodeToString(decoded) != value {
		return fmt.Errorf("token must be 32-byte unpadded base64url")
	}
	return nil
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func constantTimeDigestEqual(lhs, rhs string) bool {
	lhsBytes, lhsErr := hex.DecodeString(lhs)
	rhsBytes, rhsErr := hex.DecodeString(rhs)
	return lhsErr == nil && rhsErr == nil &&
		subtle.ConstantTimeCompare(lhsBytes, rhsBytes) == 1
}

func validBase64URLSize(value string, minimum, maximum int) bool {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(decoded) >= minimum && len(decoded) <= maximum &&
		base64.RawURLEncoding.EncodeToString(decoded) == value
}
