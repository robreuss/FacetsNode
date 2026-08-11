package rendezvous

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

const (
	SchemaVersion              = 1
	EnvelopeAlgorithm          = "HKDF-SHA256+A256GCM"
	MaximumCiphertextByteCount = 1_048_576
	MaximumMessageCount        = 256
	MaximumRouteLifetimeMS     = int64(24 * 60 * 60 * 1_000)
	MaximumCreationClockSkewMS = int64(5 * 60 * 1_000)
)

var authorizationDomain = []byte("Facets principal pairing router authorization v1\x00")

type Role string

const (
	RoleSponsor   Role = "sponsor"
	RoleCandidate Role = "candidate"
)

func (r Role) Valid() bool {
	return r == RoleSponsor || r == RoleCandidate
}

type Credential struct {
	RouteID uuid.UUID
	Role    Role
	Token   string
}

type Registration struct {
	Version                      int       `json:"version"`
	RouteID                      uuid.UUID `json:"routeID"`
	SponsorAuthorizationDigest   string    `json:"sponsorAuthorizationDigest"`
	CandidateAuthorizationDigest string    `json:"candidateAuthorizationDigest"`
	CreatedAtMilliseconds        int64     `json:"createdAtMilliseconds"`
	ExpiresAtMilliseconds        int64     `json:"expiresAtMilliseconds"`
}

func (r Registration) Validate() error {
	if r.Version != SchemaVersion || r.RouteID == uuid.Nil ||
		r.CreatedAtMilliseconds < 0 ||
		r.ExpiresAtMilliseconds <= r.CreatedAtMilliseconds ||
		!validDigest(r.SponsorAuthorizationDigest) ||
		!validDigest(r.CandidateAuthorizationDigest) ||
		r.SponsorAuthorizationDigest == r.CandidateAuthorizationDigest {
		return protocolError(CodeInvalidRegistration, "registration fields are invalid")
	}
	return nil
}

func (r Registration) ValidateAt(nowMilliseconds int64) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if r.ExpiresAtMilliseconds-r.CreatedAtMilliseconds > MaximumRouteLifetimeMS {
		return protocolError(CodeInvalidRegistration, "route lifetime exceeds the carrier limit")
	}
	if !r.activeAt(nowMilliseconds) {
		return protocolError(CodeRouteExpired, "route is not active")
	}
	return nil
}

func (r Registration) Authorize(credential Credential, nowMilliseconds int64) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if credential.RouteID != r.RouteID {
		return protocolError(CodeWrongRoute, "credential belongs to another route")
	}
	if !credential.Role.Valid() {
		return protocolError(CodeUnauthorized, "credential role is invalid")
	}
	if !r.activeAt(nowMilliseconds) {
		return protocolError(CodeRouteExpired, "route is not active")
	}
	actual, err := AuthorizationDigest(credential.Token, r.RouteID, credential.Role)
	if err != nil {
		return protocolError(CodeUnauthorized, "credential token is invalid")
	}
	expected := r.CandidateAuthorizationDigest
	if credential.Role == RoleSponsor {
		expected = r.SponsorAuthorizationDigest
	}
	actualBytes, _ := hex.DecodeString(actual)
	expectedBytes, _ := hex.DecodeString(expected)
	if subtle.ConstantTimeCompare(actualBytes, expectedBytes) != 1 {
		return protocolError(CodeUnauthorized, "credential token is invalid")
	}
	return nil
}

func (r Registration) activeAt(nowMilliseconds int64) bool {
	earliestAcceptedTime := r.CreatedAtMilliseconds - MaximumCreationClockSkewMS
	if earliestAcceptedTime < 0 {
		earliestAcceptedTime = 0
	}
	return nowMilliseconds >= earliestAcceptedTime &&
		nowMilliseconds < r.ExpiresAtMilliseconds
}

type Envelope struct {
	Version               int       `json:"version"`
	Algorithm             string    `json:"algorithm"`
	RouteID               uuid.UUID `json:"routeID"`
	MessageID             uuid.UUID `json:"messageID"`
	CreatedAtMilliseconds int64     `json:"createdAtMilliseconds"`
	ExpiresAtMilliseconds int64     `json:"expiresAtMilliseconds"`
	Nonce                 string    `json:"nonce"`
	Ciphertext            string    `json:"ciphertext"`
	AuthenticationTag     string    `json:"authenticationTag"`
}

func (e Envelope) Validate() error {
	if e.Version != SchemaVersion || e.Algorithm != EnvelopeAlgorithm ||
		e.RouteID == uuid.Nil || e.MessageID == uuid.Nil ||
		e.CreatedAtMilliseconds < 0 ||
		e.ExpiresAtMilliseconds <= e.CreatedAtMilliseconds {
		return protocolError(CodeInvalidEnvelope, "envelope fields are invalid")
	}
	if !validBase64URLSize(e.Nonce, 12, 12) ||
		!validBase64URLSize(e.AuthenticationTag, 16, 16) ||
		!validBase64URLSize(e.Ciphertext, 1, MaximumCiphertextByteCount) {
		return protocolError(CodeInvalidEnvelope, "envelope binary fields are invalid")
	}
	return nil
}

func (e Envelope) ValidateForPublish(
	registration Registration,
	nowMilliseconds int64,
) error {
	if err := e.Validate(); err != nil {
		return err
	}
	if e.RouteID != registration.RouteID {
		return protocolError(CodeWrongRoute, "envelope belongs to another route")
	}
	if e.CreatedAtMilliseconds > nowMilliseconds ||
		e.ExpiresAtMilliseconds <= nowMilliseconds ||
		e.ExpiresAtMilliseconds > registration.ExpiresAtMilliseconds {
		return protocolError(CodeMessageExpired, "message is not active within the route")
	}
	return nil
}

type Entry struct {
	PublisherRole Role
	Envelope      Envelope
	Acknowledged  bool
}

type Acceptance string

const (
	AcceptanceAccepted  Acceptance = "accepted"
	AcceptanceDuplicate Acceptance = "duplicate"
)

func AuthorizationDigest(token string, routeID uuid.UUID, role Role) (string, error) {
	if routeID == uuid.Nil || !role.Valid() {
		return "", fmt.Errorf("invalid route or role")
	}
	tokenBytes, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(tokenBytes) != 32 ||
		base64.RawURLEncoding.EncodeToString(tokenBytes) != token {
		return "", fmt.Errorf("token must be 32-byte unpadded base64url")
	}
	material := make([]byte, 0, len(authorizationDomain)+36+1+len(role)+1+len(token))
	material = append(material, authorizationDomain...)
	material = append(material, strings.ToLower(routeID.String())...)
	material = append(material, 0)
	material = append(material, role...)
	material = append(material, 0)
	material = append(material, token...)
	digest := sha256.Sum256(material)
	return hex.EncodeToString(digest[:]), nil
}

func validDigest(value string) bool {
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
