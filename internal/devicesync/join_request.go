package devicesync

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/relay"
)

const (
	MinimumJoinRequestLifetimeMilliseconds = int64(5 * 60 * 1_000)
	MaximumJoinRequestLifetimeMilliseconds = int64(24 * 60 * 60 * 1_000)
	JoinRequestPINLength                   = 6
	MaximumBootstrapPublicKeyByteCount     = 512
	MaximumBootstrapCiphertextByteCount    = 1 << 20
)

var (
	joinRequestPINAuthorizationDomain     = []byte("Facets Device Sync join request PIN v1\x00")
	joinRequestPollingAuthorizationDomain = []byte("Facets Device Sync join request polling v1\x00")
)

// JoinRequest is an expiring, content-blind mailbox for beginning protected
// device enrollment. The PIN selects the request; it is not an authority or a
// content key. The server retains only PIN/polling digests and an opaque
// bootstrap ciphertext encrypted to CandidateBootstrapPublicKey.
type JoinRequest struct {
	Version                     int                    `json:"version"`
	RetryID                     uuid.UUID              `json:"retryID"`
	RequestID                   uuid.UUID              `json:"requestID"`
	CandidateDeviceID           uuid.UUID              `json:"candidateDeviceID"`
	CandidateBootstrapPublicKey string                 `json:"candidateBootstrapPublicKey"`
	PollingAuthorizationDigest  string                 `json:"-"`
	PINAuthorizationDigest      string                 `json:"-"`
	CreatedAtMilliseconds       int64                  `json:"createdAtMilliseconds"`
	ExpiresAtMilliseconds       int64                  `json:"expiresAtMilliseconds"`
	PrincipalID                 *uuid.UUID             `json:"principalID,omitempty"`
	Bootstrap                   *JoinBootstrapEnvelope `json:"bootstrap,omitempty"`
}

func (r JoinRequest) Validate() error {
	if r.Version != SchemaVersion || r.RetryID == uuid.Nil || r.RequestID == uuid.Nil ||
		r.CandidateDeviceID == uuid.Nil || !validUnpaddedBase64(r.CandidateBootstrapPublicKey, MaximumBootstrapPublicKeyByteCount) ||
		!validDigest(r.PollingAuthorizationDigest) || !validDigest(r.PINAuthorizationDigest) ||
		r.CreatedAtMilliseconds < 0 ||
		r.ExpiresAtMilliseconds-r.CreatedAtMilliseconds < MinimumJoinRequestLifetimeMilliseconds ||
		r.ExpiresAtMilliseconds-r.CreatedAtMilliseconds > MaximumJoinRequestLifetimeMilliseconds ||
		(r.PrincipalID == nil) != (r.Bootstrap == nil) {
		return NewProtocolError(CodeInvalidJoinRequest, "join request fields are invalid")
	}
	if r.PrincipalID != nil {
		if *r.PrincipalID == uuid.Nil || r.Bootstrap.RequestID != r.RequestID ||
			r.Bootstrap.ExpiresAtMilliseconds > r.ExpiresAtMilliseconds {
			return NewProtocolError(CodeInvalidJoinRequest, "join request bootstrap scope is invalid")
		}
		if err := r.Bootstrap.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (r JoinRequest) RequireActive(nowMilliseconds int64) error {
	if nowMilliseconds < r.CreatedAtMilliseconds || nowMilliseconds >= r.ExpiresAtMilliseconds {
		return NewProtocolError(CodeJoinRequestExpired, "join request is not active")
	}
	return nil
}

type JoinRequestCredential struct {
	RequestID uuid.UUID
	Token     string
}

func JoinRequestPollingAuthorizationDigest(credential JoinRequestCredential) (string, error) {
	if credential.RequestID == uuid.Nil {
		return "", fmt.Errorf("join request scope is invalid")
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(credential.Token)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != credential.Token {
		return "", fmt.Errorf("join request polling token must be 32-byte unpadded base64url")
	}
	return joinRequestAuthorizationDigest(joinRequestPollingAuthorizationDomain, credential.RequestID, credential.Token), nil
}

func JoinRequestPINAuthorizationDigest(pin string) (string, error) {
	if !validJoinRequestPIN(pin) {
		return "", fmt.Errorf("join request PIN must be six digits")
	}
	hash := sha256.New()
	_, _ = hash.Write(joinRequestPINAuthorizationDomain)
	_, _ = hash.Write([]byte(pin))
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func (r JoinRequest) VerifyPollingCredential(credential JoinRequestCredential) error {
	if credential.RequestID != r.RequestID {
		return NewProtocolError(CodeWrongScope, "join request credential has another scope")
	}
	digest, err := JoinRequestPollingAuthorizationDigest(credential)
	if err != nil || !digestEqual(digest, r.PollingAuthorizationDigest) {
		return NewProtocolError(CodeUnauthorized, "join request polling credential is invalid")
	}
	return nil
}

func (r JoinRequest) MatchesPIN(pin string) bool {
	digest, err := JoinRequestPINAuthorizationDigest(pin)
	return err == nil && digestEqual(digest, r.PINAuthorizationDigest)
}

func joinRequestAuthorizationDigest(domain []byte, requestID uuid.UUID, token string) string {
	hash := sha256.New()
	_, _ = hash.Write(domain)
	_, _ = hash.Write([]byte(requestID.String()))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(token))
	return hex.EncodeToString(hash.Sum(nil))
}

type JoinRequestCreateResult struct {
	Acceptance            relay.Acceptance `json:"acceptance"`
	RequestID             uuid.UUID        `json:"requestID"`
	ExpiresAtMilliseconds int64            `json:"expiresAtMilliseconds"`
}

// JoinRequestSponsorPresentation deliberately excludes both authorization
// digests and the encrypted bootstrap. Only an already authorized principal
// control-domain administrator who knows the displayed PIN may see it.
type JoinRequestSponsorPresentation struct {
	Version                     int       `json:"version"`
	RequestID                   uuid.UUID `json:"requestID"`
	CandidateDeviceID           uuid.UUID `json:"candidateDeviceID"`
	CandidateBootstrapPublicKey string    `json:"candidateBootstrapPublicKey"`
	ExpiresAtMilliseconds       int64     `json:"expiresAtMilliseconds"`
}

func sponsorPresentation(request JoinRequest) JoinRequestSponsorPresentation {
	return JoinRequestSponsorPresentation{
		Version: request.Version, RequestID: request.RequestID,
		CandidateDeviceID:           request.CandidateDeviceID,
		CandidateBootstrapPublicKey: request.CandidateBootstrapPublicKey,
		ExpiresAtMilliseconds:       request.ExpiresAtMilliseconds,
	}
}

// JoinBootstrapEnvelope is intentionally opaque to the server. Its payload is
// encrypted to the candidate-created public key and contains the existing
// protected pairing handoff, including the candidate route capability.
type JoinBootstrapEnvelope struct {
	Version               int       `json:"version"`
	RequestID             uuid.UUID `json:"requestID"`
	Algorithm             string    `json:"algorithm"`
	EphemeralPublicKey    string    `json:"ephemeralPublicKey"`
	Nonce                 string    `json:"nonce"`
	Ciphertext            string    `json:"ciphertext"`
	AuthenticationTag     string    `json:"authenticationTag"`
	CreatedAtMilliseconds int64     `json:"createdAtMilliseconds"`
	ExpiresAtMilliseconds int64     `json:"expiresAtMilliseconds"`
}

func (e JoinBootstrapEnvelope) Validate() error {
	if e.Version != SchemaVersion || e.RequestID == uuid.Nil || strings.TrimSpace(e.Algorithm) == "" ||
		len(e.Algorithm) > 128 || !validUnpaddedBase64(e.EphemeralPublicKey, MaximumBootstrapPublicKeyByteCount) ||
		!validUnpaddedBase64(e.Nonce, 64) || !validUnpaddedBase64(e.Ciphertext, MaximumBootstrapCiphertextByteCount) ||
		!validUnpaddedBase64(e.AuthenticationTag, 64) || e.CreatedAtMilliseconds < 0 ||
		e.ExpiresAtMilliseconds <= e.CreatedAtMilliseconds {
		return NewProtocolError(CodeInvalidJoinRequest, "join request bootstrap envelope is invalid")
	}
	return nil
}

func validJoinRequestPIN(pin string) bool {
	if len(pin) != JoinRequestPINLength {
		return false
	}
	for _, character := range pin {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func validUnpaddedBase64(value string, maximumBytes int) bool {
	if strings.TrimSpace(value) == "" || strings.ContainsAny(value, "= \t\r\n") {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(decoded) > 0 && len(decoded) <= maximumBytes &&
		base64.RawURLEncoding.EncodeToString(decoded) == value
}
