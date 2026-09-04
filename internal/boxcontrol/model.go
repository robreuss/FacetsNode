package boxcontrol

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"
)

const (
	SchemaVersion             = 1
	MinimumOwnerPasswordRunes = 15
	MaximumOwnerPasswordRunes = 128
	ConnectionRequestLifetime = 10 * time.Minute
	WebSessionIdleLifetime    = 30 * time.Minute
	WebSessionMaximumLifetime = 12 * time.Hour
	ConnectionGrantLifetime   = 180 * 24 * time.Hour
	MaximumRequestBytes       = 32 * 1024
	ApprovalCodeDigits        = 6
)

var (
	ErrNotInitialized     = errors.New("Facets Box is not initialized")
	ErrAlreadyInitialized = errors.New("Facets Box is already initialized")
	ErrAlreadyClaimed     = errors.New("Facets Box is already claimed")
	ErrInvalidCredential  = errors.New("credential rejected")
	ErrRequestExpired     = errors.New("connection request expired")
	ErrRequestReplay      = errors.New("connection request already completed")
)

type State struct {
	BoxID              uuid.UUID
	ActivationVerifier string
	OwnerVerifier      string
	DisplayName        string
	ClaimedAt          time.Time
}

func (state State) Claimed() bool { return state.OwnerVerifier != "" }

type ServiceDescriptor struct {
	Kind     string `json:"kind"`
	Endpoint string `json:"endpoint"`
}

type DeviceSyncGroup struct {
	SetDiscriminator string `json:"setDiscriminator"`
	DisplayName      string `json:"displayName"`
	Revision         uint64 `json:"revision"`
}

type PublicManifestPayload struct {
	Version     int                 `json:"version"`
	BoxID       uuid.UUID           `json:"boxID"`
	DisplayName string              `json:"displayName"`
	Claimed     bool                `json:"claimed"`
	PublicKey   string              `json:"publicKey"`
	Services    []ServiceDescriptor `json:"services"`
}

type SignedPublicManifest struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type ServiceAvailability string

const (
	ServiceAvailable     ServiceAvailability = "available"
	ServiceUnavailable   ServiceAvailability = "unavailable"
	ServiceNotConfigured ServiceAvailability = "not_configured"
)

type AuthenticatedService struct {
	Kind     string              `json:"kind"`
	Endpoint string              `json:"endpoint,omitempty"`
	Status   ServiceAvailability `json:"status"`
}

type AuthenticatedProfile struct {
	Version     int                    `json:"version"`
	BoxID       uuid.UUID              `json:"boxID"`
	DisplayName string                 `json:"displayName"`
	Services    []AuthenticatedService `json:"services"`
}

type ConnectionRequest struct {
	RequestID          uuid.UUID
	PollTokenDigest    [32]byte
	ApprovalCodeDigest [32]byte
	ClientPublicKey    [32]byte
	DeviceName         string
	CreatedAt          time.Time
	ExpiresAt          time.Time
	EncryptedResult    []byte
}

func (request ConnectionRequest) Validate(now time.Time) error {
	if request.RequestID == uuid.Nil || request.CreatedAt.IsZero() ||
		!request.ExpiresAt.After(request.CreatedAt) ||
		request.ExpiresAt.Sub(request.CreatedAt) > ConnectionRequestLifetime ||
		!request.ExpiresAt.After(now) {
		return ErrRequestExpired
	}
	deviceName := normalizedDisplayName(request.DeviceName)
	if deviceName == "" || deviceName != request.DeviceName || len(deviceName) > 256 {
		return errors.New("device name is invalid")
	}
	return nil
}

func NormalizeBoxDisplayName(value string) (string, error) {
	value = normalizedDisplayName(value)
	if value == "" || len(value) > 128 || strings.IndexFunc(value, func(value rune) bool {
		return unicode.IsControl(value) || value == '\x00'
	}) >= 0 {
		return "", errors.New("Box name is invalid")
	}
	return value, nil
}

func NormalizeApprovalCode(value string) (string, error) {
	value = strings.TrimSpace(value)
	if len(value) != ApprovalCodeDigits {
		return "", errors.New("connection code must contain six digits")
	}
	for _, digit := range []byte(value) {
		if digit < '0' || digit > '9' {
			return "", errors.New("connection code must contain six digits")
		}
	}
	return value, nil
}

func ApprovalCodeDigest(value string) ([32]byte, error) {
	value, err := NormalizeApprovalCode(value)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256([]byte("facets-box-connection-code-v1\x00" + value)), nil
}

type WebSession struct {
	TokenDigest [32]byte
	CSRFDigest  [32]byte
	CreatedAt   time.Time
	LastSeenAt  time.Time
	ExpiresAt   time.Time
}

type ConnectionGrant struct {
	GrantID     uuid.UUID
	TokenDigest [32]byte
	CreatedAt   time.Time
	ExpiresAt   time.Time
	LastSeenAt  time.Time
	RevokedAt   time.Time
	DeviceName  string
}

type AuditEvent struct {
	OccurredAt time.Time `json:"occurredAt"`
	Kind       string    `json:"kind"`
	Outcome    string    `json:"outcome"`
}

type LoginThrottle struct {
	Failures     int
	WindowStart  time.Time
	BlockedUntil time.Time
}

func normalizeOwnerPassword(value string) (string, error) {
	value = norm.NFC.String(value)
	count := utf8.RuneCountInString(value)
	if count < MinimumOwnerPasswordRunes || count > MaximumOwnerPasswordRunes {
		return "", fmt.Errorf("Box Owner password must contain %d to %d characters", MinimumOwnerPasswordRunes, MaximumOwnerPasswordRunes)
	}
	if strings.IndexFunc(value, func(value rune) bool {
		return unicode.IsControl(value) || value == '\x00'
	}) >= 0 {
		return "", errors.New("Box Owner password cannot contain control characters")
	}
	comparison := strings.ToLower(strings.Join(strings.Fields(value), " "))
	common := map[string]struct{}{
		"correct horse battery staple": {},
		"facets box password":          {},
		"password password password":   {},
		"this is my password":          {},
		"let me into facets box":       {},
	}
	if _, rejected := common[comparison]; rejected ||
		strings.Contains(comparison, "192.168.86.62") {
		return "", errors.New("Box Owner password is too common or specific to this Box")
	}
	return value, nil
}

type argonParameters struct {
	MemoryKiB uint32
	Time      uint32
	Threads   uint8
	SaltBytes uint32
	KeyBytes  uint32
}

var defaultArgonParameters = argonParameters{
	MemoryKiB: 64 * 1024,
	Time:      3,
	Threads:   1,
	SaltBytes: 16,
	KeyBytes:  32,
}

func hashSecret(value string, random io.Reader) (string, error) {
	if random == nil {
		random = rand.Reader
	}
	parameters := defaultArgonParameters
	salt := make([]byte, parameters.SaltBytes)
	if _, err := io.ReadFull(random, salt); err != nil {
		return "", err
	}
	key := argon2.IDKey(
		[]byte(value), salt, parameters.Time, parameters.MemoryKiB,
		parameters.Threads, parameters.KeyBytes,
	)
	return fmt.Sprintf(
		"$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		parameters.MemoryKiB,
		parameters.Time,
		parameters.Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

func HashActivationCode(value string) (string, error) {
	value = strings.TrimSpace(value)
	if len(value) < 12 || len(value) > 128 {
		return "", errors.New("activation code is invalid")
	}
	return hashSecret(value, rand.Reader)
}

func verifySecret(encoded, value string) bool {
	var memory, iterations uint32
	var threads uint8
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &threads); err != nil ||
		memory < 32*1024 || memory > 256*1024 || iterations < 1 || iterations > 10 || threads < 1 || threads > 8 {
		return false
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil || len(salt) < 16 || len(salt) > 64 {
		return false
	}
	expected, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil || len(expected) < 16 || len(expected) > 64 {
		return false
	}
	actual := argon2.IDKey([]byte(value), salt, iterations, memory, threads, uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func RandomToken(random io.Reader) (string, [32]byte, error) {
	if random == nil {
		random = rand.Reader
	}
	bytes := make([]byte, 32)
	if _, err := io.ReadFull(random, bytes); err != nil {
		return "", [32]byte{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(bytes)
	return token, sha256.Sum256(bytes), nil
}

func TokenDigest(token string) ([32]byte, error) {
	bytes, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(bytes) != 32 || base64.RawURLEncoding.EncodeToString(bytes) != token {
		return [32]byte{}, ErrInvalidCredential
	}
	return sha256.Sum256(bytes), nil
}

func ValidatePublicBaseURL(value string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("public Facets Box URL must be canonical HTTPS")
	}
	path := strings.TrimSuffix(parsed.EscapedPath(), "/")
	if path == "" || path == "/" || strings.Contains(strings.ToLower(path), "%2f") ||
		strings.Contains(strings.ToLower(path), "%5c") {
		return "", errors.New("public Facets Box URL requires a canonical base path")
	}
	parsed.Path = path
	parsed.RawPath = ""
	return strings.TrimSuffix(parsed.String(), "/"), nil
}

func ValidateServices(services []ServiceDescriptor) ([]ServiceDescriptor, error) {
	if len(services) == 0 || len(services) > 8 {
		return nil, errors.New("service catalog is empty or too large")
	}
	result := append([]ServiceDescriptor(nil), services...)
	slices.SortFunc(result, func(left, right ServiceDescriptor) int {
		return strings.Compare(left.Kind, right.Kind)
	})
	seen := map[string]struct{}{}
	for _, service := range result {
		if service.Kind == "" || len(service.Kind) > 64 {
			return nil, errors.New("service kind is invalid")
		}
		if _, present := seen[service.Kind]; present {
			return nil, errors.New("service kind is duplicated")
		}
		seen[service.Kind] = struct{}{}
		parsed, err := url.Parse(service.Endpoint)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
			parsed.RawQuery != "" || parsed.Fragment != "" {
			return nil, errors.New("service endpoint is invalid")
		}
	}
	return result, nil
}

func normalizedDisplayName(value string) string {
	return norm.NFC.String(strings.TrimSpace(value))
}
