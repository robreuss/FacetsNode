package sharedspaces

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
)

const (
	ComputeCapabilityAlgorithm              = "Ed25519"
	MaximumComputeCapabilityLifetimeMillis  = int64(15 * 60 * 1_000)
	computeCapabilitySignatureDomain        = "Facets Shared Space Compute Capability v1\x00"
	maximumComputeCapabilityIssuerByteCount = 512
)

// ComputeCapabilityClaims is the complete, immutable authority a compute
// broker needs to admit one Space participant's work. Membership is evaluated
// only when these claims are issued; the broker never reads Shared Spaces
// membership storage.
type ComputeCapabilityClaims struct {
	Version                 int                    `json:"version"`
	CapabilityID            uuid.UUID              `json:"capabilityID"`
	Issuer                  string                 `json:"issuer"`
	KeyID                   string                 `json:"keyID"`
	SubjectParticipantID    uuid.UUID              `json:"subjectParticipantID"`
	SpaceID                 uuid.UUID              `json:"spaceID"`
	PoolID                  uuid.UUID              `json:"poolID"`
	Operation               string                 `json:"operation"`
	ResourceCeiling         ComputeResourceCeiling `json:"resourceCeiling"`
	PricingRevision         uint64                 `json:"pricingRevision"`
	DataSensitivityContract string                 `json:"dataSensitivityContract"`
	ProcessingContract      string                 `json:"processingContract"`
	BindingRevision         uint64                 `json:"bindingRevision"`
	KeyEpoch                uint64                 `json:"keyEpoch"`
	IssuedAtMilliseconds    int64                  `json:"issuedAtMilliseconds"`
	ExpiresAtMilliseconds   int64                  `json:"expiresAtMilliseconds"`
}

// ComputeCapabilityRequest is a participant-authenticated request for one
// narrowly scoped compute authority. RetryID becomes CapabilityID so retries
// are deterministic without requiring an issuance ledger.
type ComputeCapabilityRequest struct {
	Version                 int                    `json:"version"`
	RetryID                 uuid.UUID              `json:"retryID"`
	SpaceID                 uuid.UUID              `json:"spaceID"`
	PoolID                  uuid.UUID              `json:"poolID"`
	Operation               string                 `json:"operation"`
	ResourceRequest         ComputeResourceCeiling `json:"resourceRequest"`
	ExpectedBindingRevision uint64                 `json:"expectedBindingRevision"`
	ExpectedKeyEpoch        uint64                 `json:"expectedKeyEpoch"`
	IssuedAtMilliseconds    int64                  `json:"issuedAtMilliseconds"`
	ExpiresAtMilliseconds   int64                  `json:"expiresAtMilliseconds"`
}

func (r ComputeCapabilityRequest) Validate() error {
	if r.Version != SchemaVersion || r.RetryID == uuid.Nil || r.SpaceID == uuid.Nil ||
		r.PoolID == uuid.Nil || r.ExpectedBindingRevision == 0 || r.ExpectedKeyEpoch == 0 ||
		!validComputeOperation(r.Operation) || r.IssuedAtMilliseconds < 0 ||
		r.ExpiresAtMilliseconds <= r.IssuedAtMilliseconds ||
		r.ExpiresAtMilliseconds-r.IssuedAtMilliseconds > MaximumComputeCapabilityLifetimeMillis {
		return NewProtocolError(
			CodeInvalidComputeCapability,
			"Shared Space compute capability request is invalid",
		)
	}
	if err := r.ResourceRequest.Validate(); err != nil {
		return NewProtocolError(
			CodeInvalidComputeCapability,
			"Shared Space compute capability resource request is invalid",
		)
	}
	return nil
}

// ComputeCapabilityAuthorization is the policy result produced while the
// participant, pool, binding, and key epoch are read consistently. It is
// signed outside the authority store so compute brokers need no membership
// database access.
type ComputeCapabilityAuthorization struct {
	Version                 int                    `json:"version"`
	CapabilityID            uuid.UUID              `json:"capabilityID"`
	SubjectParticipantID    uuid.UUID              `json:"subjectParticipantID"`
	SpaceID                 uuid.UUID              `json:"spaceID"`
	PoolID                  uuid.UUID              `json:"poolID"`
	Operation               string                 `json:"operation"`
	ResourceCeiling         ComputeResourceCeiling `json:"resourceCeiling"`
	PricingRevision         uint64                 `json:"pricingRevision"`
	DataSensitivityContract string                 `json:"dataSensitivityContract"`
	ProcessingContract      string                 `json:"processingContract"`
	BindingRevision         uint64                 `json:"bindingRevision"`
	KeyEpoch                uint64                 `json:"keyEpoch"`
	IssuedAtMilliseconds    int64                  `json:"issuedAtMilliseconds"`
	ExpiresAtMilliseconds   int64                  `json:"expiresAtMilliseconds"`
}

func (a ComputeCapabilityAuthorization) Validate() error {
	claims := ComputeCapabilityClaims{
		Version: a.Version, CapabilityID: a.CapabilityID, Issuer: "authorization",
		KeyID:                base64.RawURLEncoding.EncodeToString(make([]byte, sha256.Size)),
		SubjectParticipantID: a.SubjectParticipantID, SpaceID: a.SpaceID, PoolID: a.PoolID,
		Operation: a.Operation, ResourceCeiling: a.ResourceCeiling,
		PricingRevision: a.PricingRevision, DataSensitivityContract: a.DataSensitivityContract,
		ProcessingContract: a.ProcessingContract, BindingRevision: a.BindingRevision,
		KeyEpoch: a.KeyEpoch, IssuedAtMilliseconds: a.IssuedAtMilliseconds,
		ExpiresAtMilliseconds: a.ExpiresAtMilliseconds,
	}
	return claims.Validate()
}

func (c ComputeCapabilityClaims) Validate() error {
	if c.Version != SchemaVersion || c.CapabilityID == uuid.Nil ||
		c.SubjectParticipantID == uuid.Nil || c.SpaceID == uuid.Nil ||
		c.PoolID == uuid.Nil || c.PricingRevision == 0 ||
		c.BindingRevision == 0 || c.KeyEpoch == 0 ||
		!validComputeIssuer(c.Issuer) || !validComputeKeyID(c.KeyID) ||
		!validComputeOperation(c.Operation) ||
		!validComputeContract(c.DataSensitivityContract) ||
		!validComputeContract(c.ProcessingContract) ||
		c.IssuedAtMilliseconds < 0 || c.ExpiresAtMilliseconds <= c.IssuedAtMilliseconds ||
		c.ExpiresAtMilliseconds-c.IssuedAtMilliseconds > MaximumComputeCapabilityLifetimeMillis {
		return NewProtocolError(
			CodeInvalidComputeCapability,
			"Shared Space compute capability claims are invalid",
		)
	}
	return c.ResourceCeiling.Validate()
}

// SignedComputeCapability is transport-safe and independently verifiable.
// JSON field order is fixed by ComputeCapabilityClaims; signatures always
// cover the canonical JSON encoding plus a protocol-specific domain prefix.
type SignedComputeCapability struct {
	Version   int                     `json:"version"`
	Algorithm string                  `json:"algorithm"`
	Claims    ComputeCapabilityClaims `json:"claims"`
	Signature string                  `json:"signature"`
}

func (c SignedComputeCapability) Validate() error {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(c.Signature)
	if c.Version != SchemaVersion || c.Algorithm != ComputeCapabilityAlgorithm ||
		err != nil || len(decoded) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(decoded) != c.Signature {
		return NewProtocolError(
			CodeInvalidComputeCapability,
			"signed Shared Space compute capability is invalid",
		)
	}
	return c.Claims.Validate()
}

// ComputeCapabilityVerificationKey is safe to publish to compute brokers.
type ComputeCapabilityVerificationKey struct {
	Version   int    `json:"version"`
	Issuer    string `json:"issuer"`
	KeyID     string `json:"keyID"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"publicKey"`
}

func (k ComputeCapabilityVerificationKey) Validate() error {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(k.PublicKey)
	if k.Version != SchemaVersion || k.Algorithm != ComputeCapabilityAlgorithm ||
		!validComputeIssuer(k.Issuer) || !validComputeKeyID(k.KeyID) ||
		err != nil || len(decoded) != ed25519.PublicKeySize ||
		base64.RawURLEncoding.EncodeToString(decoded) != k.PublicKey ||
		computeCapabilityKeyID(decoded) != k.KeyID {
		return NewProtocolError(
			CodeInvalidComputeCapability,
			"Shared Space compute capability verification key is invalid",
		)
	}
	return nil
}

type ComputeCapabilitySigner struct {
	issuer     string
	keyID      string
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

func NewComputeCapabilitySigner(seed []byte, issuer string) (*ComputeCapabilitySigner, error) {
	if len(seed) != ed25519.SeedSize || !validComputeIssuer(issuer) {
		return nil, NewProtocolError(
			CodeInvalidComputeCapability,
			"Shared Space compute capability signer configuration is invalid",
		)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := append(ed25519.PublicKey(nil), privateKey.Public().(ed25519.PublicKey)...)
	return &ComputeCapabilitySigner{
		issuer: issuer, keyID: computeCapabilityKeyID(publicKey),
		privateKey: privateKey, publicKey: publicKey,
	}, nil
}

func (s *ComputeCapabilitySigner) VerificationKey() ComputeCapabilityVerificationKey {
	return ComputeCapabilityVerificationKey{
		Version: SchemaVersion, Issuer: s.issuer, KeyID: s.keyID,
		Algorithm: ComputeCapabilityAlgorithm,
		PublicKey: base64.RawURLEncoding.EncodeToString(s.publicKey),
	}
}

func (s *ComputeCapabilitySigner) Sign(claims ComputeCapabilityClaims) (SignedComputeCapability, error) {
	if claims.Issuer != s.issuer || claims.KeyID != s.keyID {
		return SignedComputeCapability{}, NewProtocolError(
			CodeInvalidComputeCapability,
			"Shared Space compute capability claims use another signing authority",
		)
	}
	if err := claims.Validate(); err != nil {
		return SignedComputeCapability{}, err
	}
	payload, err := computeCapabilitySignaturePayload(claims)
	if err != nil {
		return SignedComputeCapability{}, err
	}
	return SignedComputeCapability{
		Version: SchemaVersion, Algorithm: ComputeCapabilityAlgorithm, Claims: claims,
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.privateKey, payload)),
	}, nil
}

func (s *ComputeCapabilitySigner) Issue(
	authorization ComputeCapabilityAuthorization,
) (SignedComputeCapability, error) {
	if err := authorization.Validate(); err != nil {
		return SignedComputeCapability{}, err
	}
	return s.Sign(ComputeCapabilityClaims{
		Version: authorization.Version, CapabilityID: authorization.CapabilityID,
		Issuer: s.issuer, KeyID: s.keyID,
		SubjectParticipantID: authorization.SubjectParticipantID,
		SpaceID:              authorization.SpaceID, PoolID: authorization.PoolID,
		Operation: authorization.Operation, ResourceCeiling: authorization.ResourceCeiling,
		PricingRevision:         authorization.PricingRevision,
		DataSensitivityContract: authorization.DataSensitivityContract,
		ProcessingContract:      authorization.ProcessingContract,
		BindingRevision:         authorization.BindingRevision, KeyEpoch: authorization.KeyEpoch,
		IssuedAtMilliseconds:  authorization.IssuedAtMilliseconds,
		ExpiresAtMilliseconds: authorization.ExpiresAtMilliseconds,
	})
}

type ComputeCapabilityVerifier struct {
	keys map[string]computeCapabilityVerifierKey
}

type computeCapabilityVerifierKey struct {
	issuer    string
	publicKey ed25519.PublicKey
}

func NewComputeCapabilityVerifier(keys ...ComputeCapabilityVerificationKey) (*ComputeCapabilityVerifier, error) {
	verifier := &ComputeCapabilityVerifier{keys: make(map[string]computeCapabilityVerifierKey, len(keys))}
	for _, key := range keys {
		if err := key.Validate(); err != nil {
			return nil, err
		}
		if _, found := verifier.keys[key.KeyID]; found {
			return nil, NewProtocolError(
				CodeInvalidComputeCapability,
				"Shared Space compute capability verification key ID is duplicated",
			)
		}
		decoded, _ := base64.RawURLEncoding.Strict().DecodeString(key.PublicKey)
		verifier.keys[key.KeyID] = computeCapabilityVerifierKey{
			issuer: key.Issuer, publicKey: ed25519.PublicKey(decoded),
		}
	}
	return verifier, nil
}

type ComputeCapabilityRequirement struct {
	Issuer               string
	SubjectParticipantID uuid.UUID
	SpaceID              uuid.UUID
	PoolID               uuid.UUID
	Operation            string
	ResourceRequest      ComputeResourceCeiling
	KeyEpoch             uint64
}

func (v *ComputeCapabilityVerifier) Verify(
	capability SignedComputeCapability,
	requirement ComputeCapabilityRequirement,
	nowMilliseconds int64,
) (ComputeCapabilityClaims, error) {
	if err := capability.Validate(); err != nil {
		return ComputeCapabilityClaims{}, err
	}
	key, found := v.keys[capability.Claims.KeyID]
	if !found || subtle.ConstantTimeCompare([]byte(key.issuer), []byte(capability.Claims.Issuer)) != 1 {
		return ComputeCapabilityClaims{}, NewProtocolError(
			CodeComputeCapabilityUnauthorized,
			"Shared Space compute capability signing authority is not trusted",
		)
	}
	payload, err := computeCapabilitySignaturePayload(capability.Claims)
	if err != nil {
		return ComputeCapabilityClaims{}, err
	}
	signature, _ := base64.RawURLEncoding.Strict().DecodeString(capability.Signature)
	if !ed25519.Verify(key.publicKey, payload, signature) {
		return ComputeCapabilityClaims{}, NewProtocolError(
			CodeComputeCapabilityUnauthorized,
			"Shared Space compute capability signature is invalid",
		)
	}
	claims := capability.Claims
	if nowMilliseconds < claims.IssuedAtMilliseconds || nowMilliseconds >= claims.ExpiresAtMilliseconds {
		return ComputeCapabilityClaims{}, NewProtocolError(
			CodeComputeCapabilityExpired,
			"Shared Space compute capability is not currently valid",
		)
	}
	if requirement.Issuer != "" && claims.Issuer != requirement.Issuer ||
		requirement.SubjectParticipantID != uuid.Nil && claims.SubjectParticipantID != requirement.SubjectParticipantID ||
		requirement.SpaceID != uuid.Nil && claims.SpaceID != requirement.SpaceID ||
		requirement.PoolID != uuid.Nil && claims.PoolID != requirement.PoolID ||
		requirement.Operation != "" && claims.Operation != requirement.Operation ||
		requirement.KeyEpoch != 0 && claims.KeyEpoch != requirement.KeyEpoch {
		return ComputeCapabilityClaims{}, NewProtocolError(
			CodeComputeCapabilityUnauthorized,
			"Shared Space compute capability scope does not authorize this request",
		)
	}
	if !computeResourceCeilingContains(claims.ResourceCeiling, requirement.ResourceRequest) {
		return ComputeCapabilityClaims{}, NewProtocolError(
			CodeComputeCapabilityUnauthorized,
			"Shared Space compute capability resource ceiling was exceeded",
		)
	}
	return claims, nil
}

func computeCapabilitySignaturePayload(claims ComputeCapabilityClaims) ([]byte, error) {
	encoded, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("encode Shared Space compute capability claims: %w", err)
	}
	return append([]byte(computeCapabilitySignatureDomain), encoded...), nil
}

func computeCapabilityKeyID(publicKey []byte) string {
	digest := sha256.Sum256(publicKey)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func validComputeKeyID(value string) bool {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(decoded) == sha256.Size &&
		base64.RawURLEncoding.EncodeToString(decoded) == value
}

func validComputeIssuer(value string) bool {
	trimmed := strings.TrimSpace(value)
	return trimmed == value && trimmed != "" && len(value) <= maximumComputeCapabilityIssuerByteCount
}

func validComputeOperation(value string) bool {
	return validComputeOperations([]string{value})
}

func computeResourceCeilingContains(ceiling, request ComputeResourceCeiling) bool {
	if request == (ComputeResourceCeiling{}) {
		return true
	}
	if request.Validate() != nil {
		return false
	}
	return request.MaximumInputBytes <= ceiling.MaximumInputBytes &&
		request.MaximumOutputBytes <= ceiling.MaximumOutputBytes &&
		request.MaximumMemoryBytes <= ceiling.MaximumMemoryBytes &&
		request.MaximumWallTimeMilliseconds <= ceiling.MaximumWallTimeMilliseconds
}

// AuthorizeComputeCapability evaluates the mutable Shared Space policy needed
// to issue an immutable capability. Callers must authenticate the participant
// credential and read pool, binding, and key epoch in one consistent snapshot
// before invoking this function.
func AuthorizeComputeCapability(
	request ComputeCapabilityRequest,
	participantID uuid.UUID,
	currentKeyEpoch uint64,
	pool ComputePool,
	binding SpaceComputeBinding,
	nowMilliseconds int64,
) (ComputeCapabilityAuthorization, error) {
	if err := request.Validate(); err != nil {
		return ComputeCapabilityAuthorization{}, err
	}
	if participantID == uuid.Nil || request.IssuedAtMilliseconds > nowMilliseconds ||
		nowMilliseconds >= request.ExpiresAtMilliseconds {
		return ComputeCapabilityAuthorization{}, NewProtocolError(
			CodeInvalidComputeCapability,
			"Shared Space compute capability request is not currently valid",
		)
	}
	if err := pool.Validate(); err != nil {
		return ComputeCapabilityAuthorization{}, err
	}
	if err := binding.Validate(); err != nil {
		return ComputeCapabilityAuthorization{}, err
	}
	if !pool.Enabled || pool.SpaceID != request.SpaceID || binding.SpaceID != request.SpaceID ||
		pool.PoolID != request.PoolID || binding.PoolID != request.PoolID ||
		binding.Revision != request.ExpectedBindingRevision ||
		currentKeyEpoch != request.ExpectedKeyEpoch {
		return ComputeCapabilityAuthorization{}, NewProtocolError(
			CodeComputeCapabilityUnauthorized,
			"Shared Space compute capability policy changed or is unavailable",
		)
	}
	operationIndex := sort.SearchStrings(binding.AllowedOperations, request.Operation)
	if operationIndex >= len(binding.AllowedOperations) ||
		binding.AllowedOperations[operationIndex] != request.Operation ||
		!computeResourceCeilingContains(binding.ResourceCeiling, request.ResourceRequest) {
		return ComputeCapabilityAuthorization{}, NewProtocolError(
			CodeComputeCapabilityUnauthorized,
			"Shared Space compute capability request exceeds its binding policy",
		)
	}
	return ComputeCapabilityAuthorization{
		Version: SchemaVersion, CapabilityID: request.RetryID,
		SubjectParticipantID: participantID, SpaceID: request.SpaceID, PoolID: request.PoolID,
		Operation: request.Operation, ResourceCeiling: request.ResourceRequest,
		PricingRevision:         binding.PricingRevision,
		DataSensitivityContract: binding.DataSensitivityContract,
		ProcessingContract:      binding.ProcessingContract,
		BindingRevision:         binding.Revision, KeyEpoch: currentKeyEpoch,
		IssuedAtMilliseconds:  request.IssuedAtMilliseconds,
		ExpiresAtMilliseconds: request.ExpiresAtMilliseconds,
	}, nil
}
