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
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/computepool"
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
	Version                    int                      `json:"version"`
	CapabilityID               uuid.UUID                `json:"capabilityID"`
	Issuer                     string                   `json:"issuer"`
	KeyID                      string                   `json:"keyID"`
	SubjectParticipantID       uuid.UUID                `json:"subjectParticipantID"`
	SpaceID                    uuid.UUID                `json:"spaceID"`
	BindingID                  uuid.UUID                `json:"bindingID"`
	PoolID                     uuid.UUID                `json:"poolID"`
	PoolAuthorityRevision      uint64                   `json:"poolAuthorityRevision"`
	PoolAuthorityDigest        string                   `json:"poolAuthorityDigest"`
	Operation                  string                   `json:"operation"`
	AllowedProviderIdentifiers []string                 `json:"allowedProviderIdentifiers"`
	ResourceCeiling            ComputeResourceCeiling   `json:"resourceCeiling"`
	PricingRevision            uint64                   `json:"pricingRevision"`
	DataSensitivityContract    string                   `json:"dataSensitivityContract"`
	ProcessingContract         string                   `json:"processingContract"`
	BudgetContract             string                   `json:"budgetContract"`
	ResultPolicy               computepool.ResultPolicy `json:"resultPolicy"`
	BindingRevision            uint64                   `json:"bindingRevision"`
	SourceAuthorityRevision    uint64                   `json:"sourceAuthorityRevision"`
	KeyEpoch                   uint64                   `json:"keyEpoch"`
	IssuedAtMilliseconds       int64                    `json:"issuedAtMilliseconds"`
	ExpiresAtMilliseconds      int64                    `json:"expiresAtMilliseconds"`
}

// ComputeCapabilityRequest is a participant-authenticated request for one
// narrowly scoped compute authority. RetryID becomes CapabilityID so retries
// are deterministic without requiring an issuance ledger.
type ComputeCapabilityRequest struct {
	Version                 int                    `json:"version"`
	RetryID                 uuid.UUID              `json:"retryID"`
	SpaceID                 uuid.UUID              `json:"spaceID"`
	BindingID               uuid.UUID              `json:"bindingID"`
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
		r.BindingID == uuid.Nil || r.PoolID == uuid.Nil ||
		r.ExpectedBindingRevision == 0 || r.ExpectedKeyEpoch == 0 ||
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
// participant, binding, and key epoch are read consistently. It is
// signed outside the authority store so compute brokers need no membership
// database access.
type ComputeCapabilityAuthorization struct {
	Version                    int                      `json:"version"`
	CapabilityID               uuid.UUID                `json:"capabilityID"`
	SubjectParticipantID       uuid.UUID                `json:"subjectParticipantID"`
	SpaceID                    uuid.UUID                `json:"spaceID"`
	BindingID                  uuid.UUID                `json:"bindingID"`
	PoolID                     uuid.UUID                `json:"poolID"`
	PoolAuthorityRevision      uint64                   `json:"poolAuthorityRevision"`
	PoolAuthorityDigest        string                   `json:"poolAuthorityDigest"`
	Operation                  string                   `json:"operation"`
	AllowedProviderIdentifiers []string                 `json:"allowedProviderIdentifiers"`
	ResourceCeiling            ComputeResourceCeiling   `json:"resourceCeiling"`
	PricingRevision            uint64                   `json:"pricingRevision"`
	DataSensitivityContract    string                   `json:"dataSensitivityContract"`
	ProcessingContract         string                   `json:"processingContract"`
	BudgetContract             string                   `json:"budgetContract"`
	ResultPolicy               computepool.ResultPolicy `json:"resultPolicy"`
	BindingRevision            uint64                   `json:"bindingRevision"`
	SourceAuthorityRevision    uint64                   `json:"sourceAuthorityRevision"`
	KeyEpoch                   uint64                   `json:"keyEpoch"`
	IssuedAtMilliseconds       int64                    `json:"issuedAtMilliseconds"`
	ExpiresAtMilliseconds      int64                    `json:"expiresAtMilliseconds"`
}

func (a ComputeCapabilityAuthorization) Validate() error {
	claims := ComputeCapabilityClaims{
		Version: a.Version, CapabilityID: a.CapabilityID, Issuer: "authorization",
		KeyID:                base64.RawURLEncoding.EncodeToString(make([]byte, sha256.Size)),
		SubjectParticipantID: a.SubjectParticipantID, SpaceID: a.SpaceID,
		BindingID: a.BindingID, PoolID: a.PoolID,
		PoolAuthorityRevision:      a.PoolAuthorityRevision,
		PoolAuthorityDigest:        a.PoolAuthorityDigest,
		Operation:                  a.Operation,
		AllowedProviderIdentifiers: append([]string(nil), a.AllowedProviderIdentifiers...),
		ResourceCeiling:            a.ResourceCeiling,
		PricingRevision:            a.PricingRevision, DataSensitivityContract: a.DataSensitivityContract,
		ProcessingContract: a.ProcessingContract, BudgetContract: a.BudgetContract,
		ResultPolicy: a.ResultPolicy, BindingRevision: a.BindingRevision,
		SourceAuthorityRevision: a.SourceAuthorityRevision, KeyEpoch: a.KeyEpoch,
		IssuedAtMilliseconds:  a.IssuedAtMilliseconds,
		ExpiresAtMilliseconds: a.ExpiresAtMilliseconds,
	}
	return claims.Validate()
}

func (c ComputeCapabilityClaims) Validate() error {
	if c.Version != SchemaVersion || c.CapabilityID == uuid.Nil ||
		c.SubjectParticipantID == uuid.Nil || c.SpaceID == uuid.Nil ||
		c.BindingID == uuid.Nil || c.PoolID == uuid.Nil ||
		c.PoolAuthorityRevision == 0 || !validFingerprint(c.PoolAuthorityDigest) ||
		c.PricingRevision == 0 || c.BindingRevision == 0 ||
		c.SourceAuthorityRevision == 0 || c.KeyEpoch == 0 ||
		!validComputeIssuer(c.Issuer) || !validComputeKeyID(c.KeyID) ||
		!validComputeOperation(c.Operation) ||
		!validComputeIdentifiers(c.AllowedProviderIdentifiers, false) ||
		!validComputeContract(c.DataSensitivityContract) ||
		!validComputeContract(c.ProcessingContract) ||
		!validComputeContract(c.BudgetContract) || !c.ResultPolicy.Valid() ||
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
		SpaceID:              authorization.SpaceID, BindingID: authorization.BindingID,
		PoolID:                authorization.PoolID,
		PoolAuthorityRevision: authorization.PoolAuthorityRevision,
		PoolAuthorityDigest:   authorization.PoolAuthorityDigest,
		Operation:             authorization.Operation,
		AllowedProviderIdentifiers: append(
			[]string(nil), authorization.AllowedProviderIdentifiers...,
		),
		ResourceCeiling:         authorization.ResourceCeiling,
		PricingRevision:         authorization.PricingRevision,
		DataSensitivityContract: authorization.DataSensitivityContract,
		ProcessingContract:      authorization.ProcessingContract,
		BudgetContract:          authorization.BudgetContract, ResultPolicy: authorization.ResultPolicy,
		BindingRevision:         authorization.BindingRevision,
		SourceAuthorityRevision: authorization.SourceAuthorityRevision,
		KeyEpoch:                authorization.KeyEpoch,
		IssuedAtMilliseconds:    authorization.IssuedAtMilliseconds,
		ExpiresAtMilliseconds:   authorization.ExpiresAtMilliseconds,
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
	Issuer                  string
	SubjectParticipantID    uuid.UUID
	SpaceID                 uuid.UUID
	BindingID               uuid.UUID
	PoolID                  uuid.UUID
	PoolAuthorityRevision   uint64
	PoolAuthorityDigest     string
	SourceAuthorityRevision uint64
	ProviderIdentifier      string
	Operation               string
	ResourceRequest         ComputeResourceCeiling
	KeyEpoch                uint64
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
		requirement.BindingID != uuid.Nil && claims.BindingID != requirement.BindingID ||
		requirement.PoolID != uuid.Nil && claims.PoolID != requirement.PoolID ||
		requirement.PoolAuthorityRevision != 0 && claims.PoolAuthorityRevision != requirement.PoolAuthorityRevision ||
		requirement.PoolAuthorityDigest != "" && claims.PoolAuthorityDigest != requirement.PoolAuthorityDigest ||
		requirement.SourceAuthorityRevision != 0 && claims.SourceAuthorityRevision != requirement.SourceAuthorityRevision ||
		requirement.Operation != "" && claims.Operation != requirement.Operation ||
		requirement.KeyEpoch != 0 && claims.KeyEpoch != requirement.KeyEpoch {
		return ComputeCapabilityClaims{}, NewProtocolError(
			CodeComputeCapabilityUnauthorized,
			"Shared Space compute capability scope does not authorize this request",
		)
	}
	if requirement.ProviderIdentifier != "" &&
		!sortedStringsContain(claims.AllowedProviderIdentifiers, requirement.ProviderIdentifier) {
		return ComputeCapabilityClaims{}, NewProtocolError(
			CodeComputeCapabilityUnauthorized,
			"Shared Space compute capability does not authorize this provider",
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
	return validComputeIdentifier(value)
}

func validComputeIdentifier(value string) bool {
	trimmed := strings.TrimSpace(value)
	return utf8.ValidString(value) && value == trimmed && value != "" && len(value) <= 256
}

func validComputeIdentifiers(values []string, optional bool) bool {
	if len(values) > 128 || !sort.StringsAreSorted(values) || !optional && len(values) == 0 {
		return false
	}
	previous := ""
	for _, value := range values {
		if !validComputeIdentifier(value) || value == previous {
			return false
		}
		previous = value
	}
	return true
}

func validComputeContract(value string) bool {
	trimmed := strings.TrimSpace(value)
	return utf8.ValidString(value) && value == trimmed && value != "" && len(value) <= 1_024
}

func sortedStringsContain(values []string, value string) bool {
	index := sort.SearchStrings(values, value)
	return index < len(values) && values[index] == value
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
// credential and read binding, role, and key epoch in one consistent snapshot
// before invoking this function.
func AuthorizeComputeCapability(
	request ComputeCapabilityRequest,
	participantID uuid.UUID,
	participantRole Role,
	currentKeyEpoch uint64,
	binding SpaceComputeBinding,
	nowMilliseconds int64,
) (ComputeCapabilityAuthorization, error) {
	if err := request.Validate(); err != nil {
		return ComputeCapabilityAuthorization{}, err
	}
	if participantID == uuid.Nil || !participantRole.Valid() ||
		request.IssuedAtMilliseconds > nowMilliseconds ||
		nowMilliseconds >= request.ExpiresAtMilliseconds {
		return ComputeCapabilityAuthorization{}, NewProtocolError(
			CodeInvalidComputeCapability,
			"Shared Space compute capability request is not currently valid",
		)
	}
	if err := binding.Validate(); err != nil {
		return ComputeCapabilityAuthorization{}, NewProtocolError(
			CodeInvalidComputeBinding, "Shared Space compute binding is invalid",
		)
	}
	if binding.SpaceID != request.SpaceID || binding.BindingID != request.BindingID ||
		binding.PoolAuthority.PoolID != request.PoolID ||
		binding.Revision != request.ExpectedBindingRevision ||
		binding.SourceAuthorityRevision != currentKeyEpoch ||
		currentKeyEpoch != request.ExpectedKeyEpoch {
		return ComputeCapabilityAuthorization{}, NewProtocolError(
			CodeComputeCapabilityUnauthorized,
			"Shared Space compute capability policy changed or is unavailable",
		)
	}
	if !bindingAllowsParticipant(binding, participantID, participantRole) ||
		!sortedStringsContain(binding.AllowedOperations, request.Operation) ||
		!computeResourceCeilingContains(binding.ResourceCeiling, request.ResourceRequest) {
		return ComputeCapabilityAuthorization{}, NewProtocolError(
			CodeComputeCapabilityUnauthorized,
			"Shared Space compute capability request exceeds its binding policy",
		)
	}
	return ComputeCapabilityAuthorization{
		Version: SchemaVersion, CapabilityID: request.RetryID,
		SubjectParticipantID: participantID, SpaceID: request.SpaceID,
		BindingID: request.BindingID, PoolID: request.PoolID,
		PoolAuthorityRevision: binding.PoolAuthority.AcceptedManifestRevision,
		PoolAuthorityDigest:   binding.PoolAuthority.AcceptedManifestDigest,
		Operation:             request.Operation,
		AllowedProviderIdentifiers: append(
			[]string(nil), binding.AllowedProviderIdentifiers...,
		),
		ResourceCeiling:         request.ResourceRequest,
		PricingRevision:         binding.PricingRevision,
		DataSensitivityContract: binding.DataSensitivityContract,
		ProcessingContract:      binding.ProcessingContract,
		BudgetContract:          binding.BudgetContract, ResultPolicy: binding.ResultPolicy,
		BindingRevision:         binding.Revision,
		SourceAuthorityRevision: binding.SourceAuthorityRevision,
		KeyEpoch:                currentKeyEpoch,
		IssuedAtMilliseconds:    request.IssuedAtMilliseconds,
		ExpiresAtMilliseconds:   request.ExpiresAtMilliseconds,
	}, nil
}

func bindingAllowsParticipant(
	binding SpaceComputeBinding,
	participantID uuid.UUID,
	participantRole Role,
) bool {
	participant := participantID.String()
	principalIndex := sort.Search(len(binding.EligiblePrincipalIDs), func(index int) bool {
		return binding.EligiblePrincipalIDs[index].String() >= participant
	})
	if principalIndex < len(binding.EligiblePrincipalIDs) &&
		binding.EligiblePrincipalIDs[principalIndex] == participantID {
		return true
	}
	return sortedStringsContain(binding.EligibleRoleIdentifiers, string(participantRole))
}
