package computepool

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"strings"

	"github.com/google/uuid"
)

const (
	spacePolicyDomain           = "Facets Space protection policy v1\x00"
	policyAcknowledgementDomain = "Facets Space protection acknowledgement v1\x00"
	workerCardDomain            = "Facets Compute Worker Card v1\x00"
)

type PrivacyClassificationBasis string

const (
	BasisModelDefault PrivacyClassificationBasis = "model_default"
	BasisUserAssigned PrivacyClassificationBasis = "user_assigned"
	BasisInherited    PrivacyClassificationBasis = "inherited"
	BasisSpacePolicy  PrivacyClassificationBasis = "space_policy"
)

func (value PrivacyClassificationBasis) Valid() bool {
	return value == BasisModelDefault || value == BasisUserAssigned || value == BasisInherited || value == BasisSpacePolicy
}

type ObjectPrivacyComponent struct {
	Identifier   string       `json:"id"`
	PrivacyClass PrivacyClass `json:"privacyClass"`
}

func (component ObjectPrivacyComponent) Validate() error {
	if !validIdentifier(component.Identifier) || !component.PrivacyClass.Valid() {
		return ErrInvalid
	}
	return nil
}

type ObjectPrivacyDescriptor struct {
	Version             int                        `json:"version"`
	ObjectID            FacetsObjectID             `json:"objectID"`
	ContentDigest       string                     `json:"contentDigest"`
	ModelTypeIdentifier string                     `json:"modelTypeIdentifier"`
	PrivacyClass        PrivacyClass               `json:"privacyClass"`
	Basis               PrivacyClassificationBasis `json:"basis"`
	Components          []ObjectPrivacyComponent   `json:"components"`
}

func (descriptor ObjectPrivacyDescriptor) Validate() error {
	if descriptor.Version != 1 || descriptor.ObjectID.Validate() != nil || !validSHA256Hex(descriptor.ContentDigest) ||
		!validIdentifier(descriptor.ModelTypeIdentifier) || !descriptor.PrivacyClass.Valid() ||
		!descriptor.Basis.Valid() || len(descriptor.Components) > maximumIdentifierCount {
		return ErrInvalid
	}
	previous := ""
	for _, component := range descriptor.Components {
		if component.Validate() != nil || component.Identifier <= previous {
			return ErrInvalid
		}
		previous = component.Identifier
	}
	return nil
}

type FacetsObjectID struct {
	ProviderRootURI string `json:"providerRootURI"`
	Kind            string `json:"kind"`
	SourceID        string `json:"sourceID"`
}

func (identifier FacetsObjectID) Validate() error {
	if identifier.ProviderRootURI == "" || identifier.Kind == "" || identifier.SourceID == "" ||
		strings.ContainsRune(identifier.ProviderRootURI, '\x00') || strings.ContainsRune(identifier.SourceID, '\x00') {
		return ErrInvalid
	}
	return nil
}

type SpaceUseCaseTemplate string

const (
	TemplatePersonalWorkspace        SpaceUseCaseTemplate = "personal_workspace"
	TemplateTrustedCircle            SpaceUseCaseTemplate = "trusted_circle"
	TemplateConfidentialRelationship SpaceUseCaseTemplate = "confidential_relationship"
	TemplatePublicCommunity          SpaceUseCaseTemplate = "public_community"
	TemplateCustom                   SpaceUseCaseTemplate = "custom"
)

func (value SpaceUseCaseTemplate) Valid() bool {
	return value == TemplatePersonalWorkspace || value == TemplateTrustedCircle ||
		value == TemplateConfidentialRelationship || value == TemplatePublicCommunity || value == TemplateCustom
}

type SpaceProtectionPosture string

const (
	PostureStandard      SpaceProtectionPosture = "standard"
	PosturePrivacyFirst  SpaceProtectionPosture = "privacy_first"
	PostureHighAssurance SpaceProtectionPosture = "high_assurance"
	PostureCustom        SpaceProtectionPosture = "custom"
)

func (value SpaceProtectionPosture) Valid() bool {
	return value == PostureStandard || value == PosturePrivacyFirst || value == PostureHighAssurance || value == PostureCustom
}

type SpaceSecurityProfile string

const (
	SecurityPrivate SpaceSecurityProfile = "private"
	SecuritySecure  SpaceSecurityProfile = "secure"
	SecurityManaged SpaceSecurityProfile = "managed"
)

func (value SpaceSecurityProfile) Valid() bool {
	return value == SecurityPrivate || value == SecuritySecure || value == SecurityManaged
}

type SpaceProtectionCommitments struct {
	Sharing                            PolicyControl `json:"sharing"`
	Computation                        PolicyControl `json:"computation"`
	ExternalAgents                     PolicyControl `json:"externalAgents"`
	LocalLLM                           PolicyControl `json:"localLLM"`
	PrivateInfrastructureLLM           PolicyControl `json:"privateInfrastructureLLM"`
	ExternalProviderLLM                PolicyControl `json:"externalProviderLLM"`
	ExportCopy                         PolicyControl `json:"exportCopy"`
	DisclosureOverrides                PolicyControl `json:"disclosureOverrides"`
	SharedBrowserHistoryEnabled        bool          `json:"sharedBrowserHistoryEnabled"`
	PrivateUserConfigurationsByDefault bool          `json:"privateUserConfigurationsByDefault"`
}

func (commitments SpaceProtectionCommitments) Validate() error {
	controls := []PolicyControl{commitments.Sharing, commitments.Computation, commitments.ExternalAgents,
		commitments.LocalLLM, commitments.PrivateInfrastructureLLM, commitments.ExternalProviderLLM,
		commitments.ExportCopy, commitments.DisclosureOverrides}
	for _, control := range controls {
		if !control.Valid() {
			return ErrInvalid
		}
	}
	return nil
}

type PrivacyClassRule struct {
	PrivacyClass             PrivacyClass  `json:"privacyClass"`
	PublicSharing            PolicyControl `json:"publicSharing"`
	ExternalProcessing       PolicyControl `json:"externalProcessing"`
	ExportCopy               PolicyControl `json:"exportCopy"`
	RememberedConsentAllowed bool          `json:"rememberedConsentAllowed"`
}

func (rule PrivacyClassRule) Validate() error {
	if !rule.PrivacyClass.Valid() || !rule.PublicSharing.Valid() || !rule.ExternalProcessing.Valid() ||
		!rule.ExportCopy.Valid() || rule.RememberedConsentAllowed &&
		(rule.PrivacyClass == PrivacyConfidential || rule.PrivacyClass == PrivacyRestricted) {
		return ErrInvalid
	}
	return nil
}

type SpaceProtectionPolicy struct {
	Version                    int                        `json:"version"`
	PolicyID                   uuid.UUID                  `json:"policyID"`
	SpaceID                    uuid.UUID                  `json:"spaceID"`
	SharedSpaceSecurityProfile *SpaceSecurityProfile      `json:"sharedSpaceSecurityProfile,omitempty"`
	Revision                   uint64                     `json:"revision"`
	PredecessorDigest          *string                    `json:"predecessorDigest,omitempty"`
	Rules                      []PrivacyClassRule         `json:"rules"`
	Commitments                SpaceProtectionCommitments `json:"commitments"`
	CreatedAtMilliseconds      int64                      `json:"createdAtMilliseconds"`
}

func (policy SpaceProtectionPolicy) Validate() error {
	if policy.Version != 1 || policy.PolicyID == uuid.Nil || policy.SpaceID == uuid.Nil || policy.Revision == 0 ||
		policy.SharedSpaceSecurityProfile != nil && !policy.SharedSpaceSecurityProfile.Valid() ||
		(policy.Revision == 1) != (policy.PredecessorDigest == nil) ||
		policy.PredecessorDigest != nil && !validSHA256Hex(*policy.PredecessorDigest) ||
		len(policy.Rules) != len(privacyClasses) || policy.Commitments.Validate() != nil || policy.CreatedAtMilliseconds < 0 {
		return ErrInvalid
	}
	for index, rule := range policy.Rules {
		if rule.Validate() != nil || rule.PrivacyClass != privacyClasses[index] {
			return ErrInvalid
		}
	}
	if policy.SharedSpaceSecurityProfile != nil && policy.Commitments.SharedBrowserHistoryEnabled {
		return ErrInvalid
	}
	return nil
}

func (policy SpaceProtectionPolicy) Digest() (string, error) { return canonicalDigest(policy) }

type ES256Signature struct {
	Algorithm             string    `json:"algorithm"`
	SignerID              uuid.UUID `json:"signerID"`
	PublicSigningKeyX963  string    `json:"publicSigningKeyX963"`
	SigningKeyFingerprint string    `json:"signingKeyFingerprint"`
	Signature             string    `json:"signature"`
}

type Ed25519Signature struct {
	Algorithm               string    `json:"algorithm"`
	SignerID                uuid.UUID `json:"signerID"`
	PublicSigningKeyEd25519 string    `json:"publicSigningKeyEd25519"`
	SigningKeyFingerprint   string    `json:"signingKeyFingerprint"`
	Signature               string    `json:"signature"`
}

func verifyES256(signature ES256Signature, payload any, domain string) error {
	keyBytes, keyError := decodeBase64URL(signature.PublicSigningKeyX963)
	signatureBytes, signatureError := decodeBase64URL(signature.Signature)
	x, y := elliptic.Unmarshal(elliptic.P256(), keyBytes)
	fingerprint := sha256.Sum256(keyBytes)
	encoded, encodeError := canonicalJSON(payload)
	if signature.Algorithm != "ES256" || signature.SignerID == uuid.Nil || keyError != nil ||
		signatureError != nil || len(signatureBytes) != 64 || x == nil || y == nil || encodeError != nil ||
		hex.EncodeToString(fingerprint[:]) != signature.SigningKeyFingerprint {
		return ErrInvalid
	}
	digest := sha256.Sum256(append([]byte(domain), encoded...))
	if !ecdsa.Verify(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, digest[:],
		newBigInt(signatureBytes[:32]), newBigInt(signatureBytes[32:])) {
		return ErrInvalid
	}
	return nil
}

func newBigInt(value []byte) *big.Int { return new(big.Int).SetBytes(value) }

func verifyEd25519(signature Ed25519Signature, payload any, domain string) error {
	keyBytes, keyError := decodeBase64URL(signature.PublicSigningKeyEd25519)
	signatureBytes, signatureError := decodeBase64URL(signature.Signature)
	fingerprint := sha256.Sum256(keyBytes)
	encoded, encodeError := canonicalJSON(payload)
	if signature.Algorithm != "Ed25519" || signature.SignerID == uuid.Nil || keyError != nil ||
		signatureError != nil || len(keyBytes) != ed25519.PublicKeySize || len(signatureBytes) != ed25519.SignatureSize ||
		encodeError != nil || hex.EncodeToString(fingerprint[:]) != signature.SigningKeyFingerprint ||
		!ed25519.Verify(ed25519.PublicKey(keyBytes), append([]byte(domain), encoded...), signatureBytes) {
		return ErrInvalid
	}
	return nil
}

type SignedSpaceProtectionPolicy struct {
	Policy    SpaceProtectionPolicy `json:"policy"`
	Signature ES256Signature        `json:"signature"`
}

func (signed SignedSpaceProtectionPolicy) Validate() error {
	if signed.Policy.Validate() != nil {
		return ErrInvalid
	}
	return verifyES256(signed.Signature, signed.Policy, spacePolicyDomain)
}

type PolicyAcknowledgement struct {
	Version                    int            `json:"version"`
	AcknowledgementID          uuid.UUID      `json:"acknowledgementID"`
	SpaceID                    uuid.UUID      `json:"spaceID"`
	PolicyID                   uuid.UUID      `json:"policyID"`
	PolicyRevision             uint64         `json:"policyRevision"`
	PolicyDigest               string         `json:"policyDigest"`
	ParticipantID              uuid.UUID      `json:"participantID"`
	AcknowledgedAtMilliseconds int64          `json:"acknowledgedAtMilliseconds"`
	Signature                  ES256Signature `json:"signature"`
}

func (ack PolicyAcknowledgement) signingPayload() any {
	return struct {
		Version                    int       `json:"version"`
		AcknowledgementID          uuid.UUID `json:"acknowledgementID"`
		SpaceID                    uuid.UUID `json:"spaceID"`
		PolicyID                   uuid.UUID `json:"policyID"`
		PolicyRevision             uint64    `json:"policyRevision"`
		PolicyDigest               string    `json:"policyDigest"`
		ParticipantID              uuid.UUID `json:"participantID"`
		AcknowledgedAtMilliseconds int64     `json:"acknowledgedAtMilliseconds"`
	}{ack.Version, ack.AcknowledgementID, ack.SpaceID, ack.PolicyID, ack.PolicyRevision, ack.PolicyDigest, ack.ParticipantID, ack.AcknowledgedAtMilliseconds}
}

func (ack PolicyAcknowledgement) Validate() error {
	if ack.Version != 1 || ack.AcknowledgementID == uuid.Nil || ack.SpaceID == uuid.Nil || ack.PolicyID == uuid.Nil ||
		ack.PolicyRevision == 0 || !validSHA256Hex(ack.PolicyDigest) || ack.ParticipantID == uuid.Nil ||
		ack.AcknowledgedAtMilliseconds < 0 || ack.Signature.SignerID != ack.ParticipantID {
		return ErrInvalid
	}
	return verifyES256(ack.Signature, ack.signingPayload(), policyAcknowledgementDomain)
}

type SignedWorkerCard struct {
	Card      WorkerCard       `json:"card"`
	Signature Ed25519Signature `json:"signature"`
}

func NewSignedWorkerCard(card WorkerCard, privateKey ed25519.PrivateKey) (SignedWorkerCard, error) {
	if card.Validate() != nil || len(privateKey) != ed25519.PrivateKeySize {
		return SignedWorkerCard{}, ErrInvalid
	}
	encoded, err := canonicalJSON(card)
	if err != nil {
		return SignedWorkerCard{}, ErrInvalid
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	fingerprint := sha256.Sum256(publicKey)
	return SignedWorkerCard{
		Card: card,
		Signature: Ed25519Signature{
			Algorithm: "Ed25519", SignerID: card.WorkerEnrollmentID,
			PublicSigningKeyEd25519: base64.RawURLEncoding.EncodeToString(publicKey),
			SigningKeyFingerprint:   hex.EncodeToString(fingerprint[:]),
			Signature:               base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, append([]byte(workerCardDomain), encoded...))),
		},
	}, nil
}

func (signed SignedWorkerCard) Validate(enrollment WorkerEnrollment) error {
	if signed.Card.Validate() != nil || enrollment.Validate() != nil || signed.Signature.SignerID != signed.Card.WorkerEnrollmentID ||
		enrollment.EnrollmentID != signed.Card.WorkerEnrollmentID || enrollment.PoolID != signed.Card.PoolID ||
		enrollment.WorkerOwnerAuthorityID != signed.Card.WorkerOwnerAuthorityID ||
		enrollment.PublicSigningKeyEd25519 != signed.Signature.PublicSigningKeyEd25519 ||
		enrollment.SigningKeyFingerprint != signed.Signature.SigningKeyFingerprint || !enrollment.Enabled {
		return ErrInvalid
	}
	return verifyEd25519(signed.Signature, signed.Card, workerCardDomain)
}

type TrustDisposition string

const (
	TrustDoNotUse          TrustDisposition = "do_not_use"
	TrustAskEveryTime      TrustDisposition = "ask_every_time"
	TrustAllowPublic       TrustDisposition = "allow_public"
	TrustAllowPersonal     TrustDisposition = "allow_personal"
	TrustAllowConfidential TrustDisposition = "allow_confidential"
	TrustAllowRestricted   TrustDisposition = "allow_restricted"
)

func (value TrustDisposition) Valid() bool {
	switch value {
	case TrustDoNotUse, TrustAskEveryTime, TrustAllowPublic, TrustAllowPersonal, TrustAllowConfidential, TrustAllowRestricted:
		return true
	}
	return false
}

type OperatorTrust string

const (
	OperatorNoAdditionalTrust      OperatorTrust = "no_additional_trust"
	OperatorAcceptClaimsAsDeclared OperatorTrust = "accept_claims_as_declared"
	OperatorPersonallyTrusted      OperatorTrust = "personally_trust_operator"
)

func (value OperatorTrust) Valid() bool {
	return value == OperatorNoAdditionalTrust || value == OperatorAcceptClaimsAsDeclared || value == OperatorPersonallyTrusted
}

type TrustPreference struct {
	Version                    int              `json:"version"`
	PoolID                     uuid.UUID        `json:"poolID"`
	WorkerCardID               uuid.UUID        `json:"workerCardID"`
	AcceptedWorkerCardRevision uint64           `json:"acceptedWorkerCardRevision"`
	AcceptedWorkerCardDigest   string           `json:"acceptedWorkerCardDigest"`
	Disposition                TrustDisposition `json:"disposition"`
	OperatorTrust              OperatorTrust    `json:"operatorTrust"`
	CreatedAtMilliseconds      int64            `json:"createdAtMilliseconds"`
	ExpiresAtMilliseconds      *int64           `json:"expiresAtMilliseconds,omitempty"`
}

func (preference TrustPreference) Validate() error {
	if preference.Version != 1 || preference.PoolID == uuid.Nil || preference.WorkerCardID == uuid.Nil ||
		preference.AcceptedWorkerCardRevision == 0 || !validSHA256Hex(preference.AcceptedWorkerCardDigest) ||
		!preference.Disposition.Valid() || !preference.OperatorTrust.Valid() || preference.CreatedAtMilliseconds < 0 ||
		preference.ExpiresAtMilliseconds != nil && *preference.ExpiresAtMilliseconds <= preference.CreatedAtMilliseconds {
		return ErrInvalid
	}
	return nil
}
