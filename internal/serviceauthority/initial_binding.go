package serviceauthority

import (
	"bytes"
	"encoding/json"
	"math"

	"github.com/google/uuid"
)

// InitialBinding is a sealed, prevalidated service-authority value produced
// only from a complete InitialEnrollment and the local deployment signer.
// Its unexported representation prevents service stores from accepting a
// merely self-consistent anchor and Manifest as deployment authority.
type InitialBinding struct {
	localDeploymentID    uuid.UUID
	manifest             Manifest
	manifestDigest       string
	manifestRecord       []byte
	revision             uint64
	validatedAtMillis    int64
	offerIssuedAtMillis  int64
	offerExpiresAtMillis int64
}

const maximumInitialBindingRecordByteCount = 1024 * 1024

func NewInitialBinding(
	enrollment InitialEnrollment,
	localSigner *DeploymentSigner,
	expectedScope Scope,
	nowMilliseconds int64,
) (*InitialBinding, error) {
	if localSigner == nil || nowMilliseconds < 0 || expectedScope.Validate() != nil {
		return nil, ErrInvalid
	}
	payload, err := enrollment.ValidateForAdmissionClaim(expectedScope)
	offer, offerErr := enrollment.DeploymentOffer.VerifiedPayload(nil)
	digest, digestErr := enrollment.Manifest.ReferenceDigest()
	record, recordErr := json.Marshal(enrollment.Manifest)
	if err != nil || offerErr != nil || digestErr != nil || recordErr != nil ||
		payload.Revision != 1 || payload.Revision > math.MaxInt64 ||
		payload.Transition != TransitionInitialActivation ||
		payload.ActiveDeployment.DeploymentID != localSigner.DeploymentID() ||
		payload.ActiveDeployment.PublicSigningKeyX963 != localSigner.PublicSigningKeyX963() ||
		payload.ActiveDeployment.SigningKeyFingerprint != localSigner.SigningKeyFingerprint() ||
		len(record) == 0 || len(record) > maximumInitialBindingRecordByteCount {
		return nil, ErrInvalid
	}
	return &InitialBinding{
		localDeploymentID: localSigner.DeploymentID(),
		manifest: Manifest{
			Payload:   append([]byte(nil), enrollment.Manifest.Payload...),
			Signature: enrollment.Manifest.Signature,
		},
		manifestDigest:       digest,
		manifestRecord:       append([]byte(nil), record...),
		revision:             payload.Revision,
		validatedAtMillis:    nowMilliseconds,
		offerIssuedAtMillis:  offer.IssuedAtMilliseconds,
		offerExpiresAtMillis: offer.ExpiresAtMilliseconds,
	}, nil
}

func (binding *InitialBinding) Validate() error {
	if binding == nil || binding.localDeploymentID == uuid.Nil ||
		binding.revision != 1 || binding.revision > math.MaxInt64 ||
		binding.validatedAtMillis < 0 || binding.offerIssuedAtMillis < 0 ||
		binding.offerExpiresAtMillis <= binding.offerIssuedAtMillis ||
		len(binding.manifestRecord) == 0 ||
		len(binding.manifestRecord) > maximumInitialBindingRecordByteCount {
		return ErrInvalid
	}
	payload, err := binding.manifest.VerifiedPayload()
	digest, digestErr := binding.manifest.ReferenceDigest()
	record, recordErr := json.Marshal(binding.manifest)
	if err != nil || digestErr != nil || recordErr != nil ||
		payload.Scope.Validate() != nil ||
		payload.Revision != binding.revision ||
		payload.Transition != TransitionInitialActivation ||
		payload.ActiveDeployment.DeploymentID != binding.localDeploymentID ||
		payload.Validate(nil) != nil ||
		digest != binding.manifestDigest ||
		!bytes.Equal(record, binding.manifestRecord) {
		return ErrInvalid
	}
	return nil
}

// RequireFreshClaimAt applies temporal checks only while a service admission
// remains unclaimed. Exact retries compare the already committed authority
// identity first and intentionally do not extend an offer or Manifest.
func (binding *InitialBinding) RequireFreshClaimAt(nowMilliseconds int64) error {
	if binding.Validate() != nil || nowMilliseconds < binding.offerIssuedAtMillis ||
		nowMilliseconds >= binding.offerExpiresAtMillis {
		return ErrInvalid
	}
	payload, err := binding.manifest.VerifiedPayload()
	if err != nil || payload.Validate(&nowMilliseconds) != nil {
		return ErrInvalid
	}
	return nil
}

func (binding *InitialBinding) LocalDeploymentID() uuid.UUID {
	if binding == nil {
		return uuid.Nil
	}
	return binding.localDeploymentID
}

func (binding *InitialBinding) Manifest() Manifest {
	if binding == nil {
		return Manifest{}
	}
	return Manifest{
		Payload:   append([]byte(nil), binding.manifest.Payload...),
		Signature: binding.manifest.Signature,
	}
}

func (binding *InitialBinding) Scope() Scope {
	if binding == nil {
		return Scope{}
	}
	payload, err := binding.manifest.VerifiedPayload()
	if err != nil {
		return Scope{}
	}
	return payload.Scope
}

func (binding *InitialBinding) ManifestDigest() string {
	if binding == nil {
		return ""
	}
	return binding.manifestDigest
}

func (binding *InitialBinding) ManifestRecord() []byte {
	if binding == nil {
		return nil
	}
	return append([]byte(nil), binding.manifestRecord...)
}

func (binding *InitialBinding) Revision() uint64 {
	if binding == nil {
		return 0
	}
	return binding.revision
}

func (binding *InitialBinding) ValidatedAtMilliseconds() int64 {
	if binding == nil {
		return -1
	}
	return binding.validatedAtMillis
}

func InitialBindingsEqual(left *InitialBinding, right *InitialBinding) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.localDeploymentID == right.localDeploymentID &&
		left.revision == right.revision &&
		left.manifestDigest == right.manifestDigest &&
		bytes.Equal(left.manifestRecord, right.manifestRecord)
}
