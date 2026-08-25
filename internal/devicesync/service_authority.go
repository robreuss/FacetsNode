package devicesync

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

// InitialServiceAuthorityBinding is a sealed, prevalidated value produced only
// from a complete InitialEnrollment and the local deployment signer. Its
// unexported representation prevents storage callers from binding a principal
// using only a self-consistent anchor and Manifest.
type InitialServiceAuthorityBinding struct {
	localDeploymentID    uuid.UUID
	manifest             serviceauthority.Manifest
	manifestDigest       string
	manifestRecord       []byte
	revision             uint64
	validatedAtMillis    int64
	offerIssuedAtMillis  int64
	offerExpiresAtMillis int64
}

const maximumInitialServiceAuthorityRecordByteCount = 1024 * 1024

func NewInitialServiceAuthorityBinding(
	enrollment serviceauthority.InitialEnrollment,
	localSigner *serviceauthority.DeploymentSigner,
	expectedScope serviceauthority.Scope,
	nowMilliseconds int64,
) (*InitialServiceAuthorityBinding, error) {
	if localSigner == nil || nowMilliseconds < 0 || expectedScope.Validate() != nil {
		return nil, serviceauthority.ErrInvalid
	}
	payload, err := enrollment.ValidateForAdmissionClaim(expectedScope)
	offer, offerErr := enrollment.DeploymentOffer.VerifiedPayload(nil)
	digest, digestErr := enrollment.Manifest.ReferenceDigest()
	record, recordErr := json.Marshal(enrollment.Manifest)
	if err != nil || offerErr != nil || digestErr != nil || recordErr != nil ||
		payload.Revision != 1 || payload.Revision > math.MaxInt64 ||
		payload.Transition != serviceauthority.TransitionInitialActivation ||
		payload.ActiveDeployment.DeploymentID != localSigner.DeploymentID() ||
		payload.ActiveDeployment.PublicSigningKeyX963 != localSigner.PublicSigningKeyX963() ||
		payload.ActiveDeployment.SigningKeyFingerprint != localSigner.SigningKeyFingerprint() ||
		len(record) == 0 || len(record) > maximumInitialServiceAuthorityRecordByteCount {
		return nil, serviceauthority.ErrInvalid
	}
	return &InitialServiceAuthorityBinding{
		localDeploymentID: localSigner.DeploymentID(),
		manifest: serviceauthority.Manifest{
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

func (binding *InitialServiceAuthorityBinding) Validate() error {
	if binding == nil || binding.localDeploymentID == uuid.Nil ||
		binding.revision != 1 || binding.revision > math.MaxInt64 ||
		binding.validatedAtMillis < 0 || binding.offerIssuedAtMillis < 0 ||
		binding.offerExpiresAtMillis <= binding.offerIssuedAtMillis ||
		len(binding.manifestRecord) == 0 ||
		len(binding.manifestRecord) > maximumInitialServiceAuthorityRecordByteCount {
		return serviceauthority.ErrInvalid
	}
	payload, err := binding.manifest.VerifiedPayload()
	digest, digestErr := binding.manifest.ReferenceDigest()
	record, recordErr := json.Marshal(binding.manifest)
	if err != nil || digestErr != nil || recordErr != nil ||
		payload.Scope.Kind != serviceauthority.ScopeDeviceSync ||
		payload.Revision != binding.revision ||
		payload.Transition != serviceauthority.TransitionInitialActivation ||
		payload.ActiveDeployment.DeploymentID != binding.localDeploymentID ||
		payload.Validate(nil) != nil ||
		digest != binding.manifestDigest ||
		!bytes.Equal(record, binding.manifestRecord) {
		return serviceauthority.ErrInvalid
	}
	return nil
}

// RequireFreshClaimAt applies the temporal checks that are required only when
// an admission has not yet been claimed. Exact retries compare the committed
// authority identity first and intentionally do not reapply offer or Manifest
// expiry.
func (binding *InitialServiceAuthorityBinding) RequireFreshClaimAt(
	nowMilliseconds int64,
) error {
	if binding.Validate() != nil || nowMilliseconds < binding.offerIssuedAtMillis ||
		nowMilliseconds >= binding.offerExpiresAtMillis {
		return serviceauthority.ErrInvalid
	}
	payload, err := binding.manifest.VerifiedPayload()
	if err != nil || payload.Validate(&nowMilliseconds) != nil {
		return serviceauthority.ErrInvalid
	}
	return nil
}

func (binding *InitialServiceAuthorityBinding) LocalDeploymentID() uuid.UUID {
	if binding == nil {
		return uuid.Nil
	}
	return binding.localDeploymentID
}

func (binding *InitialServiceAuthorityBinding) Manifest() serviceauthority.Manifest {
	if binding == nil {
		return serviceauthority.Manifest{}
	}
	return serviceauthority.Manifest{
		Payload:   append([]byte(nil), binding.manifest.Payload...),
		Signature: binding.manifest.Signature,
	}
}

func (binding *InitialServiceAuthorityBinding) Scope() serviceauthority.Scope {
	if binding == nil {
		return serviceauthority.Scope{}
	}
	payload, err := binding.manifest.VerifiedPayload()
	if err != nil {
		return serviceauthority.Scope{}
	}
	return payload.Scope
}

func (binding *InitialServiceAuthorityBinding) ManifestDigest() string {
	if binding == nil {
		return ""
	}
	return binding.manifestDigest
}

func (binding *InitialServiceAuthorityBinding) ManifestRecord() []byte {
	if binding == nil {
		return nil
	}
	return append([]byte(nil), binding.manifestRecord...)
}

func (binding *InitialServiceAuthorityBinding) Revision() uint64 {
	if binding == nil {
		return 0
	}
	return binding.revision
}

func (binding *InitialServiceAuthorityBinding) ValidatedAtMilliseconds() int64 {
	if binding == nil {
		return -1
	}
	return binding.validatedAtMillis
}

func InitialServiceAuthorityBindingsEqual(
	left *InitialServiceAuthorityBinding,
	right *InitialServiceAuthorityBinding,
) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.localDeploymentID == right.localDeploymentID &&
		left.revision == right.revision &&
		left.manifestDigest == right.manifestDigest &&
		bytes.Equal(left.manifestRecord, right.manifestRecord)
}

type AuthorityBoundAccountStore interface {
	ClaimAccountAdmissionWithAuthority(
		context.Context,
		AdmissionCredential,
		PrincipalProvisioning,
		*InitialServiceAuthorityBinding,
		int64,
	) (PrincipalProvisioningResult, error)
	ActivateBoundDeviceSyncScope(
		context.Context,
		uuid.UUID,
		uuid.UUID,
		uint64,
		string,
		int64,
	) error
}

var ErrInitialServiceAuthorityConflict = errors.New(
	"initial Device Sync service authority conflicts with committed authority",
)
