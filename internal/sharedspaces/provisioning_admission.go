package sharedspaces

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/relay"
)

const (
	MinimumProvisioningAdmissionLifetimeMilliseconds = int64(5 * 60 * 1_000)
	MaximumProvisioningAdmissionLifetimeMilliseconds = int64(7 * 24 * 60 * 60 * 1_000)
)

var provisioningAdmissionAuthorizationDomain = []byte(
	"Facets Shared Space provisioning admission v1\x00",
)

type ProvisioningAdmissionCredential struct {
	AdmissionID uuid.UUID
	Token       string
}

func ProvisioningAdmissionAuthorizationDigest(
	credential ProvisioningAdmissionCredential,
) (string, error) {
	if credential.AdmissionID == uuid.Nil {
		return "", fmt.Errorf("Shared Space provisioning admission scope is invalid")
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(credential.Token)
	if err != nil || len(decoded) != 32 ||
		base64.RawURLEncoding.EncodeToString(decoded) != credential.Token {
		return "", fmt.Errorf("Shared Space provisioning admission token must be 32-byte unpadded base64url")
	}
	digest := sha256.New()
	_, _ = digest.Write(provisioningAdmissionAuthorizationDomain)
	_, _ = digest.Write([]byte(credential.AdmissionID.String()))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(credential.Token))
	return hex.EncodeToString(digest.Sum(nil)), nil
}

type ProvisioningAdmission struct {
	Version               int        `json:"version"`
	RetryID               uuid.UUID  `json:"retryID"`
	AdmissionID           uuid.UUID  `json:"admissionID"`
	AuthorizationDigest   string     `json:"authorizationDigest"`
	CreatedAtMilliseconds int64      `json:"createdAtMilliseconds"`
	ExpiresAtMilliseconds int64      `json:"expiresAtMilliseconds"`
	ClaimedAtMilliseconds *int64     `json:"claimedAtMilliseconds,omitempty"`
	ClaimedSpaceID        *uuid.UUID `json:"claimedSpaceID,omitempty"`
	ClaimedRequestDigest  *string    `json:"claimedRequestDigest,omitempty"`
}

func (admission ProvisioningAdmission) Validate() error {
	if admission.Version != SchemaVersion || admission.RetryID == uuid.Nil ||
		admission.AdmissionID == uuid.Nil || !validFingerprint(admission.AuthorizationDigest) ||
		admission.CreatedAtMilliseconds < 0 ||
		admission.ExpiresAtMilliseconds-admission.CreatedAtMilliseconds <
			MinimumProvisioningAdmissionLifetimeMilliseconds ||
		admission.ExpiresAtMilliseconds-admission.CreatedAtMilliseconds >
			MaximumProvisioningAdmissionLifetimeMilliseconds {
		return NewProtocolError(
			CodeInvalidProvisioningAdmission,
			"Shared Space provisioning admission fields are invalid",
		)
	}
	claimedValues := 0
	if admission.ClaimedAtMilliseconds != nil {
		claimedValues++
	}
	if admission.ClaimedSpaceID != nil {
		claimedValues++
	}
	if admission.ClaimedRequestDigest != nil {
		claimedValues++
	}
	if claimedValues != 0 && claimedValues != 3 {
		return NewProtocolError(
			CodeInvalidProvisioningAdmission,
			"Shared Space provisioning admission claim state is incomplete",
		)
	}
	if claimedValues == 3 &&
		(*admission.ClaimedAtMilliseconds < admission.CreatedAtMilliseconds ||
			*admission.ClaimedAtMilliseconds >= admission.ExpiresAtMilliseconds ||
			*admission.ClaimedSpaceID == uuid.Nil ||
			!validFingerprint(*admission.ClaimedRequestDigest)) {
		return NewProtocolError(
			CodeInvalidProvisioningAdmission,
			"Shared Space provisioning admission claim state is invalid",
		)
	}
	return nil
}

// SameIssuance compares only operator-authored immutable admission fields.
// Claim state is server-authored after issuance and must not turn an exact
// operator retry into a collision.
func (admission ProvisioningAdmission) SameIssuance(
	other ProvisioningAdmission,
) bool {
	return admission.Version == other.Version &&
		admission.RetryID == other.RetryID &&
		admission.AdmissionID == other.AdmissionID &&
		admission.AuthorizationDigest == other.AuthorizationDigest &&
		admission.CreatedAtMilliseconds == other.CreatedAtMilliseconds &&
		admission.ExpiresAtMilliseconds == other.ExpiresAtMilliseconds
}

func (admission ProvisioningAdmission) VerifyCredential(
	credential ProvisioningAdmissionCredential,
) error {
	if credential.AdmissionID != admission.AdmissionID {
		return NewProtocolError(
			CodeWrongScope,
			"Shared Space provisioning admission credential has another scope",
		)
	}
	digest, err := ProvisioningAdmissionAuthorizationDigest(credential)
	if err != nil || subtle.ConstantTimeCompare(
		[]byte(digest), []byte(admission.AuthorizationDigest),
	) != 1 {
		return NewProtocolError(
			CodeUnauthorized,
			"Shared Space provisioning admission credential is invalid",
		)
	}
	return nil
}

func (admission ProvisioningAdmission) RequireActive(
	nowMilliseconds int64,
) error {
	if admission.ClaimedAtMilliseconds != nil {
		return NewProtocolError(
			CodeProvisioningAdmissionClaimed,
			"Shared Space provisioning admission was already claimed",
		)
	}
	if nowMilliseconds < admission.CreatedAtMilliseconds ||
		nowMilliseconds >= admission.ExpiresAtMilliseconds {
		return NewProtocolError(
			CodeProvisioningAdmissionExpired,
			"Shared Space provisioning admission is not active",
		)
	}
	return nil
}

type ProvisioningAdmissionClaim struct {
	Version               int       `json:"version"`
	SpaceID               uuid.UUID `json:"spaceID"`
	RequestDigest         string    `json:"requestDigest"`
	ClaimedAtMilliseconds int64     `json:"claimedAtMilliseconds"`
}

func (claim ProvisioningAdmissionClaim) Validate() error {
	if claim.Version != SchemaVersion || claim.SpaceID == uuid.Nil ||
		!validFingerprint(claim.RequestDigest) || claim.ClaimedAtMilliseconds < 0 {
		return NewProtocolError(
			CodeInvalidProvisioningAdmission,
			"Shared Space provisioning admission claim is invalid",
		)
	}
	return nil
}

type ProvisioningAdmissionCreateResult struct {
	Acceptance relay.Acceptance      `json:"acceptance"`
	Admission  ProvisioningAdmission `json:"admission"`
}

type ProvisioningAdmissionClaimResult struct {
	Acceptance            relay.Acceptance `json:"acceptance"`
	AdmissionID           uuid.UUID        `json:"admissionID"`
	SpaceID               uuid.UUID        `json:"spaceID"`
	RequestDigest         string           `json:"requestDigest"`
	ClaimedAtMilliseconds int64            `json:"claimedAtMilliseconds"`
}
