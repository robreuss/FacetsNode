package backupcustody

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

const (
	accountAdmissionAuthorizationDomain = "Facets backup custody account admission authorization v1\x00"
	targetCredentialAuthorizationDomain = "Facets backup custody target credential authorization v1\x00"
	bearerByteCount                     = 32
)

// AccountAdmissionCredential carries the bearer corresponding to the portable,
// non-secret admission reference. The bearer must never be persisted or logged.
type AccountAdmissionCredential struct {
	Reference AccountAdmissionReference
	bearer    string
}

// TargetCredential carries the bearer corresponding to one exact target
// reference. Portable requests contain only Reference.
type TargetCredential struct {
	Reference TargetCredentialReference
	bearer    string
}

func NewAccountAdmissionCredential(reference AccountAdmissionReference) (AccountAdmissionCredential, error) {
	if reference.Validate() != nil {
		return AccountAdmissionCredential{}, serviceauthority.ErrInvalid
	}
	bearer, err := randomBearer()
	if err != nil {
		return AccountAdmissionCredential{}, err
	}
	return AccountAdmissionCredential{Reference: reference, bearer: bearer}, nil
}

func NewTargetCredential(reference TargetCredentialReference) (TargetCredential, error) {
	if reference.Validate() != nil {
		return TargetCredential{}, serviceauthority.ErrInvalid
	}
	bearer, err := randomBearer()
	if err != nil {
		return TargetCredential{}, err
	}
	return TargetCredential{Reference: reference, bearer: bearer}, nil
}

func ParseAccountAdmissionCredential(reference AccountAdmissionReference, bearer string) (AccountAdmissionCredential, error) {
	credential := AccountAdmissionCredential{Reference: reference, bearer: bearer}
	if _, err := credential.AuthorizationDigest(); err != nil {
		return AccountAdmissionCredential{}, err
	}
	return credential, nil
}

func ParseTargetCredential(reference TargetCredentialReference, bearer string) (TargetCredential, error) {
	credential := TargetCredential{Reference: reference, bearer: bearer}
	if _, err := credential.AuthorizationDigest(); err != nil {
		return TargetCredential{}, err
	}
	return credential, nil
}

// TransportBearer is an explicit secret-release seam for a future TLS handler.
// Credential formatting and JSON encoding never expose it.
func (credential AccountAdmissionCredential) TransportBearer() string { return credential.bearer }
func (credential TargetCredential) TransportBearer() string           { return credential.bearer }

func (credential AccountAdmissionCredential) String() string {
	return "backup-account-admission-credential(redacted)"
}
func (credential AccountAdmissionCredential) GoString() string { return credential.String() }
func (credential TargetCredential) String() string             { return "backup-target-credential(redacted)" }
func (credential TargetCredential) GoString() string           { return credential.String() }

func (credential AccountAdmissionCredential) MarshalJSON() ([]byte, error) {
	return nil, serviceauthority.ErrInvalid
}

func (credential TargetCredential) MarshalJSON() ([]byte, error) {
	return nil, serviceauthority.ErrInvalid
}

func (credential AccountAdmissionCredential) AuthorizationDigest() (string, error) {
	if credential.Reference.Validate() != nil {
		return "", serviceauthority.ErrInvalid
	}
	return authorizationDigest(accountAdmissionAuthorizationDomain, credential.Reference, credential.bearer)
}

func (credential TargetCredential) AuthorizationDigest() (string, error) {
	if credential.Reference.Validate() != nil {
		return "", serviceauthority.ErrInvalid
	}
	return authorizationDigest(targetCredentialAuthorizationDomain, credential.Reference, credential.bearer)
}

func (credential AccountAdmissionCredential) Authorizes(reference AccountAdmissionReference, storedDigest string) bool {
	if reference.Validate() != nil || credential.Reference.Validate() != nil || credential.Reference != reference ||
		!validHexDigest(storedDigest) {
		return false
	}
	digest, err := credential.AuthorizationDigest()
	return err == nil && constantTimeHexEqual(digest, storedDigest)
}

func (credential TargetCredential) Authorizes(reference TargetCredentialReference, storedDigest string) bool {
	if reference.Validate() != nil || credential.Reference.Validate() != nil ||
		!targetReferencesEqual(credential.Reference, reference) || !validHexDigest(storedDigest) {
		return false
	}
	digest, err := credential.AuthorizationDigest()
	return err == nil && constantTimeHexEqual(digest, storedDigest)
}

func authorizationDigest(domain string, reference any, bearer string) (string, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(bearer)
	if err != nil || len(decoded) != bearerByteCount || base64.RawURLEncoding.EncodeToString(decoded) != bearer {
		return "", serviceauthority.ErrInvalid
	}
	encoded, err := json.Marshal(reference)
	if err != nil {
		return "", serviceauthority.ErrInvalid
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(domain))
	_, _ = digest.Write(encoded)
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write(decoded)
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func randomBearer() (string, error) {
	value := make([]byte, bearerByteCount)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func constantTimeHexEqual(left, right string) bool {
	leftBytes, leftErr := hex.DecodeString(left)
	rightBytes, rightErr := hex.DecodeString(right)
	return leftErr == nil && rightErr == nil && len(leftBytes) == sha256.Size &&
		len(rightBytes) == sha256.Size && subtle.ConstantTimeCompare(leftBytes, rightBytes) == 1
}

func targetReferencesEqual(left, right TargetCredentialReference) bool {
	if left.AccountID != right.AccountID || left.BackupSetID != right.BackupSetID ||
		left.CredentialID != right.CredentialID || left.ExpiresAtMilliseconds != right.ExpiresAtMilliseconds ||
		left.RequestNonce != right.RequestNonce || left.TargetID != right.TargetID || left.Version != right.Version ||
		len(left.Capabilities) != len(right.Capabilities) {
		return false
	}
	for index := range left.Capabilities {
		if left.Capabilities[index] != right.Capabilities[index] {
			return false
		}
	}
	return true
}

func canonicalRequest(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) == 0 || len(encoded) > MaximumRequestByteCount {
		return nil, serviceauthority.ErrInvalid
	}
	return encoded, nil
}

var _ fmt.Stringer = AccountAdmissionCredential{}
var _ fmt.GoStringer = AccountAdmissionCredential{}
var _ fmt.Stringer = TargetCredential{}
var _ fmt.GoStringer = TargetCredential{}

func nonzeroUUID(value uuid.UUID) bool { return value != uuid.Nil }
