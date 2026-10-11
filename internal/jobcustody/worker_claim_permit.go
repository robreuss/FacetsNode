package jobcustody

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/computequeue"
)

const (
	WorkerClaimPermitVersion                  = 1
	MaximumWorkerClaimPermitLifetimeMillisecs = int64(5 * 60 * 1000)
	workerClaimPermitSignatureDomain          = "Facets Job Custody Worker claim permit v1\x00"
	workerClaimPermitDigestDomain             = "facets.job-custody.worker-claim-permit.v1"
)

// WorkerClaimPermitPayload is issued by the same Box authority that admitted
// a protected capsule. The Box authenticates the current Worker owner device
// and exact advertised capability revision before signing. Job Custody can
// therefore match an opaque retained capsule to its intended Worker without
// learning Job semantics or treating a requester-supplied Worker UUID as
// authority.
//
// ClaimID is part of the signed payload. Replaying a permit can only reopen the
// same durable claim; it cannot acquire another assignment.
// Field declaration order is canonical sorted-key JSON.
type WorkerClaimPermitPayload struct {
	AuthorityID                  uuid.UUID              `json:"authorityID"`
	ClaimID                      uuid.UUID              `json:"claimID"`
	ExpiresAt                    computequeue.Timestamp `json:"expiresAt"`
	IssuedAt                     computequeue.Timestamp `json:"issuedAt"`
	PermitID                     uuid.UUID              `json:"permitID"`
	RouteRecipientKeyFingerprint computequeue.Digest    `json:"routeRecipientKeyFingerprint"`
	RouteRecipientWorkerID       computequeue.WorkerID  `json:"routeRecipientWorkerID"`
	Version                      int                    `json:"version"`
	WorkerCapabilitiesDigest     computequeue.Digest    `json:"workerCapabilitiesDigest"`
	WorkerOwnerAuthorityDigest   computequeue.Digest    `json:"workerOwnerAuthorityDigest"`
}

func (value WorkerClaimPermitPayload) Validate() error {
	if value.Version != WorkerClaimPermitVersion || value.AuthorityID == uuid.Nil ||
		value.ClaimID == uuid.Nil || value.PermitID == uuid.Nil ||
		value.RouteRecipientKeyFingerprint.Validate() != nil ||
		value.RouteRecipientWorkerID.Validate() != nil ||
		value.WorkerCapabilitiesDigest.Validate() != nil ||
		value.WorkerOwnerAuthorityDigest.Validate() != nil ||
		value.IssuedAt.Validate() != nil || value.ExpiresAt.Validate() != nil ||
		value.IssuedAt >= value.ExpiresAt ||
		int64(value.ExpiresAt-value.IssuedAt) > MaximumWorkerClaimPermitLifetimeMillisecs {
		return ErrAdmissionPermitAuthentication
	}
	return nil
}

type SignedWorkerClaimPermit struct {
	Payload   []byte                      `json:"payload"`
	Signature computequeue.SignatureValue `json:"signature"`
}

type WorkerClaimPermitSigner struct {
	authorityID uuid.UUID
	privateKey  ed25519.PrivateKey
}

func NewWorkerClaimPermitSigner(
	authorityID uuid.UUID,
	privateKey ed25519.PrivateKey,
) (*WorkerClaimPermitSigner, error) {
	if authorityID == uuid.Nil || len(privateKey) != ed25519.PrivateKeySize {
		return nil, ErrAdmissionPermitAuthentication
	}
	return &WorkerClaimPermitSigner{
		authorityID: authorityID,
		privateKey:  bytes.Clone(privateKey),
	}, nil
}

func (signer *WorkerClaimPermitSigner) Sign(
	payload WorkerClaimPermitPayload,
) (SignedWorkerClaimPermit, error) {
	if signer == nil || signer.authorityID == uuid.Nil ||
		len(signer.privateKey) != ed25519.PrivateKeySize || payload.Validate() != nil ||
		payload.AuthorityID != signer.authorityID {
		return SignedWorkerClaimPermit{}, ErrAdmissionPermitAuthentication
	}
	encoded, err := computequeue.EncodeCanonical(payload)
	if err != nil || len(encoded) > MaximumAdmissionPermitBytes {
		return SignedWorkerClaimPermit{}, ErrAdmissionPermitAuthentication
	}
	signature := ed25519.Sign(signer.privateKey, workerClaimPermitSigningBytes(encoded))
	return SignedWorkerClaimPermit{
		Payload:   encoded,
		Signature: computequeue.SignatureValue(base64.RawURLEncoding.EncodeToString(signature)),
	}, nil
}

// WorkerClaimAuthorization is verified runtime evidence. Its private fields
// prevent decoded HTTP input from becoming trusted Worker identity.
type WorkerClaimAuthorization struct {
	payload      WorkerClaimPermitPayload
	permitDigest computequeue.Digest
}

func (value WorkerClaimAuthorization) Payload() WorkerClaimPermitPayload {
	return value.payload
}

func (value WorkerClaimAuthorization) PermitDigest() computequeue.Digest {
	return value.permitDigest
}

func (value WorkerClaimAuthorization) MarshalJSON() ([]byte, error) {
	return nil, ErrAdmissionPermitAuthentication
}

func (value WorkerClaimAuthorization) String() string {
	return "verified-job-custody-worker-claim-authorization(redacted)"
}

func (value WorkerClaimAuthorization) GoString() string { return value.String() }

func (verifier *AdmissionPermitVerifier) VerifyWorkerClaim(
	permit SignedWorkerClaimPermit,
	now computequeue.Timestamp,
) (WorkerClaimAuthorization, error) {
	if verifier == nil || len(permit.Payload) == 0 ||
		len(permit.Payload) > MaximumAdmissionPermitBytes || now.Validate() != nil {
		return WorkerClaimAuthorization{}, ErrAdmissionPermitAuthentication
	}
	payload, err := computequeue.DecodeCanonical[WorkerClaimPermitPayload](permit.Payload)
	if err != nil || payload.Validate() != nil {
		return WorkerClaimAuthorization{}, ErrAdmissionPermitAuthentication
	}
	publicKey, trusted := verifier.keys[payload.AuthorityID]
	rawSignature, signatureErr := base64.RawURLEncoding.Strict().DecodeString(string(permit.Signature))
	if !trusted || signatureErr != nil || len(rawSignature) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(rawSignature) != string(permit.Signature) ||
		!ed25519.Verify(publicKey, workerClaimPermitSigningBytes(permit.Payload), rawSignature) ||
		now < payload.IssuedAt || now >= payload.ExpiresAt {
		return WorkerClaimAuthorization{}, ErrAdmissionPermitAuthentication
	}
	permitDigest, err := computequeue.ExactBytesDigest(
		workerClaimPermitDigestDomain,
		append(bytes.Clone(permit.Payload), rawSignature...),
		MaximumAdmissionPermitBytes+ed25519.SignatureSize,
	)
	if err != nil {
		return WorkerClaimAuthorization{}, ErrAdmissionPermitAuthentication
	}
	return WorkerClaimAuthorization{payload: payload, permitDigest: permitDigest}, nil
}

func workerClaimPermitSigningBytes(payload []byte) []byte {
	result := make([]byte, 0, len(workerClaimPermitSignatureDomain)+len(payload))
	result = append(result, workerClaimPermitSignatureDomain...)
	return append(result, payload...)
}
