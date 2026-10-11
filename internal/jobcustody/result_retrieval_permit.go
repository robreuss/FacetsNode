package jobcustody

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/computequeue"
)

const (
	ResultRetrievalPermitVersion         = 1
	resultRetrievalPermitSignatureDomain = "Facets Job Custody result retrieval permit v1\x00"
	resultRetrievalPermitDigestDomain    = "facets.job-custody.result-retrieval-permit.v1"
)

// ResultRetrievalPermitPayload is a short-lived Box assertion that the
// currently authenticated source device is the same authority that submitted
// one exact retained input capsule. The source needs only its input capsule
// and original admission-permit commitment; the Box does not learn result
// semantics or the result capsule identifier.
// Field declaration order is canonical sorted-key JSON.
type ResultRetrievalPermitPayload struct {
	AdmissionPermitDigest    computequeue.Digest       `json:"admissionPermitDigest"`
	AuthorityID              uuid.UUID                 `json:"authorityID"`
	ExpiresAt                computequeue.Timestamp    `json:"expiresAt"`
	InputCapsuleID           computequeue.JobCapsuleID `json:"inputCapsuleID"`
	IssuedAt                 computequeue.Timestamp    `json:"issuedAt"`
	PermitID                 uuid.UUID                 `json:"permitID"`
	RequesterAuthorityDigest computequeue.Digest       `json:"requesterAuthorityDigest"`
	Version                  int                       `json:"version"`
}

func (value ResultRetrievalPermitPayload) Validate() error {
	if value.Version != ResultRetrievalPermitVersion || value.AuthorityID == uuid.Nil ||
		value.PermitID == uuid.Nil || value.AdmissionPermitDigest.Validate() != nil ||
		value.InputCapsuleID.Validate() != nil || value.RequesterAuthorityDigest.Validate() != nil ||
		value.IssuedAt.Validate() != nil || value.ExpiresAt.Validate() != nil ||
		value.IssuedAt >= value.ExpiresAt ||
		int64(value.ExpiresAt-value.IssuedAt) > MaximumAdmissionPermitLifetimeMillisecs {
		return ErrAdmissionPermitAuthentication
	}
	return nil
}

type SignedResultRetrievalPermit struct {
	Payload   []byte                      `json:"payload"`
	Signature computequeue.SignatureValue `json:"signature"`
}

type ResultRetrievalPermitSigner struct {
	authorityID uuid.UUID
	privateKey  ed25519.PrivateKey
}

func NewResultRetrievalPermitSigner(
	authorityID uuid.UUID,
	privateKey ed25519.PrivateKey,
) (*ResultRetrievalPermitSigner, error) {
	if authorityID == uuid.Nil || len(privateKey) != ed25519.PrivateKeySize {
		return nil, ErrAdmissionPermitAuthentication
	}
	return &ResultRetrievalPermitSigner{
		authorityID: authorityID, privateKey: bytes.Clone(privateKey),
	}, nil
}

func (signer *ResultRetrievalPermitSigner) Sign(
	payload ResultRetrievalPermitPayload,
) (SignedResultRetrievalPermit, error) {
	if signer == nil || signer.authorityID == uuid.Nil ||
		len(signer.privateKey) != ed25519.PrivateKeySize || payload.Validate() != nil ||
		payload.AuthorityID != signer.authorityID {
		return SignedResultRetrievalPermit{}, ErrAdmissionPermitAuthentication
	}
	encoded, err := computequeue.EncodeCanonical(payload)
	if err != nil || len(encoded) > MaximumAdmissionPermitBytes {
		return SignedResultRetrievalPermit{}, ErrAdmissionPermitAuthentication
	}
	signature := ed25519.Sign(signer.privateKey, resultRetrievalPermitSigningBytes(encoded))
	return SignedResultRetrievalPermit{
		Payload:   encoded,
		Signature: computequeue.SignatureValue(base64.RawURLEncoding.EncodeToString(signature)),
	}, nil
}

type ResultRetrievalAuthorization struct {
	payload      ResultRetrievalPermitPayload
	permitDigest computequeue.Digest
}

func (value ResultRetrievalAuthorization) Payload() ResultRetrievalPermitPayload {
	return value.payload
}

func (value ResultRetrievalAuthorization) PermitDigest() computequeue.Digest {
	return value.permitDigest
}

func (value ResultRetrievalAuthorization) MarshalJSON() ([]byte, error) {
	return nil, ErrAdmissionPermitAuthentication
}

func (value ResultRetrievalAuthorization) String() string {
	return "verified-job-custody-result-retrieval-authorization(redacted)"
}

func (value ResultRetrievalAuthorization) GoString() string { return value.String() }

func (verifier *AdmissionPermitVerifier) VerifyResultRetrieval(
	permit SignedResultRetrievalPermit,
	now computequeue.Timestamp,
) (ResultRetrievalAuthorization, error) {
	if verifier == nil || len(permit.Payload) == 0 ||
		len(permit.Payload) > MaximumAdmissionPermitBytes || now.Validate() != nil {
		return ResultRetrievalAuthorization{}, ErrAdmissionPermitAuthentication
	}
	payload, err := computequeue.DecodeCanonical[ResultRetrievalPermitPayload](permit.Payload)
	if err != nil || payload.Validate() != nil {
		return ResultRetrievalAuthorization{}, ErrAdmissionPermitAuthentication
	}
	publicKey, trusted := verifier.keys[payload.AuthorityID]
	rawSignature, signatureErr := base64.RawURLEncoding.Strict().DecodeString(string(permit.Signature))
	if !trusted || signatureErr != nil || len(rawSignature) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(rawSignature) != string(permit.Signature) ||
		!ed25519.Verify(publicKey, resultRetrievalPermitSigningBytes(permit.Payload), rawSignature) ||
		now < payload.IssuedAt || now >= payload.ExpiresAt {
		return ResultRetrievalAuthorization{}, ErrAdmissionPermitAuthentication
	}
	permitDigest, err := computequeue.ExactBytesDigest(
		resultRetrievalPermitDigestDomain,
		append(bytes.Clone(permit.Payload), rawSignature...),
		MaximumAdmissionPermitBytes+ed25519.SignatureSize,
	)
	if err != nil {
		return ResultRetrievalAuthorization{}, ErrAdmissionPermitAuthentication
	}
	return ResultRetrievalAuthorization{payload: payload, permitDigest: permitDigest}, nil
}

func resultRetrievalPermitSigningBytes(payload []byte) []byte {
	result := make([]byte, 0, len(resultRetrievalPermitSignatureDomain)+len(payload))
	result = append(result, resultRetrievalPermitSignatureDomain...)
	return append(result, payload...)
}
