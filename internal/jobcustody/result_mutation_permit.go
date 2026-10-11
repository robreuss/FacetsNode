package jobcustody

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/computequeue"
)

const (
	ResultMutationPermitVersion         = 1
	resultMutationPermitSignatureDomain = "Facets Job Custody result mutation permit v1\x00"
	resultMutationPermitDigestDomain    = "facets.job-custody.result-mutation-permit.v1"
)

type ResultMutationAction string

const (
	ResultMutationAcknowledgeDelivery ResultMutationAction = "acknowledgeDelivery"
	ResultMutationReleaseCustody      ResultMutationAction = "releaseCustody"
)

func (value ResultMutationAction) valid() bool {
	return value == ResultMutationAcknowledgeDelivery || value == ResultMutationReleaseCustody
}

// Validate reports whether value names one of the two source-authorized result
// lifecycle transitions. It is intentionally independent of a complete permit
// so the Box can validate the signed request before it derives the enrolled
// source authority digest.
func (value ResultMutationAction) Validate() error {
	if !value.valid() {
		return ErrAdmissionPermitAuthentication
	}
	return nil
}

// ResultMutationPermitPayload is a short-lived Box assertion that the
// currently authenticated original source device requested one exact
// content-blind delivery or release transition. SourceTransitionReceiptDigest
// commits to the source-owned signed lifecycle receipt without exposing it to
// Job Custody as semantic authority.
// Field declaration order is canonical sorted-key JSON.
type ResultMutationPermitPayload struct {
	Action                        ResultMutationAction      `json:"action"`
	AdmissionPermitDigest         computequeue.Digest       `json:"admissionPermitDigest"`
	AuthorityID                   uuid.UUID                 `json:"authorityID"`
	ExpiresAt                     computequeue.Timestamp    `json:"expiresAt"`
	InputCapsuleID                computequeue.JobCapsuleID `json:"inputCapsuleID"`
	IssuedAt                      computequeue.Timestamp    `json:"issuedAt"`
	PermitID                      uuid.UUID                 `json:"permitID"`
	RequesterAuthorityDigest      computequeue.Digest       `json:"requesterAuthorityDigest"`
	ResultCapsuleID               computequeue.JobCapsuleID `json:"resultCapsuleID"`
	ResultCustodyReceiptDigest    computequeue.Digest       `json:"resultCustodyReceiptDigest"`
	ResultSetDigest               computequeue.Digest       `json:"resultSetDigest"`
	SourceTransitionReceiptDigest computequeue.Digest       `json:"sourceTransitionReceiptDigest"`
	Version                       int                       `json:"version"`
}

func (value ResultMutationPermitPayload) Validate() error {
	if value.Version != ResultMutationPermitVersion || value.Action.Validate() != nil ||
		value.AuthorityID == uuid.Nil || value.PermitID == uuid.Nil ||
		value.AdmissionPermitDigest.Validate() != nil || value.InputCapsuleID.Validate() != nil ||
		value.RequesterAuthorityDigest.Validate() != nil || value.ResultCapsuleID.Validate() != nil ||
		value.InputCapsuleID == value.ResultCapsuleID ||
		value.ResultCustodyReceiptDigest.Validate() != nil || value.ResultSetDigest.Validate() != nil ||
		value.SourceTransitionReceiptDigest.Validate() != nil ||
		value.IssuedAt.Validate() != nil || value.ExpiresAt.Validate() != nil ||
		value.IssuedAt >= value.ExpiresAt ||
		int64(value.ExpiresAt-value.IssuedAt) > MaximumAdmissionPermitLifetimeMillisecs {
		return ErrAdmissionPermitAuthentication
	}
	return nil
}

type SignedResultMutationPermit struct {
	Payload   []byte                      `json:"payload"`
	Signature computequeue.SignatureValue `json:"signature"`
}

type ResultMutationPermitSigner struct {
	authorityID uuid.UUID
	privateKey  ed25519.PrivateKey
}

func NewResultMutationPermitSigner(
	authorityID uuid.UUID,
	privateKey ed25519.PrivateKey,
) (*ResultMutationPermitSigner, error) {
	if authorityID == uuid.Nil || len(privateKey) != ed25519.PrivateKeySize {
		return nil, ErrAdmissionPermitAuthentication
	}
	return &ResultMutationPermitSigner{
		authorityID: authorityID, privateKey: bytes.Clone(privateKey),
	}, nil
}

func (signer *ResultMutationPermitSigner) Sign(
	payload ResultMutationPermitPayload,
) (SignedResultMutationPermit, error) {
	if signer == nil || signer.authorityID == uuid.Nil ||
		len(signer.privateKey) != ed25519.PrivateKeySize || payload.Validate() != nil ||
		payload.AuthorityID != signer.authorityID {
		return SignedResultMutationPermit{}, ErrAdmissionPermitAuthentication
	}
	encoded, err := computequeue.EncodeCanonical(payload)
	if err != nil || len(encoded) > MaximumAdmissionPermitBytes {
		return SignedResultMutationPermit{}, ErrAdmissionPermitAuthentication
	}
	signature := ed25519.Sign(signer.privateKey, resultMutationPermitSigningBytes(encoded))
	return SignedResultMutationPermit{
		Payload:   encoded,
		Signature: computequeue.SignatureValue(base64.RawURLEncoding.EncodeToString(signature)),
	}, nil
}

type ResultMutationAuthorization struct {
	payload      ResultMutationPermitPayload
	permitDigest computequeue.Digest
}

func (value ResultMutationAuthorization) Payload() ResultMutationPermitPayload { return value.payload }
func (value ResultMutationAuthorization) PermitDigest() computequeue.Digest {
	return value.permitDigest
}
func (value ResultMutationAuthorization) MarshalJSON() ([]byte, error) {
	return nil, ErrAdmissionPermitAuthentication
}
func (value ResultMutationAuthorization) String() string {
	return "verified-job-custody-result-mutation-authorization(redacted)"
}
func (value ResultMutationAuthorization) GoString() string { return value.String() }

func (verifier *AdmissionPermitVerifier) VerifyResultMutation(
	permit SignedResultMutationPermit,
	now computequeue.Timestamp,
) (ResultMutationAuthorization, error) {
	if verifier == nil || len(permit.Payload) == 0 ||
		len(permit.Payload) > MaximumAdmissionPermitBytes || now.Validate() != nil {
		return ResultMutationAuthorization{}, ErrAdmissionPermitAuthentication
	}
	payload, err := computequeue.DecodeCanonical[ResultMutationPermitPayload](permit.Payload)
	if err != nil || payload.Validate() != nil {
		return ResultMutationAuthorization{}, ErrAdmissionPermitAuthentication
	}
	publicKey, trusted := verifier.keys[payload.AuthorityID]
	rawSignature, signatureErr := base64.RawURLEncoding.Strict().DecodeString(string(permit.Signature))
	if !trusted || signatureErr != nil || len(rawSignature) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(rawSignature) != string(permit.Signature) ||
		!ed25519.Verify(publicKey, resultMutationPermitSigningBytes(permit.Payload), rawSignature) ||
		now < payload.IssuedAt || now >= payload.ExpiresAt {
		return ResultMutationAuthorization{}, ErrAdmissionPermitAuthentication
	}
	permitDigest, err := computequeue.ExactBytesDigest(
		resultMutationPermitDigestDomain,
		append(bytes.Clone(permit.Payload), rawSignature...),
		MaximumAdmissionPermitBytes+ed25519.SignatureSize,
	)
	if err != nil {
		return ResultMutationAuthorization{}, ErrAdmissionPermitAuthentication
	}
	return ResultMutationAuthorization{payload: payload, permitDigest: permitDigest}, nil
}

func resultMutationPermitSigningBytes(payload []byte) []byte {
	result := make([]byte, 0, len(resultMutationPermitSignatureDomain)+len(payload))
	result = append(result, resultMutationPermitSignatureDomain...)
	return append(result, payload...)
}
