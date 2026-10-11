package jobcustody

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/computequeue"
)

const (
	WorkerResultPermitVersion         = 1
	workerResultPermitSignatureDomain = "Facets Job Custody Worker result permit v1\x00"
	workerResultPermitDigestDomain    = "facets.job-custody.worker-result-permit.v1"
)

// WorkerResultHeader commits the exact opaque result object produced for one
// durable Worker claim. It deliberately contains no Space, prompt, model,
// object, label, or plaintext result metadata.
// Field declaration order is canonical sorted-key JSON.
type WorkerResultHeader struct {
	AssignmentID                 computequeue.AssignmentID                        `json:"assignmentID"`
	ClaimID                      uuid.UUID                                        `json:"claimID"`
	IdempotencyKey               computequeue.Digest                              `json:"idempotencyKey"`
	InputCapsuleID               computequeue.JobCapsuleID                        `json:"inputCapsuleID"`
	ProtectedObject              computequeue.JobCapsuleProtectedObjectDescriptor `json:"protectedObject"`
	ResultCapsuleID              computequeue.JobCapsuleID                        `json:"resultCapsuleID"`
	ResultSetDigest              computequeue.Digest                              `json:"resultSetDigest"`
	RetentionUntil               computequeue.Timestamp                           `json:"retentionUntil"`
	Version                      int                                              `json:"version"`
	WorkerExecutionReceiptDigest computequeue.Digest                              `json:"workerExecutionReceiptDigest"`
}

func NewWorkerResultHeader(
	assignmentID computequeue.AssignmentID,
	claimID uuid.UUID,
	inputCapsuleID computequeue.JobCapsuleID,
	resultCapsuleID computequeue.JobCapsuleID,
	protectedObject computequeue.JobCapsuleProtectedObjectDescriptor,
	resultSetDigest computequeue.Digest,
	workerExecutionReceiptDigest computequeue.Digest,
	retentionUntil computequeue.Timestamp,
) (WorkerResultHeader, error) {
	value := WorkerResultHeader{
		AssignmentID: assignmentID, ClaimID: claimID,
		InputCapsuleID: inputCapsuleID, ProtectedObject: protectedObject,
		ResultCapsuleID: resultCapsuleID, ResultSetDigest: resultSetDigest,
		RetentionUntil: retentionUntil, Version: WorkerResultPermitVersion,
		WorkerExecutionReceiptDigest: workerExecutionReceiptDigest,
	}
	value.IdempotencyKey = value.MakeIdempotencyKey()
	if value.Validate() != nil {
		return WorkerResultHeader{}, ErrAdmissionPermitAuthentication
	}
	return value, nil
}

func (value WorkerResultHeader) Validate() error {
	if value.Version != WorkerResultPermitVersion || value.AssignmentID.Validate() != nil ||
		value.ClaimID == uuid.Nil || value.IdempotencyKey.Validate() != nil ||
		value.InputCapsuleID.Validate() != nil || value.ProtectedObject.Validate() != nil ||
		value.ResultCapsuleID.Validate() != nil || value.ResultCapsuleID == value.InputCapsuleID ||
		value.ResultSetDigest.Validate() != nil || value.RetentionUntil.Validate() != nil ||
		value.WorkerExecutionReceiptDigest.Validate() != nil ||
		value.IdempotencyKey != value.MakeIdempotencyKey() {
		return ErrAdmissionPermitAuthentication
	}
	return nil
}

func (value WorkerResultHeader) MakeIdempotencyKey() computequeue.Digest {
	return computequeue.SHA256Digest(
		"facets.job-custody.worker-result-idempotency.v1",
		string(value.AssignmentID), value.ClaimID.String(), string(value.InputCapsuleID),
		string(value.ProtectedObject.Digest()), string(value.ResultCapsuleID),
		string(value.ResultSetDigest), fmt.Sprint(value.RetentionUntil),
		string(value.WorkerExecutionReceiptDigest),
	)
}

func (value WorkerResultHeader) Digest() computequeue.Digest {
	return computequeue.SHA256Digest(
		"facets.job-custody.worker-result-header.v1",
		fmt.Sprint(value.Version), string(value.AssignmentID), value.ClaimID.String(),
		string(value.IdempotencyKey), string(value.InputCapsuleID),
		string(value.ProtectedObject.Digest()), string(value.ResultCapsuleID),
		string(value.ResultSetDigest), fmt.Sprint(value.RetentionUntil),
		string(value.WorkerExecutionReceiptDigest),
	)
}

// WorkerResultPermitPayload is issued by the Box only after authenticating
// the currently enrolled owner of the exact advertised Worker capability.
// Job Custody additionally binds it to the existing durable claim.
// Field declaration order is canonical sorted-key JSON.
type WorkerResultPermitPayload struct {
	AuthorityID                  uuid.UUID              `json:"authorityID"`
	ExpiresAt                    computequeue.Timestamp `json:"expiresAt"`
	IssuedAt                     computequeue.Timestamp `json:"issuedAt"`
	PermitID                     uuid.UUID              `json:"permitID"`
	Result                       WorkerResultHeader     `json:"result"`
	RouteRecipientKeyFingerprint computequeue.Digest    `json:"routeRecipientKeyFingerprint"`
	RouteRecipientWorkerID       computequeue.WorkerID  `json:"routeRecipientWorkerID"`
	Version                      int                    `json:"version"`
	WorkerCapabilitiesDigest     computequeue.Digest    `json:"workerCapabilitiesDigest"`
	WorkerOwnerAuthorityDigest   computequeue.Digest    `json:"workerOwnerAuthorityDigest"`
}

func (value WorkerResultPermitPayload) Validate() error {
	if value.Version != WorkerResultPermitVersion || value.AuthorityID == uuid.Nil ||
		value.PermitID == uuid.Nil || value.Result.Validate() != nil ||
		value.RouteRecipientKeyFingerprint.Validate() != nil ||
		value.RouteRecipientWorkerID.Validate() != nil ||
		value.WorkerCapabilitiesDigest.Validate() != nil ||
		value.WorkerOwnerAuthorityDigest.Validate() != nil ||
		value.IssuedAt.Validate() != nil || value.ExpiresAt.Validate() != nil ||
		value.IssuedAt >= value.ExpiresAt || value.ExpiresAt > value.Result.RetentionUntil ||
		int64(value.ExpiresAt-value.IssuedAt) > MaximumWorkerClaimPermitLifetimeMillisecs {
		return ErrAdmissionPermitAuthentication
	}
	return nil
}

type SignedWorkerResultPermit struct {
	Payload   []byte                      `json:"payload"`
	Signature computequeue.SignatureValue `json:"signature"`
}

type WorkerResultPermitSigner struct {
	authorityID uuid.UUID
	privateKey  ed25519.PrivateKey
}

func NewWorkerResultPermitSigner(
	authorityID uuid.UUID,
	privateKey ed25519.PrivateKey,
) (*WorkerResultPermitSigner, error) {
	if authorityID == uuid.Nil || len(privateKey) != ed25519.PrivateKeySize {
		return nil, ErrAdmissionPermitAuthentication
	}
	return &WorkerResultPermitSigner{
		authorityID: authorityID, privateKey: bytes.Clone(privateKey),
	}, nil
}

func (signer *WorkerResultPermitSigner) Sign(
	payload WorkerResultPermitPayload,
) (SignedWorkerResultPermit, error) {
	if signer == nil || signer.authorityID == uuid.Nil ||
		len(signer.privateKey) != ed25519.PrivateKeySize || payload.Validate() != nil ||
		payload.AuthorityID != signer.authorityID {
		return SignedWorkerResultPermit{}, ErrAdmissionPermitAuthentication
	}
	encoded, err := computequeue.EncodeCanonical(payload)
	if err != nil || len(encoded) > MaximumAdmissionPermitBytes {
		return SignedWorkerResultPermit{}, ErrAdmissionPermitAuthentication
	}
	signature := ed25519.Sign(signer.privateKey, workerResultPermitSigningBytes(encoded))
	return SignedWorkerResultPermit{
		Payload:   encoded,
		Signature: computequeue.SignatureValue(base64.RawURLEncoding.EncodeToString(signature)),
	}, nil
}

type WorkerResultAuthorization struct {
	payload      WorkerResultPermitPayload
	permitDigest computequeue.Digest
}

func (value WorkerResultAuthorization) Payload() WorkerResultPermitPayload { return value.payload }
func (value WorkerResultAuthorization) PermitDigest() computequeue.Digest  { return value.permitDigest }
func (value WorkerResultAuthorization) MarshalJSON() ([]byte, error) {
	return nil, ErrAdmissionPermitAuthentication
}
func (value WorkerResultAuthorization) String() string {
	return "verified-job-custody-worker-result-authorization(redacted)"
}
func (value WorkerResultAuthorization) GoString() string { return value.String() }

func (verifier *AdmissionPermitVerifier) VerifyWorkerResult(
	permit SignedWorkerResultPermit,
	now computequeue.Timestamp,
) (WorkerResultAuthorization, error) {
	if verifier == nil || len(permit.Payload) == 0 ||
		len(permit.Payload) > MaximumAdmissionPermitBytes || now.Validate() != nil {
		return WorkerResultAuthorization{}, ErrAdmissionPermitAuthentication
	}
	payload, err := computequeue.DecodeCanonical[WorkerResultPermitPayload](permit.Payload)
	if err != nil || payload.Validate() != nil {
		return WorkerResultAuthorization{}, ErrAdmissionPermitAuthentication
	}
	publicKey, trusted := verifier.keys[payload.AuthorityID]
	rawSignature, signatureErr := base64.RawURLEncoding.Strict().DecodeString(string(permit.Signature))
	if !trusted || signatureErr != nil || len(rawSignature) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(rawSignature) != string(permit.Signature) ||
		!ed25519.Verify(publicKey, workerResultPermitSigningBytes(permit.Payload), rawSignature) ||
		now < payload.IssuedAt || now >= payload.ExpiresAt {
		return WorkerResultAuthorization{}, ErrAdmissionPermitAuthentication
	}
	permitDigest, err := computequeue.ExactBytesDigest(
		workerResultPermitDigestDomain,
		append(bytes.Clone(permit.Payload), rawSignature...),
		MaximumAdmissionPermitBytes+ed25519.SignatureSize,
	)
	if err != nil {
		return WorkerResultAuthorization{}, ErrAdmissionPermitAuthentication
	}
	return WorkerResultAuthorization{payload: payload, permitDigest: permitDigest}, nil
}

func workerResultPermitSigningBytes(payload []byte) []byte {
	result := make([]byte, 0, len(workerResultPermitSignatureDomain)+len(payload))
	result = append(result, workerResultPermitSignatureDomain...)
	return append(result, payload...)
}
