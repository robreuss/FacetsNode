package serviceauthority

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	"github.com/google/uuid"
)

const (
	JobCustodyResultReceiptVersion                 = 1
	MaximumJobCustodyResultReceiptPayloadByteCount = 32 * 1024
	MaximumJobCustodyResultReceiptRecordByteCount  = 40 * 1024
	JobCustodyResultReceiptKind                    = "result_custodied"
	JobCustodyResultReceiptSignatureDomain         = "Facets Job Custody result receipt v1\x00"
	JobCustodyResultReceiptReferenceDomain         = "Facets Job Custody result receipt reference v1\x00"
)

// JobCustodyResultReceiptPayload proves durable custody of one exact opaque
// protected result. It does not assert that execution succeeded, that the
// encrypted result is semantically valid, or that the source applied it.
// Field declaration order is canonical sorted-key JSON.
type JobCustodyResultReceiptPayload struct {
	AssignmentID                    uuid.UUID `json:"assignmentID"`
	ClaimID                         uuid.UUID `json:"claimID"`
	ClaimPermitDigest               string    `json:"claimPermitDigest"`
	CommittedAtMilliseconds         int64     `json:"committedAtMilliseconds"`
	DeploymentID                    uuid.UUID `json:"deploymentID"`
	InputCapsuleID                  uuid.UUID `json:"inputCapsuleID"`
	Kind                            string    `json:"kind"`
	ProtectedObjectByteCount        int64     `json:"protectedObjectByteCount"`
	ProtectedObjectDescriptorDigest string    `json:"protectedObjectDescriptorDigest"`
	ProtectedObjectSHA256           string    `json:"protectedObjectSHA256"`
	ResultCapsuleID                 uuid.UUID `json:"resultCapsuleID"`
	ResultIdempotencyKey            string    `json:"resultIdempotencyKey"`
	ResultPermitDigest              string    `json:"resultPermitDigest"`
	ResultSetDigest                 string    `json:"resultSetDigest"`
	RetentionUntilMilliseconds      int64     `json:"retentionUntilMilliseconds"`
	Version                         int       `json:"version"`
	WorkerExecutionReceiptDigest    string    `json:"workerExecutionReceiptDigest"`
}

func (payload JobCustodyResultReceiptPayload) Validate() error {
	if payload.Version != JobCustodyResultReceiptVersion ||
		payload.Kind != JobCustodyResultReceiptKind || payload.AssignmentID == uuid.Nil ||
		payload.ClaimID == uuid.Nil || payload.DeploymentID == uuid.Nil ||
		payload.InputCapsuleID == uuid.Nil || payload.ResultCapsuleID == uuid.Nil ||
		payload.InputCapsuleID == payload.ResultCapsuleID || payload.CommittedAtMilliseconds < 0 ||
		payload.RetentionUntilMilliseconds < payload.CommittedAtMilliseconds ||
		payload.ProtectedObjectByteCount <= 0 || !validDigest(payload.ClaimPermitDigest) ||
		!validDigest(payload.ProtectedObjectDescriptorDigest) ||
		!validDigest(payload.ProtectedObjectSHA256) ||
		!validDigest(payload.ResultIdempotencyKey) || !validDigest(payload.ResultPermitDigest) ||
		!validDigest(payload.ResultSetDigest) || !validDigest(payload.WorkerExecutionReceiptDigest) {
		return ErrInvalid
	}
	return nil
}

type JobCustodyResultReceipt struct {
	Payload   []byte    `json:"payload"`
	Signature Signature `json:"signature"`
}

func (signer *DeploymentSigner) SignJobCustodyResultReceipt(
	payload JobCustodyResultReceiptPayload,
) (JobCustodyResultReceipt, error) {
	if signer == nil || payload.Validate() != nil || payload.DeploymentID != signer.deploymentID {
		return JobCustodyResultReceipt{}, ErrInvalid
	}
	encoded, err := json.Marshal(payload)
	if err != nil || len(encoded) > MaximumJobCustodyResultReceiptPayloadByteCount {
		return JobCustodyResultReceipt{}, ErrInvalid
	}
	signature, err := signer.signRecord(JobCustodyResultReceiptSignatureDomain, encoded)
	if err != nil {
		return JobCustodyResultReceipt{}, err
	}
	receipt := JobCustodyResultReceipt{Payload: encoded, Signature: signature}
	if _, err := receipt.VerifiedPayload(); err != nil {
		return JobCustodyResultReceipt{}, err
	}
	return receipt, nil
}

func (receipt JobCustodyResultReceipt) VerifiedPayload() (JobCustodyResultReceiptPayload, error) {
	var payload JobCustodyResultReceiptPayload
	if len(receipt.Payload) == 0 ||
		len(receipt.Payload) > MaximumJobCustodyResultReceiptPayloadByteCount ||
		decodeCanonicalJobCustodyResultReceipt(receipt.Payload, &payload) != nil ||
		payload.Validate() != nil ||
		verifyCanonicalRecord(receipt.Payload, receipt.Signature,
			JobCustodyResultReceiptSignatureDomain, &payload) != nil ||
		receipt.Signature.SignerID != payload.DeploymentID {
		return JobCustodyResultReceiptPayload{}, ErrInvalid
	}
	return payload, nil
}

func (receipt JobCustodyResultReceipt) Authorize(
	deployment DeploymentDescriptor,
) (JobCustodyResultReceiptPayload, error) {
	payload, err := receipt.VerifiedPayload()
	if err != nil || deployment.Validate() != nil ||
		payload.DeploymentID != deployment.DeploymentID ||
		receipt.Signature.SignerID != deployment.DeploymentID ||
		receipt.Signature.PublicSigningKeyX963 != deployment.PublicSigningKeyX963 ||
		receipt.Signature.SigningKeyFingerprint != deployment.SigningKeyFingerprint {
		return JobCustodyResultReceiptPayload{}, ErrInvalid
	}
	return payload, nil
}

func (receipt JobCustodyResultReceipt) ReferenceDigest() (string, error) {
	if _, err := receipt.VerifiedPayload(); err != nil {
		return "", ErrInvalid
	}
	encodedSignature, err := json.Marshal(receipt.Signature)
	if err != nil {
		return "", ErrInvalid
	}
	digest := sha256.Sum256(append(append(
		[]byte(JobCustodyResultReceiptReferenceDomain), receipt.Payload...),
		encodedSignature...))
	return hex.EncodeToString(digest[:]), nil
}

func (receipt JobCustodyResultReceipt) CanonicalJSON() ([]byte, error) {
	if _, err := receipt.VerifiedPayload(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(receipt)
	if err != nil || len(encoded) > MaximumJobCustodyResultReceiptRecordByteCount {
		return nil, ErrInvalid
	}
	return encoded, nil
}

func DecodeJobCustodyResultReceipt(input []byte) (JobCustodyResultReceipt, error) {
	if len(input) == 0 || len(input) > MaximumJobCustodyResultReceiptRecordByteCount {
		return JobCustodyResultReceipt{}, ErrInvalid
	}
	var receipt JobCustodyResultReceipt
	if decodeCanonicalJobCustodyResultReceipt(input, &receipt) != nil {
		return JobCustodyResultReceipt{}, ErrInvalid
	}
	if _, err := receipt.VerifiedPayload(); err != nil {
		return JobCustodyResultReceipt{}, err
	}
	return receipt, nil
}

func decodeCanonicalJobCustodyResultReceipt(input []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	encoded, err := json.Marshal(target)
	if err != nil || !bytes.Equal(encoded, input) {
		return ErrInvalid
	}
	return nil
}
