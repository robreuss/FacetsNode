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
	JobCustodyResultStagingExpiryReceiptVersion                 = 1
	MaximumJobCustodyResultStagingExpiryReceiptPayloadByteCount = 32 * 1024
	MaximumJobCustodyResultStagingExpiryReceiptRecordByteCount  = 40 * 1024
	JobCustodyResultStagingExpiryReceiptKind                    = "result_staging_expired"
	JobCustodyResultStagingExpiryReceiptSignatureDomain         = "Facets Job Custody result staging expiry receipt v1\x00"
	JobCustodyResultStagingExpiryReceiptReferenceDomain         = "Facets Job Custody result staging expiry receipt reference v1\x00"
)

// JobCustodyResultStagingExpiryReceiptPayload proves namespace removal of one
// exact incomplete opaque result after its signed retention bound elapsed. No
// durable result-custody receipt was issued. This does not assert secure-media
// erasure, semantic validity, delivery, release, or canonical application.
// Field declaration order is canonical sorted-key JSON.
type JobCustodyResultStagingExpiryReceiptPayload struct {
	AssignmentID                 uuid.UUID `json:"assignmentID"`
	CommittedBytes               int64     `json:"committedBytes"`
	DeploymentID                 uuid.UUID `json:"deploymentID"`
	ExpiredAtMilliseconds        int64     `json:"expiredAtMilliseconds"`
	InputCapsuleID               uuid.UUID `json:"inputCapsuleID"`
	Kind                         string    `json:"kind"`
	ProtectedObjectByteCount     int64     `json:"protectedObjectByteCount"`
	ProtectedObjectSHA256        string    `json:"protectedObjectSHA256"`
	ResultCapsuleID              uuid.UUID `json:"resultCapsuleID"`
	ResultPermitDigest           string    `json:"resultPermitDigest"`
	ResultSetDigest              string    `json:"resultSetDigest"`
	RetentionUntilMilliseconds   int64     `json:"retentionUntilMilliseconds"`
	Version                      int       `json:"version"`
	WorkerExecutionReceiptDigest string    `json:"workerExecutionReceiptDigest"`
}

func (payload JobCustodyResultStagingExpiryReceiptPayload) Validate() error {
	if payload.Version != JobCustodyResultStagingExpiryReceiptVersion ||
		payload.Kind != JobCustodyResultStagingExpiryReceiptKind ||
		payload.AssignmentID == uuid.Nil || payload.DeploymentID == uuid.Nil ||
		payload.InputCapsuleID == uuid.Nil || payload.ResultCapsuleID == uuid.Nil ||
		payload.InputCapsuleID == payload.ResultCapsuleID ||
		payload.ProtectedObjectByteCount <= 0 || payload.CommittedBytes < 0 ||
		payload.CommittedBytes > payload.ProtectedObjectByteCount ||
		payload.RetentionUntilMilliseconds <= 0 ||
		payload.ExpiredAtMilliseconds < payload.RetentionUntilMilliseconds ||
		!validDigest(payload.ProtectedObjectSHA256) ||
		!validDigest(payload.ResultPermitDigest) || !validDigest(payload.ResultSetDigest) ||
		!validDigest(payload.WorkerExecutionReceiptDigest) {
		return ErrInvalid
	}
	return nil
}

type JobCustodyResultStagingExpiryReceipt struct {
	Payload   []byte    `json:"payload"`
	Signature Signature `json:"signature"`
}

func (signer *DeploymentSigner) SignJobCustodyResultStagingExpiryReceipt(
	payload JobCustodyResultStagingExpiryReceiptPayload,
) (JobCustodyResultStagingExpiryReceipt, error) {
	if signer == nil || payload.Validate() != nil || payload.DeploymentID != signer.deploymentID {
		return JobCustodyResultStagingExpiryReceipt{}, ErrInvalid
	}
	encoded, err := json.Marshal(payload)
	if err != nil || len(encoded) > MaximumJobCustodyResultStagingExpiryReceiptPayloadByteCount {
		return JobCustodyResultStagingExpiryReceipt{}, ErrInvalid
	}
	signature, err := signer.signRecord(JobCustodyResultStagingExpiryReceiptSignatureDomain, encoded)
	if err != nil {
		return JobCustodyResultStagingExpiryReceipt{}, err
	}
	receipt := JobCustodyResultStagingExpiryReceipt{Payload: encoded, Signature: signature}
	if _, err := receipt.VerifiedPayload(); err != nil {
		return JobCustodyResultStagingExpiryReceipt{}, err
	}
	return receipt, nil
}

func (receipt JobCustodyResultStagingExpiryReceipt) VerifiedPayload() (JobCustodyResultStagingExpiryReceiptPayload, error) {
	var payload JobCustodyResultStagingExpiryReceiptPayload
	if len(receipt.Payload) == 0 ||
		len(receipt.Payload) > MaximumJobCustodyResultStagingExpiryReceiptPayloadByteCount ||
		decodeCanonicalJobCustodyResultStagingExpiryReceipt(receipt.Payload, &payload) != nil ||
		payload.Validate() != nil ||
		verifyCanonicalRecord(receipt.Payload, receipt.Signature,
			JobCustodyResultStagingExpiryReceiptSignatureDomain, &payload) != nil ||
		receipt.Signature.SignerID != payload.DeploymentID {
		return JobCustodyResultStagingExpiryReceiptPayload{}, ErrInvalid
	}
	return payload, nil
}

func (receipt JobCustodyResultStagingExpiryReceipt) Authorize(
	deployment DeploymentDescriptor,
) (JobCustodyResultStagingExpiryReceiptPayload, error) {
	payload, err := receipt.VerifiedPayload()
	if err != nil || deployment.Validate() != nil || payload.DeploymentID != deployment.DeploymentID ||
		receipt.Signature.SignerID != deployment.DeploymentID ||
		receipt.Signature.PublicSigningKeyX963 != deployment.PublicSigningKeyX963 ||
		receipt.Signature.SigningKeyFingerprint != deployment.SigningKeyFingerprint {
		return JobCustodyResultStagingExpiryReceiptPayload{}, ErrInvalid
	}
	return payload, nil
}

func (receipt JobCustodyResultStagingExpiryReceipt) ReferenceDigest() (string, error) {
	if _, err := receipt.VerifiedPayload(); err != nil {
		return "", ErrInvalid
	}
	encodedSignature, err := json.Marshal(receipt.Signature)
	if err != nil {
		return "", ErrInvalid
	}
	digest := sha256.Sum256(append(append(
		[]byte(JobCustodyResultStagingExpiryReceiptReferenceDomain), receipt.Payload...),
		encodedSignature...))
	return hex.EncodeToString(digest[:]), nil
}

func (receipt JobCustodyResultStagingExpiryReceipt) CanonicalJSON() ([]byte, error) {
	if _, err := receipt.VerifiedPayload(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(receipt)
	if err != nil || len(encoded) > MaximumJobCustodyResultStagingExpiryReceiptRecordByteCount {
		return nil, ErrInvalid
	}
	return encoded, nil
}

func DecodeJobCustodyResultStagingExpiryReceipt(
	input []byte,
) (JobCustodyResultStagingExpiryReceipt, error) {
	if len(input) == 0 || len(input) > MaximumJobCustodyResultStagingExpiryReceiptRecordByteCount {
		return JobCustodyResultStagingExpiryReceipt{}, ErrInvalid
	}
	var receipt JobCustodyResultStagingExpiryReceipt
	if decodeCanonicalJobCustodyResultStagingExpiryReceipt(input, &receipt) != nil {
		return JobCustodyResultStagingExpiryReceipt{}, ErrInvalid
	}
	if _, err := receipt.VerifiedPayload(); err != nil {
		return JobCustodyResultStagingExpiryReceipt{}, err
	}
	return receipt, nil
}

func decodeCanonicalJobCustodyResultStagingExpiryReceipt(input []byte, target any) error {
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
