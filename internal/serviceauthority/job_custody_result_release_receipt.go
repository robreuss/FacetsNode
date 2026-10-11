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
	JobCustodyResultReleaseReceiptVersion                 = 1
	MaximumJobCustodyResultReleaseReceiptPayloadByteCount = 32 * 1024
	MaximumJobCustodyResultReleaseReceiptRecordByteCount  = 40 * 1024
	JobCustodyResultReleaseReceiptKind                    = "result_custody_released"
	JobCustodyResultReleaseReceiptSignatureDomain         = "Facets Job Custody result release receipt v1\x00"
	JobCustodyResultReleaseReceiptReferenceDomain         = "Facets Job Custody result release receipt reference v1\x00"
)

// JobCustodyResultReleaseReceiptPayload proves that Job Custody relinquished
// its filesystem custody of one exact opaque result after an authenticated
// source release request. It does not assert secure-media erasure, semantic
// result validity, or canonical application by the source.
// Field declaration order is canonical sorted-key JSON.
type JobCustodyResultReleaseReceiptPayload struct {
	AssignmentID                 uuid.UUID `json:"assignmentID"`
	CustodyReceiptDigest         string    `json:"custodyReceiptDigest"`
	DeliveryAcknowledgedAtMillis int64     `json:"deliveryAcknowledgedAtMilliseconds"`
	DeploymentID                 uuid.UUID `json:"deploymentID"`
	InputCapsuleID               uuid.UUID `json:"inputCapsuleID"`
	Kind                         string    `json:"kind"`
	ReleasedAtMilliseconds       int64     `json:"releasedAtMilliseconds"`
	ResultCapsuleID              uuid.UUID `json:"resultCapsuleID"`
	ResultSetDigest              string    `json:"resultSetDigest"`
	SourceDeliveryReceiptDigest  string    `json:"sourceDeliveryReceiptDigest"`
	SourceReleaseReceiptDigest   string    `json:"sourceReleaseReceiptDigest"`
	Version                      int       `json:"version"`
}

func (payload JobCustodyResultReleaseReceiptPayload) Validate() error {
	if payload.Version != JobCustodyResultReleaseReceiptVersion ||
		payload.Kind != JobCustodyResultReleaseReceiptKind || payload.AssignmentID == uuid.Nil ||
		payload.DeploymentID == uuid.Nil || payload.InputCapsuleID == uuid.Nil ||
		payload.ResultCapsuleID == uuid.Nil || payload.InputCapsuleID == payload.ResultCapsuleID ||
		payload.DeliveryAcknowledgedAtMillis < 0 ||
		payload.ReleasedAtMilliseconds < payload.DeliveryAcknowledgedAtMillis ||
		!validDigest(payload.CustodyReceiptDigest) || !validDigest(payload.ResultSetDigest) ||
		!validDigest(payload.SourceDeliveryReceiptDigest) ||
		!validDigest(payload.SourceReleaseReceiptDigest) {
		return ErrInvalid
	}
	return nil
}

type JobCustodyResultReleaseReceipt struct {
	Payload   []byte    `json:"payload"`
	Signature Signature `json:"signature"`
}

func (signer *DeploymentSigner) SignJobCustodyResultReleaseReceipt(
	payload JobCustodyResultReleaseReceiptPayload,
) (JobCustodyResultReleaseReceipt, error) {
	if signer == nil || payload.Validate() != nil || payload.DeploymentID != signer.deploymentID {
		return JobCustodyResultReleaseReceipt{}, ErrInvalid
	}
	encoded, err := json.Marshal(payload)
	if err != nil || len(encoded) > MaximumJobCustodyResultReleaseReceiptPayloadByteCount {
		return JobCustodyResultReleaseReceipt{}, ErrInvalid
	}
	signature, err := signer.signRecord(JobCustodyResultReleaseReceiptSignatureDomain, encoded)
	if err != nil {
		return JobCustodyResultReleaseReceipt{}, err
	}
	receipt := JobCustodyResultReleaseReceipt{Payload: encoded, Signature: signature}
	if _, err := receipt.VerifiedPayload(); err != nil {
		return JobCustodyResultReleaseReceipt{}, err
	}
	return receipt, nil
}

func (receipt JobCustodyResultReleaseReceipt) VerifiedPayload() (JobCustodyResultReleaseReceiptPayload, error) {
	var payload JobCustodyResultReleaseReceiptPayload
	if len(receipt.Payload) == 0 ||
		len(receipt.Payload) > MaximumJobCustodyResultReleaseReceiptPayloadByteCount ||
		decodeCanonicalJobCustodyResultReleaseReceipt(receipt.Payload, &payload) != nil ||
		payload.Validate() != nil ||
		verifyCanonicalRecord(receipt.Payload, receipt.Signature,
			JobCustodyResultReleaseReceiptSignatureDomain, &payload) != nil ||
		receipt.Signature.SignerID != payload.DeploymentID {
		return JobCustodyResultReleaseReceiptPayload{}, ErrInvalid
	}
	return payload, nil
}

func (receipt JobCustodyResultReleaseReceipt) Authorize(
	deployment DeploymentDescriptor,
) (JobCustodyResultReleaseReceiptPayload, error) {
	payload, err := receipt.VerifiedPayload()
	if err != nil || deployment.Validate() != nil ||
		payload.DeploymentID != deployment.DeploymentID ||
		receipt.Signature.SignerID != deployment.DeploymentID ||
		receipt.Signature.PublicSigningKeyX963 != deployment.PublicSigningKeyX963 ||
		receipt.Signature.SigningKeyFingerprint != deployment.SigningKeyFingerprint {
		return JobCustodyResultReleaseReceiptPayload{}, ErrInvalid
	}
	return payload, nil
}

func (receipt JobCustodyResultReleaseReceipt) ReferenceDigest() (string, error) {
	if _, err := receipt.VerifiedPayload(); err != nil {
		return "", ErrInvalid
	}
	encodedSignature, err := json.Marshal(receipt.Signature)
	if err != nil {
		return "", ErrInvalid
	}
	digest := sha256.Sum256(append(append(
		[]byte(JobCustodyResultReleaseReceiptReferenceDomain), receipt.Payload...),
		encodedSignature...))
	return hex.EncodeToString(digest[:]), nil
}

func (receipt JobCustodyResultReleaseReceipt) CanonicalJSON() ([]byte, error) {
	if _, err := receipt.VerifiedPayload(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(receipt)
	if err != nil || len(encoded) > MaximumJobCustodyResultReleaseReceiptRecordByteCount {
		return nil, ErrInvalid
	}
	return encoded, nil
}

func DecodeJobCustodyResultReleaseReceipt(input []byte) (JobCustodyResultReleaseReceipt, error) {
	if len(input) == 0 || len(input) > MaximumJobCustodyResultReleaseReceiptRecordByteCount {
		return JobCustodyResultReleaseReceipt{}, ErrInvalid
	}
	var receipt JobCustodyResultReleaseReceipt
	if decodeCanonicalJobCustodyResultReleaseReceipt(input, &receipt) != nil {
		return JobCustodyResultReleaseReceipt{}, ErrInvalid
	}
	if _, err := receipt.VerifiedPayload(); err != nil {
		return JobCustodyResultReleaseReceipt{}, err
	}
	return receipt, nil
}

func decodeCanonicalJobCustodyResultReleaseReceipt(input []byte, target any) error {
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
