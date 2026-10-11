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
	JobCustodyResultExpiryReceiptVersion                 = 1
	MaximumJobCustodyResultExpiryReceiptPayloadByteCount = 32 * 1024
	MaximumJobCustodyResultExpiryReceiptRecordByteCount  = 40 * 1024
	JobCustodyResultExpiryReceiptKind                    = "result_custody_expired"
	JobCustodyResultExpiryReceiptSignatureDomain         = "Facets Job Custody result expiry receipt v1\x00"
	JobCustodyResultExpiryReceiptReferenceDomain         = "Facets Job Custody result expiry receipt reference v1\x00"
)

// JobCustodyResultExpiryReceiptPayload proves that Job Custody relinquished
// filesystem custody of one exact opaque result after its signed retention
// bound elapsed. It does not assert secure-media erasure, semantic result
// validity, source release, or canonical application. When the source already
// acknowledged delivery, that receipt commitment is preserved as history.
// Field declaration order is canonical sorted-key JSON.
type JobCustodyResultExpiryReceiptPayload struct {
	AssignmentID                 uuid.UUID `json:"assignmentID"`
	CustodyReceiptDigest         string    `json:"custodyReceiptDigest"`
	DeliveryAcknowledgedAtMillis int64     `json:"deliveryAcknowledgedAtMilliseconds"`
	DeploymentID                 uuid.UUID `json:"deploymentID"`
	ExpiredAtMilliseconds        int64     `json:"expiredAtMilliseconds"`
	InputCapsuleID               uuid.UUID `json:"inputCapsuleID"`
	Kind                         string    `json:"kind"`
	ResultCapsuleID              uuid.UUID `json:"resultCapsuleID"`
	ResultSetDigest              string    `json:"resultSetDigest"`
	RetentionUntilMilliseconds   int64     `json:"retentionUntilMilliseconds"`
	SourceDeliveryReceiptDigest  string    `json:"sourceDeliveryReceiptDigest"`
	Version                      int       `json:"version"`
}

func (payload JobCustodyResultExpiryReceiptPayload) Validate() error {
	deliveryAbsent := payload.DeliveryAcknowledgedAtMillis == 0 &&
		payload.SourceDeliveryReceiptDigest == ""
	deliveryPresent := payload.DeliveryAcknowledgedAtMillis > 0 &&
		validDigest(payload.SourceDeliveryReceiptDigest)
	if payload.Version != JobCustodyResultExpiryReceiptVersion ||
		payload.Kind != JobCustodyResultExpiryReceiptKind || payload.AssignmentID == uuid.Nil ||
		payload.DeploymentID == uuid.Nil || payload.InputCapsuleID == uuid.Nil ||
		payload.ResultCapsuleID == uuid.Nil || payload.InputCapsuleID == payload.ResultCapsuleID ||
		payload.RetentionUntilMilliseconds <= 0 ||
		payload.ExpiredAtMilliseconds < payload.RetentionUntilMilliseconds ||
		(!deliveryAbsent && !deliveryPresent) ||
		(deliveryPresent && payload.DeliveryAcknowledgedAtMillis > payload.RetentionUntilMilliseconds) ||
		!validDigest(payload.CustodyReceiptDigest) || !validDigest(payload.ResultSetDigest) {
		return ErrInvalid
	}
	return nil
}

type JobCustodyResultExpiryReceipt struct {
	Payload   []byte    `json:"payload"`
	Signature Signature `json:"signature"`
}

func (signer *DeploymentSigner) SignJobCustodyResultExpiryReceipt(
	payload JobCustodyResultExpiryReceiptPayload,
) (JobCustodyResultExpiryReceipt, error) {
	if signer == nil || payload.Validate() != nil || payload.DeploymentID != signer.deploymentID {
		return JobCustodyResultExpiryReceipt{}, ErrInvalid
	}
	encoded, err := json.Marshal(payload)
	if err != nil || len(encoded) > MaximumJobCustodyResultExpiryReceiptPayloadByteCount {
		return JobCustodyResultExpiryReceipt{}, ErrInvalid
	}
	signature, err := signer.signRecord(JobCustodyResultExpiryReceiptSignatureDomain, encoded)
	if err != nil {
		return JobCustodyResultExpiryReceipt{}, err
	}
	receipt := JobCustodyResultExpiryReceipt{Payload: encoded, Signature: signature}
	if _, err := receipt.VerifiedPayload(); err != nil {
		return JobCustodyResultExpiryReceipt{}, err
	}
	return receipt, nil
}

func (receipt JobCustodyResultExpiryReceipt) VerifiedPayload() (JobCustodyResultExpiryReceiptPayload, error) {
	var payload JobCustodyResultExpiryReceiptPayload
	if len(receipt.Payload) == 0 ||
		len(receipt.Payload) > MaximumJobCustodyResultExpiryReceiptPayloadByteCount ||
		decodeCanonicalJobCustodyResultExpiryReceipt(receipt.Payload, &payload) != nil ||
		payload.Validate() != nil ||
		verifyCanonicalRecord(receipt.Payload, receipt.Signature,
			JobCustodyResultExpiryReceiptSignatureDomain, &payload) != nil ||
		receipt.Signature.SignerID != payload.DeploymentID {
		return JobCustodyResultExpiryReceiptPayload{}, ErrInvalid
	}
	return payload, nil
}

func (receipt JobCustodyResultExpiryReceipt) Authorize(
	deployment DeploymentDescriptor,
) (JobCustodyResultExpiryReceiptPayload, error) {
	payload, err := receipt.VerifiedPayload()
	if err != nil || deployment.Validate() != nil ||
		payload.DeploymentID != deployment.DeploymentID ||
		receipt.Signature.SignerID != deployment.DeploymentID ||
		receipt.Signature.PublicSigningKeyX963 != deployment.PublicSigningKeyX963 ||
		receipt.Signature.SigningKeyFingerprint != deployment.SigningKeyFingerprint {
		return JobCustodyResultExpiryReceiptPayload{}, ErrInvalid
	}
	return payload, nil
}

func (receipt JobCustodyResultExpiryReceipt) ReferenceDigest() (string, error) {
	if _, err := receipt.VerifiedPayload(); err != nil {
		return "", ErrInvalid
	}
	encodedSignature, err := json.Marshal(receipt.Signature)
	if err != nil {
		return "", ErrInvalid
	}
	digest := sha256.Sum256(append(append(
		[]byte(JobCustodyResultExpiryReceiptReferenceDomain), receipt.Payload...),
		encodedSignature...))
	return hex.EncodeToString(digest[:]), nil
}

func (receipt JobCustodyResultExpiryReceipt) CanonicalJSON() ([]byte, error) {
	if _, err := receipt.VerifiedPayload(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(receipt)
	if err != nil || len(encoded) > MaximumJobCustodyResultExpiryReceiptRecordByteCount {
		return nil, ErrInvalid
	}
	return encoded, nil
}

func DecodeJobCustodyResultExpiryReceipt(input []byte) (JobCustodyResultExpiryReceipt, error) {
	if len(input) == 0 || len(input) > MaximumJobCustodyResultExpiryReceiptRecordByteCount {
		return JobCustodyResultExpiryReceipt{}, ErrInvalid
	}
	var receipt JobCustodyResultExpiryReceipt
	if decodeCanonicalJobCustodyResultExpiryReceipt(input, &receipt) != nil {
		return JobCustodyResultExpiryReceipt{}, ErrInvalid
	}
	if _, err := receipt.VerifiedPayload(); err != nil {
		return JobCustodyResultExpiryReceipt{}, err
	}
	return receipt, nil
}

func decodeCanonicalJobCustodyResultExpiryReceipt(input []byte, target any) error {
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
