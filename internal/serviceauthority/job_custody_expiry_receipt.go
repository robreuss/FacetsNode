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
	JobCustodyExpiryReceiptVersion                 = 1
	MaximumJobCustodyExpiryReceiptPayloadByteCount = 32 * 1024
	MaximumJobCustodyExpiryReceiptRecordByteCount  = 40 * 1024
	JobCustodyExpiryReceiptKind                    = "input_custody_expired"
	JobCustodyExpiryReceiptSignatureDomain         = "Facets Job Custody input expiry receipt v1\x00"
	JobCustodyExpiryReceiptReferenceDomain         = "Facets Job Custody input expiry receipt reference v1\x00"

	JobCustodyStagingExpiryReceiptVersion                 = 1
	MaximumJobCustodyStagingExpiryReceiptPayloadByteCount = 32 * 1024
	MaximumJobCustodyStagingExpiryReceiptRecordByteCount  = 40 * 1024
	JobCustodyStagingExpiryReceiptKind                    = "input_staging_expired"
	JobCustodyStagingExpiryReceiptSignatureDomain         = "Facets Job Custody input staging expiry receipt v1\x00"
	JobCustodyStagingExpiryReceiptReferenceDomain         = "Facets Job Custody input staging expiry receipt reference v1\x00"
)

// JobCustodyExpiryReceiptPayload proves namespace removal of one exact opaque
// input after its signed retention bound elapsed. It does not assert
// secure-media erasure, execution, result delivery, or canonical application.
// Field declaration order is canonical sorted-key JSON.
type JobCustodyExpiryReceiptPayload struct {
	AdmissionEnvelopeDigest    string    `json:"admissionEnvelopeDigest"`
	AdmissionPermitDigest      string    `json:"admissionPermitDigest"`
	AssignmentID               uuid.UUID `json:"assignmentID"`
	CapsuleID                  uuid.UUID `json:"capsuleID"`
	CustodyReceiptDigest       string    `json:"custodyReceiptDigest"`
	DeploymentID               uuid.UUID `json:"deploymentID"`
	ExpiredAtMilliseconds      int64     `json:"expiredAtMilliseconds"`
	Kind                       string    `json:"kind"`
	RetentionUntilMilliseconds int64     `json:"retentionUntilMilliseconds"`
	Version                    int       `json:"version"`
}

func (payload JobCustodyExpiryReceiptPayload) Validate() error {
	if payload.Version != JobCustodyExpiryReceiptVersion ||
		payload.Kind != JobCustodyExpiryReceiptKind || payload.AssignmentID == uuid.Nil ||
		payload.CapsuleID == uuid.Nil || payload.DeploymentID == uuid.Nil ||
		payload.RetentionUntilMilliseconds <= 0 ||
		payload.ExpiredAtMilliseconds < payload.RetentionUntilMilliseconds ||
		!validDigest(payload.AdmissionEnvelopeDigest) ||
		!validDigest(payload.AdmissionPermitDigest) || !validDigest(payload.CustodyReceiptDigest) {
		return ErrInvalid
	}
	return nil
}

type JobCustodyExpiryReceipt struct {
	Payload   []byte    `json:"payload"`
	Signature Signature `json:"signature"`
}

func (signer *DeploymentSigner) SignJobCustodyExpiryReceipt(
	payload JobCustodyExpiryReceiptPayload,
) (JobCustodyExpiryReceipt, error) {
	if signer == nil || payload.Validate() != nil || payload.DeploymentID != signer.deploymentID {
		return JobCustodyExpiryReceipt{}, ErrInvalid
	}
	encoded, err := json.Marshal(payload)
	if err != nil || len(encoded) > MaximumJobCustodyExpiryReceiptPayloadByteCount {
		return JobCustodyExpiryReceipt{}, ErrInvalid
	}
	signature, err := signer.signRecord(JobCustodyExpiryReceiptSignatureDomain, encoded)
	if err != nil {
		return JobCustodyExpiryReceipt{}, err
	}
	receipt := JobCustodyExpiryReceipt{Payload: encoded, Signature: signature}
	if _, err := receipt.VerifiedPayload(); err != nil {
		return JobCustodyExpiryReceipt{}, err
	}
	return receipt, nil
}

func (receipt JobCustodyExpiryReceipt) VerifiedPayload() (JobCustodyExpiryReceiptPayload, error) {
	var payload JobCustodyExpiryReceiptPayload
	if len(receipt.Payload) == 0 || len(receipt.Payload) > MaximumJobCustodyExpiryReceiptPayloadByteCount ||
		decodeCanonicalJobCustodyExpiryReceipt(receipt.Payload, &payload) != nil ||
		payload.Validate() != nil ||
		verifyCanonicalRecord(receipt.Payload, receipt.Signature,
			JobCustodyExpiryReceiptSignatureDomain, &payload) != nil ||
		receipt.Signature.SignerID != payload.DeploymentID {
		return JobCustodyExpiryReceiptPayload{}, ErrInvalid
	}
	return payload, nil
}

func (receipt JobCustodyExpiryReceipt) Authorize(
	deployment DeploymentDescriptor,
) (JobCustodyExpiryReceiptPayload, error) {
	payload, err := receipt.VerifiedPayload()
	if err != nil || deployment.Validate() != nil || payload.DeploymentID != deployment.DeploymentID ||
		receipt.Signature.SignerID != deployment.DeploymentID ||
		receipt.Signature.PublicSigningKeyX963 != deployment.PublicSigningKeyX963 ||
		receipt.Signature.SigningKeyFingerprint != deployment.SigningKeyFingerprint {
		return JobCustodyExpiryReceiptPayload{}, ErrInvalid
	}
	return payload, nil
}

func (receipt JobCustodyExpiryReceipt) ReferenceDigest() (string, error) {
	if _, err := receipt.VerifiedPayload(); err != nil {
		return "", ErrInvalid
	}
	encodedSignature, err := json.Marshal(receipt.Signature)
	if err != nil {
		return "", ErrInvalid
	}
	digest := sha256.Sum256(append(append(
		[]byte(JobCustodyExpiryReceiptReferenceDomain), receipt.Payload...), encodedSignature...))
	return hex.EncodeToString(digest[:]), nil
}

func (receipt JobCustodyExpiryReceipt) CanonicalJSON() ([]byte, error) {
	if _, err := receipt.VerifiedPayload(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(receipt)
	if err != nil || len(encoded) > MaximumJobCustodyExpiryReceiptRecordByteCount {
		return nil, ErrInvalid
	}
	return encoded, nil
}

func DecodeJobCustodyExpiryReceipt(input []byte) (JobCustodyExpiryReceipt, error) {
	if len(input) == 0 || len(input) > MaximumJobCustodyExpiryReceiptRecordByteCount {
		return JobCustodyExpiryReceipt{}, ErrInvalid
	}
	var receipt JobCustodyExpiryReceipt
	if decodeCanonicalJobCustodyExpiryReceipt(input, &receipt) != nil {
		return JobCustodyExpiryReceipt{}, ErrInvalid
	}
	if _, err := receipt.VerifiedPayload(); err != nil {
		return JobCustodyExpiryReceipt{}, err
	}
	return receipt, nil
}

func decodeCanonicalJobCustodyExpiryReceipt(input []byte, target any) error {
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

// JobCustodyStagingExpiryReceiptPayload proves namespace removal of one exact
// incomplete opaque input after its signed retention bound elapsed. No durable
// input-custody receipt was issued. This does not assert secure-media erasure.
// Field declaration order is canonical sorted-key JSON.
type JobCustodyStagingExpiryReceiptPayload struct {
	AdmissionEnvelopeDigest    string    `json:"admissionEnvelopeDigest"`
	AdmissionPermitDigest      string    `json:"admissionPermitDigest"`
	AssignmentID               uuid.UUID `json:"assignmentID"`
	CapsuleID                  uuid.UUID `json:"capsuleID"`
	CommittedBytes             int64     `json:"committedBytes"`
	DeploymentID               uuid.UUID `json:"deploymentID"`
	ExpiredAtMilliseconds      int64     `json:"expiredAtMilliseconds"`
	Kind                       string    `json:"kind"`
	ProtectedObjectByteCount   int64     `json:"protectedObjectByteCount"`
	ProtectedObjectSHA256      string    `json:"protectedObjectSHA256"`
	RetentionUntilMilliseconds int64     `json:"retentionUntilMilliseconds"`
	Version                    int       `json:"version"`
}

func (payload JobCustodyStagingExpiryReceiptPayload) Validate() error {
	if payload.Version != JobCustodyStagingExpiryReceiptVersion ||
		payload.Kind != JobCustodyStagingExpiryReceiptKind || payload.AssignmentID == uuid.Nil ||
		payload.CapsuleID == uuid.Nil || payload.DeploymentID == uuid.Nil ||
		payload.ProtectedObjectByteCount <= 0 || payload.CommittedBytes < 0 ||
		payload.CommittedBytes > payload.ProtectedObjectByteCount ||
		payload.RetentionUntilMilliseconds <= 0 ||
		payload.ExpiredAtMilliseconds < payload.RetentionUntilMilliseconds ||
		!validDigest(payload.AdmissionEnvelopeDigest) ||
		!validDigest(payload.AdmissionPermitDigest) || !validDigest(payload.ProtectedObjectSHA256) {
		return ErrInvalid
	}
	return nil
}

type JobCustodyStagingExpiryReceipt struct {
	Payload   []byte    `json:"payload"`
	Signature Signature `json:"signature"`
}

func (signer *DeploymentSigner) SignJobCustodyStagingExpiryReceipt(
	payload JobCustodyStagingExpiryReceiptPayload,
) (JobCustodyStagingExpiryReceipt, error) {
	if signer == nil || payload.Validate() != nil || payload.DeploymentID != signer.deploymentID {
		return JobCustodyStagingExpiryReceipt{}, ErrInvalid
	}
	encoded, err := json.Marshal(payload)
	if err != nil || len(encoded) > MaximumJobCustodyStagingExpiryReceiptPayloadByteCount {
		return JobCustodyStagingExpiryReceipt{}, ErrInvalid
	}
	signature, err := signer.signRecord(JobCustodyStagingExpiryReceiptSignatureDomain, encoded)
	if err != nil {
		return JobCustodyStagingExpiryReceipt{}, err
	}
	receipt := JobCustodyStagingExpiryReceipt{Payload: encoded, Signature: signature}
	if _, err := receipt.VerifiedPayload(); err != nil {
		return JobCustodyStagingExpiryReceipt{}, err
	}
	return receipt, nil
}

func (receipt JobCustodyStagingExpiryReceipt) VerifiedPayload() (JobCustodyStagingExpiryReceiptPayload, error) {
	var payload JobCustodyStagingExpiryReceiptPayload
	if len(receipt.Payload) == 0 ||
		len(receipt.Payload) > MaximumJobCustodyStagingExpiryReceiptPayloadByteCount ||
		decodeCanonicalJobCustodyStagingExpiryReceipt(receipt.Payload, &payload) != nil ||
		payload.Validate() != nil ||
		verifyCanonicalRecord(receipt.Payload, receipt.Signature,
			JobCustodyStagingExpiryReceiptSignatureDomain, &payload) != nil ||
		receipt.Signature.SignerID != payload.DeploymentID {
		return JobCustodyStagingExpiryReceiptPayload{}, ErrInvalid
	}
	return payload, nil
}

func (receipt JobCustodyStagingExpiryReceipt) Authorize(
	deployment DeploymentDescriptor,
) (JobCustodyStagingExpiryReceiptPayload, error) {
	payload, err := receipt.VerifiedPayload()
	if err != nil || deployment.Validate() != nil || payload.DeploymentID != deployment.DeploymentID ||
		receipt.Signature.SignerID != deployment.DeploymentID ||
		receipt.Signature.PublicSigningKeyX963 != deployment.PublicSigningKeyX963 ||
		receipt.Signature.SigningKeyFingerprint != deployment.SigningKeyFingerprint {
		return JobCustodyStagingExpiryReceiptPayload{}, ErrInvalid
	}
	return payload, nil
}

func (receipt JobCustodyStagingExpiryReceipt) ReferenceDigest() (string, error) {
	if _, err := receipt.VerifiedPayload(); err != nil {
		return "", ErrInvalid
	}
	encodedSignature, err := json.Marshal(receipt.Signature)
	if err != nil {
		return "", ErrInvalid
	}
	digest := sha256.Sum256(append(append(
		[]byte(JobCustodyStagingExpiryReceiptReferenceDomain), receipt.Payload...), encodedSignature...))
	return hex.EncodeToString(digest[:]), nil
}

func (receipt JobCustodyStagingExpiryReceipt) CanonicalJSON() ([]byte, error) {
	if _, err := receipt.VerifiedPayload(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(receipt)
	if err != nil || len(encoded) > MaximumJobCustodyStagingExpiryReceiptRecordByteCount {
		return nil, ErrInvalid
	}
	return encoded, nil
}

func DecodeJobCustodyStagingExpiryReceipt(input []byte) (JobCustodyStagingExpiryReceipt, error) {
	if len(input) == 0 || len(input) > MaximumJobCustodyStagingExpiryReceiptRecordByteCount {
		return JobCustodyStagingExpiryReceipt{}, ErrInvalid
	}
	var receipt JobCustodyStagingExpiryReceipt
	if decodeCanonicalJobCustodyStagingExpiryReceipt(input, &receipt) != nil {
		return JobCustodyStagingExpiryReceipt{}, ErrInvalid
	}
	if _, err := receipt.VerifiedPayload(); err != nil {
		return JobCustodyStagingExpiryReceipt{}, err
	}
	return receipt, nil
}

func decodeCanonicalJobCustodyStagingExpiryReceipt(input []byte, target any) error {
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
