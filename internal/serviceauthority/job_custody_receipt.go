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
	JobCustodyReceiptVersion                 = 1
	MaximumJobCustodyReceiptPayloadByteCount = 32 * 1024
	MaximumJobCustodyReceiptRecordByteCount  = 40 * 1024
	JobCustodyCommittedReceiptKind           = "custody_committed"
	JobCustodyReceiptSignatureDomain         = "Facets Job Custody committed receipt v1\x00"
	JobCustodyReceiptReferenceDomain         = "Facets Job Custody committed receipt reference v1\x00"
)

// JobCustodyReceiptPayload proves only durable custody of one exact opaque
// protected object. Inner occurrence, attempt, object, prompt, model, and
// Space identities remain encrypted inside the Job Capsule and are
// intentionally absent from this Box-visible contract.
//
// Field declaration order is canonical sorted-key JSON and must remain in
// lockstep with the portable Swift verifier.
type JobCustodyReceiptPayload struct {
	AdmissionEnvelopeDigest         string    `json:"admissionEnvelopeDigest"`
	AdmissionIdempotencyKey         string    `json:"admissionIdempotencyKey"`
	AdmissionPermitDigest           string    `json:"admissionPermitDigest"`
	AssignmentID                    uuid.UUID `json:"assignmentID"`
	CapsuleID                       uuid.UUID `json:"capsuleID"`
	CommittedAtMilliseconds         int64     `json:"committedAtMilliseconds"`
	DeploymentID                    uuid.UUID `json:"deploymentID"`
	Kind                            string    `json:"kind"`
	ProtectedObjectByteCount        int64     `json:"protectedObjectByteCount"`
	ProtectedObjectDescriptorDigest string    `json:"protectedObjectDescriptorDigest"`
	ProtectedObjectSHA256           string    `json:"protectedObjectSHA256"`
	RetentionUntilMilliseconds      int64     `json:"retentionUntilMilliseconds"`
	Version                         int       `json:"version"`
}

func (payload JobCustodyReceiptPayload) Validate() error {
	if payload.Version != JobCustodyReceiptVersion ||
		payload.Kind != JobCustodyCommittedReceiptKind ||
		payload.AssignmentID == uuid.Nil || payload.CapsuleID == uuid.Nil ||
		payload.DeploymentID == uuid.Nil || payload.CommittedAtMilliseconds < 0 ||
		payload.RetentionUntilMilliseconds < payload.CommittedAtMilliseconds ||
		payload.ProtectedObjectByteCount <= 0 ||
		!validDigest(payload.AdmissionEnvelopeDigest) ||
		!validDigest(payload.AdmissionIdempotencyKey) ||
		!validDigest(payload.AdmissionPermitDigest) ||
		!validDigest(payload.ProtectedObjectDescriptorDigest) ||
		!validDigest(payload.ProtectedObjectSHA256) {
		return ErrInvalid
	}
	return nil
}

type JobCustodyReceipt struct {
	Payload   []byte    `json:"payload"`
	Signature Signature `json:"signature"`
}

func (signer *DeploymentSigner) SignJobCustodyReceipt(
	payload JobCustodyReceiptPayload,
) (JobCustodyReceipt, error) {
	if signer == nil || payload.Validate() != nil ||
		payload.DeploymentID != signer.deploymentID {
		return JobCustodyReceipt{}, ErrInvalid
	}
	encoded, err := json.Marshal(payload)
	if err != nil || len(encoded) > MaximumJobCustodyReceiptPayloadByteCount {
		return JobCustodyReceipt{}, ErrInvalid
	}
	signature, err := signer.signRecord(JobCustodyReceiptSignatureDomain, encoded)
	if err != nil {
		return JobCustodyReceipt{}, err
	}
	receipt := JobCustodyReceipt{Payload: encoded, Signature: signature}
	if _, err := receipt.VerifiedPayload(); err != nil {
		return JobCustodyReceipt{}, err
	}
	return receipt, nil
}

// VerifiedPayload verifies internal canonical encoding and signature
// integrity. It does not establish that the signer is the selected Job
// Custody deployment; callers must also call Authorize with the owner-pinned
// deployment descriptor.
func (receipt JobCustodyReceipt) VerifiedPayload() (JobCustodyReceiptPayload, error) {
	var payload JobCustodyReceiptPayload
	if len(receipt.Payload) == 0 ||
		len(receipt.Payload) > MaximumJobCustodyReceiptPayloadByteCount ||
		decodeCanonicalJobCustodyReceipt(receipt.Payload, &payload) != nil ||
		payload.Validate() != nil ||
		verifyCanonicalRecord(receipt.Payload, receipt.Signature,
			JobCustodyReceiptSignatureDomain, &payload) != nil ||
		receipt.Signature.SignerID != payload.DeploymentID {
		return JobCustodyReceiptPayload{}, ErrInvalid
	}
	return payload, nil
}

func (receipt JobCustodyReceipt) Authorize(
	deployment DeploymentDescriptor,
) (JobCustodyReceiptPayload, error) {
	payload, err := receipt.VerifiedPayload()
	if err != nil || deployment.Validate() != nil ||
		payload.DeploymentID != deployment.DeploymentID ||
		receipt.Signature.SignerID != deployment.DeploymentID ||
		receipt.Signature.PublicSigningKeyX963 != deployment.PublicSigningKeyX963 ||
		receipt.Signature.SigningKeyFingerprint != deployment.SigningKeyFingerprint {
		return JobCustodyReceiptPayload{}, ErrInvalid
	}
	return payload, nil
}

func (receipt JobCustodyReceipt) ReferenceDigest() (string, error) {
	if _, err := receipt.VerifiedPayload(); err != nil {
		return "", ErrInvalid
	}
	encodedSignature, err := json.Marshal(receipt.Signature)
	if err != nil {
		return "", ErrInvalid
	}
	digest := sha256.Sum256(append(append(
		[]byte(JobCustodyReceiptReferenceDomain), receipt.Payload...),
		encodedSignature...))
	return hex.EncodeToString(digest[:]), nil
}

func (receipt JobCustodyReceipt) CanonicalJSON() ([]byte, error) {
	if _, err := receipt.VerifiedPayload(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(receipt)
	if err != nil || len(encoded) > MaximumJobCustodyReceiptRecordByteCount {
		return nil, ErrInvalid
	}
	return encoded, nil
}

func DecodeJobCustodyReceipt(input []byte) (JobCustodyReceipt, error) {
	if len(input) == 0 || len(input) > MaximumJobCustodyReceiptRecordByteCount {
		return JobCustodyReceipt{}, ErrInvalid
	}
	var receipt JobCustodyReceipt
	if decodeCanonicalJobCustodyReceipt(input, &receipt) != nil {
		return JobCustodyReceipt{}, ErrInvalid
	}
	if _, err := receipt.VerifiedPayload(); err != nil {
		return JobCustodyReceipt{}, err
	}
	return receipt, nil
}

func decodeCanonicalJobCustodyReceipt(input []byte, target any) error {
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
