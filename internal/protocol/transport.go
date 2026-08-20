package protocol

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/google/uuid"
)

const CurrentVersion = 1

type PayloadKind string

const (
	PayloadFEFCheckpoint     PayloadKind = "fef_checkpoint"
	PayloadFEFMutationBatch  PayloadKind = "fef_mutation_batch"
	PayloadControlMessage    PayloadKind = "control_message"
	PayloadBlobManifest      PayloadKind = "blob_manifest"
	PayloadDeliveryReceipt   PayloadKind = "delivery_receipt"
	PayloadCorrectionReceipt PayloadKind = "correction_receipt"
	PayloadAIJobRequest      PayloadKind = "ai_job_request"
	PayloadAIJobResult       PayloadKind = "ai_job_result"
)

var PayloadKinds = []PayloadKind{
	PayloadFEFCheckpoint,
	PayloadFEFMutationBatch,
	PayloadControlMessage,
	PayloadBlobManifest,
	PayloadDeliveryReceipt,
	PayloadCorrectionReceipt,
	PayloadAIJobRequest,
	PayloadAIJobResult,
}

type DeliveryStage string

const (
	DeliveryAccepted         DeliveryStage = "accepted"
	DeliveryCanonicalApplied DeliveryStage = "canonical_applied"
)

type CorrectionCode string

const (
	CorrectionMissingDependency   CorrectionCode = "missing_dependency"
	CorrectionInvalidPayload      CorrectionCode = "invalid_payload"
	CorrectionUnauthorized        CorrectionCode = "unauthorized"
	CorrectionConflict            CorrectionCode = "conflict"
	CorrectionQuotaExceeded       CorrectionCode = "quota_exceeded"
	CorrectionUnsupportedProtocol CorrectionCode = "unsupported_protocol"
)

var (
	ErrUnsupportedVersion          = errors.New("unsupported transport version")
	ErrInvalidEnvelope             = errors.New("invalid transport envelope")
	ErrInvalidDependencies         = errors.New("invalid transport dependencies")
	ErrInvalidBlob                 = errors.New("invalid blob reference")
	ErrDuplicateBlob               = errors.New("duplicate blob reference")
	ErrPayloadDigest               = errors.New("payload digest mismatch")
	ErrInvalidReceipt              = errors.New("invalid receipt")
	ErrInvalidCorrectionBundle     = errors.New("invalid correction bundle")
	ErrCorrectionDependencyMissing = errors.New("corrected bundle does not satisfy a requested dependency")
	ErrCorrectionDependencyCycle   = errors.New("corrected bundle contains a dependency cycle")
)

type BlobReference struct {
	BlobID      string `json:"blobID"`
	SHA256      string `json:"sha256"`
	ByteCount   int64  `json:"byteCount"`
	ContentType string `json:"contentType"`
}

func (reference BlobReference) Validate() error {
	if strings.TrimSpace(reference.BlobID) == "" ||
		!isLowercaseSHA256(reference.SHA256) ||
		reference.ByteCount < 0 ||
		strings.TrimSpace(reference.ContentType) == "" {
		return ErrInvalidBlob
	}
	return nil
}

type TransportEnvelope struct {
	Version               int             `json:"version"`
	Kind                  PayloadKind     `json:"kind"`
	MessageID             uuid.UUID       `json:"messageID"`
	CreatedAtMilliseconds int64           `json:"createdAtMilliseconds"`
	PayloadContentType    string          `json:"payloadContentType"`
	PayloadSHA256         string          `json:"payloadSHA256"`
	PayloadBase64URL      string          `json:"payloadBase64URL"`
	DependencyMessageIDs  []uuid.UUID     `json:"dependencyMessageIDs"`
	BlobReferences        []BlobReference `json:"blobReferences"`
}

func NewTransportEnvelope(
	kind PayloadKind,
	messageID uuid.UUID,
	createdAtMilliseconds int64,
	payloadContentType string,
	payload []byte,
	dependencyMessageIDs []uuid.UUID,
	blobReferences []BlobReference,
) (TransportEnvelope, error) {
	digest := sha256.Sum256(payload)
	envelope := TransportEnvelope{
		Version:               CurrentVersion,
		Kind:                  kind,
		MessageID:             messageID,
		CreatedAtMilliseconds: createdAtMilliseconds,
		PayloadContentType:    strings.TrimSpace(payloadContentType),
		PayloadSHA256:         hex.EncodeToString(digest[:]),
		PayloadBase64URL:      base64.RawURLEncoding.EncodeToString(payload),
		DependencyMessageIDs:  slices.Clone(dependencyMessageIDs),
		BlobReferences:        slices.Clone(blobReferences),
	}
	envelope.normalize()
	if err := envelope.Validate(); err != nil {
		return TransportEnvelope{}, err
	}
	return envelope, nil
}

func (envelope TransportEnvelope) Validate() error {
	if envelope.Version != CurrentVersion {
		return fmt.Errorf("%w: %d", ErrUnsupportedVersion, envelope.Version)
	}
	if !slices.Contains(PayloadKinds, envelope.Kind) ||
		envelope.MessageID == uuid.Nil ||
		envelope.CreatedAtMilliseconds < 0 ||
		strings.TrimSpace(envelope.PayloadContentType) == "" ||
		!isLowercaseSHA256(envelope.PayloadSHA256) {
		return ErrInvalidEnvelope
	}

	seenDependencies := make(map[uuid.UUID]struct{}, len(envelope.DependencyMessageIDs))
	for _, dependency := range envelope.DependencyMessageIDs {
		if dependency == uuid.Nil || dependency == envelope.MessageID {
			return ErrInvalidDependencies
		}
		if _, exists := seenDependencies[dependency]; exists {
			return ErrInvalidDependencies
		}
		seenDependencies[dependency] = struct{}{}
	}

	seenBlobs := make(map[string]struct{}, len(envelope.BlobReferences))
	for _, reference := range envelope.BlobReferences {
		if err := reference.Validate(); err != nil {
			return err
		}
		if _, exists := seenBlobs[reference.BlobID]; exists {
			return ErrDuplicateBlob
		}
		seenBlobs[reference.BlobID] = struct{}{}
	}

	_, err := envelope.PayloadBytes()
	return err
}

func (envelope TransportEnvelope) PayloadBytes() ([]byte, error) {
	payload, err := base64.RawURLEncoding.DecodeString(envelope.PayloadBase64URL)
	if err != nil || base64.RawURLEncoding.EncodeToString(payload) != envelope.PayloadBase64URL {
		return nil, ErrPayloadDigest
	}
	digest := sha256.Sum256(payload)
	if hex.EncodeToString(digest[:]) != envelope.PayloadSHA256 {
		return nil, ErrPayloadDigest
	}
	return payload, nil
}

func (envelope TransportEnvelope) CanonicalJSON() ([]byte, error) {
	normalized := envelope
	normalized.normalize()
	if err := normalized.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(normalized)
}

func (envelope *TransportEnvelope) normalize() {
	sort.Slice(envelope.DependencyMessageIDs, func(i, j int) bool {
		return strings.ToLower(envelope.DependencyMessageIDs[i].String()) <
			strings.ToLower(envelope.DependencyMessageIDs[j].String())
	})
	sort.Slice(envelope.BlobReferences, func(i, j int) bool {
		if envelope.BlobReferences[i].BlobID == envelope.BlobReferences[j].BlobID {
			return envelope.BlobReferences[i].SHA256 < envelope.BlobReferences[j].SHA256
		}
		return envelope.BlobReferences[i].BlobID < envelope.BlobReferences[j].BlobID
	})
}

func (envelope *TransportEnvelope) UnmarshalJSON(data []byte) error {
	type rawEnvelope TransportEnvelope
	var decoded rawEnvelope
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	candidate := TransportEnvelope(decoded)
	candidate.normalize()
	if err := candidate.Validate(); err != nil {
		return err
	}
	*envelope = candidate
	return nil
}

type DeliveryReceipt struct {
	Version                int           `json:"version"`
	ReferencedMessageID    uuid.UUID     `json:"referencedMessageID"`
	RecipientID            string        `json:"recipientID"`
	Stage                  DeliveryStage `json:"stage"`
	RecordedAtMilliseconds int64         `json:"recordedAtMilliseconds"`
}

func NewDeliveryReceipt(messageID uuid.UUID, recipientID string, stage DeliveryStage, recordedAtMilliseconds int64) (DeliveryReceipt, error) {
	receipt := DeliveryReceipt{CurrentVersion, messageID, strings.TrimSpace(recipientID), stage, recordedAtMilliseconds}
	return receipt, receipt.Validate()
}

func (receipt DeliveryReceipt) Validate() error {
	if receipt.Version != CurrentVersion {
		return fmt.Errorf("%w: %d", ErrUnsupportedVersion, receipt.Version)
	}
	if receipt.ReferencedMessageID == uuid.Nil || strings.TrimSpace(receipt.RecipientID) == "" ||
		receipt.RecordedAtMilliseconds < 0 ||
		(receipt.Stage != DeliveryAccepted && receipt.Stage != DeliveryCanonicalApplied) {
		return ErrInvalidReceipt
	}
	return nil
}

type CorrectionReceipt struct {
	Version                int            `json:"version"`
	ReferencedMessageID    uuid.UUID      `json:"referencedMessageID"`
	RecipientID            string         `json:"recipientID"`
	Code                   CorrectionCode `json:"code"`
	MissingDependencyIDs   []string       `json:"missingDependencyIDs"`
	RecordedAtMilliseconds int64          `json:"recordedAtMilliseconds"`
}

func NewCorrectionReceipt(messageID uuid.UUID, recipientID string, code CorrectionCode, missing []string, recordedAtMilliseconds int64) (CorrectionReceipt, error) {
	trimmed := make([]string, len(missing))
	for index, value := range missing {
		trimmed[index] = strings.TrimSpace(value)
	}
	sort.Strings(trimmed)
	receipt := CorrectionReceipt{CurrentVersion, messageID, strings.TrimSpace(recipientID), code, trimmed, recordedAtMilliseconds}
	return receipt, receipt.Validate()
}

func (receipt CorrectionReceipt) Validate() error {
	if receipt.Version != CurrentVersion {
		return fmt.Errorf("%w: %d", ErrUnsupportedVersion, receipt.Version)
	}
	validCode := receipt.Code == CorrectionMissingDependency || receipt.Code == CorrectionInvalidPayload ||
		receipt.Code == CorrectionUnauthorized || receipt.Code == CorrectionConflict ||
		receipt.Code == CorrectionQuotaExceeded || receipt.Code == CorrectionUnsupportedProtocol
	if receipt.ReferencedMessageID == uuid.Nil || strings.TrimSpace(receipt.RecipientID) == "" ||
		receipt.RecordedAtMilliseconds < 0 || !validCode {
		return ErrInvalidReceipt
	}
	seen := make(map[string]struct{}, len(receipt.MissingDependencyIDs))
	for _, dependency := range receipt.MissingDependencyIDs {
		if strings.TrimSpace(dependency) == "" {
			return ErrInvalidReceipt
		}
		if _, exists := seen[dependency]; exists {
			return ErrInvalidReceipt
		}
		seen[dependency] = struct{}{}
	}
	if receipt.Code != CorrectionMissingDependency && len(receipt.MissingDependencyIDs) != 0 {
		return ErrInvalidReceipt
	}
	return nil
}

// CorrectedBundle returns a deterministic, dependency-ordered repair bundle for
// a typed missing-dependency receipt. The server does not call this function
// and never reconstructs a semantic Facets graph: an authenticated sender
// supplies the complete transport bundle and a receiving client verifies that
// it fulfils the explicit request before applying it through the FEF importer.
//
// A requested dependency is satisfied by either an envelope message ID or a
// blob identifier included in the correction. Dependencies not named by the
// receipt may be external anchors the receiver already has; only in-bundle
// dependency edges affect the returned ordering.
func CorrectedBundle(receipt CorrectionReceipt, envelopes []TransportEnvelope) ([]TransportEnvelope, error) {
	if err := receipt.Validate(); err != nil || receipt.Code != CorrectionMissingDependency {
		return nil, ErrInvalidCorrectionBundle
	}

	byMessageID := make(map[uuid.UUID]TransportEnvelope, len(envelopes))
	blobIDs := make(map[string]struct{})
	for _, envelope := range envelopes {
		if err := envelope.Validate(); err != nil {
			return nil, err
		}
		if _, exists := byMessageID[envelope.MessageID]; exists {
			return nil, ErrInvalidCorrectionBundle
		}
		byMessageID[envelope.MessageID] = envelope
		for _, reference := range envelope.BlobReferences {
			blobIDs[reference.BlobID] = struct{}{}
		}
	}
	if _, exists := byMessageID[receipt.ReferencedMessageID]; !exists {
		return nil, ErrInvalidCorrectionBundle
	}
	for _, required := range receipt.MissingDependencyIDs {
		if messageID, err := uuid.Parse(required); err == nil {
			if _, exists := byMessageID[messageID]; exists {
				continue
			}
		}
		if _, exists := blobIDs[required]; !exists {
			return nil, ErrCorrectionDependencyMissing
		}
	}

	remaining := make(map[uuid.UUID]TransportEnvelope, len(byMessageID))
	for messageID, envelope := range byMessageID {
		remaining[messageID] = envelope
	}
	ordered := make([]TransportEnvelope, 0, len(envelopes))
	for len(remaining) > 0 {
		ready := make([]uuid.UUID, 0, len(remaining))
		for messageID, envelope := range remaining {
			blocked := false
			for _, dependency := range envelope.DependencyMessageIDs {
				if _, exists := remaining[dependency]; exists {
					blocked = true
					break
				}
			}
			if !blocked {
				ready = append(ready, messageID)
			}
		}
		if len(ready) == 0 {
			return nil, ErrCorrectionDependencyCycle
		}
		sort.Slice(ready, func(i, j int) bool {
			return strings.ToLower(ready[i].String()) < strings.ToLower(ready[j].String())
		})
		for _, messageID := range ready {
			ordered = append(ordered, remaining[messageID])
			delete(remaining, messageID)
		}
	}
	return ordered, nil
}

func isLowercaseSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}
