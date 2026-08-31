// Package backupcustody defines content-blind request validation only. It has
// no HTTP handler, database, object store, or authority to issue receipts.
package backupcustody

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

const Version = 1

const MaximumRequestByteCount = 32 * 1024

const (
	outerMagic               = "facets.backup.outer.v1\x00"
	maximumHeaderBytes       = 128 * 1024
	maximumCatalogBytes      = 128 * 1024
	maximumFinalizationBytes = 4 * 1024
	recoveryChunkBytes       = 1024 * 1024
	aesGCMOverhead           = 28
)

type Capability string

const (
	Publish        Capability = "publish"
	Read           Capability = "read"
	RetentionProof Capability = "retention_proof"
)

type AccountAdmissionReference struct {
	AccountID             uuid.UUID `json:"accountID"`
	AdmissionID           uuid.UUID `json:"admissionID"`
	ExpiresAtMilliseconds int64     `json:"expiresAtMilliseconds"`
	RequestNonce          string    `json:"requestNonce"`
	Version               int       `json:"version"`
}

func (reference AccountAdmissionReference) Validate() error {
	if reference.Version != Version || reference.AccountID == uuid.Nil ||
		reference.AdmissionID == uuid.Nil || reference.ExpiresAtMilliseconds < 0 ||
		!validNonce(reference.RequestNonce) {
		return serviceauthority.ErrInvalid
	}
	return nil
}

type TargetCredentialReference struct {
	AccountID             uuid.UUID    `json:"accountID"`
	BackupSetID           uuid.UUID    `json:"backupSetID"`
	Capabilities          []Capability `json:"capabilities"`
	CredentialID          uuid.UUID    `json:"credentialID"`
	ExpiresAtMilliseconds int64        `json:"expiresAtMilliseconds"`
	RequestNonce          string       `json:"requestNonce"`
	TargetID              uuid.UUID    `json:"targetID"`
	Version               int          `json:"version"`
}

func (reference TargetCredentialReference) Validate() error {
	if reference.Version != Version || reference.AccountID == uuid.Nil ||
		reference.BackupSetID == uuid.Nil || reference.TargetID == uuid.Nil ||
		reference.CredentialID == uuid.Nil || reference.ExpiresAtMilliseconds < 0 ||
		!validNonce(reference.RequestNonce) || len(reference.Capabilities) == 0 {
		return serviceauthority.ErrInvalid
	}
	previous := Capability("")
	for _, capability := range reference.Capabilities {
		if (capability != Publish && capability != Read && capability != RetentionProof) ||
			(previous != "" && strings.Compare(string(previous), string(capability)) >= 0) {
			return serviceauthority.ErrInvalid
		}
		previous = capability
	}
	return nil
}

func (reference TargetCredentialReference) Admits(capability Capability, at int64) bool {
	if reference.Validate() != nil || at < 0 || at >= reference.ExpiresAtMilliseconds {
		return false
	}
	for _, candidate := range reference.Capabilities {
		if candidate == capability {
			return true
		}
	}
	return false
}

type PublishRequest struct {
	Credential                  TargetCredentialReference `json:"credential"`
	ExpectedHeadReferenceDigest *string                   `json:"expectedHeadReferenceDigest,omitempty"`
	Generation                  uint64                    `json:"generation"`
	RequestID                   uuid.UUID                 `json:"requestID"`
	RequestedAtMilliseconds     int64                     `json:"requestedAtMilliseconds"`
	Version                     int                       `json:"version"`
}

func (request PublishRequest) Validate() error {
	if request.Version != Version || request.RequestID == uuid.Nil || request.Generation == 0 ||
		!request.Credential.Admits(Publish, request.RequestedAtMilliseconds) {
		return serviceauthority.ErrInvalid
	}
	if request.Generation == 1 {
		if request.ExpectedHeadReferenceDigest != nil {
			return serviceauthority.ErrInvalid
		}
	} else if request.ExpectedHeadReferenceDigest == nil || !validHexDigest(*request.ExpectedHeadReferenceDigest) {
		return serviceauthority.ErrInvalid
	}
	return nil
}

func (request PublishRequest) Scope() (serviceauthority.Scope, error) {
	if request.Validate() != nil {
		return serviceauthority.Scope{}, serviceauthority.ErrInvalid
	}
	return serviceauthority.Scope{Kind: serviceauthority.ScopeBackupCustody, ScopeID: request.Credential.AccountID}, nil
}

// ComputeGenerationRecord validates the bounded, content-blind Backup wire and
// computes the exact digest and byte count from accepted bytes. The client does
// not supply either value. The supplied predecessor is the current atomic head.
func ComputeGenerationRecord(
	request PublishRequest,
	uploadID uuid.UUID,
	acceptedOuterBytes []byte,
	predecessor *serviceauthority.BackupCustodyGenerationRecord,
) (serviceauthority.BackupCustodyGenerationRecord, error) {
	if request.Validate() != nil || uploadID == uuid.Nil || len(acceptedOuterBytes) == 0 {
		return serviceauthority.BackupCustodyGenerationRecord{}, serviceauthority.ErrInvalid
	}
	predecessorReference := (*string)(nil)
	if request.Generation == 1 {
		if predecessor != nil || request.ExpectedHeadReferenceDigest != nil {
			return serviceauthority.BackupCustodyGenerationRecord{}, serviceauthority.ErrInvalid
		}
	} else {
		if predecessor == nil || predecessor.Validate() != nil ||
			predecessor.AccountID != request.Credential.AccountID ||
			predecessor.TargetID != request.Credential.TargetID ||
			predecessor.BackupSetID != request.Credential.BackupSetID ||
			predecessor.Generation == ^uint64(0) || request.Generation != predecessor.Generation+1 {
			return serviceauthority.BackupCustodyGenerationRecord{}, serviceauthority.ErrInvalid
		}
		reference, err := predecessor.ReferenceDigest()
		if err != nil || request.ExpectedHeadReferenceDigest == nil ||
			*request.ExpectedHeadReferenceDigest != reference {
			return serviceauthority.BackupCustodyGenerationRecord{}, serviceauthority.ErrInvalid
		}
		predecessorReference = &reference
	}
	header, err := validateOuterWire(acceptedOuterBytes)
	if err != nil || header.BackupSetID != request.Credential.BackupSetID ||
		header.Generation != request.Generation {
		return serviceauthority.BackupCustodyGenerationRecord{}, serviceauthority.ErrInvalid
	}
	if predecessor == nil {
		if header.PredecessorOuterDigest != nil {
			return serviceauthority.BackupCustodyGenerationRecord{}, serviceauthority.ErrInvalid
		}
	} else if header.PredecessorOuterDigest == nil || *header.PredecessorOuterDigest != predecessor.OuterDigest {
		return serviceauthority.BackupCustodyGenerationRecord{}, serviceauthority.ErrInvalid
	}
	digest := sha256.Sum256(acceptedOuterBytes)
	record := serviceauthority.BackupCustodyGenerationRecord{
		AccountID:                  request.Credential.AccountID,
		BackupSetID:                request.Credential.BackupSetID,
		Generation:                 request.Generation,
		OuterByteCount:             uint64(len(acceptedOuterBytes)),
		OuterDigest:                base64.RawURLEncoding.EncodeToString(digest[:]),
		PredecessorReferenceDigest: predecessorReference,
		TargetID:                   request.Credential.TargetID,
		UploadID:                   uploadID,
		Version:                    Version,
	}
	if record.Validate() != nil {
		return serviceauthority.BackupCustodyGenerationRecord{}, serviceauthority.ErrInvalid
	}
	return record, nil
}

type ReadRequest struct {
	Credential                TargetCredentialReference `json:"credential"`
	GenerationReferenceDigest *string                   `json:"generationReferenceDigest,omitempty"`
	RequestID                 uuid.UUID                 `json:"requestID"`
	RequestedAtMilliseconds   int64                     `json:"requestedAtMilliseconds"`
	Version                   int                       `json:"version"`
}

func (request ReadRequest) Validate() error {
	if request.Version != Version || request.RequestID == uuid.Nil ||
		!request.Credential.Admits(Read, request.RequestedAtMilliseconds) ||
		(request.GenerationReferenceDigest != nil && !validHexDigest(*request.GenerationReferenceDigest)) {
		return serviceauthority.ErrInvalid
	}
	return nil
}

func (request ReadRequest) Scope() (serviceauthority.Scope, error) {
	if request.Validate() != nil {
		return serviceauthority.Scope{}, serviceauthority.ErrInvalid
	}
	return serviceauthority.Scope{
		Kind: serviceauthority.ScopeBackupCustody, ScopeID: request.Credential.AccountID,
	}, nil
}

type RetentionProofRequest struct {
	Credential                         TargetCredentialReference `json:"credential"`
	CustodyReceiptReferenceDigest      string                    `json:"custodyReceiptReferenceDigest"`
	GenerationReferenceDigest          string                    `json:"generationReferenceDigest"`
	RequestID                          uuid.UUID                 `json:"requestID"`
	RequestedAtMilliseconds            int64                     `json:"requestedAtMilliseconds"`
	MinimumRetainedThroughMilliseconds int64                     `json:"minimumRetainedThroughMilliseconds"`
	Version                            int                       `json:"version"`
}

func (request RetentionProofRequest) Validate() error {
	if request.Version != Version || request.RequestID == uuid.Nil ||
		!request.Credential.Admits(RetentionProof, request.RequestedAtMilliseconds) ||
		!validHexDigest(request.CustodyReceiptReferenceDigest) ||
		!validHexDigest(request.GenerationReferenceDigest) ||
		request.MinimumRetainedThroughMilliseconds < request.RequestedAtMilliseconds {
		return serviceauthority.ErrInvalid
	}
	return nil
}

func (request RetentionProofRequest) Scope() (serviceauthority.Scope, error) {
	if request.Validate() != nil {
		return serviceauthority.Scope{}, serviceauthority.ErrInvalid
	}
	return serviceauthority.Scope{
		Kind: serviceauthority.ScopeBackupCustody, ScopeID: request.Credential.AccountID,
	}, nil
}

func validNonce(value string) bool {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func DecodeAccountAdmissionReference(input []byte) (AccountAdmissionReference, error) {
	var value AccountAdmissionReference
	if decodeCanonical(input, &value) != nil || value.Validate() != nil {
		return value, serviceauthority.ErrInvalid
	}
	return value, nil
}

func DecodeTargetCredentialReference(input []byte) (TargetCredentialReference, error) {
	var value TargetCredentialReference
	if decodeCanonical(input, &value) != nil || value.Validate() != nil {
		return value, serviceauthority.ErrInvalid
	}
	return value, nil
}

func DecodePublishRequest(input []byte) (PublishRequest, error) {
	var value PublishRequest
	if decodeCanonical(input, &value) != nil || value.Validate() != nil {
		return value, serviceauthority.ErrInvalid
	}
	return value, nil
}

func DecodeReadRequest(input []byte) (ReadRequest, error) {
	var value ReadRequest
	if decodeCanonical(input, &value) != nil || value.Validate() != nil {
		return value, serviceauthority.ErrInvalid
	}
	return value, nil
}

func DecodeRetentionProofRequest(input []byte) (RetentionProofRequest, error) {
	var value RetentionProofRequest
	if decodeCanonical(input, &value) != nil || value.Validate() != nil {
		return value, serviceauthority.ErrInvalid
	}
	return value, nil
}

func decodeCanonical(input []byte, target any) error {
	if len(input) == 0 || len(input) > MaximumRequestByteCount {
		return serviceauthority.ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return serviceauthority.ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return serviceauthority.ErrInvalid
	}
	encoded, err := json.Marshal(target)
	if err != nil || !bytes.Equal(encoded, input) {
		return serviceauthority.ErrInvalid
	}
	return nil
}

func validHexDigest(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

type backupOuterHeader struct {
	BackupSetID            uuid.UUID             `json:"backupSetID"`
	Generation             uint64                `json:"generation"`
	PredecessorOuterDigest *string               `json:"predecessorOuterDigest,omitempty"`
	RecipientSlots         []backupRecipientSlot `json:"recipientSlots"`
	Version                int                   `json:"version"`
}

type backupRecipientSlot struct {
	EphemeralPublicKey []byte `json:"ephemeralPublicKey"`
	SealedContentKey   []byte `json:"sealedContentKey"`
}

func validateOuterWire(input []byte) (backupOuterHeader, error) {
	var header backupOuterHeader
	if len(input) <= len(outerMagic)+4 || string(input[:len(outerMagic)]) != outerMagic {
		return header, serviceauthority.ErrInvalid
	}
	headerCount := int(binary.BigEndian.Uint32(input[len(outerMagic) : len(outerMagic)+4]))
	headerStart := len(outerMagic) + 4
	if headerCount <= 0 || headerCount > maximumHeaderBytes || headerStart+headerCount >= len(input) {
		return header, serviceauthority.ErrInvalid
	}
	headerBytes := input[headerStart : headerStart+headerCount]
	decoder := json.NewDecoder(bytes.NewReader(headerBytes))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&header) != nil {
		return header, serviceauthority.ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return header, serviceauthority.ErrInvalid
	}
	canonical, err := json.Marshal(header)
	if err != nil || !bytes.Equal(canonical, headerBytes) || header.Version != Version ||
		header.BackupSetID == uuid.Nil || header.Generation == 0 ||
		(header.Generation == 1) != (header.PredecessorOuterDigest == nil) ||
		(header.PredecessorOuterDigest != nil && !validBase64URLDigest(*header.PredecessorOuterDigest)) ||
		!slotBucket(len(header.RecipientSlots)) {
		return header, serviceauthority.ErrInvalid
	}
	seen := make(map[string]struct{}, len(header.RecipientSlots))
	var previous backupRecipientSlot
	for index, slot := range header.RecipientSlots {
		if len(slot.EphemeralPublicKey) != 32 || len(slot.SealedContentKey) != 60 {
			return header, serviceauthority.ErrInvalid
		}
		key := string(slot.EphemeralPublicKey)
		if _, duplicate := seen[key]; duplicate {
			return header, serviceauthority.ErrInvalid
		}
		seen[key] = struct{}{}
		if index > 0 && compareSlots(previous, slot) >= 0 {
			return header, serviceauthority.ErrInvalid
		}
		previous = slot
	}
	offset := headerStart + headerCount
	expectedRecovery := uint64(0)
	seenCatalog := false
	seenRecovery := false
	previousRecoveryLength := 0
	for offset < len(input) {
		if offset+13 > len(input) {
			return header, serviceauthority.ErrInvalid
		}
		kind := input[offset]
		index := binary.BigEndian.Uint64(input[offset+1 : offset+9])
		count := int(binary.BigEndian.Uint32(input[offset+9 : offset+13]))
		offset += 13
		maximum := 0
		switch kind {
		case 1:
			maximum = maximumCatalogBytes + aesGCMOverhead
		case 2:
			maximum = recoveryChunkBytes + aesGCMOverhead
		case 3:
			maximum = maximumFinalizationBytes + aesGCMOverhead
		default:
			return header, serviceauthority.ErrInvalid
		}
		if count < aesGCMOverhead+1 || count > maximum || offset+count > len(input) {
			return header, serviceauthority.ErrInvalid
		}
		offset += count
		switch kind {
		case 1:
			if seenCatalog || seenRecovery || index != 0 {
				return header, serviceauthority.ErrInvalid
			}
			seenCatalog = true
		case 2:
			if !seenCatalog || index != expectedRecovery ||
				(seenRecovery && previousRecoveryLength != recoveryChunkBytes+aesGCMOverhead) {
				return header, serviceauthority.ErrInvalid
			}
			if expectedRecovery == ^uint64(0) {
				return header, serviceauthority.ErrInvalid
			}
			expectedRecovery++
			seenRecovery = true
			previousRecoveryLength = count
		case 3:
			if !seenCatalog || !seenRecovery || index != expectedRecovery || offset != len(input) {
				return header, serviceauthority.ErrInvalid
			}
			return header, nil
		}
	}
	return header, serviceauthority.ErrInvalid
}

func compareSlots(lhs, rhs backupRecipientSlot) int {
	if comparison := bytes.Compare(lhs.EphemeralPublicKey, rhs.EphemeralPublicKey); comparison != 0 {
		return comparison
	}
	return bytes.Compare(lhs.SealedContentKey, rhs.SealedContentKey)
}

func slotBucket(count int) bool {
	for _, candidate := range []int{1, 2, 4, 8, 16, 32, 64} {
		if count == candidate {
			return true
		}
	}
	return false
}

func validBase64URLDigest(value string) bool {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && base64.RawURLEncoding.EncodeToString(decoded) == value
}
