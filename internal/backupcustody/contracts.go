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
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

const Version = 1

const MaximumRequestByteCount = 32 * 1024

const MaximumGenerationPageCount = 32

const MaximumGenerationPageByteCount = 2 * 1024 * 1024

const MaximumRangeByteCount uint64 = 64 * 1024 * 1024

const targetCredentialReferenceDomain = "Facets backup custody target credential reference v1\x00"

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

func (reference TargetCredentialReference) ReferenceDigest() (string, error) {
	if reference.Validate() != nil {
		return "", serviceauthority.ErrInvalid
	}
	encoded, err := json.Marshal(reference)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append([]byte(targetCredentialReferenceDomain), encoded...))
	return fmt.Sprintf("%x", digest[:]), nil
}

type BackupBulkResource struct {
	CredentialReferenceDigest string
	Direction                 serviceauthority.BulkDirection
	GenerationReferenceDigest string
	UploadID                  uuid.UUID
	Offset                    uint64
	ByteCount                 uint64
}

func UploadChunkResourceID(reference TargetCredentialReference, uploadID uuid.UUID, offset, byteCount uint64) (string, error) {
	credentialReference, err := reference.ReferenceDigest()
	if err != nil || uploadID == uuid.Nil || byteCount == 0 || byteCount > MaximumRangeByteCount || offset > ^uint64(0)-byteCount {
		return "", serviceauthority.ErrInvalid
	}
	return fmt.Sprintf("facets-backup-upload-chunk-v1:%s:%s:%d:%d", credentialReference, uploadID, offset, byteCount), nil
}

func DownloadRangeResourceID(reference TargetCredentialReference, generationReference string, offset, byteCount uint64) (string, error) {
	credentialReference, err := reference.ReferenceDigest()
	if err != nil || !validHexDigest(generationReference) || byteCount == 0 || byteCount > MaximumRangeByteCount || offset > ^uint64(0)-byteCount {
		return "", serviceauthority.ErrInvalid
	}
	return fmt.Sprintf("facets-backup-download-range-v1:%s:%s:%d:%d", credentialReference, generationReference, offset, byteCount), nil
}

func ParseBackupBulkResourceID(value string) (BackupBulkResource, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 5 || !validHexDigest(parts[1]) {
		return BackupBulkResource{}, serviceauthority.ErrInvalid
	}
	offset, offsetErr := strconv.ParseUint(parts[3], 10, 64)
	count, countErr := strconv.ParseUint(parts[4], 10, 64)
	resource := BackupBulkResource{CredentialReferenceDigest: parts[1], Offset: offset, ByteCount: count}
	if offsetErr != nil || countErr != nil || strconv.FormatUint(offset, 10) != parts[3] ||
		strconv.FormatUint(count, 10) != parts[4] || count == 0 || count > MaximumRangeByteCount ||
		offset > ^uint64(0)-count {
		return BackupBulkResource{}, serviceauthority.ErrInvalid
	}
	switch parts[0] {
	case "facets-backup-upload-chunk-v1":
		resource.Direction = serviceauthority.BulkUpload
		resource.UploadID, offsetErr = uuid.Parse(parts[2])
		if offsetErr != nil || resource.UploadID == uuid.Nil || resource.UploadID.String() != parts[2] {
			return BackupBulkResource{}, serviceauthority.ErrInvalid
		}
	case "facets-backup-download-range-v1":
		resource.Direction = serviceauthority.BulkDownload
		resource.GenerationReferenceDigest = parts[2]
		if !validHexDigest(resource.GenerationReferenceDigest) {
			return BackupBulkResource{}, serviceauthority.ErrInvalid
		}
	default:
		return BackupBulkResource{}, serviceauthority.ErrInvalid
	}
	return resource, nil
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
	GenerationReferenceDigest string                    `json:"generationReferenceDigest"`
	MaximumByteCount          uint64                    `json:"maximumByteCount"`
	RangeOffset               uint64                    `json:"rangeOffset"`
	RequestID                 uuid.UUID                 `json:"requestID"`
	RequestedAtMilliseconds   int64                     `json:"requestedAtMilliseconds"`
	Version                   int                       `json:"version"`
}

func (request ReadRequest) Validate() error {
	if request.Version != Version || request.RequestID == uuid.Nil ||
		!request.Credential.Admits(Read, request.RequestedAtMilliseconds) ||
		!validHexDigest(request.GenerationReferenceDigest) ||
		request.MaximumByteCount == 0 || request.MaximumByteCount > MaximumRangeByteCount ||
		request.RangeOffset > ^uint64(0)-request.MaximumByteCount {
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

type GenerationListRequest struct {
	AfterGeneration                uint64                    `json:"afterGeneration"`
	AfterGenerationReferenceDigest *string                   `json:"afterGenerationReferenceDigest,omitempty"`
	Credential                     TargetCredentialReference `json:"credential"`
	PageCount                      int                       `json:"pageCount"`
	RequestID                      uuid.UUID                 `json:"requestID"`
	RequestedAtMilliseconds        int64                     `json:"requestedAtMilliseconds"`
	SnapshotHeadReferenceDigest    *string                   `json:"snapshotHeadReferenceDigest,omitempty"`
	Version                        int                       `json:"version"`
}

func (request GenerationListRequest) Validate() error {
	if request.Version != Version || request.RequestID == uuid.Nil ||
		!request.Credential.Admits(Read, request.RequestedAtMilliseconds) ||
		(request.AfterGeneration == 0) != (request.SnapshotHeadReferenceDigest == nil) ||
		(request.AfterGeneration == 0) != (request.AfterGenerationReferenceDigest == nil) ||
		(request.AfterGenerationReferenceDigest != nil && !validHexDigest(*request.AfterGenerationReferenceDigest)) ||
		(request.SnapshotHeadReferenceDigest != nil && !validHexDigest(*request.SnapshotHeadReferenceDigest)) ||
		request.PageCount <= 0 || request.PageCount > MaximumGenerationPageCount {
		return serviceauthority.ErrInvalid
	}
	return nil
}

func (request GenerationListRequest) Scope() (serviceauthority.Scope, error) {
	if request.Validate() != nil {
		return serviceauthority.Scope{}, serviceauthority.ErrInvalid
	}
	return serviceauthority.Scope{
		Kind: serviceauthority.ScopeBackupCustody, ScopeID: request.Credential.AccountID,
	}, nil
}

type GenerationListItem struct {
	CustodyReceipt            serviceauthority.BackupCustodyReceipt `json:"custodyReceipt"`
	GenerationReferenceDigest string                                `json:"generationReferenceDigest"`
}

func (item GenerationListItem) Validate() error {
	payload, err := item.CustodyReceipt.VerifiedPayload()
	if err != nil {
		return serviceauthority.ErrInvalid
	}
	reference, referenceErr := payload.Generation.ReferenceDigest()
	if referenceErr != nil || payload.Kind != serviceauthority.BackupCustodyCommittedKind ||
		!validHexDigest(item.GenerationReferenceDigest) || reference != item.GenerationReferenceDigest {
		return serviceauthority.ErrInvalid
	}
	return nil
}

type GenerationListPage struct {
	AfterGeneration                uint64                                `json:"afterGeneration"`
	AfterGenerationReferenceDigest *string                               `json:"afterGenerationReferenceDigest,omitempty"`
	Items                          []GenerationListItem                  `json:"items"`
	RequestID                      uuid.UUID                             `json:"requestID"`
	SnapshotHeadCustodyReceipt     serviceauthority.BackupCustodyReceipt `json:"snapshotHeadCustodyReceipt"`
	SnapshotHeadReferenceDigest    string                                `json:"snapshotHeadReferenceDigest"`
	Version                        int                                   `json:"version"`
}

func (page GenerationListPage) Validate() error {
	head, err := page.SnapshotHeadCustodyReceipt.VerifiedPayload()
	if err != nil {
		return serviceauthority.ErrInvalid
	}
	headReference, referenceErr := head.Generation.ReferenceDigest()
	if referenceErr != nil || page.Version != Version || page.RequestID == uuid.Nil ||
		head.Kind != serviceauthority.BackupCustodyCommittedKind || !validHexDigest(page.SnapshotHeadReferenceDigest) ||
		headReference != page.SnapshotHeadReferenceDigest || len(page.Items) == 0 ||
		len(page.Items) > MaximumGenerationPageCount || page.AfterGeneration >= head.Generation.Generation {
		return serviceauthority.ErrInvalid
	}
	previous := page.AfterGeneration
	previousReference := page.AfterGenerationReferenceDigest
	if (page.AfterGeneration == 0) != (previousReference == nil) ||
		(previousReference != nil && !validHexDigest(*previousReference)) {
		return serviceauthority.ErrInvalid
	}
	for _, item := range page.Items {
		payload, itemErr := item.CustodyReceipt.VerifiedPayload()
		if item.Validate() != nil || itemErr != nil || previous == ^uint64(0) ||
			payload.Generation.AccountID != head.Generation.AccountID ||
			payload.Generation.TargetID != head.Generation.TargetID ||
			payload.Generation.BackupSetID != head.Generation.BackupSetID ||
			payload.Generation.Generation != previous+1 ||
			!sameOptionalString(payload.Generation.PredecessorReferenceDigest, previousReference) ||
			payload.Generation.Generation > head.Generation.Generation {
			return serviceauthority.ErrInvalid
		}
		previous = payload.Generation.Generation
		reference := item.GenerationReferenceDigest
		previousReference = &reference
	}
	if previous == head.Generation.Generation &&
		(previousReference == nil || *previousReference != page.SnapshotHeadReferenceDigest) {
		return serviceauthority.ErrInvalid
	}
	return nil
}

// ValidateResponse exact-binds a self-consistent page to the request that
// elicited it. The initial response selects one signed head; every successor
// response must preserve that head and echo the exact prior position. A page
// must also be full unless it reaches the pinned head, preventing silent
// omission from being confused with completion.
func (page GenerationListPage) ValidateResponse(request GenerationListRequest) error {
	if page.Validate() != nil || request.Validate() != nil || page.RequestID != request.RequestID ||
		page.AfterGeneration != request.AfterGeneration ||
		!sameOptionalString(page.AfterGenerationReferenceDigest, request.AfterGenerationReferenceDigest) ||
		(request.SnapshotHeadReferenceDigest != nil &&
			*request.SnapshotHeadReferenceDigest != page.SnapshotHeadReferenceDigest) {
		return serviceauthority.ErrInvalid
	}
	head, err := page.SnapshotHeadCustodyReceipt.VerifiedPayload()
	if err != nil || head.Generation.AccountID != request.Credential.AccountID ||
		head.Generation.TargetID != request.Credential.TargetID ||
		head.Generation.BackupSetID != request.Credential.BackupSetID {
		return serviceauthority.ErrInvalid
	}
	remaining := head.Generation.Generation - request.AfterGeneration
	expectedCount := uint64(request.PageCount)
	if expectedCount > remaining {
		expectedCount = remaining
	}
	if uint64(len(page.Items)) != expectedCount {
		return serviceauthority.ErrInvalid
	}
	return nil
}

func sameOptionalString(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
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

func DecodeGenerationListRequest(input []byte) (GenerationListRequest, error) {
	var value GenerationListRequest
	if decodeCanonical(input, &value) != nil || value.Validate() != nil {
		return value, serviceauthority.ErrInvalid
	}
	return value, nil
}

func DecodeGenerationListPage(input []byte) (GenerationListPage, error) {
	var value GenerationListPage
	if decodeCanonicalBounded(input, &value, MaximumGenerationPageByteCount) != nil || value.Validate() != nil {
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
	return decodeCanonicalBounded(input, target, MaximumRequestByteCount)
}

func decodeCanonicalBounded(input []byte, target any, maximum int) error {
	if len(input) == 0 || maximum <= 0 || len(input) > maximum {
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
