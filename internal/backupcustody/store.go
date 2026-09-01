package backupcustody

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"time"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

var (
	ErrConflict      = errors.New("Backup custody conflict")
	ErrNotFound      = errors.New("Backup custody record not found")
	ErrUnauthorized  = errors.New("Backup custody credential is unauthorized")
	ErrClockRollback = errors.New("Backup custody server clock moved backwards")
)

type AccountRecord struct {
	AccountID                    uuid.UUID
	ClaimID                      uuid.UUID
	Admission                    AccountAdmissionReference
	AdmissionAuthorizationDigest string
	AuthorityRevision            uint64
	AuthorityManifestDigest      string
	DeploymentID                 uuid.UUID
	InitialManifestRecord        []byte
	InitialAnchorRecord          []byte
	InitialEnrollmentRecord      []byte
	InitialControlAnchor         ControlPossessionAnchor
	InitialBinding               *serviceauthority.InitialBinding
	CreatedAtMilliseconds        int64
}

const (
	AccountStateStandby  = "standby"
	AccountStateWritable = "writable"
)

type ReadAuthorization struct {
	scope                    serviceauthority.Scope
	authorityRevision        uint64
	authorityManifestDigest  string
	deploymentID             uuid.UUID
	authorizedAtMilliseconds int64
}

func newReadAuthorization(binding serviceauthority.RequestBinding, now time.Time) (ReadAuthorization, error) {
	value := ReadAuthorization{scope: binding.Scope, authorityRevision: binding.AuthorityRevision,
		authorityManifestDigest: binding.AuthorityDigest, deploymentID: binding.DeploymentID,
		authorizedAtMilliseconds: now.UnixMilli()}
	if value.Validate() != nil {
		return ReadAuthorization{}, serviceauthority.ErrInvalid
	}
	return value, nil
}

func (authorization ReadAuthorization) Validate() error {
	if authorization.scope.Validate() != nil || authorization.scope.Kind != serviceauthority.ScopeBackupCustody ||
		authorization.authorityRevision == 0 || !validHexDigest(authorization.authorityManifestDigest) ||
		authorization.deploymentID == uuid.Nil || authorization.authorizedAtMilliseconds < 0 {
		return serviceauthority.ErrInvalid
	}
	return nil
}

func (authorization ReadAuthorization) Scope() serviceauthority.Scope { return authorization.scope }
func (authorization ReadAuthorization) AuthorityRevision() uint64 {
	return authorization.authorityRevision
}
func (authorization ReadAuthorization) AuthorityManifestDigest() string {
	return authorization.authorityManifestDigest
}
func (authorization ReadAuthorization) DeploymentID() uuid.UUID { return authorization.deploymentID }
func (authorization ReadAuthorization) AuthorizedAtMilliseconds() int64 {
	return authorization.authorizedAtMilliseconds
}

type TargetRecord struct {
	AccountID                           uuid.UUID
	TargetID                            uuid.UUID
	BackupSetID                         uuid.UUID
	CreateControlCommandReferenceDigest string
	CreatedAtMilliseconds               int64
	Head                                *serviceauthority.BackupCustodyGenerationRecord
	HeadReferenceDigest                 *string
}

// CredentialUse is a bounded, secret-free proof derived from one presented
// bearer. The bearer itself never crosses into persistence or logging.
type CredentialUse struct {
	Reference           TargetCredentialReference
	AuthorizationDigest string
}

func credentialUse(credential TargetCredential) (CredentialUse, error) {
	digest, err := credential.AuthorizationDigest()
	if err != nil {
		return CredentialUse{}, err
	}
	return CredentialUse{Reference: credential.Reference, AuthorizationDigest: digest}, nil
}

type ControlCommandAcceptance struct {
	AccountID                      uuid.UUID `json:"accountID"`
	CommandID                      uuid.UUID `json:"commandID"`
	CommandReferenceDigest         string    `json:"commandReferenceDigest"`
	ControlGeneration              uint64    `json:"controlGeneration"`
	ControlHeadReferenceDigest     string    `json:"controlHeadReferenceDigest"`
	ControlKeyID                   uuid.UUID `json:"controlKeyID"`
	CredentialGrantReferenceDigest *string   `json:"credentialGrantReferenceDigest,omitempty"`
	Sequence                       uint64    `json:"sequence"`
	Version                        int       `json:"version"`
}

func (value ControlCommandAcceptance) Validate() error {
	if value.Version != CredentialAuthorityVersion || value.AccountID == uuid.Nil || value.CommandID == uuid.Nil ||
		value.Sequence == 0 || value.ControlGeneration == 0 || value.ControlKeyID == uuid.Nil ||
		!validHexDigest(value.CommandReferenceDigest) ||
		value.ControlHeadReferenceDigest != value.CommandReferenceDigest ||
		(value.CredentialGrantReferenceDigest != nil && !validHexDigest(*value.CredentialGrantReferenceDigest)) {
		return serviceauthority.ErrInvalid
	}
	return nil
}

type AcceptedCredentialAuthority struct {
	Grant                CredentialGrant
	GrantReferenceDigest string
	ControlHead          AcceptedControlHead
}

func (value AcceptedCredentialAuthority) Validate() error {
	reference, err := value.Grant.ReferenceDigest()
	if err != nil || reference != value.GrantReferenceDigest || value.ControlHead.AccountID != value.Grant.Credential.AccountID ||
		value.ControlHead.Sequence == 0 || !validHexDigest(value.ControlHead.ReferenceDigest) {
		return serviceauthority.ErrInvalid
	}
	return nil
}

type UploadRecord struct {
	AccountID             uuid.UUID
	TargetID              uuid.UUID
	BackupSetID           uuid.UUID
	UploadID              uuid.UUID
	Request               PublishRequest
	RequestBytes          []byte
	CommittedBytes        uint64
	Committed             bool
	MaximumChunkCount     int
	CreatedAtMilliseconds int64
}

type GenerationRecord struct {
	Generation                    serviceauthority.BackupCustodyGenerationRecord
	GenerationReferenceDigest     string
	ObjectPath                    string
	CustodyReceipt                serviceauthority.BackupCustodyReceipt
	CustodyReceiptBytes           []byte
	CustodyReceiptReferenceDigest string
}

func (record GenerationRecord) ValidateStored() error {
	if record.Generation.Validate() != nil || record.ObjectPath != objectPath(record.Generation) {
		return serviceauthority.ErrInvalid
	}
	generationReference, err := record.Generation.ReferenceDigest()
	receiptReference, receiptErr := record.CustodyReceipt.ReferenceDigest()
	receiptBytes, encodeErr := record.CustodyReceipt.CanonicalJSON()
	payload, payloadErr := record.CustodyReceipt.VerifiedPayload()
	if err != nil || receiptErr != nil || encodeErr != nil || payloadErr != nil ||
		generationReference != record.GenerationReferenceDigest || receiptReference != record.CustodyReceiptReferenceDigest ||
		!bytes.Equal(receiptBytes, record.CustodyReceiptBytes) || payload.Kind != serviceauthority.BackupCustodyCommittedKind ||
		!reflect.DeepEqual(payload.Generation, record.Generation) || payload.RequestID == uuid.Nil || payload.CredentialID == uuid.Nil {
		return serviceauthority.ErrInvalid
	}
	return nil
}

type RetentionRecord struct {
	AccountID              uuid.UUID
	Request                RetentionProofRequest
	RequestBytes           []byte
	Receipt                serviceauthority.BackupCustodyReceipt
	ReceiptBytes           []byte
	ReceiptReferenceDigest string
}

func (record RetentionRecord) ValidateStored() error {
	requestBytes, err := canonicalRequest(record.Request)
	receiptBytes, receiptErr := record.Receipt.CanonicalJSON()
	reference, referenceErr := record.Receipt.ReferenceDigest()
	payload, payloadErr := record.Receipt.VerifiedPayload()
	generationReference, generationErr := payload.Generation.ReferenceDigest()
	if err != nil || receiptErr != nil || referenceErr != nil || payloadErr != nil || generationErr != nil ||
		record.AccountID == uuid.Nil || record.Request.Credential.AccountID != record.AccountID ||
		!bytes.Equal(requestBytes, record.RequestBytes) || !bytes.Equal(receiptBytes, record.ReceiptBytes) ||
		reference != record.ReceiptReferenceDigest || payload.Kind != serviceauthority.BackupRetentionConfirmedKind ||
		payload.RequestID != record.Request.RequestID || payload.CredentialID != record.Request.Credential.CredentialID ||
		generationReference != record.Request.GenerationReferenceDigest || payload.CustodyReceiptReferenceDigest == nil ||
		*payload.CustodyReceiptReferenceDigest != record.Request.CustodyReceiptReferenceDigest ||
		payload.RetainedThroughMilliseconds == nil ||
		*payload.RetainedThroughMilliseconds < record.Request.MinimumRetainedThroughMilliseconds {
		return serviceauthority.ErrInvalid
	}
	return nil
}

// Finalization holds the durable target/authority row locks across content
// publication, receipt signing, and the synchronous metadata commit.
type Finalization interface {
	Upload() UploadRecord
	Target() TargetRecord
	Existing() *GenerationRecord
	CredentialAuthority() AcceptedCredentialAuthority
	Revalidate(context.Context, serviceauthority.MutationAuthorization) error
	Commit(context.Context, GenerationRecord) error
	Abort(context.Context) error
}

type UploadAppend interface {
	Upload() UploadRecord
	ExistingNextOffset() *uint64
	Commit(context.Context, uint64) error
	Abort(context.Context) error
}

type RetentionConfirmation interface {
	Target() TargetRecord
	Generation() GenerationRecord
	Existing() *RetentionRecord
	CredentialAuthority() AcceptedCredentialAuthority
	ServerTimeHighWaterMilliseconds() int64
	Revalidate(context.Context, serviceauthority.MutationAuthorization) error
	Commit(context.Context, RetentionRecord, int64) error
	Abort(context.Context) error
}

// Store is implemented by a dedicated Backup-custody database. It must not be
// backed by the Device Sync or Shared Spaces database.
type Store interface {
	LoadAccountClaim(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (AccountRecord, string, error)
	PrepareAccount(context.Context, AccountRecord) error
	ActivateAccount(context.Context, uuid.UUID, uint64, string, uuid.UUID, int64) error
	ApplyControlCommand(context.Context, SignedControlCommand, serviceauthority.MutationAuthorization) (ControlCommandAcceptance, error)
	ValidateControlLedger(context.Context, uuid.UUID) error
	LoadTarget(context.Context, uuid.UUID, uuid.UUID) (TargetRecord, error)
	AuthorizeUploadSnapshot(context.Context, ReadAuthorization, CredentialUse, Clock, uuid.UUID) (UploadRecord, error)
	ReserveUpload(context.Context, UploadRecord, CredentialUse, Clock, serviceauthority.MutationAuthorization) (UploadRecord, bool, error)
	LoadUpload(context.Context, uuid.UUID, uuid.UUID) (UploadRecord, error)
	BeginUploadAppend(context.Context, uuid.UUID, uuid.UUID, uint64, string, uint64, CredentialUse, Clock, serviceauthority.MutationAuthorization) (UploadAppend, error)
	BeginFinalization(context.Context, uuid.UUID, uuid.UUID, CredentialUse, serviceauthority.MutationAuthorization) (Finalization, error)
	AuthorizeHistoricalCredential(context.Context, CredentialUse, string, string, Capability, int64) error
	LoadGenerationByUpload(context.Context, uuid.UUID, uuid.UUID) (GenerationRecord, error)
	LoadGeneration(context.Context, uuid.UUID, string) (GenerationRecord, error)
	LoadRetentionByRequest(context.Context, uuid.UUID, uuid.UUID) (RetentionRecord, error)
	BeginRetention(context.Context, RetentionProofRequest, []byte, CredentialUse, serviceauthority.MutationAuthorization) (RetentionConfirmation, error)
	ReadSnapshot(context.Context, ReadAuthorization, CredentialUse, Clock, uuid.UUID, string) (TargetRecord, GenerationRecord, error)
	ListGenerationSnapshot(context.Context, ReadAuthorization, CredentialUse, Clock, GenerationListRequest) (TargetRecord, GenerationRecord, []GenerationRecord, error)
}

type ReadResult struct {
	Generation     GenerationRecord
	Content        io.ReadCloser
	RangeOffset    uint64
	RangeByteCount uint64
}

type GenerationListResult struct {
	Target TargetRecord
	Head   GenerationRecord
	Items  []GenerationRecord
}

func cloneGeneration(record *serviceauthority.BackupCustodyGenerationRecord) *serviceauthority.BackupCustodyGenerationRecord {
	if record == nil {
		return nil
	}
	copy := *record
	copy.PredecessorReferenceDigest = cloneString(record.PredecessorReferenceDigest)
	return &copy
}
