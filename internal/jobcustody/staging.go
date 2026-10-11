package jobcustody

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/computequeue"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
	"github.com/robreuss/FacetsNode/internal/storagecapacity"
)

type AdmissionState string

const MaximumAdmissionExpiryBatchSize = 256

const (
	AdmissionStaging              AdmissionState = "staging"
	AdmissionStagingExpiryPending AdmissionState = "stagingExpiryPending"
	AdmissionRetained             AdmissionState = "retained"
	AdmissionExpiryPending        AdmissionState = "expiryPending"
	AdmissionExpired              AdmissionState = "expired"
)

// AdmissionRecord is the complete durable metadata permitted beside opaque
// protected bytes. It intentionally has no Space, object, prompt, model,
// operation, result, credential, label, or caller-selected path field.
type AdmissionRecord struct {
	EnvelopeBytes            []byte
	Header                   computequeue.JobCustodyAdmissionHeader
	ExpectedSigner           computequeue.ReceiptSignerBinding
	AdmissionPermitDigest    computequeue.Digest
	RouteAuthorityID         uuid.UUID
	RequesterAuthorityDigest computequeue.Digest
	WorkerCapabilitiesDigest computequeue.Digest
	AcceptedAt               computequeue.Timestamp
	CommittedBytes           int64
	State                    AdmissionState
	ObjectPath               string
	CustodyReceiptBytes      []byte
	ExpiryStartedAt          computequeue.Timestamp
	ExpiryReceiptBytes       []byte
	UpdatedAtMillis          int64
}

func (record AdmissionRecord) ValidateStored() error {
	if len(record.EnvelopeBytes) == 0 || record.Header.Validate() != nil ||
		record.ExpectedSigner.Validate() != nil || record.AcceptedAt.Validate() != nil ||
		record.AdmissionPermitDigest.Validate() != nil ||
		record.RouteAuthorityID == uuid.Nil || record.RequesterAuthorityDigest.Validate() != nil ||
		record.WorkerCapabilitiesDigest.Validate() != nil ||
		record.AcceptedAt < record.Header.NotBeforeAt || record.AcceptedAt >= record.Header.ExpiresAt ||
		record.CommittedBytes < 0 || record.CommittedBytes > record.Header.ProtectedObject.ByteCount ||
		record.UpdatedAtMillis < int64(record.AcceptedAt) {
		return ErrInvalid
	}
	envelope, err := computequeue.DecodeJobCustodyAdmissionCanonical(record.EnvelopeBytes)
	if err != nil || envelope.Header != record.Header ||
		envelope.SignatureProfileID != record.ExpectedSigner.SignatureProfileID {
		return ErrInvalid
	}
	expectedPath := filepath.Join("objects", string(record.Header.CapsuleID))
	noExpiry := record.ExpiryStartedAt == 0 && len(record.ExpiryReceiptBytes) == 0
	hasPendingExpiry := record.ExpiryStartedAt >= record.Header.RetentionUntil &&
		record.UpdatedAtMillis == int64(record.ExpiryStartedAt) && len(record.ExpiryReceiptBytes) == 0
	hasFinishedExpiry := record.ExpiryStartedAt >= record.Header.RetentionUntil &&
		record.UpdatedAtMillis >= int64(record.ExpiryStartedAt) && len(record.ExpiryReceiptBytes) > 0
	switch record.State {
	case AdmissionStaging:
		if record.ObjectPath != "" || len(record.CustodyReceiptBytes) != 0 || !noExpiry {
			return ErrInvalid
		}
	case AdmissionStagingExpiryPending:
		if record.ObjectPath != "" || len(record.CustodyReceiptBytes) != 0 || !hasPendingExpiry {
			return ErrInvalid
		}
	case AdmissionRetained:
		if record.CommittedBytes != record.Header.ProtectedObject.ByteCount ||
			record.ObjectPath != expectedPath || len(record.CustodyReceiptBytes) == 0 ||
			validateCustodyReceiptRecord(record, nil) != nil || !noExpiry {
			return ErrInvalid
		}
	case AdmissionExpiryPending:
		if record.CommittedBytes != record.Header.ProtectedObject.ByteCount ||
			record.ObjectPath != expectedPath || len(record.CustodyReceiptBytes) == 0 ||
			validateCustodyReceiptRecord(record, nil) != nil || !hasPendingExpiry {
			return ErrInvalid
		}
	case AdmissionExpired:
		if len(record.CustodyReceiptBytes) == 0 {
			if record.ObjectPath != "" || !hasFinishedExpiry ||
				validateAdmissionStagingExpiryReceiptRecord(record, nil) != nil {
				return ErrInvalid
			}
		} else if record.CommittedBytes != record.Header.ProtectedObject.ByteCount ||
			record.ObjectPath != "" || validateCustodyReceiptRecord(record, nil) != nil ||
			!hasFinishedExpiry || validateAdmissionExpiryReceiptRecord(record, nil) != nil {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func sameAdmissionIdentity(left, right AdmissionRecord) bool {
	return bytes.Equal(left.EnvelopeBytes, right.EnvelopeBytes) &&
		left.Header == right.Header && left.ExpectedSigner == right.ExpectedSigner &&
		left.RouteAuthorityID == right.RouteAuthorityID &&
		left.RequesterAuthorityDigest == right.RequesterAuthorityDigest &&
		left.WorkerCapabilitiesDigest == right.WorkerCapabilitiesDigest
}

func sameAdmission(left, right AdmissionRecord) bool {
	return sameAdmissionIdentity(left, right) && left.AcceptedAt == right.AcceptedAt
}

type AdmissionVerifier interface {
	Verify(
		computequeue.JobCustodySignedAdmissionEnvelope,
		computequeue.JobCustodyAdmissionExpectation,
		computequeue.ReceiptSignerBinding,
	) (computequeue.VerifiedJobCustodyAdmission, error)
}

type Ledger interface {
	LoadAdmission(context.Context, computequeue.JobCapsuleID) (AdmissionRecord, error)
	ReserveAdmission(context.Context, AdmissionRecord) (AdmissionRecord, bool, error)
	BeginAppend(context.Context, AppendRequest) (AppendLease, error)
	BeginFinalization(context.Context, computequeue.JobCapsuleID) (FinalizationLease, error)
}

type AdmissionLifecycleLedger interface {
	ListAdmissionExpiryCandidates(
		context.Context, computequeue.Timestamp, int,
	) ([]AdmissionRecord, error)
	RequestAdmissionExpiry(
		context.Context, computequeue.JobCapsuleID, computequeue.Timestamp,
	) (AdmissionRecord, error)
	FinalizeAdmissionExpiry(
		context.Context, computequeue.JobCapsuleID, []byte, int64,
	) (AdmissionRecord, error)
}

type AppendRequest struct {
	CapsuleID   computequeue.JobCapsuleID
	ChunkIndex  int64
	Offset      int64
	ByteCount   int64
	ChunkSHA256 computequeue.Digest
}

func (request AppendRequest) Validate(
	descriptor computequeue.JobCapsuleProtectedObjectDescriptor,
) error {
	if request.CapsuleID.Validate() != nil || descriptor.Validate() != nil ||
		request.ChunkSHA256.Validate() != nil || request.ChunkIndex < 0 ||
		request.ChunkIndex >= descriptor.ChunkCount || request.Offset < 0 || request.ByteCount <= 0 ||
		request.ChunkIndex > (descriptor.ByteCount-1)/descriptor.ChunkByteCount ||
		request.Offset != request.ChunkIndex*descriptor.ChunkByteCount {
		return ErrInvalid
	}
	expectedCount := min(descriptor.ChunkByteCount, descriptor.ByteCount-request.Offset)
	if request.ByteCount != expectedCount {
		return ErrInvalid
	}
	return nil
}

type AppendLease interface {
	Admission() AdmissionRecord
	ExistingNextOffset() *int64
	Commit(context.Context, int64) error
	Abort(context.Context) error
}

type FinalizationLease interface {
	Admission() AdmissionRecord
	Commit(context.Context, string, []byte, int64) (AdmissionRecord, error)
	Abort(context.Context) error
}

type CapacityAuthority interface {
	Reserve(context.Context, int64) (CapacityReservation, error)
}

type CapacityReservation interface {
	Recheck(context.Context) error
	Commit(context.Context) error
	Release(context.Context) error
}

type Clock interface{ Now() time.Time }

type ReceiptSigner interface {
	DeploymentID() uuid.UUID
	PublicSigningKeyX963() string
	SigningKeyFingerprint() string
	SignJobCustodyReceipt(
		serviceauthority.JobCustodyReceiptPayload,
	) (serviceauthority.JobCustodyReceipt, error)
}

type AdmissionExpiryReceiptSigner interface {
	DeploymentID() uuid.UUID
	PublicSigningKeyX963() string
	SigningKeyFingerprint() string
	SignJobCustodyExpiryReceipt(
		serviceauthority.JobCustodyExpiryReceiptPayload,
	) (serviceauthority.JobCustodyExpiryReceipt, error)
	SignJobCustodyStagingExpiryReceipt(
		serviceauthority.JobCustodyStagingExpiryReceiptPayload,
	) (serviceauthority.JobCustodyStagingExpiryReceipt, error)
}

type AdmissionExpiryCoordinator struct {
	Ledger        AdmissionLifecycleLedger
	Content       *ContentStore
	ReceiptSigner AdmissionExpiryReceiptSigner
	Clock         Clock
}

func (coordinator *AdmissionExpiryCoordinator) validate() error {
	if coordinator == nil || coordinator.Ledger == nil || coordinator.Content == nil ||
		coordinator.ReceiptSigner == nil || coordinator.ReceiptSigner.DeploymentID() == uuid.Nil ||
		coordinator.Clock == nil {
		return ErrInvalid
	}
	return nil
}

type Coordinator struct {
	Ledger        Ledger
	Content       *ContentStore
	Capacity      CapacityAuthority
	Verifier      AdmissionVerifier
	ReceiptSigner ReceiptSigner
	Clock         Clock
}

func (coordinator *Coordinator) validate() error {
	if coordinator == nil || coordinator.Ledger == nil || coordinator.Content == nil ||
		coordinator.Capacity == nil || coordinator.Verifier == nil ||
		coordinator.ReceiptSigner == nil || coordinator.ReceiptSigner.DeploymentID() == uuid.Nil ||
		coordinator.Clock == nil {
		return ErrInvalid
	}
	return nil
}

// AdmissionHandle is authenticated runtime state, not a wire or persistence
// contract. Callers cannot manufacture its private verified admission.
type AdmissionHandle struct {
	verified computequeue.VerifiedJobCustodyAdmission
	record   AdmissionRecord
}

func (handle AdmissionHandle) Header() computequeue.JobCustodyAdmissionHeader {
	return handle.verified.Header()
}

func (handle AdmissionHandle) Record() AdmissionRecord {
	result := handle.record
	result.EnvelopeBytes = bytes.Clone(handle.record.EnvelopeBytes)
	result.CustodyReceiptBytes = bytes.Clone(handle.record.CustodyReceiptBytes)
	result.ExpiryReceiptBytes = bytes.Clone(handle.record.ExpiryReceiptBytes)
	return result
}

// AdmitAuthorized accepts only route authority produced by the Box permit
// verifier. HTTP or other transport adapters must not recreate expected
// signer/header values from requester-controlled fields.
func (coordinator *Coordinator) AdmitAuthorized(
	ctx context.Context,
	envelopeBytes []byte,
	authorization AdmissionAuthorization,
) (AdmissionHandle, error) {
	expectedHeader := authorization.header
	expectedSigner := authorization.expectedSigner
	if coordinator.validate() != nil || ctx == nil || len(envelopeBytes) == 0 {
		return AdmissionHandle{}, ErrInvalid
	}
	if expectedHeader.Validate() != nil || expectedSigner.Validate() != nil ||
		authorization.permitDigest.Validate() != nil || authorization.authorityID == uuid.Nil ||
		authorization.workerCapabilitiesDigest.Validate() != nil {
		return AdmissionHandle{}, ErrInvalid
	}
	envelope, err := computequeue.DecodeJobCustodyAdmissionCanonical(envelopeBytes)
	if err != nil {
		return AdmissionHandle{}, err
	}
	if existing, loadErr := coordinator.Ledger.LoadAdmission(ctx, expectedHeader.CapsuleID); loadErr == nil {
		if existing.ValidateStored() != nil || !bytes.Equal(existing.EnvelopeBytes, envelopeBytes) ||
			existing.Header != expectedHeader || existing.ExpectedSigner != expectedSigner {
			return AdmissionHandle{}, ErrConflict
		}
		expectation, err := computequeue.NewJobCustodyAdmissionExpectation(
			expectedHeader,
			existing.AcceptedAt,
		)
		if err != nil {
			return AdmissionHandle{}, err
		}
		verified, err := coordinator.Verifier.Verify(envelope, expectation, expectedSigner)
		if err != nil {
			return AdmissionHandle{}, err
		}
		return coordinator.openAdmission(verified, existing, false)
	} else if !errors.Is(loadErr, ErrMissing) {
		return AdmissionHandle{}, loadErr
	}
	acceptedAt := computequeue.Timestamp(coordinator.Clock.Now().UnixMilli())
	expectation, err := computequeue.NewJobCustodyAdmissionExpectation(expectedHeader, acceptedAt)
	if err != nil {
		return AdmissionHandle{}, err
	}
	verified, err := coordinator.Verifier.Verify(envelope, expectation, expectedSigner)
	if err != nil {
		return AdmissionHandle{}, err
	}
	candidate := AdmissionRecord{
		EnvelopeBytes:            bytes.Clone(envelopeBytes),
		Header:                   verified.Header(),
		ExpectedSigner:           verified.ExpectedSigner(),
		AdmissionPermitDigest:    authorization.permitDigest,
		RouteAuthorityID:         authorization.authorityID,
		RequesterAuthorityDigest: authorization.requesterAuthorityDigest,
		WorkerCapabilitiesDigest: authorization.workerCapabilitiesDigest,
		AcceptedAt:               acceptedAt,
		State:                    AdmissionStaging,
		UpdatedAtMillis:          int64(acceptedAt),
	}
	if err := candidate.ValidateStored(); err != nil {
		return AdmissionHandle{}, err
	}
	record, created, err := coordinator.Ledger.ReserveAdmission(ctx, candidate)
	if err != nil {
		return AdmissionHandle{}, err
	}
	if record.ValidateStored() != nil || !sameAdmissionIdentity(record, candidate) {
		return AdmissionHandle{}, ErrConflict
	}
	// The ledger's first acceptedAt is authoritative when two exact admissions
	// race. Re-verify against that durable time before constructing a handle so
	// later operations remain bound to one immutable historical acceptance.
	durableExpectation, err := computequeue.NewJobCustodyAdmissionExpectation(
		expectedHeader,
		record.AcceptedAt,
	)
	if err != nil {
		return AdmissionHandle{}, err
	}
	verified, err = coordinator.Verifier.Verify(envelope, durableExpectation, record.ExpectedSigner)
	if err != nil {
		return AdmissionHandle{}, err
	}
	return coordinator.openAdmission(verified, record, created)
}

func (coordinator *Coordinator) openAdmission(
	verified computequeue.VerifiedJobCustodyAdmission,
	record AdmissionRecord,
	created bool,
) (AdmissionHandle, error) {
	if created || (record.State == AdmissionStaging && record.CommittedBytes == 0) {
		if err := coordinator.Content.Prepare(record.Header.CapsuleID); err != nil {
			return AdmissionHandle{}, err
		}
	} else if record.State == AdmissionRetained {
		if validateCustodyReceiptRecord(record, coordinator.ReceiptSigner) != nil {
			return AdmissionHandle{}, ErrInvalid
		}
		file, err := coordinator.Content.OpenObject(record.Header.CapsuleID, record.Header.ProtectedObject)
		if err != nil {
			return AdmissionHandle{}, err
		}
		if err := file.Close(); err != nil {
			return AdmissionHandle{}, ErrUnavailable
		}
	}
	return AdmissionHandle{verified: verified, record: record}, nil
}

func (coordinator *Coordinator) AppendChunk(
	ctx context.Context,
	handle AdmissionHandle,
	chunkIndex int64,
	chunk []byte,
	chunkSHA256 computequeue.Digest,
) (int64, error) {
	if coordinator.validate() != nil || ctx == nil || len(chunk) == 0 {
		return 0, ErrInvalid
	}
	header := handle.verified.Header()
	if header.Validate() != nil || handle.verified.ExpectedSigner().Validate() != nil ||
		handle.record.ValidateStored() != nil || handle.record.Header != header ||
		handle.record.ExpectedSigner != handle.verified.ExpectedSigner() ||
		handle.record.State != AdmissionStaging {
		return 0, ErrInvalid
	}
	digest := sha256.Sum256(chunk)
	if fmt.Sprintf("%x", digest[:]) != string(chunkSHA256) {
		return 0, ErrInvalid
	}
	request := AppendRequest{
		CapsuleID: header.CapsuleID, ChunkIndex: chunkIndex,
		Offset:    chunkIndex * header.ProtectedObject.ChunkByteCount,
		ByteCount: int64(len(chunk)), ChunkSHA256: chunkSHA256,
	}
	if err := request.Validate(header.ProtectedObject); err != nil {
		return 0, err
	}
	appendLease, err := coordinator.Ledger.BeginAppend(ctx, request)
	if err != nil {
		return 0, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = appendLease.Abort(context.WithoutCancel(ctx))
		}
	}()
	record := appendLease.Admission()
	if record.ValidateStored() != nil || !sameAdmission(record, handle.record) || record.State != AdmissionStaging {
		return 0, ErrConflict
	}
	if existing := appendLease.ExistingNextOffset(); existing != nil {
		if *existing != request.Offset+request.ByteCount ||
			coordinator.Content.VerifyRange(header.CapsuleID, request.Offset, request.ByteCount, request.ChunkSHA256) != nil {
			return 0, ErrConflict
		}
		if err := appendLease.Abort(ctx); err != nil {
			return 0, err
		}
		committed = true
		return *existing, nil
	}
	if record.CommittedBytes != request.Offset {
		return 0, ErrConflict
	}
	byteCeiling, err := storagecapacity.AppendReservation(request.ByteCount)
	if err != nil {
		return 0, err
	}
	capacityLease, err := coordinator.Capacity.Reserve(ctx, byteCeiling)
	if err != nil {
		return 0, err
	}
	releaseCapacity := true
	defer func() {
		if releaseCapacity {
			_ = capacityLease.Release(context.WithoutCancel(ctx))
		}
	}()
	if err := capacityLease.Recheck(ctx); err != nil {
		return 0, err
	}
	next, err := coordinator.Content.ReconcileAndAppend(
		header.CapsuleID,
		header.ProtectedObject,
		request.Offset,
		chunk,
	)
	if err != nil {
		return 0, err
	}
	criticalContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := appendLease.Commit(criticalContext, next); err != nil {
		return 0, err
	}
	releaseCapacity = false
	if err := capacityLease.Commit(criticalContext); err != nil {
		return 0, err
	}
	committed = true
	return next, nil
}

func (coordinator *Coordinator) Finalize(
	ctx context.Context,
	handle AdmissionHandle,
) (AdmissionRecord, error) {
	if coordinator.validate() != nil || ctx == nil || handle.record.ValidateStored() != nil {
		return AdmissionRecord{}, ErrInvalid
	}
	header := handle.verified.Header()
	if handle.record.Header != header || handle.record.ExpectedSigner != handle.verified.ExpectedSigner() {
		return AdmissionRecord{}, ErrInvalid
	}
	lease, err := coordinator.Ledger.BeginFinalization(ctx, header.CapsuleID)
	if err != nil {
		return AdmissionRecord{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = lease.Abort(context.WithoutCancel(ctx))
		}
	}()
	record := lease.Admission()
	if record.ValidateStored() != nil || !sameAdmission(record, handle.record) {
		return AdmissionRecord{}, ErrConflict
	}
	if record.State == AdmissionRetained {
		if validateCustodyReceiptRecord(record, coordinator.ReceiptSigner) != nil {
			return AdmissionRecord{}, ErrInvalid
		}
		file, err := coordinator.Content.OpenObject(header.CapsuleID, header.ProtectedObject)
		if err != nil {
			return AdmissionRecord{}, err
		}
		if err := file.Close(); err != nil {
			return AdmissionRecord{}, ErrUnavailable
		}
		if err := lease.Abort(ctx); err != nil {
			return AdmissionRecord{}, err
		}
		committed = true
		return record, nil
	}
	if record.State != AdmissionStaging || record.CommittedBytes != header.ProtectedObject.ByteCount {
		return AdmissionRecord{}, ErrConflict
	}
	objectPath, err := coordinator.Content.Finalize(header.CapsuleID, header.ProtectedObject)
	if err != nil {
		return AdmissionRecord{}, err
	}
	committedAt := coordinator.Clock.Now().UnixMilli()
	if committedAt < record.UpdatedAtMillis {
		committedAt = record.UpdatedAtMillis
	}
	if committedAt > int64(header.RetentionUntil) {
		return AdmissionRecord{}, ErrConflict
	}
	receiptBytes, err := coordinator.signCustodyReceipt(record, committedAt)
	if err != nil {
		return AdmissionRecord{}, err
	}
	criticalContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	committedRecord, err := lease.Commit(criticalContext, objectPath, receiptBytes, committedAt)
	if err != nil {
		return AdmissionRecord{}, err
	}
	committed = true
	if committedRecord.ValidateStored() != nil ||
		!sameAdmission(committedRecord, record) ||
		committedRecord.State != AdmissionRetained ||
		committedRecord.CommittedBytes != header.ProtectedObject.ByteCount ||
		committedRecord.ObjectPath != objectPath ||
		validateCustodyReceiptRecord(committedRecord, coordinator.ReceiptSigner) != nil {
		return AdmissionRecord{}, ErrInvalid
	}
	return committedRecord, nil
}

func (coordinator *Coordinator) signCustodyReceipt(
	record AdmissionRecord,
	committedAt int64,
) ([]byte, error) {
	capsuleID, capsuleErr := uuid.Parse(string(record.Header.CapsuleID))
	assignmentID, assignmentErr := uuid.Parse(string(record.Header.AssignmentID))
	envelopeDigest, digestErr := AdmissionEnvelopeDigest(record.EnvelopeBytes)
	if capsuleErr != nil || assignmentErr != nil || digestErr != nil {
		return nil, ErrInvalid
	}
	payload := serviceauthority.JobCustodyReceiptPayload{
		AdmissionEnvelopeDigest:         string(envelopeDigest),
		AdmissionIdempotencyKey:         string(record.Header.IdempotencyKey),
		AdmissionPermitDigest:           string(record.AdmissionPermitDigest),
		AssignmentID:                    assignmentID,
		CapsuleID:                       capsuleID,
		CommittedAtMilliseconds:         committedAt,
		DeploymentID:                    coordinator.ReceiptSigner.DeploymentID(),
		Kind:                            serviceauthority.JobCustodyCommittedReceiptKind,
		ProtectedObjectByteCount:        record.Header.ProtectedObject.ByteCount,
		ProtectedObjectDescriptorDigest: string(record.Header.ProtectedObject.Digest()),
		ProtectedObjectSHA256:           string(record.Header.ProtectedObject.SHA256),
		RetentionUntilMilliseconds:      int64(record.Header.RetentionUntil),
		Version:                         serviceauthority.JobCustodyReceiptVersion,
	}
	receipt, err := coordinator.ReceiptSigner.SignJobCustodyReceipt(payload)
	if err != nil {
		return nil, ErrUnavailable
	}
	encoded, err := receipt.CanonicalJSON()
	if err != nil {
		return nil, ErrUnavailable
	}
	return encoded, nil
}

func validateCustodyReceiptRecord(record AdmissionRecord, signer ReceiptSigner) error {
	receipt, err := serviceauthority.DecodeJobCustodyReceipt(record.CustodyReceiptBytes)
	if err != nil {
		return ErrInvalid
	}
	payload, err := receipt.VerifiedPayload()
	if err != nil {
		return ErrInvalid
	}
	capsuleID, capsuleErr := uuid.Parse(string(record.Header.CapsuleID))
	assignmentID, assignmentErr := uuid.Parse(string(record.Header.AssignmentID))
	envelopeDigest, digestErr := AdmissionEnvelopeDigest(record.EnvelopeBytes)
	if capsuleErr != nil || assignmentErr != nil || digestErr != nil ||
		payload.CapsuleID != capsuleID || payload.AssignmentID != assignmentID ||
		payload.AdmissionEnvelopeDigest != string(envelopeDigest) ||
		payload.AdmissionIdempotencyKey != string(record.Header.IdempotencyKey) ||
		payload.AdmissionPermitDigest != string(record.AdmissionPermitDigest) ||
		payload.ProtectedObjectByteCount != record.Header.ProtectedObject.ByteCount ||
		payload.ProtectedObjectDescriptorDigest != string(record.Header.ProtectedObject.Digest()) ||
		payload.ProtectedObjectSHA256 != string(record.Header.ProtectedObject.SHA256) ||
		payload.RetentionUntilMilliseconds != int64(record.Header.RetentionUntil) ||
		payload.CommittedAtMilliseconds < int64(record.AcceptedAt) ||
		payload.CommittedAtMilliseconds > int64(record.Header.RetentionUntil) ||
		payload.CommittedAtMilliseconds > record.UpdatedAtMillis ||
		(record.State == AdmissionRetained && payload.CommittedAtMilliseconds != record.UpdatedAtMillis) {
		return ErrInvalid
	}
	if signer != nil {
		if payload.DeploymentID != signer.DeploymentID() ||
			receipt.Signature.SignerID != signer.DeploymentID() ||
			receipt.Signature.PublicSigningKeyX963 != signer.PublicSigningKeyX963() ||
			receipt.Signature.SigningKeyFingerprint != signer.SigningKeyFingerprint() {
			return ErrInvalid
		}
	}
	return nil
}

func (coordinator *AdmissionExpiryCoordinator) ReconcileExpiredAdmissions(
	ctx context.Context,
	limit int,
) (int, error) {
	if coordinator.validate() != nil || ctx == nil || limit <= 0 ||
		limit > MaximumAdmissionExpiryBatchSize {
		return 0, ErrInvalid
	}
	now := computequeue.Timestamp(coordinator.Clock.Now().UnixMilli())
	records, err := coordinator.Ledger.ListAdmissionExpiryCandidates(ctx, now, limit)
	if err != nil {
		return 0, err
	}
	completed := 0
	for _, record := range records {
		if record.State == AdmissionStaging || record.State == AdmissionRetained {
			record, err = coordinator.Ledger.RequestAdmissionExpiry(
				ctx, record.Header.CapsuleID, now,
			)
			if err != nil {
				return completed, err
			}
		}
		if _, err := coordinator.finishPendingAdmissionExpiry(ctx, record); err != nil {
			return completed, err
		}
		completed++
	}
	return completed, nil
}

func (coordinator *AdmissionExpiryCoordinator) finishPendingAdmissionExpiry(
	ctx context.Context,
	record AdmissionRecord,
) (AdmissionRecord, error) {
	if ctx == nil || record.ValidateStored() != nil ||
		(record.State != AdmissionStagingExpiryPending && record.State != AdmissionExpiryPending) {
		return AdmissionRecord{}, ErrInvalid
	}
	if record.State == AdmissionStagingExpiryPending {
		if err := coordinator.Content.DeleteStaging(
			record.Header.CapsuleID, record.Header.ProtectedObject, record.CommittedBytes,
		); err != nil {
			return AdmissionRecord{}, err
		}
	} else if err := coordinator.Content.DeleteObject(
		record.Header.CapsuleID, record.Header.ProtectedObject,
	); err != nil {
		return AdmissionRecord{}, err
	}
	expiredAt := coordinator.Clock.Now().UnixMilli()
	if expiredAt < int64(record.Header.RetentionUntil) {
		expiredAt = int64(record.Header.RetentionUntil)
	}
	if expiredAt < record.UpdatedAtMillis {
		expiredAt = record.UpdatedAtMillis
	}
	var receiptBytes []byte
	var err error
	if record.State == AdmissionStagingExpiryPending {
		receiptBytes, err = coordinator.signAdmissionStagingExpiryReceipt(record, expiredAt)
	} else {
		receiptBytes, err = coordinator.signAdmissionExpiryReceipt(record, expiredAt)
	}
	if err != nil {
		return AdmissionRecord{}, err
	}
	criticalContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	expired, err := coordinator.Ledger.FinalizeAdmissionExpiry(
		criticalContext, record.Header.CapsuleID, receiptBytes, expiredAt,
	)
	if err != nil {
		return AdmissionRecord{}, err
	}
	receiptErr := validateAdmissionExpiryReceiptRecord(expired, coordinator.ReceiptSigner)
	if record.State == AdmissionStagingExpiryPending {
		receiptErr = validateAdmissionStagingExpiryReceiptRecord(expired, coordinator.ReceiptSigner)
	}
	if expired.ValidateStored() != nil || expired.State != AdmissionExpired ||
		!sameAdmission(expired, record) || receiptErr != nil {
		return AdmissionRecord{}, ErrInvalid
	}
	return expired, nil
}

func (coordinator *AdmissionExpiryCoordinator) signAdmissionExpiryReceipt(
	record AdmissionRecord,
	expiredAt int64,
) ([]byte, error) {
	if record.ValidateStored() != nil || record.State != AdmissionExpiryPending ||
		expiredAt < int64(record.Header.RetentionUntil) || expiredAt < record.UpdatedAtMillis {
		return nil, ErrInvalid
	}
	capsuleID, capsuleErr := uuid.Parse(string(record.Header.CapsuleID))
	assignmentID, assignmentErr := uuid.Parse(string(record.Header.AssignmentID))
	envelopeDigest, envelopeErr := AdmissionEnvelopeDigest(record.EnvelopeBytes)
	custodyDigest, custodyErr := admissionCustodyReceiptReferenceDigest(record)
	if capsuleErr != nil || assignmentErr != nil || envelopeErr != nil || custodyErr != nil {
		return nil, ErrInvalid
	}
	receipt, err := coordinator.ReceiptSigner.SignJobCustodyExpiryReceipt(
		serviceauthority.JobCustodyExpiryReceiptPayload{
			AdmissionEnvelopeDigest:    string(envelopeDigest),
			AdmissionPermitDigest:      string(record.AdmissionPermitDigest),
			AssignmentID:               assignmentID,
			CapsuleID:                  capsuleID,
			CustodyReceiptDigest:       string(custodyDigest),
			DeploymentID:               coordinator.ReceiptSigner.DeploymentID(),
			ExpiredAtMilliseconds:      expiredAt,
			Kind:                       serviceauthority.JobCustodyExpiryReceiptKind,
			RetentionUntilMilliseconds: int64(record.Header.RetentionUntil),
			Version:                    serviceauthority.JobCustodyExpiryReceiptVersion,
		},
	)
	if err != nil {
		return nil, ErrUnavailable
	}
	encoded, err := receipt.CanonicalJSON()
	if err != nil {
		return nil, ErrUnavailable
	}
	return encoded, nil
}

func (coordinator *AdmissionExpiryCoordinator) signAdmissionStagingExpiryReceipt(
	record AdmissionRecord,
	expiredAt int64,
) ([]byte, error) {
	if record.ValidateStored() != nil || record.State != AdmissionStagingExpiryPending ||
		expiredAt < int64(record.Header.RetentionUntil) || expiredAt < record.UpdatedAtMillis {
		return nil, ErrInvalid
	}
	capsuleID, capsuleErr := uuid.Parse(string(record.Header.CapsuleID))
	assignmentID, assignmentErr := uuid.Parse(string(record.Header.AssignmentID))
	envelopeDigest, envelopeErr := AdmissionEnvelopeDigest(record.EnvelopeBytes)
	if capsuleErr != nil || assignmentErr != nil || envelopeErr != nil {
		return nil, ErrInvalid
	}
	receipt, err := coordinator.ReceiptSigner.SignJobCustodyStagingExpiryReceipt(
		serviceauthority.JobCustodyStagingExpiryReceiptPayload{
			AdmissionEnvelopeDigest:    string(envelopeDigest),
			AdmissionPermitDigest:      string(record.AdmissionPermitDigest),
			AssignmentID:               assignmentID,
			CapsuleID:                  capsuleID,
			CommittedBytes:             record.CommittedBytes,
			DeploymentID:               coordinator.ReceiptSigner.DeploymentID(),
			ExpiredAtMilliseconds:      expiredAt,
			Kind:                       serviceauthority.JobCustodyStagingExpiryReceiptKind,
			ProtectedObjectByteCount:   record.Header.ProtectedObject.ByteCount,
			ProtectedObjectSHA256:      string(record.Header.ProtectedObject.SHA256),
			RetentionUntilMilliseconds: int64(record.Header.RetentionUntil),
			Version:                    serviceauthority.JobCustodyStagingExpiryReceiptVersion,
		},
	)
	if err != nil {
		return nil, ErrUnavailable
	}
	encoded, err := receipt.CanonicalJSON()
	if err != nil {
		return nil, ErrUnavailable
	}
	return encoded, nil
}

func admissionCustodyReceiptReferenceDigest(record AdmissionRecord) (computequeue.Digest, error) {
	if len(record.CustodyReceiptBytes) == 0 {
		return "", ErrInvalid
	}
	receipt, err := serviceauthority.DecodeJobCustodyReceipt(record.CustodyReceiptBytes)
	if err != nil {
		return "", ErrInvalid
	}
	digest, err := receipt.ReferenceDigest()
	if err != nil {
		return "", ErrInvalid
	}
	return computequeue.Digest(digest), nil
}

func validateAdmissionExpiryReceiptRecord(
	record AdmissionRecord,
	signer AdmissionExpiryReceiptSigner,
) error {
	if record.State != AdmissionExpired || len(record.CustodyReceiptBytes) == 0 ||
		len(record.ExpiryReceiptBytes) == 0 {
		return ErrInvalid
	}
	receipt, err := serviceauthority.DecodeJobCustodyExpiryReceipt(record.ExpiryReceiptBytes)
	if err != nil {
		return ErrInvalid
	}
	payload, err := receipt.VerifiedPayload()
	if err != nil {
		return ErrInvalid
	}
	capsuleID, capsuleErr := uuid.Parse(string(record.Header.CapsuleID))
	assignmentID, assignmentErr := uuid.Parse(string(record.Header.AssignmentID))
	envelopeDigest, envelopeErr := AdmissionEnvelopeDigest(record.EnvelopeBytes)
	custodyDigest, custodyErr := admissionCustodyReceiptReferenceDigest(record)
	if capsuleErr != nil || assignmentErr != nil || envelopeErr != nil || custodyErr != nil ||
		payload.AdmissionEnvelopeDigest != string(envelopeDigest) ||
		payload.AdmissionPermitDigest != string(record.AdmissionPermitDigest) ||
		payload.AssignmentID != assignmentID || payload.CapsuleID != capsuleID ||
		payload.CustodyReceiptDigest != string(custodyDigest) ||
		payload.ExpiredAtMilliseconds != record.UpdatedAtMillis ||
		payload.RetentionUntilMilliseconds != int64(record.Header.RetentionUntil) {
		return ErrInvalid
	}
	if signer != nil && (payload.DeploymentID != signer.DeploymentID() ||
		receipt.Signature.SignerID != signer.DeploymentID() ||
		receipt.Signature.PublicSigningKeyX963 != signer.PublicSigningKeyX963() ||
		receipt.Signature.SigningKeyFingerprint != signer.SigningKeyFingerprint()) {
		return ErrInvalid
	}
	return nil
}

func validateAdmissionStagingExpiryReceiptRecord(
	record AdmissionRecord,
	signer AdmissionExpiryReceiptSigner,
) error {
	if record.State != AdmissionExpired || len(record.CustodyReceiptBytes) != 0 ||
		len(record.ExpiryReceiptBytes) == 0 {
		return ErrInvalid
	}
	receipt, err := serviceauthority.DecodeJobCustodyStagingExpiryReceipt(record.ExpiryReceiptBytes)
	if err != nil {
		return ErrInvalid
	}
	payload, err := receipt.VerifiedPayload()
	if err != nil {
		return ErrInvalid
	}
	capsuleID, capsuleErr := uuid.Parse(string(record.Header.CapsuleID))
	assignmentID, assignmentErr := uuid.Parse(string(record.Header.AssignmentID))
	envelopeDigest, envelopeErr := AdmissionEnvelopeDigest(record.EnvelopeBytes)
	if capsuleErr != nil || assignmentErr != nil || envelopeErr != nil ||
		payload.AdmissionEnvelopeDigest != string(envelopeDigest) ||
		payload.AdmissionPermitDigest != string(record.AdmissionPermitDigest) ||
		payload.AssignmentID != assignmentID || payload.CapsuleID != capsuleID ||
		payload.CommittedBytes != record.CommittedBytes ||
		payload.ExpiredAtMilliseconds != record.UpdatedAtMillis ||
		payload.ProtectedObjectByteCount != record.Header.ProtectedObject.ByteCount ||
		payload.ProtectedObjectSHA256 != string(record.Header.ProtectedObject.SHA256) ||
		payload.RetentionUntilMilliseconds != int64(record.Header.RetentionUntil) {
		return ErrInvalid
	}
	if signer != nil && (payload.DeploymentID != signer.DeploymentID() ||
		receipt.Signature.SignerID != signer.DeploymentID() ||
		receipt.Signature.PublicSigningKeyX963 != signer.PublicSigningKeyX963() ||
		receipt.Signature.SigningKeyFingerprint != signer.SigningKeyFingerprint()) {
		return ErrInvalid
	}
	return nil
}
