package jobcustody

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/robreuss/FacetsNode/internal/computequeue"
	"github.com/robreuss/FacetsNode/internal/storagecapacity"
)

type AdmissionState string

const (
	AdmissionStaging  AdmissionState = "staging"
	AdmissionRetained AdmissionState = "retained"
)

// AdmissionRecord is the complete durable metadata permitted beside opaque
// protected bytes. It intentionally has no Space, object, prompt, model,
// operation, result, credential, label, or caller-selected path field.
type AdmissionRecord struct {
	EnvelopeBytes   []byte
	Header          computequeue.JobCustodyAdmissionHeader
	ExpectedSigner  computequeue.ReceiptSignerBinding
	AcceptedAt      computequeue.Timestamp
	CommittedBytes  int64
	State           AdmissionState
	ObjectPath      string
	UpdatedAtMillis int64
}

func (record AdmissionRecord) ValidateStored() error {
	if len(record.EnvelopeBytes) == 0 || record.Header.Validate() != nil ||
		record.ExpectedSigner.Validate() != nil || record.AcceptedAt.Validate() != nil ||
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
	switch record.State {
	case AdmissionStaging:
		if record.ObjectPath != "" {
			return ErrInvalid
		}
	case AdmissionRetained:
		if record.CommittedBytes != record.Header.ProtectedObject.ByteCount ||
			record.ObjectPath != expectedPath {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func sameAdmissionIdentity(left, right AdmissionRecord) bool {
	return bytes.Equal(left.EnvelopeBytes, right.EnvelopeBytes) &&
		left.Header == right.Header && left.ExpectedSigner == right.ExpectedSigner
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
	Commit(context.Context, string) (AdmissionRecord, error)
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

type Coordinator struct {
	Ledger   Ledger
	Content  *ContentStore
	Capacity CapacityAuthority
	Verifier AdmissionVerifier
	Clock    Clock
}

func (coordinator *Coordinator) validate() error {
	if coordinator == nil || coordinator.Ledger == nil || coordinator.Content == nil ||
		coordinator.Capacity == nil || coordinator.Verifier == nil || coordinator.Clock == nil {
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
		authorization.permitDigest.Validate() != nil {
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
		EnvelopeBytes:   bytes.Clone(envelopeBytes),
		Header:          verified.Header(),
		ExpectedSigner:  verified.ExpectedSigner(),
		AcceptedAt:      acceptedAt,
		State:           AdmissionStaging,
		UpdatedAtMillis: int64(acceptedAt),
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
	criticalContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	committedRecord, err := lease.Commit(criticalContext, objectPath)
	if err != nil {
		return AdmissionRecord{}, err
	}
	committed = true
	if committedRecord.ValidateStored() != nil ||
		!sameAdmission(committedRecord, record) ||
		committedRecord.State != AdmissionRetained ||
		committedRecord.CommittedBytes != header.ProtectedObject.ByteCount ||
		committedRecord.ObjectPath != objectPath {
		return AdmissionRecord{}, ErrInvalid
	}
	return committedRecord, nil
}
