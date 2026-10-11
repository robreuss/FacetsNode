package jobcustody

import (
	"context"
	"errors"
	"io"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/computequeue"
)

var ErrNoWork = errors.New("no retained job custody assignment is ready")

type WorkerClaimState string

const (
	WorkerClaimClaimed WorkerClaimState = "claimed"
	WorkerClaimExpired WorkerClaimState = "expired"
)

// WorkerClaimRecord is content-blind lease state for one exact retained
// capsule. Assignment semantics remain protected inside the capsule.
type WorkerClaimRecord struct {
	ClaimID                      uuid.UUID
	CapsuleID                    computequeue.JobCapsuleID
	RouteAuthorityID             uuid.UUID
	RouteRecipientWorkerID       computequeue.WorkerID
	RouteRecipientKeyFingerprint computequeue.Digest
	WorkerCapabilitiesDigest     computequeue.Digest
	WorkerOwnerAuthorityDigest   computequeue.Digest
	ClaimPermitDigest            computequeue.Digest
	ClaimedAt                    computequeue.Timestamp
	LeaseExpiresAt               computequeue.Timestamp
	State                        WorkerClaimState
	UpdatedAtMillis              int64
}

func (record WorkerClaimRecord) ValidateStored() error {
	if record.ClaimID == uuid.Nil || record.CapsuleID.Validate() != nil ||
		record.RouteAuthorityID == uuid.Nil || record.RouteRecipientWorkerID.Validate() != nil ||
		record.RouteRecipientKeyFingerprint.Validate() != nil ||
		record.WorkerCapabilitiesDigest.Validate() != nil ||
		record.WorkerOwnerAuthorityDigest.Validate() != nil ||
		record.ClaimPermitDigest.Validate() != nil || record.ClaimedAt.Validate() != nil ||
		record.LeaseExpiresAt.Validate() != nil || record.ClaimedAt >= record.LeaseExpiresAt ||
		record.UpdatedAtMillis < int64(record.ClaimedAt) {
		return ErrInvalid
	}
	switch record.State {
	case WorkerClaimClaimed, WorkerClaimExpired:
		return nil
	default:
		return ErrInvalid
	}
}

type WorkerClaimLedger interface {
	ClaimNext(context.Context, WorkerClaimAuthorization) (WorkerClaimRecord, AdmissionRecord, error)
	RenewClaim(context.Context, WorkerClaimAuthorization) (WorkerClaimRecord, AdmissionRecord, error)
}

type WorkerClaimCoordinator struct {
	Ledger  WorkerClaimLedger
	Content *ContentStore
	Clock   Clock
}

func (coordinator *WorkerClaimCoordinator) validate() error {
	if coordinator == nil || coordinator.Ledger == nil || coordinator.Content == nil ||
		coordinator.Clock == nil {
		return ErrInvalid
	}
	return nil
}

type WorkerClaimHandle struct {
	record    WorkerClaimRecord
	admission AdmissionRecord
}

func (handle WorkerClaimHandle) Record() WorkerClaimRecord { return handle.record }

func (handle WorkerClaimHandle) Admission() AdmissionRecord {
	return cloneWorkerClaimAdmission(handle.admission)
}

func (coordinator *WorkerClaimCoordinator) Claim(
	ctx context.Context,
	authorization WorkerClaimAuthorization,
) (WorkerClaimHandle, error) {
	if coordinator.validate() != nil || ctx == nil ||
		authorization.payload.Validate() != nil || authorization.permitDigest.Validate() != nil {
		return WorkerClaimHandle{}, ErrInvalid
	}
	now := computequeue.Timestamp(coordinator.Clock.Now().UnixMilli())
	if now < authorization.payload.IssuedAt || now >= authorization.payload.ExpiresAt {
		return WorkerClaimHandle{}, ErrConflict
	}
	record, admission, err := coordinator.Ledger.ClaimNext(ctx, authorization)
	if err != nil {
		return WorkerClaimHandle{}, err
	}
	if validateWorkerClaimBinding(record, admission, authorization) != nil ||
		record.State != WorkerClaimClaimed || now >= record.LeaseExpiresAt {
		return WorkerClaimHandle{}, ErrInvalid
	}
	file, err := coordinator.Content.OpenObject(admission.Header.CapsuleID, admission.Header.ProtectedObject)
	if err != nil {
		return WorkerClaimHandle{}, err
	}
	if err := file.Close(); err != nil {
		return WorkerClaimHandle{}, ErrUnavailable
	}
	return WorkerClaimHandle{record: record, admission: admission}, nil
}

func (coordinator *WorkerClaimCoordinator) Renew(
	ctx context.Context,
	authorization WorkerClaimAuthorization,
) (WorkerClaimHandle, error) {
	if coordinator.validate() != nil || ctx == nil || authorization.payload.Validate() != nil ||
		authorization.permitDigest.Validate() != nil {
		return WorkerClaimHandle{}, ErrInvalid
	}
	now := computequeue.Timestamp(coordinator.Clock.Now().UnixMilli())
	if now < authorization.payload.IssuedAt || now >= authorization.payload.ExpiresAt {
		return WorkerClaimHandle{}, ErrConflict
	}
	record, admission, err := coordinator.Ledger.RenewClaim(ctx, authorization)
	if err != nil {
		return WorkerClaimHandle{}, err
	}
	if validateWorkerClaimBinding(record, admission, authorization) != nil ||
		record.State != WorkerClaimClaimed || record.ClaimID != authorization.payload.ClaimID {
		return WorkerClaimHandle{}, ErrInvalid
	}
	return WorkerClaimHandle{record: record, admission: admission}, nil
}

func (coordinator *WorkerClaimCoordinator) ReadChunk(
	handle WorkerClaimHandle,
	chunkIndex int64,
) ([]byte, error) {
	if coordinator.validate() != nil || handle.record.ValidateStored() != nil ||
		handle.admission.ValidateStored() != nil || handle.record.State != WorkerClaimClaimed ||
		chunkIndex < 0 || chunkIndex >= handle.admission.Header.ProtectedObject.ChunkCount {
		return nil, ErrInvalid
	}
	descriptor := handle.admission.Header.ProtectedObject
	offset := chunkIndex * descriptor.ChunkByteCount
	byteCount := min(descriptor.ChunkByteCount, descriptor.ByteCount-offset)
	file, err := coordinator.Content.OpenObject(handle.admission.Header.CapsuleID, descriptor)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return nil, ErrUnavailable
	}
	result := make([]byte, int(byteCount))
	if _, err := io.ReadFull(file, result); err != nil {
		return nil, ErrUnavailable
	}
	return result, nil
}

func validateWorkerClaimBinding(
	record WorkerClaimRecord,
	admission AdmissionRecord,
	authorization WorkerClaimAuthorization,
) error {
	payload := authorization.payload
	if record.ValidateStored() != nil || admission.ValidateStored() != nil ||
		admission.State != AdmissionRetained || record.CapsuleID != admission.Header.CapsuleID ||
		record.ClaimID != payload.ClaimID || record.RouteAuthorityID != payload.AuthorityID ||
		record.RouteAuthorityID != admission.RouteAuthorityID ||
		record.RouteRecipientWorkerID != payload.RouteRecipientWorkerID ||
		record.RouteRecipientWorkerID != admission.Header.RouteRecipientWorkerID ||
		record.RouteRecipientKeyFingerprint != payload.RouteRecipientKeyFingerprint ||
		record.RouteRecipientKeyFingerprint != admission.Header.RouteRecipientKeyFingerprint ||
		record.WorkerCapabilitiesDigest != payload.WorkerCapabilitiesDigest ||
		record.WorkerCapabilitiesDigest != admission.WorkerCapabilitiesDigest ||
		record.WorkerOwnerAuthorityDigest != payload.WorkerOwnerAuthorityDigest ||
		record.ClaimPermitDigest != authorization.permitDigest ||
		record.LeaseExpiresAt != payload.ExpiresAt ||
		record.LeaseExpiresAt > admission.Header.RetentionUntil {
		return ErrInvalid
	}
	return nil
}

func cloneWorkerClaimAdmission(record AdmissionRecord) AdmissionRecord {
	record.EnvelopeBytes = append([]byte(nil), record.EnvelopeBytes...)
	record.CustodyReceiptBytes = append([]byte(nil), record.CustodyReceiptBytes...)
	return record
}
