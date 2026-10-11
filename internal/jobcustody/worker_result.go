package jobcustody

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/computequeue"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
	"github.com/robreuss/FacetsNode/internal/storagecapacity"
)

type ResultState string

const (
	ResultStaging  ResultState = "staging"
	ResultRetained ResultState = "retained"
)

// ResultRecord is the complete clear metadata retained beside one opaque
// protected result. It contains only custody and routing commitments.
type ResultRecord struct {
	Header                       WorkerResultHeader
	RouteAuthorityID             uuid.UUID
	RouteRecipientWorkerID       computequeue.WorkerID
	RouteRecipientKeyFingerprint computequeue.Digest
	WorkerCapabilitiesDigest     computequeue.Digest
	WorkerOwnerAuthorityDigest   computequeue.Digest
	ClaimPermitDigest            computequeue.Digest
	ResultPermitDigest           computequeue.Digest
	AcceptedAt                   computequeue.Timestamp
	CommittedBytes               int64
	State                        ResultState
	ObjectPath                   string
	CustodyReceiptBytes          []byte
	UpdatedAtMillis              int64
}

func (record ResultRecord) ValidateStored() error {
	if record.Header.Validate() != nil || record.RouteAuthorityID == uuid.Nil ||
		record.RouteRecipientWorkerID.Validate() != nil ||
		record.RouteRecipientKeyFingerprint.Validate() != nil ||
		record.WorkerCapabilitiesDigest.Validate() != nil ||
		record.WorkerOwnerAuthorityDigest.Validate() != nil ||
		record.ClaimPermitDigest.Validate() != nil || record.ResultPermitDigest.Validate() != nil ||
		record.AcceptedAt.Validate() != nil || record.AcceptedAt >= record.Header.RetentionUntil ||
		record.CommittedBytes < 0 || record.CommittedBytes > record.Header.ProtectedObject.ByteCount ||
		record.UpdatedAtMillis < int64(record.AcceptedAt) {
		return ErrInvalid
	}
	expectedPath := filepath.Join("objects", string(record.Header.ResultCapsuleID))
	switch record.State {
	case ResultStaging:
		if record.ObjectPath != "" || len(record.CustodyReceiptBytes) != 0 {
			return ErrInvalid
		}
	case ResultRetained:
		if record.CommittedBytes != record.Header.ProtectedObject.ByteCount ||
			record.ObjectPath != expectedPath || len(record.CustodyReceiptBytes) == 0 ||
			validateResultCustodyReceiptRecord(record, nil) != nil {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func sameResultIdentity(left, right ResultRecord) bool {
	return left.Header == right.Header && left.RouteAuthorityID == right.RouteAuthorityID &&
		left.RouteRecipientWorkerID == right.RouteRecipientWorkerID &&
		left.RouteRecipientKeyFingerprint == right.RouteRecipientKeyFingerprint &&
		left.WorkerCapabilitiesDigest == right.WorkerCapabilitiesDigest &&
		left.WorkerOwnerAuthorityDigest == right.WorkerOwnerAuthorityDigest &&
		left.ClaimPermitDigest == right.ClaimPermitDigest
}

func sameResult(left, right ResultRecord) bool {
	return sameResultIdentity(left, right) && left.AcceptedAt == right.AcceptedAt
}

type ResultLedger interface {
	LoadWorkerClaim(context.Context, uuid.UUID) (WorkerClaimRecord, AdmissionRecord, error)
	LoadResult(context.Context, computequeue.JobCapsuleID) (ResultRecord, error)
	ListResultsForInput(context.Context, computequeue.JobCapsuleID) ([]ResultRecord, AdmissionRecord, error)
	ReserveResult(context.Context, ResultRecord) (ResultRecord, bool, error)
	BeginResultAppend(context.Context, AppendRequest) (ResultAppendLease, error)
	BeginResultFinalization(context.Context, computequeue.JobCapsuleID) (ResultFinalizationLease, error)
}

type ResultDeliveryCoordinator struct {
	Ledger  ResultLedger
	Content *ContentStore
	Clock   Clock
}

func (coordinator *ResultDeliveryCoordinator) validate() error {
	if coordinator == nil || coordinator.Ledger == nil || coordinator.Content == nil ||
		coordinator.Clock == nil {
		return ErrInvalid
	}
	return nil
}

type ResultDeliveryHandle struct {
	authorization ResultRetrievalAuthorization
	record        ResultRecord
}

func (handle ResultDeliveryHandle) Record() ResultRecord {
	return cloneResultRecord(handle.record)
}

func (coordinator *ResultDeliveryCoordinator) ListAuthorized(
	ctx context.Context,
	authorization ResultRetrievalAuthorization,
) ([]ResultRecord, error) {
	if coordinator.validate() != nil || ctx == nil || authorization.payload.Validate() != nil ||
		authorization.permitDigest.Validate() != nil {
		return nil, ErrInvalid
	}
	payload := authorization.payload
	now := computequeue.Timestamp(coordinator.Clock.Now().UnixMilli())
	if now < payload.IssuedAt || now >= payload.ExpiresAt {
		return nil, ErrConflict
	}
	results, admission, err := coordinator.Ledger.ListResultsForInput(ctx, payload.InputCapsuleID)
	if err != nil {
		return nil, err
	}
	if validateResultRetrievalBinding(admission, authorization, now) != nil {
		return nil, ErrConflict
	}
	cloned := make([]ResultRecord, 0, len(results))
	for _, result := range results {
		if result.ValidateStored() != nil || result.Header.InputCapsuleID != payload.InputCapsuleID ||
			result.RouteAuthorityID != payload.AuthorityID {
			return nil, ErrInvalid
		}
		if now >= result.Header.RetentionUntil {
			continue
		}
		cloned = append(cloned, cloneResultRecord(result))
	}
	return cloned, nil
}

func (coordinator *ResultDeliveryCoordinator) OpenAuthorized(
	ctx context.Context,
	authorization ResultRetrievalAuthorization,
	resultCapsuleID computequeue.JobCapsuleID,
) (ResultDeliveryHandle, error) {
	if resultCapsuleID.Validate() != nil {
		return ResultDeliveryHandle{}, ErrInvalid
	}
	results, err := coordinator.ListAuthorized(ctx, authorization)
	if err != nil {
		return ResultDeliveryHandle{}, err
	}
	for _, result := range results {
		if result.Header.ResultCapsuleID != resultCapsuleID {
			continue
		}
		if result.State != ResultRetained {
			return ResultDeliveryHandle{}, ErrConflict
		}
		file, err := coordinator.Content.OpenObject(resultCapsuleID, result.Header.ProtectedObject)
		if err != nil {
			return ResultDeliveryHandle{}, err
		}
		if err := file.Close(); err != nil {
			return ResultDeliveryHandle{}, ErrUnavailable
		}
		return ResultDeliveryHandle{authorization: authorization, record: result}, nil
	}
	return ResultDeliveryHandle{}, ErrMissing
}

func (coordinator *ResultDeliveryCoordinator) ReadChunk(
	handle ResultDeliveryHandle,
	chunkIndex int64,
) ([]byte, error) {
	if coordinator.validate() != nil || handle.authorization.payload.Validate() != nil ||
		handle.record.ValidateStored() != nil || handle.record.State != ResultRetained ||
		handle.record.Header.InputCapsuleID != handle.authorization.payload.InputCapsuleID ||
		chunkIndex < 0 || chunkIndex >= handle.record.Header.ProtectedObject.ChunkCount {
		return nil, ErrInvalid
	}
	now := computequeue.Timestamp(coordinator.Clock.Now().UnixMilli())
	if now < handle.authorization.payload.IssuedAt || now >= handle.authorization.payload.ExpiresAt ||
		now >= handle.record.Header.RetentionUntil {
		return nil, ErrConflict
	}
	descriptor := handle.record.Header.ProtectedObject
	offset := chunkIndex * descriptor.ChunkByteCount
	byteCount := min(descriptor.ChunkByteCount, descriptor.ByteCount-offset)
	file, err := coordinator.Content.OpenObject(handle.record.Header.ResultCapsuleID, descriptor)
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

type ResultAppendLease interface {
	Result() ResultRecord
	ExistingNextOffset() *int64
	Commit(context.Context, int64) error
	Abort(context.Context) error
}

type ResultFinalizationLease interface {
	Result() ResultRecord
	Commit(context.Context, string, []byte, int64) (ResultRecord, error)
	Abort(context.Context) error
}

type ResultReceiptSigner interface {
	DeploymentID() uuid.UUID
	PublicSigningKeyX963() string
	SigningKeyFingerprint() string
	SignJobCustodyResultReceipt(
		serviceauthority.JobCustodyResultReceiptPayload,
	) (serviceauthority.JobCustodyResultReceipt, error)
}

type ResultCoordinator struct {
	Ledger        ResultLedger
	Content       *ContentStore
	Capacity      CapacityAuthority
	ReceiptSigner ResultReceiptSigner
	Clock         Clock
}

func (coordinator *ResultCoordinator) validate() error {
	if coordinator == nil || coordinator.Ledger == nil || coordinator.Content == nil ||
		coordinator.Capacity == nil || coordinator.ReceiptSigner == nil ||
		coordinator.ReceiptSigner.DeploymentID() == uuid.Nil || coordinator.Clock == nil {
		return ErrInvalid
	}
	return nil
}

type ResultHandle struct {
	authorization WorkerResultAuthorization
	record        ResultRecord
}

func (handle ResultHandle) Record() ResultRecord { return cloneResultRecord(handle.record) }

func (coordinator *ResultCoordinator) AcceptAuthorized(
	ctx context.Context,
	authorization WorkerResultAuthorization,
) (ResultHandle, error) {
	if coordinator.validate() != nil || ctx == nil || authorization.payload.Validate() != nil ||
		authorization.permitDigest.Validate() != nil {
		return ResultHandle{}, ErrInvalid
	}
	payload := authorization.payload
	now := computequeue.Timestamp(coordinator.Clock.Now().UnixMilli())
	if now < payload.IssuedAt || now >= payload.ExpiresAt {
		return ResultHandle{}, ErrConflict
	}
	claim, admission, err := coordinator.Ledger.LoadWorkerClaim(ctx, payload.Result.ClaimID)
	if err != nil {
		return ResultHandle{}, err
	}
	if validateWorkerResultBinding(claim, admission, authorization, now) != nil {
		return ResultHandle{}, ErrConflict
	}
	if existing, loadErr := coordinator.Ledger.LoadResult(ctx, payload.Result.ResultCapsuleID); loadErr == nil {
		if existing.ValidateStored() != nil || !sameResultAuthorization(existing, authorization) {
			return ResultHandle{}, ErrConflict
		}
		return coordinator.openResult(authorization, existing, false)
	} else if !errors.Is(loadErr, ErrMissing) {
		return ResultHandle{}, loadErr
	}
	candidate := ResultRecord{
		Header: payload.Result, RouteAuthorityID: payload.AuthorityID,
		RouteRecipientWorkerID:       payload.RouteRecipientWorkerID,
		RouteRecipientKeyFingerprint: payload.RouteRecipientKeyFingerprint,
		WorkerCapabilitiesDigest:     payload.WorkerCapabilitiesDigest,
		WorkerOwnerAuthorityDigest:   payload.WorkerOwnerAuthorityDigest,
		ClaimPermitDigest:            claim.ClaimPermitDigest,
		ResultPermitDigest:           authorization.permitDigest,
		AcceptedAt:                   now, State: ResultStaging, UpdatedAtMillis: int64(now),
	}
	if candidate.ValidateStored() != nil {
		return ResultHandle{}, ErrInvalid
	}
	record, created, err := coordinator.Ledger.ReserveResult(ctx, candidate)
	if err != nil {
		return ResultHandle{}, err
	}
	if record.ValidateStored() != nil || !sameResultIdentity(record, candidate) {
		return ResultHandle{}, ErrConflict
	}
	return coordinator.openResult(authorization, record, created)
}

func (coordinator *ResultCoordinator) openResult(
	authorization WorkerResultAuthorization,
	record ResultRecord,
	created bool,
) (ResultHandle, error) {
	if created || (record.State == ResultStaging && record.CommittedBytes == 0) {
		if err := coordinator.Content.Prepare(record.Header.ResultCapsuleID); err != nil {
			return ResultHandle{}, err
		}
	} else if record.State == ResultRetained {
		if validateResultCustodyReceiptRecord(record, coordinator.ReceiptSigner) != nil {
			return ResultHandle{}, ErrInvalid
		}
		file, err := coordinator.Content.OpenObject(
			record.Header.ResultCapsuleID, record.Header.ProtectedObject,
		)
		if err != nil {
			return ResultHandle{}, err
		}
		if err := file.Close(); err != nil {
			return ResultHandle{}, ErrUnavailable
		}
	}
	return ResultHandle{authorization: authorization, record: record}, nil
}

func (coordinator *ResultCoordinator) AppendChunk(
	ctx context.Context,
	handle ResultHandle,
	chunkIndex int64,
	chunk []byte,
	chunkSHA256 computequeue.Digest,
) (int64, error) {
	if coordinator.validate() != nil || ctx == nil || len(chunk) == 0 ||
		handle.authorization.payload.Validate() != nil || handle.record.ValidateStored() != nil ||
		!sameResultAuthorization(handle.record, handle.authorization) ||
		handle.record.State != ResultStaging {
		return 0, ErrInvalid
	}
	now := computequeue.Timestamp(coordinator.Clock.Now().UnixMilli())
	if now < handle.authorization.payload.IssuedAt || now >= handle.authorization.payload.ExpiresAt {
		return 0, ErrConflict
	}
	header := handle.record.Header
	digest := sha256.Sum256(chunk)
	if fmt.Sprintf("%x", digest[:]) != string(chunkSHA256) {
		return 0, ErrInvalid
	}
	request := AppendRequest{
		CapsuleID: header.ResultCapsuleID, ChunkIndex: chunkIndex,
		Offset:    chunkIndex * header.ProtectedObject.ChunkByteCount,
		ByteCount: int64(len(chunk)), ChunkSHA256: chunkSHA256,
	}
	if err := request.Validate(header.ProtectedObject); err != nil {
		return 0, err
	}
	appendLease, err := coordinator.Ledger.BeginResultAppend(ctx, request)
	if err != nil {
		return 0, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = appendLease.Abort(context.WithoutCancel(ctx))
		}
	}()
	record := appendLease.Result()
	if record.ValidateStored() != nil || !sameResult(record, handle.record) || record.State != ResultStaging {
		return 0, ErrConflict
	}
	if existing := appendLease.ExistingNextOffset(); existing != nil {
		if *existing != request.Offset+request.ByteCount ||
			coordinator.Content.VerifyRange(header.ResultCapsuleID, request.Offset, request.ByteCount, request.ChunkSHA256) != nil {
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
		header.ResultCapsuleID, header.ProtectedObject, request.Offset, chunk,
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

func (coordinator *ResultCoordinator) Finalize(
	ctx context.Context,
	handle ResultHandle,
) (ResultRecord, error) {
	if coordinator.validate() != nil || ctx == nil || handle.record.ValidateStored() != nil ||
		handle.authorization.payload.Validate() != nil ||
		!sameResultAuthorization(handle.record, handle.authorization) {
		return ResultRecord{}, ErrInvalid
	}
	now := computequeue.Timestamp(coordinator.Clock.Now().UnixMilli())
	if now < handle.authorization.payload.IssuedAt || now >= handle.authorization.payload.ExpiresAt {
		return ResultRecord{}, ErrConflict
	}
	lease, err := coordinator.Ledger.BeginResultFinalization(ctx, handle.record.Header.ResultCapsuleID)
	if err != nil {
		return ResultRecord{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = lease.Abort(context.WithoutCancel(ctx))
		}
	}()
	record := lease.Result()
	if record.ValidateStored() != nil || !sameResult(record, handle.record) {
		return ResultRecord{}, ErrConflict
	}
	if record.State == ResultRetained {
		if validateResultCustodyReceiptRecord(record, coordinator.ReceiptSigner) != nil {
			return ResultRecord{}, ErrInvalid
		}
		file, err := coordinator.Content.OpenObject(record.Header.ResultCapsuleID, record.Header.ProtectedObject)
		if err != nil {
			return ResultRecord{}, err
		}
		if err := file.Close(); err != nil {
			return ResultRecord{}, ErrUnavailable
		}
		if err := lease.Abort(ctx); err != nil {
			return ResultRecord{}, err
		}
		committed = true
		return record, nil
	}
	if record.State != ResultStaging || record.CommittedBytes != record.Header.ProtectedObject.ByteCount {
		return ResultRecord{}, ErrConflict
	}
	objectPath, err := coordinator.Content.Finalize(record.Header.ResultCapsuleID, record.Header.ProtectedObject)
	if err != nil {
		return ResultRecord{}, err
	}
	committedAt := coordinator.Clock.Now().UnixMilli()
	if committedAt < record.UpdatedAtMillis {
		committedAt = record.UpdatedAtMillis
	}
	if committedAt > int64(record.Header.RetentionUntil) {
		return ResultRecord{}, ErrConflict
	}
	receiptBytes, err := coordinator.signResultCustodyReceipt(record, committedAt)
	if err != nil {
		return ResultRecord{}, err
	}
	criticalContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	committedRecord, err := lease.Commit(criticalContext, objectPath, receiptBytes, committedAt)
	if err != nil {
		return ResultRecord{}, err
	}
	committed = true
	if committedRecord.ValidateStored() != nil || !sameResult(committedRecord, record) ||
		committedRecord.State != ResultRetained ||
		validateResultCustodyReceiptRecord(committedRecord, coordinator.ReceiptSigner) != nil {
		return ResultRecord{}, ErrInvalid
	}
	return committedRecord, nil
}

func validateWorkerResultBinding(
	claim WorkerClaimRecord,
	admission AdmissionRecord,
	authorization WorkerResultAuthorization,
	now computequeue.Timestamp,
) error {
	payload := authorization.payload
	header := payload.Result
	if claim.ValidateStored() != nil || admission.ValidateStored() != nil ||
		claim.State != WorkerClaimClaimed || now >= claim.LeaseExpiresAt ||
		payload.ExpiresAt > claim.LeaseExpiresAt || header.ClaimID != claim.ClaimID ||
		header.InputCapsuleID != admission.Header.CapsuleID ||
		header.AssignmentID != admission.Header.AssignmentID ||
		header.RetentionUntil > admission.Header.RetentionUntil ||
		claim.RouteAuthorityID != payload.AuthorityID ||
		claim.RouteRecipientWorkerID != payload.RouteRecipientWorkerID ||
		claim.RouteRecipientKeyFingerprint != payload.RouteRecipientKeyFingerprint ||
		claim.WorkerCapabilitiesDigest != payload.WorkerCapabilitiesDigest ||
		claim.WorkerOwnerAuthorityDigest != payload.WorkerOwnerAuthorityDigest {
		return ErrInvalid
	}
	return nil
}

func validateResultRetrievalBinding(
	admission AdmissionRecord,
	authorization ResultRetrievalAuthorization,
	now computequeue.Timestamp,
) error {
	payload := authorization.payload
	if admission.ValidateStored() != nil || admission.State != AdmissionRetained ||
		payload.Validate() != nil || authorization.permitDigest.Validate() != nil ||
		now < payload.IssuedAt || now >= payload.ExpiresAt ||
		now >= admission.Header.RetentionUntil ||
		admission.Header.CapsuleID != payload.InputCapsuleID ||
		admission.RouteAuthorityID != payload.AuthorityID ||
		admission.RequesterAuthorityDigest != payload.RequesterAuthorityDigest ||
		admission.AdmissionPermitDigest != payload.AdmissionPermitDigest {
		return ErrInvalid
	}
	return nil
}

func sameResultAuthorization(record ResultRecord, authorization WorkerResultAuthorization) bool {
	payload := authorization.payload
	return record.ValidateStored() == nil && payload.Validate() == nil &&
		record.Header == payload.Result && record.RouteAuthorityID == payload.AuthorityID &&
		record.RouteRecipientWorkerID == payload.RouteRecipientWorkerID &&
		record.RouteRecipientKeyFingerprint == payload.RouteRecipientKeyFingerprint &&
		record.WorkerCapabilitiesDigest == payload.WorkerCapabilitiesDigest &&
		record.WorkerOwnerAuthorityDigest == payload.WorkerOwnerAuthorityDigest
}

func (coordinator *ResultCoordinator) signResultCustodyReceipt(
	record ResultRecord,
	committedAt int64,
) ([]byte, error) {
	assignmentID, assignmentErr := uuid.Parse(string(record.Header.AssignmentID))
	inputCapsuleID, inputErr := uuid.Parse(string(record.Header.InputCapsuleID))
	resultCapsuleID, resultErr := uuid.Parse(string(record.Header.ResultCapsuleID))
	if assignmentErr != nil || inputErr != nil || resultErr != nil {
		return nil, ErrInvalid
	}
	payload := serviceauthority.JobCustodyResultReceiptPayload{
		AssignmentID: assignmentID, ClaimID: record.Header.ClaimID,
		ClaimPermitDigest:       string(record.ClaimPermitDigest),
		CommittedAtMilliseconds: committedAt,
		DeploymentID:            coordinator.ReceiptSigner.DeploymentID(), InputCapsuleID: inputCapsuleID,
		Kind:                            serviceauthority.JobCustodyResultReceiptKind,
		ProtectedObjectByteCount:        record.Header.ProtectedObject.ByteCount,
		ProtectedObjectDescriptorDigest: string(record.Header.ProtectedObject.Digest()),
		ProtectedObjectSHA256:           string(record.Header.ProtectedObject.SHA256),
		ResultCapsuleID:                 resultCapsuleID,
		ResultIdempotencyKey:            string(record.Header.IdempotencyKey),
		ResultPermitDigest:              string(record.ResultPermitDigest),
		ResultSetDigest:                 string(record.Header.ResultSetDigest),
		RetentionUntilMilliseconds:      int64(record.Header.RetentionUntil),
		Version:                         serviceauthority.JobCustodyResultReceiptVersion,
		WorkerExecutionReceiptDigest:    string(record.Header.WorkerExecutionReceiptDigest),
	}
	receipt, err := coordinator.ReceiptSigner.SignJobCustodyResultReceipt(payload)
	if err != nil {
		return nil, ErrUnavailable
	}
	encoded, err := receipt.CanonicalJSON()
	if err != nil {
		return nil, ErrUnavailable
	}
	return encoded, nil
}

func validateResultCustodyReceiptRecord(record ResultRecord, signer ResultReceiptSigner) error {
	receipt, err := serviceauthority.DecodeJobCustodyResultReceipt(record.CustodyReceiptBytes)
	if err != nil {
		return ErrInvalid
	}
	payload, err := receipt.VerifiedPayload()
	if err != nil {
		return ErrInvalid
	}
	assignmentID, assignmentErr := uuid.Parse(string(record.Header.AssignmentID))
	inputCapsuleID, inputErr := uuid.Parse(string(record.Header.InputCapsuleID))
	resultCapsuleID, resultErr := uuid.Parse(string(record.Header.ResultCapsuleID))
	if assignmentErr != nil || inputErr != nil || resultErr != nil ||
		payload.AssignmentID != assignmentID || payload.ClaimID != record.Header.ClaimID ||
		payload.ClaimPermitDigest != string(record.ClaimPermitDigest) ||
		payload.InputCapsuleID != inputCapsuleID || payload.ResultCapsuleID != resultCapsuleID ||
		payload.ProtectedObjectByteCount != record.Header.ProtectedObject.ByteCount ||
		payload.ProtectedObjectDescriptorDigest != string(record.Header.ProtectedObject.Digest()) ||
		payload.ProtectedObjectSHA256 != string(record.Header.ProtectedObject.SHA256) ||
		payload.ResultIdempotencyKey != string(record.Header.IdempotencyKey) ||
		payload.ResultPermitDigest != string(record.ResultPermitDigest) ||
		payload.ResultSetDigest != string(record.Header.ResultSetDigest) ||
		payload.RetentionUntilMilliseconds != int64(record.Header.RetentionUntil) ||
		payload.WorkerExecutionReceiptDigest != string(record.Header.WorkerExecutionReceiptDigest) ||
		payload.CommittedAtMilliseconds != record.UpdatedAtMillis {
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

func cloneResultRecord(record ResultRecord) ResultRecord {
	record.CustodyReceiptBytes = bytes.Clone(record.CustodyReceiptBytes)
	return record
}
