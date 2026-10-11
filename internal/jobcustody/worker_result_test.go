package jobcustody

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/computequeue"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

func TestResultCoordinatorRetainsExactProtectedResult(t *testing.T) {
	inputContent, _ := temporaryContentStore(t)
	resultContent, _ := temporaryContentStore(t)
	ledger := newMemoryLedger()
	capacity := &memoryCapacityAuthority{}
	fixture := newStagingFixture(t, []byte("opaque-input-capsule"), 64)
	clock := fixedJobCustodyClock{time.UnixMilli(1_800_000_000_010)}
	signer := testJobCustodyReceiptSigner(t)
	inputCoordinator := &Coordinator{
		Ledger: ledger, Content: inputContent, Capacity: capacity,
		Verifier: fixture.verifier, ReceiptSigner: signer, Clock: clock,
	}
	inputHandle, err := inputCoordinator.AdmitAuthorized(
		t.Context(), fixture.envelopeBytes, fixture.authorization(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inputCoordinator.AppendChunk(
		t.Context(), inputHandle, 0, fixture.protectedBytes, digestBytes(fixture.protectedBytes),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := inputCoordinator.Finalize(t.Context(), inputHandle); err != nil {
		t.Fatal(err)
	}
	claimAuthorization := verifiedWorkerClaimAuthorization(t, fixture, 1_800_000_060_000)
	claimCoordinator := &WorkerClaimCoordinator{Ledger: ledger, Content: inputContent, Clock: clock}
	claim, err := claimCoordinator.Claim(t.Context(), claimAuthorization)
	if err != nil {
		t.Fatal(err)
	}
	protectedResult := []byte("opaque-encrypted-result-with-several-chunks")
	resultAuthorization := verifiedWorkerResultAuthorization(
		t, fixture, claim.Record(), protectedResult, 9, 1_800_000_050_000,
	)
	coordinator := &ResultCoordinator{
		Ledger: ledger, Content: resultContent, Capacity: capacity,
		ReceiptSigner: signer, Clock: clock,
	}
	handle, err := coordinator.AcceptAuthorized(t.Context(), resultAuthorization)
	if err != nil {
		t.Fatal(err)
	}
	for index := int64(0); index < handle.record.Header.ProtectedObject.ChunkCount; index++ {
		offset := index * handle.record.Header.ProtectedObject.ChunkByteCount
		end := min(offset+handle.record.Header.ProtectedObject.ChunkByteCount, int64(len(protectedResult)))
		chunk := protectedResult[offset:end]
		next, err := coordinator.AppendChunk(t.Context(), handle, index, chunk, digestBytes(chunk))
		if err != nil || next != end {
			t.Fatalf("chunk %d next=%d err=%v", index, next, err)
		}
	}
	retained, err := coordinator.Finalize(t.Context(), handle)
	if err != nil {
		t.Fatal(err)
	}
	if retained.State != ResultRetained || retained.CommittedBytes != int64(len(protectedResult)) {
		t.Fatalf("retained=%+v", retained)
	}
	receipt, err := serviceauthority.DecodeJobCustodyResultReceipt(retained.CustodyReceiptBytes)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := receipt.VerifiedPayload()
	if err != nil || payload.ClaimID != claim.Record().ClaimID ||
		payload.ResultCapsuleID.String() != string(retained.Header.ResultCapsuleID) ||
		payload.ResultSetDigest != string(retained.Header.ResultSetDigest) ||
		payload.WorkerExecutionReceiptDigest != string(retained.Header.WorkerExecutionReceiptDigest) ||
		payload.ProtectedObjectSHA256 != string(retained.Header.ProtectedObject.SHA256) {
		t.Fatalf("result receipt=%+v err=%v", payload, err)
	}
	if retry, err := coordinator.Finalize(t.Context(), handle); err != nil ||
		!bytes.Equal(retry.CustodyReceiptBytes, retained.CustodyReceiptBytes) {
		t.Fatalf("finalization retry=%+v err=%v", retry, err)
	}
}

func TestResultCoordinatorRejectsChangedResultAndExpiredClaim(t *testing.T) {
	inputContent, _ := temporaryContentStore(t)
	resultContent, _ := temporaryContentStore(t)
	ledger := newMemoryLedger()
	fixture := newStagingFixture(t, []byte("opaque-input-capsule"), 64)
	clock := fixedJobCustodyClock{time.UnixMilli(1_800_000_000_010)}
	signer := testJobCustodyReceiptSigner(t)
	inputCoordinator := &Coordinator{
		Ledger: ledger, Content: inputContent, Capacity: &memoryCapacityAuthority{},
		Verifier: fixture.verifier, ReceiptSigner: signer, Clock: clock,
	}
	inputHandle, err := inputCoordinator.AdmitAuthorized(
		t.Context(), fixture.envelopeBytes, fixture.authorization(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inputCoordinator.AppendChunk(
		t.Context(), inputHandle, 0, fixture.protectedBytes, digestBytes(fixture.protectedBytes),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := inputCoordinator.Finalize(t.Context(), inputHandle); err != nil {
		t.Fatal(err)
	}
	claimAuthorization := verifiedWorkerClaimAuthorization(t, fixture, 1_800_000_060_000)
	claimCoordinator := &WorkerClaimCoordinator{Ledger: ledger, Content: inputContent, Clock: clock}
	claim, err := claimCoordinator.Claim(t.Context(), claimAuthorization)
	if err != nil {
		t.Fatal(err)
	}
	authorization := verifiedWorkerResultAuthorization(
		t, fixture, claim.Record(), []byte("opaque-result"), 64, 1_800_000_050_000,
	)
	coordinator := &ResultCoordinator{
		Ledger: ledger, Content: resultContent, Capacity: &memoryCapacityAuthority{},
		ReceiptSigner: signer, Clock: clock,
	}
	if _, err := coordinator.AcceptAuthorized(t.Context(), authorization); err != nil {
		t.Fatal(err)
	}
	changed := authorization
	changed.payload.Result.ResultSetDigest = computequeue.SHA256Digest("changed", "result-set")
	changed.payload.Result.IdempotencyKey = changed.payload.Result.MakeIdempotencyKey()
	if _, err := coordinator.AcceptAuthorized(t.Context(), changed); err == nil {
		t.Fatal("accepted changed result under an existing result capsule ID")
	}
	coordinator.Clock = fixedJobCustodyClock{time.UnixMilli(1_800_000_060_000)}
	if _, err := coordinator.AcceptAuthorized(t.Context(), authorization); err == nil {
		t.Fatal("accepted result after claim and permit expiry")
	}
}

func verifiedWorkerClaimAuthorization(
	t *testing.T,
	fixture stagingFixture,
	expiresAt computequeue.Timestamp,
) WorkerClaimAuthorization {
	t.Helper()
	payload := WorkerClaimPermitPayload{
		AuthorityID: fixture.authorization().AuthorityID(), ClaimID: uuid.New(),
		ExpiresAt: expiresAt, IssuedAt: 1_800_000_000_000, PermitID: uuid.New(),
		RouteRecipientKeyFingerprint: fixture.header.RouteRecipientKeyFingerprint,
		RouteRecipientWorkerID:       fixture.header.RouteRecipientWorkerID,
		Version:                      WorkerClaimPermitVersion,
		WorkerCapabilitiesDigest:     fixture.authorization().WorkerCapabilitiesDigest(),
		WorkerOwnerAuthorityDigest:   computequeue.SHA256Digest("worker-result-test", "owner"),
	}
	return WorkerClaimAuthorization{
		payload: payload,
		permitDigest: computequeue.SHA256Digest(
			"worker-result-test", "claim-permit", payload.ClaimID.String(),
		),
	}
}

func verifiedWorkerResultAuthorization(
	t *testing.T,
	fixture stagingFixture,
	claim WorkerClaimRecord,
	protected []byte,
	chunkBytes int64,
	expiresAt computequeue.Timestamp,
) WorkerResultAuthorization {
	t.Helper()
	descriptor, err := computequeue.NewJobCapsuleProtectedObjectDescriptor(
		int64(len(protected)), digestBytes(protected), chunkBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	header, err := NewWorkerResultHeader(
		fixture.header.AssignmentID, claim.ClaimID, fixture.header.CapsuleID,
		computequeue.JobCapsuleID(uuid.New().String()), descriptor,
		computequeue.SHA256Digest("worker-result-test", "result-set"),
		computequeue.SHA256Digest("worker-result-test", "execution-receipt"),
		1_800_000_100_000,
	)
	if err != nil {
		t.Fatal(err)
	}
	payload := WorkerResultPermitPayload{
		AuthorityID: claim.RouteAuthorityID, ExpiresAt: expiresAt,
		IssuedAt: 1_800_000_000_000, PermitID: uuid.New(), Result: header,
		RouteRecipientKeyFingerprint: claim.RouteRecipientKeyFingerprint,
		RouteRecipientWorkerID:       claim.RouteRecipientWorkerID,
		Version:                      WorkerResultPermitVersion,
		WorkerCapabilitiesDigest:     claim.WorkerCapabilitiesDigest,
		WorkerOwnerAuthorityDigest:   claim.WorkerOwnerAuthorityDigest,
	}
	return WorkerResultAuthorization{
		payload: payload,
		permitDigest: computequeue.SHA256Digest(
			"worker-result-test", "result-permit", string(header.ResultCapsuleID),
		),
	}
}

func (ledger *memoryLedger) LoadResult(
	_ context.Context,
	resultCapsuleID computequeue.JobCapsuleID,
) (ResultRecord, error) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	record, present := ledger.results[resultCapsuleID]
	if !present {
		return ResultRecord{}, ErrMissing
	}
	return cloneResultRecord(record), nil
}

func (ledger *memoryLedger) ReserveResult(
	_ context.Context,
	candidate ResultRecord,
) (ResultRecord, bool, error) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	resultCapsuleID := candidate.Header.ResultCapsuleID
	if current, present := ledger.results[resultCapsuleID]; present {
		if !sameResultIdentity(current, candidate) {
			return ResultRecord{}, false, ErrConflict
		}
		return cloneResultRecord(current), false, nil
	}
	if owner, present := ledger.resultIdempotency[candidate.Header.IdempotencyKey]; present && owner != resultCapsuleID {
		return ResultRecord{}, false, ErrConflict
	}
	ledger.results[resultCapsuleID] = cloneResultRecord(candidate)
	ledger.resultIdempotency[candidate.Header.IdempotencyKey] = resultCapsuleID
	ledger.resultChunks[resultCapsuleID] = make(map[int64]AppendRequest)
	return cloneResultRecord(candidate), true, nil
}

func (ledger *memoryLedger) BeginResultAppend(
	_ context.Context,
	request AppendRequest,
) (ResultAppendLease, error) {
	ledger.mu.Lock()
	record, present := ledger.results[request.CapsuleID]
	if !present || record.State != ResultStaging {
		ledger.mu.Unlock()
		return nil, ErrMissing
	}
	if existing, present := ledger.resultChunks[request.CapsuleID][request.ChunkIndex]; present {
		if existing != request {
			ledger.mu.Unlock()
			return nil, ErrConflict
		}
		next := existing.Offset + existing.ByteCount
		return &memoryResultAppendLease{
			ledger: ledger, request: request, record: cloneResultRecord(record), existing: &next,
		}, nil
	}
	if record.CommittedBytes != request.Offset {
		ledger.mu.Unlock()
		return nil, ErrConflict
	}
	return &memoryResultAppendLease{ledger: ledger, request: request, record: cloneResultRecord(record)}, nil
}

func (ledger *memoryLedger) BeginResultFinalization(
	_ context.Context,
	resultCapsuleID computequeue.JobCapsuleID,
) (ResultFinalizationLease, error) {
	ledger.mu.Lock()
	record, present := ledger.results[resultCapsuleID]
	if !present {
		ledger.mu.Unlock()
		return nil, ErrMissing
	}
	return &memoryResultFinalizationLease{ledger: ledger, record: cloneResultRecord(record)}, nil
}

type memoryResultAppendLease struct {
	ledger   *memoryLedger
	request  AppendRequest
	record   ResultRecord
	existing *int64
	closed   bool
}

func (lease *memoryResultAppendLease) Result() ResultRecord { return cloneResultRecord(lease.record) }
func (lease *memoryResultAppendLease) ExistingNextOffset() *int64 {
	if lease.existing == nil {
		return nil
	}
	value := *lease.existing
	return &value
}
func (lease *memoryResultAppendLease) Commit(_ context.Context, next int64) error {
	if lease.closed || lease.existing != nil || next != lease.request.Offset+lease.request.ByteCount {
		return ErrConflict
	}
	lease.closed = true
	defer lease.ledger.mu.Unlock()
	record := lease.ledger.results[lease.request.CapsuleID]
	record.CommittedBytes = next
	record.UpdatedAtMillis++
	lease.ledger.results[lease.request.CapsuleID] = record
	lease.ledger.resultChunks[lease.request.CapsuleID][lease.request.ChunkIndex] = lease.request
	return nil
}
func (lease *memoryResultAppendLease) Abort(context.Context) error {
	if lease.closed {
		return nil
	}
	lease.closed = true
	lease.ledger.mu.Unlock()
	return nil
}

type memoryResultFinalizationLease struct {
	ledger *memoryLedger
	record ResultRecord
	closed bool
}

func (lease *memoryResultFinalizationLease) Result() ResultRecord {
	return cloneResultRecord(lease.record)
}
func (lease *memoryResultFinalizationLease) Commit(
	_ context.Context,
	objectPath string,
	receiptBytes []byte,
	committedAt int64,
) (ResultRecord, error) {
	if lease.closed || len(receiptBytes) == 0 || committedAt < lease.record.UpdatedAtMillis {
		return ResultRecord{}, ErrConflict
	}
	lease.closed = true
	defer lease.ledger.mu.Unlock()
	record := lease.ledger.results[lease.record.Header.ResultCapsuleID]
	record.State = ResultRetained
	record.ObjectPath = objectPath
	record.CustodyReceiptBytes = bytes.Clone(receiptBytes)
	record.UpdatedAtMillis = committedAt
	lease.ledger.results[lease.record.Header.ResultCapsuleID] = record
	return cloneResultRecord(record), nil
}
func (lease *memoryResultFinalizationLease) Abort(context.Context) error {
	if lease.closed {
		return nil
	}
	lease.closed = true
	lease.ledger.mu.Unlock()
	return nil
}
