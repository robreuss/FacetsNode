package jobcustody

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"slices"
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

func TestResultDeliveryCoordinatorListsAndReadsOnlyOriginalSourceResults(t *testing.T) {
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
	protectedResult := []byte("opaque-result-for-original-source")
	resultAuthorization := verifiedWorkerResultAuthorization(
		t, fixture, claim.Record(), protectedResult, 8, 1_800_000_050_000,
	)
	resultCoordinator := &ResultCoordinator{
		Ledger: ledger, Content: resultContent, Capacity: &memoryCapacityAuthority{},
		ReceiptSigner: signer, Clock: clock,
	}
	resultHandle, err := resultCoordinator.AcceptAuthorized(t.Context(), resultAuthorization)
	if err != nil {
		t.Fatal(err)
	}
	for index := int64(0); index < resultHandle.record.Header.ProtectedObject.ChunkCount; index++ {
		offset := index * resultHandle.record.Header.ProtectedObject.ChunkByteCount
		end := min(offset+resultHandle.record.Header.ProtectedObject.ChunkByteCount, int64(len(protectedResult)))
		chunk := protectedResult[offset:end]
		if _, err := resultCoordinator.AppendChunk(
			t.Context(), resultHandle, index, chunk, digestBytes(chunk),
		); err != nil {
			t.Fatal(err)
		}
	}
	retained, err := resultCoordinator.Finalize(t.Context(), resultHandle)
	if err != nil {
		t.Fatal(err)
	}
	partialLifecycle := retained
	partialLifecycle.DeliveryPermitDigest = computequeue.SHA256Digest(
		"result-delivery-test", "partial-delivery",
	)
	if partialLifecycle.ValidateStored() == nil {
		t.Fatal("retained result accepted a partial delivery transition")
	}
	retrievalAuthorization := ResultRetrievalAuthorization{
		payload: ResultRetrievalPermitPayload{
			AdmissionPermitDigest:    inputHandle.record.AdmissionPermitDigest,
			AuthorityID:              inputHandle.record.RouteAuthorityID,
			ExpiresAt:                1_800_000_050_000,
			InputCapsuleID:           inputHandle.record.Header.CapsuleID,
			IssuedAt:                 1_800_000_000_000,
			PermitID:                 uuid.New(),
			RequesterAuthorityDigest: inputHandle.record.RequesterAuthorityDigest,
			Version:                  ResultRetrievalPermitVersion,
		},
		permitDigest: computequeue.SHA256Digest("result-delivery-test", "retrieval-permit"),
	}
	delivery := &ResultDeliveryCoordinator{
		Ledger: ledger, Content: resultContent, ReceiptSigner: signer, Clock: clock,
	}
	listed, err := delivery.ListAuthorized(t.Context(), retrievalAuthorization)
	if err != nil || len(listed) != 1 || listed[0].Header != retained.Header {
		t.Fatalf("listed=%+v err=%v", listed, err)
	}
	deliveryHandle, err := delivery.OpenAuthorized(
		t.Context(), retrievalAuthorization, retained.Header.ResultCapsuleID,
	)
	if err != nil {
		t.Fatal(err)
	}
	var received []byte
	for index := int64(0); index < retained.Header.ProtectedObject.ChunkCount; index++ {
		chunk, err := delivery.ReadChunk(deliveryHandle, index)
		if err != nil {
			t.Fatal(err)
		}
		received = append(received, chunk...)
	}
	if !bytes.Equal(received, protectedResult) {
		t.Fatal("source did not receive exact protected result bytes")
	}
	wrongSource := retrievalAuthorization
	wrongSource.payload.RequesterAuthorityDigest = computequeue.SHA256Digest(
		"result-delivery-test", "wrong-source",
	)
	if _, err := delivery.ListAuthorized(t.Context(), wrongSource); err == nil {
		t.Fatal("different source authority retrieved the result")
	}
	if _, err := delivery.OpenAuthorized(
		t.Context(), retrievalAuthorization, computequeue.JobCapsuleID(uuid.NewString()),
	); !errors.Is(err, ErrMissing) {
		t.Fatalf("unknown result error=%v", err)
	}
	custodyDigest, err := resultCustodyReceiptReferenceDigest(retained)
	if err != nil {
		t.Fatal(err)
	}
	delivery.Clock = fixedJobCustodyClock{time.UnixMilli(1_800_000_000_100)}
	acknowledgement := ResultMutationAuthorization{
		payload: ResultMutationPermitPayload{
			Action:                ResultMutationAcknowledgeDelivery,
			AdmissionPermitDigest: inputHandle.record.AdmissionPermitDigest,
			AuthorityID:           inputHandle.record.RouteAuthorityID,
			ExpiresAt:             1_800_000_050_000, InputCapsuleID: inputHandle.record.Header.CapsuleID,
			IssuedAt: 1_800_000_000_000, PermitID: uuid.New(),
			RequesterAuthorityDigest:   inputHandle.record.RequesterAuthorityDigest,
			ResultCapsuleID:            retained.Header.ResultCapsuleID,
			ResultCustodyReceiptDigest: custodyDigest,
			ResultSetDigest:            retained.Header.ResultSetDigest,
			SourceTransitionReceiptDigest: computequeue.SHA256Digest(
				"result-delivery-test", "source-delivered-receipt",
			),
			Version: ResultMutationPermitVersion,
		},
		permitDigest: computequeue.SHA256Digest("result-delivery-test", "acknowledgement-permit"),
	}
	delivered, err := delivery.AcknowledgeDelivery(t.Context(), acknowledgement)
	if err != nil || delivered.State != ResultDelivered ||
		delivered.SourceDeliveryReceiptDigest != acknowledgement.payload.SourceTransitionReceiptDigest {
		t.Fatalf("delivered=%+v err=%v", delivered, err)
	}
	if chunk, err := delivery.ReadChunk(
		ResultDeliveryHandle{authorization: retrievalAuthorization, record: delivered}, 0,
	); err != nil || len(chunk) == 0 {
		t.Fatalf("acknowledged result became unreadable: %d bytes err=%v", len(chunk), err)
	}
	release := ResultMutationAuthorization{
		payload: ResultMutationPermitPayload{
			Action:                ResultMutationReleaseCustody,
			AdmissionPermitDigest: inputHandle.record.AdmissionPermitDigest,
			AuthorityID:           inputHandle.record.RouteAuthorityID,
			ExpiresAt:             1_800_000_050_000, InputCapsuleID: inputHandle.record.Header.CapsuleID,
			IssuedAt: 1_800_000_000_000, PermitID: uuid.New(),
			RequesterAuthorityDigest:   inputHandle.record.RequesterAuthorityDigest,
			ResultCapsuleID:            retained.Header.ResultCapsuleID,
			ResultCustodyReceiptDigest: custodyDigest,
			ResultSetDigest:            retained.Header.ResultSetDigest,
			SourceTransitionReceiptDigest: computequeue.SHA256Digest(
				"result-delivery-test", "source-release-request",
			),
			Version: ResultMutationPermitVersion,
		},
		permitDigest: computequeue.SHA256Digest("result-delivery-test", "release-permit"),
	}
	delivery.Clock = fixedJobCustodyClock{time.UnixMilli(1_800_000_000_200)}
	ledger.mu.Lock()
	ledger.failResultReleaseFinalizeOnce = true
	ledger.mu.Unlock()
	if _, err := delivery.ReleaseResult(t.Context(), release); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("injected release finalization error=%v", err)
	}
	pending, err := ledger.LoadResult(t.Context(), retained.Header.ResultCapsuleID)
	if err != nil || pending.State != ResultReleasePending {
		t.Fatalf("pending release=%+v err=%v", pending, err)
	}
	if _, err := resultContent.OpenObject(
		retained.Header.ResultCapsuleID, retained.Header.ProtectedObject,
	); !errors.Is(err, ErrMissing) {
		t.Fatalf("release intent did not unlink result before injected crash: %v", err)
	}
	if completed, err := delivery.ReconcilePendingReleases(t.Context(), 16); err != nil || completed != 1 {
		t.Fatalf("pending release reconciliation completed=%d err=%v", completed, err)
	}
	released, err := ledger.LoadResult(t.Context(), retained.Header.ResultCapsuleID)
	if err != nil || released.State != ResultReleased || released.ObjectPath != "" ||
		len(released.ReleaseReceiptBytes) == 0 {
		t.Fatalf("released=%+v err=%v", released, err)
	}
	if completed, err := delivery.ReconcilePendingReleases(t.Context(), 16); err != nil || completed != 0 {
		t.Fatalf("empty release reconciliation completed=%d err=%v", completed, err)
	}
	if _, err := delivery.ReconcilePendingReleases(t.Context(), 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unbounded release reconciliation error=%v", err)
	}
	if _, err := serviceauthority.DecodeJobCustodyResultReleaseReceipt(
		released.ReleaseReceiptBytes,
	); err != nil {
		t.Fatal(err)
	}
	if retry, err := delivery.ReleaseResult(t.Context(), release); err != nil ||
		!bytes.Equal(retry.ReleaseReceiptBytes, released.ReleaseReceiptBytes) {
		t.Fatalf("release retry=%+v err=%v", retry, err)
	}
	if _, err := delivery.OpenAuthorized(
		t.Context(), retrievalAuthorization, retained.Header.ResultCapsuleID,
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("released result remained downloadable: %v", err)
	}
	delivery.Clock = fixedJobCustodyClock{time.UnixMilli(int64(retrievalAuthorization.payload.ExpiresAt))}
	if _, err := delivery.ReadChunk(deliveryHandle, 0); !errors.Is(err, ErrConflict) {
		t.Fatalf("expired retrieval handle error=%v", err)
	}
}

func TestResultDeliveryCoordinatorExpiresUndeliveredResultAndResumesAfterUnlink(t *testing.T) {
	inputContent, _ := temporaryContentStore(t)
	resultContent, _ := temporaryContentStore(t)
	ledger := newMemoryLedger()
	fixture := newStagingFixture(t, []byte("opaque-expiry-input"), 64)
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
	claimCoordinator := &WorkerClaimCoordinator{Ledger: ledger, Content: inputContent, Clock: clock}
	claim, err := claimCoordinator.Claim(
		t.Context(), verifiedWorkerClaimAuthorization(t, fixture, 1_800_000_060_000),
	)
	if err != nil {
		t.Fatal(err)
	}
	protectedResult := []byte("opaque-result-that-will-expire")
	resultCoordinator := &ResultCoordinator{
		Ledger: ledger, Content: resultContent, Capacity: &memoryCapacityAuthority{},
		ReceiptSigner: signer, Clock: clock,
	}
	handle, err := resultCoordinator.AcceptAuthorized(t.Context(), verifiedWorkerResultAuthorization(
		t, fixture, claim.Record(), protectedResult, 64, 1_800_000_050_000,
	))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resultCoordinator.AppendChunk(
		t.Context(), handle, 0, protectedResult, digestBytes(protectedResult),
	); err != nil {
		t.Fatal(err)
	}
	retained, err := resultCoordinator.Finalize(t.Context(), handle)
	if err != nil {
		t.Fatal(err)
	}
	delivery := &ResultDeliveryCoordinator{
		Ledger: ledger, Content: resultContent, ReceiptSigner: signer,
		Clock: fixedJobCustodyClock{time.UnixMilli(int64(retained.Header.RetentionUntil) - 1)},
	}
	if completed, err := delivery.ReconcileExpiredResults(t.Context(), 16); err != nil || completed != 0 {
		t.Fatalf("early expiry completed=%d err=%v", completed, err)
	}
	delivery.Clock = fixedJobCustodyClock{time.UnixMilli(int64(retained.Header.RetentionUntil))}
	ledger.mu.Lock()
	ledger.failResultExpiryFinalizeOnce = true
	ledger.mu.Unlock()
	if completed, err := delivery.ReconcileExpiredResults(t.Context(), 16); !errors.Is(err, ErrUnavailable) || completed != 0 {
		t.Fatalf("injected expiry completed=%d err=%v", completed, err)
	}
	pending, err := ledger.LoadResult(t.Context(), retained.Header.ResultCapsuleID)
	if err != nil || pending.State != ResultExpiryPending ||
		pending.ExpiryStartedAt != retained.Header.RetentionUntil {
		t.Fatalf("pending expiry=%+v err=%v", pending, err)
	}
	if _, err := resultContent.OpenObject(
		retained.Header.ResultCapsuleID, retained.Header.ProtectedObject,
	); !errors.Is(err, ErrMissing) {
		t.Fatalf("expiry intent did not unlink result before injected crash: %v", err)
	}
	if completed, err := delivery.ReconcileExpiredResults(t.Context(), 16); err != nil || completed != 1 {
		t.Fatalf("expiry resume completed=%d err=%v", completed, err)
	}
	expired, err := ledger.LoadResult(t.Context(), retained.Header.ResultCapsuleID)
	if err != nil || expired.State != ResultExpired || expired.ObjectPath != "" ||
		len(expired.ExpiryReceiptBytes) == 0 || expired.DeliveryAcknowledgedAt != 0 {
		t.Fatalf("expired=%+v err=%v", expired, err)
	}
	receipt, err := serviceauthority.DecodeJobCustodyResultExpiryReceipt(expired.ExpiryReceiptBytes)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := receipt.VerifiedPayload()
	if err != nil || payload.RetentionUntilMilliseconds != int64(retained.Header.RetentionUntil) ||
		payload.SourceDeliveryReceiptDigest != "" {
		t.Fatalf("expiry receipt=%+v err=%v", payload, err)
	}
	if completed, err := delivery.ReconcileExpiredResults(t.Context(), 16); err != nil || completed != 0 {
		t.Fatalf("replayed expiry completed=%d err=%v", completed, err)
	}
	if _, err := delivery.ReconcileExpiredResults(t.Context(), 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unbounded expiry reconciliation error=%v", err)
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

func (ledger *memoryLedger) ListResultsForInput(
	_ context.Context,
	inputCapsuleID computequeue.JobCapsuleID,
) ([]ResultRecord, AdmissionRecord, error) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	admission, present := ledger.records[inputCapsuleID]
	if !present {
		return nil, AdmissionRecord{}, ErrMissing
	}
	results := make([]ResultRecord, 0)
	for _, record := range ledger.results {
		if record.Header.InputCapsuleID == inputCapsuleID {
			results = append(results, cloneResultRecord(record))
		}
	}
	slices.SortFunc(results, func(left, right ResultRecord) int {
		if left.AcceptedAt != right.AcceptedAt {
			return cmp.Compare(left.AcceptedAt, right.AcceptedAt)
		}
		return cmp.Compare(left.Header.ResultCapsuleID, right.Header.ResultCapsuleID)
	})
	return results, cloneWorkerClaimAdmission(admission), nil
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

func (ledger *memoryLedger) AcknowledgeResultDelivery(
	_ context.Context,
	resultCapsuleID computequeue.JobCapsuleID,
	permitDigest computequeue.Digest,
	sourceReceiptDigest computequeue.Digest,
	acknowledgedAt computequeue.Timestamp,
) (ResultRecord, error) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	record, present := ledger.results[resultCapsuleID]
	if !present {
		return ResultRecord{}, ErrMissing
	}
	if record.State == ResultDelivered {
		if record.DeliveryPermitDigest != permitDigest ||
			record.SourceDeliveryReceiptDigest != sourceReceiptDigest {
			return ResultRecord{}, ErrConflict
		}
		return cloneResultRecord(record), nil
	}
	if record.State != ResultRetained || acknowledgedAt < computequeue.Timestamp(record.UpdatedAtMillis) {
		return ResultRecord{}, ErrConflict
	}
	record.State = ResultDelivered
	record.DeliveryAcknowledgedAt = acknowledgedAt
	record.DeliveryPermitDigest = permitDigest
	record.SourceDeliveryReceiptDigest = sourceReceiptDigest
	record.UpdatedAtMillis = int64(acknowledgedAt)
	ledger.results[resultCapsuleID] = record
	return cloneResultRecord(record), nil
}

func (ledger *memoryLedger) ListPendingResultReleases(
	_ context.Context,
	limit int,
) ([]ResultRecord, error) {
	if limit <= 0 || limit > MaximumPendingResultReleaseBatchSize {
		return nil, ErrInvalid
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	results := make([]ResultRecord, 0, limit)
	for _, record := range ledger.results {
		if record.State == ResultReleasePending {
			results = append(results, cloneResultRecord(record))
		}
	}
	slices.SortFunc(results, func(left, right ResultRecord) int {
		if left.ReleaseRequestedAt != right.ReleaseRequestedAt {
			return cmp.Compare(left.ReleaseRequestedAt, right.ReleaseRequestedAt)
		}
		return cmp.Compare(left.Header.ResultCapsuleID, right.Header.ResultCapsuleID)
	})
	if len(results) > limit {
		results = results[:limit]
	}
	return results, nil
}

func (ledger *memoryLedger) ListResultExpiryCandidates(
	_ context.Context,
	now computequeue.Timestamp,
	limit int,
) ([]ResultRecord, error) {
	if limit <= 0 || limit > MaximumResultExpiryBatchSize {
		return nil, ErrInvalid
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	results := make([]ResultRecord, 0, limit)
	for _, record := range ledger.results {
		if record.State == ResultExpiryPending ||
			((record.State == ResultRetained || record.State == ResultDelivered) &&
				record.Header.RetentionUntil <= now) {
			results = append(results, cloneResultRecord(record))
		}
	}
	slices.SortFunc(results, func(left, right ResultRecord) int {
		if left.Header.RetentionUntil != right.Header.RetentionUntil {
			return cmp.Compare(left.Header.RetentionUntil, right.Header.RetentionUntil)
		}
		return cmp.Compare(left.Header.ResultCapsuleID, right.Header.ResultCapsuleID)
	})
	if len(results) > limit {
		results = results[:limit]
	}
	return results, nil
}

func (ledger *memoryLedger) RequestResultRelease(
	_ context.Context,
	resultCapsuleID computequeue.JobCapsuleID,
	permitDigest computequeue.Digest,
	sourceReceiptDigest computequeue.Digest,
	requestedAt computequeue.Timestamp,
) (ResultRecord, error) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	record, present := ledger.results[resultCapsuleID]
	if !present {
		return ResultRecord{}, ErrMissing
	}
	if record.State == ResultReleasePending || record.State == ResultReleased {
		if record.ReleasePermitDigest != permitDigest ||
			record.SourceReleaseReceiptDigest != sourceReceiptDigest {
			return ResultRecord{}, ErrConflict
		}
		return cloneResultRecord(record), nil
	}
	if record.State != ResultDelivered || requestedAt < record.DeliveryAcknowledgedAt {
		return ResultRecord{}, ErrConflict
	}
	record.State = ResultReleasePending
	record.ReleaseRequestedAt = requestedAt
	record.ReleasePermitDigest = permitDigest
	record.SourceReleaseReceiptDigest = sourceReceiptDigest
	record.UpdatedAtMillis = int64(requestedAt)
	ledger.results[resultCapsuleID] = record
	return cloneResultRecord(record), nil
}

func (ledger *memoryLedger) FinalizeResultRelease(
	_ context.Context,
	resultCapsuleID computequeue.JobCapsuleID,
	receiptBytes []byte,
	releasedAt int64,
) (ResultRecord, error) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	record, present := ledger.results[resultCapsuleID]
	if !present {
		return ResultRecord{}, ErrMissing
	}
	if record.State == ResultReleased {
		return cloneResultRecord(record), nil
	}
	if record.State != ResultReleasePending || len(receiptBytes) == 0 ||
		releasedAt < record.UpdatedAtMillis {
		return ResultRecord{}, ErrConflict
	}
	if ledger.failResultReleaseFinalizeOnce {
		ledger.failResultReleaseFinalizeOnce = false
		return ResultRecord{}, ErrUnavailable
	}
	record.State = ResultReleased
	record.ObjectPath = ""
	record.ReleaseReceiptBytes = bytes.Clone(receiptBytes)
	record.UpdatedAtMillis = releasedAt
	ledger.results[resultCapsuleID] = record
	return cloneResultRecord(record), nil
}

func (ledger *memoryLedger) RequestResultExpiry(
	_ context.Context,
	resultCapsuleID computequeue.JobCapsuleID,
	startedAt computequeue.Timestamp,
) (ResultRecord, error) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	record, present := ledger.results[resultCapsuleID]
	if !present {
		return ResultRecord{}, ErrMissing
	}
	if record.State == ResultExpiryPending || record.State == ResultExpired {
		return cloneResultRecord(record), nil
	}
	if (record.State != ResultRetained && record.State != ResultDelivered) ||
		startedAt < record.Header.RetentionUntil || startedAt < computequeue.Timestamp(record.UpdatedAtMillis) {
		return ResultRecord{}, ErrConflict
	}
	record.State = ResultExpiryPending
	record.ExpiryStartedAt = startedAt
	record.UpdatedAtMillis = int64(startedAt)
	ledger.results[resultCapsuleID] = record
	return cloneResultRecord(record), nil
}

func (ledger *memoryLedger) FinalizeResultExpiry(
	_ context.Context,
	resultCapsuleID computequeue.JobCapsuleID,
	receiptBytes []byte,
	expiredAt int64,
) (ResultRecord, error) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	record, present := ledger.results[resultCapsuleID]
	if !present {
		return ResultRecord{}, ErrMissing
	}
	if record.State == ResultExpired {
		return cloneResultRecord(record), nil
	}
	if record.State != ResultExpiryPending || len(receiptBytes) == 0 ||
		expiredAt < record.UpdatedAtMillis || expiredAt < int64(record.Header.RetentionUntil) {
		return ResultRecord{}, ErrConflict
	}
	if ledger.failResultExpiryFinalizeOnce {
		ledger.failResultExpiryFinalizeOnce = false
		return ResultRecord{}, ErrUnavailable
	}
	record.State = ResultExpired
	record.ObjectPath = ""
	record.ExpiryReceiptBytes = bytes.Clone(receiptBytes)
	record.UpdatedAtMillis = expiredAt
	ledger.results[resultCapsuleID] = record
	return cloneResultRecord(record), nil
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
