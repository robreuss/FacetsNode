package boxcontrol

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func sharedWorkerOperationStoreFixture(
	t *testing.T,
) (participantFixture, participantFixture, *MemoryStore, BoxSharedWorkerAdvertisement, BoxSharedWorkerAccessGrant, BoxSharedWorkerOperation) {
	t.Helper()
	owner, requester, store, worker, accessRequest, code := sharedWorkerAccessStoreFixture(t)
	ctx := context.Background()
	if err := store.CreateSharedWorkerAccessRequest(ctx, accessRequest, owner.now); err != nil {
		t.Fatal(err)
	}
	accessGrant := sharedWorkerAccessGrant(owner, requester, worker, accessRequest, code)
	codeDigest, _ := SharedWorkerAccessCodeDigest(code)
	if err := store.ConfirmSharedWorkerAccess(ctx, accessGrant, codeDigest, owner.now); err != nil {
		t.Fatal(err)
	}
	requestBytes := []byte("opaque-encrypted-worker-source-control-request")
	operation := BoxSharedWorkerOperation{
		Version: 1, OperationID: uuid.New(), BoxID: worker.BoxID,
		WorkerID: worker.WorkerID, AccessGrantID: accessGrant.GrantID,
		RequesterParticipantID: requester.anchor.ParticipantID,
		RequesterDeviceID:      requester.device.DeviceID,
		JobID:                  uuid.New(), RunID: uuid.New(), Attempt: 1,
		CapabilitiesDigest: worker.CapabilitiesDigest,
		RequestDigest:      SharedWorkerOperationDigest(requestBytes), RequestBytes: requestBytes,
		RequestedAtMilliseconds: owner.now,
		ExpiresAtMilliseconds:   owner.now + 60_000,
		ConnectionGrantID:       accessRequest.ConnectionGrantID,
		State:                   SharedWorkerOperationQueued,
	}
	return owner, requester, store, worker, accessGrant, operation
}

func TestSharedWorkerOperationRequiresExactGrantAndAssignedWorker(t *testing.T) {
	owner, requester, store, worker, _, operation := sharedWorkerOperationStoreFixture(t)
	ctx := context.Background()
	if err := store.EnqueueSharedWorkerOperation(ctx, operation, owner.now); err != nil {
		t.Fatal(err)
	}
	if err := store.EnqueueSharedWorkerOperation(ctx, operation, owner.now); err != nil {
		t.Fatalf("exact enqueue retry: %v", err)
	}
	substituted := operation
	substituted.RequestBytes = []byte("different ciphertext")
	substituted.RequestDigest = SharedWorkerOperationDigest(substituted.RequestBytes)
	if err := store.EnqueueSharedWorkerOperation(ctx, substituted, owner.now); !errors.Is(err, ErrSharedWorkerOperationCollision) {
		t.Fatalf("operation substitution: %v", err)
	}

	claim := BoxSharedWorkerOperationClaim{
		Version: 1, ClaimID: uuid.New(), BoxID: worker.BoxID,
		WorkerID: worker.WorkerID, OwnerParticipantID: owner.anchor.ParticipantID,
		OwnerDeviceID: owner.device.DeviceID, RequestedAtMilliseconds: owner.now,
		ExpiresAtMilliseconds: owner.now + 30_000,
	}
	claimed, err := store.ClaimSharedWorkerOperation(ctx, claim, owner.now)
	if err != nil || claimed == nil || claimed.OperationID != operation.OperationID ||
		claimed.ConnectionGrantID != uuid.Nil || string(claimed.RequestBytes) != string(operation.RequestBytes) {
		t.Fatalf("claimed operation: %v %+v", err, claimed)
	}
	if _, err := store.ClaimSharedWorkerOperation(ctx, BoxSharedWorkerOperationClaim{
		Version: 1, ClaimID: uuid.New(), BoxID: worker.BoxID,
		WorkerID: worker.WorkerID, OwnerParticipantID: requester.anchor.ParticipantID,
		OwnerDeviceID: requester.device.DeviceID, RequestedAtMilliseconds: owner.now,
		ExpiresAtMilliseconds: owner.now + 30_000,
	}, owner.now); !errors.Is(err, ErrSharedWorkerOperation) {
		t.Fatalf("non-owner claim: %v", err)
	}

	responseBytes := []byte("opaque-encrypted-worker-source-control-reply")
	response := BoxSharedWorkerOperationResponse{
		Version: 1, OperationID: operation.OperationID, ClaimID: claim.ClaimID,
		BoxID: worker.BoxID, WorkerID: worker.WorkerID,
		OwnerParticipantID: owner.anchor.ParticipantID,
		OwnerDeviceID:      owner.device.DeviceID,
		ResponseDigest:     SharedWorkerOperationDigest(responseBytes), ResponseBytes: responseBytes,
		RespondedAtMilliseconds: owner.now + 1,
	}
	if err := store.CompleteSharedWorkerOperation(ctx, response, owner.now+1); err != nil {
		t.Fatal(err)
	}
	status, err := store.SharedWorkerOperationStatus(
		ctx, operation.OperationID, operation.ConnectionGrantID, owner.now+1,
	)
	if err != nil || status.State != SharedWorkerOperationResponseReady || status.Response == nil ||
		string(status.Response.ResponseBytes) != string(responseBytes) {
		t.Fatalf("operation status: %v %+v", err, status)
	}
	if _, err := store.SharedWorkerOperationStatus(
		ctx, operation.OperationID, uuid.New(), owner.now+1,
	); !errors.Is(err, ErrSharedWorkerOperation) {
		t.Fatalf("other connection read: %v", err)
	}
}

func TestSharedWorkerOperationRequeuesOnlyAfterClaimLeaseExpires(t *testing.T) {
	owner, _, store, worker, _, operation := sharedWorkerOperationStoreFixture(t)
	ctx := context.Background()
	if err := store.EnqueueSharedWorkerOperation(ctx, operation, owner.now); err != nil {
		t.Fatal(err)
	}
	first := BoxSharedWorkerOperationClaim{
		Version: 1, ClaimID: uuid.New(), BoxID: worker.BoxID,
		WorkerID: worker.WorkerID, OwnerParticipantID: owner.anchor.ParticipantID,
		OwnerDeviceID: owner.device.DeviceID, RequestedAtMilliseconds: owner.now,
		ExpiresAtMilliseconds: owner.now + 1_000,
	}
	if _, err := store.ClaimSharedWorkerOperation(ctx, first, owner.now); err != nil {
		t.Fatal(err)
	}
	second := first
	second.ClaimID = uuid.New()
	if _, err := store.ClaimSharedWorkerOperation(ctx, second, owner.now+999); !errors.Is(err, ErrSharedWorkerOperationNoWork) {
		t.Fatalf("claimed operation became available early: %v", err)
	}
	second.RequestedAtMilliseconds = owner.now + 1_000
	second.ExpiresAtMilliseconds = owner.now + 2_000
	reclaimed, err := store.ClaimSharedWorkerOperation(ctx, second, owner.now+1_000)
	if err != nil || reclaimed == nil || reclaimed.ClaimID != second.ClaimID {
		t.Fatalf("expired claim was not reassigned: %v %+v", err, reclaimed)
	}
}
