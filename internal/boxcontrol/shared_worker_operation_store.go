package boxcontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"math"
	"sort"
	"time"

	"github.com/google/uuid"
)

const (
	maximumSharedWorkerOperationBytes                = 2 * 1024 * 1024
	maximumSharedWorkerOperationLifetimeMilliseconds = int64(15 * 60 * 1000)
	maximumSharedWorkerClaimLifetimeMilliseconds     = int64(30 * 1000)
)

var (
	ErrSharedWorkerOperation          = errors.New("BOX-WORKER-OPERATION: shared Worker operation is invalid")
	ErrSharedWorkerOperationNoWork    = errors.New("BOX-WORKER-OPERATION-NO-WORK: no assigned operation is ready")
	ErrSharedWorkerOperationCollision = errors.New("BOX-WORKER-OPERATION-COLLISION: operation identifier was reused")
)

type BoxSharedWorkerOperationState string

const (
	SharedWorkerOperationQueued        BoxSharedWorkerOperationState = "queued"
	SharedWorkerOperationClaimed       BoxSharedWorkerOperationState = "claimed"
	SharedWorkerOperationResponseReady BoxSharedWorkerOperationState = "response-ready"
	SharedWorkerOperationExpired       BoxSharedWorkerOperationState = "expired"
)

// BoxSharedWorkerOperation is one exact source-control exchange assigned to a
// previously granted Worker. The Box retains opaque request bytes and routing
// facts only; the protected Worker protocol authenticates and decrypts them.
type BoxSharedWorkerOperation struct {
	Version                    int                               `json:"version"`
	OperationID                uuid.UUID                         `json:"operationID"`
	BoxID                      uuid.UUID                         `json:"boxID"`
	WorkerID                   uuid.UUID                         `json:"workerID"`
	AccessGrantID              uuid.UUID                         `json:"accessGrantID"`
	RequesterParticipantID     uuid.UUID                         `json:"requesterParticipantID"`
	RequesterDeviceID          uuid.UUID                         `json:"requesterDeviceID"`
	JobID                      uuid.UUID                         `json:"jobID"`
	RunID                      uuid.UUID                         `json:"runID"`
	Attempt                    uint64                            `json:"attempt"`
	CapabilitiesDigest         string                            `json:"capabilitiesDigest"`
	RequestDigest              string                            `json:"requestDigest"`
	RequestBytes               []byte                            `json:"requestBytes"`
	RequestedAtMilliseconds    int64                             `json:"requestedAtMilliseconds"`
	ExpiresAtMilliseconds      int64                             `json:"expiresAtMilliseconds"`
	ConnectionGrantID          uuid.UUID                         `json:"-"`
	State                      BoxSharedWorkerOperationState     `json:"-"`
	ClaimID                    uuid.UUID                         `json:"-"`
	ClaimedAtMilliseconds      int64                             `json:"-"`
	ClaimExpiresAtMilliseconds int64                             `json:"-"`
	Response                   *BoxSharedWorkerOperationResponse `json:"-"`
}

func SharedWorkerOperationDigest(value []byte) string {
	digest := sha256.Sum256(value)
	return hexDigest(digest[:])
}

func (value BoxSharedWorkerOperation) validAt(nowMilliseconds int64) bool {
	return value.Version == 1 && value.OperationID != uuid.Nil &&
		value.BoxID != uuid.Nil && value.WorkerID != uuid.Nil &&
		value.AccessGrantID != uuid.Nil && value.RequesterParticipantID != uuid.Nil &&
		value.RequesterDeviceID != uuid.Nil && value.JobID != uuid.Nil &&
		value.RunID != uuid.Nil && value.Attempt > 0 && value.Attempt <= math.MaxInt64 &&
		validParticipantRequestDigest(value.CapabilitiesDigest) &&
		validParticipantRequestDigest(value.RequestDigest) &&
		len(value.RequestBytes) > 0 && len(value.RequestBytes) <= maximumSharedWorkerOperationBytes &&
		value.RequestDigest == SharedWorkerOperationDigest(value.RequestBytes) &&
		value.RequestedAtMilliseconds > 0 && value.RequestedAtMilliseconds <= nowMilliseconds &&
		value.ExpiresAtMilliseconds > nowMilliseconds &&
		value.ExpiresAtMilliseconds-value.RequestedAtMilliseconds <= maximumSharedWorkerOperationLifetimeMilliseconds &&
		value.ConnectionGrantID != uuid.Nil && value.State == SharedWorkerOperationQueued &&
		value.ClaimID == uuid.Nil && value.ClaimedAtMilliseconds == 0 &&
		value.ClaimExpiresAtMilliseconds == 0 && value.Response == nil
}

func cloneSharedWorkerOperation(value BoxSharedWorkerOperation) BoxSharedWorkerOperation {
	value.RequestBytes = bytes.Clone(value.RequestBytes)
	if value.Response != nil {
		copy := *value.Response
		copy.ResponseBytes = bytes.Clone(copy.ResponseBytes)
		value.Response = &copy
	}
	return value
}

func sameSharedWorkerOperation(left, right BoxSharedWorkerOperation) bool {
	leftCopy, rightCopy := cloneSharedWorkerOperation(left), cloneSharedWorkerOperation(right)
	leftCopy.Response, rightCopy.Response = nil, nil
	return leftCopy.Version == rightCopy.Version &&
		leftCopy.OperationID == rightCopy.OperationID && leftCopy.BoxID == rightCopy.BoxID &&
		leftCopy.WorkerID == rightCopy.WorkerID && leftCopy.AccessGrantID == rightCopy.AccessGrantID &&
		leftCopy.RequesterParticipantID == rightCopy.RequesterParticipantID &&
		leftCopy.RequesterDeviceID == rightCopy.RequesterDeviceID && leftCopy.JobID == rightCopy.JobID &&
		leftCopy.RunID == rightCopy.RunID && leftCopy.Attempt == rightCopy.Attempt &&
		leftCopy.CapabilitiesDigest == rightCopy.CapabilitiesDigest &&
		leftCopy.RequestDigest == rightCopy.RequestDigest && bytes.Equal(leftCopy.RequestBytes, rightCopy.RequestBytes) &&
		leftCopy.RequestedAtMilliseconds == rightCopy.RequestedAtMilliseconds &&
		leftCopy.ExpiresAtMilliseconds == rightCopy.ExpiresAtMilliseconds &&
		leftCopy.ConnectionGrantID == rightCopy.ConnectionGrantID
}

type BoxSharedWorkerOperationClaim struct {
	Version                 int       `json:"version"`
	ClaimID                 uuid.UUID `json:"claimID"`
	BoxID                   uuid.UUID `json:"boxID"`
	WorkerID                uuid.UUID `json:"workerID"`
	OwnerParticipantID      uuid.UUID `json:"ownerParticipantID"`
	OwnerDeviceID           uuid.UUID `json:"ownerDeviceID"`
	RequestedAtMilliseconds int64     `json:"requestedAtMilliseconds"`
	ExpiresAtMilliseconds   int64     `json:"expiresAtMilliseconds"`
}

func (value BoxSharedWorkerOperationClaim) validAt(nowMilliseconds int64) bool {
	return value.Version == 1 && value.ClaimID != uuid.Nil && value.BoxID != uuid.Nil &&
		value.WorkerID != uuid.Nil && value.OwnerParticipantID != uuid.Nil &&
		value.OwnerDeviceID != uuid.Nil && value.RequestedAtMilliseconds > 0 &&
		value.RequestedAtMilliseconds <= nowMilliseconds && value.ExpiresAtMilliseconds > nowMilliseconds &&
		value.ExpiresAtMilliseconds-value.RequestedAtMilliseconds <= maximumSharedWorkerClaimLifetimeMilliseconds
}

type BoxSharedWorkerOperationResponse struct {
	Version                 int       `json:"version"`
	OperationID             uuid.UUID `json:"operationID"`
	ClaimID                 uuid.UUID `json:"claimID"`
	BoxID                   uuid.UUID `json:"boxID"`
	WorkerID                uuid.UUID `json:"workerID"`
	OwnerParticipantID      uuid.UUID `json:"ownerParticipantID"`
	OwnerDeviceID           uuid.UUID `json:"ownerDeviceID"`
	ResponseDigest          string    `json:"responseDigest"`
	ResponseBytes           []byte    `json:"responseBytes"`
	RespondedAtMilliseconds int64     `json:"respondedAtMilliseconds"`
}

func (value BoxSharedWorkerOperationResponse) validAt(nowMilliseconds int64) bool {
	return value.Version == 1 && value.OperationID != uuid.Nil && value.ClaimID != uuid.Nil &&
		value.BoxID != uuid.Nil && value.WorkerID != uuid.Nil &&
		value.OwnerParticipantID != uuid.Nil && value.OwnerDeviceID != uuid.Nil &&
		validParticipantRequestDigest(value.ResponseDigest) &&
		len(value.ResponseBytes) > 0 && len(value.ResponseBytes) <= maximumSharedWorkerOperationBytes &&
		value.ResponseDigest == SharedWorkerOperationDigest(value.ResponseBytes) &&
		value.RespondedAtMilliseconds > 0 && value.RespondedAtMilliseconds <= nowMilliseconds
}

type BoxSharedWorkerOperationStatus struct {
	Version               int                               `json:"version"`
	OperationID           uuid.UUID                         `json:"operationID"`
	State                 BoxSharedWorkerOperationState     `json:"state"`
	ExpiresAtMilliseconds int64                             `json:"expiresAtMilliseconds"`
	Response              *BoxSharedWorkerOperationResponse `json:"response,omitempty"`
}

func (store *MemoryStore) EnqueueSharedWorkerOperation(
	_ context.Context, value BoxSharedWorkerOperation, nowMilliseconds int64,
) error {
	if !value.validAt(nowMilliseconds) {
		return ErrSharedWorkerOperation
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, present := store.sharedWorkerOperations[value.OperationID]; present {
		if sameSharedWorkerOperation(existing, value) {
			return nil
		}
		return ErrSharedWorkerOperationCollision
	}
	worker, workerPresent := store.sharedWorkers[value.WorkerID]
	grant, grantPresent := store.sharedWorkerGrants[value.AccessGrantID]
	requester, requesterPresent := store.participantEnrollments[value.RequesterParticipantID]
	accessRequest, requestPresent := store.sharedWorkerRequests[grant.RequestID]
	if store.state == nil || !store.state.Claimed() || store.state.BoxID != value.BoxID ||
		!workerPresent || worker.BoxID != value.BoxID || worker.ExpiresAtMilliseconds <= nowMilliseconds ||
		!grantPresent || !grant.validAt(nowMilliseconds) || grant.BoxID != value.BoxID ||
		grant.WorkerID != value.WorkerID || grant.GranteeParticipantID != value.RequesterParticipantID ||
		grant.CapabilitiesDigest != value.CapabilitiesDigest || grant.OwnerParticipantID != worker.OwnerParticipantID ||
		grant.OwnerDeviceID != worker.OwnerDeviceID || !requesterPresent ||
		requester.Device.DeviceID != value.RequesterDeviceID || !requester.validInitialAt(nowMilliseconds) ||
		!requestPresent || accessRequest.ConnectionGrantID != value.ConnectionGrantID {
		return ErrSharedWorkerOperation
	}
	store.sharedWorkerOperations[value.OperationID] = cloneSharedWorkerOperation(value)
	return nil
}

func (store *MemoryStore) ClaimSharedWorkerOperation(
	_ context.Context, claim BoxSharedWorkerOperationClaim, nowMilliseconds int64,
) (*BoxSharedWorkerOperation, error) {
	if !claim.validAt(nowMilliseconds) {
		return nil, ErrSharedWorkerOperation
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	worker, present := store.sharedWorkers[claim.WorkerID]
	owner, ownerPresent := store.participantEnrollments[claim.OwnerParticipantID]
	if !present || !ownerPresent || worker.BoxID != claim.BoxID ||
		worker.OwnerParticipantID != claim.OwnerParticipantID || worker.OwnerDeviceID != claim.OwnerDeviceID ||
		worker.ExpiresAtMilliseconds <= nowMilliseconds || owner.Device.DeviceID != claim.OwnerDeviceID ||
		!owner.validInitialAt(nowMilliseconds) {
		return nil, ErrSharedWorkerOperation
	}
	for id, operation := range store.sharedWorkerOperations {
		if operation.State == SharedWorkerOperationClaimed &&
			operation.ClaimExpiresAtMilliseconds <= nowMilliseconds && operation.Response == nil {
			operation.State = SharedWorkerOperationQueued
			operation.ClaimID = uuid.Nil
			operation.ClaimedAtMilliseconds = 0
			operation.ClaimExpiresAtMilliseconds = 0
			store.sharedWorkerOperations[id] = operation
		}
		if (operation.State == SharedWorkerOperationQueued || operation.State == SharedWorkerOperationClaimed) &&
			operation.ExpiresAtMilliseconds <= nowMilliseconds {
			operation.State = SharedWorkerOperationExpired
			operation.ClaimID = uuid.Nil
			operation.ClaimedAtMilliseconds = 0
			operation.ClaimExpiresAtMilliseconds = 0
			store.sharedWorkerOperations[id] = operation
		}
	}
	var candidates []BoxSharedWorkerOperation
	for _, operation := range store.sharedWorkerOperations {
		grant, grantPresent := store.sharedWorkerGrants[operation.AccessGrantID]
		if operation.WorkerID == claim.WorkerID && operation.State == SharedWorkerOperationQueued &&
			operation.ExpiresAtMilliseconds > nowMilliseconds && grantPresent &&
			grant.validAt(nowMilliseconds) && grant.OwnerParticipantID == claim.OwnerParticipantID {
			candidates = append(candidates, operation)
		}
	}
	if len(candidates) == 0 {
		return nil, ErrSharedWorkerOperationNoWork
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].RequestedAtMilliseconds == candidates[j].RequestedAtMilliseconds {
			return candidates[i].OperationID.String() < candidates[j].OperationID.String()
		}
		return candidates[i].RequestedAtMilliseconds < candidates[j].RequestedAtMilliseconds
	})
	selected := candidates[0]
	selected.State = SharedWorkerOperationClaimed
	selected.ClaimID = claim.ClaimID
	selected.ClaimedAtMilliseconds = nowMilliseconds
	selected.ClaimExpiresAtMilliseconds = claim.ExpiresAtMilliseconds
	store.sharedWorkerOperations[selected.OperationID] = selected
	copy := cloneSharedWorkerOperation(selected)
	copy.ConnectionGrantID = uuid.Nil
	return &copy, nil
}

func (store *MemoryStore) CompleteSharedWorkerOperation(
	_ context.Context, response BoxSharedWorkerOperationResponse, nowMilliseconds int64,
) error {
	if !response.validAt(nowMilliseconds) {
		return ErrSharedWorkerOperation
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	operation, present := store.sharedWorkerOperations[response.OperationID]
	worker, workerPresent := store.sharedWorkers[response.WorkerID]
	owner, ownerPresent := store.participantEnrollments[response.OwnerParticipantID]
	grant, grantPresent := store.sharedWorkerGrants[operation.AccessGrantID]
	if present && operation.State == SharedWorkerOperationResponseReady && operation.Response != nil {
		if sameSharedWorkerOperationResponse(*operation.Response, response) {
			return nil
		}
		return ErrSharedWorkerOperationCollision
	}
	if !present || !workerPresent || !ownerPresent || !grantPresent ||
		operation.State != SharedWorkerOperationClaimed ||
		operation.ClaimID != response.ClaimID || operation.ClaimExpiresAtMilliseconds <= nowMilliseconds ||
		operation.ExpiresAtMilliseconds <= nowMilliseconds ||
		operation.BoxID != response.BoxID || operation.WorkerID != response.WorkerID ||
		worker.OwnerParticipantID != response.OwnerParticipantID || worker.OwnerDeviceID != response.OwnerDeviceID ||
		worker.ExpiresAtMilliseconds <= nowMilliseconds || owner.Device.DeviceID != response.OwnerDeviceID ||
		!owner.validInitialAt(nowMilliseconds) || !grant.validAt(nowMilliseconds) ||
		grant.BoxID != operation.BoxID || grant.WorkerID != operation.WorkerID ||
		grant.CapabilitiesDigest != operation.CapabilitiesDigest ||
		grant.OwnerParticipantID != response.OwnerParticipantID || grant.OwnerDeviceID != response.OwnerDeviceID {
		return ErrSharedWorkerOperation
	}
	copy := response
	copy.ResponseBytes = bytes.Clone(response.ResponseBytes)
	operation.Response = &copy
	operation.State = SharedWorkerOperationResponseReady
	store.sharedWorkerOperations[operation.OperationID] = operation
	return nil
}

func sameSharedWorkerOperationResponse(left, right BoxSharedWorkerOperationResponse) bool {
	return left.Version == right.Version && left.OperationID == right.OperationID &&
		left.ClaimID == right.ClaimID && left.BoxID == right.BoxID &&
		left.WorkerID == right.WorkerID && left.OwnerParticipantID == right.OwnerParticipantID &&
		left.OwnerDeviceID == right.OwnerDeviceID && left.ResponseDigest == right.ResponseDigest &&
		bytes.Equal(left.ResponseBytes, right.ResponseBytes) &&
		left.RespondedAtMilliseconds == right.RespondedAtMilliseconds
}

func (store *MemoryStore) SharedWorkerOperationStatus(
	_ context.Context, operationID, connectionGrantID uuid.UUID, nowMilliseconds int64,
) (BoxSharedWorkerOperationStatus, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	operation, present := store.sharedWorkerOperations[operationID]
	connection, connectionPresent := store.grants[connectionGrantID]
	if !present || operation.ConnectionGrantID != connectionGrantID || !connectionPresent ||
		!connection.RevokedAt.IsZero() ||
		!connection.ExpiresAt.After(time.UnixMilli(nowMilliseconds)) {
		return BoxSharedWorkerOperationStatus{}, ErrSharedWorkerOperation
	}
	if (operation.State == SharedWorkerOperationQueued || operation.State == SharedWorkerOperationClaimed) &&
		operation.ExpiresAtMilliseconds <= nowMilliseconds {
		operation.State = SharedWorkerOperationExpired
		operation.ClaimID = uuid.Nil
		operation.ClaimedAtMilliseconds = 0
		operation.ClaimExpiresAtMilliseconds = 0
		store.sharedWorkerOperations[operationID] = operation
	}
	status := BoxSharedWorkerOperationStatus{
		Version: 1, OperationID: operationID, State: operation.State,
		ExpiresAtMilliseconds: operation.ExpiresAtMilliseconds,
	}
	if operation.Response != nil {
		copy := *operation.Response
		copy.ResponseBytes = bytes.Clone(copy.ResponseBytes)
		status.Response = &copy
	}
	return status, nil
}
