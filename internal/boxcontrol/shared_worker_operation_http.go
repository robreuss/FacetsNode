package boxcontrol

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
)

const maximumSharedWorkerOperationHTTPBytes = 3 * 1024 * 1024

type sharedWorkerOperationEnqueueBody struct {
	Version          int                             `json:"version"`
	OperationPayload json.RawMessage                 `json:"operationPayload"`
	ChallengeID      uuid.UUID                       `json:"challengeID"`
	Proof            BoxSignedParticipantActionProof `json:"proof"`
}

type sharedWorkerOperationClaimBody struct {
	Version      int                             `json:"version"`
	ClaimPayload json.RawMessage                 `json:"claimPayload"`
	ChallengeID  uuid.UUID                       `json:"challengeID"`
	Proof        BoxSignedParticipantActionProof `json:"proof"`
}

type sharedWorkerOperationResponseBody struct {
	Version         int                             `json:"version"`
	ResponsePayload json.RawMessage                 `json:"responsePayload"`
	ChallengeID     uuid.UUID                       `json:"challengeID"`
	Proof           BoxSignedParticipantActionProof `json:"proof"`
}

type sharedWorkerOperationAssignment struct {
	Version                    int                      `json:"version"`
	Operation                  BoxSharedWorkerOperation `json:"operation"`
	ClaimID                    uuid.UUID                `json:"claimID"`
	ClaimedAtMilliseconds      int64                    `json:"claimedAtMilliseconds"`
	ClaimExpiresAtMilliseconds int64                    `json:"claimExpiresAtMilliseconds"`
}

func (service *Service) handleEnqueueSharedWorkerOperation(writer http.ResponseWriter, request *http.Request) {
	connection, err := service.authorizeGrant(request)
	if err != nil {
		http.Error(writer, "Connection grant rejected. Reconnect this Facets installation to the Box.", http.StatusUnauthorized)
		return
	}
	workerID, parseErr := uuid.Parse(request.PathValue("workerID"))
	var body sharedWorkerOperationEnqueueBody
	var operation BoxSharedWorkerOperation
	if parseErr != nil || workerID == uuid.Nil ||
		decodeBoundedJSON(request, &body, maximumSharedWorkerOperationHTTPBytes) != nil ||
		body.Version != 1 || body.ChallengeID == uuid.Nil ||
		strictBoundedJSON(body.OperationPayload, &operation, maximumSharedWorkerOperationHTTPBytes) != nil ||
		operation.Version != 1 || operation.WorkerID != workerID {
		http.Error(writer, "SHARED-WORKER-OPERATION-FORMAT: The Worker operation is invalid.", http.StatusBadRequest)
		return
	}
	verifier, err := NewBoxParticipantProofVerifier(service.store)
	if err != nil {
		service.internalError(writer, request, "shared_worker_operation_verifier", err)
		return
	}
	now := service.now().UnixMilli()
	enrollment, err := verifier.AuthorizePresentedAction(
		request.Context(), body.Proof, body.ChallengeID,
		ParticipantActionEnqueueWorkerOperation, body.OperationPayload, now,
	)
	if errors.Is(err, ErrParticipantAuthority) || errors.Is(err, ErrParticipantReplay) {
		http.Error(writer, "SHARED-WORKER-OPERATION-AUTHORITY: The signed operation was rejected. Request a fresh challenge.", http.StatusForbidden)
		return
	}
	if err != nil {
		service.internalError(writer, request, "shared_worker_operation_authorize", err)
		return
	}
	if operation.BoxID != enrollment.Anchor.BoxID ||
		operation.RequesterParticipantID != enrollment.Anchor.ParticipantID ||
		operation.RequesterDeviceID != enrollment.Device.DeviceID {
		http.Error(writer, "SHARED-WORKER-OPERATION-AUTHORITY: The requester does not match this participant device.", http.StatusForbidden)
		return
	}
	operation.ConnectionGrantID = connection.GrantID
	operation.State = SharedWorkerOperationQueued
	err = service.store.EnqueueSharedWorkerOperation(request.Context(), operation, now)
	switch {
	case errors.Is(err, ErrSharedWorkerOperationCollision):
		http.Error(writer, "SHARED-WORKER-OPERATION-COLLISION: The operation identifier was already used for different content.", http.StatusConflict)
		return
	case errors.Is(err, ErrSharedWorkerOperation):
		http.Error(writer, "SHARED-WORKER-OPERATION-STATE: The Worker access grant or requested operation is no longer valid.", http.StatusConflict)
		return
	case err != nil:
		service.internalError(writer, request, "shared_worker_operation_enqueue", err)
		return
	}
	service.audit(request.Context(), "shared_worker_operation", "enqueued")
	writeJSON(writer, http.StatusCreated, BoxSharedWorkerOperationStatus{
		Version: 1, OperationID: operation.OperationID, State: SharedWorkerOperationQueued,
		ExpiresAtMilliseconds: operation.ExpiresAtMilliseconds,
	})
}

func (service *Service) handleClaimSharedWorkerOperation(writer http.ResponseWriter, request *http.Request) {
	if _, err := service.authorizeGrant(request); err != nil {
		http.Error(writer, "Connection grant rejected. Reconnect this Facets installation to the Box.", http.StatusUnauthorized)
		return
	}
	workerID, parseErr := uuid.Parse(request.PathValue("workerID"))
	var body sharedWorkerOperationClaimBody
	var claim BoxSharedWorkerOperationClaim
	if parseErr != nil || workerID == uuid.Nil || decodeJSON(request, &body) != nil ||
		body.Version != 1 || body.ChallengeID == uuid.Nil ||
		strictParticipantJSON(body.ClaimPayload, &claim) != nil ||
		claim.Version != 1 || claim.WorkerID != workerID {
		http.Error(writer, "SHARED-WORKER-CLAIM-FORMAT: The Worker operation claim is invalid.", http.StatusBadRequest)
		return
	}
	verifier, err := NewBoxParticipantProofVerifier(service.store)
	if err != nil {
		service.internalError(writer, request, "shared_worker_claim_verifier", err)
		return
	}
	now := service.now().UnixMilli()
	enrollment, err := verifier.AuthorizePresentedAction(
		request.Context(), body.Proof, body.ChallengeID,
		ParticipantActionClaimWorkerOperation, body.ClaimPayload, now,
	)
	if errors.Is(err, ErrParticipantAuthority) || errors.Is(err, ErrParticipantReplay) {
		http.Error(writer, "SHARED-WORKER-CLAIM-AUTHORITY: The signed operation claim was rejected. Request a fresh challenge.", http.StatusForbidden)
		return
	}
	if err != nil {
		service.internalError(writer, request, "shared_worker_claim_authorize", err)
		return
	}
	if claim.BoxID != enrollment.Anchor.BoxID ||
		claim.OwnerParticipantID != enrollment.Anchor.ParticipantID ||
		claim.OwnerDeviceID != enrollment.Device.DeviceID {
		http.Error(writer, "SHARED-WORKER-CLAIM-AUTHORITY: The Worker owner does not match this participant device.", http.StatusForbidden)
		return
	}
	operation, err := service.store.ClaimSharedWorkerOperation(request.Context(), claim, now)
	if errors.Is(err, ErrSharedWorkerOperationNoWork) {
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	if errors.Is(err, ErrSharedWorkerOperation) {
		http.Error(writer, "SHARED-WORKER-CLAIM-STATE: The Worker or participant authority is no longer valid.", http.StatusConflict)
		return
	}
	if err != nil {
		service.internalError(writer, request, "shared_worker_operation_claim", err)
		return
	}
	service.audit(request.Context(), "shared_worker_operation", "claimed")
	writeJSON(writer, http.StatusOK, sharedWorkerOperationAssignment{
		Version: 1, Operation: *operation, ClaimID: operation.ClaimID,
		ClaimedAtMilliseconds:      operation.ClaimedAtMilliseconds,
		ClaimExpiresAtMilliseconds: operation.ClaimExpiresAtMilliseconds,
	})
}

func (service *Service) handleCompleteSharedWorkerOperation(writer http.ResponseWriter, request *http.Request) {
	if _, err := service.authorizeGrant(request); err != nil {
		http.Error(writer, "Connection grant rejected. Reconnect this Facets installation to the Box.", http.StatusUnauthorized)
		return
	}
	operationID, parseErr := uuid.Parse(request.PathValue("operationID"))
	var body sharedWorkerOperationResponseBody
	var response BoxSharedWorkerOperationResponse
	if parseErr != nil || operationID == uuid.Nil ||
		decodeBoundedJSON(request, &body, maximumSharedWorkerOperationHTTPBytes) != nil ||
		body.Version != 1 || body.ChallengeID == uuid.Nil ||
		strictBoundedJSON(body.ResponsePayload, &response, maximumSharedWorkerOperationHTTPBytes) != nil ||
		response.Version != 1 || response.OperationID != operationID {
		http.Error(writer, "SHARED-WORKER-RESPONSE-FORMAT: The Worker operation response is invalid.", http.StatusBadRequest)
		return
	}
	verifier, err := NewBoxParticipantProofVerifier(service.store)
	if err != nil {
		service.internalError(writer, request, "shared_worker_response_verifier", err)
		return
	}
	now := service.now().UnixMilli()
	enrollment, err := verifier.AuthorizePresentedAction(
		request.Context(), body.Proof, body.ChallengeID,
		ParticipantActionRespondWorkerOperation, body.ResponsePayload, now,
	)
	if errors.Is(err, ErrParticipantAuthority) || errors.Is(err, ErrParticipantReplay) {
		http.Error(writer, "SHARED-WORKER-RESPONSE-AUTHORITY: The signed operation response was rejected. Request a fresh challenge.", http.StatusForbidden)
		return
	}
	if err != nil {
		service.internalError(writer, request, "shared_worker_response_authorize", err)
		return
	}
	if response.BoxID != enrollment.Anchor.BoxID ||
		response.OwnerParticipantID != enrollment.Anchor.ParticipantID ||
		response.OwnerDeviceID != enrollment.Device.DeviceID {
		http.Error(writer, "SHARED-WORKER-RESPONSE-AUTHORITY: The Worker owner does not match this participant device.", http.StatusForbidden)
		return
	}
	err = service.store.CompleteSharedWorkerOperation(request.Context(), response, now)
	switch {
	case errors.Is(err, ErrSharedWorkerOperationCollision):
		http.Error(writer, "SHARED-WORKER-RESPONSE-COLLISION: The operation already has a different response.", http.StatusConflict)
		return
	case errors.Is(err, ErrSharedWorkerOperation):
		http.Error(writer, "SHARED-WORKER-RESPONSE-STATE: The claim, Worker, or access grant is no longer valid.", http.StatusConflict)
		return
	case err != nil:
		service.internalError(writer, request, "shared_worker_operation_complete", err)
		return
	}
	service.audit(request.Context(), "shared_worker_operation", "response-ready")
	writer.WriteHeader(http.StatusNoContent)
}

func (service *Service) handleSharedWorkerOperationStatus(writer http.ResponseWriter, request *http.Request) {
	connection, err := service.authorizeGrant(request)
	operationID, parseErr := uuid.Parse(request.PathValue("operationID"))
	if err != nil || parseErr != nil || operationID == uuid.Nil {
		http.NotFound(writer, request)
		return
	}
	status, err := service.store.SharedWorkerOperationStatus(
		request.Context(), operationID, connection.GrantID, service.now().UnixMilli(),
	)
	if errors.Is(err, ErrSharedWorkerOperation) {
		http.NotFound(writer, request)
		return
	}
	if err != nil {
		service.internalError(writer, request, "shared_worker_operation_status", err)
		return
	}
	writeJSON(writer, http.StatusOK, status)
}
