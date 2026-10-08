package boxcontrol

import (
	"errors"
	"net/http"

	"github.com/google/uuid"
)

const maximumSharedWorkerAccessPayloadBytes = 8 * 1024

type sharedWorkerAccessRequestBody struct {
	Version        int                             `json:"version"`
	RequestPayload []byte                          `json:"requestPayload"`
	ChallengeID    uuid.UUID                       `json:"challengeID"`
	Proof          BoxSignedParticipantActionProof `json:"proof"`
}

type sharedWorkerAccessRequestResponse struct {
	Version               int       `json:"version"`
	RequestID             uuid.UUID `json:"requestID"`
	ConfirmationCode      string    `json:"confirmationCode"`
	ExpiresAtMilliseconds int64     `json:"expiresAtMilliseconds"`
}

func (service *Service) handleRequestSharedWorkerAccess(writer http.ResponseWriter, request *http.Request) {
	connection, err := service.authorizeGrant(request)
	if err != nil {
		http.Error(writer, "Connection grant rejected. Reconnect this Facets installation to the Box.", http.StatusUnauthorized)
		return
	}
	workerID, err := uuid.Parse(request.PathValue("workerID"))
	var body sharedWorkerAccessRequestBody
	var accessRequest BoxSharedWorkerAccessRequest
	if err != nil || workerID == uuid.Nil || decodeJSON(request, &body) != nil ||
		body.Version != 1 || body.ChallengeID == uuid.Nil ||
		len(body.RequestPayload) == 0 || len(body.RequestPayload) > maximumSharedWorkerAccessPayloadBytes ||
		strictParticipantJSON(body.RequestPayload, &accessRequest) != nil ||
		accessRequest.Version != 1 || accessRequest.WorkerID != workerID {
		http.Error(writer, "SHARED-WORKER-ACCESS-FORMAT: The Worker access request is invalid.", http.StatusBadRequest)
		return
	}
	verifier, err := NewBoxParticipantProofVerifier(service.store)
	if err != nil {
		service.internalError(writer, request, "shared_worker_access_verifier", err)
		return
	}
	now := service.now().UnixMilli()
	enrollment, err := verifier.AuthorizePresentedAction(
		request.Context(), body.Proof, body.ChallengeID,
		ParticipantActionRequestWorkerAccess, body.RequestPayload, now,
	)
	if errors.Is(err, ErrParticipantAuthority) || errors.Is(err, ErrParticipantReplay) {
		http.Error(writer, "SHARED-WORKER-ACCESS-AUTHORITY: The signed access request was rejected. Request a fresh challenge.", http.StatusForbidden)
		return
	}
	if err != nil {
		service.internalError(writer, request, "shared_worker_access_authorize", err)
		return
	}
	if accessRequest.BoxID != enrollment.Anchor.BoxID ||
		accessRequest.RequesterParticipantID != enrollment.Anchor.ParticipantID ||
		accessRequest.RequesterDeviceID != enrollment.Device.DeviceID {
		http.Error(writer, "SHARED-WORKER-ACCESS-AUTHORITY: The requester does not match this participant device.", http.StatusForbidden)
		return
	}
	accessRequest.ConnectionGrantID = connection.GrantID
	accessRequest.Decision = SharedWorkerAccessPending
	for attempt := 0; attempt < 32; attempt++ {
		code, err := service.randomApprovalCode()
		if err != nil {
			service.internalError(writer, request, "shared_worker_access_code", err)
			return
		}
		digest, err := SharedWorkerAccessCodeDigest(code)
		if err != nil {
			service.internalError(writer, request, "shared_worker_access_code_digest", err)
			return
		}
		accessRequest.ConfirmationCodeDigest = digest
		err = service.store.CreateSharedWorkerAccessRequest(request.Context(), accessRequest, now)
		if errors.Is(err, ErrSharedWorkerAccessCodeCollision) {
			continue
		}
		if errors.Is(err, ErrSharedWorkerAccess) {
			http.Error(writer, "SHARED-WORKER-ACCESS-STATE: The Worker or requested capabilities are no longer available.", http.StatusConflict)
			return
		}
		if err != nil {
			service.internalError(writer, request, "shared_worker_access_create", err)
			return
		}
		service.audit(request.Context(), "shared_worker_access_request", "created")
		writeJSON(writer, http.StatusCreated, sharedWorkerAccessRequestResponse{
			Version: 1, RequestID: accessRequest.RequestID, ConfirmationCode: code,
			ExpiresAtMilliseconds: accessRequest.ExpiresAtMilliseconds,
		})
		return
	}
	service.internalError(writer, request, "shared_worker_access_code", ErrSharedWorkerAccessCodeCollision)
}

func (service *Service) handleSharedWorkerAccessRequestStatus(writer http.ResponseWriter, request *http.Request) {
	connection, err := service.authorizeGrant(request)
	requestID, parseErr := uuid.Parse(request.PathValue("requestID"))
	if err != nil || parseErr != nil || requestID == uuid.Nil {
		http.NotFound(writer, request)
		return
	}
	status, err := service.store.SharedWorkerAccessRequest(
		request.Context(), requestID, connection.GrantID, service.now().UnixMilli(),
	)
	if errors.Is(err, ErrSharedWorkerAccess) {
		http.NotFound(writer, request)
		return
	}
	if err != nil {
		service.internalError(writer, request, "shared_worker_access_status", err)
		return
	}
	writeJSON(writer, http.StatusOK, status)
}

type sharedWorkerAccessGrantBody struct {
	Version          int                             `json:"version"`
	GrantPayload     []byte                          `json:"grantPayload"`
	ConfirmationCode string                          `json:"confirmationCode"`
	ChallengeID      uuid.UUID                       `json:"challengeID"`
	Proof            BoxSignedParticipantActionProof `json:"proof"`
}

func (service *Service) handleGrantSharedWorkerAccess(writer http.ResponseWriter, request *http.Request) {
	if _, err := service.authorizeGrant(request); err != nil {
		http.Error(writer, "Connection grant rejected. Reconnect this Facets installation to the Box.", http.StatusUnauthorized)
		return
	}
	workerID, err := uuid.Parse(request.PathValue("workerID"))
	var body sharedWorkerAccessGrantBody
	var grant BoxSharedWorkerAccessGrant
	if err != nil || workerID == uuid.Nil || decodeJSON(request, &body) != nil ||
		body.Version != 1 || body.ChallengeID == uuid.Nil ||
		len(body.GrantPayload) == 0 || len(body.GrantPayload) > maximumSharedWorkerAccessPayloadBytes ||
		strictParticipantJSON(body.GrantPayload, &grant) != nil ||
		grant.Version != 1 || grant.WorkerID != workerID {
		http.Error(writer, "SHARED-WORKER-GRANT-FORMAT: The Worker access grant is invalid.", http.StatusBadRequest)
		return
	}
	codeDigest, err := SharedWorkerAccessCodeDigest(body.ConfirmationCode)
	if err != nil || grant.ConfirmationCodeDigest != sharedWorkerAccessCodeDigestString(codeDigest) {
		http.Error(writer, "SHARED-WORKER-ACCESS-CODE: The confirmation code is invalid.", http.StatusUnauthorized)
		return
	}
	verifier, err := NewBoxParticipantProofVerifier(service.store)
	if err != nil {
		service.internalError(writer, request, "shared_worker_grant_verifier", err)
		return
	}
	now := service.now().UnixMilli()
	enrollment, err := verifier.AuthorizePresentedAction(
		request.Context(), body.Proof, body.ChallengeID,
		ParticipantActionGrantWorkerAccess, body.GrantPayload, now,
	)
	if errors.Is(err, ErrParticipantAuthority) || errors.Is(err, ErrParticipantReplay) {
		http.Error(writer, "SHARED-WORKER-GRANT-AUTHORITY: The signed access grant was rejected. Request a fresh challenge.", http.StatusForbidden)
		return
	}
	if err != nil {
		service.internalError(writer, request, "shared_worker_grant_authorize", err)
		return
	}
	if grant.BoxID != enrollment.Anchor.BoxID ||
		grant.OwnerParticipantID != enrollment.Anchor.ParticipantID ||
		grant.OwnerDeviceID != enrollment.Device.DeviceID {
		http.Error(writer, "SHARED-WORKER-GRANT-AUTHORITY: The Worker owner does not match this participant device.", http.StatusForbidden)
		return
	}
	err = service.store.ConfirmSharedWorkerAccess(request.Context(), grant, codeDigest, now)
	switch {
	case errors.Is(err, ErrSharedWorkerAccessCode):
		http.Error(writer, "SHARED-WORKER-ACCESS-CODE: The confirmation code is invalid.", http.StatusUnauthorized)
		return
	case errors.Is(err, ErrSharedWorkerAccessLocked):
		http.Error(writer, "SHARED-WORKER-ACCESS-LOCKED: Too many incorrect confirmation attempts. Create a new request.", http.StatusTooManyRequests)
		return
	case errors.Is(err, ErrSharedWorkerAccess):
		http.Error(writer, "SHARED-WORKER-GRANT-STATE: The request, Worker, or participant authority is no longer valid.", http.StatusConflict)
		return
	case err != nil:
		service.internalError(writer, request, "shared_worker_grant_confirm", err)
		return
	}
	service.audit(request.Context(), "shared_worker_access_grant", "approved")
	writeJSON(writer, http.StatusCreated, grant)
}

type sharedWorkerAccessRevocation struct {
	Version            int       `json:"version"`
	BoxID              uuid.UUID `json:"boxID"`
	GrantID            uuid.UUID `json:"grantID"`
	OwnerParticipantID uuid.UUID `json:"ownerParticipantID"`
	OwnerDeviceID      uuid.UUID `json:"ownerDeviceID"`
	Revision           uint64    `json:"revision"`
}

type sharedWorkerAccessRevocationBody struct {
	Version           int                             `json:"version"`
	RevocationPayload []byte                          `json:"revocationPayload"`
	ChallengeID       uuid.UUID                       `json:"challengeID"`
	Proof             BoxSignedParticipantActionProof `json:"proof"`
}

func (service *Service) handleRevokeSharedWorkerAccess(writer http.ResponseWriter, request *http.Request) {
	if _, err := service.authorizeGrant(request); err != nil {
		http.Error(writer, "Connection grant rejected. Reconnect this Facets installation to the Box.", http.StatusUnauthorized)
		return
	}
	grantID, err := uuid.Parse(request.PathValue("grantID"))
	var body sharedWorkerAccessRevocationBody
	var revocation sharedWorkerAccessRevocation
	if err != nil || grantID == uuid.Nil || decodeJSON(request, &body) != nil ||
		body.Version != 1 || body.ChallengeID == uuid.Nil ||
		len(body.RevocationPayload) == 0 || len(body.RevocationPayload) > maximumSharedWorkerAccessPayloadBytes ||
		strictParticipantJSON(body.RevocationPayload, &revocation) != nil ||
		revocation.Version != 1 || revocation.GrantID != grantID || revocation.Revision == 0 {
		http.Error(writer, "SHARED-WORKER-REVOKE-FORMAT: The Worker access revocation is invalid.", http.StatusBadRequest)
		return
	}
	verifier, err := NewBoxParticipantProofVerifier(service.store)
	if err != nil {
		service.internalError(writer, request, "shared_worker_revoke_verifier", err)
		return
	}
	now := service.now().UnixMilli()
	enrollment, err := verifier.AuthorizePresentedAction(
		request.Context(), body.Proof, body.ChallengeID,
		ParticipantActionRevokeWorkerAccess, body.RevocationPayload, now,
	)
	if errors.Is(err, ErrParticipantAuthority) || errors.Is(err, ErrParticipantReplay) {
		http.Error(writer, "SHARED-WORKER-REVOKE-AUTHORITY: The signed access revocation was rejected. Request a fresh challenge.", http.StatusForbidden)
		return
	}
	if err != nil {
		service.internalError(writer, request, "shared_worker_revoke_authorize", err)
		return
	}
	if revocation.BoxID != enrollment.Anchor.BoxID ||
		revocation.OwnerParticipantID != enrollment.Anchor.ParticipantID ||
		revocation.OwnerDeviceID != enrollment.Device.DeviceID {
		http.Error(writer, "SHARED-WORKER-REVOKE-AUTHORITY: The Worker owner does not match this participant device.", http.StatusForbidden)
		return
	}
	if err := service.store.RevokeSharedWorkerAccess(
		request.Context(), revocation.BoxID, revocation.GrantID,
		revocation.OwnerParticipantID, revocation.Revision, now,
	); err != nil {
		if errors.Is(err, ErrSharedWorkerAccess) {
			http.Error(writer, "SHARED-WORKER-REVOKE-STATE: The grant owner or revision was rejected.", http.StatusConflict)
			return
		}
		service.internalError(writer, request, "shared_worker_revoke", err)
		return
	}
	service.audit(request.Context(), "shared_worker_access_grant", "revoked")
	writer.WriteHeader(http.StatusNoContent)
}
