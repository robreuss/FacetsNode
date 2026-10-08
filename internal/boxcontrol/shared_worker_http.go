package boxcontrol

import (
	"errors"
	"net/http"

	"github.com/google/uuid"
)

const participantChallengeLifetimeMilliseconds = int64(60 * 1000)

type createParticipantChallengeBody struct {
	Version       int       `json:"version"`
	ParticipantID uuid.UUID `json:"participantID"`
	DeviceID      uuid.UUID `json:"deviceID"`
}

type participantChallengeResponse struct {
	Version               int       `json:"version"`
	BoxID                 uuid.UUID `json:"boxID"`
	ParticipantID         uuid.UUID `json:"participantID"`
	DeviceID              uuid.UUID `json:"deviceID"`
	ChallengeID           uuid.UUID `json:"challengeID"`
	IssuedAtMilliseconds  int64     `json:"issuedAtMilliseconds"`
	ExpiresAtMilliseconds int64     `json:"expiresAtMilliseconds"`
}

func (service *Service) handleCreateParticipantChallenge(writer http.ResponseWriter, request *http.Request) {
	if _, err := service.authorizeGrant(request); err != nil {
		http.Error(writer, "Connection grant rejected. Reconnect this Facets installation to the Box.", http.StatusUnauthorized)
		return
	}
	var body createParticipantChallengeBody
	if decodeJSON(request, &body) != nil || body.Version != 1 ||
		body.ParticipantID == uuid.Nil || body.DeviceID == uuid.Nil {
		http.Error(writer, "PARTICIPANT-CHALLENGE-FORMAT: The participant challenge request is invalid.", http.StatusBadRequest)
		return
	}
	state, err := service.store.State(request.Context())
	if err != nil {
		service.internalError(writer, request, "participant_challenge_state", err)
		return
	}
	challengeID, err := uuid.NewRandomFromReader(service.random)
	if err != nil {
		service.internalError(writer, request, "participant_challenge_random", err)
		return
	}
	now := service.now().UnixMilli()
	challenge := BoxParticipantChallenge{
		BoxID: state.BoxID, ParticipantID: body.ParticipantID, DeviceID: body.DeviceID,
		ChallengeID: challengeID, IssuedAtMilliseconds: now,
		ExpiresAtMilliseconds: now + participantChallengeLifetimeMilliseconds,
	}
	if err := service.store.IssueParticipantChallenge(request.Context(), challenge, now); err != nil {
		http.Error(writer, "PARTICIPANT-CHALLENGE-AUTHORITY: This participant device is not active on the Box.", http.StatusForbidden)
		return
	}
	writeJSON(writer, http.StatusCreated, participantChallengeResponse{
		Version: 1, BoxID: challenge.BoxID, ParticipantID: challenge.ParticipantID,
		DeviceID: challenge.DeviceID, ChallengeID: challenge.ChallengeID,
		IssuedAtMilliseconds:  challenge.IssuedAtMilliseconds,
		ExpiresAtMilliseconds: challenge.ExpiresAtMilliseconds,
	})
}

type sharedWorkerAdvertisementBody struct {
	Version              int                             `json:"version"`
	AdvertisementPayload []byte                          `json:"advertisementPayload"`
	Enrollment           BoxParticipantEnrollment        `json:"enrollment"`
	ChallengeID          uuid.UUID                       `json:"challengeID"`
	Proof                BoxSignedParticipantActionProof `json:"proof"`
}

func (service *Service) handleAdvertiseSharedWorker(writer http.ResponseWriter, request *http.Request) {
	if _, err := service.authorizeGrant(request); err != nil {
		http.Error(writer, "Connection grant rejected. Reconnect this Facets installation to the Box.", http.StatusUnauthorized)
		return
	}
	workerID, err := uuid.Parse(request.PathValue("workerID"))
	var body sharedWorkerAdvertisementBody
	var advertisement BoxSharedWorkerAdvertisement
	if err != nil || workerID == uuid.Nil || decodeJSON(request, &body) != nil ||
		body.Version != 1 || body.ChallengeID == uuid.Nil ||
		len(body.AdvertisementPayload) == 0 ||
		len(body.AdvertisementPayload) > maximumWorkerCapabilitiesBytes+4096 ||
		strictParticipantJSON(body.AdvertisementPayload, &advertisement) != nil ||
		advertisement.WorkerID != workerID ||
		advertisement.OwnerParticipantID != body.Enrollment.Anchor.ParticipantID ||
		advertisement.OwnerDeviceID != body.Enrollment.Device.DeviceID {
		http.Error(writer, "SHARED-WORKER-FORMAT: The Worker advertisement is invalid.", http.StatusBadRequest)
		return
	}
	verifier, err := NewBoxParticipantProofVerifier(service.store)
	if err != nil {
		service.internalError(writer, request, "shared_worker_verifier", err)
		return
	}
	now := service.now().UnixMilli()
	err = verifier.AuthorizeAction(
		request.Context(), body.Enrollment.Anchor, body.Enrollment.Device,
		body.Enrollment.RootRecord, body.Enrollment.GrantRecord, nil, body.Proof,
		body.ChallengeID, ParticipantActionAdvertiseWorker,
		body.AdvertisementPayload, now,
	)
	if errors.Is(err, ErrParticipantAuthority) || errors.Is(err, ErrParticipantReplay) {
		http.Error(writer, "SHARED-WORKER-AUTHORITY: The signed Worker advertisement was rejected. Request a fresh challenge.", http.StatusForbidden)
		return
	}
	if err != nil {
		service.internalError(writer, request, "shared_worker_authorize", err)
		return
	}
	if err := service.store.UpsertSharedWorker(request.Context(), advertisement, now); err != nil {
		if errors.Is(err, ErrSharedWorkerAuthority) {
			http.Error(writer, "SHARED-WORKER-REVISION: The Worker owner, revision, availability, or expiry was rejected.", http.StatusConflict)
			return
		}
		service.internalError(writer, request, "shared_worker_upsert", err)
		return
	}
	service.audit(request.Context(), "shared_worker_advertisement", "accepted")
	writeJSON(writer, http.StatusCreated, advertisement)
}

func (service *Service) handleListSharedWorkers(writer http.ResponseWriter, request *http.Request) {
	if _, err := service.authorizeGrant(request); err != nil {
		http.Error(writer, "Connection grant rejected. Reconnect this Facets installation to the Box.", http.StatusUnauthorized)
		return
	}
	state, err := service.store.State(request.Context())
	if err != nil {
		service.internalError(writer, request, "shared_worker_list_state", err)
		return
	}
	workers, err := service.store.ListSharedWorkers(request.Context(), state.BoxID, service.now().UnixMilli())
	if err != nil {
		service.internalError(writer, request, "shared_worker_list", err)
		return
	}
	writeJSON(writer, http.StatusOK, struct {
		Version int                            `json:"version"`
		Workers []BoxSharedWorkerAdvertisement `json:"workers"`
	}{Version: 1, Workers: workers})
}

type sharedWorkerWithdrawal struct {
	Version            int       `json:"version"`
	BoxID              uuid.UUID `json:"boxID"`
	WorkerID           uuid.UUID `json:"workerID"`
	OwnerParticipantID uuid.UUID `json:"ownerParticipantID"`
	OwnerDeviceID      uuid.UUID `json:"ownerDeviceID"`
	Revision           uint64    `json:"revision"`
}

type sharedWorkerWithdrawalBody struct {
	Version           int                             `json:"version"`
	WithdrawalPayload []byte                          `json:"withdrawalPayload"`
	Enrollment        BoxParticipantEnrollment        `json:"enrollment"`
	ChallengeID       uuid.UUID                       `json:"challengeID"`
	Proof             BoxSignedParticipantActionProof `json:"proof"`
}

func (service *Service) handleWithdrawSharedWorker(writer http.ResponseWriter, request *http.Request) {
	if _, err := service.authorizeGrant(request); err != nil {
		http.Error(writer, "Connection grant rejected. Reconnect this Facets installation to the Box.", http.StatusUnauthorized)
		return
	}
	workerID, err := uuid.Parse(request.PathValue("workerID"))
	var body sharedWorkerWithdrawalBody
	var withdrawal sharedWorkerWithdrawal
	if err != nil || workerID == uuid.Nil || decodeJSON(request, &body) != nil ||
		body.Version != 1 || body.ChallengeID == uuid.Nil ||
		len(body.WithdrawalPayload) == 0 || len(body.WithdrawalPayload) > 4096 ||
		strictParticipantJSON(body.WithdrawalPayload, &withdrawal) != nil ||
		withdrawal.Version != 1 || withdrawal.WorkerID != workerID ||
		withdrawal.Revision == 0 ||
		withdrawal.OwnerParticipantID != body.Enrollment.Anchor.ParticipantID ||
		withdrawal.OwnerDeviceID != body.Enrollment.Device.DeviceID {
		http.Error(writer, "SHARED-WORKER-FORMAT: The Worker withdrawal is invalid.", http.StatusBadRequest)
		return
	}
	verifier, err := NewBoxParticipantProofVerifier(service.store)
	if err != nil {
		service.internalError(writer, request, "shared_worker_verifier", err)
		return
	}
	now := service.now().UnixMilli()
	err = verifier.AuthorizeAction(
		request.Context(), body.Enrollment.Anchor, body.Enrollment.Device,
		body.Enrollment.RootRecord, body.Enrollment.GrantRecord, nil, body.Proof,
		body.ChallengeID, ParticipantActionWithdrawWorker,
		body.WithdrawalPayload, now,
	)
	if errors.Is(err, ErrParticipantAuthority) || errors.Is(err, ErrParticipantReplay) {
		http.Error(writer, "SHARED-WORKER-AUTHORITY: The signed Worker withdrawal was rejected. Request a fresh challenge.", http.StatusForbidden)
		return
	}
	if err != nil {
		service.internalError(writer, request, "shared_worker_withdraw_authorize", err)
		return
	}
	err = service.store.WithdrawSharedWorker(
		request.Context(), withdrawal.BoxID, withdrawal.WorkerID,
		withdrawal.OwnerParticipantID, withdrawal.OwnerDeviceID,
		withdrawal.Revision, now,
	)
	if errors.Is(err, ErrSharedWorkerAuthority) {
		http.Error(writer, "SHARED-WORKER-REVISION: The Worker owner or revision was rejected.", http.StatusConflict)
		return
	}
	if err != nil {
		service.internalError(writer, request, "shared_worker_withdraw", err)
		return
	}
	service.audit(request.Context(), "shared_worker_withdrawal", "accepted")
	writer.WriteHeader(http.StatusNoContent)
}
