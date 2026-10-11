package boxcontrol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/computequeue"
	"github.com/robreuss/FacetsNode/internal/jobcustody"
)

// BoxJobCustodyWorkerResultPermitRequest is signed by the enrolled device
// that owns the advertised Worker. The result header contains only opaque
// custody metadata and exact protected-byte commitments.
// Field declaration order is canonical sorted-key JSON.
type BoxJobCustodyWorkerResultPermitRequest struct {
	BoxID                        uuid.UUID                     `json:"boxID"`
	CapabilitiesDigest           string                        `json:"capabilitiesDigest"`
	DeviceID                     uuid.UUID                     `json:"deviceID"`
	ExpiresAtMilliseconds        int64                         `json:"expiresAtMilliseconds"`
	ParticipantID                uuid.UUID                     `json:"participantID"`
	PermitID                     uuid.UUID                     `json:"permitID"`
	RequestedAtMilliseconds      int64                         `json:"requestedAtMilliseconds"`
	Result                       jobcustody.WorkerResultHeader `json:"result"`
	RouteRecipientKeyFingerprint computequeue.Digest           `json:"routeRecipientKeyFingerprint"`
	Version                      int                           `json:"version"`
	WorkerID                     uuid.UUID                     `json:"workerID"`
	ConnectionGrantID            uuid.UUID                     `json:"-"`
}

func decodeJobCustodyWorkerResultPermitRequest(
	data []byte,
	maximumBytes int,
	nowMilliseconds int64,
) (BoxJobCustodyWorkerResultPermitRequest, error) {
	var value BoxJobCustodyWorkerResultPermitRequest
	if strictBoundedJSON(data, &value, maximumBytes) != nil {
		return value, ErrJobCustodyRouteAuthority
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(data, canonical) || value.ConnectionGrantID != uuid.Nil ||
		value.validateAt(nowMilliseconds) != nil {
		return BoxJobCustodyWorkerResultPermitRequest{}, ErrJobCustodyRouteAuthority
	}
	return value, nil
}

func (value BoxJobCustodyWorkerResultPermitRequest) validateAt(nowMilliseconds int64) error {
	if value.Version != jobcustody.WorkerResultPermitVersion || value.BoxID == uuid.Nil ||
		value.DeviceID == uuid.Nil || value.ParticipantID == uuid.Nil || value.PermitID == uuid.Nil ||
		value.WorkerID == uuid.Nil || !validParticipantRequestDigest(value.CapabilitiesDigest) ||
		value.Result.Validate() != nil || value.RouteRecipientKeyFingerprint.Validate() != nil ||
		value.RequestedAtMilliseconds <= 0 || value.RequestedAtMilliseconds > nowMilliseconds ||
		nowMilliseconds-value.RequestedAtMilliseconds > maximumParticipantProofAgeMilliseconds ||
		value.ExpiresAtMilliseconds <= nowMilliseconds ||
		value.ExpiresAtMilliseconds > int64(value.Result.RetentionUntil) ||
		value.ExpiresAtMilliseconds-value.RequestedAtMilliseconds > jobcustody.MaximumWorkerClaimPermitLifetimeMillisecs {
		return ErrJobCustodyRouteAuthority
	}
	return nil
}

type jobCustodyWorkerResultPermitBody struct {
	ChallengeID    uuid.UUID                       `json:"challengeID"`
	Proof          BoxSignedParticipantActionProof `json:"proof"`
	RequestPayload json.RawMessage                 `json:"requestPayload"`
	Version        int                             `json:"version"`
}

func (service *Service) handleIssueJobCustodyWorkerResultPermit(
	writer http.ResponseWriter,
	request *http.Request,
) {
	connection, err := service.authorizeGrant(request)
	if err != nil {
		http.Error(writer, "Connection grant rejected. Reconnect this Facets installation to the Box.", http.StatusUnauthorized)
		return
	}
	var body jobCustodyWorkerResultPermitBody
	now := service.now().UnixMilli()
	if decodeBoundedJSON(request, &body, maximumJobCustodyAdmissionPermitHTTPBytes) != nil ||
		body.Version != 1 || body.ChallengeID == uuid.Nil {
		http.Error(writer, "JOB-CUSTODY-WORKER-RESULT-PERMIT-FORMAT: The Worker result permit request is invalid.", http.StatusBadRequest)
		return
	}
	permitRequest, err := decodeJobCustodyWorkerResultPermitRequest(
		body.RequestPayload, maximumJobCustodyAdmissionPermitHTTPBytes, now,
	)
	if err != nil {
		http.Error(writer, "JOB-CUSTODY-WORKER-RESULT-PERMIT-FORMAT: The Worker result permit request is invalid.", http.StatusBadRequest)
		return
	}
	verifier, err := NewBoxParticipantProofVerifier(service.store)
	if err != nil {
		service.internalError(writer, request, "job_custody_worker_result_permit_verifier", err)
		return
	}
	enrollment, err := verifier.AuthorizePresentedAction(
		request.Context(), body.Proof, body.ChallengeID,
		ParticipantActionIssueJobCustodyWorkerResultPermit, body.RequestPayload, now,
	)
	if errors.Is(err, ErrParticipantAuthority) || errors.Is(err, ErrParticipantReplay) {
		http.Error(writer, "JOB-CUSTODY-WORKER-RESULT-PERMIT-AUTHORITY: The signed Worker result request was rejected. Request a fresh challenge.", http.StatusForbidden)
		return
	}
	if err != nil {
		service.internalError(writer, request, "job_custody_worker_result_permit_authorize", err)
		return
	}
	if permitRequest.BoxID != enrollment.Anchor.BoxID ||
		permitRequest.ParticipantID != enrollment.Anchor.ParticipantID ||
		permitRequest.DeviceID != enrollment.Device.DeviceID ||
		connection.ExpiresAt.UnixMilli() < permitRequest.ExpiresAtMilliseconds {
		http.Error(writer, "JOB-CUSTODY-WORKER-RESULT-PERMIT-AUTHORITY: The requester does not match this Worker owner device.", http.StatusForbidden)
		return
	}
	workers, err := service.store.ListSharedWorkers(request.Context(), permitRequest.BoxID, now)
	if err != nil {
		service.internalError(writer, request, "job_custody_worker_result_permit_directory", err)
		return
	}
	var selected *BoxSharedWorkerAdvertisement
	for index := range workers {
		worker := &workers[index]
		if worker.WorkerID == permitRequest.WorkerID {
			selected = worker
			break
		}
	}
	if selected == nil || selected.OwnerParticipantID != permitRequest.ParticipantID ||
		selected.OwnerDeviceID != permitRequest.DeviceID ||
		selected.CapabilitiesDigest != permitRequest.CapabilitiesDigest ||
		selected.ExpiresAtMilliseconds < permitRequest.ExpiresAtMilliseconds ||
		(selected.Availability != SharedWorkerAvailable && selected.Availability != SharedWorkerBusy) {
		http.Error(writer, "JOB-CUSTODY-WORKER-RESULT-PERMIT-ROUTE: The Worker route is no longer available.", http.StatusConflict)
		return
	}
	ownerDigest := computequeue.SHA256Digest(
		"facets.box.job-custody.worker-owner-authority.v1",
		enrollment.Anchor.BoxID.String(), enrollment.Anchor.ParticipantID.String(),
		enrollment.Anchor.BoxScopedPrincipalID.String(), enrollment.Device.DeviceID.String(),
		enrollment.Device.GrantID.String(), fmt.Sprint(enrollment.Device.DeviceGeneration),
	)
	payload := jobcustody.WorkerResultPermitPayload{
		AuthorityID: permitRequest.BoxID,
		ExpiresAt:   computequeue.Timestamp(permitRequest.ExpiresAtMilliseconds),
		IssuedAt:    computequeue.Timestamp(now), PermitID: permitRequest.PermitID,
		Result:                       permitRequest.Result,
		RouteRecipientKeyFingerprint: permitRequest.RouteRecipientKeyFingerprint,
		RouteRecipientWorkerID:       computequeue.WorkerID(permitRequest.WorkerID.String()),
		Version:                      jobcustody.WorkerResultPermitVersion,
		WorkerCapabilitiesDigest:     computequeue.Digest(permitRequest.CapabilitiesDigest),
		WorkerOwnerAuthorityDigest:   ownerDigest,
	}
	signer, err := jobcustody.NewWorkerResultPermitSigner(permitRequest.BoxID, service.privateKey)
	if err != nil {
		service.internalError(writer, request, "job_custody_worker_result_permit_signer", err)
		return
	}
	permit, err := signer.Sign(payload)
	if err != nil {
		service.internalError(writer, request, "job_custody_worker_result_permit_sign", err)
		return
	}
	service.audit(request.Context(), "job_custody_worker_result_permit", "issued")
	writeJSON(writer, http.StatusCreated, permit)
}
