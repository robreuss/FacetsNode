package boxcontrol

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/computequeue"
	"github.com/robreuss/FacetsNode/internal/jobcustody"
)

const maximumJobCustodyAdmissionPermitHTTPBytes = 128 * 1024

type jobCustodyAdmissionPermitBody struct {
	ChallengeID    uuid.UUID                       `json:"challengeID"`
	Proof          BoxSignedParticipantActionProof `json:"proof"`
	RequestPayload json.RawMessage                 `json:"requestPayload"`
	Version        int                             `json:"version"`
}

func (service *Service) handleIssueJobCustodyAdmissionPermit(
	writer http.ResponseWriter,
	request *http.Request,
) {
	connection, err := service.authorizeGrant(request)
	if err != nil {
		http.Error(writer, "Connection grant rejected. Reconnect this Facets installation to the Box.", http.StatusUnauthorized)
		return
	}
	var body jobCustodyAdmissionPermitBody
	now := service.now().UnixMilli()
	if decodeBoundedJSON(request, &body, maximumJobCustodyAdmissionPermitHTTPBytes) != nil ||
		body.Version != 1 || body.ChallengeID == uuid.Nil {
		http.Error(writer, "JOB-CUSTODY-PERMIT-FORMAT: The route permit request is invalid.", http.StatusBadRequest)
		return
	}
	permitRequest, err := decodeJobCustodyAdmissionPermitRequest(
		body.RequestPayload, maximumJobCustodyAdmissionPermitHTTPBytes, now,
	)
	if err != nil {
		http.Error(writer, "JOB-CUSTODY-PERMIT-FORMAT: The route permit request is invalid.", http.StatusBadRequest)
		return
	}
	verifier, err := NewBoxParticipantProofVerifier(service.store)
	if err != nil {
		service.internalError(writer, request, "job_custody_permit_verifier", err)
		return
	}
	enrollment, err := verifier.AuthorizePresentedAction(
		request.Context(), body.Proof, body.ChallengeID,
		ParticipantActionIssueJobCustodyPermit, body.RequestPayload, now,
	)
	if errors.Is(err, ErrParticipantAuthority) || errors.Is(err, ErrParticipantReplay) {
		http.Error(writer, "JOB-CUSTODY-PERMIT-AUTHORITY: The signed permit request was rejected. Request a fresh challenge.", http.StatusForbidden)
		return
	}
	if err != nil {
		service.internalError(writer, request, "job_custody_permit_authorize", err)
		return
	}
	if permitRequest.BoxID != enrollment.Anchor.BoxID ||
		permitRequest.ParticipantID != enrollment.Anchor.ParticipantID ||
		permitRequest.DeviceID != enrollment.Device.DeviceID {
		http.Error(writer, "JOB-CUSTODY-PERMIT-AUTHORITY: The requester does not match this participant device.", http.StatusForbidden)
		return
	}
	permitRequest.ConnectionGrantID = connection.GrantID
	authority, err := service.store.AuthorizeJobCustodyAdmission(
		request.Context(), permitRequest, now,
	)
	if errors.Is(err, ErrJobCustodyRouteAuthority) {
		http.Error(writer, "JOB-CUSTODY-PERMIT-ROUTE: The Worker route or access grant is no longer valid.", http.StatusConflict)
		return
	}
	if err != nil {
		service.internalError(writer, request, "job_custody_permit_route", err)
		return
	}
	payload, err := jobcustody.NewAdmissionPermitPayload(
		permitRequest.BoxID,
		permitRequest.PermitID,
		authority.requesterAuthorityDigest,
		authority.workerAccessGrantDigest,
		authority.workerCapabilitiesDigest,
		permitRequest.AdmissionSigner,
		permitRequest.AdmissionEnvelope,
		computequeue.Timestamp(now),
		computequeue.Timestamp(permitRequest.ExpiresAtMilliseconds),
	)
	if err != nil {
		http.Error(writer, "JOB-CUSTODY-PERMIT-FORMAT: The admission envelope cannot be authorized.", http.StatusBadRequest)
		return
	}
	signer, err := jobcustody.NewAdmissionPermitSigner(permitRequest.BoxID, service.privateKey)
	if err != nil {
		service.internalError(writer, request, "job_custody_permit_signer", err)
		return
	}
	permit, err := signer.Sign(payload)
	if err != nil {
		service.internalError(writer, request, "job_custody_permit_sign", err)
		return
	}
	service.audit(request.Context(), "job_custody_admission_permit", "issued")
	writeJSON(writer, http.StatusCreated, permit)
}
