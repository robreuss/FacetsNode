package boxcontrol

import (
	"errors"
	"net/http"

	"github.com/google/uuid"
)

type participantEnrollmentRequestBody struct {
	Version           int                        `json:"version"`
	RequestID         uuid.UUID                  `json:"requestID"`
	Enrollment        BoxParticipantEnrollment   `json:"enrollment"`
	Presentation      BoxParticipantPresentation `json:"presentation"`
	Proof             BoxSignedParticipantProof  `json:"proof"`
	RequestedAtMillis int64                      `json:"requestedAtMilliseconds"`
	ExpiresAtMillis   int64                      `json:"expiresAtMilliseconds"`
}

func (service *Service) handleCreateParticipantEnrollmentRequest(writer http.ResponseWriter, request *http.Request) {
	grant, err := service.authorizeGrant(request)
	if err != nil {
		http.Error(writer, "Connection grant rejected. Reconnect this Facets installation to the Box.", http.StatusUnauthorized)
		return
	}
	var body participantEnrollmentRequestBody
	if decodeJSON(request, &body) != nil || body.Version != 1 || body.RequestID == uuid.Nil {
		http.Error(writer, "PARTICIPANT-REQUEST-FORMAT: The enrollment request is invalid. Retry from Facets.", http.StatusBadRequest)
		return
	}
	state, err := service.store.State(request.Context())
	if err != nil {
		service.internalError(writer, request, "participant_request_state", err)
		return
	}
	if !state.Claimed() || body.Enrollment.Anchor.BoxID != state.BoxID {
		http.Error(writer, "PARTICIPANT-REQUEST-BOX: This request is for a different or unclaimed Box.", http.StatusForbidden)
		return
	}
	proposal := BoxParticipantEnrollmentRequest{
		RequestID: body.RequestID, ConnectionGrantID: grant.GrantID,
		Enrollment: body.Enrollment, Presentation: body.Presentation, Proof: body.Proof,
		RequestedAtMillis: body.RequestedAtMillis, ExpiresAtMillis: body.ExpiresAtMillis,
		Decision: "pending",
	}
	err = service.store.CreateParticipantEnrollmentRequest(request.Context(), proposal, service.now().UnixMilli())
	if errors.Is(err, ErrParticipantAuthority) {
		service.audit(request.Context(), "participant_request", "rejected")
		http.Error(writer, "PARTICIPANT-REQUEST-AUTHORITY: Signed device proof, connection, or request timing was rejected. Reconnect and submit a fresh request.", http.StatusForbidden)
		return
	}
	if err != nil {
		service.internalError(writer, request, "participant_request_create", err)
		return
	}
	service.audit(request.Context(), "participant_request", "pending")
	writeJSON(writer, http.StatusAccepted, struct {
		RequestID uuid.UUID `json:"requestID"`
		Decision  string    `json:"decision"`
	}{RequestID: proposal.RequestID, Decision: "pending"})
}

func (service *Service) handleParticipantEnrollmentRequestStatus(writer http.ResponseWriter, request *http.Request) {
	grant, err := service.authorizeGrant(request)
	if err != nil {
		http.Error(writer, "Connection grant rejected. Reconnect this Facets installation to the Box.", http.StatusUnauthorized)
		return
	}
	requestID, err := uuid.Parse(request.PathValue("requestID"))
	if err != nil || requestID == uuid.Nil {
		http.NotFound(writer, request)
		return
	}
	status, err := service.store.ParticipantEnrollmentRequest(request.Context(), requestID, grant.GrantID, service.now().UnixMilli())
	if errors.Is(err, ErrParticipantAuthority) {
		http.NotFound(writer, request)
		return
	}
	if err != nil {
		service.internalError(writer, request, "participant_request_status", err)
		return
	}
	writeJSON(writer, http.StatusOK, struct {
		RequestID             uuid.UUID `json:"requestID"`
		Decision              string    `json:"decision"`
		ExpiresAtMillis       int64     `json:"expiresAtMilliseconds"`
		DecidedAtMilliseconds int64     `json:"decidedAtMilliseconds"`
	}{status.RequestID, status.Decision, status.ExpiresAtMillis, status.DecidedAtMilliseconds})
}

func (service *Service) handleParticipantEnrollmentDecision(writer http.ResponseWriter, request *http.Request) {
	_, session, authenticated := service.webContext(request)
	if !authenticated || !service.validateCSRF(request, &session) {
		http.Error(writer, "Request rejected. Sign in as Box Owner and try again.", http.StatusBadRequest)
		return
	}
	decision := request.PathValue("decision")
	if decision != "approve" && decision != "reject" {
		http.NotFound(writer, request)
		return
	}
	requestID, err := uuid.Parse(request.PathValue("requestID"))
	if err != nil || requestID == uuid.Nil {
		http.NotFound(writer, request)
		return
	}
	state, err := service.store.State(request.Context())
	if err != nil {
		service.internalError(writer, request, "participant_request_decision_state", err)
		return
	}
	err = service.store.DecideParticipantEnrollmentRequest(request.Context(), state.BoxID,
		requestID, decision == "approve", service.now().UnixMilli())
	if errors.Is(err, ErrParticipantAuthority) {
		http.Error(writer, "PARTICIPANT-REQUEST-EXPIRED: This request is no longer pending or the device connection is unavailable. Ask the device to submit a fresh request.", http.StatusConflict)
		return
	}
	if err != nil {
		service.internalError(writer, request, "participant_request_decision", err)
		return
	}
	service.audit(request.Context(), "participant_request_decision", decision)
	http.Redirect(writer, request, service.cookiePath+"/", http.StatusSeeOther)
}
