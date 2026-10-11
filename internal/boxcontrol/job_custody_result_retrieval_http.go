package boxcontrol

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/computequeue"
	"github.com/robreuss/FacetsNode/internal/jobcustody"
)

// BoxJobCustodyResultRetrievalPermitRequest is signed by the same enrolled
// source device authority that submitted the original protected Job Capsule.
// It deliberately does not repeat a Worker access grant: an already accepted
// immutable snapshot may finish after that grant expires or is revoked.
// Field declaration order is canonical sorted-key JSON.
type BoxJobCustodyResultRetrievalPermitRequest struct {
	AdmissionPermitDigest   computequeue.Digest       `json:"admissionPermitDigest"`
	BoxID                   uuid.UUID                 `json:"boxID"`
	DeviceID                uuid.UUID                 `json:"deviceID"`
	ExpiresAtMilliseconds   int64                     `json:"expiresAtMilliseconds"`
	InputCapsuleID          computequeue.JobCapsuleID `json:"inputCapsuleID"`
	ParticipantID           uuid.UUID                 `json:"participantID"`
	PermitID                uuid.UUID                 `json:"permitID"`
	RequestedAtMilliseconds int64                     `json:"requestedAtMilliseconds"`
	Version                 int                       `json:"version"`
	ConnectionGrantID       uuid.UUID                 `json:"-"`
}

func decodeJobCustodyResultRetrievalPermitRequest(
	data []byte,
	maximumBytes int,
	nowMilliseconds int64,
) (BoxJobCustodyResultRetrievalPermitRequest, error) {
	var value BoxJobCustodyResultRetrievalPermitRequest
	if strictBoundedJSON(data, &value, maximumBytes) != nil {
		return value, ErrJobCustodyRouteAuthority
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(data, canonical) || value.ConnectionGrantID != uuid.Nil ||
		value.validateAt(nowMilliseconds) != nil {
		return BoxJobCustodyResultRetrievalPermitRequest{}, ErrJobCustodyRouteAuthority
	}
	return value, nil
}

func (value BoxJobCustodyResultRetrievalPermitRequest) validateAt(nowMilliseconds int64) error {
	if value.Version != jobcustody.ResultRetrievalPermitVersion || value.BoxID == uuid.Nil ||
		value.DeviceID == uuid.Nil || value.ParticipantID == uuid.Nil || value.PermitID == uuid.Nil ||
		value.AdmissionPermitDigest.Validate() != nil || value.InputCapsuleID.Validate() != nil ||
		value.RequestedAtMilliseconds <= 0 || value.RequestedAtMilliseconds > nowMilliseconds ||
		nowMilliseconds-value.RequestedAtMilliseconds > maximumParticipantProofAgeMilliseconds ||
		value.ExpiresAtMilliseconds <= nowMilliseconds ||
		value.ExpiresAtMilliseconds-value.RequestedAtMilliseconds >
			jobcustody.MaximumAdmissionPermitLifetimeMillisecs {
		return ErrJobCustodyRouteAuthority
	}
	return nil
}

type jobCustodyResultRetrievalPermitBody struct {
	ChallengeID    uuid.UUID                       `json:"challengeID"`
	Proof          BoxSignedParticipantActionProof `json:"proof"`
	RequestPayload json.RawMessage                 `json:"requestPayload"`
	Version        int                             `json:"version"`
}

func (service *Service) handleIssueJobCustodyResultRetrievalPermit(
	writer http.ResponseWriter,
	request *http.Request,
) {
	connection, err := service.authorizeGrant(request)
	if err != nil {
		http.Error(writer, "Connection grant rejected. Reconnect this Facets installation to the Box.", http.StatusUnauthorized)
		return
	}
	var body jobCustodyResultRetrievalPermitBody
	now := service.now().UnixMilli()
	if decodeBoundedJSON(request, &body, maximumJobCustodyAdmissionPermitHTTPBytes) != nil ||
		body.Version != 1 || body.ChallengeID == uuid.Nil {
		http.Error(writer, "JOB-CUSTODY-RESULT-RETRIEVAL-PERMIT-FORMAT: The result retrieval permit request is invalid.", http.StatusBadRequest)
		return
	}
	permitRequest, err := decodeJobCustodyResultRetrievalPermitRequest(
		body.RequestPayload, maximumJobCustodyAdmissionPermitHTTPBytes, now,
	)
	if err != nil {
		http.Error(writer, "JOB-CUSTODY-RESULT-RETRIEVAL-PERMIT-FORMAT: The result retrieval permit request is invalid.", http.StatusBadRequest)
		return
	}
	verifier, err := NewBoxParticipantProofVerifier(service.store)
	if err != nil {
		service.internalError(writer, request, "job_custody_result_retrieval_permit_verifier", err)
		return
	}
	enrollment, err := verifier.AuthorizePresentedAction(
		request.Context(), body.Proof, body.ChallengeID,
		ParticipantActionIssueJobCustodyResultRetrievalPermit, body.RequestPayload, now,
	)
	if errors.Is(err, ErrParticipantAuthority) || errors.Is(err, ErrParticipantReplay) {
		http.Error(writer, "JOB-CUSTODY-RESULT-RETRIEVAL-PERMIT-AUTHORITY: The signed result retrieval request was rejected. Request a fresh challenge.", http.StatusForbidden)
		return
	}
	if err != nil {
		service.internalError(writer, request, "job_custody_result_retrieval_permit_authorize", err)
		return
	}
	if permitRequest.BoxID != enrollment.Anchor.BoxID ||
		permitRequest.ParticipantID != enrollment.Anchor.ParticipantID ||
		permitRequest.DeviceID != enrollment.Device.DeviceID ||
		connection.ExpiresAt.UnixMilli() < permitRequest.ExpiresAtMilliseconds {
		http.Error(writer, "JOB-CUSTODY-RESULT-RETRIEVAL-PERMIT-AUTHORITY: The requester does not match this source device.", http.StatusForbidden)
		return
	}
	requesterDigest, err := makeJobCustodyRequesterAuthorityDigest(enrollment)
	if err != nil {
		http.Error(writer, "JOB-CUSTODY-RESULT-RETRIEVAL-PERMIT-AUTHORITY: The source authority is no longer valid.", http.StatusForbidden)
		return
	}
	payload := jobcustody.ResultRetrievalPermitPayload{
		AdmissionPermitDigest:    permitRequest.AdmissionPermitDigest,
		AuthorityID:              permitRequest.BoxID,
		ExpiresAt:                computequeue.Timestamp(permitRequest.ExpiresAtMilliseconds),
		InputCapsuleID:           permitRequest.InputCapsuleID,
		IssuedAt:                 computequeue.Timestamp(now),
		PermitID:                 permitRequest.PermitID,
		RequesterAuthorityDigest: requesterDigest,
		Version:                  jobcustody.ResultRetrievalPermitVersion,
	}
	signer, err := jobcustody.NewResultRetrievalPermitSigner(permitRequest.BoxID, service.privateKey)
	if err != nil {
		service.internalError(writer, request, "job_custody_result_retrieval_permit_signer", err)
		return
	}
	permit, err := signer.Sign(payload)
	if err != nil {
		service.internalError(writer, request, "job_custody_result_retrieval_permit_sign", err)
		return
	}
	service.audit(request.Context(), "job_custody_result_retrieval_permit", "issued")
	writeJSON(writer, http.StatusCreated, permit)
}
