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

// BoxJobCustodyResultMutationPermitRequest is signed by the enrolled source
// device that submitted the original protected input. The Box authenticates
// the source action but does not interpret the source lifecycle receipt whose
// digest is carried here.
// Field declaration order is canonical sorted-key JSON.
type BoxJobCustodyResultMutationPermitRequest struct {
	Action                        jobcustody.ResultMutationAction `json:"action"`
	AdmissionPermitDigest         computequeue.Digest             `json:"admissionPermitDigest"`
	BoxID                         uuid.UUID                       `json:"boxID"`
	DeviceID                      uuid.UUID                       `json:"deviceID"`
	ExpiresAtMilliseconds         int64                           `json:"expiresAtMilliseconds"`
	InputCapsuleID                computequeue.JobCapsuleID       `json:"inputCapsuleID"`
	ParticipantID                 uuid.UUID                       `json:"participantID"`
	PermitID                      uuid.UUID                       `json:"permitID"`
	RequestedAtMilliseconds       int64                           `json:"requestedAtMilliseconds"`
	ResultCapsuleID               computequeue.JobCapsuleID       `json:"resultCapsuleID"`
	ResultCustodyReceiptDigest    computequeue.Digest             `json:"resultCustodyReceiptDigest"`
	ResultSetDigest               computequeue.Digest             `json:"resultSetDigest"`
	SourceTransitionReceiptDigest computequeue.Digest             `json:"sourceTransitionReceiptDigest"`
	Version                       int                             `json:"version"`
	ConnectionGrantID             uuid.UUID                       `json:"-"`
}

func decodeJobCustodyResultMutationPermitRequest(
	data []byte,
	maximumBytes int,
	nowMilliseconds int64,
) (BoxJobCustodyResultMutationPermitRequest, error) {
	var value BoxJobCustodyResultMutationPermitRequest
	if strictBoundedJSON(data, &value, maximumBytes) != nil {
		return value, ErrJobCustodyRouteAuthority
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(data, canonical) || value.ConnectionGrantID != uuid.Nil ||
		value.validateAt(nowMilliseconds) != nil {
		return BoxJobCustodyResultMutationPermitRequest{}, ErrJobCustodyRouteAuthority
	}
	return value, nil
}

func (value BoxJobCustodyResultMutationPermitRequest) validateAt(nowMilliseconds int64) error {
	issuedAt := computequeue.Timestamp(value.RequestedAtMilliseconds)
	expiresAt := computequeue.Timestamp(value.ExpiresAtMilliseconds)
	if value.Version != jobcustody.ResultMutationPermitVersion || value.Action.Validate() != nil ||
		value.BoxID == uuid.Nil || value.DeviceID == uuid.Nil || value.ParticipantID == uuid.Nil ||
		value.PermitID == uuid.Nil || value.AdmissionPermitDigest.Validate() != nil ||
		value.InputCapsuleID.Validate() != nil || value.ResultCapsuleID.Validate() != nil ||
		value.InputCapsuleID == value.ResultCapsuleID ||
		value.ResultCustodyReceiptDigest.Validate() != nil || value.ResultSetDigest.Validate() != nil ||
		value.SourceTransitionReceiptDigest.Validate() != nil ||
		issuedAt.Validate() != nil || expiresAt.Validate() != nil || issuedAt >= expiresAt ||
		value.ExpiresAtMilliseconds-value.RequestedAtMilliseconds > jobcustody.MaximumAdmissionPermitLifetimeMillisecs ||
		value.RequestedAtMilliseconds <= 0 || value.RequestedAtMilliseconds > nowMilliseconds ||
		nowMilliseconds-value.RequestedAtMilliseconds > maximumParticipantProofAgeMilliseconds ||
		value.ExpiresAtMilliseconds <= nowMilliseconds {
		return ErrJobCustodyRouteAuthority
	}
	return nil
}

type jobCustodyResultMutationPermitBody struct {
	ChallengeID    uuid.UUID                       `json:"challengeID"`
	Proof          BoxSignedParticipantActionProof `json:"proof"`
	RequestPayload json.RawMessage                 `json:"requestPayload"`
	Version        int                             `json:"version"`
}

func (service *Service) handleIssueJobCustodyResultMutationPermit(
	writer http.ResponseWriter,
	request *http.Request,
) {
	connection, err := service.authorizeGrant(request)
	if err != nil {
		http.Error(writer, "Connection grant rejected. Reconnect this Facets installation to the Box.", http.StatusUnauthorized)
		return
	}
	var body jobCustodyResultMutationPermitBody
	now := service.now().UnixMilli()
	if decodeBoundedJSON(request, &body, maximumJobCustodyAdmissionPermitHTTPBytes) != nil ||
		body.Version != 1 || body.ChallengeID == uuid.Nil {
		http.Error(writer, "JOB-CUSTODY-RESULT-MUTATION-PERMIT-FORMAT: The result mutation permit request is invalid.", http.StatusBadRequest)
		return
	}
	permitRequest, err := decodeJobCustodyResultMutationPermitRequest(
		body.RequestPayload, maximumJobCustodyAdmissionPermitHTTPBytes, now,
	)
	if err != nil {
		http.Error(writer, "JOB-CUSTODY-RESULT-MUTATION-PERMIT-FORMAT: The result mutation permit request is invalid.", http.StatusBadRequest)
		return
	}
	verifier, err := NewBoxParticipantProofVerifier(service.store)
	if err != nil {
		service.internalError(writer, request, "job_custody_result_mutation_permit_verifier", err)
		return
	}
	enrollment, err := verifier.AuthorizePresentedAction(
		request.Context(), body.Proof, body.ChallengeID,
		ParticipantActionIssueJobCustodyResultMutationPermit, body.RequestPayload, now,
	)
	if errors.Is(err, ErrParticipantAuthority) || errors.Is(err, ErrParticipantReplay) {
		http.Error(writer, "JOB-CUSTODY-RESULT-MUTATION-PERMIT-AUTHORITY: The signed result mutation request was rejected. Request a fresh challenge.", http.StatusForbidden)
		return
	}
	if err != nil {
		service.internalError(writer, request, "job_custody_result_mutation_permit_authorize", err)
		return
	}
	if permitRequest.BoxID != enrollment.Anchor.BoxID ||
		permitRequest.ParticipantID != enrollment.Anchor.ParticipantID ||
		permitRequest.DeviceID != enrollment.Device.DeviceID ||
		connection.ExpiresAt.UnixMilli() < permitRequest.ExpiresAtMilliseconds {
		http.Error(writer, "JOB-CUSTODY-RESULT-MUTATION-PERMIT-AUTHORITY: The requester does not match this source device.", http.StatusForbidden)
		return
	}
	requesterDigest, err := makeJobCustodyRequesterAuthorityDigest(enrollment)
	if err != nil {
		http.Error(writer, "JOB-CUSTODY-RESULT-MUTATION-PERMIT-AUTHORITY: The source authority is no longer valid.", http.StatusForbidden)
		return
	}
	payload := jobcustody.ResultMutationPermitPayload{
		Action: permitRequest.Action, AdmissionPermitDigest: permitRequest.AdmissionPermitDigest,
		AuthorityID:    permitRequest.BoxID,
		ExpiresAt:      computequeue.Timestamp(permitRequest.ExpiresAtMilliseconds),
		InputCapsuleID: permitRequest.InputCapsuleID, IssuedAt: computequeue.Timestamp(now),
		PermitID: permitRequest.PermitID, RequesterAuthorityDigest: requesterDigest,
		ResultCapsuleID:               permitRequest.ResultCapsuleID,
		ResultCustodyReceiptDigest:    permitRequest.ResultCustodyReceiptDigest,
		ResultSetDigest:               permitRequest.ResultSetDigest,
		SourceTransitionReceiptDigest: permitRequest.SourceTransitionReceiptDigest,
		Version:                       jobcustody.ResultMutationPermitVersion,
	}
	signer, err := jobcustody.NewResultMutationPermitSigner(permitRequest.BoxID, service.privateKey)
	if err != nil {
		service.internalError(writer, request, "job_custody_result_mutation_permit_signer", err)
		return
	}
	permit, err := signer.Sign(payload)
	if err != nil {
		service.internalError(writer, request, "job_custody_result_mutation_permit_sign", err)
		return
	}
	service.audit(request.Context(), "job_custody_result_mutation_permit", "issued")
	writeJSON(writer, http.StatusCreated, permit)
}
