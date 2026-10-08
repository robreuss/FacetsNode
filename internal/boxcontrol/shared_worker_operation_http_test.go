package boxcontrol

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

func approveSharedWorkerAccessHTTP(
	t *testing.T,
	handler http.Handler,
	ownerToken, requesterToken string,
	owner, requester *participantFixture,
	worker BoxSharedWorkerAdvertisement,
) BoxSharedWorkerAccessGrant {
	t.Helper()
	issueParticipantChallengeHTTP(t, handler, requesterToken, requester)
	accessRequest := BoxSharedWorkerAccessRequest{
		Version: 1, RequestID: uuid.New(), BoxID: worker.BoxID, WorkerID: worker.WorkerID,
		RequesterParticipantID:  requester.anchor.ParticipantID,
		RequesterDeviceID:       requester.device.DeviceID,
		CapabilitiesDigest:      worker.CapabilitiesDigest,
		RequestedAtMilliseconds: requester.now,
		ExpiresAtMilliseconds:   requester.now + 60_000,
	}
	created := postSharedWorkerAccessRequest(t, handler, requesterToken, *requester, worker, accessRequest)
	if created.Code != http.StatusCreated {
		t.Fatalf("access request status %d: %s", created.Code, created.Body.String())
	}
	var accessResponse sharedWorkerAccessRequestResponse
	if err := json.Unmarshal(created.Body.Bytes(), &accessResponse); err != nil {
		t.Fatal(err)
	}
	codeDigest, err := SharedWorkerAccessCodeDigest(accessResponse.ConfirmationCode)
	if err != nil {
		t.Fatal(err)
	}
	grant := BoxSharedWorkerAccessGrant{
		Version: 1, GrantID: uuid.New(), RequestID: accessRequest.RequestID,
		BoxID: worker.BoxID, WorkerID: worker.WorkerID,
		OwnerParticipantID:     owner.anchor.ParticipantID,
		OwnerDeviceID:          owner.device.DeviceID,
		GranteeParticipantID:   requester.anchor.ParticipantID,
		CapabilitiesDigest:     worker.CapabilitiesDigest,
		ConfirmationCodeDigest: sharedWorkerAccessCodeDigestString(codeDigest), Revision: 1,
		GrantedAtMilliseconds: owner.now,
		ExpiresAtMilliseconds: owner.now + 24*60*60*1000,
	}
	issueParticipantChallengeHTTP(t, handler, ownerToken, owner)
	approved := postSharedWorkerAccessGrant(
		t, handler, ownerToken, *owner, grant, accessResponse.ConfirmationCode,
	)
	if approved.Code != http.StatusCreated {
		t.Fatalf("access grant status %d: %s", approved.Code, approved.Body.String())
	}
	return grant
}

func postSharedWorkerOperationPayload(
	t *testing.T,
	handler http.Handler,
	method, path, token string,
	body any,
) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(encoded))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestSharedWorkerOperationHTTPRoundTripPreservesOpaqueBytes(t *testing.T) {
	owner, requester, _, handler, ownerToken, requesterToken, worker := sharedWorkerAccessHTTPFixture(t)
	grant := approveSharedWorkerAccessHTTP(
		t, handler, ownerToken, requesterToken, &owner, &requester, worker,
	)

	requestBytes := bytes.Repeat([]byte{0x91, 0x22, 0x00, 0xff}, 96*1024)
	operation := BoxSharedWorkerOperation{
		Version: 1, OperationID: uuid.New(), BoxID: worker.BoxID,
		WorkerID: worker.WorkerID, AccessGrantID: grant.GrantID,
		RequesterParticipantID: requester.anchor.ParticipantID,
		RequesterDeviceID:      requester.device.DeviceID,
		JobID:                  uuid.New(), RunID: uuid.New(), Attempt: 1,
		CapabilitiesDigest: worker.CapabilitiesDigest,
		RequestDigest:      SharedWorkerOperationDigest(requestBytes), RequestBytes: requestBytes,
		RequestedAtMilliseconds: requester.now,
		ExpiresAtMilliseconds:   requester.now + 60_000,
	}
	operationPayload, err := json.Marshal(operation)
	if err != nil {
		t.Fatal(err)
	}
	issueParticipantChallengeHTTP(t, handler, requesterToken, &requester)
	enqueued := postSharedWorkerOperationPayload(t, handler, http.MethodPost,
		"/v1/shared-workers/"+worker.WorkerID.String()+"/operations", requesterToken,
		sharedWorkerOperationEnqueueBody{
			Version: 1, OperationPayload: operationPayload, ChallengeID: requester.challengeID,
			Proof: signedParticipantActionProof(
				t, requester, ParticipantActionEnqueueWorkerOperation, operationPayload,
			),
		})
	if enqueued.Code != http.StatusCreated {
		t.Fatalf("enqueue status %d: %s", enqueued.Code, enqueued.Body.String())
	}

	claim := BoxSharedWorkerOperationClaim{
		Version: 1, ClaimID: uuid.New(), BoxID: worker.BoxID, WorkerID: worker.WorkerID,
		OwnerParticipantID: owner.anchor.ParticipantID, OwnerDeviceID: owner.device.DeviceID,
		RequestedAtMilliseconds: owner.now, ExpiresAtMilliseconds: owner.now + 30_000,
	}
	claimPayload, err := json.Marshal(claim)
	if err != nil {
		t.Fatal(err)
	}
	issueParticipantChallengeHTTP(t, handler, ownerToken, &owner)
	claimed := postSharedWorkerOperationPayload(t, handler, http.MethodPost,
		"/v1/shared-workers/"+worker.WorkerID.String()+"/operation-claims", ownerToken,
		sharedWorkerOperationClaimBody{
			Version: 1, ClaimPayload: claimPayload, ChallengeID: owner.challengeID,
			Proof: signedParticipantActionProof(
				t, owner, ParticipantActionClaimWorkerOperation, claimPayload,
			),
		})
	if claimed.Code != http.StatusOK {
		t.Fatalf("claim status %d: %s", claimed.Code, claimed.Body.String())
	}
	var assignment sharedWorkerOperationAssignment
	if err := json.Unmarshal(claimed.Body.Bytes(), &assignment); err != nil {
		t.Fatal(err)
	}
	if assignment.ClaimID != claim.ClaimID || assignment.Operation.OperationID != operation.OperationID ||
		!bytes.Equal(assignment.Operation.RequestBytes, requestBytes) {
		t.Fatalf("claimed operation changed: %+v", assignment)
	}

	responseBytes := bytes.Repeat([]byte{0x44, 0x00, 0xac}, 64*1024)
	operationResponse := BoxSharedWorkerOperationResponse{
		Version: 1, OperationID: operation.OperationID, ClaimID: claim.ClaimID,
		BoxID: worker.BoxID, WorkerID: worker.WorkerID,
		OwnerParticipantID: owner.anchor.ParticipantID, OwnerDeviceID: owner.device.DeviceID,
		ResponseDigest: SharedWorkerOperationDigest(responseBytes), ResponseBytes: responseBytes,
		RespondedAtMilliseconds: owner.now,
	}
	responsePayload, err := json.Marshal(operationResponse)
	if err != nil {
		t.Fatal(err)
	}
	postResponse := func(payload []byte) *httptest.ResponseRecorder {
		issueParticipantChallengeHTTP(t, handler, ownerToken, &owner)
		return postSharedWorkerOperationPayload(t, handler, http.MethodPost,
			"/v1/shared-worker-operations/"+operation.OperationID.String()+"/response", ownerToken,
			sharedWorkerOperationResponseBody{
				Version: 1, ResponsePayload: payload, ChallengeID: owner.challengeID,
				Proof: signedParticipantActionProof(
					t, owner, ParticipantActionRespondWorkerOperation, payload,
				),
			})
	}
	completed := postResponse(responsePayload)
	if completed.Code != http.StatusNoContent {
		t.Fatalf("response status %d: %s", completed.Code, completed.Body.String())
	}
	if retried := postResponse(responsePayload); retried.Code != http.StatusNoContent {
		t.Fatalf("exact response retry status %d: %s", retried.Code, retried.Body.String())
	}

	statusRequest := httptest.NewRequest(http.MethodGet,
		"/v1/shared-worker-operations/"+operation.OperationID.String(), nil)
	statusRequest.Header.Set("Authorization", "Bearer "+requesterToken)
	statusResponse := httptest.NewRecorder()
	handler.ServeHTTP(statusResponse, statusRequest)
	if statusResponse.Code != http.StatusOK {
		t.Fatalf("status code %d: %s", statusResponse.Code, statusResponse.Body.String())
	}
	var status BoxSharedWorkerOperationStatus
	if err := json.Unmarshal(statusResponse.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.State != SharedWorkerOperationResponseReady || status.Response == nil ||
		!bytes.Equal(status.Response.ResponseBytes, responseBytes) {
		t.Fatalf("response bytes changed: %+v", status)
	}

	otherStatus := httptest.NewRequest(http.MethodGet,
		"/v1/shared-worker-operations/"+operation.OperationID.String(), nil)
	otherStatus.Header.Set("Authorization", "Bearer "+ownerToken)
	otherResponse := httptest.NewRecorder()
	handler.ServeHTTP(otherResponse, otherStatus)
	if otherResponse.Code != http.StatusNotFound {
		t.Fatalf("other connection read status %d: %s", otherResponse.Code, otherResponse.Body.String())
	}
}

func TestSharedWorkerOperationHTTPRejectsSignedPayloadSubstitution(t *testing.T) {
	owner, requester, _, handler, ownerToken, requesterToken, worker := sharedWorkerAccessHTTPFixture(t)
	grant := approveSharedWorkerAccessHTTP(
		t, handler, ownerToken, requesterToken, &owner, &requester, worker,
	)
	operation := BoxSharedWorkerOperation{
		Version: 1, OperationID: uuid.New(), BoxID: worker.BoxID, WorkerID: worker.WorkerID,
		AccessGrantID: grant.GrantID, RequesterParticipantID: requester.anchor.ParticipantID,
		RequesterDeviceID: requester.device.DeviceID, JobID: uuid.New(), RunID: uuid.New(), Attempt: 1,
		CapabilitiesDigest: worker.CapabilitiesDigest, RequestBytes: []byte("original"),
		RequestedAtMilliseconds: requester.now, ExpiresAtMilliseconds: requester.now + 60_000,
	}
	operation.RequestDigest = SharedWorkerOperationDigest(operation.RequestBytes)
	signedPayload, _ := json.Marshal(operation)
	operation.RequestBytes = []byte("substituted")
	operation.RequestDigest = SharedWorkerOperationDigest(operation.RequestBytes)
	substitutedPayload, _ := json.Marshal(operation)
	issueParticipantChallengeHTTP(t, handler, requesterToken, &requester)
	response := postSharedWorkerOperationPayload(t, handler, http.MethodPost,
		"/v1/shared-workers/"+worker.WorkerID.String()+"/operations", requesterToken,
		sharedWorkerOperationEnqueueBody{
			Version: 1, OperationPayload: substitutedPayload, ChallengeID: requester.challengeID,
			Proof: signedParticipantActionProof(
				t, requester, ParticipantActionEnqueueWorkerOperation, signedPayload,
			),
		})
	if response.Code != http.StatusForbidden {
		t.Fatalf("substituted operation status %d: %s", response.Code, response.Body.String())
	}
}
