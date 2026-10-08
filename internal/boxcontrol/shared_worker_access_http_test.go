package boxcontrol

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

func addSharedWorkerAccessParticipant(
	t *testing.T,
	store *MemoryStore,
	boxID uuid.UUID,
	now int64,
	deviceName string,
) (participantFixture, string) {
	t.Helper()
	fixture := newParticipantFixture(t)
	fixture.anchor.BoxID = boxID
	fixture.now = now
	if err := store.PinOwnerApprovedParticipant(context.Background(), BoxParticipantEnrollment{
		Anchor: fixture.anchor, Device: fixture.device,
		RootRecord: fixture.root, GrantRecord: fixture.grant,
	}, now); err != nil {
		t.Fatal(err)
	}
	token, digest, err := RandomToken(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateGrant(context.Background(), ConnectionGrant{
		GrantID: uuid.New(), TokenDigest: digest, DeviceName: deviceName,
		CreatedAt: time.UnixMilli(now), LastSeenAt: time.UnixMilli(now),
		ExpiresAt: time.UnixMilli(now).Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	return fixture, token
}

func sharedWorkerAccessHTTPFixture(
	t *testing.T,
) (participantFixture, participantFixture, *MemoryStore, http.Handler, string, string, BoxSharedWorkerAdvertisement) {
	t.Helper()
	owner, store, service, ownerToken := sharedWorkerHTTPFixture(t)
	requester, requesterToken := addSharedWorkerAccessParticipant(
		t, store, owner.anchor.BoxID, owner.now, "Requester Mac",
	)
	handler := service.Handler()
	issueParticipantChallengeHTTP(t, handler, ownerToken, &owner)
	worker := sharedWorkerAdvertisement(owner)
	if response := advertiseSharedWorkerHTTP(t, handler, ownerToken, owner, worker, worker); response.Code != http.StatusCreated {
		t.Fatalf("advertisement status %d: %s", response.Code, response.Body.String())
	}
	return owner, requester, store, handler, ownerToken, requesterToken, worker
}

func postSharedWorkerAccessRequest(
	t *testing.T,
	handler http.Handler,
	token string,
	fixture participantFixture,
	worker BoxSharedWorkerAdvertisement,
	accessRequest BoxSharedWorkerAccessRequest,
) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := json.Marshal(accessRequest)
	if err != nil {
		t.Fatal(err)
	}
	proof := signedParticipantActionProof(
		t, fixture, ParticipantActionRequestWorkerAccess, payload,
	)
	body, err := json.Marshal(sharedWorkerAccessRequestBody{
		Version: 1, RequestPayload: payload,
		ChallengeID: fixture.challengeID, Proof: proof,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost,
		"/v1/shared-workers/"+worker.WorkerID.String()+"/access-requests",
		bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func postSharedWorkerAccessGrant(
	t *testing.T,
	handler http.Handler,
	token string,
	fixture participantFixture,
	grant BoxSharedWorkerAccessGrant,
	code string,
) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}
	proof := signedParticipantActionProof(
		t, fixture, ParticipantActionGrantWorkerAccess, payload,
	)
	body, err := json.Marshal(sharedWorkerAccessGrantBody{
		Version: 1, GrantPayload: payload, ConfirmationCode: code,
		ChallengeID: fixture.challengeID, Proof: proof,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost,
		"/v1/shared-workers/"+grant.WorkerID.String()+"/access-grants",
		bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestSharedWorkerAccessHTTPRequiresIndependentOwnerConfirmation(t *testing.T) {
	owner, requester, store, handler, ownerToken, requesterToken, worker := sharedWorkerAccessHTTPFixture(t)
	issueParticipantChallengeHTTP(t, handler, requesterToken, &requester)
	accessRequest := BoxSharedWorkerAccessRequest{
		Version: 1, RequestID: uuid.New(), BoxID: worker.BoxID, WorkerID: worker.WorkerID,
		RequesterParticipantID:  requester.anchor.ParticipantID,
		RequesterDeviceID:       requester.device.DeviceID,
		CapabilitiesDigest:      worker.CapabilitiesDigest,
		RequestedAtMilliseconds: requester.now,
		ExpiresAtMilliseconds:   requester.now + 60_000,
	}
	created := postSharedWorkerAccessRequest(t, handler, requesterToken, requester, worker, accessRequest)
	if created.Code != http.StatusCreated {
		t.Fatalf("access request status %d: %s", created.Code, created.Body.String())
	}
	var response sharedWorkerAccessRequestResponse
	if err := json.Unmarshal(created.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.RequestID != accessRequest.RequestID || len(response.ConfirmationCode) != ApprovalCodeDigits {
		t.Fatalf("access response: %+v", response)
	}
	if grants := store.activeSharedWorkerAccessGrants(requester.anchor.ParticipantID, owner.now); len(grants) != 0 {
		t.Fatalf("request alone created access: %+v", grants)
	}

	codeDigest, err := SharedWorkerAccessCodeDigest(response.ConfirmationCode)
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

	issueParticipantChallengeHTTP(t, handler, requesterToken, &requester)
	wrongOwner := postSharedWorkerAccessGrant(t, handler, requesterToken, requester, grant, response.ConfirmationCode)
	if wrongOwner.Code != http.StatusForbidden {
		t.Fatalf("requester self-approved status %d: %s", wrongOwner.Code, wrongOwner.Body.String())
	}

	issueParticipantChallengeHTTP(t, handler, ownerToken, &owner)
	approved := postSharedWorkerAccessGrant(t, handler, ownerToken, owner, grant, response.ConfirmationCode)
	if approved.Code != http.StatusCreated {
		t.Fatalf("owner grant status %d: %s", approved.Code, approved.Body.String())
	}
	if grants := store.activeSharedWorkerAccessGrants(requester.anchor.ParticipantID, owner.now); len(grants) != 1 || grants[0].GrantID != grant.GrantID {
		t.Fatalf("approved grants: %+v", grants)
	}

	statusRequest := httptest.NewRequest(http.MethodGet,
		"/v1/shared-worker-access-requests/"+accessRequest.RequestID.String(), nil)
	statusRequest.Header.Set("Authorization", "Bearer "+requesterToken)
	statusResponse := httptest.NewRecorder()
	handler.ServeHTTP(statusResponse, statusRequest)
	if statusResponse.Code != http.StatusOK ||
		!bytes.Contains(statusResponse.Body.Bytes(), []byte(`"decision":"approved"`)) {
		t.Fatalf("requester status %d: %s", statusResponse.Code, statusResponse.Body.String())
	}
	otherStatus := httptest.NewRequest(http.MethodGet,
		"/v1/shared-worker-access-requests/"+accessRequest.RequestID.String(), nil)
	otherStatus.Header.Set("Authorization", "Bearer "+ownerToken)
	otherResponse := httptest.NewRecorder()
	handler.ServeHTTP(otherResponse, otherStatus)
	if otherResponse.Code != http.StatusNotFound {
		t.Fatalf("other connection read status %d: %s", otherResponse.Code, otherResponse.Body.String())
	}
}

func TestSharedWorkerAccessHTTPRejectsPayloadSubstitution(t *testing.T) {
	_, requester, _, handler, _, requesterToken, worker := sharedWorkerAccessHTTPFixture(t)
	issueParticipantChallengeHTTP(t, handler, requesterToken, &requester)
	accessRequest := BoxSharedWorkerAccessRequest{
		Version: 1, RequestID: uuid.New(), BoxID: worker.BoxID, WorkerID: worker.WorkerID,
		RequesterParticipantID: requester.anchor.ParticipantID,
		RequesterDeviceID:      requester.device.DeviceID, CapabilitiesDigest: worker.CapabilitiesDigest,
		RequestedAtMilliseconds: requester.now, ExpiresAtMilliseconds: requester.now + 60_000,
	}
	signed := accessRequest
	signed.RequestID = uuid.New()
	payload, err := json.Marshal(accessRequest)
	if err != nil {
		t.Fatal(err)
	}
	signedPayload, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(sharedWorkerAccessRequestBody{
		Version: 1, RequestPayload: payload, ChallengeID: requester.challengeID,
		Proof: signedParticipantActionProof(t, requester, ParticipantActionRequestWorkerAccess, signedPayload),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost,
		"/v1/shared-workers/"+worker.WorkerID.String()+"/access-requests", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+requesterToken)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("substituted request status %d: %s", response.Code, response.Body.String())
	}
}
