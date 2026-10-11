package boxcontrol

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/computequeue"
	"github.com/robreuss/FacetsNode/internal/jobcustody"
)

type jobCustodyResultRetrievalFixture struct {
	jobCustodyPermitHTTPFixture
	request                  BoxJobCustodyResultRetrievalPermitRequest
	admissionRequesterDigest computequeue.Digest
}

func newJobCustodyResultRetrievalFixture(t *testing.T) jobCustodyResultRetrievalFixture {
	t.Helper()
	fixture := newJobCustodyPermitHTTPFixture(t)
	response := fixture.postPermit(
		t, fixture.requesterToken, fixture.permitRequest, nil,
	)
	if response.Code != http.StatusCreated {
		t.Fatalf("admission permit status %d: %s", response.Code, response.Body.String())
	}
	var admissionPermit jobcustody.SignedAdmissionPermit
	if err := json.Unmarshal(response.Body.Bytes(), &admissionPermit); err != nil {
		t.Fatal(err)
	}
	key, err := jobcustody.NewAdmissionPermitVerificationKey(
		fixture.worker.BoxID, fixture.service.privateKey.Public().(ed25519.PublicKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := jobcustody.NewAdmissionPermitVerifier(
		[]jobcustody.AdmissionPermitVerificationKey{key},
	)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := verifier.Verify(
		admissionPermit, fixture.permitRequest.AdmissionEnvelope,
		computequeue.Timestamp(fixture.requester.now+1),
	)
	if err != nil {
		t.Fatal(err)
	}
	request := BoxJobCustodyResultRetrievalPermitRequest{
		AdmissionPermitDigest: authorization.PermitDigest(),
		BoxID:                 fixture.worker.BoxID, DeviceID: fixture.requester.device.DeviceID,
		ExpiresAtMilliseconds: fixture.requester.now + 30_000,
		InputCapsuleID:        fixture.header.CapsuleID,
		ParticipantID:         fixture.requester.anchor.ParticipantID, PermitID: uuid.New(),
		RequestedAtMilliseconds: fixture.requester.now,
		Version:                 jobcustody.ResultRetrievalPermitVersion,
	}
	return jobCustodyResultRetrievalFixture{
		jobCustodyPermitHTTPFixture: fixture,
		request:                     request, admissionRequesterDigest: authorization.RequesterAuthorityDigest(),
	}
}

func (fixture *jobCustodyResultRetrievalFixture) postRetrievalPermit(
	t *testing.T,
	requestValue BoxJobCustodyResultRetrievalPermitRequest,
	proofValue *BoxJobCustodyResultRetrievalPermitRequest,
) *httptest.ResponseRecorder {
	t.Helper()
	issueParticipantChallengeHTTP(
		t, fixture.handler, fixture.requesterToken, &fixture.requester,
	)
	payload, err := json.Marshal(requestValue)
	if err != nil {
		t.Fatal(err)
	}
	proofPayload := payload
	if proofValue != nil {
		proofPayload, err = json.Marshal(*proofValue)
		if err != nil {
			t.Fatal(err)
		}
	}
	body, err := json.Marshal(jobCustodyResultRetrievalPermitBody{
		ChallengeID: fixture.requester.challengeID,
		Proof: signedParticipantActionProof(
			t, fixture.requester, ParticipantActionIssueJobCustodyResultRetrievalPermit,
			proofPayload,
		),
		RequestPayload: payload, Version: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(
		http.MethodPost, "/v1/job-custody/result-retrieval-permits", bytes.NewReader(body),
	)
	request.Header.Set("Authorization", "Bearer "+fixture.requesterToken)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	return response
}

func TestJobCustodyResultRetrievalPermitBindsOriginalSourceAndInput(t *testing.T) {
	fixture := newJobCustodyResultRetrievalFixture(t)
	response := fixture.postRetrievalPermit(t, fixture.request, nil)
	if response.Code != http.StatusCreated {
		t.Fatalf("retrieval permit status %d: %s", response.Code, response.Body.String())
	}
	var permit jobcustody.SignedResultRetrievalPermit
	if err := json.Unmarshal(response.Body.Bytes(), &permit); err != nil {
		t.Fatal(err)
	}
	key, err := jobcustody.NewAdmissionPermitVerificationKey(
		fixture.worker.BoxID, fixture.service.privateKey.Public().(ed25519.PublicKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := jobcustody.NewAdmissionPermitVerifier(
		[]jobcustody.AdmissionPermitVerificationKey{key},
	)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := verifier.VerifyResultRetrieval(
		permit, computequeue.Timestamp(fixture.requester.now+1),
	)
	if err != nil {
		t.Fatal(err)
	}
	payload := authorization.Payload()
	if payload.AuthorityID != fixture.request.BoxID ||
		payload.InputCapsuleID != fixture.request.InputCapsuleID ||
		payload.AdmissionPermitDigest != fixture.request.AdmissionPermitDigest ||
		payload.RequesterAuthorityDigest != fixture.admissionRequesterDigest {
		t.Fatalf("payload=%+v", payload)
	}
	if events, err := fixture.store.RecentAudit(t.Context(), 10); err != nil {
		t.Fatal(err)
	} else if len(events) == 0 || events[0].Kind != "job_custody_result_retrieval_permit" {
		t.Fatalf("missing coarse result retrieval audit: %+v", events)
	}
}

func TestJobCustodyResultRetrievalPermitRejectsProofSubstitution(t *testing.T) {
	fixture := newJobCustodyResultRetrievalFixture(t)
	signed := fixture.request
	signed.InputCapsuleID = computequeue.JobCapsuleID(uuid.NewString())
	response := fixture.postRetrievalPermit(t, fixture.request, &signed)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status %d: %s", response.Code, response.Body.String())
	}
}

func TestJobCustodyResultRetrievalPermitDoesNotReauthorizeWorkerAccess(t *testing.T) {
	fixture := newJobCustodyResultRetrievalFixture(t)
	fixture.store.mu.Lock()
	grant := fixture.store.sharedWorkerGrants[fixture.accessGrant.GrantID]
	grant.RevokedAtMilliseconds = fixture.requester.now
	fixture.store.sharedWorkerGrants[fixture.accessGrant.GrantID] = grant
	fixture.store.mu.Unlock()

	response := fixture.postRetrievalPermit(t, fixture.request, nil)
	if response.Code != http.StatusCreated {
		t.Fatalf("retrieval of an already accepted result depended on current Worker access: %d %s",
			response.Code, response.Body.String())
	}
}
