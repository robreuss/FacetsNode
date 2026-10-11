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

func TestJobCustodyResultMutationPermitBindsOriginalSourceExactResultAndAction(t *testing.T) {
	fixture := newJobCustodyResultRetrievalFixture(t)
	requestValue := BoxJobCustodyResultMutationPermitRequest{
		Action:                jobcustody.ResultMutationAcknowledgeDelivery,
		AdmissionPermitDigest: fixture.request.AdmissionPermitDigest,
		BoxID:                 fixture.request.BoxID, DeviceID: fixture.request.DeviceID,
		ExpiresAtMilliseconds: fixture.request.ExpiresAtMilliseconds,
		InputCapsuleID:        fixture.request.InputCapsuleID,
		ParticipantID:         fixture.request.ParticipantID, PermitID: uuid.New(),
		RequestedAtMilliseconds:       fixture.request.RequestedAtMilliseconds,
		ResultCapsuleID:               computequeue.JobCapsuleID(uuid.NewString()),
		ResultCustodyReceiptDigest:    computequeue.SHA256Digest("result-mutation-http", "custody"),
		ResultSetDigest:               computequeue.SHA256Digest("result-mutation-http", "result-set"),
		SourceTransitionReceiptDigest: computequeue.SHA256Digest("result-mutation-http", "source-delivered"),
		Version:                       jobcustody.ResultMutationPermitVersion,
	}
	response := postJobCustodyResultMutationPermit(t, &fixture, requestValue, nil)
	if response.Code != http.StatusCreated {
		t.Fatalf("mutation permit status %d: %s", response.Code, response.Body.String())
	}
	var permit jobcustody.SignedResultMutationPermit
	if err := json.Unmarshal(response.Body.Bytes(), &permit); err != nil {
		t.Fatal(err)
	}
	key, _ := jobcustody.NewAdmissionPermitVerificationKey(
		fixture.worker.BoxID, fixture.service.privateKey.Public().(ed25519.PublicKey),
	)
	verifier, _ := jobcustody.NewAdmissionPermitVerifier(
		[]jobcustody.AdmissionPermitVerificationKey{key},
	)
	authorization, err := verifier.VerifyResultMutation(
		permit, computequeue.Timestamp(fixture.requester.now+1),
	)
	if err != nil {
		t.Fatal(err)
	}
	payload := authorization.Payload()
	if payload.Action != requestValue.Action || payload.AuthorityID != requestValue.BoxID ||
		payload.InputCapsuleID != requestValue.InputCapsuleID ||
		payload.ResultCapsuleID != requestValue.ResultCapsuleID ||
		payload.ResultCustodyReceiptDigest != requestValue.ResultCustodyReceiptDigest ||
		payload.SourceTransitionReceiptDigest != requestValue.SourceTransitionReceiptDigest ||
		payload.RequesterAuthorityDigest != fixture.admissionRequesterDigest {
		t.Fatalf("payload=%+v", payload)
	}
	if events, err := fixture.store.RecentAudit(t.Context(), 10); err != nil {
		t.Fatal(err)
	} else if len(events) == 0 || events[0].Kind != "job_custody_result_mutation_permit" {
		t.Fatalf("missing coarse result mutation audit: %+v", events)
	}
}

func TestJobCustodyResultMutationPermitRejectsProofSubstitution(t *testing.T) {
	fixture := newJobCustodyResultRetrievalFixture(t)
	requestValue := BoxJobCustodyResultMutationPermitRequest{
		Action:                jobcustody.ResultMutationReleaseCustody,
		AdmissionPermitDigest: fixture.request.AdmissionPermitDigest,
		BoxID:                 fixture.request.BoxID, DeviceID: fixture.request.DeviceID,
		ExpiresAtMilliseconds: fixture.request.ExpiresAtMilliseconds,
		InputCapsuleID:        fixture.request.InputCapsuleID,
		ParticipantID:         fixture.request.ParticipantID, PermitID: uuid.New(),
		RequestedAtMilliseconds:       fixture.request.RequestedAtMilliseconds,
		ResultCapsuleID:               computequeue.JobCapsuleID(uuid.NewString()),
		ResultCustodyReceiptDigest:    computequeue.SHA256Digest("result-mutation-http", "custody"),
		ResultSetDigest:               computequeue.SHA256Digest("result-mutation-http", "result-set"),
		SourceTransitionReceiptDigest: computequeue.SHA256Digest("result-mutation-http", "source-release"),
		Version:                       jobcustody.ResultMutationPermitVersion,
	}
	signed := requestValue
	signed.Action = jobcustody.ResultMutationAcknowledgeDelivery
	response := postJobCustodyResultMutationPermit(t, &fixture, requestValue, &signed)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status %d: %s", response.Code, response.Body.String())
	}
}

func postJobCustodyResultMutationPermit(
	t *testing.T,
	fixture *jobCustodyResultRetrievalFixture,
	requestValue BoxJobCustodyResultMutationPermitRequest,
	proofValue *BoxJobCustodyResultMutationPermitRequest,
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
	body, err := json.Marshal(jobCustodyResultMutationPermitBody{
		ChallengeID: fixture.requester.challengeID,
		Proof: signedParticipantActionProof(
			t, fixture.requester, ParticipantActionIssueJobCustodyResultMutationPermit,
			proofPayload,
		),
		RequestPayload: payload, Version: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(
		http.MethodPost, "/v1/job-custody/result-mutation-permits", bytes.NewReader(body),
	)
	request.Header.Set("Authorization", "Bearer "+fixture.requesterToken)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	return response
}
