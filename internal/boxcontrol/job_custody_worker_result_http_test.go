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

type jobCustodyWorkerResultPermitFixture struct {
	owner   participantFixture
	store   *MemoryStore
	service *Service
	handler http.Handler
	token   string
	worker  BoxSharedWorkerAdvertisement
	request BoxJobCustodyWorkerResultPermitRequest
}

func newJobCustodyWorkerResultPermitFixture(t *testing.T) jobCustodyWorkerResultPermitFixture {
	t.Helper()
	owner, store, service, token := sharedWorkerHTTPFixture(t)
	handler := service.Handler()
	issueParticipantChallengeHTTP(t, handler, token, &owner)
	worker := sharedWorkerAdvertisement(owner)
	if response := advertiseSharedWorkerHTTP(t, handler, token, owner, worker, worker); response.Code != http.StatusCreated {
		t.Fatalf("advertisement status %d: %s", response.Code, response.Body.String())
	}
	descriptor, err := computequeue.NewJobCapsuleProtectedObjectDescriptor(
		4096, computequeue.SHA256Digest("box-worker-result", "protected"), 1024,
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := jobcustody.NewWorkerResultHeader(
		computequeue.AssignmentID(uuid.New().String()), uuid.New(),
		computequeue.JobCapsuleID(uuid.New().String()),
		computequeue.JobCapsuleID(uuid.New().String()), descriptor,
		computequeue.SHA256Digest("box-worker-result", "result-set"),
		computequeue.SHA256Digest("box-worker-result", "execution-receipt"),
		computequeue.Timestamp(owner.now+120_000),
	)
	if err != nil {
		t.Fatal(err)
	}
	request := BoxJobCustodyWorkerResultPermitRequest{
		BoxID: worker.BoxID, CapabilitiesDigest: worker.CapabilitiesDigest,
		DeviceID: owner.device.DeviceID, ExpiresAtMilliseconds: owner.now + 30_000,
		ParticipantID: owner.anchor.ParticipantID, PermitID: uuid.New(),
		RequestedAtMilliseconds: owner.now, Result: result,
		RouteRecipientKeyFingerprint: computequeue.SHA256Digest(
			"box-worker-result", "recipient-key",
		),
		Version: jobcustody.WorkerResultPermitVersion, WorkerID: worker.WorkerID,
	}
	return jobCustodyWorkerResultPermitFixture{
		owner: owner, store: store, service: service, handler: handler,
		token: token, worker: worker, request: request,
	}
}

func (fixture *jobCustodyWorkerResultPermitFixture) post(
	t *testing.T,
	requestValue BoxJobCustodyWorkerResultPermitRequest,
	proofValue *BoxJobCustodyWorkerResultPermitRequest,
) *httptest.ResponseRecorder {
	t.Helper()
	issueParticipantChallengeHTTP(t, fixture.handler, fixture.token, &fixture.owner)
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
	body, err := json.Marshal(jobCustodyWorkerResultPermitBody{
		ChallengeID: fixture.owner.challengeID,
		Proof: signedParticipantActionProof(
			t, fixture.owner, ParticipantActionIssueJobCustodyWorkerResultPermit, proofPayload,
		),
		RequestPayload: payload, Version: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(
		http.MethodPost, "/v1/job-custody/worker-result-permits", bytes.NewReader(body),
	)
	request.Header.Set("Authorization", "Bearer "+fixture.token)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	return response
}

func TestJobCustodyWorkerResultPermitBindsCurrentOwnerCapabilityAndResult(t *testing.T) {
	fixture := newJobCustodyWorkerResultPermitFixture(t)
	response := fixture.post(t, fixture.request, nil)
	if response.Code != http.StatusCreated {
		t.Fatalf("permit status %d: %s", response.Code, response.Body.String())
	}
	var permit jobcustody.SignedWorkerResultPermit
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
	authorization, err := verifier.VerifyWorkerResult(
		permit, computequeue.Timestamp(fixture.owner.now+1),
	)
	if err != nil {
		t.Fatal(err)
	}
	payload := authorization.Payload()
	if payload.AuthorityID != fixture.worker.BoxID || payload.Result != fixture.request.Result ||
		payload.RouteRecipientWorkerID != computequeue.WorkerID(fixture.worker.WorkerID.String()) ||
		payload.RouteRecipientKeyFingerprint != fixture.request.RouteRecipientKeyFingerprint ||
		payload.WorkerCapabilitiesDigest != computequeue.Digest(fixture.worker.CapabilitiesDigest) ||
		payload.WorkerOwnerAuthorityDigest.Validate() != nil {
		t.Fatalf("payload=%+v", payload)
	}
	if events, err := fixture.store.RecentAudit(t.Context(), 10); err != nil {
		t.Fatal(err)
	} else if len(events) == 0 || events[0].Kind != "job_custody_worker_result_permit" {
		t.Fatalf("missing coarse Worker result audit: %+v", events)
	}
}

func TestJobCustodyWorkerResultPermitRejectsProofAndResultSubstitution(t *testing.T) {
	t.Run("proof payload", func(t *testing.T) {
		fixture := newJobCustodyWorkerResultPermitFixture(t)
		signed := fixture.request
		signed.Result.ResultCapsuleID = computequeue.JobCapsuleID(uuid.New().String())
		signed.Result.IdempotencyKey = signed.Result.MakeIdempotencyKey()
		response := fixture.post(t, fixture.request, &signed)
		if response.Code != http.StatusForbidden {
			t.Fatalf("status %d: %s", response.Code, response.Body.String())
		}
	})

	t.Run("capability digest", func(t *testing.T) {
		fixture := newJobCustodyWorkerResultPermitFixture(t)
		changed := fixture.request
		changed.CapabilitiesDigest = string(computequeue.SHA256Digest("changed", "capabilities"))
		response := fixture.post(t, changed, nil)
		if response.Code != http.StatusConflict {
			t.Fatalf("status %d: %s", response.Code, response.Body.String())
		}
	})
}
