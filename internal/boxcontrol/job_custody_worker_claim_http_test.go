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

type jobCustodyWorkerClaimPermitFixture struct {
	owner   participantFixture
	store   *MemoryStore
	service *Service
	handler http.Handler
	token   string
	worker  BoxSharedWorkerAdvertisement
	request BoxJobCustodyWorkerClaimPermitRequest
}

func newJobCustodyWorkerClaimPermitFixture(t *testing.T) jobCustodyWorkerClaimPermitFixture {
	t.Helper()
	owner, store, service, token := sharedWorkerHTTPFixture(t)
	handler := service.Handler()
	issueParticipantChallengeHTTP(t, handler, token, &owner)
	worker := sharedWorkerAdvertisement(owner)
	if response := advertiseSharedWorkerHTTP(t, handler, token, owner, worker, worker); response.Code != http.StatusCreated {
		t.Fatalf("advertisement status %d: %s", response.Code, response.Body.String())
	}
	request := BoxJobCustodyWorkerClaimPermitRequest{
		BoxID: worker.BoxID, CapabilitiesDigest: worker.CapabilitiesDigest,
		ClaimID: uuid.New(), DeviceID: owner.device.DeviceID,
		ExpiresAtMilliseconds: owner.now + 30_000,
		ParticipantID:         owner.anchor.ParticipantID, PermitID: uuid.New(),
		RequestedAtMilliseconds: owner.now,
		RouteRecipientKeyFingerprint: computequeue.SHA256Digest(
			"job-custody-worker-permit-test", "recipient-key",
		),
		Version: jobcustody.WorkerClaimPermitVersion, WorkerID: worker.WorkerID,
	}
	return jobCustodyWorkerClaimPermitFixture{
		owner: owner, store: store, service: service, handler: handler,
		token: token, worker: worker, request: request,
	}
}

func (fixture *jobCustodyWorkerClaimPermitFixture) post(
	t *testing.T,
	requestValue BoxJobCustodyWorkerClaimPermitRequest,
	proofValue *BoxJobCustodyWorkerClaimPermitRequest,
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
	body, err := json.Marshal(jobCustodyWorkerClaimPermitBody{
		ChallengeID: fixture.owner.challengeID,
		Proof: signedParticipantActionProof(
			t, fixture.owner, ParticipantActionIssueJobCustodyWorkerClaimPermit, proofPayload,
		),
		RequestPayload: payload, Version: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(
		http.MethodPost, "/v1/job-custody/worker-claim-permits", bytes.NewReader(body),
	)
	request.Header.Set("Authorization", "Bearer "+fixture.token)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	return response
}

func TestJobCustodyWorkerClaimPermitBindsCurrentOwnerAndCapability(t *testing.T) {
	fixture := newJobCustodyWorkerClaimPermitFixture(t)
	response := fixture.post(t, fixture.request, nil)
	if response.Code != http.StatusCreated {
		t.Fatalf("permit status %d: %s", response.Code, response.Body.String())
	}
	var permit jobcustody.SignedWorkerClaimPermit
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
	authorization, err := verifier.VerifyWorkerClaim(
		permit, computequeue.Timestamp(fixture.owner.now+1),
	)
	if err != nil {
		t.Fatal(err)
	}
	payload := authorization.Payload()
	if payload.AuthorityID != fixture.worker.BoxID ||
		payload.ClaimID != fixture.request.ClaimID ||
		payload.RouteRecipientWorkerID != computequeue.WorkerID(fixture.worker.WorkerID.String()) ||
		payload.RouteRecipientKeyFingerprint != fixture.request.RouteRecipientKeyFingerprint ||
		payload.WorkerCapabilitiesDigest != computequeue.Digest(fixture.worker.CapabilitiesDigest) ||
		payload.WorkerOwnerAuthorityDigest.Validate() != nil {
		t.Fatalf("payload=%+v", payload)
	}
	if events, err := fixture.store.RecentAudit(t.Context(), 10); err != nil {
		t.Fatal(err)
	} else if len(events) == 0 || events[0].Kind != "job_custody_worker_claim_permit" {
		t.Fatalf("missing coarse Worker claim audit: %+v", events)
	}
}

func TestJobCustodyWorkerClaimPermitRejectsProofAndRouteSubstitution(t *testing.T) {
	t.Run("proof payload", func(t *testing.T) {
		fixture := newJobCustodyWorkerClaimPermitFixture(t)
		signed := fixture.request
		signed.ClaimID = uuid.New()
		response := fixture.post(t, fixture.request, &signed)
		if response.Code != http.StatusForbidden {
			t.Fatalf("status %d: %s", response.Code, response.Body.String())
		}
	})

	t.Run("capability digest", func(t *testing.T) {
		fixture := newJobCustodyWorkerClaimPermitFixture(t)
		changed := fixture.request
		changed.CapabilitiesDigest = string(computequeue.SHA256Digest("changed", "capabilities"))
		response := fixture.post(t, changed, nil)
		if response.Code != http.StatusConflict {
			t.Fatalf("status %d: %s", response.Code, response.Body.String())
		}
	})
}
