package boxcontrol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/computequeue"
	"github.com/robreuss/FacetsNode/internal/jobcustody"
)

type jobCustodyPermitHTTPFixture struct {
	owner          participantFixture
	requester      participantFixture
	store          *MemoryStore
	service        *Service
	handler        http.Handler
	ownerToken     string
	requesterToken string
	worker         BoxSharedWorkerAdvertisement
	accessGrant    BoxSharedWorkerAccessGrant
	permitRequest  BoxJobCustodyAdmissionPermitRequest
	header         computequeue.JobCustodyAdmissionHeader
}

func newJobCustodyPermitHTTPFixture(t *testing.T) jobCustodyPermitHTTPFixture {
	t.Helper()
	owner, store, service, ownerToken := sharedWorkerHTTPFixture(t)
	requester, requesterToken := addSharedWorkerAccessParticipant(
		t, store, owner.anchor.BoxID, owner.now, "Requester Mac",
	)
	handler := service.Handler()
	issueParticipantChallengeHTTP(t, handler, ownerToken, &owner)
	worker := sharedWorkerAdvertisement(owner)
	if response := advertiseSharedWorkerHTTP(
		t, handler, ownerToken, owner, worker, worker,
	); response.Code != http.StatusCreated {
		t.Fatalf("advertisement status %d: %s", response.Code, response.Body.String())
	}
	accessGrant := approveSharedWorkerAccessHTTP(
		t, handler, ownerToken, requesterToken, &owner, &requester, worker,
	)
	permitRequest, header := jobCustodyAdmissionPermitRequestForTest(
		t, owner.now, requester, worker, accessGrant,
	)
	return jobCustodyPermitHTTPFixture{
		owner: owner, requester: requester, store: store, service: service,
		handler: handler, ownerToken: ownerToken, requesterToken: requesterToken,
		worker: worker, accessGrant: accessGrant, permitRequest: permitRequest,
		header: header,
	}
}

func jobCustodyAdmissionPermitRequestForTest(
	t *testing.T,
	now int64,
	requester participantFixture,
	worker BoxSharedWorkerAdvertisement,
	accessGrant BoxSharedWorkerAccessGrant,
) (BoxJobCustodyAdmissionPermitRequest, computequeue.JobCustodyAdmissionHeader) {
	t.Helper()
	descriptor, err := computequeue.NewJobCapsuleProtectedObjectDescriptor(
		4096, computequeue.SHA256Digest("job-custody-http-fixture", "capsule"), 1024,
	)
	if err != nil {
		t.Fatal(err)
	}
	header, err := computequeue.NewJobCustodyAdmissionHeader(
		computequeue.JobCapsuleID(uuid.NewString()),
		computequeue.AssignmentID(uuid.NewString()),
		computequeue.WorkerID(worker.WorkerID.String()),
		computequeue.SHA256Digest("job-custody-http-fixture", "worker-key"),
		descriptor,
		computequeue.Timestamp(now-1_000),
		computequeue.Timestamp(now+45_000),
		computequeue.Timestamp(now+120_000),
	)
	if err != nil {
		t.Fatal(err)
	}
	signer := computequeue.ReceiptSignerBinding{
		SignerID: "source.device.fixture", SigningKeyID: "source.key.fixture",
		SigningKeyRevision: 1,
		SignatureProfileID: computequeue.JobCustodyP256AdmissionSignatureProfile,
	}
	envelope, err := computequeue.NewJobCustodySignedAdmissionEnvelope(
		header, signer.SignatureProfileID, computequeue.SignatureValue("AA"),
	)
	if err != nil {
		t.Fatal(err)
	}
	envelopeBytes, err := computequeue.EncodeJobCustodyAdmissionCanonical(envelope)
	if err != nil {
		t.Fatal(err)
	}
	permitRequest := BoxJobCustodyAdmissionPermitRequest{
		AccessGrantID: accessGrant.GrantID, AdmissionEnvelope: envelopeBytes,
		AdmissionSigner: signer, BoxID: worker.BoxID,
		CapabilitiesDigest: worker.CapabilitiesDigest,
		DeviceID:           requester.device.DeviceID, ExpiresAtMilliseconds: now + 30_000,
		ParticipantID: requester.anchor.ParticipantID, PermitID: uuid.New(),
		RequestedAtMilliseconds: now, Version: 1, WorkerID: worker.WorkerID,
	}
	return permitRequest, header
}

func (fixture *jobCustodyPermitHTTPFixture) postPermit(
	t *testing.T,
	token string,
	requestValue BoxJobCustodyAdmissionPermitRequest,
	proofValue *BoxJobCustodyAdmissionPermitRequest,
) *httptest.ResponseRecorder {
	t.Helper()
	issueParticipantChallengeHTTP(t, fixture.handler, token, &fixture.requester)
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
	body, err := json.Marshal(jobCustodyAdmissionPermitBody{
		ChallengeID: fixture.requester.challengeID,
		Proof: signedParticipantActionProof(
			t, fixture.requester, ParticipantActionIssueJobCustodyPermit, proofPayload,
		),
		RequestPayload: payload, Version: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	httpRequest := httptest.NewRequest(
		http.MethodPost, "/v1/job-custody/admission-permits", bytes.NewReader(body),
	)
	httpRequest.Header.Set("Authorization", "Bearer "+token)
	httpRequest.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, httpRequest)
	return response
}

func TestJobCustodyAdmissionPermitHTTPBindsParticipantGrantAndRoute(t *testing.T) {
	fixture := newJobCustodyPermitHTTPFixture(t)
	response := fixture.postPermit(
		t, fixture.requesterToken, fixture.permitRequest, nil,
	)
	if response.Code != http.StatusCreated {
		t.Fatalf("permit status %d: %s", response.Code, response.Body.String())
	}
	var permit jobcustody.SignedAdmissionPermit
	if err := json.Unmarshal(response.Body.Bytes(), &permit); err != nil {
		t.Fatal(err)
	}
	publicKey := fixture.service.privateKey.Public().(ed25519.PublicKey)
	key, err := jobcustody.NewAdmissionPermitVerificationKey(
		fixture.worker.BoxID, publicKey,
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
		permit, fixture.permitRequest.AdmissionEnvelope,
		computequeue.Timestamp(fixture.requester.now+1),
	)
	if err != nil {
		t.Fatal(err)
	}
	if authorization.Header() != fixture.header ||
		authorization.ExpectedSigner() != fixture.permitRequest.AdmissionSigner {
		t.Fatalf("unexpected authorization: %#v", authorization)
	}
	payload, err := computequeue.DecodeCanonical[jobcustody.AdmissionPermitPayload](permit.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if payload.AuthorityID != fixture.worker.BoxID ||
		payload.PermitID != fixture.permitRequest.PermitID ||
		payload.RouteRecipientWorkerID != computequeue.WorkerID(fixture.worker.WorkerID.String()) ||
		payload.WorkerCapabilitiesDigest != computequeue.Digest(fixture.worker.CapabilitiesDigest) ||
		payload.RequesterAuthorityDigest.Validate() != nil || payload.WorkerAccessGrantDigest.Validate() != nil {
		t.Fatalf("unexpected permit payload: %+v", payload)
	}
	if events, err := fixture.store.RecentAudit(context.Background(), 10); err != nil {
		t.Fatal(err)
	} else if len(events) == 0 || events[0].Kind != "job_custody_admission_permit" {
		t.Fatalf("missing coarse permit audit: %+v", events)
	}
}

func TestJobCustodyAdmissionPermitHTTPRejectsSubstitutionAndStaleAuthority(t *testing.T) {
	t.Run("participant proof payload substitution", func(t *testing.T) {
		fixture := newJobCustodyPermitHTTPFixture(t)
		signed := fixture.permitRequest
		signed.PermitID = uuid.New()
		response := fixture.postPermit(
			t, fixture.requesterToken, fixture.permitRequest, &signed,
		)
		if response.Code != http.StatusForbidden {
			t.Fatalf("substitution status %d: %s", response.Code, response.Body.String())
		}
	})

	t.Run("admission route substitution", func(t *testing.T) {
		fixture := newJobCustodyPermitHTTPFixture(t)
		value := fixture.permitRequest
		value.WorkerID = uuid.New()
		response := fixture.postPermit(t, fixture.requesterToken, value, nil)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("route substitution status %d: %s", response.Code, response.Body.String())
		}
	})

	t.Run("different authenticated connection", func(t *testing.T) {
		fixture := newJobCustodyPermitHTTPFixture(t)
		response := fixture.postPermit(
			t, fixture.ownerToken, fixture.permitRequest, nil,
		)
		if response.Code != http.StatusConflict {
			t.Fatalf("connection substitution status %d: %s", response.Code, response.Body.String())
		}
	})

	t.Run("revoked Worker access grant", func(t *testing.T) {
		fixture := newJobCustodyPermitHTTPFixture(t)
		if err := fixture.store.RevokeSharedWorkerAccess(
			context.Background(), fixture.worker.BoxID, fixture.accessGrant.GrantID,
			fixture.owner.anchor.ParticipantID, fixture.accessGrant.Revision+1,
			fixture.owner.now,
		); err != nil {
			t.Fatal(err)
		}
		response := fixture.postPermit(
			t, fixture.requesterToken, fixture.permitRequest, nil,
		)
		if response.Code != http.StatusConflict {
			t.Fatalf("revoked grant status %d: %s", response.Code, response.Body.String())
		}
	})
}
