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

func sharedWorkerHTTPFixture(
	t *testing.T,
) (participantFixture, *MemoryStore, *Service, string) {
	t.Helper()
	fixture := newParticipantFixture(t)
	store := NewMemoryStore()
	ctx := context.Background()
	if err := store.Initialize(ctx, State{
		BoxID: fixture.anchor.BoxID, ActivationVerifier: "activation",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Claim(
		ctx, "activation", "owner", "Box", time.UnixMilli(fixture.now),
	); err != nil {
		t.Fatal(err)
	}
	enrollment := BoxParticipantEnrollment{
		Anchor: fixture.anchor, Device: fixture.device,
		RootRecord: fixture.root, GrantRecord: fixture.grant,
	}
	if err := store.PinOwnerApprovedParticipant(ctx, enrollment, fixture.now); err != nil {
		t.Fatal(err)
	}
	token, digest, err := RandomToken(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateGrant(ctx, ConnectionGrant{
		GrantID: uuid.New(), TokenDigest: digest, DeviceName: "Connected test Mac",
		CreatedAt: time.UnixMilli(fixture.now), LastSeenAt: time.UnixMilli(fixture.now),
		ExpiresAt: time.UnixMilli(fixture.now).Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	service := makeTestService(
		t, store, &testDeviceSyncController{}, time.UnixMilli(fixture.now),
	)
	return fixture, store, service, token
}

func issueParticipantChallengeHTTP(
	t *testing.T,
	handler http.Handler,
	token string,
	fixture *participantFixture,
) {
	t.Helper()
	payload, err := json.Marshal(createParticipantChallengeBody{
		Version: 1, ParticipantID: fixture.anchor.ParticipantID,
		DeviceID: fixture.device.DeviceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(
		http.MethodPost, "/v1/participant-challenges", bytes.NewReader(payload),
	)
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("challenge status %d: %s", response.Code, response.Body.String())
	}
	var challenge participantChallengeResponse
	if err := json.Unmarshal(response.Body.Bytes(), &challenge); err != nil {
		t.Fatal(err)
	}
	if challenge.BoxID != fixture.anchor.BoxID ||
		challenge.ParticipantID != fixture.anchor.ParticipantID ||
		challenge.DeviceID != fixture.device.DeviceID || challenge.ChallengeID == uuid.Nil {
		t.Fatalf("unexpected challenge: %+v", challenge)
	}
	fixture.challengeID = challenge.ChallengeID
}

func sharedWorkerAdvertisement(fixture participantFixture) BoxSharedWorkerAdvertisement {
	capabilities := []byte(`{"models":["clef-flash:9b-q8_0"],"roles":["semanticClassification"]}`)
	return BoxSharedWorkerAdvertisement{
		Version: 1, BoxID: fixture.anchor.BoxID, WorkerID: uuid.New(),
		OwnerParticipantID: fixture.anchor.ParticipantID,
		OwnerDeviceID:      fixture.device.DeviceID, DisplayName: "5090 Worker",
		Availability: SharedWorkerAvailable, Revision: 1, Capabilities: capabilities,
		CapabilitiesDigest:    SharedWorkerCapabilitiesDigest(capabilities),
		UpdatedAtMilliseconds: fixture.now - 100,
		ExpiresAtMilliseconds: fixture.now + 60_000,
	}
}

func advertiseSharedWorkerHTTP(
	t *testing.T,
	handler http.Handler,
	token string,
	fixture participantFixture,
	advertisement BoxSharedWorkerAdvertisement,
	proofFor BoxSharedWorkerAdvertisement,
) *httptest.ResponseRecorder {
	t.Helper()
	canonical, err := json.Marshal(proofFor)
	if err != nil {
		t.Fatal(err)
	}
	proof := signedParticipantActionProof(
		t, fixture, ParticipantActionAdvertiseWorker, canonical,
	)
	body, err := json.Marshal(sharedWorkerAdvertisementBody{
		Version: 1, Advertisement: advertisement,
		Enrollment: BoxParticipantEnrollment{
			Anchor: fixture.anchor, Device: fixture.device,
			RootRecord: fixture.root, GrantRecord: fixture.grant,
		},
		ChallengeID: fixture.challengeID, Proof: proof,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/shared-workers/"+advertisement.WorkerID.String()+"/advertisement",
		bytes.NewReader(body),
	)
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestSharedWorkerDirectoryRequiresExactParticipantActionProof(t *testing.T) {
	fixture, _, service, token := sharedWorkerHTTPFixture(t)
	handler := service.Handler()
	issueParticipantChallengeHTTP(t, handler, token, &fixture)
	advertisement := sharedWorkerAdvertisement(fixture)
	substituted := advertisement
	substituted.DisplayName = "Substituted Worker"

	rejected := advertiseSharedWorkerHTTP(
		t, handler, token, fixture, substituted, advertisement,
	)
	if rejected.Code != http.StatusForbidden {
		t.Fatalf("substituted advertisement status %d: %s", rejected.Code, rejected.Body.String())
	}
	accepted := advertiseSharedWorkerHTTP(
		t, handler, token, fixture, advertisement, advertisement,
	)
	if accepted.Code != http.StatusCreated {
		t.Fatalf("advertisement status %d: %s", accepted.Code, accepted.Body.String())
	}

	listRequest := httptest.NewRequest(http.MethodGet, "/v1/shared-workers", nil)
	listRequest.Header.Set("Authorization", "Bearer "+token)
	listed := httptest.NewRecorder()
	handler.ServeHTTP(listed, listRequest)
	if listed.Code != http.StatusOK {
		t.Fatalf("list status %d: %s", listed.Code, listed.Body.String())
	}
	var catalog struct {
		Version int                            `json:"version"`
		Workers []BoxSharedWorkerAdvertisement `json:"workers"`
	}
	if err := json.Unmarshal(listed.Body.Bytes(), &catalog); err != nil {
		t.Fatal(err)
	}
	if catalog.Version != 1 || len(catalog.Workers) != 1 ||
		catalog.Workers[0].WorkerID != advertisement.WorkerID ||
		catalog.Workers[0].OwnerParticipantID != fixture.anchor.ParticipantID ||
		!bytes.Equal(catalog.Workers[0].Capabilities, advertisement.Capabilities) {
		t.Fatalf("unexpected Worker catalog: %+v", catalog)
	}

	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/v1/shared-workers", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized list status %d", unauthorized.Code)
	}
}

func TestSharedWorkerWithdrawalIsOwnerBoundAndRevisioned(t *testing.T) {
	fixture, _, service, token := sharedWorkerHTTPFixture(t)
	handler := service.Handler()
	issueParticipantChallengeHTTP(t, handler, token, &fixture)
	advertisement := sharedWorkerAdvertisement(fixture)
	if response := advertiseSharedWorkerHTTP(
		t, handler, token, fixture, advertisement, advertisement,
	); response.Code != http.StatusCreated {
		t.Fatalf("advertisement status %d: %s", response.Code, response.Body.String())
	}

	issueParticipantChallengeHTTP(t, handler, token, &fixture)
	withdrawal := sharedWorkerWithdrawal{
		Version: 1, BoxID: fixture.anchor.BoxID, WorkerID: advertisement.WorkerID,
		OwnerParticipantID: fixture.anchor.ParticipantID,
		OwnerDeviceID:      fixture.device.DeviceID, Revision: 2,
	}
	canonical, err := json.Marshal(withdrawal)
	if err != nil {
		t.Fatal(err)
	}
	proof := signedParticipantActionProof(
		t, fixture, ParticipantActionWithdrawWorker, canonical,
	)
	body, err := json.Marshal(sharedWorkerWithdrawalBody{
		Version: 1, Withdrawal: withdrawal,
		Enrollment: BoxParticipantEnrollment{
			Anchor: fixture.anchor, Device: fixture.device,
			RootRecord: fixture.root, GrantRecord: fixture.grant,
		},
		ChallengeID: fixture.challengeID, Proof: proof,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/shared-workers/"+advertisement.WorkerID.String()+"/withdraw",
		bytes.NewReader(body),
	)
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("withdraw status %d: %s", response.Code, response.Body.String())
	}

	listRequest := httptest.NewRequest(http.MethodGet, "/v1/shared-workers", nil)
	listRequest.Header.Set("Authorization", "Bearer "+token)
	listed := httptest.NewRecorder()
	handler.ServeHTTP(listed, listRequest)
	var catalog struct {
		Workers []BoxSharedWorkerAdvertisement `json:"workers"`
	}
	if err := json.Unmarshal(listed.Body.Bytes(), &catalog); err != nil {
		t.Fatal(err)
	}
	if len(catalog.Workers) != 0 {
		t.Fatalf("withdrawn Worker remained listed: %+v", catalog.Workers)
	}
}

func TestSharedWorkerDirectoryExcludesExpiredAndRevokedOwners(t *testing.T) {
	fixture, store, _, _ := sharedWorkerHTTPFixture(t)
	advertisement := sharedWorkerAdvertisement(fixture)
	if err := store.UpsertSharedWorker(context.Background(), advertisement, fixture.now); err != nil {
		t.Fatal(err)
	}
	if listed, err := store.ListSharedWorkers(
		context.Background(), fixture.anchor.BoxID, fixture.now+60_001,
	); err != nil || len(listed) != 0 {
		t.Fatalf("expired Worker remained listed: %+v, %v", listed, err)
	}
	if err := store.RevokePinnedParticipantDevice(
		context.Background(), fixture.anchor.BoxID, fixture.anchor.ParticipantID,
		fixture.device.DeviceID, fixture.now+1,
	); err != nil {
		t.Fatal(err)
	}
	if listed, err := store.ListSharedWorkers(
		context.Background(), fixture.anchor.BoxID, fixture.now+2,
	); err != nil || len(listed) != 0 {
		t.Fatalf("revoked owner's Worker remained listed: %+v, %v", listed, err)
	}
}
