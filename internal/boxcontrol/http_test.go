package boxcontrol

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/chacha20poly1305"
)

type testDeviceSyncController struct {
	groups      []DeviceSyncGroup
	bootstrap   json.RawMessage
	healthError error
	issueCount  int
}

type failingConnectionCompletionStore struct {
	Store
}

func (store failingConnectionCompletionStore) CompleteConnectionRequest(
	context.Context,
	uuid.UUID,
	[]byte,
) error {
	return errors.New("injected connection completion failure")
}

func (controller *testDeviceSyncController) Groups(context.Context) ([]DeviceSyncGroup, error) {
	return append([]DeviceSyncGroup(nil), controller.groups...), nil
}

func (controller *testDeviceSyncController) IssueAccountBootstrap(context.Context) (json.RawMessage, error) {
	controller.issueCount++
	return append(json.RawMessage(nil), controller.bootstrap...), nil
}

func (controller *testDeviceSyncController) Healthy(context.Context) error {
	return controller.healthError
}

func TestClaimAndMemberApprovalRemainSeparate(t *testing.T) {
	withFastArgon(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	store := initializedMemoryStore(t, "FIRST-BOX-CODE")
	deviceSync := &testDeviceSyncController{
		bootstrap: json.RawMessage(`{"version":1,"authorizationToken":"device-sync-secret"}`),
	}
	service := makeTestService(t, store, deviceSync, now)
	handler := service.Handler()

	home := httptest.NewRecorder()
	handler.ServeHTTP(home, httptest.NewRequest(http.MethodGet, "/", nil))
	csrfCookie := cookieNamed(t, home.Result().Cookies(), "facets_box_csrf")
	form := url.Values{
		"csrf": {csrfCookie.Value}, "display_name": {"Rob's Home Box"},
		"activation_code": {"FIRST-BOX-CODE"}, "password": {"a memorable private facets owner phrase"},
	}
	claim := httptest.NewRequest(http.MethodPost, "/claim", strings.NewReader(form.Encode()))
	claim.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	claim.AddCookie(csrfCookie)
	claimed := httptest.NewRecorder()
	handler.ServeHTTP(claimed, claim)
	if claimed.Code != http.StatusSeeOther {
		t.Fatalf("claim status %d: %s", claimed.Code, claimed.Body.String())
	}
	state, err := store.State(context.Background())
	if err != nil || !state.Claimed() || state.DisplayName != "Rob's Home Box" || state.ActivationVerifier != "" || strings.Contains(state.OwnerVerifier, "memorable") {
		t.Fatalf("unexpected claimed state: %+v, %v", state, err)
	}
	if deviceSync.issueCount != 0 {
		t.Fatalf("issued %d bootstraps", deviceSync.issueCount)
	}
	if grants, err := store.ListGrants(context.Background()); err != nil || len(grants) != 0 {
		t.Fatalf("claim created a member grant: %+v, %v", grants, err)
	}

	clientPrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pollToken, pollDigest, err := RandomToken(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	requestID := uuid.New()
	createBody, _ := json.Marshal(createConnectionRequestBody{
		Version: SchemaVersion, RequestID: requestID,
		PollTokenDigest: base64.RawURLEncoding.EncodeToString(pollDigest[:]),
		ClientPublicKey: base64.RawURLEncoding.EncodeToString(clientPrivate.PublicKey().Bytes()),
		DeviceName:      "iPad Pro",
		ExpiresAtMillis: now.Add(5 * time.Minute).UnixMilli(),
	})
	create := httptest.NewRequest(http.MethodPost, "/v1/connection-requests", bytes.NewReader(createBody))
	create.Header.Set("Content-Type", "application/json")
	created := httptest.NewRecorder()
	handler.ServeHTTP(created, create)
	if created.Code != http.StatusCreated {
		t.Fatalf("create status %d: %s", created.Code, created.Body.String())
	}
	var createdBody struct {
		ApprovalCode string `json:"approvalCode"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &createdBody); err != nil {
		t.Fatal(err)
	}
	if _, err := NormalizeApprovalCode(createdBody.ApprovalCode); err != nil {
		t.Fatalf("invalid approval code %q: %v", createdBody.ApprovalCode, err)
	}

	poll := httptest.NewRequest(http.MethodGet, "/v1/connection-requests/"+requestID.String(), nil)
	poll.Header.Set("Authorization", "Bearer "+pollToken)
	pending := httptest.NewRecorder()
	handler.ServeHTTP(pending, poll)
	if pending.Code != http.StatusAccepted {
		t.Fatalf("claim unexpectedly approved member request: %d", pending.Code)
	}

	sessionCookie := cookieNamed(t, claimed.Result().Cookies(), "facets_box_session")
	ownerCSRF := cookieNamed(t, claimed.Result().Cookies(), "facets_box_csrf")
	approvalForm := url.Values{
		"csrf": {ownerCSRF.Value}, "connection_code": {createdBody.ApprovalCode},
	}
	approval := httptest.NewRequest(http.MethodPost, "/connections/approve", strings.NewReader(approvalForm.Encode()))
	approval.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	approval.AddCookie(sessionCookie)
	approval.AddCookie(ownerCSRF)
	approved := httptest.NewRecorder()
	handler.ServeHTTP(approved, approval)
	if approved.Code != http.StatusSeeOther {
		t.Fatalf("approval status %d: %s", approved.Code, approved.Body.String())
	}
	replayRequest := httptest.NewRequest(http.MethodPost, "/connections/approve", strings.NewReader(approvalForm.Encode()))
	replayRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	replayRequest.AddCookie(sessionCookie)
	replayRequest.AddCookie(ownerCSRF)
	replay := httptest.NewRecorder()
	handler.ServeHTTP(replay, replayRequest)
	if replay.Code != http.StatusSeeOther || !strings.Contains(replay.Header().Get("Location"), "error=") {
		t.Fatalf("used code replay was not rejected: %d %s", replay.Code, replay.Header().Get("Location"))
	}

	poll = httptest.NewRequest(http.MethodGet, "/v1/connection-requests/"+requestID.String(), nil)
	poll.Header.Set("Authorization", "Bearer "+pollToken)
	polled := httptest.NewRecorder()
	handler.ServeHTTP(polled, poll)
	if polled.Code != http.StatusOK {
		t.Fatalf("poll status %d", polled.Code)
	}
	payload := openConnectionResult(t, requestID, clientPrivate, polled.Body.Bytes())
	if payload.BoxID != state.BoxID || payload.GrantToken == "" || payload.Profile.DisplayName != "Rob's Home Box" {
		t.Fatalf("unexpected handoff: %+v", payload)
	}
	if len(payload.Profile.Services) != 6 || payload.Profile.Services[2].Kind != "device-sync" || payload.Profile.Services[2].Status != ServiceAvailable {
		t.Fatalf("authenticated service catalog is incomplete: %+v", payload.Profile.Services)
	}

	manifestResponse := httptest.NewRecorder()
	handler.ServeHTTP(manifestResponse, httptest.NewRequest(http.MethodGet, "/.well-known/facets-box", nil))
	var manifest SignedPublicManifest
	if err := json.Unmarshal(manifestResponse.Body.Bytes(), &manifest); err != nil {
		t.Fatal(err)
	}
	manifestBytes, err := base64.RawURLEncoding.Strict().DecodeString(manifest.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(manifestBytes, []byte("deviceSyncGroups")) || bytes.Contains(manifestBytes, []byte("device-sync-secret")) {
		t.Fatal("public manifest disclosed private service data")
	}
	var publicPayload PublicManifestPayload
	if err := json.Unmarshal(manifestBytes, &publicPayload); err != nil {
		t.Fatal(err)
	}
	publicKey, _ := base64.RawURLEncoding.Strict().DecodeString(publicPayload.PublicKey)
	signature, _ := base64.RawURLEncoding.Strict().DecodeString(manifest.Signature)
	if !ed25519.Verify(publicKey, manifestBytes, signature) {
		t.Fatal("manifest signature rejected")
	}
	if !publicPayload.Claimed || publicPayload.DisplayName != "Rob's Home Box" {
		t.Fatalf("manifest did not publish claimed Box name: %+v", publicPayload)
	}
}

func TestConnectionRequestExpiryIsCappedToTheControllerClock(t *testing.T) {
	withFastArgon(t)
	now := time.Unix(1_800_000_000, 500_000_000).UTC()
	store := initializedMemoryStore(t, "FIRST-BOX-CODE")
	state, _ := store.State(context.Background())
	owner, err := hashSecret("a memorable owner passphrase", rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Claim(context.Background(), state.ActivationVerifier, owner, "Home Box", now); err != nil {
		t.Fatal(err)
	}
	service := makeTestService(t, store, &testDeviceSyncController{}, now)
	clientPrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, pollDigest, err := RandomToken(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	requestID := uuid.New()
	createBody, _ := json.Marshal(createConnectionRequestBody{
		Version: SchemaVersion, RequestID: requestID,
		PollTokenDigest: base64.RawURLEncoding.EncodeToString(pollDigest[:]),
		ClientPublicKey: base64.RawURLEncoding.EncodeToString(clientPrivate.PublicKey().Bytes()),
		DeviceName:      "Mac",
		// The client is 500 ms ahead and asks for the documented ten-minute lifetime.
		ExpiresAtMillis: now.Add(ConnectionRequestLifetime + 500*time.Millisecond).UnixMilli(),
	})
	create := httptest.NewRequest(http.MethodPost, "/v1/connection-requests", bytes.NewReader(createBody))
	create.Header.Set("Content-Type", "application/json")
	created := httptest.NewRecorder()
	service.Handler().ServeHTTP(created, create)
	if created.Code != http.StatusCreated {
		t.Fatalf("create status %d: %s", created.Code, created.Body.String())
	}
	stored, err := store.ConnectionRequest(context.Background(), requestID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.CreatedAt != now || stored.ExpiresAt != now.Add(ConnectionRequestLifetime) {
		t.Fatalf("controller did not enforce its own lifetime: created=%s expires=%s", stored.CreatedAt, stored.ExpiresAt)
	}
}

func TestApprovalFailureIsReportedAndDoesNotLeaveAnActiveGrant(t *testing.T) {
	withFastArgon(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	baseStore := initializedMemoryStore(t, "APPROVAL-FAILURE-CODE")
	state, _ := baseStore.State(context.Background())
	owner, err := hashSecret("a memorable approval failure password", rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := baseStore.Claim(context.Background(), state.ActivationVerifier, owner, "Home Box", now); err != nil {
		t.Fatal(err)
	}
	clientPrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, pollDigest, err := RandomToken(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	codeDigest, err := ApprovalCodeDigest("123456")
	if err != nil {
		t.Fatal(err)
	}
	requestID := uuid.New()
	connection := ConnectionRequest{
		RequestID:          requestID,
		PollTokenDigest:    pollDigest,
		ApprovalCodeDigest: codeDigest,
		DeviceName:         "iPad Pro",
		CreatedAt:          now,
		ExpiresAt:          now.Add(time.Minute),
	}
	copy(connection.ClientPublicKey[:], clientPrivate.PublicKey().Bytes())
	if err := baseStore.CreateConnectionRequest(context.Background(), connection); err != nil {
		t.Fatal(err)
	}
	service := makeTestService(
		t,
		failingConnectionCompletionStore{Store: baseStore},
		&testDeviceSyncController{},
		now,
	)

	if err := service.approveConnection(context.Background(), requestID); err == nil {
		t.Fatal("approval reported success after the durable handoff write failed")
	}
	grants, err := baseStore.ListGrants(context.Background())
	if err != nil || len(grants) != 1 || grants[0].RevokedAt.IsZero() {
		t.Fatalf("failed approval left an active grant: %+v, %v", grants, err)
	}
	stored, err := baseStore.ConnectionRequest(context.Background(), requestID)
	if err != nil || len(stored.EncryptedResult) != 0 {
		t.Fatalf("failed approval published a result: %+v, %v", stored, err)
	}
}

func TestUnclaimedBoxRejectsMemberRequests(t *testing.T) {
	withFastArgon(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	store := initializedMemoryStore(t, "UNCLAIMED-BOX-CODE")
	service := makeTestService(t, store, &testDeviceSyncController{}, now)
	request := httptest.NewRequest(http.MethodPost, "/v1/connection-requests", strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	service.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusConflict {
		t.Fatalf("unclaimed request status %d", response.Code)
	}
	if grants, err := store.ListGrants(context.Background()); err != nil || len(grants) != 0 {
		t.Fatalf("unclaimed request changed grants: %+v, %v", grants, err)
	}
}

func TestOwnerLoginThrottlesAndPasswordChangeRevokesSessionsAndGrants(t *testing.T) {
	withFastArgon(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	store := initializedMemoryStore(t, "SECOND-BOX-CODE")
	state, _ := store.State(context.Background())
	owner, err := hashSecret("a different memorable owner passphrase", rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Claim(context.Background(), state.ActivationVerifier, owner, "Home Box", now); err != nil {
		t.Fatal(err)
	}
	service := makeTestService(t, store, &testDeviceSyncController{}, now)
	handler := service.Handler()

	for attempt := 0; attempt < 5; attempt++ {
		csrf, _, _ := RandomToken(rand.Reader)
		form := url.Values{"csrf": {csrf}, "password": {"this password is definitely incorrect"}}
		request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		request.RemoteAddr = "192.0.2.10:1234"
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(&http.Cookie{Name: "facets_box_csrf", Value: csrf})
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusSeeOther {
			t.Fatalf("attempt %d status %d", attempt, response.Code)
		}
	}
	csrf, _, _ := RandomToken(rand.Reader)
	form := url.Values{"csrf": {csrf}, "password": {"a different memorable owner passphrase"}}
	blockedRequest := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	blockedRequest.RemoteAddr = "192.0.2.10:1234"
	blockedRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	blockedRequest.AddCookie(&http.Cookie{Name: "facets_box_csrf", Value: csrf})
	blocked := httptest.NewRecorder()
	handler.ServeHTTP(blocked, blockedRequest)
	if blocked.Code != http.StatusTooManyRequests {
		t.Fatalf("expected throttle, got %d", blocked.Code)
	}

	sessionToken, sessionDigest, _ := RandomToken(rand.Reader)
	sessionCSRF, csrfDigest, _ := RandomToken(rand.Reader)
	if err := store.CreateWebSession(context.Background(), WebSession{TokenDigest: sessionDigest, CSRFDigest: csrfDigest, CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	grantToken, grantDigest, _ := RandomToken(rand.Reader)
	grantID := uuid.New()
	if err := store.CreateGrant(context.Background(), ConnectionGrant{GrantID: grantID, TokenDigest: grantDigest, DeviceName: "iPad", CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	change := url.Values{"csrf": {sessionCSRF}, "current_password": {"a different memorable owner passphrase"}, "new_password": {"a replacement memorable owner passphrase"}}
	changeRequest := httptest.NewRequest(http.MethodPost, "/password", strings.NewReader(change.Encode()))
	changeRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	changeRequest.AddCookie(&http.Cookie{Name: "facets_box_session", Value: sessionToken})
	changeRequest.AddCookie(&http.Cookie{Name: "facets_box_csrf", Value: sessionCSRF})
	changed := httptest.NewRecorder()
	handler.ServeHTTP(changed, changeRequest)
	if changed.Code != http.StatusSeeOther {
		t.Fatalf("change status %d: %s", changed.Code, changed.Body.String())
	}
	if _, err := store.WebSession(context.Background(), sessionDigest, now); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("session survived: %v", err)
	}
	if _, err := store.Grant(context.Background(), grantDigest, now); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("grant %s survived: %v", grantToken, err)
	}
}

func TestCSRFRejectsCrossOriginClaimAndConnectionPollIsNotAnOwnerSession(t *testing.T) {
	withFastArgon(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	store := initializedMemoryStore(t, "THIRD-BOX-CODE")
	service := makeTestService(t, store, &testDeviceSyncController{}, now)
	handler := service.Handler()
	form := url.Values{"csrf": {"wrong"}, "activation_code": {"THIRD-BOX-CODE"}, "display_name": {"Home Box"}, "password": {"a sufficiently long owner passphrase"}}
	claim := httptest.NewRequest(http.MethodPost, "/claim", strings.NewReader(form.Encode()))
	claim.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	claim.AddCookie(&http.Cookie{Name: "facets_box_csrf", Value: "different"})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, claim)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("CSRF status %d", response.Code)
	}
	state, _ := store.State(context.Background())
	if state.Claimed() {
		t.Fatal("CSRF request claimed Box")
	}
}

func makeTestService(t *testing.T, store Store, deviceSync DeviceSyncController, now time.Time) *Service {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(store, deviceSync, privateKey, "https://box.example/facetsbox", "Test Facets Box", []ServiceDescriptor{{Kind: "device-sync", Endpoint: "https://box.example/facetsbox/device-sync"}}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }
	return service
}

func initializedMemoryStore(t *testing.T, activation string) *MemoryStore {
	t.Helper()
	verifier, err := hashSecret(activation, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemoryStore()
	if err := store.Initialize(context.Background(), State{BoxID: uuid.New(), ActivationVerifier: verifier}); err != nil {
		t.Fatal(err)
	}
	return store
}

func withFastArgon(t *testing.T) {
	t.Helper()
	previous := defaultArgonParameters
	defaultArgonParameters = argonParameters{MemoryKiB: 32 * 1024, Time: 1, Threads: 1, SaltBytes: 16, KeyBytes: 32}
	t.Cleanup(func() { defaultArgonParameters = previous })
}

func cookieNamed(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("cookie %s missing", name)
	return nil
}

func openConnectionResult(t *testing.T, requestID uuid.UUID, clientPrivate *ecdh.PrivateKey, data []byte) ConnectionResultPayload {
	t.Helper()
	var sealed SealedConnectionResult
	if err := json.Unmarshal(data, &sealed); err != nil {
		t.Fatal(err)
	}
	publicBytes, _ := base64.RawURLEncoding.Strict().DecodeString(sealed.ServerPublicKey)
	serverPublic, err := ecdh.X25519().NewPublicKey(publicBytes)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := clientPrivate.ECDH(serverPublic)
	if err != nil {
		t.Fatal(err)
	}
	context := append([]byte("facets-box-app-handoff-v1\x00"), requestID[:]...)
	key := sha256.Sum256(append(context, shared...))
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		t.Fatal(err)
	}
	nonce, _ := base64.RawURLEncoding.Strict().DecodeString(sealed.Nonce)
	ciphertext, _ := base64.RawURLEncoding.Strict().DecodeString(sealed.Ciphertext)
	plaintext, err := aead.Open(nil, nonce, ciphertext, context)
	if err != nil {
		t.Fatal(err)
	}
	var payload ConnectionResultPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		t.Fatal(err)
	}
	if subtle.ConstantTimeCompare([]byte(payload.GrantToken), []byte("")) == 1 {
		t.Fatal("empty grant")
	}
	return payload
}
