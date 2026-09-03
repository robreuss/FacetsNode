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

func TestClaimEncryptsFirstDeviceBootstrapAndNeverPublishesGroups(t *testing.T) {
	withFastArgon(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	store := initializedMemoryStore(t, "FIRST-BOX-CODE")
	deviceSync := &testDeviceSyncController{
		bootstrap: json.RawMessage(`{"version":1,"authorizationToken":"device-sync-secret"}`),
	}
	service := makeTestService(t, store, deviceSync, now)
	handler := service.Handler()
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
		Intent:          ConnectionIntentCreateFirstGroup, GroupName: "Rob's devices", DeviceName: "Mac",
		ExpiresAtMillis: now.Add(5 * time.Minute).UnixMilli(),
	})
	create := httptest.NewRequest(http.MethodPost, "/v1/connection-requests", bytes.NewReader(createBody))
	create.Header.Set("Content-Type", "application/json")
	created := httptest.NewRecorder()
	handler.ServeHTTP(created, create)
	if created.Code != http.StatusCreated {
		t.Fatalf("create status %d: %s", created.Code, created.Body.String())
	}

	home := httptest.NewRecorder()
	handler.ServeHTTP(home, httptest.NewRequest(http.MethodGet, "/?connection_request="+requestID.String(), nil))
	csrfCookie := cookieNamed(t, home.Result().Cookies(), "facets_box_csrf")
	form := url.Values{
		"csrf": {csrfCookie.Value}, "connection_request": {requestID.String()},
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
	if err != nil || !state.Claimed() || state.ActivationVerifier != "" || strings.Contains(state.OwnerVerifier, "memorable") {
		t.Fatalf("unexpected claimed state: %+v, %v", state, err)
	}
	if deviceSync.issueCount != 1 {
		t.Fatalf("issued %d bootstraps", deviceSync.issueCount)
	}
	deviceSync.groups = []DeviceSyncGroup{{SetDiscriminator: strings.Repeat("a", 32), DisplayName: "Private devices", Revision: 1}}

	poll := httptest.NewRequest(http.MethodGet, "/v1/connection-requests/"+requestID.String(), nil)
	poll.Header.Set("Authorization", "Bearer "+pollToken)
	polled := httptest.NewRecorder()
	handler.ServeHTTP(polled, poll)
	if polled.Code != http.StatusOK {
		t.Fatalf("poll status %d", polled.Code)
	}
	payload := openConnectionResult(t, requestID, clientPrivate, polled.Body.Bytes())
	if payload.BoxID != state.BoxID || payload.GrantToken == "" || !bytes.Contains(payload.DeviceSyncBootstrap, []byte("device-sync-secret")) {
		t.Fatalf("unexpected handoff: %+v", payload)
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
	if bytes.Contains(manifestBytes, []byte("Private devices")) || bytes.Contains(manifestBytes, []byte("deviceSyncGroups")) {
		t.Fatal("public manifest disclosed private Sync Group data")
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
	if err := store.Claim(context.Background(), state.ActivationVerifier, owner, now); err != nil {
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
	form := url.Values{"csrf": {"wrong"}, "activation_code": {"THIRD-BOX-CODE"}, "password": {"a sufficiently long owner passphrase"}}
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
