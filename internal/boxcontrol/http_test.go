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
	"regexp"
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

func TestClaimConnectsExactInstallationAndOwnerInvitationConnectsSecond(t *testing.T) {
	withFastArgon(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	store := initializedMemoryStore(t, "FIRST-BOX-CODE")
	deviceSync := &testDeviceSyncController{
		groups: []DeviceSyncGroup{{
			SetDiscriminator: "0123456789abcdef0123456789abcdef",
			DisplayName:      "Rob's devices",
			Revision:         1,
		}},
		bootstrap: json.RawMessage(`{"version":1,"authorizationToken":"device-sync-secret"}`),
	}
	service := makeTestService(t, store, deviceSync, now)
	handler := service.Handler()

	claimPrivate, claimPollToken, claimBody := testConnectionRequest(
		t, now, "Rob's Mac mini",
	)
	claimRequest := httptest.NewRequest(
		http.MethodPost,
		"/v1/claim-connection-requests",
		bytes.NewReader(claimBody),
	)
	claimRequest.Header.Set("Content-Type", "application/json")
	claimCreated := httptest.NewRecorder()
	handler.ServeHTTP(claimCreated, claimRequest)
	if claimCreated.Code != http.StatusCreated {
		t.Fatalf("claim connection request status %d: %s", claimCreated.Code, claimCreated.Body.String())
	}
	var claimInput createConnectionRequestBody
	if err := json.Unmarshal(claimBody, &claimInput); err != nil {
		t.Fatal(err)
	}

	home := httptest.NewRecorder()
	handler.ServeHTTP(home, httptest.NewRequest(
		http.MethodGet, "/?claim_request_id="+claimInput.RequestID.String(), nil,
	))
	if !strings.Contains(home.Body.String(), "This will also connect") ||
		!strings.Contains(home.Body.String(), "Rob&#39;s Mac mini") {
		t.Fatalf("claim page omitted exact installation: %s", home.Body.String())
	}
	csrfCookie := cookieNamed(t, home.Result().Cookies(), "facets_box_csrf")
	form := url.Values{
		"csrf": {csrfCookie.Value}, "display_name": {"Rob's Home Box"},
		"activation_code": {"FIRST-BOX-CODE"}, "password": {"a memorable private facets owner phrase"},
		"password_confirmation": {"a memorable private facets owner phrase"},
		"claim_request_id":      {claimInput.RequestID.String()},
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
	if grants, err := store.ListGrants(context.Background()); err != nil || len(grants) != 1 || grants[0].DeviceName != "Rob's Mac mini" {
		t.Fatalf("claim did not connect exact installation: %+v, %v", grants, err)
	}
	claimPoll := httptest.NewRequest(
		http.MethodGet,
		"/v1/connection-requests/"+claimInput.RequestID.String(),
		nil,
	)
	claimPoll.Header.Set("Authorization", "Bearer "+claimPollToken)
	claimPolled := httptest.NewRecorder()
	handler.ServeHTTP(claimPolled, claimPoll)
	if claimPolled.Code != http.StatusOK {
		t.Fatalf("claim connection poll status %d: %s", claimPolled.Code, claimPolled.Body.String())
	}
	claimPayload := openConnectionResult(
		t, claimInput.RequestID, claimPrivate, claimPolled.Body.Bytes(),
	)
	if claimPayload.BoxID != state.BoxID || claimPayload.Profile.DisplayName != "Rob's Home Box" {
		t.Fatalf("unexpected claiming installation handoff: %+v", claimPayload)
	}

	sessionCookie := cookieNamed(t, claimed.Result().Cookies(), "facets_box_session")
	ownerCSRF := cookieNamed(t, claimed.Result().Cookies(), "facets_box_csrf")
	authorize := httptest.NewRequest(http.MethodGet, "/authorize-device", nil)
	authorize.AddCookie(sessionCookie)
	authorize.AddCookie(ownerCSRF)
	authorizationPage := httptest.NewRecorder()
	handler.ServeHTTP(authorizationPage, authorize)
	if authorizationPage.Code != http.StatusOK {
		t.Fatalf("authorize page status %d: %s", authorizationPage.Code, authorizationPage.Body.String())
	}
	if body := authorizationPage.Body.String(); !strings.Contains(body, ">"+spacesSyncProductName+"</h3>") ||
		!strings.Contains(body, ">"+groupSpacesProductName+"</h3>") ||
		strings.Contains(body, ">Device Sync</h3>") ||
		strings.Contains(body, ">Shared Spaces</h3>") {
		t.Fatalf("dashboard used stale service product names: %s", body)
	}
	match := regexp.MustCompile(`<p class="pin">([0-9]{6})</p>`).FindStringSubmatch(authorizationPage.Body.String())
	if len(match) != 2 {
		t.Fatalf("authorization page omitted six-digit code: %s", authorizationPage.Body.String())
	}
	authorizationCode := match[1]

	clientPrivate, pollToken, secondBody := testConnectionRequest(t, now, "iPad Pro")
	var secondInput createConnectionRequestBody
	if err := json.Unmarshal(secondBody, &secondInput); err != nil {
		t.Fatal(err)
	}
	secondInput.AuthorizationCode = authorizationCode
	secondBody, _ = json.Marshal(secondInput)
	redeem := httptest.NewRequest(http.MethodPost, "/v1/connection-invitations/redeem", bytes.NewReader(secondBody))
	redeem.Header.Set("Content-Type", "application/json")
	redeemed := httptest.NewRecorder()
	handler.ServeHTTP(redeemed, redeem)
	if redeemed.Code != http.StatusCreated {
		t.Fatalf("redeem status %d: %s", redeemed.Code, redeemed.Body.String())
	}

	poll := httptest.NewRequest(http.MethodGet, "/v1/connection-requests/"+secondInput.RequestID.String(), nil)
	poll.Header.Set("Authorization", "Bearer "+pollToken)
	polled := httptest.NewRecorder()
	handler.ServeHTTP(polled, poll)
	if polled.Code != http.StatusOK {
		t.Fatalf("poll status %d", polled.Code)
	}
	payload := openConnectionResult(t, secondInput.RequestID, clientPrivate, polled.Body.Bytes())
	if payload.BoxID != state.BoxID || payload.GrantToken == "" || payload.Profile.DisplayName != "Rob's Home Box" {
		t.Fatalf("unexpected handoff: %+v", payload)
	}
	if len(payload.Profile.Services) != 6 || payload.Profile.Services[2].Kind != "device-sync" || payload.Profile.Services[2].Status != ServiceAvailable {
		t.Fatalf("authenticated service catalog is incomplete: %+v", payload.Profile.Services)
	}
	_, _, replayBody := testConnectionRequest(t, now, "Replay device")
	var replayInput createConnectionRequestBody
	if err := json.Unmarshal(replayBody, &replayInput); err != nil {
		t.Fatal(err)
	}
	replayInput.AuthorizationCode = authorizationCode
	replayBody, _ = json.Marshal(replayInput)
	replayRequest := httptest.NewRequest(http.MethodPost, "/v1/connection-invitations/redeem", bytes.NewReader(replayBody))
	replayRequest.Header.Set("Content-Type", "application/json")
	replay := httptest.NewRecorder()
	handler.ServeHTTP(replay, replayRequest)
	if replay.Code != http.StatusUnauthorized {
		t.Fatalf("used code replay status %d: %s", replay.Code, replay.Body.String())
	}
	if grants, err := store.ListGrants(context.Background()); err != nil || len(grants) != 2 {
		t.Fatalf("code replay changed grants: %+v, %v", grants, err)
	}

	admission := httptest.NewRequest(http.MethodPost, "/v1/services/device-sync/account-admissions", strings.NewReader("{}"))
	admission.Header.Set("Authorization", "Bearer "+payload.GrantToken)
	admission.Header.Set("Content-Type", "application/json")
	issued := httptest.NewRecorder()
	handler.ServeHTTP(issued, admission)
	if issued.Code != http.StatusCreated || deviceSync.issueCount != 1 {
		t.Fatalf("member bootstrap status %d, count %d: %s", issued.Code, deviceSync.issueCount, issued.Body.String())
	}
	var issuedBody struct {
		BoxID     uuid.UUID       `json:"boxID"`
		Bootstrap json.RawMessage `json:"bootstrap"`
	}
	if err := json.Unmarshal(issued.Body.Bytes(), &issuedBody); err != nil || issuedBody.BoxID != state.BoxID || !bytes.Equal(issuedBody.Bootstrap, deviceSync.bootstrap) {
		t.Fatalf("unexpected member bootstrap: %+v, %v", issuedBody, err)
	}
	unauthorizedAdmission := httptest.NewRecorder()
	handler.ServeHTTP(unauthorizedAdmission, httptest.NewRequest(http.MethodPost, "/v1/services/device-sync/account-admissions", strings.NewReader("{}")))
	if unauthorizedAdmission.Code != http.StatusUnauthorized || deviceSync.issueCount != 1 {
		t.Fatalf("unauthorized bootstrap was not rejected: %d, count %d", unauthorizedAdmission.Code, deviceSync.issueCount)
	}

	groupsRequest := httptest.NewRequest(http.MethodGet, "/v1/services/device-sync/groups", nil)
	groupsRequest.Header.Set("Authorization", "Bearer "+payload.GrantToken)
	groupsResponse := httptest.NewRecorder()
	handler.ServeHTTP(groupsResponse, groupsRequest)
	if groupsResponse.Code != http.StatusOK {
		t.Fatalf("member group catalog status %d: %s", groupsResponse.Code, groupsResponse.Body.String())
	}
	var groupCatalog struct {
		BoxID  uuid.UUID         `json:"boxID"`
		Groups []DeviceSyncGroup `json:"groups"`
	}
	if err := json.Unmarshal(groupsResponse.Body.Bytes(), &groupCatalog); err != nil ||
		groupCatalog.BoxID != state.BoxID || len(groupCatalog.Groups) != 1 ||
		groupCatalog.Groups[0] != deviceSync.groups[0] {
		t.Fatalf("unexpected member group catalog: %+v, %v", groupCatalog, err)
	}
	unauthorizedGroups := httptest.NewRecorder()
	handler.ServeHTTP(unauthorizedGroups, httptest.NewRequest(http.MethodGet, "/v1/services/device-sync/groups", nil))
	if unauthorizedGroups.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized group catalog was not rejected: %d", unauthorizedGroups.Code)
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
	if bytes.Contains(manifestBytes, []byte("deviceSyncGroups")) ||
		bytes.Contains(manifestBytes, []byte(deviceSync.groups[0].DisplayName)) ||
		bytes.Contains(manifestBytes, []byte(deviceSync.groups[0].SetDiscriminator)) ||
		bytes.Contains(manifestBytes, []byte("device-sync-secret")) {
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
		// The client is 500 ms ahead and asks for the documented one-hour claim lifetime.
		ExpiresAtMillis: now.Add(ClaimRequestLifetime + 500*time.Millisecond).UnixMilli(),
	})
	create := httptest.NewRequest(http.MethodPost, "/v1/claim-connection-requests", bytes.NewReader(createBody))
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
	if stored.CreatedAt != now || stored.ExpiresAt != now.Add(ClaimRequestLifetime) {
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
		AuthorizedAt:       now,
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

func TestUnclaimedBoxRejectsInvitationRedemption(t *testing.T) {
	withFastArgon(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	store := initializedMemoryStore(t, "UNCLAIMED-BOX-CODE")
	service := makeTestService(t, store, &testDeviceSyncController{}, now)
	request := httptest.NewRequest(http.MethodPost, "/v1/connection-invitations/redeem", strings.NewReader(`{}`))
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

func testConnectionRequest(
	t *testing.T,
	now time.Time,
	deviceName string,
) (*ecdh.PrivateKey, string, []byte) {
	t.Helper()
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pollToken, pollDigest, err := RandomToken(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(createConnectionRequestBody{
		Version: SchemaVersion, RequestID: uuid.New(),
		PollTokenDigest: base64.RawURLEncoding.EncodeToString(pollDigest[:]),
		ClientPublicKey: base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes()),
		DeviceName:      deviceName,
		ExpiresAtMillis: now.Add(5 * time.Minute).UnixMilli(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return privateKey, pollToken, body
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
