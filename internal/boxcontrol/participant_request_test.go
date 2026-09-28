package boxcontrol

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func participantRequestFixture(t *testing.T) (participantFixture, *MemoryStore, BoxParticipantEnrollmentRequest, string) {
	t.Helper()
	fixture := newParticipantFixture(t)
	store := NewMemoryStore()
	ctx := context.Background()
	if err := store.Initialize(ctx, State{BoxID: fixture.anchor.BoxID, ActivationVerifier: "activation"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Claim(ctx, "activation", "owner", "Box", time.UnixMilli(fixture.now)); err != nil {
		t.Fatal(err)
	}
	grantToken, grantDigest, err := RandomToken(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	connectionID := uuid.New()
	if err := store.CreateGrant(ctx, ConnectionGrant{
		GrantID: connectionID, TokenDigest: grantDigest, DeviceName: "Connected test Mac",
		CreatedAt: time.UnixMilli(fixture.now), LastSeenAt: time.UnixMilli(fixture.now),
		ExpiresAt: time.UnixMilli(fixture.now).Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	enrollment := BoxParticipantEnrollment{Anchor: fixture.anchor, Device: fixture.device,
		RootRecord: fixture.root, GrantRecord: fixture.grant}
	enrollment.Anchor.ApprovedAtMilliseconds = 0
	requestedAt := fixture.now - 100
	request := BoxParticipantEnrollmentRequest{
		RequestID: fixture.challengeID, ConnectionGrantID: connectionID,
		Enrollment: enrollment, Presentation: BoxParticipantPresentation{
			ParticipantID: fixture.anchor.ParticipantID, DisplayName: "Sue", Revision: 1,
		}, Proof: fixture.proof, RequestedAtMillis: requestedAt,
		ExpiresAtMillis: requestedAt + participantRequestLifetimeMilliseconds, Decision: "pending",
	}
	var proofFields map[string]json.RawMessage
	if err := json.Unmarshal(request.Proof.Payload, &proofFields); err != nil {
		t.Fatal(err)
	}
	encodedDigest, err := json.Marshal(participantPresentationDigest(request.Presentation))
	if err != nil {
		t.Fatal(err)
	}
	proofFields["presentationDigest"] = encodedDigest
	request.Proof.Payload, err = json.Marshal(proofFields)
	if err != nil {
		t.Fatal(err)
	}
	request.Proof.Signature = signParticipantBytes(t, fixture.deviceKey, participantProofDomain, request.Proof.Payload)
	return fixture, store, request, grantToken
}

func TestParticipantRequestStoreApprovalRequiresLiveGrantAndExactSignedProof(t *testing.T) {
	fixture, store, request, _ := participantRequestFixture(t)
	ctx := context.Background()
	if err := store.CreateParticipantEnrollmentRequest(ctx, request, fixture.now); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateParticipantEnrollmentRequest(ctx, request, fixture.now); err != nil {
		t.Fatalf("exact retry: %v", err)
	}
	other := cloneParticipantRequest(request)
	other.Presentation.DisplayName = "Impostor"
	if err := store.CreateParticipantEnrollmentRequest(ctx, other, fixture.now); !errors.Is(err, ErrParticipantAuthority) {
		t.Fatalf("changed retry: %v", err)
	}
	other = cloneParticipantRequest(request)
	other.RequestID = uuid.New()
	other.Presentation.DisplayName = "Impostor"
	if err := store.CreateParticipantEnrollmentRequest(ctx, other, fixture.now); !errors.Is(err, ErrParticipantAuthority) {
		t.Fatalf("presentation substitution: %v", err)
	}
	other = cloneParticipantRequest(request)
	other.RequestID = uuid.New()
	if err := store.CreateParticipantEnrollmentRequest(ctx, other, fixture.now); !errors.Is(err, ErrParticipantAuthority) {
		t.Fatalf("proof replay under new ID: %v", err)
	}
	other = cloneParticipantRequest(request)
	other.RequestID = uuid.New()
	other.Proof.Signature = "bad"
	if err := store.CreateParticipantEnrollmentRequest(ctx, other, fixture.now); !errors.Is(err, ErrParticipantAuthority) {
		t.Fatalf("bad signature: %v", err)
	}
	if _, err := store.ParticipantEnrollmentRequest(ctx, request.RequestID, uuid.New(), fixture.now); !errors.Is(err, ErrParticipantAuthority) {
		t.Fatalf("other connection read: %v", err)
	}
	if err := store.DecideParticipantEnrollmentRequest(ctx, uuid.New(), request.RequestID, true, fixture.now); !errors.Is(err, ErrParticipantAuthority) {
		t.Fatalf("wrong Box approved: %v", err)
	}
	if err := store.DecideParticipantEnrollmentRequest(ctx, fixture.anchor.BoxID, request.RequestID, true, fixture.now); err != nil {
		t.Fatal(err)
	}
	status, err := store.ParticipantEnrollmentRequest(ctx, request.RequestID, request.ConnectionGrantID, fixture.now)
	if err != nil || status.Decision != "approved" {
		t.Fatalf("approved status: %v %+v", err, status)
	}
	if _, err := store.PinnedParticipant(ctx, fixture.anchor.BoxID, fixture.anchor.ParticipantID, fixture.device.DeviceID); err != nil {
		t.Fatal(err)
	}
	if err := store.DecideParticipantEnrollmentRequest(ctx, fixture.anchor.BoxID, request.RequestID, true, fixture.now); !errors.Is(err, ErrParticipantAuthority) {
		t.Fatalf("second decision: %v", err)
	}
}

func TestParticipantRequestStoreExpiryAndConnectionRevocation(t *testing.T) {
	fixture, store, request, _ := participantRequestFixture(t)
	ctx := context.Background()
	if err := store.CreateParticipantEnrollmentRequest(ctx, request, fixture.now); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeGrant(ctx, request.ConnectionGrantID, time.UnixMilli(fixture.now+1)); err != nil {
		t.Fatal(err)
	}
	pending, err := store.PendingParticipantEnrollmentRequests(ctx, fixture.anchor.BoxID, fixture.now+1)
	if err != nil || len(pending) != 0 {
		t.Fatalf("revoked grant remained pending: %v %+v", err, pending)
	}
	if err := store.DecideParticipantEnrollmentRequest(ctx, fixture.anchor.BoxID, request.RequestID, true, fixture.now+1); !errors.Is(err, ErrParticipantAuthority) {
		t.Fatalf("revoked grant approved: %v", err)
	}
	_, otherStore, otherRequest, _ := participantRequestFixture(t)
	if err := otherStore.CreateParticipantEnrollmentRequest(ctx, otherRequest, fixture.now); err != nil {
		t.Fatal(err)
	}
	status, err := otherStore.ParticipantEnrollmentRequest(ctx, otherRequest.RequestID,
		otherRequest.ConnectionGrantID, otherRequest.ExpiresAtMillis)
	if err != nil || status.Decision != "expired" {
		t.Fatalf("expiry status: %v %+v", err, status)
	}
	if err := otherStore.DecideParticipantEnrollmentRequest(ctx, otherRequest.Enrollment.Anchor.BoxID,
		otherRequest.RequestID, true, otherRequest.ExpiresAtMillis); !errors.Is(err, ErrParticipantAuthority) {
		t.Fatalf("expired request approved: %v", err)
	}
}

func TestParticipantRequestRejectionDoesNotPinAndPendingCapacityIsBounded(t *testing.T) {
	fixture, store, request, _ := participantRequestFixture(t)
	ctx := context.Background()
	if err := store.CreateParticipantEnrollmentRequest(ctx, request, fixture.now); err != nil {
		t.Fatal(err)
	}
	if err := store.DecideParticipantEnrollmentRequest(ctx, fixture.anchor.BoxID, request.RequestID, false, fixture.now); err != nil {
		t.Fatal(err)
	}
	status, err := store.ParticipantEnrollmentRequest(ctx, request.RequestID, request.ConnectionGrantID, fixture.now)
	if err != nil || status.Decision != "rejected" {
		t.Fatalf("rejected status: %v %+v", err, status)
	}
	if _, err := store.PinnedParticipant(ctx, fixture.anchor.BoxID, fixture.anchor.ParticipantID, fixture.device.DeviceID); !errors.Is(err, ErrParticipantAuthority) {
		t.Fatalf("rejected request pinned: %v", err)
	}
	// Capacity is checked before storing new signed submissions. Populate only
	// the pending-accounting map here; cryptographic validity is tested above.
	for index := 0; index < maximumPendingRequestsPerConnection; index++ {
		pending := cloneParticipantRequest(request)
		pending.RequestID = uuid.New()
		pending.Decision = "pending"
		store.participantRequests[pending.RequestID] = pending
	}
	if err := store.CreateParticipantEnrollmentRequest(ctx, request, fixture.now); err != nil {
		t.Fatalf("exact retry blocked by capacity: %v", err)
	}
	newRequest := cloneParticipantRequest(request)
	newRequest.RequestID = uuid.New()
	newRequest.Decision = "pending"
	if err := store.CreateParticipantEnrollmentRequest(ctx, newRequest, fixture.now); !errors.Is(err, ErrParticipantAuthority) {
		t.Fatalf("pending capacity not enforced: %v", err)
	}
}

func TestParticipantRequestHTTPNeedsAppProofAndOwnerApproval(t *testing.T) {
	fixture, store, proposal, grantToken := participantRequestFixture(t)
	now := time.UnixMilli(fixture.now)
	service := makeTestService(t, store, &testDeviceSyncController{}, now)
	handler := service.Handler()
	ownerToken, ownerDigest, err := RandomToken(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrf, csrfDigest, err := RandomToken(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateWebSession(context.Background(), WebSession{
		TokenDigest: ownerDigest, CSRFDigest: csrfDigest, CreatedAt: now,
		LastSeenAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(participantEnrollmentRequestBody{
		Version: 1, RequestID: proposal.RequestID, Enrollment: proposal.Enrollment,
		Presentation: proposal.Presentation, Proof: proposal.Proof,
		RequestedAtMillis: proposal.RequestedAtMillis, ExpiresAtMillis: proposal.ExpiresAtMillis,
	})
	if err != nil {
		t.Fatal(err)
	}
	submit := func(token string, payload []byte) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/v1/participant-enrollment-requests", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		return out
	}
	if result := submit("", body); result.Code != http.StatusUnauthorized {
		t.Fatalf("no app grant: %d", result.Code)
	}
	if result := submit(grantToken, body); result.Code != http.StatusAccepted {
		t.Fatalf("submit: %d %s", result.Code, result.Body.String())
	}
	if result := submit(grantToken, body); result.Code != http.StatusAccepted {
		t.Fatalf("exact retry: %d", result.Code)
	}
	statusPath := "/v1/participant-enrollment-requests/" + proposal.RequestID.String()
	status := func(token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, statusPath, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		return out
	}
	if result := status(""); result.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous status: %d", result.Code)
	}
	if result := status(grantToken); result.Code != http.StatusOK || !strings.Contains(result.Body.String(), `"decision":"pending"`) {
		t.Fatalf("pending status: %d %s", result.Code, result.Body.String())
	}
	page := func(authenticated bool) string {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if authenticated {
			req.AddCookie(&http.Cookie{Name: "facets_box_session", Value: ownerToken})
			req.AddCookie(&http.Cookie{Name: "facets_box_csrf", Value: csrf})
		}
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		if out.Code != http.StatusOK {
			t.Fatalf("owner page: %d", out.Code)
		}
		return out.Body.String()
	}
	if strings.Contains(page(false), proposal.RequestID.String()) {
		t.Fatal("anonymous page exposed pending request")
	}
	if ownerPage := page(true); !strings.Contains(ownerPage, "Sue") || !strings.Contains(ownerPage, "Connected test Mac") || !strings.Contains(ownerPage, proposal.RequestID.String()) {
		t.Fatal("owner page omitted request")
	}
	path := "/v1/owner/participant-enrollment-requests/" + proposal.RequestID.String() + "/approve"
	decide := func(authenticated bool, formCSRF string) *httptest.ResponseRecorder {
		form := url.Values{"csrf": {formCSRF}}
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if authenticated {
			req.AddCookie(&http.Cookie{Name: "facets_box_session", Value: ownerToken})
			req.AddCookie(&http.Cookie{Name: "facets_box_csrf", Value: csrf})
		}
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		return out
	}
	if result := decide(false, csrf); result.Code != http.StatusBadRequest {
		t.Fatalf("app approval: %d", result.Code)
	}
	if result := decide(true, "wrong"); result.Code != http.StatusBadRequest {
		t.Fatalf("bad CSRF approval: %d", result.Code)
	}
	if result := decide(true, csrf); result.Code != http.StatusSeeOther {
		t.Fatalf("owner approval: %d %s", result.Code, result.Body.String())
	}
	if result := status(grantToken); result.Code != http.StatusOK || !strings.Contains(result.Body.String(), `"decision":"approved"`) {
		t.Fatalf("approved status: %d %s", result.Code, result.Body.String())
	}
	if _, err := store.PinnedParticipant(context.Background(), fixture.anchor.BoxID, fixture.anchor.ParticipantID, fixture.device.DeviceID); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(page(true), ">Approve</button>") {
		t.Fatal("approved request remained actionable")
	}
}

func TestPostgresParticipantRequestSurvivesRestartAndOwnerApprovalPins(t *testing.T) {
	databaseURL := os.Getenv("FACETS_BOX_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("FACETS_BOX_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "participant_request_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	openStore := func() (*PostgresStore, *pgxpool.Pool) {
		pool, err := pgxpool.NewWithConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		return NewPostgresStore(pool), pool
	}
	store, pool := openStore()
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	fixture, _, request, _ := participantRequestFixture(t)
	if err := store.Initialize(ctx, State{BoxID: fixture.anchor.BoxID, ActivationVerifier: "activation"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Claim(ctx, "activation", "owner", "Box", time.UnixMilli(fixture.now)); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateGrant(ctx, ConnectionGrant{
		GrantID: request.ConnectionGrantID, DeviceName: "Connected test Mac",
		CreatedAt: time.UnixMilli(fixture.now), LastSeenAt: time.UnixMilli(fixture.now),
		ExpiresAt: time.UnixMilli(fixture.now).Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateParticipantEnrollmentRequest(ctx, request, fixture.now); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateParticipantEnrollmentRequest(ctx, request, fixture.now); err != nil {
		t.Fatalf("exact retry: %v", err)
	}
	pending, err := store.PendingParticipantEnrollmentRequests(ctx, fixture.anchor.BoxID, fixture.now)
	if err != nil || len(pending) != 1 || pending[0].ConnectionDeviceName != "Connected test Mac" {
		t.Fatalf("pending request: %v %+v", err, pending)
	}
	pool.Close()
	store, pool = openStore()
	defer pool.Close()
	if err := store.DecideParticipantEnrollmentRequest(ctx, fixture.anchor.BoxID, request.RequestID, true, fixture.now); err != nil {
		t.Fatal(err)
	}
	status, err := store.ParticipantEnrollmentRequest(ctx, request.RequestID, request.ConnectionGrantID, fixture.now)
	if err != nil || status.Decision != "approved" {
		t.Fatalf("approved after restart: %v %+v", err, status)
	}
	if _, err := store.PinnedParticipant(ctx, fixture.anchor.BoxID, fixture.anchor.ParticipantID, fixture.device.DeviceID); err != nil {
		t.Fatal(err)
	}
}
