package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/robreuss/FacetsNode/internal/rendezvous"
	"github.com/robreuss/FacetsNode/internal/testfixture"
)

func TestHealthResponsesIdentifyTheRunningService(t *testing.T) {
	server := New(
		rendezvous.NewMemoryStore(),
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	server.SetServiceIdentity("facets-device-sync-server")

	for _, path := range []string{"/livez", "/readyz"} {
		response := performJSON(t, server.Handler(), http.MethodGet, path, nil, "", "")
		requireStatus(t, response, http.StatusOK)
		var body struct {
			Status  string `json:"status"`
			Service string `json:"service"`
		}
		if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.Service != "facets-device-sync-server" {
			t.Fatalf("%s service=%q", path, body.Service)
		}
	}
}

func TestPairingAPIReproducesOpaqueMailboxFlowWithoutLoggingSecrets(t *testing.T) {
	fixture, err := testfixture.LoadRendezvous()
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	server := New(
		rendezvous.NewMemoryStore(),
		slog.New(slog.NewJSONHandler(&logs, nil)),
	)
	server.now = func() time.Time { return time.UnixMilli(3_000) }
	handler := server.Handler()

	create := performJSON(
		t,
		handler,
		http.MethodPost,
		"/v1/pairing/routes",
		fixture.Registration,
		fixture.SponsorAccess.RouterAuthorizationToken,
		rendezvous.RoleSponsor,
	)
	requireStatus(t, create, http.StatusCreated)

	publishPath := "/v1/pairing/routes/" + fixture.Registration.RouteID.String() +
		"/messages/" + fixture.Envelope.MessageID.String()
	publish := performJSON(
		t,
		handler,
		http.MethodPut,
		publishPath,
		fixture.Envelope,
		fixture.CandidateAccess.RouterAuthorizationToken,
		rendezvous.RoleCandidate,
	)
	requireStatus(t, publish, http.StatusCreated)
	retry := performJSON(
		t,
		handler,
		http.MethodPut,
		publishPath,
		fixture.Envelope,
		fixture.CandidateAccess.RouterAuthorizationToken,
		rendezvous.RoleCandidate,
	)
	requireStatus(t, retry, http.StatusOK)

	fetchPath := "/v1/pairing/routes/" + fixture.Registration.RouteID.String() + "/messages"
	fetch := performJSON(
		t,
		handler,
		http.MethodGet,
		fetchPath,
		nil,
		fixture.SponsorAccess.RouterAuthorizationToken,
		rendezvous.RoleSponsor,
	)
	requireStatus(t, fetch, http.StatusOK)
	var fetched struct {
		Envelopes []rendezvous.Envelope `json:"envelopes"`
	}
	if err := json.NewDecoder(fetch.Body).Decode(&fetched); err != nil {
		t.Fatal(err)
	}
	if len(fetched.Envelopes) != 1 || fetched.Envelopes[0] != fixture.Envelope {
		t.Fatalf("unexpected fetch response: %#v", fetched.Envelopes)
	}

	acknowledge := performJSON(
		t,
		handler,
		http.MethodPost,
		publishPath+"/acknowledgement",
		nil,
		fixture.SponsorAccess.RouterAuthorizationToken,
		rendezvous.RoleSponsor,
	)
	requireStatus(t, acknowledge, http.StatusNoContent)

	unauthorized := performJSON(
		t,
		handler,
		http.MethodGet,
		fetchPath,
		nil,
		fixture.CandidateAccess.RouterAuthorizationToken+"x",
		rendezvous.RoleCandidate,
	)
	requireStatus(t, unauthorized, http.StatusUnauthorized)

	logText := logs.String()
	for _, secret := range []string{
		fixture.SponsorAccess.RouterAuthorizationToken,
		fixture.CandidateAccess.RouterAuthorizationToken,
		fixture.SponsorAccess.EncryptionKeyMaterial,
		fixture.Envelope.Ciphertext,
	} {
		if strings.Contains(logText, secret) {
			t.Fatalf("logs contain protected material %q", secret)
		}
	}
	if !strings.Contains(logText, `"pattern":"PUT /v1/pairing/routes/{routeID}/messages/{messageID}"`) {
		t.Fatalf("logs did not use the bounded route pattern: %s", logText)
	}
}

func TestAPIRejectsUnknownJSONFieldsAndOversizedBodies(t *testing.T) {
	server := New(
		rendezvous.NewMemoryStore(),
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	handler := server.Handler()

	unknown := httptest.NewRequest(
		http.MethodPost,
		"/v1/pairing/routes",
		strings.NewReader(`{"version":1,"unknown":true}`),
	)
	unknown.Header.Set("Content-Type", "application/json")
	unknownRecorder := httptest.NewRecorder()
	handler.ServeHTTP(unknownRecorder, unknown)
	requireStatus(t, unknownRecorder.Result(), http.StatusBadRequest)

	oversized := httptest.NewRequest(
		http.MethodPost,
		"/v1/pairing/routes",
		strings.NewReader(`{"padding":"`+strings.Repeat("a", maximumRequestByteCount)+`"}`),
	)
	oversized.Header.Set("Content-Type", "application/json")
	oversizedRecorder := httptest.NewRecorder()
	handler.ServeHTTP(oversizedRecorder, oversized)
	requireStatus(t, oversizedRecorder.Result(), http.StatusBadRequest)
}

func performJSON(
	t *testing.T,
	handler http.Handler,
	method string,
	path string,
	body any,
	token string,
	role rendezvous.Role,
) *http.Response {
	t.Helper()
	var requestBody io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		requestBody = bytes.NewReader(encoded)
	}
	request := httptest.NewRequest(method, path, requestBody)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-Facets-Rendezvous-Role", string(role))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder.Result()
}

func requireStatus(t *testing.T, response *http.Response, expected int) {
	t.Helper()
	if response.StatusCode != expected {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("status=%d body=%s; want %d", response.StatusCode, body, expected)
	}
}
