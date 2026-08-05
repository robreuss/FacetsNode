package integration_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/rendezvous"
)

func TestLivePairingRendezvousRoundTrip(t *testing.T) {
	baseURL := strings.TrimRight(os.Getenv("FACETS_NODE_TEST_BASE_URL"), "/")
	if baseURL == "" {
		t.Skip("FACETS_NODE_TEST_BASE_URL is not set")
	}
	now := time.Now().UnixMilli()
	routeID := uuid.New()
	sponsorToken := encodedBytes(0)
	candidateToken := encodedBytes(32)
	sponsorDigest, err := rendezvous.AuthorizationDigest(
		sponsorToken, routeID, rendezvous.RoleSponsor,
	)
	if err != nil {
		t.Fatal(err)
	}
	candidateDigest, err := rendezvous.AuthorizationDigest(
		candidateToken, routeID, rendezvous.RoleCandidate,
	)
	if err != nil {
		t.Fatal(err)
	}
	registration := rendezvous.Registration{
		Version:                      rendezvous.SchemaVersion,
		RouteID:                      routeID,
		SponsorAuthorizationDigest:   sponsorDigest,
		CandidateAuthorizationDigest: candidateDigest,
		CreatedAtMilliseconds:        now - 1_000,
		ExpiresAtMilliseconds:        now + 120_000,
	}
	envelope := rendezvous.Envelope{
		Version:               rendezvous.SchemaVersion,
		Algorithm:             rendezvous.EnvelopeAlgorithm,
		RouteID:               routeID,
		MessageID:             uuid.New(),
		CreatedAtMilliseconds: now,
		ExpiresAtMilliseconds: now + 60_000,
		Nonce:                 base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xa1}, 12)),
		Ciphertext:            base64.RawURLEncoding.EncodeToString([]byte("opaque-live-smoke-payload")),
		AuthenticationTag:     base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xb2}, 16)),
	}
	client := &http.Client{Timeout: 5 * time.Second}

	createURL := baseURL + "/v1/pairing/routes"
	requireStatusAndClose(t, requestJSON(
		t, client, http.MethodPost, createURL, registration,
		sponsorToken, rendezvous.RoleSponsor,
	), http.StatusCreated)

	publishURL := fmt.Sprintf(
		"%s/v1/pairing/routes/%s/messages/%s",
		baseURL, routeID, envelope.MessageID,
	)
	requireStatusAndClose(t, requestJSON(
		t, client, http.MethodPut, publishURL, envelope,
		candidateToken, rendezvous.RoleCandidate,
	), http.StatusCreated)
	requireStatusAndClose(t, requestJSON(
		t, client, http.MethodPut, publishURL, envelope,
		candidateToken, rendezvous.RoleCandidate,
	), http.StatusOK)

	fetchURL := fmt.Sprintf("%s/v1/pairing/routes/%s/messages", baseURL, routeID)
	fetch := requestJSON(
		t, client, http.MethodGet, fetchURL, nil,
		sponsorToken, rendezvous.RoleSponsor,
	)
	requireStatus(t, fetch, http.StatusOK)
	var fetched struct {
		Envelopes []rendezvous.Envelope `json:"envelopes"`
	}
	if err := json.NewDecoder(fetch.Body).Decode(&fetched); err != nil {
		t.Fatal(err)
	}
	_ = fetch.Body.Close()
	if len(fetched.Envelopes) != 1 || fetched.Envelopes[0] != envelope {
		t.Fatalf("live fetch mismatch: %#v", fetched.Envelopes)
	}

	requireStatusAndClose(t, requestJSON(
		t, client, http.MethodPost, publishURL+"/acknowledgement", nil,
		sponsorToken, rendezvous.RoleSponsor,
	), http.StatusNoContent)
	fetch = requestJSON(
		t, client, http.MethodGet, fetchURL, nil,
		sponsorToken, rendezvous.RoleSponsor,
	)
	requireStatus(t, fetch, http.StatusOK)
	if err := json.NewDecoder(fetch.Body).Decode(&fetched); err != nil {
		t.Fatal(err)
	}
	_ = fetch.Body.Close()
	if len(fetched.Envelopes) != 0 {
		t.Fatalf("acknowledged message returned again: %#v", fetched.Envelopes)
	}

	closeURL := fmt.Sprintf("%s/v1/pairing/routes/%s/close", baseURL, routeID)
	requireStatusAndClose(t, requestJSON(
		t, client, http.MethodPost, closeURL, nil,
		sponsorToken, rendezvous.RoleSponsor,
	), http.StatusNoContent)
	requireStatusAndClose(t, requestJSON(
		t, client, http.MethodPut, publishURL, envelope,
		candidateToken, rendezvous.RoleCandidate,
	), http.StatusOK)
}

func requestJSON(
	t *testing.T,
	client *http.Client,
	method string,
	url string,
	body any,
	token string,
	role rendezvous.Role,
) *http.Response {
	t.Helper()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-Facets-Rendezvous-Role", string(role))
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func requireStatus(t *testing.T, response *http.Response, expected int) {
	t.Helper()
	if response.StatusCode != expected {
		body, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		t.Fatalf("status=%d body=%s; want=%d", response.StatusCode, body, expected)
	}
}

func requireStatusAndClose(t *testing.T, response *http.Response, expected int) {
	t.Helper()
	requireStatus(t, response, expected)
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
}

func encodedBytes(start byte) string {
	value := make([]byte, 32)
	for index := range value {
		value[index] = start + byte(index)
	}
	return base64.RawURLEncoding.EncodeToString(value)
}
