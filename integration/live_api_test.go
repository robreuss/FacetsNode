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

	"github.com/robreuss/FacetsNode/internal/relay"
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

func TestLiveReplicaRelayRoundTripAndRevocation(t *testing.T) {
	baseURL := strings.TrimRight(os.Getenv("FACETS_NODE_TEST_BASE_URL"), "/")
	operatorToken := os.Getenv("FACETS_NODE_TEST_OPERATOR_TOKEN")
	if baseURL == "" || operatorToken == "" {
		t.Skip("FACETS_NODE_TEST_BASE_URL and FACETS_NODE_TEST_OPERATOR_TOKEN are required")
	}
	client := &http.Client{Timeout: 10 * time.Second}
	create := requestRelayJSON(
		t, client, http.MethodPost, baseURL+"/v1/relay/domains", nil,
		operatorToken, uuid.Nil,
	)
	requireStatus(t, create, http.StatusCreated)
	var domain struct {
		Domain                   relay.DomainRegistration `json:"domain"`
		AdministrationCredential struct {
			AuthorizationToken string `json:"authorizationToken"`
		} `json:"administrationCredential"`
		Member           relay.MemberRegistration `json:"member"`
		MemberCredential struct {
			AuthorizationToken string `json:"authorizationToken"`
		} `json:"memberCredential"`
	}
	if err := json.NewDecoder(create.Body).Decode(&domain); err != nil {
		t.Fatal(err)
	}
	_ = create.Body.Close()
	basePath := fmt.Sprintf(
		"%s/v1/relay/tenants/%s/domains/%s",
		baseURL,
		domain.Domain.TenantID,
		domain.Domain.DomainID,
	)
	createMember := requestRelayJSON(
		t,
		client,
		http.MethodPost,
		basePath+"/members",
		map[string]any{
			"capabilities": []string{"message_fetch", "message_acknowledge"},
		},
		domain.AdministrationCredential.AuthorizationToken,
		uuid.Nil,
	)
	requireStatus(t, createMember, http.StatusCreated)
	var recipient struct {
		Member     relay.MemberRegistration `json:"member"`
		Credential struct {
			AuthorizationToken string `json:"authorizationToken"`
		} `json:"credential"`
	}
	if err := json.NewDecoder(createMember.Body).Decode(&recipient); err != nil {
		t.Fatal(err)
	}
	_ = createMember.Body.Close()
	now := time.Now().UnixMilli()
	envelope := relay.Envelope{
		Version:               relay.SchemaVersion,
		Algorithm:             relay.EnvelopeAlgorithm,
		TenantID:              domain.Domain.TenantID,
		DomainID:              domain.Domain.DomainID,
		MessageID:             uuid.New(),
		PublisherMemberID:     domain.Member.MemberID,
		KeyEpoch:              1,
		CreatedAtMilliseconds: now,
		Nonce:                 base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xc3}, 12)),
		Ciphertext:            base64.RawURLEncoding.EncodeToString([]byte("opaque-live-relay-payload")),
		AuthenticationTag:     base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xd4}, 16)),
	}
	publishURL := basePath + "/messages/" + envelope.MessageID.String()
	requireStatusAndClose(t, requestRelayJSON(
		t,
		client,
		http.MethodPut,
		publishURL,
		envelope,
		domain.MemberCredential.AuthorizationToken,
		domain.Member.MemberID,
	), http.StatusCreated)
	fetch := requestRelayJSON(
		t,
		client,
		http.MethodGet,
		basePath+"/messages",
		nil,
		recipient.Credential.AuthorizationToken,
		recipient.Member.MemberID,
	)
	requireStatus(t, fetch, http.StatusOK)
	var fetched struct {
		Messages []relay.Message `json:"messages"`
		Cursor   string          `json:"cursor"`
	}
	if err := json.NewDecoder(fetch.Body).Decode(&fetched); err != nil {
		t.Fatal(err)
	}
	_ = fetch.Body.Close()
	if len(fetched.Messages) != 1 || fetched.Messages[0].Envelope != envelope ||
		fetched.Cursor != relay.EncodeCursor(1) {
		t.Fatalf("live relay fetch mismatch: %+v", fetched)
	}
	for _, stage := range []string{"accepted", "applied"} {
		requireStatusAndClose(t, requestRelayJSON(
			t,
			client,
			http.MethodPost,
			publishURL+"/acknowledgments",
			map[string]string{"stage": stage},
			recipient.Credential.AuthorizationToken,
			recipient.Member.MemberID,
		), http.StatusOK)
	}
	requireStatusAndClose(t, requestRelayJSON(
		t,
		client,
		http.MethodPost,
		basePath+"/members/"+recipient.Member.MemberID.String()+"/revocation",
		nil,
		domain.AdministrationCredential.AuthorizationToken,
		uuid.Nil,
	), http.StatusOK)
	requireStatusAndClose(t, requestRelayJSON(
		t,
		client,
		http.MethodGet,
		basePath+"/messages",
		nil,
		recipient.Credential.AuthorizationToken,
		recipient.Member.MemberID,
	), http.StatusForbidden)
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

func requestRelayJSON(
	t *testing.T,
	client *http.Client,
	method string,
	url string,
	body any,
	token string,
	memberID uuid.UUID,
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
	if memberID != uuid.Nil {
		request.Header.Set("X-Facets-Member-ID", memberID.String())
	}
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
