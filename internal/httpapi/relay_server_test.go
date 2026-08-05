package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/rendezvous"
)

func TestRelayAPICreatesDomainDeliversAndRevokesWithoutLoggingSecrets(t *testing.T) {
	operatorToken := relayTestToken(192)
	var logs bytes.Buffer
	server, err := NewWithRelay(
		rendezvous.NewMemoryStore(),
		relay.NewMemoryStore(),
		slog.New(slog.NewJSONHandler(&logs, nil)),
		operatorToken,
	)
	if err != nil {
		t.Fatal(err)
	}
	server.now = func() time.Time { return time.UnixMilli(1_500) }
	handler := server.Handler()

	wrongOperator := performRelayJSON(
		t,
		handler,
		http.MethodPost,
		"/v1/relay/domains",
		nil,
		relayTestToken(160),
		uuid.Nil,
	)
	requireStatus(t, wrongOperator, http.StatusUnauthorized)

	create := performRelayJSON(
		t,
		handler,
		http.MethodPost,
		"/v1/relay/domains",
		nil,
		operatorToken,
		uuid.Nil,
	)
	requireStatus(t, create, http.StatusCreated)
	var created struct {
		Domain                   relay.DomainRegistration `json:"domain"`
		AdministrationCredential struct {
			AuthorizationToken string `json:"authorizationToken"`
		} `json:"administrationCredential"`
		Member           relay.MemberRegistration `json:"member"`
		MemberCredential relayMemberCredential    `json:"memberCredential"`
	}
	if err := json.NewDecoder(create.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	_ = create.Body.Close()
	if created.Domain.TenantID == uuid.Nil || created.Domain.DomainID == uuid.Nil ||
		created.Member.MemberID == uuid.Nil ||
		created.AdministrationCredential.AuthorizationToken == "" ||
		created.MemberCredential.AuthorizationToken == "" {
		t.Fatalf("incomplete domain creation response: %+v", created)
	}

	basePath := "/v1/relay/tenants/" + created.Domain.TenantID.String() +
		"/domains/" + created.Domain.DomainID.String()
	createMember := performRelayJSON(
		t,
		handler,
		http.MethodPost,
		basePath+"/members",
		map[string]any{
			"capabilities": []string{"message_fetch", "message_acknowledge"},
		},
		created.AdministrationCredential.AuthorizationToken,
		uuid.Nil,
	)
	requireStatus(t, createMember, http.StatusCreated)
	var recipient struct {
		Member     relay.MemberRegistration `json:"member"`
		Credential relayMemberCredential    `json:"credential"`
	}
	if err := json.NewDecoder(createMember.Body).Decode(&recipient); err != nil {
		t.Fatal(err)
	}
	_ = createMember.Body.Close()
	if len(recipient.Member.Capabilities) != 2 ||
		recipient.Member.Capabilities[0] != relay.CapabilityAcknowledgeMessage ||
		recipient.Member.Capabilities[1] != relay.CapabilityFetchMessage {
		t.Fatalf("capabilities were not normalized: %v", recipient.Member.Capabilities)
	}

	envelope := relay.Envelope{
		Version:               relay.SchemaVersion,
		Algorithm:             relay.EnvelopeAlgorithm,
		TenantID:              created.Domain.TenantID,
		DomainID:              created.Domain.DomainID,
		MessageID:             uuid.New(),
		PublisherMemberID:     created.Member.MemberID,
		KeyEpoch:              1,
		CreatedAtMilliseconds: 1_500,
		Nonce:                 base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xa1}, 12)),
		Ciphertext:            base64.RawURLEncoding.EncodeToString([]byte("opaque-relay-api-payload")),
		AuthenticationTag:     base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xb2}, 16)),
	}
	publishPath := basePath + "/messages/" + envelope.MessageID.String()
	publish := performRelayJSON(
		t,
		handler,
		http.MethodPut,
		publishPath,
		envelope,
		created.MemberCredential.AuthorizationToken,
		created.Member.MemberID,
	)
	requireStatus(t, publish, http.StatusCreated)
	retry := performRelayJSON(
		t,
		handler,
		http.MethodPut,
		publishPath,
		envelope,
		created.MemberCredential.AuthorizationToken,
		created.Member.MemberID,
	)
	requireStatus(t, retry, http.StatusOK)

	fetch := performRelayJSON(
		t,
		handler,
		http.MethodGet,
		basePath+"/messages?limit=10",
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
		t.Fatalf("unexpected fetch: %+v", fetched)
	}

	appliedFirst := performRelayJSON(
		t,
		handler,
		http.MethodPost,
		publishPath+"/acknowledgments",
		map[string]string{"stage": "applied"},
		recipient.Credential.AuthorizationToken,
		recipient.Member.MemberID,
	)
	requireStatus(t, appliedFirst, http.StatusConflict)
	for _, stage := range []string{"accepted", "applied"} {
		response := performRelayJSON(
			t,
			handler,
			http.MethodPost,
			publishPath+"/acknowledgments",
			map[string]string{"stage": stage},
			recipient.Credential.AuthorizationToken,
			recipient.Member.MemberID,
		)
		requireStatus(t, response, http.StatusOK)
	}

	revoke := performRelayJSON(
		t,
		handler,
		http.MethodPost,
		basePath+"/members/"+recipient.Member.MemberID.String()+"/revocation",
		nil,
		created.AdministrationCredential.AuthorizationToken,
		uuid.Nil,
	)
	requireStatus(t, revoke, http.StatusOK)
	blocked := performRelayJSON(
		t,
		handler,
		http.MethodGet,
		basePath+"/messages",
		nil,
		recipient.Credential.AuthorizationToken,
		recipient.Member.MemberID,
	)
	requireStatus(t, blocked, http.StatusForbidden)

	logText := logs.String()
	for _, protected := range []string{
		operatorToken,
		created.AdministrationCredential.AuthorizationToken,
		created.MemberCredential.AuthorizationToken,
		recipient.Credential.AuthorizationToken,
		envelope.Ciphertext,
	} {
		if strings.Contains(logText, protected) {
			t.Fatalf("logs contain protected material %q", protected)
		}
	}
	if !strings.Contains(
		logText,
		`"pattern":"PUT /v1/relay/tenants/{tenantID}/domains/{domainID}/messages/{messageID}"`,
	) {
		t.Fatalf("logs did not use the bounded relay pattern: %s", logText)
	}
}

func TestRelayDomainProvisioningEndpointIsAbsentWithoutOperatorToken(t *testing.T) {
	server, err := NewWithRelay(
		rendezvous.NewMemoryStore(),
		relay.NewMemoryStore(),
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		"",
	)
	if err != nil {
		t.Fatal(err)
	}
	response := performRelayJSON(
		t,
		server.Handler(),
		http.MethodPost,
		"/v1/relay/domains",
		nil,
		relayTestToken(192),
		uuid.Nil,
	)
	requireStatus(t, response, http.StatusNotFound)
}

func performRelayJSON(
	t *testing.T,
	handler http.Handler,
	method string,
	path string,
	body any,
	token string,
	memberID uuid.UUID,
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
	if memberID != uuid.Nil {
		request.Header.Set("X-Facets-Member-ID", memberID.String())
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder.Result()
}

func relayTestToken(seed byte) string {
	value := make([]byte, 32)
	for index := range value {
		value[index] = seed + byte(index)
	}
	return base64.RawURLEncoding.EncodeToString(value)
}
