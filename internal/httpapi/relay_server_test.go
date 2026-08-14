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
	blobContentStore, err := relay.NewFileBlobContentStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewWithRelay(
		rendezvous.NewMemoryStore(),
		relay.NewMemoryStore(),
		blobContentStore,
		slog.New(slog.NewJSONHandler(&logs, nil)),
		operatorToken,
	)
	if err != nil {
		t.Fatal(err)
	}
	server.now = func() time.Time { return time.UnixMilli(1_500) }
	handler := server.Handler()
	provisioning := newRelayDomainProvisioningRequest(1_500, 16, 64)

	wrongOperator := performRelayJSON(
		t,
		handler,
		http.MethodPost,
		"/v1/relay/domains",
		provisioning,
		relayTestToken(160),
		uuid.Nil,
	)
	requireStatus(t, wrongOperator, http.StatusUnauthorized)

	create := performRelayJSON(
		t,
		handler,
		http.MethodPost,
		"/v1/relay/domains",
		provisioning,
		operatorToken,
		uuid.Nil,
	)
	requireStatus(t, create, http.StatusCreated)
	var created struct {
		Acceptance               relay.Acceptance         `json:"acceptance"`
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
	if created.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("unexpected domain acceptance: %q", created.Acceptance)
	}
	provisionRetry := performRelayJSON(
		t,
		handler,
		http.MethodPost,
		"/v1/relay/domains",
		provisioning,
		operatorToken,
		uuid.Nil,
	)
	requireStatus(t, provisionRetry, http.StatusOK)
	var retried struct {
		Acceptance               relay.Acceptance              `json:"acceptance"`
		Domain                   relay.DomainRegistration      `json:"domain"`
		AdministrationCredential relayAdministrationCredential `json:"administrationCredential"`
		Member                   relay.MemberRegistration      `json:"member"`
		MemberCredential         relayMemberCredential         `json:"memberCredential"`
	}
	if err := json.NewDecoder(provisionRetry.Body).Decode(&retried); err != nil {
		t.Fatal(err)
	}
	_ = provisionRetry.Body.Close()
	if retried.Acceptance != relay.AcceptanceDuplicate ||
		retried.Domain != created.Domain ||
		retried.MemberCredential != created.MemberCredential ||
		retried.AdministrationCredential.AuthorizationToken !=
			created.AdministrationCredential.AuthorizationToken {
		t.Fatalf("provisioning retry changed authority: %+v", retried)
	}
	collision := provisioning
	collision.MemberCapabilities = []relay.Capability{
		relay.CapabilityFetchMessage,
	}
	requireStatus(t, performRelayJSON(
		t,
		handler,
		http.MethodPost,
		"/v1/relay/domains",
		collision,
		operatorToken,
		uuid.Nil,
	), http.StatusConflict)

	basePath := "/v1/relay/tenants/" + created.Domain.TenantID.String() +
		"/domains/" + created.Domain.DomainID.String()
	createMember := performRelayJSON(
		t,
		handler,
		http.MethodPost,
		basePath+"/members",
		map[string]any{
			"capabilities": []string{
				"blob_fetch",
				"message_fetch",
				"message_acknowledge",
			},
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
	if len(recipient.Member.Capabilities) != 3 ||
		recipient.Member.Capabilities[0] != relay.CapabilityFetchBlob ||
		recipient.Member.Capabilities[1] != relay.CapabilityAcknowledgeMessage ||
		recipient.Member.Capabilities[2] != relay.CapabilityFetchMessage {
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
	publishedWake := server.relayWakeBroker.subscribe(
		created.Domain.TenantID,
		created.Domain.DomainID,
	)
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
	select {
	case <-publishedWake:
	case <-time.After(time.Second):
		t.Fatal("accepted relay publish did not emit a wake hint")
	}
	retryWake := server.relayWakeBroker.subscribe(
		created.Domain.TenantID,
		created.Domain.DomainID,
	)
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
	select {
	case <-retryWake:
		t.Fatal("duplicate relay publish emitted another wake hint")
	default:
	}
	wake := performRelayJSON(
		t,
		handler,
		http.MethodGet,
		basePath+"/messages/wake?waitMilliseconds=10",
		nil,
		recipient.Credential.AuthorizationToken,
		recipient.Member.MemberID,
	)
	requireStatus(t, wake, http.StatusOK)
	var wakeResponse struct {
		Changed bool `json:"changed"`
	}
	if err := json.NewDecoder(wake.Body).Decode(&wakeResponse); err != nil {
		t.Fatal(err)
	}
	_ = wake.Body.Close()
	if !wakeResponse.Changed {
		t.Fatal("wake response did not report the durable relay message")
	}

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
	quietWake := performRelayJSON(
		t,
		handler,
		http.MethodGet,
		basePath+"/messages/wake?cursor="+fetched.Cursor+
			"&waitMilliseconds=1",
		nil,
		recipient.Credential.AuthorizationToken,
		recipient.Member.MemberID,
	)
	requireStatus(t, quietWake, http.StatusNoContent)
	_ = quietWake.Body.Close()

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

	blobBytes := []byte("opaque independently encrypted blob bytes")
	blobID := relay.BlobID(blobBytes)
	blobPath := basePath + "/blobs/" + blobID
	upload := performRelayBlob(
		t,
		handler,
		http.MethodPut,
		blobPath,
		blobBytes,
		created.MemberCredential.AuthorizationToken,
		created.Member.MemberID,
		"",
	)
	requireStatus(t, upload, http.StatusCreated)
	uploadRetry := performRelayBlob(
		t,
		handler,
		http.MethodPut,
		blobPath,
		blobBytes,
		created.MemberCredential.AuthorizationToken,
		created.Member.MemberID,
		"",
	)
	requireStatus(t, uploadRetry, http.StatusOK)
	download := performRelayBlob(
		t,
		handler,
		http.MethodGet,
		blobPath,
		nil,
		recipient.Credential.AuthorizationToken,
		recipient.Member.MemberID,
		"",
	)
	requireStatus(t, download, http.StatusOK)
	downloaded, err := io.ReadAll(download.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = download.Body.Close()
	if !bytes.Equal(downloaded, blobBytes) || download.Header.Get("ETag") != `"`+blobID+`"` {
		t.Fatalf("blob download mismatch headers=%v bytes=%q", download.Header, downloaded)
	}
	partial := performRelayBlob(
		t,
		handler,
		http.MethodGet,
		blobPath,
		nil,
		recipient.Credential.AuthorizationToken,
		recipient.Member.MemberID,
		"bytes=7-19",
	)
	requireStatus(t, partial, http.StatusPartialContent)
	partialBytes, err := io.ReadAll(partial.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = partial.Body.Close()
	if !bytes.Equal(partialBytes, blobBytes[7:20]) {
		t.Fatalf("partial blob=%q", partialBytes)
	}
	head := performRelayBlob(
		t,
		handler,
		http.MethodHead,
		blobPath,
		nil,
		recipient.Credential.AuthorizationToken,
		recipient.Member.MemberID,
		"",
	)
	requireStatus(t, head, http.StatusOK)
	_ = head.Body.Close()
	if head.ContentLength != int64(len(blobBytes)) {
		t.Fatalf("blob HEAD length=%d", head.ContentLength)
	}
	digestMismatch := performRelayBlob(
		t,
		handler,
		http.MethodPut,
		basePath+"/blobs/"+relay.BlobID([]byte("other")),
		blobBytes,
		created.MemberCredential.AuthorizationToken,
		created.Member.MemberID,
		"",
	)
	requireStatus(t, digestMismatch, http.StatusBadRequest)

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
		string(blobBytes),
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

func performRelayBlob(
	t *testing.T,
	handler http.Handler,
	method string,
	path string,
	body []byte,
	token string,
	memberID uuid.UUID,
	byteRange string,
) *http.Response {
	t.Helper()
	var requestBody io.Reader
	if body != nil {
		requestBody = bytes.NewReader(body)
	}
	request := httptest.NewRequest(method, path, requestBody)
	if body != nil {
		request.Header.Set("Content-Type", "application/octet-stream")
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-Facets-Member-ID", memberID.String())
	if byteRange != "" {
		request.Header.Set("Range", byteRange)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder.Result()
}

func TestRelayDomainProvisioningEndpointIsAbsentWithoutOperatorToken(t *testing.T) {
	server, err := NewWithRelay(
		rendezvous.NewMemoryStore(),
		relay.NewMemoryStore(),
		nil,
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

func TestRelayAdmissionIsOneTimeRetrySafeAndSecretRedacted(t *testing.T) {
	operatorToken := relayTestToken(192)
	var logs bytes.Buffer
	server, err := NewWithRelay(
		rendezvous.NewMemoryStore(),
		relay.NewMemoryStore(),
		nil,
		slog.New(slog.NewJSONHandler(&logs, nil)),
		operatorToken,
	)
	if err != nil {
		t.Fatal(err)
	}
	nowMilliseconds := int64(1_000)
	server.now = func() time.Time { return time.UnixMilli(nowMilliseconds) }
	handler := server.Handler()

	createDomain := performRelayJSON(
		t,
		handler,
		http.MethodPost,
		"/v1/relay/domains",
		newRelayDomainProvisioningRequest(nowMilliseconds, 32, 96),
		operatorToken,
		uuid.Nil,
	)
	requireStatus(t, createDomain, http.StatusCreated)
	var created struct {
		Domain                   relay.DomainRegistration `json:"domain"`
		AdministrationCredential struct {
			AuthorizationToken string `json:"authorizationToken"`
		} `json:"administrationCredential"`
	}
	if err := json.NewDecoder(createDomain.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	_ = createDomain.Body.Close()
	basePath := "/v1/relay/tenants/" + created.Domain.TenantID.String() +
		"/domains/" + created.Domain.DomainID.String()

	admissionToken := relayTestToken(64)
	admissionCredential := relay.AdmissionCredential{
		TenantID:    created.Domain.TenantID,
		DomainID:    created.Domain.DomainID,
		AdmissionID: uuid.New(),
		Token:       admissionToken,
	}
	admissionDigest, err := relay.AdmissionAuthorizationDigest(admissionCredential)
	if err != nil {
		t.Fatal(err)
	}
	createAdmissionBody := map[string]any{
		"admissionID":           admissionCredential.AdmissionID,
		"authorizationDigest":   admissionDigest,
		"capabilities":          []string{"message_fetch"},
		"expiresAtMilliseconds": 2_000,
	}
	createAdmission := performRelayJSON(
		t,
		handler,
		http.MethodPost,
		basePath+"/admissions",
		createAdmissionBody,
		created.AdministrationCredential.AuthorizationToken,
		uuid.Nil,
	)
	requireStatus(t, createAdmission, http.StatusCreated)
	var admissionResponse struct {
		Acceptance relay.Acceptance      `json:"acceptance"`
		Admission  relay.MemberAdmission `json:"admission"`
	}
	if err := json.NewDecoder(createAdmission.Body).Decode(&admissionResponse); err != nil {
		t.Fatal(err)
	}
	_ = createAdmission.Body.Close()
	if admissionResponse.Acceptance != relay.AcceptanceAccepted ||
		admissionResponse.Admission.AdmissionID != admissionCredential.AdmissionID ||
		admissionResponse.Admission.AuthorizationDigest != admissionDigest {
		t.Fatalf("unexpected admission response: %+v", admissionResponse)
	}

	memberToken := relayTestToken(32)
	memberCredential := relay.Credential{
		TenantID: created.Domain.TenantID,
		DomainID: created.Domain.DomainID,
		MemberID: uuid.New(),
		Token:    memberToken,
	}
	memberDigest, err := relay.AuthorizationDigest(memberCredential)
	if err != nil {
		t.Fatal(err)
	}
	claimBody := relay.MemberAdmissionClaim{
		MemberID:            memberCredential.MemberID,
		AuthorizationDigest: memberDigest,
	}
	claimPath := basePath + "/admissions/" +
		admissionCredential.AdmissionID.String() + "/claim"
	wrongClaim := performRelayJSON(
		t,
		handler,
		http.MethodPost,
		claimPath,
		claimBody,
		relayTestToken(65),
		uuid.Nil,
	)
	requireStatus(t, wrongClaim, http.StatusUnauthorized)
	claim := performRelayJSON(
		t,
		handler,
		http.MethodPost,
		claimPath,
		claimBody,
		admissionToken,
		uuid.Nil,
	)
	requireStatus(t, claim, http.StatusCreated)
	var claimed relay.AdmissionClaimResult
	if err := json.NewDecoder(claim.Body).Decode(&claimed); err != nil {
		t.Fatal(err)
	}
	_ = claim.Body.Close()
	if claimed.Acceptance != relay.AcceptanceAccepted ||
		claimed.Member.MemberID != memberCredential.MemberID ||
		len(claimed.Member.Capabilities) != 1 ||
		claimed.Member.Capabilities[0] != relay.CapabilityFetchMessage {
		t.Fatalf("unexpected claim response: %+v", claimed)
	}

	// Response-loss recovery uses the same candidate-generated member secret;
	// no plaintext member credential must be retained by the Node.
	nowMilliseconds = 3_000
	claimRetry := performRelayJSON(
		t,
		handler,
		http.MethodPost,
		claimPath,
		claimBody,
		admissionToken,
		uuid.Nil,
	)
	requireStatus(t, claimRetry, http.StatusOK)
	otherClaimBody := claimBody
	otherClaimBody.MemberID = uuid.New()
	secondClaim := performRelayJSON(
		t,
		handler,
		http.MethodPost,
		claimPath,
		otherClaimBody,
		admissionToken,
		uuid.Nil,
	)
	requireStatus(t, secondClaim, http.StatusConflict)
	fetch := performRelayJSON(
		t,
		handler,
		http.MethodGet,
		basePath+"/messages",
		nil,
		memberToken,
		memberCredential.MemberID,
	)
	requireStatus(t, fetch, http.StatusOK)

	revokedCredential := relay.AdmissionCredential{
		TenantID:    created.Domain.TenantID,
		DomainID:    created.Domain.DomainID,
		AdmissionID: uuid.New(),
		Token:       relayTestToken(96),
	}
	revokedDigest, err := relay.AdmissionAuthorizationDigest(revokedCredential)
	if err != nil {
		t.Fatal(err)
	}
	nowMilliseconds = 3_100
	createRevoked := performRelayJSON(
		t,
		handler,
		http.MethodPost,
		basePath+"/admissions",
		map[string]any{
			"admissionID":           revokedCredential.AdmissionID,
			"authorizationDigest":   revokedDigest,
			"capabilities":          []string{"message_fetch"},
			"expiresAtMilliseconds": 4_000,
		},
		created.AdministrationCredential.AuthorizationToken,
		uuid.Nil,
	)
	requireStatus(t, createRevoked, http.StatusCreated)
	revokePath := basePath + "/admissions/" +
		revokedCredential.AdmissionID.String() + "/revocation"
	revoke := performRelayJSON(
		t,
		handler,
		http.MethodPost,
		revokePath,
		nil,
		created.AdministrationCredential.AuthorizationToken,
		uuid.Nil,
	)
	requireStatus(t, revoke, http.StatusOK)
	revokedClaim := performRelayJSON(
		t,
		handler,
		http.MethodPost,
		basePath+"/admissions/"+revokedCredential.AdmissionID.String()+"/claim",
		claimBody,
		revokedCredential.Token,
		uuid.Nil,
	)
	requireStatus(t, revokedClaim, http.StatusForbidden)

	logText := logs.String()
	for _, protected := range []string{
		operatorToken,
		created.AdministrationCredential.AuthorizationToken,
		admissionToken,
		memberToken,
		revokedCredential.Token,
	} {
		if strings.Contains(logText, protected) {
			t.Fatalf("logs contain protected material %q", protected)
		}
	}
	if !strings.Contains(
		logText,
		`"pattern":"POST /v1/relay/tenants/{tenantID}/domains/{domainID}/admissions/{admissionID}/claim"`,
	) {
		t.Fatalf("logs did not use the bounded admission pattern: %s", logText)
	}
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

type relayDomainProvisioningRequest struct {
	AdministrationCredential relayAdministrationCredential `json:"administrationCredential"`
	MemberCredential         relayMemberCredential         `json:"memberCredential"`
	MemberCapabilities       []relay.Capability            `json:"memberCapabilities"`
	CreatedAtMilliseconds    int64                         `json:"createdAtMilliseconds"`
}

func newRelayDomainProvisioningRequest(
	createdAtMilliseconds int64,
	administrationTokenSeed byte,
	memberTokenSeed byte,
) relayDomainProvisioningRequest {
	tenantID := uuid.New()
	domainID := uuid.New()
	return relayDomainProvisioningRequest{
		AdministrationCredential: relayAdministrationCredential{
			TenantID:           tenantID,
			DomainID:           domainID,
			AuthorizationToken: relayTestToken(administrationTokenSeed),
		},
		MemberCredential: relayMemberCredential{
			TenantID:           tenantID,
			DomainID:           domainID,
			MemberID:           uuid.New(),
			AuthorizationToken: relayTestToken(memberTokenSeed),
		},
		MemberCapabilities:    append([]relay.Capability(nil), allRelayCapabilities...),
		CreatedAtMilliseconds: createdAtMilliseconds,
	}
}
