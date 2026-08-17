package httpapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	blobRoot := t.TempDir()
	blobContentStore, err := relay.NewFileBlobContentStore(blobRoot)
	if err != nil {
		t.Fatal(err)
	}
	blobUploadStore, err := relay.NewFileBlobUploadContentStore(blobRoot, blobContentStore)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewWithRelay(
		rendezvous.NewMemoryStore(),
		relay.NewMemoryStore(),
		blobContentStore,
		slog.New(slog.NewJSONHandler(&logs, nil)),
		operatorToken,
		blobUploadStore,
	)
	if err != nil {
		t.Fatal(err)
	}
	server.now = func() time.Time { return time.UnixMilli(1_500) }
	handler := server.Handler()
	provisioning := newRelayDomainProvisioningRequest(1_500, 16, 64)
	tenantToken := relayTestToken(15)
	tenantProvisioning := newRelayTenantProvisioningRequest(provisioning, tenantToken)

	wrongOperator := performRelayJSON(
		t,
		handler,
		http.MethodPost,
		"/v1/relay/tenants",
		tenantProvisioning,
		relayTestToken(160),
		uuid.Nil,
	)
	requireStatus(t, wrongOperator, http.StatusUnauthorized)

	create := performRelayJSON(
		t,
		handler,
		http.MethodPost,
		"/v1/relay/tenants",
		tenantProvisioning,
		operatorToken,
		uuid.Nil,
	)
	requireStatus(t, create, http.StatusCreated)
	var provisioned relay.TenantProvisioningResult
	if err := json.NewDecoder(create.Body).Decode(&provisioned); err != nil {
		t.Fatal(err)
	}
	_ = create.Body.Close()
	if provisioned.Acceptance != relay.AcceptanceAccepted ||
		provisioned.InitialDomain.SubscriptionID != provisioning.SubscriptionID ||
		provisioned.InitialDomain.AdministrationAuthorizationDigest == "" ||
		provisioned.InitialDomain.MemberAuthorizationDigest == "" {
		t.Fatalf("incomplete tenant creation response: %+v", provisioned)
	}
	created := struct {
		Domain                   relay.DomainRegistration
		AdministrationCredential relayAdministrationCredential
		Member                   relay.MemberRegistration
		MemberCredential         relayMemberCredential
	}{
		Domain:                   relay.DomainRegistration{TenantID: provisioning.AdministrationCredential.TenantID, DomainID: provisioning.AdministrationCredential.DomainID},
		AdministrationCredential: provisioning.AdministrationCredential,
		Member:                   relay.MemberRegistration{TenantID: provisioning.MemberCredential.TenantID, DomainID: provisioning.MemberCredential.DomainID, MemberID: provisioning.MemberCredential.MemberID},
		MemberCredential:         provisioning.MemberCredential,
	}
	provisionRetry := performRelayJSON(
		t,
		handler,
		http.MethodPost,
		"/v1/relay/tenants",
		tenantProvisioning,
		operatorToken,
		uuid.Nil,
	)
	requireStatus(t, provisionRetry, http.StatusOK)
	var retried relay.TenantProvisioningResult
	if err := json.NewDecoder(provisionRetry.Body).Decode(&retried); err != nil {
		t.Fatal(err)
	}
	_ = provisionRetry.Body.Close()
	if retried.Acceptance != relay.AcceptanceDuplicate ||
		retried.InitialDomain.RetryID != provisioned.InitialDomain.RetryID ||
		retried.InitialDomain.TenantID != provisioned.InitialDomain.TenantID ||
		retried.InitialDomain.DomainID != provisioned.InitialDomain.DomainID ||
		retried.InitialDomain.SubscriptionID != provisioned.InitialDomain.SubscriptionID ||
		retried.InitialDomain.MemberID != provisioned.InitialDomain.MemberID ||
		retried.InitialDomain.AdministrationAuthorizationDigest != provisioned.InitialDomain.AdministrationAuthorizationDigest ||
		retried.InitialDomain.MemberAuthorizationDigest != provisioned.InitialDomain.MemberAuthorizationDigest {
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
		"/v1/relay/tenants",
		newRelayTenantProvisioningRequest(collision, tenantToken),
		operatorToken,
		uuid.Nil,
	), http.StatusConflict)

	basePath := "/v1/relay/tenants/" + created.Domain.TenantID.String() +
		"/domains/" + created.Domain.DomainID.String()
	recipientSubscriptionID := uuid.New()
	createSubscription := performRelayJSON(
		t, handler, http.MethodPost, basePath+"/subscriptions",
		relay.SubscriptionCreateRequest{RetryID: uuid.New(), SubscriptionID: recipientSubscriptionID, CreatedAtMilliseconds: 1_500},
		created.AdministrationCredential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, createSubscription, http.StatusCreated)
	_ = createSubscription.Body.Close()
	createMember := performRelayJSON(
		t,
		handler,
		http.MethodPost,
		basePath+"/members",
		map[string]any{
			"subscriptionID": recipientSubscriptionID,
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
		Member     relay.SubscriptionMemberRegistration `json:"member"`
		Credential relayMemberCredential                `json:"credential"`
	}
	if err := json.NewDecoder(createMember.Body).Decode(&recipient); err != nil {
		t.Fatal(err)
	}
	_ = createMember.Body.Close()
	if len(recipient.Member.MemberRegistration.Capabilities) != 3 ||
		recipient.Member.MemberRegistration.Capabilities[0] != relay.CapabilityFetchBlob ||
		recipient.Member.MemberRegistration.Capabilities[1] != relay.CapabilityAcknowledgeMessage ||
		recipient.Member.MemberRegistration.Capabilities[2] != relay.CapabilityFetchMessage {
		t.Fatalf("capabilities were not normalized: %v", recipient.Member.MemberRegistration.Capabilities)
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
		recipient.Member.MemberRegistration.MemberID,
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
		recipient.Member.MemberRegistration.MemberID,
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
		recipient.Member.MemberRegistration.MemberID,
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
		recipient.Member.MemberRegistration.MemberID,
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
			recipient.Member.MemberRegistration.MemberID,
		)
		requireStatus(t, response, http.StatusOK)
	}

	blobBytes := []byte("opaque independently encrypted blob bytes")
	blobID := relay.BlobID(blobBytes)
	blobPath := basePath + "/blobs/" + blobID
	legacyUpload := performRelayBlob(
		t,
		handler,
		http.MethodPut,
		blobPath,
		blobBytes,
		created.MemberCredential.AuthorizationToken,
		created.Member.MemberID,
		"",
	)
	requireStatus(t, legacyUpload, http.StatusMethodNotAllowed)
	uploadID := uuid.New()
	createRetryID := uuid.New()
	uploadPath := basePath + "/blob-uploads/" + uploadID.String()
	uploadCreate := performRelayJSON(t, handler, http.MethodPost, basePath+"/blob-uploads", relay.BlobUploadRequest{
		RetryID: createRetryID, UploadID: uploadID, RelayBlobID: blobID,
		ByteCount: int64(len(blobBytes)), CreatedAtMilliseconds: 1_500,
	}, created.MemberCredential.AuthorizationToken, created.Member.MemberID)
	requireStatus(t, uploadCreate, http.StatusCreated)
	uploadCreateRetry := performRelayJSON(t, handler, http.MethodPost, basePath+"/blob-uploads", relay.BlobUploadRequest{
		RetryID: createRetryID, UploadID: uploadID, RelayBlobID: blobID,
		ByteCount: int64(len(blobBytes)), CreatedAtMilliseconds: 1_500,
	}, created.MemberCredential.AuthorizationToken, created.Member.MemberID)
	requireStatus(t, uploadCreateRetry, http.StatusOK)
	uploadCreateCollision := performRelayJSON(t, handler, http.MethodPost, basePath+"/blob-uploads", relay.BlobUploadRequest{
		RetryID: createRetryID, UploadID: uuid.New(), RelayBlobID: blobID,
		ByteCount: int64(len(blobBytes)), CreatedAtMilliseconds: 1_500,
	}, created.MemberCredential.AuthorizationToken, created.Member.MemberID)
	requireStatus(t, uploadCreateCollision, http.StatusConflict)
	uploadStatus := performRelayJSON(t, handler, http.MethodGet, uploadPath, nil, created.MemberCredential.AuthorizationToken, created.Member.MemberID)
	requireStatus(t, uploadStatus, http.StatusOK)
	chunkDigest := sha256.Sum256(blobBytes)
	badChunkRequest := httptest.NewRequest(http.MethodPatch, uploadPath, bytes.NewReader(blobBytes))
	badChunkRequest.Header.Set("Authorization", "Bearer "+created.MemberCredential.AuthorizationToken)
	badChunkRequest.Header.Set("X-Facets-Member-ID", created.Member.MemberID.String())
	badChunkRequest.Header.Set("Content-Type", "application/octet-stream")
	badChunkRequest.Header.Set("Upload-Offset", "0")
	badChunkRequest.Header.Set("X-Chunk-SHA256", strings.Repeat("0", 64))
	badChunkResponse := httptest.NewRecorder()
	handler.ServeHTTP(badChunkResponse, badChunkRequest)
	if badChunkResponse.Code != http.StatusBadRequest {
		t.Fatalf("bad chunk status=%d body=%s", badChunkResponse.Code, badChunkResponse.Body.String())
	}
	chunkRequest := httptest.NewRequest(http.MethodPatch, uploadPath, bytes.NewReader(blobBytes))
	chunkRequest.Header.Set("Authorization", "Bearer "+created.MemberCredential.AuthorizationToken)
	chunkRequest.Header.Set("X-Facets-Member-ID", created.Member.MemberID.String())
	chunkRequest.Header.Set("Content-Type", "application/octet-stream")
	chunkRequest.Header.Set("Upload-Offset", "0")
	chunkRequest.Header.Set("X-Chunk-SHA256", hex.EncodeToString(chunkDigest[:]))
	chunkResponse := httptest.NewRecorder()
	handler.ServeHTTP(chunkResponse, chunkRequest)
	if chunkResponse.Code != http.StatusOK {
		t.Fatalf("chunk status=%d body=%s", chunkResponse.Code, chunkResponse.Body.String())
	}
	chunkRetryRequest := httptest.NewRequest(http.MethodPatch, uploadPath, bytes.NewReader(blobBytes))
	chunkRetryRequest.Header = chunkRequest.Header.Clone()
	chunkRetryResponse := httptest.NewRecorder()
	handler.ServeHTTP(chunkRetryResponse, chunkRetryRequest)
	if chunkRetryResponse.Code != http.StatusOK {
		t.Fatalf("chunk retry status=%d body=%s", chunkRetryResponse.Code, chunkRetryResponse.Body.String())
	}
	finalizeRequest := relay.BlobUploadFinalizationRequest{
		RetryID: uuid.New(), UploadID: uploadID, RelayBlobID: blobID,
		ByteCount: int64(len(blobBytes)), FinalizedAtMilliseconds: 1_500,
	}
	finalize := performRelayJSON(t, handler, http.MethodPost, uploadPath+"/finalization", finalizeRequest, created.MemberCredential.AuthorizationToken, created.Member.MemberID)
	requireStatus(t, finalize, http.StatusCreated)
	finalizeRetry := performRelayJSON(t, handler, http.MethodPost, uploadPath+"/finalization", finalizeRequest, created.MemberCredential.AuthorizationToken, created.Member.MemberID)
	requireStatus(t, finalizeRetry, http.StatusOK)
	emptyUploadID := uuid.New()
	emptyBlobID := relay.BlobID(nil)
	emptyCreate := performRelayJSON(t, handler, http.MethodPost, basePath+"/blob-uploads", relay.BlobUploadRequest{
		RetryID: uuid.New(), UploadID: emptyUploadID, RelayBlobID: emptyBlobID,
		ByteCount: 0, CreatedAtMilliseconds: 1_500,
	}, created.MemberCredential.AuthorizationToken, created.Member.MemberID)
	requireStatus(t, emptyCreate, http.StatusCreated)
	emptyFinalize := performRelayJSON(t, handler, http.MethodPost, basePath+"/blob-uploads/"+emptyUploadID.String()+"/finalization", relay.BlobUploadFinalizationRequest{
		RetryID: uuid.New(), UploadID: emptyUploadID, RelayBlobID: emptyBlobID,
		ByteCount: 0, FinalizedAtMilliseconds: 1_500,
	}, created.MemberCredential.AuthorizationToken, created.Member.MemberID)
	requireStatus(t, emptyFinalize, http.StatusCreated)
	mismatchBytes := []byte("digest mismatch")
	mismatchUploadID := uuid.New()
	mismatchBlobID := relay.BlobID([]byte("different final bytes"))
	mismatchCreate := performRelayJSON(t, handler, http.MethodPost, basePath+"/blob-uploads", relay.BlobUploadRequest{
		RetryID: uuid.New(), UploadID: mismatchUploadID, RelayBlobID: mismatchBlobID,
		ByteCount: int64(len(mismatchBytes)), CreatedAtMilliseconds: 1_500,
	}, created.MemberCredential.AuthorizationToken, created.Member.MemberID)
	requireStatus(t, mismatchCreate, http.StatusCreated)
	mismatchDigest := sha256.Sum256(mismatchBytes)
	mismatchPath := basePath + "/blob-uploads/" + mismatchUploadID.String()
	mismatchChunk := httptest.NewRequest(http.MethodPatch, mismatchPath, bytes.NewReader(mismatchBytes))
	mismatchChunk.Header.Set("Authorization", "Bearer "+created.MemberCredential.AuthorizationToken)
	mismatchChunk.Header.Set("X-Facets-Member-ID", created.Member.MemberID.String())
	mismatchChunk.Header.Set("Content-Type", "application/octet-stream")
	mismatchChunk.Header.Set("Upload-Offset", "0")
	mismatchChunk.Header.Set("X-Chunk-SHA256", hex.EncodeToString(mismatchDigest[:]))
	mismatchChunkResponse := httptest.NewRecorder()
	handler.ServeHTTP(mismatchChunkResponse, mismatchChunk)
	if mismatchChunkResponse.Code != http.StatusOK {
		t.Fatalf("mismatch chunk status=%d body=%s", mismatchChunkResponse.Code, mismatchChunkResponse.Body.String())
	}
	mismatchFinalize := performRelayJSON(t, handler, http.MethodPost, mismatchPath+"/finalization", relay.BlobUploadFinalizationRequest{
		RetryID: uuid.New(), UploadID: mismatchUploadID, RelayBlobID: mismatchBlobID,
		ByteCount: int64(len(mismatchBytes)), FinalizedAtMilliseconds: 1_500,
	}, created.MemberCredential.AuthorizationToken, created.Member.MemberID)
	requireStatus(t, mismatchFinalize, http.StatusBadRequest)
	download := performRelayBlob(
		t,
		handler,
		http.MethodGet,
		blobPath,
		nil,
		recipient.Credential.AuthorizationToken,
		recipient.Member.MemberRegistration.MemberID,
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
		recipient.Member.MemberRegistration.MemberID,
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
		recipient.Member.MemberRegistration.MemberID,
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
	requireStatus(t, digestMismatch, http.StatusMethodNotAllowed)

	revoke := performRelayJSON(
		t,
		handler,
		http.MethodPost,
		basePath+"/members/"+recipient.Member.MemberRegistration.MemberID.String()+"/revocation",
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
		recipient.Member.MemberRegistration.MemberID,
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

func TestRelayTenantCredentialProvisionsAdditionalDomains(t *testing.T) {
	operatorToken := relayTestToken(192)
	server, err := NewWithRelay(
		rendezvous.NewMemoryStore(),
		relay.NewMemoryStore(),
		nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		operatorToken,
	)
	if err != nil {
		t.Fatal(err)
	}
	server.now = func() time.Time { return time.UnixMilli(1_500) }
	handler := server.Handler()
	parent := provisionRelayTestAuthority(t, handler, operatorToken, 1_000, 32, 64)
	tenantPath := "/v1/relay/tenants/" + parent.Domain.TenantID.String() + "/domains"
	requireStatus(t, performRelayJSON(
		t, handler, http.MethodPost, "/v1/relay/domains", nil,
		operatorToken, uuid.Nil,
	), http.StatusNotFound)
	requireStatus(t, performRelayJSON(
		t, handler, http.MethodPost,
		tenantPath+"/"+parent.Domain.DomainID.String()+"/delegated-domains", nil,
		parent.AdministrationCredential.AuthorizationToken, uuid.Nil,
	), http.StatusNotFound)

	childRequest := newRelayDomainProvisioningRequest(1_500, 96, 128)
	childRequest.AdministrationCredential.TenantID =
		parent.Domain.TenantID
	childRequest.MemberCredential.TenantID =
		parent.Domain.TenantID
	created := performRelayJSON(
		t,
		handler,
		http.MethodPost,
		tenantPath,
		childRequest,
		parent.TenantCredential.AuthorizationToken,
		uuid.Nil,
	)
	requireStatus(t, created, http.StatusCreated)
	_ = created.Body.Close()
	retry := performRelayJSON(
		t,
		handler,
		http.MethodPost,
		tenantPath,
		childRequest,
		parent.TenantCredential.AuthorizationToken,
		uuid.Nil,
	)
	requireStatus(t, retry, http.StatusOK)
	_ = retry.Body.Close()

	wrongTenant := newRelayDomainProvisioningRequest(1_500, 160, 176)
	requireStatus(t, performRelayJSON(
		t,
		handler,
		http.MethodPost,
		tenantPath,
		wrongTenant,
		parent.TenantCredential.AuthorizationToken,
		uuid.Nil,
	), http.StatusBadRequest)
	requireStatus(t, performRelayJSON(
		t,
		handler,
		http.MethodPost,
		tenantPath,
		childRequest,
		relayTestToken(208),
		uuid.Nil,
	), http.StatusUnauthorized)
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

	created := provisionRelayTestAuthority(
		t, handler, operatorToken, nowMilliseconds, 32, 96,
	)
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
		"subscriptionID":        created.SubscriptionID,
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
		Acceptance relay.Acceptance                  `json:"acceptance"`
		Admission  relay.SubscriptionMemberAdmission `json:"admission"`
	}
	if err := json.NewDecoder(createAdmission.Body).Decode(&admissionResponse); err != nil {
		t.Fatal(err)
	}
	_ = createAdmission.Body.Close()
	if admissionResponse.Acceptance != relay.AcceptanceAccepted ||
		admissionResponse.Admission.SubscriptionID != created.SubscriptionID ||
		admissionResponse.Admission.Admission.AdmissionID != admissionCredential.AdmissionID ||
		admissionResponse.Admission.Admission.AuthorizationDigest != admissionDigest {
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
	var claimed relay.SubscriptionAdmissionClaimResult
	if err := json.NewDecoder(claim.Body).Decode(&claimed); err != nil {
		t.Fatal(err)
	}
	_ = claim.Body.Close()
	if claimed.Acceptance != relay.AcceptanceAccepted ||
		claimed.Member.SubscriptionID != created.SubscriptionID ||
		claimed.Member.MemberRegistration.MemberID != memberCredential.MemberID ||
		len(claimed.Member.MemberRegistration.Capabilities) != 1 ||
		claimed.Member.MemberRegistration.Capabilities[0] != relay.CapabilityFetchMessage {
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
			"subscriptionID":        created.SubscriptionID,
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

func TestRelaySubscriptionLifecycleStatusAndTenantRotationAreExactRetrySafe(t *testing.T) {
	operatorToken := relayTestToken(230)
	server, err := NewWithRelay(
		rendezvous.NewMemoryStore(), relay.NewMemoryStore(), nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)), operatorToken,
	)
	if err != nil {
		t.Fatal(err)
	}
	nowMilliseconds := int64(1_000)
	server.now = func() time.Time { return time.UnixMilli(nowMilliseconds) }
	handler := server.Handler()
	authority := provisionRelayTestAuthority(t, handler, operatorToken, nowMilliseconds, 231, 232)
	tenantRoot := "/v1/relay/tenants/" + authority.Domain.TenantID.String()
	domainRoot := tenantRoot + "/domains/" + authority.Domain.DomainID.String()

	tenantStatus := performRelayJSON(t, handler, http.MethodGet, tenantRoot+"/status", nil, authority.TenantCredential.AuthorizationToken, uuid.Nil)
	requireStatus(t, tenantStatus, http.StatusOK)
	var initialTenantStatus relay.TenantStatus
	if err := json.NewDecoder(tenantStatus.Body).Decode(&initialTenantStatus); err != nil {
		t.Fatal(err)
	}
	_ = tenantStatus.Body.Close()
	if initialTenantStatus.DomainCount != 1 || initialTenantStatus.ReservedBlobCount != 0 || initialTenantStatus.Quota.MaximumAggregateMessageByteCount <= 0 {
		t.Fatalf("unexpected tenant status: %+v", initialTenantStatus)
	}

	nowMilliseconds = 1_100
	createRequest := relay.SubscriptionCreateRequest{
		RetryID: uuid.New(), SubscriptionID: uuid.New(), CreatedAtMilliseconds: nowMilliseconds,
	}
	create := performRelayJSON(t, handler, http.MethodPost, domainRoot+"/subscriptions", createRequest, authority.AdministrationCredential.AuthorizationToken, uuid.Nil)
	requireStatus(t, create, http.StatusCreated)
	var created relay.SubscriptionCreateResponse
	if err := json.NewDecoder(create.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	_ = create.Body.Close()
	if created.Acceptance != relay.AcceptanceAccepted || created.RetryID != createRequest.RetryID || created.Subscription.SubscriptionID != createRequest.SubscriptionID {
		t.Fatalf("unexpected subscription creation: %+v", created)
	}
	retry := performRelayJSON(t, handler, http.MethodPost, domainRoot+"/subscriptions", createRequest, authority.AdministrationCredential.AuthorizationToken, uuid.Nil)
	requireStatus(t, retry, http.StatusOK)
	var retried relay.SubscriptionCreateResponse
	if err := json.NewDecoder(retry.Body).Decode(&retried); err != nil {
		t.Fatal(err)
	}
	_ = retry.Body.Close()
	if retried.Acceptance != relay.AcceptanceDuplicate || retried.Subscription != created.Subscription {
		t.Fatalf("unexpected subscription retry: %+v", retried)
	}
	collision := createRequest
	collision.SubscriptionID = uuid.New()
	requireStatus(t, performRelayJSON(t, handler, http.MethodPost, domainRoot+"/subscriptions", collision, authority.AdministrationCredential.AuthorizationToken, uuid.Nil), http.StatusConflict)

	get := performRelayJSON(t, handler, http.MethodGet, domainRoot+"/subscriptions/"+createRequest.SubscriptionID.String(), nil, authority.AdministrationCredential.AuthorizationToken, uuid.Nil)
	requireStatus(t, get, http.StatusOK)
	_ = get.Body.Close()
	nowMilliseconds = 1_200
	statusRequest := relay.SubscriptionStatusChangeRequest{RetryID: uuid.New(), Status: relay.SubscriptionRebootstrapRequired, ChangedAtMilliseconds: nowMilliseconds}
	statusPath := domainRoot + "/subscriptions/" + createRequest.SubscriptionID.String() + "/status"
	change := performRelayJSON(t, handler, http.MethodPost, statusPath, statusRequest, authority.AdministrationCredential.AuthorizationToken, uuid.Nil)
	requireStatus(t, change, http.StatusCreated)
	_ = change.Body.Close()
	changeRetry := performRelayJSON(t, handler, http.MethodPost, statusPath, statusRequest, authority.AdministrationCredential.AuthorizationToken, uuid.Nil)
	requireStatus(t, changeRetry, http.StatusOK)
	var statusRetry relay.SubscriptionStatusChangeResponse
	if err := json.NewDecoder(changeRetry.Body).Decode(&statusRetry); err != nil {
		t.Fatal(err)
	}
	_ = changeRetry.Body.Close()
	if statusRetry.Acceptance != relay.AcceptanceDuplicate || statusRetry.Subscription.Status != relay.SubscriptionRebootstrapRequired {
		t.Fatalf("unexpected status retry: %+v", statusRetry)
	}

	domainStatus := performRelayJSON(t, handler, http.MethodGet, domainRoot+"/status", nil, authority.AdministrationCredential.AuthorizationToken, uuid.Nil)
	requireStatus(t, domainStatus, http.StatusOK)
	var status relay.DomainStatus
	if err := json.NewDecoder(domainStatus.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	_ = domainStatus.Body.Close()
	if status.ActiveSubscriptionCount != 1 || status.ReservedBlobCount != 0 || status.Quota.MaximumBlobByteCount <= 0 {
		t.Fatalf("unexpected domain status: %+v", status)
	}

	replacementToken := relayTestToken(233)
	replacementDigest, err := relay.TenantAuthorizationDigest(relay.TenantCredential{TenantID: authority.Domain.TenantID, Token: replacementToken})
	if err != nil {
		t.Fatal(err)
	}
	nowMilliseconds = 1_300
	rotation := relay.TenantCredentialRotation{
		Version: relay.SchemaVersion, RotationID: uuid.New(), TenantID: authority.Domain.TenantID,
		ReplacementAuthorizationDigest: replacementDigest, RotatedAtMilliseconds: nowMilliseconds,
	}
	rotationPath := tenantRoot + "/credential-rotations/" + rotation.RotationID.String()
	rotate := performRelayJSON(t, handler, http.MethodPost, rotationPath, rotation, authority.TenantCredential.AuthorizationToken, uuid.Nil)
	requireStatus(t, rotate, http.StatusCreated)
	_ = rotate.Body.Close()
	rotationRetry := performRelayJSON(t, handler, http.MethodPost, rotationPath, rotation, authority.TenantCredential.AuthorizationToken, uuid.Nil)
	requireStatus(t, rotationRetry, http.StatusOK)
	_ = rotationRetry.Body.Close()
	requireStatus(t, performRelayJSON(t, handler, http.MethodGet, tenantRoot+"/status", nil, authority.TenantCredential.AuthorizationToken, uuid.Nil), http.StatusUnauthorized)
	newStatus := performRelayJSON(t, handler, http.MethodGet, tenantRoot+"/status", nil, replacementToken, uuid.Nil)
	requireStatus(t, newStatus, http.StatusOK)
	_ = newStatus.Body.Close()
}

func TestRelayCheckpointHTTPStagesActivatesPlansAndCollects(t *testing.T) {
	operatorToken := relayTestToken(240)
	server, err := NewWithRelay(
		rendezvous.NewMemoryStore(), relay.NewMemoryStore(), nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)), operatorToken,
	)
	if err != nil {
		t.Fatal(err)
	}
	nowMilliseconds := int64(1_000)
	server.now = func() time.Time { return time.UnixMilli(nowMilliseconds) }
	handler := server.Handler()
	authority := provisionRelayTestAuthority(t, handler, operatorToken, nowMilliseconds, 241, 242)
	domainRoot := "/v1/relay/tenants/" + authority.Domain.TenantID.String() +
		"/domains/" + authority.Domain.DomainID.String()

	nowMilliseconds = 1_100
	candidate := relay.CheckpointCandidate{
		Version: relay.SchemaVersion, RetryID: uuid.New(), CheckpointID: uuid.New(),
		TenantID: authority.Domain.TenantID, DomainID: authority.Domain.DomainID,
		PublisherSubscriptionID: authority.SubscriptionID,
		CoveredThroughCursor:    relay.EncodeCursor(0),
		RetainedMessageIDs:      []uuid.UUID{}, RetainedBlobIDs: []string{},
		CreatedAtMilliseconds: nowMilliseconds,
	}
	stagePath := domainRoot + "/checkpoints/candidates"
	stage := performRelayJSON(t, handler, http.MethodPost, stagePath, candidate, authority.MemberCredential.AuthorizationToken, authority.Member.MemberID)
	requireStatus(t, stage, http.StatusCreated)
	var stageResult relay.CheckpointStageResponse
	if err := json.NewDecoder(stage.Body).Decode(&stageResult); err != nil {
		t.Fatal(err)
	}
	_ = stage.Body.Close()
	if stageResult.Acceptance != relay.AcceptanceAccepted || stageResult.CheckpointID != candidate.CheckpointID {
		t.Fatalf("unexpected checkpoint stage: %+v", stageResult)
	}
	stageRetry := performRelayJSON(t, handler, http.MethodPost, stagePath, candidate, authority.MemberCredential.AuthorizationToken, authority.Member.MemberID)
	requireStatus(t, stageRetry, http.StatusOK)
	_ = stageRetry.Body.Close()

	nowMilliseconds = 1_200
	activation := relay.CheckpointActivationRequest{RetryID: uuid.New(), CheckpointID: candidate.CheckpointID, ActivatedAtMilliseconds: nowMilliseconds}
	checkpointRoot := domainRoot + "/checkpoints/" + candidate.CheckpointID.String()
	activate := performRelayJSON(t, handler, http.MethodPost, checkpointRoot+"/activation", activation, authority.AdministrationCredential.AuthorizationToken, uuid.Nil)
	requireStatus(t, activate, http.StatusCreated)
	var activationResult relay.CheckpointActivationResponse
	if err := json.NewDecoder(activate.Body).Decode(&activationResult); err != nil {
		t.Fatal(err)
	}
	_ = activate.Body.Close()
	if activationResult.StartCursor != relay.EncodeCursor(0) {
		t.Fatalf("unexpected checkpoint start cursor: %+v", activationResult)
	}

	dryRun := performRelayJSON(t, handler, http.MethodPost, checkpointRoot+"/collection-dry-run", relay.CheckpointDryRunRequest{CheckpointID: candidate.CheckpointID}, authority.AdministrationCredential.AuthorizationToken, uuid.Nil)
	requireStatus(t, dryRun, http.StatusOK)
	var plan relay.CheckpointDryRunResponse
	if err := json.NewDecoder(dryRun.Body).Decode(&plan); err != nil {
		t.Fatal(err)
	}
	_ = dryRun.Body.Close()
	if !plan.Eligible || plan.PlanDigest == "" || plan.MessageCount != 0 || plan.BlobCount != 0 {
		t.Fatalf("unexpected checkpoint plan: %+v", plan)
	}

	nowMilliseconds = 1_300
	collection := relay.CheckpointCollectionRequest{
		RetryID: uuid.New(), CheckpointID: candidate.CheckpointID, PlanDigest: plan.PlanDigest,
		MaximumMessageCount: 1, RequestedAtMilliseconds: nowMilliseconds,
	}
	collect := performRelayJSON(t, handler, http.MethodPost, checkpointRoot+"/collection", collection, authority.AdministrationCredential.AuthorizationToken, uuid.Nil)
	requireStatus(t, collect, http.StatusOK)
	var collected relay.CheckpointCollectionResponse
	if err := json.NewDecoder(collect.Body).Decode(&collected); err != nil {
		t.Fatal(err)
	}
	_ = collect.Body.Close()
	if !collected.Completed || collected.Duplicate {
		t.Fatalf("unexpected checkpoint collection: %+v", collected)
	}
	collectRetry := performRelayJSON(t, handler, http.MethodPost, checkpointRoot+"/collection", collection, authority.AdministrationCredential.AuthorizationToken, uuid.Nil)
	requireStatus(t, collectRetry, http.StatusOK)
	var retried relay.CheckpointCollectionResponse
	if err := json.NewDecoder(collectRetry.Body).Decode(&retried); err != nil {
		t.Fatal(err)
	}
	_ = collectRetry.Body.Close()
	if !retried.Duplicate || !retried.Completed {
		t.Fatalf("unexpected checkpoint collection retry: %+v", retried)
	}
}

func relayTestToken(seed byte) string {
	value := make([]byte, 32)
	for index := range value {
		value[index] = seed + byte(index)
	}
	return base64.RawURLEncoding.EncodeToString(value)
}

type relayDomainProvisioningRequest struct {
	Version                  int                           `json:"version"`
	RetryID                  uuid.UUID                     `json:"retryID"`
	AdministrationCredential relayAdministrationCredential `json:"administrationCredential"`
	SubscriptionID           uuid.UUID                     `json:"subscriptionID"`
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
		Version: relay.SchemaVersion,
		RetryID: uuid.New(),
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
		SubscriptionID:        uuid.New(),
		MemberCapabilities:    append([]relay.Capability(nil), allRelayCapabilities...),
		CreatedAtMilliseconds: createdAtMilliseconds,
	}
}

func newRelayTenantProvisioningRequest(
	domain relayDomainProvisioningRequest,
	tenantToken string,
) relayTenantProvisioningInput {
	return relayTenantProvisioningInput{
		Version: relay.SchemaVersion,
		RetryID: uuid.New(),
		TenantProvisioningCredential: relayTenantCredential{
			TenantID:           domain.AdministrationCredential.TenantID,
			AuthorizationToken: tenantToken,
		},
		InitialDomain: relayDomainProvisioningInput{
			Version:                  domain.Version,
			RetryID:                  domain.RetryID,
			AdministrationCredential: domain.AdministrationCredential,
			SubscriptionID:           domain.SubscriptionID,
			MemberCredential:         domain.MemberCredential,
			MemberCapabilities:       domain.MemberCapabilities,
			CreatedAtMilliseconds:    domain.CreatedAtMilliseconds,
		},
	}
}

type relayTestAuthority struct {
	Domain                   relay.DomainRegistration
	AdministrationCredential relayAdministrationCredential
	SubscriptionID           uuid.UUID
	Member                   relay.MemberRegistration
	MemberCredential         relayMemberCredential
	TenantCredential         relayTenantCredential
}

func provisionRelayTestAuthority(
	t *testing.T,
	handler http.Handler,
	operatorToken string,
	createdAtMilliseconds int64,
	administrationTokenSeed byte,
	memberTokenSeed byte,
) relayTestAuthority {
	t.Helper()
	domain := newRelayDomainProvisioningRequest(
		createdAtMilliseconds, administrationTokenSeed, memberTokenSeed,
	)
	tenantToken := relayTestToken(administrationTokenSeed - 1)
	input := newRelayTenantProvisioningRequest(domain, tenantToken)
	response := performRelayJSON(
		t, handler, http.MethodPost, "/v1/relay/tenants", input,
		operatorToken, uuid.Nil,
	)
	requireStatus(t, response, http.StatusCreated)
	var result relay.TenantProvisioningResult
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if result.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("unexpected tenant provisioning result: %+v", result)
	}
	return relayTestAuthority{
		Domain: relay.DomainRegistration{
			TenantID: domain.AdministrationCredential.TenantID,
			DomainID: domain.AdministrationCredential.DomainID,
		},
		AdministrationCredential: domain.AdministrationCredential,
		SubscriptionID:           domain.SubscriptionID,
		Member: relay.MemberRegistration{
			TenantID:     domain.MemberCredential.TenantID,
			DomainID:     domain.MemberCredential.DomainID,
			MemberID:     domain.MemberCredential.MemberID,
			Capabilities: append([]relay.Capability(nil), domain.MemberCapabilities...),
		},
		MemberCredential: domain.MemberCredential,
		TenantCredential: input.TenantProvisioningCredential,
	}
}
