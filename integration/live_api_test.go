package integration_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	baseURL := strings.TrimRight(os.Getenv("FACETS_SERVER_TEST_BASE_URL"), "/")
	if baseURL == "" {
		t.Skip("FACETS_SERVER_TEST_BASE_URL is not set")
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
	baseURL := strings.TrimRight(os.Getenv("FACETS_SERVER_TEST_BASE_URL"), "/")
	operatorToken := os.Getenv("FACETS_SERVER_TEST_OPERATOR_TOKEN")
	if baseURL == "" || operatorToken == "" {
		t.Skip("FACETS_SERVER_TEST_BASE_URL and FACETS_SERVER_TEST_OPERATOR_TOKEN are required")
	}
	client := &http.Client{Timeout: 10 * time.Second}
	domain := provisionLiveRelayDomain(t, client, baseURL, operatorToken)
	basePath := fmt.Sprintf(
		"%s/v1/relay/tenants/%s/domains/%s",
		baseURL,
		domain.Domain.TenantID,
		domain.Domain.DomainID,
	)
	now := time.Now().UnixMilli()
	recipientSubscriptionID := uuid.New()
	requireStatusAndClose(t, requestRelayJSON(
		t, client, http.MethodPost, basePath+"/subscriptions",
		relay.SubscriptionCreateRequest{RetryID: uuid.New(), SubscriptionID: recipientSubscriptionID, CreatedAtMilliseconds: now},
		domain.AdministrationCredential.AuthorizationToken, uuid.Nil,
	), http.StatusCreated)
	admissionToken := encodedBytes(64)
	admissionCredential := relay.AdmissionCredential{
		TenantID:    domain.Domain.TenantID,
		DomainID:    domain.Domain.DomainID,
		AdmissionID: uuid.New(),
		Token:       admissionToken,
	}
	admissionDigest, err := relay.AdmissionAuthorizationDigest(admissionCredential)
	if err != nil {
		t.Fatal(err)
	}
	createAdmission := requestRelayJSON(
		t,
		client,
		http.MethodPost,
		basePath+"/admissions",
		map[string]any{
			"subscriptionID":      recipientSubscriptionID,
			"admissionID":         admissionCredential.AdmissionID,
			"authorizationDigest": admissionDigest,
			"capabilities": []string{
				"blob_fetch",
				"message_fetch",
				"message_acknowledge",
			},
			"expiresAtMilliseconds": now + 60_000,
		},
		domain.AdministrationCredential.AuthorizationToken,
		uuid.Nil,
	)
	requireStatusAndClose(t, createAdmission, http.StatusCreated)
	memberToken := encodedBytes(96)
	memberCredential := relay.Credential{
		TenantID: domain.Domain.TenantID,
		DomainID: domain.Domain.DomainID,
		MemberID: uuid.New(),
		Token:    memberToken,
	}
	memberDigest, err := relay.AuthorizationDigest(memberCredential)
	if err != nil {
		t.Fatal(err)
	}
	claim := requestRelayJSON(
		t,
		client,
		http.MethodPost,
		basePath+"/admissions/"+admissionCredential.AdmissionID.String()+"/claim",
		relay.MemberAdmissionClaim{
			MemberID:            memberCredential.MemberID,
			AuthorizationDigest: memberDigest,
		},
		admissionToken,
		uuid.Nil,
	)
	requireStatus(t, claim, http.StatusCreated)
	var recipient struct {
		Member relay.SubscriptionMemberRegistration `json:"member"`
	}
	if err := json.NewDecoder(claim.Body).Decode(&recipient); err != nil {
		t.Fatal(err)
	}
	_ = claim.Body.Close()
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
		memberToken,
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
		t.Fatalf("live relay fetch mismatch: %+v", fetched)
	}
	for _, stage := range []string{"accepted", "applied"} {
		requireStatusAndClose(t, requestRelayJSON(
			t,
			client,
			http.MethodPost,
			publishURL+"/acknowledgments",
			map[string]string{"stage": stage},
			memberToken,
			recipient.Member.MemberRegistration.MemberID,
		), http.StatusOK)
	}
	blobBytes := []byte("opaque-live-encrypted-blob")
	blobURL := basePath + "/blobs/" + relay.BlobID(blobBytes)
	uploadLiveRelayBlob(t, client, basePath, relay.Credential{TenantID: domain.Domain.TenantID, DomainID: domain.Domain.DomainID, MemberID: domain.Member.MemberID, Token: domain.MemberCredential.AuthorizationToken}, blobBytes, true)
	blobDownload := requestRelayBlob(
		t,
		client,
		http.MethodGet,
		blobURL,
		nil,
		memberToken,
		recipient.Member.MemberRegistration.MemberID,
		"bytes=7-10",
	)
	requireStatus(t, blobDownload, http.StatusPartialContent)
	downloaded, err := io.ReadAll(blobDownload.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = blobDownload.Body.Close()
	if !bytes.Equal(downloaded, blobBytes[7:11]) {
		t.Fatalf("live blob range mismatch: %q", downloaded)
	}
	requireStatusAndClose(t, requestRelayJSON(
		t,
		client,
		http.MethodPost,
		basePath+"/members/"+recipient.Member.MemberRegistration.MemberID.String()+"/revocation",
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
		memberToken,
		recipient.Member.MemberRegistration.MemberID,
	), http.StatusForbidden)
}

func requestRelayBlob(
	t *testing.T,
	client *http.Client,
	method string,
	url string,
	body []byte,
	token string,
	memberID uuid.UUID,
	byteRange string,
) *http.Response {
	t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/octet-stream")
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-Facets-Member-ID", memberID.String())
	if byteRange != "" {
		request.Header.Set("Range", byteRange)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func uploadLiveRelayBlob(t *testing.T, client *http.Client, basePath string, credential relay.Credential, content []byte, split bool) {
	t.Helper()
	now := time.Now().UnixMilli()
	uploadID, createRetryID := uuid.New(), uuid.New()
	blobID := relay.BlobID(content)
	uploadBase := basePath + "/blob-uploads"
	create := relay.BlobUploadRequest{RetryID: createRetryID, UploadID: uploadID, RelayBlobID: blobID, ByteCount: int64(len(content)), CreatedAtMilliseconds: now}
	requireStatusAndClose(t, requestRelayJSON(t, client, http.MethodPost, uploadBase, create, credential.Token, credential.MemberID), http.StatusCreated)
	requireStatusAndClose(t, requestRelayJSON(t, client, http.MethodPost, uploadBase, create, credential.Token, credential.MemberID), http.StatusOK)
	uploadURL := uploadBase + "/" + uploadID.String()
	boundaries := []int{len(content)}
	if split && len(content) > 1 {
		boundaries = []int{len(content) / 2, len(content)}
	}
	offset := 0
	for _, end := range boundaries {
		chunk := content[offset:end]
		digest := sha256.Sum256(chunk)
		request, err := http.NewRequest(http.MethodPatch, uploadURL, bytes.NewReader(chunk))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/octet-stream")
		request.Header.Set("Authorization", "Bearer "+credential.Token)
		request.Header.Set("X-Facets-Member-ID", credential.MemberID.String())
		request.Header.Set("Upload-Offset", fmt.Sprint(offset))
		request.Header.Set("X-Chunk-SHA256", hex.EncodeToString(digest[:]))
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		requireStatusAndClose(t, response, http.StatusOK)
		offset = end
		statusResponse := requestRelayJSON(t, client, http.MethodGet, uploadURL, nil, credential.Token, credential.MemberID)
		requireStatus(t, statusResponse, http.StatusOK)
		var status relay.BlobUploadStatus
		if err := json.NewDecoder(statusResponse.Body).Decode(&status); err != nil {
			t.Fatal(err)
		}
		_ = statusResponse.Body.Close()
		if status.CommittedOffset != int64(offset) {
			t.Fatalf("live upload offset=%d want=%d", status.CommittedOffset, offset)
		}
	}
	finalization := relay.BlobUploadFinalizationRequest{RetryID: uuid.New(), UploadID: uploadID, RelayBlobID: blobID, ByteCount: int64(len(content)), FinalizedAtMilliseconds: time.Now().UnixMilli()}
	requireStatusAndClose(t, requestRelayJSON(t, client, http.MethodPost, uploadURL+"/finalization", finalization, credential.Token, credential.MemberID), http.StatusCreated)
	requireStatusAndClose(t, requestRelayJSON(t, client, http.MethodPost, uploadURL+"/finalization", finalization, credential.Token, credential.MemberID), http.StatusOK)
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

type liveRelayAdministrationCredential struct {
	TenantID           uuid.UUID `json:"tenantID"`
	DomainID           uuid.UUID `json:"domainID"`
	AuthorizationToken string    `json:"authorizationToken"`
}

type liveRelayMemberCredential struct {
	TenantID           uuid.UUID `json:"tenantID"`
	DomainID           uuid.UUID `json:"domainID"`
	MemberID           uuid.UUID `json:"memberID"`
	AuthorizationToken string    `json:"authorizationToken"`
}

type liveRelayDomainProvisioningRequest struct {
	Version                  int                               `json:"version"`
	RetryID                  uuid.UUID                         `json:"retryID"`
	AdministrationCredential liveRelayAdministrationCredential `json:"administrationCredential"`
	SubscriptionID           uuid.UUID                         `json:"subscriptionID"`
	MemberCredential         liveRelayMemberCredential         `json:"memberCredential"`
	MemberCapabilities       []relay.Capability                `json:"memberCapabilities"`
	Quota                    *relay.DomainQuota                `json:"quota,omitempty"`
	CreatedAtMilliseconds    int64                             `json:"createdAtMilliseconds"`
}

func newLiveRelayDomainProvisioningRequest(
	createdAtMilliseconds int64,
) liveRelayDomainProvisioningRequest {
	tenantID := uuid.New()
	domainID := uuid.New()
	return liveRelayDomainProvisioningRequest{
		Version: relay.SchemaVersion,
		RetryID: uuid.New(),
		AdministrationCredential: liveRelayAdministrationCredential{
			TenantID:           tenantID,
			DomainID:           domainID,
			AuthorizationToken: encodedBytes(192),
		},
		MemberCredential: liveRelayMemberCredential{
			TenantID:           tenantID,
			DomainID:           domainID,
			MemberID:           uuid.New(),
			AuthorizationToken: encodedBytes(224),
		},
		SubscriptionID: uuid.New(),
		MemberCapabilities: []relay.Capability{
			relay.CapabilityFetchBlob,
			relay.CapabilityPublishBlob,
			relay.CapabilityPublishCheckpoint,
			relay.CapabilityAcknowledgeMessage,
			relay.CapabilityFetchMessage,
			relay.CapabilityPublishMessage,
		},
		CreatedAtMilliseconds: createdAtMilliseconds,
	}
}

type liveRelayTenantCredential struct {
	TenantID           uuid.UUID `json:"tenantID"`
	AuthorizationToken string    `json:"authorizationToken"`
}

type liveRelayTenantProvisioningRequest struct {
	Version                      int                                `json:"version"`
	RetryID                      uuid.UUID                          `json:"retryID"`
	TenantProvisioningCredential liveRelayTenantCredential          `json:"tenantProvisioningCredential"`
	InitialDomain                liveRelayDomainProvisioningRequest `json:"initialDomain"`
}
