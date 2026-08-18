package integration_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/relay"
)

type liveRelayDomain struct {
	Domain                   relay.DomainRegistration
	AdministrationCredential struct {
		AuthorizationToken string `json:"authorizationToken"`
	}
	SubscriptionID   uuid.UUID
	Member           relay.MemberRegistration
	MemberCredential struct {
		AuthorizationToken string `json:"authorizationToken"`
	}
	TenantCredential liveRelayTenantCredential
}

type liveRelayMember struct {
	Registration relay.MemberRegistration
	Credential   relay.Credential
}

type liveRelayFetchPage struct {
	Messages []relay.Message `json:"messages"`
	Cursor   string          `json:"cursor"`
}

// TestLiveReplicaRelayDeliveryMatrix proves replica-correct delivery behavior
// across the real HTTP, PostgreSQL, and filesystem-blob boundaries. It treats
// envelope timestamps and ciphertext as opaque client material and relies only
// on relay-assigned sequence and message identity for catch-up.
func TestLiveReplicaRelayDeliveryMatrix(t *testing.T) {
	baseURL := strings.TrimRight(os.Getenv("FACETS_SERVER_TEST_BASE_URL"), "/")
	operatorToken := os.Getenv("FACETS_SERVER_TEST_OPERATOR_TOKEN")
	if baseURL == "" || operatorToken == "" {
		t.Skip("FACETS_SERVER_TEST_BASE_URL and FACETS_SERVER_TEST_OPERATOR_TOKEN are required")
	}
	client := &http.Client{Timeout: 15 * time.Second}
	domain := provisionLiveRelayDomain(t, client, baseURL, operatorToken)
	basePath := fmt.Sprintf(
		"%s/v1/relay/tenants/%s/domains/%s",
		baseURL,
		domain.Domain.TenantID,
		domain.Domain.DomainID,
	)
	recipientA := admitLiveRelayRecipient(t, client, basePath, domain, 32, 64)
	recipientB := admitLiveRelayRecipient(t, client, basePath, domain, 96, 128)
	publisher := relay.Credential{
		TenantID: domain.Domain.TenantID,
		DomainID: domain.Domain.DomainID,
		MemberID: domain.Member.MemberID,
		Token:    domain.MemberCredential.AuthorizationToken,
	}

	createdBase := time.Now().Add(-time.Hour).UnixMilli()
	initialOrder := []int{4, 1, 5}
	delayedOrder := []int{0, 3, 2}
	allInitial := make([]relay.Envelope, 0, len(initialOrder)+len(delayedOrder))
	for _, logicalIndex := range initialOrder {
		envelope := liveRelayEnvelope(domain, logicalIndex, createdBase)
		result := requireLiveRelayPublish(
			t, client, basePath, publisher, envelope, http.StatusCreated,
		)
		if result.Acceptance != relay.AcceptanceAccepted ||
			result.Sequence != uint64(len(allInitial)+1) {
			t.Fatalf("initial publish result=%+v", result)
		}
		allInitial = append(allInitial, envelope)
	}
	retry := requireLiveRelayPublish(
		t, client, basePath, publisher, allInitial[1], http.StatusOK,
	)
	if retry.Acceptance != relay.AcceptanceDuplicate || retry.Sequence != 2 {
		t.Fatalf("exact retry result=%+v", retry)
	}

	firstPage := fetchLiveRelayPage(t, client, basePath, recipientA, "", 2)
	if got := relaySequences(firstPage.Messages); !reflect.DeepEqual(got, []uint64{1, 2}) ||
		firstPage.Cursor != relay.EncodeCursor(2) {
		t.Fatalf("first page sequences=%v cursor=%q", got, firstPage.Cursor)
	}
	responseLossReplay := fetchLiveRelayPage(t, client, basePath, recipientA, "", 2)
	if !reflect.DeepEqual(responseLossReplay, firstPage) {
		t.Fatalf("cursor replay changed page: first=%+v replay=%+v", firstPage, responseLossReplay)
	}
	initialTail := fetchLiveRelayPage(
		t, client, basePath, recipientA, firstPage.Cursor, relay.MaximumPageSize,
	)
	if got := relaySequences(initialTail.Messages); !reflect.DeepEqual(got, []uint64{3}) ||
		initialTail.Cursor != relay.EncodeCursor(3) {
		t.Fatalf("initial tail sequences=%v cursor=%q", got, initialTail.Cursor)
	}

	for _, logicalIndex := range delayedOrder {
		envelope := liveRelayEnvelope(domain, logicalIndex, createdBase)
		result := requireLiveRelayPublish(
			t, client, basePath, publisher, envelope, http.StatusCreated,
		)
		if result.Acceptance != relay.AcceptanceAccepted ||
			result.Sequence != uint64(len(allInitial)+1) {
			t.Fatalf("delayed publish result=%+v", result)
		}
		allInitial = append(allInitial, envelope)
	}
	delayedPage := fetchLiveRelayPage(
		t, client, basePath, recipientA, initialTail.Cursor, relay.MaximumPageSize,
	)
	if got := relaySequences(delayedPage.Messages); !reflect.DeepEqual(got, []uint64{4, 5, 6}) ||
		delayedPage.Cursor != relay.EncodeCursor(6) {
		t.Fatalf("delayed page sequences=%v cursor=%q", got, delayedPage.Cursor)
	}
	assertLiveRelayEnvelopeOrder(
		t,
		append(append([]relay.Message{}, firstPage.Messages...),
			append(initialTail.Messages, delayedPage.Messages...)...),
		allInitial,
	)

	recipientBInitial := fetchLiveRelayPage(
		t, client, basePath, recipientB, "", relay.MaximumPageSize,
	)
	if got := relaySequences(recipientBInitial.Messages); !reflect.DeepEqual(got, []uint64{1, 2, 3, 4, 5, 6}) ||
		recipientBInitial.Cursor != relay.EncodeCursor(6) {
		t.Fatalf("recipient B initial sequences=%v cursor=%q", got, recipientBInitial.Cursor)
	}

	const concurrentCount = 8
	concurrentEnvelopes := make([]relay.Envelope, concurrentCount)
	results := make(chan liveRelayPublishOutcome, concurrentCount)
	for index := range concurrentEnvelopes {
		concurrentEnvelopes[index] = liveRelayEnvelope(domain, index+6, createdBase)
		envelope := concurrentEnvelopes[index]
		go func() {
			status, result, err := publishLiveRelayEnvelope(
				client, basePath, publisher, envelope,
			)
			results <- liveRelayPublishOutcome{
				Envelope: envelope,
				Status:   status,
				Result:   result,
				Err:      err,
			}
		}()
	}
	concurrentSequences := make([]uint64, 0, concurrentCount)
	sequenceByMessageID := make(map[uuid.UUID]uint64, concurrentCount)
	for range concurrentCount {
		outcome := <-results
		if outcome.Err != nil {
			t.Fatal(outcome.Err)
		}
		if outcome.Status != http.StatusCreated ||
			outcome.Result.Acceptance != relay.AcceptanceAccepted {
			t.Fatalf("concurrent publish outcome=%+v", outcome)
		}
		concurrentSequences = append(concurrentSequences, outcome.Result.Sequence)
		sequenceByMessageID[outcome.Envelope.MessageID] = outcome.Result.Sequence
	}
	sort.Slice(concurrentSequences, func(left, right int) bool {
		return concurrentSequences[left] < concurrentSequences[right]
	})
	expectedConcurrentSequences := make([]uint64, concurrentCount)
	for index := range expectedConcurrentSequences {
		expectedConcurrentSequences[index] = uint64(index + 7)
	}
	if !reflect.DeepEqual(concurrentSequences, expectedConcurrentSequences) {
		t.Fatalf("concurrent sequences=%v; want=%v", concurrentSequences, expectedConcurrentSequences)
	}
	concurrentRetry := requireLiveRelayPublish(
		t, client, basePath, publisher, concurrentEnvelopes[0], http.StatusOK,
	)
	if concurrentRetry.Acceptance != relay.AcceptanceDuplicate ||
		concurrentRetry.Sequence != sequenceByMessageID[concurrentEnvelopes[0].MessageID] {
		t.Fatalf("concurrent exact retry result=%+v", concurrentRetry)
	}

	recipientAConcurrent := fetchLiveRelayPage(
		t, client, basePath, recipientA, delayedPage.Cursor, relay.MaximumPageSize,
	)
	if got := relaySequences(recipientAConcurrent.Messages); !reflect.DeepEqual(got, expectedConcurrentSequences) ||
		recipientAConcurrent.Cursor != relay.EncodeCursor(14) {
		t.Fatalf("recipient A concurrent sequences=%v cursor=%q", got, recipientAConcurrent.Cursor)
	}
	assertLiveRelayMessageSet(t, recipientAConcurrent.Messages, concurrentEnvelopes)

	acknowledgedMessageID := allInitial[0].MessageID
	accepted := acknowledgeLiveRelayMessage(
		t, client, basePath, recipientA, acknowledgedMessageID, relay.AcknowledgmentAccepted,
	)
	if accepted.Acceptance != relay.AcceptanceAccepted ||
		accepted.Stage != relay.AcknowledgmentAccepted {
		t.Fatalf("accepted acknowledgment=%+v", accepted)
	}
	applied := acknowledgeLiveRelayMessage(
		t, client, basePath, recipientA, acknowledgedMessageID, relay.AcknowledgmentApplied,
	)
	if applied.Acceptance != relay.AcceptanceAccepted ||
		applied.Stage != relay.AcknowledgmentApplied {
		t.Fatalf("applied acknowledgment=%+v", applied)
	}
	lowerRetry := acknowledgeLiveRelayMessage(
		t, client, basePath, recipientA, acknowledgedMessageID, relay.AcknowledgmentAccepted,
	)
	if lowerRetry.Acceptance != relay.AcceptanceDuplicate ||
		lowerRetry.Stage != relay.AcknowledgmentApplied {
		t.Fatalf("lower-stage acknowledgment retry=%+v", lowerRetry)
	}

	recipientBConcurrent := fetchLiveRelayPage(
		t, client, basePath, recipientB, recipientBInitial.Cursor, relay.MaximumPageSize,
	)
	if got := relaySequences(recipientBConcurrent.Messages); !reflect.DeepEqual(got, expectedConcurrentSequences) ||
		recipientBConcurrent.Cursor != relay.EncodeCursor(14) {
		t.Fatalf("recipient B concurrent sequences=%v cursor=%q", got, recipientBConcurrent.Cursor)
	}
	independentAccepted := acknowledgeLiveRelayMessage(
		t, client, basePath, recipientB, acknowledgedMessageID, relay.AcknowledgmentAccepted,
	)
	if independentAccepted.Acceptance != relay.AcceptanceAccepted ||
		independentAccepted.Stage != relay.AcknowledgmentAccepted {
		t.Fatalf("recipient B acknowledgment=%+v", independentAccepted)
	}

	blobBytes := bytes.Repeat([]byte("opaque-encrypted-relay-blob-matrix-"), 4_096)
	blobID := relay.BlobID(blobBytes)
	blobURL := basePath + "/blobs/" + blobID
	uploadLiveRelayBlob(t, client, basePath, publisher, blobBytes, true)
	download := requestRelayBlob(
		t, client, http.MethodGet, blobURL, nil,
		recipientB.Credential.Token, recipientB.Registration.MemberID, "",
	)
	requireStatus(t, download, http.StatusOK)
	downloaded, err := io.ReadAll(download.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = download.Body.Close()
	if !bytes.Equal(downloaded, blobBytes) {
		t.Fatalf("blob download byte count=%d; want=%d", len(downloaded), len(blobBytes))
	}
}

func provisionLiveRelayDomain(
	t *testing.T,
	client *http.Client,
	baseURL string,
	operatorToken string,
) liveRelayDomain {
	t.Helper()
	domainRequest := newLiveRelayDomainProvisioningRequest(time.Now().UnixMilli())
	tenantCredential := liveRelayTenantCredential{
		TenantID:           domainRequest.AdministrationCredential.TenantID,
		AuthorizationToken: encodedBytes(160),
	}
	provisioning := liveRelayTenantProvisioningRequest{
		Version: relay.SchemaVersion, RetryID: uuid.New(),
		TenantProvisioningCredential: tenantCredential,
		InitialDomain:                domainRequest,
	}
	response := requestRelayJSON(
		t, client, http.MethodPost, baseURL+"/v1/relay/tenants",
		provisioning,
		operatorToken, uuid.Nil,
	)
	requireStatus(t, response, http.StatusCreated)
	var result relay.TenantProvisioningResult
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if result.InitialDomain.SubscriptionID != domainRequest.SubscriptionID {
		t.Fatalf("provisioned subscription=%s; want=%s", result.InitialDomain.SubscriptionID, domainRequest.SubscriptionID)
	}
	domain := liveRelayDomain{
		Domain:           relay.DomainRegistration{TenantID: tenantCredential.TenantID, DomainID: domainRequest.AdministrationCredential.DomainID},
		SubscriptionID:   domainRequest.SubscriptionID,
		Member:           relay.MemberRegistration{TenantID: tenantCredential.TenantID, DomainID: domainRequest.AdministrationCredential.DomainID, MemberID: domainRequest.MemberCredential.MemberID},
		TenantCredential: tenantCredential,
	}
	domain.AdministrationCredential.AuthorizationToken = domainRequest.AdministrationCredential.AuthorizationToken
	domain.MemberCredential.AuthorizationToken = domainRequest.MemberCredential.AuthorizationToken
	return domain
}

func admitLiveRelayRecipient(
	t *testing.T,
	client *http.Client,
	basePath string,
	domain liveRelayDomain,
	admissionTokenSeed byte,
	memberTokenSeed byte,
) liveRelayMember {
	t.Helper()
	subscriptionID := uuid.New()
	now := time.Now().UnixMilli()
	createSubscription := requestRelayJSON(
		t, client, http.MethodPost, basePath+"/subscriptions",
		relay.SubscriptionCreateRequest{RetryID: uuid.New(), SubscriptionID: subscriptionID, CreatedAtMilliseconds: now},
		domain.AdministrationCredential.AuthorizationToken, uuid.Nil,
	)
	requireStatusAndClose(t, createSubscription, http.StatusCreated)
	admission := relay.AdmissionCredential{
		TenantID:    domain.Domain.TenantID,
		DomainID:    domain.Domain.DomainID,
		AdmissionID: uuid.New(),
		Token:       encodedBytes(admissionTokenSeed),
	}
	admissionDigest, err := relay.AdmissionAuthorizationDigest(admission)
	if err != nil {
		t.Fatal(err)
	}
	response := requestRelayJSON(
		t,
		client,
		http.MethodPost,
		basePath+"/admissions",
		map[string]any{
			"subscriptionID":      subscriptionID,
			"admissionID":         admission.AdmissionID,
			"authorizationDigest": admissionDigest,
			"capabilities": []relay.Capability{
				relay.CapabilityFetchBlob,
				relay.CapabilityAcknowledgeMessage,
				relay.CapabilityFetchMessage,
			},
			"expiresAtMilliseconds": time.Now().Add(time.Minute).UnixMilli(),
		},
		domain.AdministrationCredential.AuthorizationToken,
		uuid.Nil,
	)
	requireStatusAndClose(t, response, http.StatusCreated)
	credential := relay.Credential{
		TenantID: domain.Domain.TenantID,
		DomainID: domain.Domain.DomainID,
		MemberID: uuid.New(),
		Token:    encodedBytes(memberTokenSeed),
	}
	digest, err := relay.AuthorizationDigest(credential)
	if err != nil {
		t.Fatal(err)
	}
	response = requestRelayJSON(
		t,
		client,
		http.MethodPost,
		basePath+"/admissions/"+admission.AdmissionID.String()+"/claim",
		relay.MemberAdmissionClaim{
			MemberID:            credential.MemberID,
			AuthorizationDigest: digest,
		},
		admission.Token,
		uuid.Nil,
	)
	requireStatus(t, response, http.StatusCreated)
	var claim relay.SubscriptionAdmissionClaimResult
	if err := json.NewDecoder(response.Body).Decode(&claim); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	return liveRelayMember{Registration: claim.Member.MemberRegistration, Credential: credential}
}

func liveRelayEnvelope(
	domain liveRelayDomain,
	logicalIndex int,
	createdBase int64,
) relay.Envelope {
	return relay.Envelope{
		Version:               relay.SchemaVersion,
		Algorithm:             relay.EnvelopeAlgorithm,
		TenantID:              domain.Domain.TenantID,
		DomainID:              domain.Domain.DomainID,
		MessageID:             uuid.New(),
		PublisherMemberID:     domain.Member.MemberID,
		KeyEpoch:              uint64(logicalIndex/4 + 1),
		CreatedAtMilliseconds: createdBase + int64(logicalIndex)*1_000,
		Nonce: base64.RawURLEncoding.EncodeToString(
			bytes.Repeat([]byte{byte(logicalIndex + 1)}, 12),
		),
		Ciphertext: base64.RawURLEncoding.EncodeToString(
			[]byte(fmt.Sprintf("opaque-logical-message-%02d", logicalIndex)),
		),
		AuthenticationTag: base64.RawURLEncoding.EncodeToString(
			bytes.Repeat([]byte{byte(logicalIndex + 101)}, 16),
		),
	}
}

type liveRelayPublishOutcome struct {
	Envelope relay.Envelope
	Status   int
	Result   relay.PublishResult
	Err      error
}

func publishLiveRelayEnvelope(
	client *http.Client,
	basePath string,
	credential relay.Credential,
	envelope relay.Envelope,
) (int, relay.PublishResult, error) {
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return 0, relay.PublishResult{}, err
	}
	request, err := http.NewRequest(
		http.MethodPut,
		basePath+"/messages/"+envelope.MessageID.String(),
		bytes.NewReader(encoded),
	)
	if err != nil {
		return 0, relay.PublishResult{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+credential.Token)
	request.Header.Set("X-Facets-Member-ID", credential.MemberID.String())
	response, err := client.Do(request)
	if err != nil {
		return 0, relay.PublishResult{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		return response.StatusCode, relay.PublishResult{}, fmt.Errorf(
			"publish status=%d body=%s", response.StatusCode, body,
		)
	}
	var result relay.PublishResult
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return response.StatusCode, relay.PublishResult{}, err
	}
	return response.StatusCode, result, nil
}

func requireLiveRelayPublish(
	t *testing.T,
	client *http.Client,
	basePath string,
	credential relay.Credential,
	envelope relay.Envelope,
	expectedStatus int,
) relay.PublishResult {
	t.Helper()
	status, result, err := publishLiveRelayEnvelope(client, basePath, credential, envelope)
	if err != nil {
		t.Fatal(err)
	}
	if status != expectedStatus {
		t.Fatalf("publish status=%d; want=%d", status, expectedStatus)
	}
	return result
}

func fetchLiveRelayPage(
	t *testing.T,
	client *http.Client,
	basePath string,
	member liveRelayMember,
	cursor string,
	limit int,
) liveRelayFetchPage {
	t.Helper()
	parameters := url.Values{"limit": []string{fmt.Sprint(limit)}}
	if cursor != "" {
		parameters.Set("cursor", cursor)
	}
	response := requestRelayJSON(
		t,
		client,
		http.MethodGet,
		basePath+"/messages?"+parameters.Encode(),
		nil,
		member.Credential.Token,
		member.Registration.MemberID,
	)
	requireStatus(t, response, http.StatusOK)
	var page liveRelayFetchPage
	if err := json.NewDecoder(response.Body).Decode(&page); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	return page
}

func acknowledgeLiveRelayMessage(
	t *testing.T,
	client *http.Client,
	basePath string,
	member liveRelayMember,
	messageID uuid.UUID,
	stage relay.AcknowledgmentStage,
) relay.AcknowledgmentResult {
	t.Helper()
	response := requestRelayJSON(
		t,
		client,
		http.MethodPost,
		basePath+"/messages/"+messageID.String()+"/acknowledgments",
		map[string]relay.AcknowledgmentStage{"stage": stage},
		member.Credential.Token,
		member.Registration.MemberID,
	)
	requireStatus(t, response, http.StatusOK)
	var result relay.AcknowledgmentResult
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	return result
}

func relaySequences(messages []relay.Message) []uint64 {
	sequences := make([]uint64, len(messages))
	for index, message := range messages {
		sequences[index] = message.Sequence
	}
	return sequences
}

func assertLiveRelayEnvelopeOrder(
	t *testing.T,
	messages []relay.Message,
	expected []relay.Envelope,
) {
	t.Helper()
	if len(messages) != len(expected) {
		t.Fatalf("message count=%d; want=%d", len(messages), len(expected))
	}
	for index := range expected {
		if messages[index].Sequence != uint64(index+1) ||
			messages[index].Envelope != expected[index] {
			t.Fatalf("message[%d]=%+v; want envelope=%+v", index, messages[index], expected[index])
		}
	}
	if messages[0].Envelope.CreatedAtMilliseconds <=
		messages[len(messages)-1].Envelope.CreatedAtMilliseconds {
		t.Fatal("test did not establish that relay order is independent of envelope time")
	}
}

func assertLiveRelayMessageSet(
	t *testing.T,
	messages []relay.Message,
	expected []relay.Envelope,
) {
	t.Helper()
	expectedByID := make(map[uuid.UUID]relay.Envelope, len(expected))
	for _, envelope := range expected {
		expectedByID[envelope.MessageID] = envelope
	}
	if len(messages) != len(expectedByID) {
		t.Fatalf("message count=%d; want=%d", len(messages), len(expectedByID))
	}
	for _, message := range messages {
		envelope, ok := expectedByID[message.Envelope.MessageID]
		if !ok || envelope != message.Envelope {
			t.Fatalf("unexpected concurrent message=%+v", message)
		}
		delete(expectedByID, message.Envelope.MessageID)
	}
	if len(expectedByID) != 0 {
		t.Fatalf("missing concurrent message IDs=%v", expectedByID)
	}
}
