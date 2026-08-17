package integration_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/relay"
)

const (
	highVolumeHistoryMessageCount  = 10_050
	highVolumeSnapshotMessageCount = 3
	highVolumeStateVersion         = 1
)

type highVolumeLiveState struct {
	Version                   int       `json:"version"`
	TenantID                  uuid.UUID `json:"tenantID"`
	DomainID                  uuid.UUID `json:"domainID"`
	AdministrationToken       string    `json:"administrationToken"`
	PublisherSubscriptionID   uuid.UUID `json:"publisherSubscriptionID"`
	PublisherMemberID         uuid.UUID `json:"publisherMemberID"`
	PublisherMemberToken      string    `json:"publisherMemberToken"`
	ReplacementSubscriptionID uuid.UUID `json:"replacementSubscriptionID"`
	ReplacementMemberID       uuid.UUID `json:"replacementMemberID"`
	ReplacementMemberToken    string    `json:"replacementMemberToken"`
	CheckpointID              uuid.UUID `json:"checkpointID"`
	CheckpointBoundaryCursor  string    `json:"checkpointBoundaryCursor"`
	DeliveryCursor            string    `json:"deliveryCursor"`
	SnapshotBlobID            string    `json:"snapshotBlobID"`
	PreparedAtMilliseconds    int64     `json:"preparedAtMilliseconds"`
}

type highVolumeHTTPClient struct {
	t                   *testing.T
	client              *http.Client
	retryRateLimited    bool
	maximumRetryElapsed time.Duration
}

// TestLiveReplicaRelayHighVolumeCheckpointRestart is deliberately opt-in. The
// prepare phase proves the complete high-volume checkpoint/collection path and
// writes only explicitly requested, mode-0600 recovery state outside the
// repository. The verify phase consumes that authority after the Node and
// PostgreSQL containers have been recreated and proves continued delivery
// without provisioning another tenant or domain.
func TestLiveReplicaRelayHighVolumeCheckpointRestart(t *testing.T) {
	if os.Getenv("FACETS_NODE_TEST_HIGH_VOLUME") != "1" {
		t.Skip("FACETS_NODE_TEST_HIGH_VOLUME=1 is required")
	}
	baseURL := strings.TrimRight(os.Getenv("FACETS_NODE_TEST_BASE_URL"), "/")
	statePath := os.Getenv("FACETS_NODE_TEST_HIGH_VOLUME_STATE_PATH")
	if baseURL == "" || statePath == "" {
		t.Fatal("FACETS_NODE_TEST_BASE_URL and FACETS_NODE_TEST_HIGH_VOLUME_STATE_PATH are required")
	}
	validateHighVolumeStatePath(t, statePath)
	httpClient := &highVolumeHTTPClient{
		t:                   t,
		client:              &http.Client{Timeout: 45 * time.Second},
		retryRateLimited:    os.Getenv("FACETS_NODE_TEST_HIGH_VOLUME_RETRY_429") == "1",
		maximumRetryElapsed: 2 * time.Minute,
	}
	switch phase := os.Getenv("FACETS_NODE_TEST_HIGH_VOLUME_PHASE"); phase {
	case "prepare":
		operatorToken := os.Getenv("FACETS_NODE_TEST_OPERATOR_TOKEN")
		if operatorToken == "" {
			t.Fatal("FACETS_NODE_TEST_OPERATOR_TOKEN is required for the prepare phase")
		}
		prepareHighVolumeRelayState(t, httpClient, baseURL, operatorToken, statePath)
	case "verify":
		verifyHighVolumeRelayState(t, httpClient, baseURL, statePath)
	default:
		t.Fatalf("FACETS_NODE_TEST_HIGH_VOLUME_PHASE=%q; want prepare or verify", phase)
	}
}

func prepareHighVolumeRelayState(
	t *testing.T,
	httpClient *highVolumeHTTPClient,
	baseURL string,
	operatorToken string,
	statePath string,
) {
	t.Helper()
	domain := provisionHighVolumeRelayDomain(t, httpClient, baseURL, operatorToken)
	basePath := fmt.Sprintf(
		"%s/v1/relay/tenants/%s/domains/%s",
		baseURL, domain.Domain.TenantID, domain.Domain.DomainID,
	)
	publisher := liveRelayMember{
		Registration: domain.Member,
		Credential: relay.Credential{
			TenantID: domain.Domain.TenantID, DomainID: domain.Domain.DomainID,
			MemberID: domain.Member.MemberID, Token: domain.MemberCredential.AuthorizationToken,
		},
	}
	initialTenantStatus := getHighVolumeTenantStatus(t, httpClient, baseURL, domain)
	if initialTenantStatus.Quota.MaximumAggregateMessageCount <= highVolumeHistoryMessageCount ||
		initialTenantStatus.Quota.MaximumAggregateMessageByteCount <= 0 ||
		initialTenantStatus.Quota.MaximumAggregateBlobCount <= 0 ||
		initialTenantStatus.Quota.MaximumAggregateBlobByteCount <= 0 {
		t.Fatalf("tenant was not provisioned with sufficient aggregate quota: %+v", initialTenantStatus.Quota)
	}
	recipientSubscription := createHighVolumeSubscription(t, httpClient, basePath, domain, time.Now().UnixMilli())
	recipient := createHighVolumeMember(
		t, httpClient, basePath, domain, recipientSubscription.SubscriptionID,
		[]relay.Capability{relay.CapabilityFetchBlob, relay.CapabilityAcknowledgeMessage, relay.CapabilityFetchMessage},
	)
	recipientAgentTwo := createHighVolumeMember(
		t, httpClient, basePath, domain, recipientSubscription.SubscriptionID,
		[]relay.Capability{relay.CapabilityFetchBlob, relay.CapabilityAcknowledgeMessage, relay.CapabilityFetchMessage},
	)

	historyIDs := make([]uuid.UUID, 0, highVolumeHistoryMessageCount)
	createdAt := time.Now().UnixMilli()
	for index := 0; index < highVolumeHistoryMessageCount; index++ {
		envelope := highVolumeEnvelope(domain, publisher.Credential.MemberID, index, createdAt)
		result := publishHighVolumeEnvelope(t, httpClient, basePath, publisher, envelope)
		if result.Sequence != uint64(index+1) || result.Acceptance != relay.AcceptanceAccepted {
			t.Fatalf("history publish[%d]=%+v", index, result)
		}
		historyIDs = append(historyIDs, envelope.MessageID)
	}

	cursor := ""
	acknowledged := 0
	for acknowledged < highVolumeHistoryMessageCount {
		page := fetchHighVolumePage(t, httpClient, basePath, recipient, cursor, relay.MaximumPageSize)
		if len(page.Messages) == 0 {
			t.Fatalf("fetch stopped at %d of %d messages", acknowledged, highVolumeHistoryMessageCount)
		}
		if acknowledged == 0 {
			duplicatePage := fetchHighVolumePage(t, httpClient, basePath, recipientAgentTwo, cursor, relay.MaximumPageSize)
			if len(duplicatePage.Messages) != len(page.Messages) || duplicatePage.Cursor != page.Cursor {
				t.Fatalf("same-subscription agents received different first pages: first=%d/%s second=%d/%s", len(page.Messages), page.Cursor, len(duplicatePage.Messages), duplicatePage.Cursor)
			}
			for index := range page.Messages {
				if page.Messages[index].Envelope.MessageID != duplicatePage.Messages[index].Envelope.MessageID {
					t.Fatalf("same-subscription page differs at index %d", index)
				}
			}
		}
		for _, message := range page.Messages {
			if message.Sequence != uint64(acknowledged+1) ||
				message.Envelope.MessageID != historyIDs[acknowledged] {
				t.Fatalf("history fetch[%d]=sequence %d message %s", acknowledged, message.Sequence, message.Envelope.MessageID)
			}
			agent := recipient
			if acknowledged%2 == 1 {
				agent = recipientAgentTwo
			}
			acknowledgeHighVolumeMessage(t, httpClient, basePath, agent, message.Envelope.MessageID)
			acknowledged++
		}
		cursor = page.Cursor
	}
	if cursor != relay.EncodeCursor(highVolumeHistoryMessageCount) {
		t.Fatalf("history cursor=%s; want=%s", cursor, relay.EncodeCursor(highVolumeHistoryMessageCount))
	}

	statusBeforeFence := getHighVolumeDomainStatus(t, httpClient, basePath, domain)
	if statusBeforeFence.MessageCount != highVolumeHistoryMessageCount ||
		statusBeforeFence.Quota.MaximumMessageCount <= highVolumeHistoryMessageCount {
		t.Fatalf("domain was not provisioned with checkpoint headroom: %+v", statusBeforeFence)
	}

	fenceRequest := relay.CheckpointFenceRequest{
		RetryID: uuid.New(), FenceID: uuid.New(), RequestedAtMilliseconds: time.Now().UnixMilli(),
	}
	var fence relay.CheckpointFenceResponse
	httpClient.json(
		http.MethodPost, basePath+"/checkpoint-fences", fenceRequest,
		publisher.Credential.Token, publisher.Credential.MemberID, &fence, http.StatusCreated,
	)
	if fence.BoundaryCursor != cursor {
		t.Fatalf("fence boundary=%s; want=%s", fence.BoundaryCursor, cursor)
	}

	snapshotBytes := highVolumeSnapshotBytes()
	snapshotBlobID := uploadHighVolumeSnapshot(t, httpClient, basePath, publisher, snapshotBytes)
	statusAfterUpload := getHighVolumeDomainStatus(t, httpClient, basePath, domain)
	if statusAfterUpload.ReservedBlobCount != 0 || statusAfterUpload.ReservedBlobByteCount != 0 ||
		statusAfterUpload.BlobCount != 1 || statusAfterUpload.BlobByteCount != int64(len(snapshotBytes)) {
		t.Fatalf("unexpected finalized snapshot counters: %+v", statusAfterUpload)
	}

	snapshotEnvelopes := make([]relay.Envelope, 0, highVolumeSnapshotMessageCount)
	for index := 0; index < highVolumeSnapshotMessageCount; index++ {
		envelope := highVolumeEnvelope(
			domain, publisher.Credential.MemberID,
			highVolumeHistoryMessageCount+index, createdAt,
		)
		result := publishHighVolumeEnvelope(t, httpClient, basePath, publisher, envelope)
		if result.Sequence != uint64(highVolumeHistoryMessageCount+index+1) {
			t.Fatalf("snapshot publish[%d]=%+v", index, result)
		}
		snapshotEnvelopes = append(snapshotEnvelopes, envelope)
	}
	quarantined := fetchHighVolumePage(t, httpClient, basePath, recipient, fence.BoundaryCursor, relay.MaximumPageSize)
	if len(quarantined.Messages) != 0 || quarantined.Cursor != fence.BoundaryCursor {
		t.Fatalf("checkpoint suffix escaped quarantine: %+v", quarantined)
	}

	retainedMessageIDs := make([]uuid.UUID, 0, len(snapshotEnvelopes))
	for _, envelope := range snapshotEnvelopes {
		retainedMessageIDs = append(retainedMessageIDs, envelope.MessageID)
	}
	sort.Slice(retainedMessageIDs, func(i, j int) bool {
		return retainedMessageIDs[i].String() < retainedMessageIDs[j].String()
	})
	candidate := relay.CheckpointCandidate{
		Version: relay.SchemaVersion, RetryID: uuid.New(), CheckpointID: uuid.New(), FenceID: fence.FenceID,
		TenantID: domain.Domain.TenantID, DomainID: domain.Domain.DomainID,
		PublisherSubscriptionID: domain.SubscriptionID,
		CoveredThroughCursor:    fence.BoundaryCursor, RetainedMessageIDs: retainedMessageIDs,
		RetainedBlobIDs: []string{snapshotBlobID}, CreatedAtMilliseconds: time.Now().UnixMilli(),
	}
	var staged relay.CheckpointStageResponse
	httpClient.json(
		http.MethodPost, basePath+"/checkpoints/candidates", candidate,
		publisher.Credential.Token, publisher.Credential.MemberID, &staged, http.StatusCreated,
	)
	activationRequest := relay.CheckpointActivationRequest{
		RetryID: uuid.New(), CheckpointID: candidate.CheckpointID, ActivatedAtMilliseconds: time.Now().UnixMilli(),
	}
	checkpointPath := basePath + "/checkpoints/" + candidate.CheckpointID.String()
	var activation relay.CheckpointActivationResponse
	httpClient.json(
		http.MethodPost, checkpointPath+"/activation", activationRequest,
		domain.AdministrationCredential.AuthorizationToken, uuid.Nil, &activation, http.StatusCreated,
	)
	if activation.StartCursor != fence.BoundaryCursor {
		t.Fatalf("activation start cursor=%s; want boundary=%s", activation.StartCursor, fence.BoundaryCursor)
	}
	revealed := fetchHighVolumePage(t, httpClient, basePath, recipientAgentTwo, fence.BoundaryCursor, relay.MaximumPageSize)
	assertHighVolumeSnapshotMessages(t, revealed.Messages, snapshotEnvelopes)

	firstPlan := dryRunHighVolumeCollection(t, httpClient, checkpointPath, domain, candidate.CheckpointID)
	if !firstPlan.Eligible || firstPlan.MessageCount != highVolumeHistoryMessageCount ||
		firstPlan.BlobCount != 0 || len(firstPlan.MissingCustodySubscriptionIDs) != 0 {
		t.Fatalf("unexpected first collection plan: %+v", firstPlan)
	}
	firstCollectionRequest := relay.CheckpointCollectionRequest{
		RetryID: uuid.New(), CheckpointID: candidate.CheckpointID, PlanDigest: firstPlan.PlanDigest,
		MaximumMessageCount:     relay.MaximumCheckpointCollectionCount,
		MaximumBlobCount:        relay.MaximumCheckpointCollectionCount,
		RequestedAtMilliseconds: time.Now().UnixMilli(),
	}
	firstCollection := collectHighVolumeCheckpoint(t, httpClient, checkpointPath, domain, firstCollectionRequest)
	if firstCollection.Duplicate || firstCollection.Completed ||
		firstCollection.DeletedMessageCount != relay.MaximumCheckpointCollectionCount {
		t.Fatalf("unexpected first collection: %+v", firstCollection)
	}
	firstRetry := collectHighVolumeCheckpoint(t, httpClient, checkpointPath, domain, firstCollectionRequest)
	if !firstRetry.Duplicate || firstRetry.DeletedMessageCount != relay.MaximumCheckpointCollectionCount {
		t.Fatalf("unexpected first collection exact retry: %+v", firstRetry)
	}

	remainingPlan := dryRunHighVolumeCollection(t, httpClient, checkpointPath, domain, candidate.CheckpointID)
	remainingCount := int64(highVolumeHistoryMessageCount) - relay.MaximumCheckpointCollectionCount
	if !remainingPlan.Eligible || remainingPlan.MessageCount != remainingCount ||
		remainingPlan.PlanDigest == firstPlan.PlanDigest {
		t.Fatalf("unexpected remaining collection plan: %+v", remainingPlan)
	}
	remainingRequest := relay.CheckpointCollectionRequest{
		RetryID: uuid.New(), CheckpointID: candidate.CheckpointID, PlanDigest: remainingPlan.PlanDigest,
		MaximumMessageCount:     relay.MaximumCheckpointCollectionCount,
		MaximumBlobCount:        relay.MaximumCheckpointCollectionCount,
		RequestedAtMilliseconds: time.Now().UnixMilli(),
	}
	remainingCollection := collectHighVolumeCheckpoint(t, httpClient, checkpointPath, domain, remainingRequest)
	if remainingCollection.Duplicate || !remainingCollection.Completed ||
		remainingCollection.DeletedMessageCount != remainingCount {
		t.Fatalf("unexpected remaining collection: %+v", remainingCollection)
	}
	remainingRetry := collectHighVolumeCheckpoint(t, httpClient, checkpointPath, domain, remainingRequest)
	if !remainingRetry.Duplicate || !remainingRetry.Completed ||
		remainingRetry.DeletedMessageCount != remainingCount {
		t.Fatalf("unexpected remaining collection exact retry: %+v", remainingRetry)
	}

	change := relay.SubscriptionStatusChangeRequest{
		RetryID: uuid.New(), Status: relay.SubscriptionRebootstrapRequired,
		ChangedAtMilliseconds: time.Now().UnixMilli(),
	}
	var changed relay.SubscriptionStatusChangeResponse
	httpClient.json(
		http.MethodPost,
		basePath+"/subscriptions/"+recipientSubscription.SubscriptionID.String()+"/status",
		change, domain.AdministrationCredential.AuthorizationToken, uuid.Nil, &changed, http.StatusCreated,
	)
	if changed.Subscription.StartCursor == nil || *changed.Subscription.StartCursor != fence.BoundaryCursor {
		t.Fatalf("rebootstrap cursor=%v; want=%s", changed.Subscription.StartCursor, fence.BoundaryCursor)
	}

	replacementSubscription := createHighVolumeSubscription(t, httpClient, basePath, domain, time.Now().UnixMilli())
	if replacementSubscription.StartCursor == nil || *replacementSubscription.StartCursor != fence.BoundaryCursor {
		t.Fatalf("replacement start cursor=%v; want=%s", replacementSubscription.StartCursor, fence.BoundaryCursor)
	}
	replacement := createHighVolumeMember(
		t, httpClient, basePath, domain, replacementSubscription.SubscriptionID,
		[]relay.Capability{relay.CapabilityFetchBlob, relay.CapabilityAcknowledgeMessage, relay.CapabilityFetchMessage},
	)
	replacementSnapshot := fetchHighVolumePage(
		t, httpClient, basePath, replacement, *replacementSubscription.StartCursor, relay.MaximumPageSize,
	)
	assertHighVolumeSnapshotMessages(t, replacementSnapshot.Messages, snapshotEnvelopes)

	mutation := highVolumeEnvelope(
		domain, publisher.Credential.MemberID,
		highVolumeHistoryMessageCount+highVolumeSnapshotMessageCount, createdAt,
	)
	mutationResult := publishHighVolumeEnvelope(t, httpClient, basePath, publisher, mutation)
	if mutationResult.Sequence != uint64(highVolumeHistoryMessageCount+highVolumeSnapshotMessageCount+1) {
		t.Fatalf("post-checkpoint mutation result=%+v", mutationResult)
	}
	mutationPage := fetchHighVolumePage(
		t, httpClient, basePath, replacement, replacementSnapshot.Cursor, relay.MaximumPageSize,
	)
	if len(mutationPage.Messages) != 1 || mutationPage.Messages[0].Envelope != mutation {
		t.Fatalf("post-checkpoint mutation delivery=%+v", mutationPage)
	}
	acknowledgeHighVolumeMessage(t, httpClient, basePath, replacement, mutation.MessageID)

	domainStatus := getHighVolumeDomainStatus(t, httpClient, basePath, domain)
	expectedMessageBytes := int64(0)
	for _, envelope := range append(snapshotEnvelopes, mutation) {
		byteCount, err := envelope.CiphertextByteCount()
		if err != nil {
			t.Fatal(err)
		}
		expectedMessageBytes += byteCount
	}
	if domainStatus.MessageCount != highVolumeSnapshotMessageCount+1 ||
		domainStatus.MessageByteCount != expectedMessageBytes ||
		domainStatus.BlobCount != 1 || domainStatus.BlobByteCount != int64(len(snapshotBytes)) ||
		domainStatus.ReservedBlobCount != 0 || domainStatus.ReservedBlobByteCount != 0 ||
		domainStatus.ActiveSubscriptionCount != 2 ||
		domainStatus.OldestUncollectedCursor == nil || *domainStatus.OldestUncollectedCursor != fence.BoundaryCursor ||
		domainStatus.LatestActivatedCheckpointID == nil || *domainStatus.LatestActivatedCheckpointID != candidate.CheckpointID {
		t.Fatalf("unexpected final domain status: %+v", domainStatus)
	}
	tenantStatus := getHighVolumeTenantStatus(t, httpClient, baseURL, domain)
	if tenantStatus.DomainCount != 1 ||
		tenantStatus.AggregateMessageCount != domainStatus.MessageCount ||
		tenantStatus.AggregateMessageByteCount != domainStatus.MessageByteCount ||
		tenantStatus.AggregateBlobCount != domainStatus.BlobCount ||
		tenantStatus.AggregateBlobByteCount != domainStatus.BlobByteCount ||
		tenantStatus.ReservedBlobCount != 0 || tenantStatus.ReservedBlobByteCount != 0 {
		t.Fatalf("unexpected final tenant status: %+v", tenantStatus)
	}

	state := highVolumeLiveState{
		Version:  highVolumeStateVersion,
		TenantID: domain.Domain.TenantID,
		DomainID: domain.Domain.DomainID, AdministrationToken: domain.AdministrationCredential.AuthorizationToken,
		PublisherSubscriptionID: domain.SubscriptionID,
		PublisherMemberID:       publisher.Credential.MemberID, PublisherMemberToken: publisher.Credential.Token,
		ReplacementSubscriptionID: replacementSubscription.SubscriptionID,
		ReplacementMemberID:       replacement.Credential.MemberID, ReplacementMemberToken: replacement.Credential.Token,
		CheckpointID: candidate.CheckpointID, CheckpointBoundaryCursor: fence.BoundaryCursor,
		DeliveryCursor: mutationPage.Cursor, SnapshotBlobID: snapshotBlobID,
		PreparedAtMilliseconds: time.Now().UnixMilli(),
	}
	writeHighVolumeState(t, statePath, state)
}

func verifyHighVolumeRelayState(
	t *testing.T,
	httpClient *highVolumeHTTPClient,
	baseURL string,
	statePath string,
) {
	t.Helper()
	state := readHighVolumeState(t, statePath)
	domain := liveRelayDomain{
		Domain:         relay.DomainRegistration{TenantID: state.TenantID, DomainID: state.DomainID},
		SubscriptionID: state.PublisherSubscriptionID,
		Member:         relay.MemberRegistration{TenantID: state.TenantID, DomainID: state.DomainID, MemberID: state.PublisherMemberID},
	}
	domain.AdministrationCredential.AuthorizationToken = state.AdministrationToken
	domain.MemberCredential.AuthorizationToken = state.PublisherMemberToken
	basePath := fmt.Sprintf(
		"%s/v1/relay/tenants/%s/domains/%s", baseURL, state.TenantID, state.DomainID,
	)
	status := getHighVolumeDomainStatus(t, httpClient, basePath, domain)
	if status.LatestActivatedCheckpointID == nil || *status.LatestActivatedCheckpointID != state.CheckpointID ||
		status.ReservedBlobCount != 0 || status.ReservedBlobByteCount != 0 {
		t.Fatalf("restored domain status=%+v", status)
	}
	snapshotResponse := httpClient.request(
		http.MethodGet, basePath+"/blobs/"+state.SnapshotBlobID, nil, "",
		state.ReplacementMemberToken, state.ReplacementMemberID, []int{http.StatusOK},
	)
	snapshot, err := io.ReadAll(snapshotResponse.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = snapshotResponse.Body.Close()
	if !bytes.Equal(snapshot, highVolumeSnapshotBytes()) {
		t.Fatalf("restored snapshot bytes=%d; want=%d", len(snapshot), len(highVolumeSnapshotBytes()))
	}

	publisher := liveRelayMember{
		Registration: relay.MemberRegistration{TenantID: state.TenantID, DomainID: state.DomainID, MemberID: state.PublisherMemberID},
		Credential:   relay.Credential{TenantID: state.TenantID, DomainID: state.DomainID, MemberID: state.PublisherMemberID, Token: state.PublisherMemberToken},
	}
	replacement := liveRelayMember{
		Registration: relay.MemberRegistration{TenantID: state.TenantID, DomainID: state.DomainID, MemberID: state.ReplacementMemberID},
		Credential:   relay.Credential{TenantID: state.TenantID, DomainID: state.DomainID, MemberID: state.ReplacementMemberID, Token: state.ReplacementMemberToken},
	}
	mutation := highVolumeEnvelope(domain, publisher.Credential.MemberID, int(time.Now().UnixNano()), time.Now().UnixMilli())
	published := publishHighVolumeEnvelope(t, httpClient, basePath, publisher, mutation)
	if published.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("post-recreation publication was unexpectedly duplicate: %+v", published)
	}
	page := fetchHighVolumePage(t, httpClient, basePath, replacement, state.DeliveryCursor, relay.MaximumPageSize)
	if len(page.Messages) == 0 || page.Messages[len(page.Messages)-1].Envelope.MessageID != mutation.MessageID {
		t.Fatalf("post-recreation delivery does not contain new mutation %s: %+v", mutation.MessageID, page)
	}
	acknowledgeHighVolumeMessage(t, httpClient, basePath, replacement, mutation.MessageID)
}

func provisionHighVolumeRelayDomain(
	t *testing.T,
	httpClient *highVolumeHTTPClient,
	baseURL string,
	operatorToken string,
) liveRelayDomain {
	t.Helper()
	domainRequest := newLiveRelayDomainProvisioningRequest(time.Now().UnixMilli())
	domainRequest.AdministrationCredential.AuthorizationToken = highVolumeToken(t)
	domainRequest.MemberCredential.AuthorizationToken = highVolumeToken(t)
	domainRequest.Quota = &relay.DomainQuota{
		MaximumMessageCount:     20_000,
		MaximumMessageByteCount: relay.DefaultMaximumMessageByteCount,
		MaximumBlobCount:        relay.DefaultMaximumBlobCount,
		MaximumBlobByteCount:    relay.DefaultMaximumBlobByteCount,
	}
	tenantCredential := liveRelayTenantCredential{
		TenantID:           domainRequest.AdministrationCredential.TenantID,
		AuthorizationToken: highVolumeToken(t),
	}
	request := liveRelayTenantProvisioningRequest{
		Version: relay.SchemaVersion, RetryID: uuid.New(),
		TenantProvisioningCredential: tenantCredential, InitialDomain: domainRequest,
	}
	var result relay.TenantProvisioningResult
	httpClient.json(
		http.MethodPost, baseURL+"/v1/relay/tenants", request,
		operatorToken, uuid.Nil, &result, http.StatusCreated,
	)
	if result.InitialDomain.SubscriptionID != domainRequest.SubscriptionID {
		t.Fatalf("provisioned subscription=%s; want=%s", result.InitialDomain.SubscriptionID, domainRequest.SubscriptionID)
	}
	domain := liveRelayDomain{
		Domain: relay.DomainRegistration{
			TenantID: tenantCredential.TenantID,
			DomainID: domainRequest.AdministrationCredential.DomainID,
		},
		SubscriptionID: domainRequest.SubscriptionID,
		Member: relay.MemberRegistration{
			TenantID: tenantCredential.TenantID,
			DomainID: domainRequest.AdministrationCredential.DomainID,
			MemberID: domainRequest.MemberCredential.MemberID,
		},
		TenantCredential: tenantCredential,
	}
	domain.AdministrationCredential.AuthorizationToken = domainRequest.AdministrationCredential.AuthorizationToken
	domain.MemberCredential.AuthorizationToken = domainRequest.MemberCredential.AuthorizationToken
	return domain
}

func createHighVolumeSubscription(
	t *testing.T,
	httpClient *highVolumeHTTPClient,
	basePath string,
	domain liveRelayDomain,
	createdAt int64,
) relay.Subscription {
	t.Helper()
	request := relay.SubscriptionCreateRequest{
		RetryID: uuid.New(), SubscriptionID: uuid.New(), CreatedAtMilliseconds: createdAt,
	}
	var response relay.SubscriptionCreateResponse
	httpClient.json(
		http.MethodPost, basePath+"/subscriptions", request,
		domain.AdministrationCredential.AuthorizationToken, uuid.Nil, &response, http.StatusCreated,
	)
	return response.Subscription
}

func createHighVolumeMember(
	t *testing.T,
	httpClient *highVolumeHTTPClient,
	basePath string,
	domain liveRelayDomain,
	subscriptionID uuid.UUID,
	capabilities []relay.Capability,
) liveRelayMember {
	t.Helper()
	var response struct {
		Member     relay.SubscriptionMemberRegistration `json:"member"`
		Credential liveRelayMemberCredential            `json:"credential"`
	}
	httpClient.json(
		http.MethodPost, basePath+"/members",
		map[string]any{"subscriptionID": subscriptionID, "capabilities": capabilities},
		domain.AdministrationCredential.AuthorizationToken, uuid.Nil, &response, http.StatusCreated,
	)
	return liveRelayMember{
		Registration: response.Member.MemberRegistration,
		Credential: relay.Credential{
			TenantID: response.Credential.TenantID, DomainID: response.Credential.DomainID,
			MemberID: response.Credential.MemberID, Token: response.Credential.AuthorizationToken,
		},
	}
}

func highVolumeEnvelope(
	domain liveRelayDomain,
	publisherMemberID uuid.UUID,
	logicalIndex int,
	createdAt int64,
) relay.Envelope {
	messageID := uuid.New()
	digest := sha256.Sum256(messageID[:])
	return relay.Envelope{
		Version: relay.SchemaVersion, Algorithm: relay.EnvelopeAlgorithm,
		TenantID: domain.Domain.TenantID, DomainID: domain.Domain.DomainID,
		MessageID: messageID, PublisherMemberID: publisherMemberID,
		KeyEpoch: 1, CreatedAtMilliseconds: createdAt,
		Nonce: base64.RawURLEncoding.EncodeToString(digest[:12]),
		Ciphertext: base64.RawURLEncoding.EncodeToString(
			[]byte(fmt.Sprintf("opaque-high-volume-message-%d", logicalIndex)),
		),
		AuthenticationTag: base64.RawURLEncoding.EncodeToString(digest[16:]),
	}
}

func publishHighVolumeEnvelope(
	t *testing.T,
	httpClient *highVolumeHTTPClient,
	basePath string,
	publisher liveRelayMember,
	envelope relay.Envelope,
) relay.PublishResult {
	t.Helper()
	var result relay.PublishResult
	httpClient.json(
		http.MethodPut, basePath+"/messages/"+envelope.MessageID.String(), envelope,
		publisher.Credential.Token, publisher.Credential.MemberID, &result, http.StatusCreated,
	)
	return result
}

func fetchHighVolumePage(
	t *testing.T,
	httpClient *highVolumeHTTPClient,
	basePath string,
	member liveRelayMember,
	cursor string,
	limit int,
) liveRelayFetchPage {
	t.Helper()
	query := url.Values{"limit": []string{strconv.Itoa(limit)}}
	if cursor != "" {
		query.Set("cursor", cursor)
	}
	var page liveRelayFetchPage
	httpClient.json(
		http.MethodGet, basePath+"/messages?"+query.Encode(), nil,
		member.Credential.Token, member.Credential.MemberID, &page, http.StatusOK,
	)
	return page
}

func acknowledgeHighVolumeMessage(
	t *testing.T,
	httpClient *highVolumeHTTPClient,
	basePath string,
	member liveRelayMember,
	messageID uuid.UUID,
) {
	t.Helper()
	var result relay.AcknowledgmentResult
	httpClient.json(
		http.MethodPost, basePath+"/messages/"+messageID.String()+"/acknowledgments",
		map[string]relay.AcknowledgmentStage{"stage": relay.AcknowledgmentAccepted},
		member.Credential.Token, member.Credential.MemberID, &result, http.StatusOK,
	)
	if result.Stage != relay.AcknowledgmentAccepted && result.Stage != relay.AcknowledgmentApplied {
		t.Fatalf("acknowledgment result=%+v", result)
	}
}

func uploadHighVolumeSnapshot(
	t *testing.T,
	httpClient *highVolumeHTTPClient,
	basePath string,
	publisher liveRelayMember,
	content []byte,
) string {
	t.Helper()
	uploadID := uuid.New()
	blobID := relay.BlobID(content)
	request := relay.BlobUploadRequest{
		RetryID: uuid.New(), UploadID: uploadID, RelayBlobID: blobID,
		ByteCount: int64(len(content)), CreatedAtMilliseconds: time.Now().UnixMilli(),
	}
	var created relay.BlobUploadCreateResponse
	httpClient.json(
		http.MethodPost, basePath+"/blob-uploads", request,
		publisher.Credential.Token, publisher.Credential.MemberID, &created, http.StatusCreated,
	)
	uploadPath := basePath + "/blob-uploads/" + uploadID.String()
	const chunkSize = 128 * 1_024
	for offset := 0; offset < len(content); offset += chunkSize {
		end := offset + chunkSize
		if end > len(content) {
			end = len(content)
		}
		chunk := content[offset:end]
		digest := sha256.Sum256(chunk)
		response := httpClient.request(
			http.MethodPatch, uploadPath, chunk, "application/octet-stream",
			publisher.Credential.Token, publisher.Credential.MemberID, []int{http.StatusOK},
			map[string]string{
				"Upload-Offset":  strconv.Itoa(offset),
				"X-Chunk-SHA256": hex.EncodeToString(digest[:]),
			},
		)
		var status relay.BlobUploadStatus
		if err := json.NewDecoder(response.Body).Decode(&status); err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if status.CommittedOffset != int64(end) {
			t.Fatalf("snapshot upload offset=%d; want=%d", status.CommittedOffset, end)
		}
	}
	finalization := relay.BlobUploadFinalizationRequest{
		RetryID: uuid.New(), UploadID: uploadID, RelayBlobID: blobID,
		ByteCount: int64(len(content)), FinalizedAtMilliseconds: time.Now().UnixMilli(),
	}
	var finalized relay.BlobUploadFinalizationResponse
	httpClient.json(
		http.MethodPost, uploadPath+"/finalization", finalization,
		publisher.Credential.Token, publisher.Credential.MemberID, &finalized, http.StatusCreated,
	)
	if finalized.RelayBlobID != blobID || finalized.ByteCount != int64(len(content)) {
		t.Fatalf("snapshot finalization=%+v", finalized)
	}
	return blobID
}

func highVolumeSnapshotBytes() []byte {
	pattern := []byte("facets-node-opaque-retained-snapshot-v1\x00")
	result := make([]byte, 768*1_024+317)
	for offset := 0; offset < len(result); offset += len(pattern) {
		copy(result[offset:], pattern)
	}
	return result
}

func dryRunHighVolumeCollection(
	t *testing.T,
	httpClient *highVolumeHTTPClient,
	checkpointPath string,
	domain liveRelayDomain,
	checkpointID uuid.UUID,
) relay.CheckpointDryRunResponse {
	t.Helper()
	var response relay.CheckpointDryRunResponse
	httpClient.json(
		http.MethodPost, checkpointPath+"/collection-dry-run",
		relay.CheckpointDryRunRequest{CheckpointID: checkpointID},
		domain.AdministrationCredential.AuthorizationToken, uuid.Nil, &response, http.StatusOK,
	)
	return response
}

func collectHighVolumeCheckpoint(
	t *testing.T,
	httpClient *highVolumeHTTPClient,
	checkpointPath string,
	domain liveRelayDomain,
	request relay.CheckpointCollectionRequest,
) relay.CheckpointCollectionResponse {
	t.Helper()
	var response relay.CheckpointCollectionResponse
	httpClient.json(
		http.MethodPost, checkpointPath+"/collection", request,
		domain.AdministrationCredential.AuthorizationToken, uuid.Nil, &response, http.StatusOK,
	)
	return response
}

func getHighVolumeDomainStatus(
	t *testing.T,
	httpClient *highVolumeHTTPClient,
	basePath string,
	domain liveRelayDomain,
) relay.DomainStatus {
	t.Helper()
	var status relay.DomainStatus
	httpClient.json(
		http.MethodGet, basePath+"/status", nil,
		domain.AdministrationCredential.AuthorizationToken, uuid.Nil, &status, http.StatusOK,
	)
	return status
}

func getHighVolumeTenantStatus(
	t *testing.T,
	httpClient *highVolumeHTTPClient,
	baseURL string,
	domain liveRelayDomain,
) relay.TenantStatus {
	t.Helper()
	var status relay.TenantStatus
	httpClient.json(
		http.MethodGet,
		baseURL+"/v1/relay/tenants/"+domain.Domain.TenantID.String()+"/status", nil,
		domain.TenantCredential.AuthorizationToken, uuid.Nil, &status, http.StatusOK,
	)
	return status
}

func assertHighVolumeSnapshotMessages(
	t *testing.T,
	messages []relay.Message,
	expected []relay.Envelope,
) {
	t.Helper()
	if len(messages) != len(expected) {
		t.Fatalf("snapshot message count=%d; want=%d", len(messages), len(expected))
	}
	for index := range expected {
		if messages[index].Envelope != expected[index] {
			t.Fatalf("snapshot message[%d]=%+v; want=%+v", index, messages[index].Envelope, expected[index])
		}
	}
}

func (client *highVolumeHTTPClient) json(
	method string,
	requestURL string,
	body any,
	token string,
	memberID uuid.UUID,
	result any,
	expected ...int,
) int {
	client.t.Helper()
	var encoded []byte
	var err error
	if body != nil {
		encoded, err = json.Marshal(body)
		if err != nil {
			client.t.Fatal(err)
		}
	}
	response := client.request(
		method, requestURL, encoded, "application/json", token, memberID, expected,
	)
	defer response.Body.Close()
	if result != nil {
		if err := json.NewDecoder(response.Body).Decode(result); err != nil {
			client.t.Fatal(err)
		}
	} else {
		_, _ = io.Copy(io.Discard, response.Body)
	}
	return response.StatusCode
}

func (client *highVolumeHTTPClient) request(
	method string,
	requestURL string,
	body []byte,
	contentType string,
	token string,
	memberID uuid.UUID,
	expectedStatuses []int,
	extraHeaders ...map[string]string,
) *http.Response {
	client.t.Helper()
	started := time.Now()
	for {
		request, err := http.NewRequest(method, requestURL, bytes.NewReader(body))
		if err != nil {
			client.t.Fatal(err)
		}
		if body != nil && contentType != "" {
			request.Header.Set("Content-Type", contentType)
		}
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		if memberID != uuid.Nil {
			request.Header.Set("X-Facets-Member-ID", memberID.String())
		}
		for _, headers := range extraHeaders {
			for name, value := range headers {
				request.Header.Set(name, value)
			}
		}
		response, err := client.client.Do(request)
		if err != nil {
			client.t.Fatal(err)
		}
		if response.StatusCode == http.StatusTooManyRequests && client.retryRateLimited {
			retrySeconds, parseErr := strconv.Atoi(response.Header.Get("Retry-After"))
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if parseErr != nil || retrySeconds <= 0 {
				client.t.Fatalf("rate-limited response has invalid Retry-After=%q", response.Header.Get("Retry-After"))
			}
			if time.Since(started)+time.Duration(retrySeconds)*time.Second > client.maximumRetryElapsed {
				client.t.Fatalf("rate limit did not refill within %s", client.maximumRetryElapsed)
			}
			time.Sleep(time.Duration(retrySeconds) * time.Second)
			continue
		}
		for _, status := range expectedStatuses {
			if response.StatusCode == status {
				return response
			}
		}
		responseBody, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		client.t.Fatalf("%s %s status=%d body=%s; want=%v", method, requestURL, response.StatusCode, responseBody, expectedStatuses)
	}
}

func highVolumeToken(t *testing.T) string {
	t.Helper()
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(value)
}

func validateHighVolumeStatePath(t *testing.T, path string) {
	t.Helper()
	if !filepath.IsAbs(path) {
		t.Fatal("FACETS_NODE_TEST_HIGH_VOLUME_STATE_PATH must be absolute")
	}
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	repositoryRoot := workingDirectory
	for {
		if _, statErr := os.Stat(filepath.Join(repositoryRoot, ".git")); statErr == nil {
			break
		}
		parent := filepath.Dir(repositoryRoot)
		if parent == repositoryRoot {
			t.Fatal("cannot locate FacetsNode repository root for state-path validation")
		}
		repositoryRoot = parent
	}
	realRepositoryRoot, err := filepath.EvalSymlinks(repositoryRoot)
	if err != nil {
		t.Fatal(err)
	}
	realParent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		t.Fatalf("state output parent must already exist: %v", err)
	}
	relative, err := filepath.Rel(realRepositoryRoot, filepath.Join(realParent, filepath.Base(path)))
	if err != nil {
		t.Fatal(err)
	}
	if relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		t.Fatal("FACETS_NODE_TEST_HIGH_VOLUME_STATE_PATH must be outside the repository")
	}
}

func writeHighVolumeState(t *testing.T, path string, state highVolumeLiveState) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatalf("create high-volume state without overwriting an existing file: %v", err)
	}
	succeeded := false
	defer func() {
		_ = file.Close()
		if !succeeded {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		t.Fatal(err)
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(state); err != nil {
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	succeeded = true
}

func readHighVolumeState(t *testing.T, path string) highVolumeLiveState {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("high-volume state must be a regular mode-0600 file; mode=%s", info.Mode())
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 64*1_024))
	decoder.DisallowUnknownFields()
	var state highVolumeLiveState
	if err := decoder.Decode(&state); err != nil {
		t.Fatal(err)
	}
	if state.Version != highVolumeStateVersion || state.TenantID == uuid.Nil ||
		state.DomainID == uuid.Nil || state.PublisherSubscriptionID == uuid.Nil ||
		state.PublisherMemberID == uuid.Nil || state.ReplacementSubscriptionID == uuid.Nil ||
		state.ReplacementMemberID == uuid.Nil || state.CheckpointID == uuid.Nil ||
		state.CheckpointBoundaryCursor == "" || state.DeliveryCursor == "" ||
		relay.ValidateBlobID(state.SnapshotBlobID) != nil {
		t.Fatal("high-volume state is incomplete")
	}
	for name, token := range map[string]string{
		"administration": state.AdministrationToken, "publisher": state.PublisherMemberToken,
		"replacement": state.ReplacementMemberToken,
	} {
		decoded, decodeErr := base64.RawURLEncoding.DecodeString(token)
		if decodeErr != nil || len(decoded) != 32 {
			t.Fatalf("%s credential in high-volume state is invalid", name)
		}
	}
	return state
}
