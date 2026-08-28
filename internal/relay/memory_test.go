package relay_test

import (
	"context"
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/testfixture"
)

func TestMemoryStoreDeliversOncePerDomainWithPerSubscriptionFacts(t *testing.T) {
	ctx := context.Background()
	fixture, err := testfixture.LoadRelayCarrier()
	if err != nil {
		t.Fatal(err)
	}
	admin := relay.AdministrationCredential{
		TenantID: fixture.Envelope.TenantID,
		DomainID: fixture.Envelope.DomainID,
		Token:    token(128),
	}
	adminDigest, err := relay.AdministrationDigest(admin)
	if err != nil {
		t.Fatal(err)
	}
	domain := relay.DomainRegistration{
		Version:                 relay.SchemaVersion,
		TenantID:                admin.TenantID,
		DomainID:                admin.DomainID,
		AdministrationDigest:    adminDigest,
		CreatedAtMilliseconds:   1_000,
		MaximumMessageCount:     10,
		MaximumBlobCount:        10,
		MaximumMessageByteCount: 2_048,
		MaximumBlobByteCount:    2_048,
	}
	store := relay.NewMemoryStore()
	acceptance, err := store.CreateDomain(ctx, domain, fixture.PublisherRegistration)
	if err != nil || acceptance != relay.AcceptanceAccepted {
		t.Fatalf("create domain acceptance=%q err=%v", acceptance, err)
	}

	recipientCredential := fixture.RecipientAccess.Credential()
	recipientDigest, err := relay.AuthorizationDigest(recipientCredential)
	if err != nil {
		t.Fatal(err)
	}
	recipient := relay.MemberRegistration{
		Version:             relay.SchemaVersion,
		TenantID:            recipientCredential.TenantID,
		DomainID:            recipientCredential.DomainID,
		MemberID:            recipientCredential.MemberID,
		AuthorizationDigest: recipientDigest,
		Capabilities: []relay.Capability{
			relay.CapabilityAcknowledgeMessage,
			relay.CapabilityFetchMessage,
		},
		CreatedAtMilliseconds: 1_000,
	}
	acceptance, err = store.CreateMember(ctx, admin, recipient, 1_500)
	if err != nil || acceptance != relay.AcceptanceAccepted {
		t.Fatalf("create member acceptance=%q err=%v", acceptance, err)
	}

	published, err := store.Publish(
		ctx,
		fixture.PublisherAccess.Credential(),
		fixture.Envelope,
		1_500,
	)
	if err != nil || published.Acceptance != relay.AcceptanceAccepted ||
		published.Sequence != 1 {
		t.Fatalf("publish=%+v err=%v", published, err)
	}
	retry, err := store.Publish(
		ctx,
		fixture.PublisherAccess.Credential(),
		fixture.Envelope,
		1_500,
	)
	if err != nil || retry.Acceptance != relay.AcceptanceDuplicate ||
		retry.Sequence != published.Sequence {
		t.Fatalf("retry=%+v err=%v", retry, err)
	}

	fetched, err := store.Fetch(ctx, recipientCredential, 0, 10, 1_500)
	if err != nil || len(fetched.Messages) != 1 ||
		fetched.Messages[0].Envelope != fixture.Envelope ||
		fetched.NextSequence != 1 {
		t.Fatalf("fetch=%+v err=%v", fetched, err)
	}
	publisherFetch, err := store.Fetch(
		ctx,
		fixture.PublisherAccess.Credential(),
		0,
		10,
		1_500,
	)
	if err != nil || len(publisherFetch.Messages) != 0 ||
		publisherFetch.NextSequence != 1 {
		t.Fatalf("publisher fetch=%+v err=%v", publisherFetch, err)
	}
	recovered, err := store.GetMessage(
		ctx,
		recipientCredential,
		fixture.Envelope.MessageID,
		1_500,
	)
	if err != nil || recovered.Sequence != 1 || recovered.Envelope != fixture.Envelope {
		t.Fatalf("recovered=%+v err=%v", recovered, err)
	}
	if _, err := store.GetMessage(
		ctx,
		fixture.PublisherAccess.Credential(),
		fixture.Envelope.MessageID,
		1_500,
	); !relay.ErrorHasCode(err, relay.CodeMessageNotFound) {
		t.Fatalf("publisher exact retrieval err=%v", err)
	}

	if _, err := store.Acknowledge(
		ctx,
		recipientCredential,
		fixture.Envelope.MessageID,
		relay.AcknowledgmentApplied,
		1_500,
	); !relay.ErrorHasCode(err, relay.CodeInvalidAcknowledgment) {
		t.Fatalf("applied-before-accepted err=%v", err)
	}
	accepted, err := store.Acknowledge(
		ctx,
		recipientCredential,
		fixture.Envelope.MessageID,
		relay.AcknowledgmentAccepted,
		1_500,
	)
	if err != nil || accepted.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("accepted=%+v err=%v", accepted, err)
	}
	applied, err := store.Acknowledge(
		ctx,
		recipientCredential,
		fixture.Envelope.MessageID,
		relay.AcknowledgmentApplied,
		1_500,
	)
	if err != nil || applied.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("applied=%+v err=%v", applied, err)
	}
	lowerRetry, err := store.Acknowledge(
		ctx,
		recipientCredential,
		fixture.Envelope.MessageID,
		relay.AcknowledgmentAccepted,
		1_500,
	)
	if err != nil || lowerRetry.Acceptance != relay.AcceptanceDuplicate ||
		lowerRetry.Stage != relay.AcknowledgmentApplied {
		t.Fatalf("lower retry=%+v err=%v", lowerRetry, err)
	}

	revocation, err := store.RevokeMember(
		ctx,
		admin,
		recipientCredential.MemberID,
		1_600,
	)
	if err != nil || revocation != relay.AcceptanceAccepted {
		t.Fatalf("revocation=%q err=%v", revocation, err)
	}
	if _, err := store.Fetch(ctx, recipientCredential, 0, 10, 1_600); !relay.ErrorHasCode(err, relay.CodeMemberRevoked) {
		t.Fatalf("fetch after revocation err=%v", err)
	}
}

func TestMemoryStoreRevokesTenantMembershipsAtomically(t *testing.T) {
	ctx := context.Background()
	tenantCredential := relay.TenantCredential{TenantID: uuid.New(), Token: token(201)}
	tenantDigest, err := relay.TenantAuthorizationDigest(tenantCredential)
	if err != nil {
		t.Fatal(err)
	}
	memberID := uuid.New()
	first, firstCredential := tenantDomainProvisioning(
		t,
		tenantCredential.TenantID,
		uuid.New(),
		uuid.New(),
		memberID,
		202,
		203,
	)
	second, secondCredential := tenantDomainProvisioning(
		t,
		tenantCredential.TenantID,
		uuid.New(),
		uuid.New(),
		memberID,
		204,
		205,
	)
	store := relay.NewMemoryStore()
	tenant := relay.TenantRegistration{
		Version:                          relay.SchemaVersion,
		RetryID:                          uuid.New(),
		TenantID:                         tenantCredential.TenantID,
		AuthorizationDigest:              tenantDigest,
		CreatedAtMilliseconds:            1_000,
		MaximumDomainCount:               4,
		MaximumAggregateMessageCount:     100,
		MaximumAggregateMessageByteCount: 1_024,
		MaximumAggregateBlobCount:        100,
		MaximumAggregateBlobByteCount:    1_024,
	}
	if result, provisionErr := store.ProvisionTenant(ctx, tenant, first); provisionErr != nil ||
		result.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("provision tenant result=%+v err=%v", result, provisionErr)
	}
	if result, provisionErr := store.ProvisionDomain(ctx, tenantCredential, second, 1_000); provisionErr != nil ||
		result.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("provision second domain result=%+v err=%v", result, provisionErr)
	}

	revocation := relay.TenantMembershipRevocation{
		Version:               relay.SchemaVersion,
		RetryID:               uuid.New(),
		RevokedAtMilliseconds: 1_500,
		Memberships: []relay.TenantMembershipRevocationItem{
			{
				DomainID:       first.Registration.DomainID,
				SubscriptionID: first.Subscription.SubscriptionID,
				MemberID:       memberID,
			},
			{
				DomainID:       second.Registration.DomainID,
				SubscriptionID: uuid.New(),
				MemberID:       memberID,
			},
		},
	}
	if _, revokeErr := store.RevokeTenantMemberships(ctx, tenantCredential, revocation); !relay.ErrorHasCode(revokeErr, relay.CodeMemberNotFound) {
		t.Fatalf("partial revocation should fail before mutation err=%v", revokeErr)
	}
	if _, fetchErr := store.Fetch(ctx, firstCredential, 0, 1, 1_500); fetchErr != nil {
		t.Fatalf("first membership was changed by failed atomic revocation: %v", fetchErr)
	}
	if _, fetchErr := store.Fetch(ctx, secondCredential, 0, 1, 1_500); fetchErr != nil {
		t.Fatalf("second membership was changed by failed atomic revocation: %v", fetchErr)
	}

	revocation.Memberships[1].SubscriptionID = second.Subscription.SubscriptionID
	accepted, err := store.RevokeTenantMemberships(ctx, tenantCredential, revocation)
	if err != nil || accepted.Acceptance != relay.AcceptanceAccepted || len(accepted.Memberships) != 2 {
		t.Fatalf("accepted revocation=%+v err=%v", accepted, err)
	}
	if _, fetchErr := store.Fetch(ctx, firstCredential, 0, 1, 1_500); !relay.ErrorHasCode(fetchErr, relay.CodeMemberRevoked) {
		t.Fatalf("first membership remained active err=%v", fetchErr)
	}
	if _, fetchErr := store.Fetch(ctx, secondCredential, 0, 1, 1_500); !relay.ErrorHasCode(fetchErr, relay.CodeMemberRevoked) {
		t.Fatalf("second membership remained active err=%v", fetchErr)
	}
	retry, err := store.RevokeTenantMemberships(ctx, tenantCredential, revocation)
	if err != nil || retry.Acceptance != relay.AcceptanceDuplicate || !reflect.DeepEqual(retry.Memberships, accepted.Memberships) {
		t.Fatalf("revocation retry=%+v err=%v", retry, err)
	}
}

func tenantDomainProvisioning(
	t *testing.T,
	tenantID uuid.UUID,
	domainID uuid.UUID,
	subscriptionID uuid.UUID,
	memberID uuid.UUID,
	adminSeed byte,
	memberSeed byte,
) (relay.DomainProvisioning, relay.Credential) {
	t.Helper()
	admin := relay.AdministrationCredential{TenantID: tenantID, DomainID: domainID, Token: token(adminSeed)}
	adminDigest, err := relay.AdministrationDigest(admin)
	if err != nil {
		t.Fatal(err)
	}
	member := relay.Credential{TenantID: tenantID, DomainID: domainID, MemberID: memberID, Token: token(memberSeed)}
	memberDigest, err := relay.AuthorizationDigest(member)
	if err != nil {
		t.Fatal(err)
	}
	return relay.DomainProvisioning{
		Version: relay.SchemaVersion,
		RetryID: uuid.New(),
		Registration: relay.DomainRegistration{
			Version: relay.SchemaVersion, TenantID: tenantID, DomainID: domainID,
			AdministrationDigest: adminDigest, CreatedAtMilliseconds: 1_000,
			MaximumMessageCount: 100, MaximumMessageByteCount: 1_024,
			MaximumBlobCount: 100, MaximumBlobByteCount: 1_024,
		},
		Subscription: relay.Subscription{
			Version: relay.SchemaVersion, TenantID: tenantID, DomainID: domainID,
			SubscriptionID: subscriptionID, Status: relay.SubscriptionActive,
			CreatedAtMilliseconds: 1_000, UpdatedAtMilliseconds: 1_000,
		},
		InitialMember: relay.MemberRegistration{
			Version: relay.SchemaVersion, TenantID: tenantID, DomainID: domainID,
			MemberID: memberID, AuthorizationDigest: memberDigest,
			Capabilities:          []relay.Capability{relay.CapabilityFetchMessage},
			CreatedAtMilliseconds: 1_000,
		},
	}, member
}

func TestMemoryStoreResumableUploadReservesQuotaAndAllowsSameSubscriptionAgent(t *testing.T) {
	ctx := context.Background()
	tenantID, domainID := uuid.New(), uuid.New()
	first := relay.Credential{TenantID: tenantID, DomainID: domainID, MemberID: uuid.New(), Token: token(41)}
	firstDigest, _ := relay.AuthorizationDigest(first)
	admin := relay.AdministrationCredential{TenantID: tenantID, DomainID: domainID, Token: token(42)}
	adminDigest, _ := relay.AdministrationDigest(admin)
	store := relay.NewMemoryStore()
	_, err := store.CreateDomain(ctx, relay.DomainRegistration{
		Version: relay.SchemaVersion, TenantID: tenantID, DomainID: domainID,
		AdministrationDigest: adminDigest, CreatedAtMilliseconds: 1_000,
		MaximumMessageCount: 1, MaximumMessageByteCount: 1,
		MaximumBlobCount: 1, MaximumBlobByteCount: 8,
	}, relay.MemberRegistration{
		Version: relay.SchemaVersion, TenantID: tenantID, DomainID: domainID, MemberID: first.MemberID,
		AuthorizationDigest: firstDigest, Capabilities: []relay.Capability{relay.CapabilityPublishBlob}, CreatedAtMilliseconds: 1_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	second := relay.Credential{TenantID: tenantID, DomainID: domainID, MemberID: uuid.New(), Token: token(43)}
	secondDigest, _ := relay.AuthorizationDigest(second)
	if _, err := store.CreateSubscriptionMember(ctx, admin, first.MemberID, relay.MemberRegistration{
		Version: relay.SchemaVersion, TenantID: tenantID, DomainID: domainID, MemberID: second.MemberID,
		AuthorizationDigest: secondDigest, Capabilities: []relay.Capability{relay.CapabilityPublishBlob}, CreatedAtMilliseconds: 1_100,
	}, 1_100); err != nil {
		t.Fatal(err)
	}
	bytes := []byte("12345678")
	request := relay.BlobUploadRequest{RetryID: uuid.New(), UploadID: uuid.New(), RelayBlobID: relay.BlobID(bytes), ByteCount: 8, CreatedAtMilliseconds: 1_200}
	created, err := store.CreateBlobUpload(ctx, first, request, 1_200)
	if err != nil || created.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("create=%+v err=%v", created, err)
	}
	retry, err := store.CreateBlobUpload(ctx, second, request, 1_200)
	if err != nil || retry.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("same-sub retry=%+v err=%v", retry, err)
	}
	status, _ := store.GetDomainStatus(ctx, admin)
	if status.ReservedBlobCount != 1 || status.ReservedBlobByteCount != 8 || status.BlobCount != 0 {
		t.Fatalf("reserved status=%+v", status)
	}
	other := relay.BlobUploadRequest{RetryID: uuid.New(), UploadID: uuid.New(), RelayBlobID: relay.BlobID([]byte("x")), ByteCount: 1, CreatedAtMilliseconds: 1_200}
	if _, err := store.CreateBlobUpload(ctx, first, other, 1_200); !relay.ErrorHasCode(err, relay.CodeDomainFull) {
		t.Fatalf("oversubscription err=%v", err)
	}
	chunk := relay.BlobUploadChunkRequest{UploadID: request.UploadID, Offset: 0, ByteCount: 8, ChunkSHA256: strings.Repeat("a", 64)}
	competingChunk := chunk
	competingChunk.ChunkSHA256 = strings.Repeat("c", 64)
	type appendResult struct {
		status relay.BlobUploadStatus
		err    error
	}
	entered, release := make(chan struct{}), make(chan struct{})
	firstResult, secondResult := make(chan appendResult, 1), make(chan appendResult, 1)
	go func() {
		status, appendErr := store.AppendBlobUploadChunk(ctx, second, chunk, 1_300, func(status relay.BlobUploadStatus) error {
			close(entered)
			<-release
			return nil
		})
		firstResult <- appendResult{status: status, err: appendErr}
	}()
	<-entered
	competingCallback := make(chan struct{}, 1)
	go func() {
		status, appendErr := store.AppendBlobUploadChunk(ctx, first, competingChunk, 1_300, func(relay.BlobUploadStatus) error {
			competingCallback <- struct{}{}
			return nil
		})
		secondResult <- appendResult{status: status, err: appendErr}
	}()
	select {
	case result := <-secondResult:
		t.Fatalf("competing append escaped serialization: %+v", result)
	case <-time.After(25 * time.Millisecond):
	}
	close(release)
	committed := <-firstResult
	if committed.err != nil || committed.status.CommittedOffset != 8 || committed.status.Finalized {
		t.Fatalf("commit=%+v", committed)
	}
	competing := <-secondResult
	if !relay.ErrorHasCode(competing.err, relay.CodeBlobUploadCollision) {
		t.Fatalf("different concurrent content err=%v", competing.err)
	}
	select {
	case <-competingCallback:
		t.Fatal("losing concurrent request touched content")
	default:
	}
	duplicateCalled := false
	duplicate, err := store.AppendBlobUploadChunk(ctx, first, chunk, 1_300, func(relay.BlobUploadStatus) error { duplicateCalled = true; return nil })
	if err != nil || duplicate.CommittedOffset != 8 || duplicateCalled {
		t.Fatalf("duplicate status=%+v callback=%v err=%v", duplicate, duplicateCalled, err)
	}
	// The authoring device clock may trail the server clock used to timestamp
	// chunk acceptance. Finalization must not rely on cross-device wall-clock
	// ordering when the upload identity, byte count, and durable offset match.
	finalRequest := relay.BlobUploadFinalizationRequest{RetryID: uuid.New(), UploadID: request.UploadID, RelayBlobID: request.RelayBlobID, ByteCount: 8, FinalizedAtMilliseconds: 1_250}
	finalized, err := store.FinalizeBlobUpload(ctx, first, finalRequest, 1_400, func(relay.BlobUploadStatus) error { return nil })
	if err != nil || finalized.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("finalize=%+v err=%v", finalized, err)
	}
	finalRetryCallback := false
	finalRetry, err := store.FinalizeBlobUpload(ctx, second, finalRequest, 1_400, func(relay.BlobUploadStatus) error { finalRetryCallback = true; return nil })
	if err != nil || finalRetry.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("finalize retry=%+v err=%v", finalRetry, err)
	}
	if finalRetryCallback {
		t.Fatal("finalization retry republished content")
	}
	if status, err := store.GetBlobUpload(ctx, first, request.UploadID, 1_400); err != nil || status.UpdatedAtMilliseconds != 1_400 {
		t.Fatalf("finalized upload status=%+v err=%v", status, err)
	}
	status, _ = store.GetDomainStatus(ctx, admin)
	if status.ReservedBlobCount != 0 || status.ReservedBlobByteCount != 0 || status.BlobCount != 1 || status.BlobByteCount != 8 {
		t.Fatalf("final status=%+v", status)
	}
}

func TestMemoryStoreRejectsScopeCapabilityAndMessageCollisions(t *testing.T) {
	ctx := context.Background()
	fixture, err := testfixture.LoadRelayCarrier()
	if err != nil {
		t.Fatal(err)
	}
	admin := relay.AdministrationCredential{
		TenantID: fixture.Envelope.TenantID,
		DomainID: fixture.Envelope.DomainID,
		Token:    token(128),
	}
	digest, _ := relay.AdministrationDigest(admin)
	store := relay.NewMemoryStore()
	_, err = store.CreateDomain(ctx, relay.DomainRegistration{
		Version:                 relay.SchemaVersion,
		TenantID:                admin.TenantID,
		DomainID:                admin.DomainID,
		AdministrationDigest:    digest,
		CreatedAtMilliseconds:   1_000,
		MaximumMessageCount:     10,
		MaximumBlobCount:        10,
		MaximumMessageByteCount: 2_048,
		MaximumBlobByteCount:    2_048,
	}, fixture.PublisherRegistration)
	if err != nil {
		t.Fatal(err)
	}

	changed := fixture.Envelope
	changed.AuthenticationTag = "AAAAAAAAAAAAAAAAAAAAAA"
	if _, err := store.Publish(
		ctx,
		fixture.PublisherAccess.Credential(),
		fixture.Envelope,
		1_500,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Publish(
		ctx,
		fixture.PublisherAccess.Credential(),
		changed,
		1_500,
	); !relay.ErrorHasCode(err, relay.CodeMessageCollision) {
		t.Fatalf("collision err=%v", err)
	}

	wrongScope := fixture.PublisherAccess.Credential()
	wrongScope.DomainID = uuid.New()
	if _, err := store.Publish(ctx, wrongScope, fixture.Envelope, 1_500); !relay.ErrorHasCode(err, relay.CodeDomainNotFound) {
		t.Fatalf("wrong scope err=%v", err)
	}

	fetchOnlyCredential := fixture.RecipientAccess.Credential()
	fetchOnlyDigest, err := relay.AuthorizationDigest(fetchOnlyCredential)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.CreateMember(ctx, admin, relay.MemberRegistration{
		Version:               relay.SchemaVersion,
		TenantID:              fetchOnlyCredential.TenantID,
		DomainID:              fetchOnlyCredential.DomainID,
		MemberID:              fetchOnlyCredential.MemberID,
		AuthorizationDigest:   fetchOnlyDigest,
		Capabilities:          []relay.Capability{relay.CapabilityFetchMessage},
		CreatedAtMilliseconds: 1_000,
	}, 1_500)
	if err != nil {
		t.Fatal(err)
	}
	fetchOnlyEnvelope := fixture.Envelope
	fetchOnlyEnvelope.MessageID = uuid.New()
	fetchOnlyEnvelope.PublisherMemberID = fetchOnlyCredential.MemberID
	if _, err := store.Publish(
		ctx,
		fetchOnlyCredential,
		fetchOnlyEnvelope,
		1_500,
	); !relay.ErrorHasCode(err, relay.CodeMissingCapability) {
		t.Fatalf("publish without capability err=%v", err)
	}

	expiredCredential := relay.Credential{
		TenantID: admin.TenantID,
		DomainID: admin.DomainID,
		MemberID: uuid.New(),
		Token:    token(64),
	}
	expiredDigest, err := relay.AuthorizationDigest(expiredCredential)
	if err != nil {
		t.Fatal(err)
	}
	expiresAt := int64(1_400)
	expiredRegistration := relay.MemberRegistration{
		Version:               relay.SchemaVersion,
		TenantID:              expiredCredential.TenantID,
		DomainID:              expiredCredential.DomainID,
		MemberID:              expiredCredential.MemberID,
		AuthorizationDigest:   expiredDigest,
		Capabilities:          []relay.Capability{relay.CapabilityPublishMessage},
		CreatedAtMilliseconds: 1_000,
		ExpiresAtMilliseconds: &expiresAt,
	}
	_, err = store.CreateMember(ctx, admin, expiredRegistration, 1_200)
	if err != nil {
		t.Fatal(err)
	}
	if acceptance, err := store.CreateMember(
		ctx, admin, expiredRegistration, 1_500,
	); err != nil || acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("expired member exact retry acceptance=%q err=%v", acceptance, err)
	}
	expiredEnvelope := fixture.Envelope
	expiredEnvelope.MessageID = uuid.New()
	expiredEnvelope.PublisherMemberID = expiredCredential.MemberID
	if _, err := store.Publish(
		ctx,
		expiredCredential,
		expiredEnvelope,
		1_500,
	); !relay.ErrorHasCode(err, relay.CodeMemberExpired) {
		t.Fatalf("publish after member expiry err=%v", err)
	}
}

func TestMemoryStoreEnforcesStoredByteQuotaWithoutChargingRetries(t *testing.T) {
	ctx := context.Background()
	fixture, err := testfixture.LoadRelayCarrier()
	if err != nil {
		t.Fatal(err)
	}
	ciphertextByteCount, err := fixture.Envelope.CiphertextByteCount()
	if err != nil {
		t.Fatal(err)
	}
	admin := relay.AdministrationCredential{
		TenantID: fixture.Envelope.TenantID,
		DomainID: fixture.Envelope.DomainID,
		Token:    token(128),
	}
	adminDigest, err := relay.AdministrationDigest(admin)
	if err != nil {
		t.Fatal(err)
	}
	store := relay.NewMemoryStore()
	_, err = store.CreateDomain(ctx, relay.DomainRegistration{
		Version:                 relay.SchemaVersion,
		TenantID:                admin.TenantID,
		DomainID:                admin.DomainID,
		AdministrationDigest:    adminDigest,
		CreatedAtMilliseconds:   1_000,
		MaximumMessageCount:     10,
		MaximumBlobCount:        10,
		MaximumMessageByteCount: ciphertextByteCount,
		MaximumBlobByteCount:    ciphertextByteCount,
	}, fixture.PublisherRegistration)
	if err != nil {
		t.Fatal(err)
	}
	credential := fixture.PublisherAccess.Credential()
	first, err := store.Publish(ctx, credential, fixture.Envelope, 1_500)
	if err != nil || first.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("first publish=%+v err=%v", first, err)
	}
	retry, err := store.Publish(ctx, credential, fixture.Envelope, 1_500)
	if err != nil || retry.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("retry=%+v err=%v", retry, err)
	}
	second := fixture.Envelope
	second.MessageID = uuid.New()
	if _, err := store.Publish(ctx, credential, second, 1_500); !relay.ErrorHasCode(err, relay.CodeDomainFull) {
		t.Fatalf("publish beyond stored-byte quota err=%v", err)
	}
}

func TestMemoryStoreAuthorizesAndAccountsForOpaqueBlobs(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	domainID := uuid.New()
	publisherCredential := relay.Credential{
		TenantID: tenantID,
		DomainID: domainID,
		MemberID: uuid.New(),
		Token:    token(96),
	}
	publisherDigest, err := relay.AuthorizationDigest(publisherCredential)
	if err != nil {
		t.Fatal(err)
	}
	admin := relay.AdministrationCredential{
		TenantID: tenantID,
		DomainID: domainID,
		Token:    token(128),
	}
	adminDigest, err := relay.AdministrationDigest(admin)
	if err != nil {
		t.Fatal(err)
	}
	store := relay.NewMemoryStore()
	_, err = store.CreateDomain(ctx, relay.DomainRegistration{
		Version:                 relay.SchemaVersion,
		TenantID:                tenantID,
		DomainID:                domainID,
		AdministrationDigest:    adminDigest,
		CreatedAtMilliseconds:   1_000,
		MaximumMessageCount:     1,
		MaximumBlobCount:        1,
		MaximumMessageByteCount: 4,
		MaximumBlobByteCount:    4,
	}, relay.MemberRegistration{
		Version:               relay.SchemaVersion,
		TenantID:              tenantID,
		DomainID:              domainID,
		MemberID:              publisherCredential.MemberID,
		AuthorizationDigest:   publisherDigest,
		Capabilities:          []relay.Capability{relay.CapabilityPublishBlob},
		CreatedAtMilliseconds: 1_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	blobBytes := []byte{1, 2, 3, 4}
	blobID := relay.BlobID(blobBytes)
	if err := store.PrepareBlobPublish(
		ctx, publisherCredential, blobID, int64(len(blobBytes)), 1_500,
	); err != nil {
		t.Fatal(err)
	}
	published, err := store.CommitBlobPublish(
		ctx, publisherCredential, blobID, int64(len(blobBytes)), 1_500,
	)
	if err != nil || published.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("blob publish=%+v err=%v", published, err)
	}
	retry, err := store.CommitBlobPublish(
		ctx, publisherCredential, blobID, int64(len(blobBytes)), 1_500,
	)
	if err != nil || retry.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("blob retry=%+v err=%v", retry, err)
	}
	secondBytes := []byte{5}
	if err := store.PrepareBlobPublish(
		ctx,
		publisherCredential,
		relay.BlobID(secondBytes),
		int64(len(secondBytes)),
		1_500,
	); !relay.ErrorHasCode(err, relay.CodeDomainFull) {
		t.Fatalf("blob over quota err=%v", err)
	}

	fetchCredential := relay.Credential{
		TenantID: tenantID,
		DomainID: domainID,
		MemberID: uuid.New(),
		Token:    token(32),
	}
	fetchDigest, err := relay.AuthorizationDigest(fetchCredential)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.CreateMember(ctx, admin, relay.MemberRegistration{
		Version:               relay.SchemaVersion,
		TenantID:              tenantID,
		DomainID:              domainID,
		MemberID:              fetchCredential.MemberID,
		AuthorizationDigest:   fetchDigest,
		Capabilities:          []relay.Capability{relay.CapabilityFetchBlob},
		CreatedAtMilliseconds: 1_000,
	}, 1_500)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := store.GetBlobMetadata(ctx, fetchCredential, blobID, 1_500)
	if err != nil || metadata.ByteCount != int64(len(blobBytes)) ||
		metadata.PublisherMemberID != publisherCredential.MemberID {
		t.Fatalf("blob metadata=%+v err=%v", metadata, err)
	}
	if _, err := store.RevokeMember(
		ctx, admin, fetchCredential.MemberID, 1_600,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetBlobMetadata(
		ctx, fetchCredential, blobID, 1_600,
	); !relay.ErrorHasCode(err, relay.CodeMemberRevoked) {
		t.Fatalf("blob fetch after revocation err=%v", err)
	}
	if _, err := store.RevokeMember(
		ctx, admin, publisherCredential.MemberID, 1_700,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitBlobPublish(
		ctx,
		publisherCredential,
		blobID,
		int64(len(blobBytes)),
		1_700,
	); !relay.ErrorHasCode(err, relay.CodeMemberRevoked) {
		t.Fatalf("blob commit after publisher revocation err=%v", err)
	}
}

func TestMemoryStoreClaimsAdmissionOnceAndRevokesBeforeClaim(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	domainID := uuid.New()
	admin := relay.AdministrationCredential{
		TenantID: tenantID,
		DomainID: domainID,
		Token:    token(128),
	}
	adminDigest, err := relay.AdministrationDigest(admin)
	if err != nil {
		t.Fatal(err)
	}
	initialCredential := relay.Credential{
		TenantID: tenantID,
		DomainID: domainID,
		MemberID: uuid.New(),
		Token:    token(96),
	}
	initialDigest, err := relay.AuthorizationDigest(initialCredential)
	if err != nil {
		t.Fatal(err)
	}
	store := relay.NewMemoryStore()
	if _, err := store.CreateDomain(ctx, relay.DomainRegistration{
		Version:                 relay.SchemaVersion,
		TenantID:                tenantID,
		DomainID:                domainID,
		AdministrationDigest:    adminDigest,
		CreatedAtMilliseconds:   1_000,
		MaximumMessageCount:     10,
		MaximumBlobCount:        10,
		MaximumMessageByteCount: 1_024,
		MaximumBlobByteCount:    1_024,
	}, relay.MemberRegistration{
		Version:               relay.SchemaVersion,
		TenantID:              tenantID,
		DomainID:              domainID,
		MemberID:              initialCredential.MemberID,
		AuthorizationDigest:   initialDigest,
		Capabilities:          []relay.Capability{relay.CapabilityFetchMessage},
		CreatedAtMilliseconds: 1_000,
	}); err != nil {
		t.Fatal(err)
	}

	admissionCredential := relay.AdmissionCredential{
		TenantID:    tenantID,
		DomainID:    domainID,
		AdmissionID: uuid.New(),
		Token:       token(64),
	}
	admissionDigest, err := relay.AdmissionAuthorizationDigest(admissionCredential)
	if err != nil {
		t.Fatal(err)
	}
	admission := relay.MemberAdmission{
		Version:               relay.SchemaVersion,
		TenantID:              tenantID,
		DomainID:              domainID,
		AdmissionID:           admissionCredential.AdmissionID,
		AuthorizationDigest:   admissionDigest,
		Capabilities:          []relay.Capability{relay.CapabilityFetchMessage},
		CreatedAtMilliseconds: 1_500,
		ExpiresAtMilliseconds: 2_500,
	}
	accepted, err := store.CreateAdmission(ctx, admin, admission, 1_500)
	if err != nil || accepted.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("create admission result=%+v err=%v", accepted, err)
	}
	retriedAdmission := admission
	retriedAdmission.CreatedAtMilliseconds = 1_600
	duplicate, err := store.CreateAdmission(ctx, admin, retriedAdmission, 1_600)
	if err != nil || duplicate.Acceptance != relay.AcceptanceDuplicate ||
		duplicate.Admission.CreatedAtMilliseconds != 1_500 {
		t.Fatalf("duplicate admission result=%+v err=%v", duplicate, err)
	}

	memberCredential := relay.Credential{
		TenantID: tenantID,
		DomainID: domainID,
		MemberID: uuid.New(),
		Token:    token(32),
	}
	memberDigest, err := relay.AuthorizationDigest(memberCredential)
	if err != nil {
		t.Fatal(err)
	}
	claim := relay.MemberAdmissionClaim{
		MemberID:            memberCredential.MemberID,
		AuthorizationDigest: memberDigest,
	}
	wrongAdmissionCredential := admissionCredential
	wrongAdmissionCredential.Token = token(65)
	if _, err := store.ClaimAdmission(
		ctx, wrongAdmissionCredential, claim, 1_700,
	); !relay.ErrorHasCode(err, relay.CodeUnauthorized) {
		t.Fatalf("wrong admission token err=%v", err)
	}
	claimed, err := store.ClaimAdmission(
		ctx, admissionCredential, claim, 1_700,
	)
	if err != nil || claimed.Acceptance != relay.AcceptanceAccepted ||
		claimed.Member.MemberID != memberCredential.MemberID ||
		len(claimed.Member.Capabilities) != 1 ||
		claimed.Member.Capabilities[0] != relay.CapabilityFetchMessage {
		t.Fatalf("claim=%+v err=%v", claimed, err)
	}
	creationRetryAfterClaim := admission
	creationRetryAfterClaim.CreatedAtMilliseconds = 1_800
	current, err := store.CreateAdmission(
		ctx, admin, creationRetryAfterClaim, 1_800,
	)
	if err != nil || current.Acceptance != relay.AcceptanceDuplicate ||
		current.Admission.ClaimedMemberID == nil ||
		*current.Admission.ClaimedMemberID != memberCredential.MemberID {
		t.Fatalf("creation retry after claim=%+v err=%v", current, err)
	}
	if _, err := store.Fetch(
		ctx, memberCredential, 0, 10, 1_800,
	); err != nil {
		t.Fatalf("claimed member was not authorized: %v", err)
	}
	// Exact retry remains recoverable after the one-time admission expires.
	retry, err := store.ClaimAdmission(
		ctx, admissionCredential, claim, 3_000,
	)
	if err != nil || retry.Acceptance != relay.AcceptanceDuplicate ||
		!reflect.DeepEqual(retry.Member, claimed.Member) {
		t.Fatalf("claim retry=%+v err=%v", retry, err)
	}
	otherClaim := claim
	otherClaim.MemberID = uuid.New()
	if _, err := store.ClaimAdmission(
		ctx, admissionCredential, otherClaim, 3_000,
	); !relay.ErrorHasCode(err, relay.CodeAdmissionClaimed) {
		t.Fatalf("second claimant err=%v", err)
	}

	revokedCredential := relay.AdmissionCredential{
		TenantID:    tenantID,
		DomainID:    domainID,
		AdmissionID: uuid.New(),
		Token:       token(160),
	}
	revokedDigest, err := relay.AdmissionAuthorizationDigest(revokedCredential)
	if err != nil {
		t.Fatal(err)
	}
	revokedAdmission := admission
	revokedAdmission.AdmissionID = revokedCredential.AdmissionID
	revokedAdmission.AuthorizationDigest = revokedDigest
	revokedAdmission.CreatedAtMilliseconds = 3_000
	revokedAdmission.ExpiresAtMilliseconds = 4_000
	if _, err := store.CreateAdmission(
		ctx, admin, revokedAdmission, 3_000,
	); err != nil {
		t.Fatal(err)
	}
	if acceptance, err := store.RevokeAdmission(
		ctx, admin, revokedCredential.AdmissionID, 3_100,
	); err != nil || acceptance != relay.AcceptanceAccepted {
		t.Fatalf("revoke acceptance=%q err=%v", acceptance, err)
	}
	if acceptance, err := store.RevokeAdmission(
		ctx, admin, revokedCredential.AdmissionID, 3_200,
	); err != nil || acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("revoke retry acceptance=%q err=%v", acceptance, err)
	}
	if _, err := store.ClaimAdmission(
		ctx, revokedCredential, relay.MemberAdmissionClaim{
			MemberID:            uuid.New(),
			AuthorizationDigest: memberDigest,
		}, 3_300,
	); !relay.ErrorHasCode(err, relay.CodeAdmissionRevoked) {
		t.Fatalf("claim revoked admission err=%v", err)
	}
	beforeRecovery := int64(1_700) + relay.AdmissionRecoveryWindowMilliseconds - 1
	collection, err := store.CollectAdmissions(ctx, admin, beforeRecovery)
	if err != nil || collection.CollectedCount != 0 {
		t.Fatalf("early admission collection=%+v err=%v", collection, err)
	}
	afterRecovery := int64(3_100) + relay.AdmissionRecoveryWindowMilliseconds
	collection, err = store.CollectAdmissions(ctx, admin, afterRecovery)
	if err != nil || collection.CollectedCount != 2 || collection.HasMore {
		t.Fatalf("admission collection=%+v err=%v", collection, err)
	}
	if _, err := store.ClaimAdmission(
		ctx, admissionCredential, claim, afterRecovery,
	); !relay.ErrorHasCode(err, relay.CodeAdmissionNotFound) {
		t.Fatalf("collected admission remained retryable err=%v", err)
	}
}

func TestMemoryStoreRotatesCredentialsWithoutChangingAuthority(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	domainID := uuid.New()
	oldAdmin := relay.AdministrationCredential{
		TenantID: tenantID,
		DomainID: domainID,
		Token:    token(200),
	}
	oldMember := relay.Credential{
		TenantID: tenantID,
		DomainID: domainID,
		MemberID: uuid.New(),
		Token:    token(201),
	}
	adminDigest, err := relay.AdministrationDigest(oldAdmin)
	if err != nil {
		t.Fatal(err)
	}
	memberDigest, err := relay.AuthorizationDigest(oldMember)
	if err != nil {
		t.Fatal(err)
	}
	store := relay.NewMemoryStore()
	if _, err := store.CreateDomain(ctx, relay.DomainRegistration{
		Version:                 relay.SchemaVersion,
		TenantID:                tenantID,
		DomainID:                domainID,
		AdministrationDigest:    adminDigest,
		CreatedAtMilliseconds:   1_000,
		MaximumMessageCount:     10,
		MaximumBlobCount:        10,
		MaximumMessageByteCount: 1_024,
		MaximumBlobByteCount:    1_024,
	}, relay.MemberRegistration{
		Version:               relay.SchemaVersion,
		TenantID:              tenantID,
		DomainID:              domainID,
		MemberID:              oldMember.MemberID,
		AuthorizationDigest:   memberDigest,
		Capabilities:          []relay.Capability{relay.CapabilityFetchMessage},
		CreatedAtMilliseconds: 1_000,
	}); err != nil {
		t.Fatal(err)
	}

	newAdmin := oldAdmin
	newAdmin.Token = token(202)
	newAdminDigest, err := relay.AdministrationDigest(newAdmin)
	if err != nil {
		t.Fatal(err)
	}
	adminRotation := relay.CredentialRotation{
		RotationID:          uuid.New(),
		AuthorizationDigest: newAdminDigest,
	}
	rotatedAdmin, err := store.RotateAdministrationCredential(
		ctx, oldAdmin, adminRotation, 1_500,
	)
	if err != nil || rotatedAdmin.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("rotate admin=%+v err=%v", rotatedAdmin, err)
	}
	for _, credential := range []relay.AdministrationCredential{oldAdmin, newAdmin} {
		retry, err := store.RotateAdministrationCredential(
			ctx, credential, adminRotation, 1_600,
		)
		if err != nil || retry.Acceptance != relay.AcceptanceDuplicate ||
			retry.RotatedAtMilliseconds != 1_500 {
			t.Fatalf("admin rotation retry=%+v err=%v", retry, err)
		}
	}
	if _, err := store.CollectAdmissions(ctx, oldAdmin, 1_600); !relay.ErrorHasCode(err, relay.CodeUnauthorized) {
		t.Fatalf("old admin remained authorized err=%v", err)
	}
	if _, err := store.RotateAdministrationCredential(
		ctx,
		newAdmin,
		relay.CredentialRotation{
			RotationID:          uuid.New(),
			AuthorizationDigest: adminDigest,
		},
		1_700,
	); !relay.ErrorHasCode(err, relay.CodeCredentialReuse) {
		t.Fatalf("admin credential reuse err=%v", err)
	}
	collision := adminRotation
	collision.AuthorizationDigest = memberDigest
	if _, err := store.RotateAdministrationCredential(
		ctx, newAdmin, collision, 1_700,
	); !relay.ErrorHasCode(err, relay.CodeCredentialRotationCollision) {
		t.Fatalf("admin rotation collision err=%v", err)
	}

	newMember := oldMember
	newMember.Token = token(203)
	newMemberDigest, err := relay.AuthorizationDigest(newMember)
	if err != nil {
		t.Fatal(err)
	}
	memberRotation := relay.CredentialRotation{
		RotationID:          uuid.New(),
		AuthorizationDigest: newMemberDigest,
	}
	rotatedMember, err := store.RotateMemberCredential(
		ctx, oldMember, memberRotation, 1_500,
	)
	if err != nil || rotatedMember.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("rotate member=%+v err=%v", rotatedMember, err)
	}
	for _, credential := range []relay.Credential{oldMember, newMember} {
		retry, err := store.RotateMemberCredential(
			ctx, credential, memberRotation, 1_600,
		)
		if err != nil || retry.Acceptance != relay.AcceptanceDuplicate ||
			retry.RotatedAtMilliseconds != 1_500 {
			t.Fatalf("member rotation retry=%+v err=%v", retry, err)
		}
	}
	if _, err := store.Fetch(ctx, oldMember, 0, 10, 1_600); !relay.ErrorHasCode(err, relay.CodeUnauthorized) {
		t.Fatalf("old member remained authorized err=%v", err)
	}
	if _, err := store.Fetch(ctx, newMember, 0, 10, 1_600); err != nil {
		t.Fatalf("new member was not authorized: %v", err)
	}
}

func TestMemoryStoreBoundsActiveMembersAndOutstandingAdmissions(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	domainID := uuid.New()
	admin := relay.AdministrationCredential{
		TenantID: tenantID,
		DomainID: domainID,
		Token:    token(210),
	}
	adminDigest, err := relay.AdministrationDigest(admin)
	if err != nil {
		t.Fatal(err)
	}
	initial := relay.Credential{
		TenantID: tenantID,
		DomainID: domainID,
		MemberID: uuid.New(),
		Token:    token(211),
	}
	initialDigest, err := relay.AuthorizationDigest(initial)
	if err != nil {
		t.Fatal(err)
	}
	store := relay.NewMemoryStore()
	if _, err := store.CreateDomain(ctx, relay.DomainRegistration{
		Version:                 relay.SchemaVersion,
		TenantID:                tenantID,
		DomainID:                domainID,
		AdministrationDigest:    adminDigest,
		CreatedAtMilliseconds:   1_000,
		MaximumMessageCount:     10,
		MaximumBlobCount:        10,
		MaximumMessageByteCount: 1_024,
		MaximumBlobByteCount:    1_024,
	}, relay.MemberRegistration{
		Version:               relay.SchemaVersion,
		TenantID:              tenantID,
		DomainID:              domainID,
		MemberID:              initial.MemberID,
		AuthorizationDigest:   initialDigest,
		Capabilities:          []relay.Capability{relay.CapabilityFetchMessage},
		CreatedAtMilliseconds: 1_000,
	}); err != nil {
		t.Fatal(err)
	}
	createdMemberIDs := make([]uuid.UUID, 0, relay.MaximumActiveMemberCountPerDomain-1)
	for index := 1; index < relay.MaximumActiveMemberCountPerDomain; index++ {
		credential := relay.Credential{
			TenantID: tenantID,
			DomainID: domainID,
			MemberID: uuid.New(),
			Token:    token(byte(index)),
		}
		digest, err := relay.AuthorizationDigest(credential)
		if err != nil {
			t.Fatal(err)
		}
		registration := relay.MemberRegistration{
			Version:               relay.SchemaVersion,
			TenantID:              tenantID,
			DomainID:              domainID,
			MemberID:              credential.MemberID,
			AuthorizationDigest:   digest,
			Capabilities:          []relay.Capability{relay.CapabilityFetchMessage},
			CreatedAtMilliseconds: 1_500,
		}
		if _, err := store.CreateMember(ctx, admin, registration, 1_500); err != nil {
			t.Fatalf("create member %d: %v", index, err)
		}
		createdMemberIDs = append(createdMemberIDs, credential.MemberID)
	}
	overflowMember := relay.MemberRegistration{
		Version:               relay.SchemaVersion,
		TenantID:              tenantID,
		DomainID:              domainID,
		MemberID:              uuid.New(),
		AuthorizationDigest:   initialDigest,
		Capabilities:          []relay.Capability{relay.CapabilityFetchMessage},
		CreatedAtMilliseconds: 1_500,
	}
	if _, err := store.CreateMember(ctx, admin, overflowMember, 1_500); !relay.ErrorHasCode(err, relay.CodeDomainFull) {
		t.Fatalf("active member limit err=%v", err)
	}
	if _, err := store.RevokeMember(ctx, admin, createdMemberIDs[0], 1_600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateMember(ctx, admin, overflowMember, 1_600); err != nil {
		t.Fatalf("member slot was not released after revocation: %v", err)
	}

	admissionIDs := make([]uuid.UUID, 0, relay.MaximumOutstandingAdmissionCount)
	for index := 0; index < relay.MaximumOutstandingAdmissionCount; index++ {
		credential := relay.AdmissionCredential{
			TenantID:    tenantID,
			DomainID:    domainID,
			AdmissionID: uuid.New(),
			Token:       token(byte(index + 40)),
		}
		digest, err := relay.AdmissionAuthorizationDigest(credential)
		if err != nil {
			t.Fatal(err)
		}
		registration := relay.MemberAdmission{
			Version:               relay.SchemaVersion,
			TenantID:              tenantID,
			DomainID:              domainID,
			AdmissionID:           credential.AdmissionID,
			AuthorizationDigest:   digest,
			Capabilities:          []relay.Capability{relay.CapabilityFetchMessage},
			CreatedAtMilliseconds: 2_000,
			ExpiresAtMilliseconds: 3_000,
		}
		if _, err := store.CreateAdmission(ctx, admin, registration, 2_000); err != nil {
			t.Fatalf("create admission %d: %v", index, err)
		}
		admissionIDs = append(admissionIDs, credential.AdmissionID)
	}
	overflowAdmission := relay.MemberAdmission{
		Version:               relay.SchemaVersion,
		TenantID:              tenantID,
		DomainID:              domainID,
		AdmissionID:           uuid.New(),
		AuthorizationDigest:   initialDigest,
		Capabilities:          []relay.Capability{relay.CapabilityFetchMessage},
		CreatedAtMilliseconds: 2_000,
		ExpiresAtMilliseconds: 3_000,
	}
	if _, err := store.CreateAdmission(ctx, admin, overflowAdmission, 2_000); !relay.ErrorHasCode(err, relay.CodeDomainFull) {
		t.Fatalf("outstanding admission limit err=%v", err)
	}
	if _, err := store.RevokeAdmission(ctx, admin, admissionIDs[0], 2_100); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateAdmission(ctx, admin, overflowAdmission, 2_100); err != nil {
		t.Fatalf("admission slot was not released after revocation: %v", err)
	}
}

func TestMemoryStoreSharesDeliveryAndAcknowledgmentFactsAcrossSubscriptionAgents(t *testing.T) {
	ctx := context.Background()
	fixture, err := testfixture.LoadRelayCarrier()
	if err != nil {
		t.Fatal(err)
	}
	admin := relay.AdministrationCredential{
		TenantID: fixture.Envelope.TenantID,
		DomainID: fixture.Envelope.DomainID,
		Token:    token(210),
	}
	adminDigest, err := relay.AdministrationDigest(admin)
	if err != nil {
		t.Fatal(err)
	}
	store := relay.NewMemoryStore()
	_, err = store.CreateDomain(ctx, relay.DomainRegistration{
		Version: relay.SchemaVersion, TenantID: admin.TenantID, DomainID: admin.DomainID,
		AdministrationDigest: adminDigest, CreatedAtMilliseconds: 1_000,
		MaximumMessageCount: 10, MaximumMessageByteCount: 2_048,
		MaximumBlobCount: 10, MaximumBlobByteCount: 2_048,
	}, fixture.PublisherRegistration)
	if err != nil {
		t.Fatal(err)
	}

	recipientSubscriptionID := uuid.New()
	createRequest := relay.SubscriptionCreateRequest{
		RetryID: uuid.New(), SubscriptionID: recipientSubscriptionID,
		CreatedAtMilliseconds: 1_100,
	}
	created, err := store.CreateSubscription(ctx, admin, createRequest)
	if err != nil || created.Acceptance != relay.AcceptanceAccepted ||
		created.Subscription.Status != relay.SubscriptionActive {
		t.Fatalf("create subscription=%+v err=%v", created, err)
	}
	retry, err := store.CreateSubscription(ctx, admin, createRequest)
	if err != nil || retry.Acceptance != relay.AcceptanceDuplicate || retry.Subscription != created.Subscription {
		t.Fatalf("subscription retry=%+v err=%v", retry, err)
	}
	collision := createRequest
	collision.SubscriptionID = uuid.New()
	if _, err := store.CreateSubscription(ctx, admin, collision); !relay.ErrorHasCode(err, relay.CodeSubscriptionCollision) {
		t.Fatalf("subscription retry collision err=%v", err)
	}

	newAgent := func(seed byte, subscriptionID uuid.UUID) (relay.Credential, relay.MemberRegistration) {
		credential := relay.Credential{
			TenantID: admin.TenantID, DomainID: admin.DomainID,
			MemberID: uuid.New(), Token: token(seed),
		}
		digest, digestErr := relay.AuthorizationDigest(credential)
		if digestErr != nil {
			t.Fatal(digestErr)
		}
		registration := relay.MemberRegistration{
			Version: relay.SchemaVersion, TenantID: admin.TenantID, DomainID: admin.DomainID,
			MemberID: credential.MemberID, AuthorizationDigest: digest,
			Capabilities:          []relay.Capability{relay.CapabilityAcknowledgeMessage, relay.CapabilityFetchMessage},
			CreatedAtMilliseconds: 1_200,
		}
		if acceptance, createErr := store.CreateSubscriptionMember(ctx, admin, subscriptionID, registration, 1_200); createErr != nil || acceptance != relay.AcceptanceAccepted {
			t.Fatalf("create agent acceptance=%q err=%v", acceptance, createErr)
		}
		return credential, registration
	}
	agentA, agentARegistration := newAgent(211, recipientSubscriptionID)
	agentB, _ := newAgent(212, recipientSubscriptionID)
	publisherAgent, _ := newAgent(213, fixture.PublisherRegistration.MemberID)

	published, err := store.Publish(ctx, fixture.PublisherAccess.Credential(), fixture.Envelope, 1_300)
	if err != nil || published.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("publish=%+v err=%v", published, err)
	}
	for name, credential := range map[string]relay.Credential{"agent A": agentA, "agent B": agentB} {
		fetched, fetchErr := store.Fetch(ctx, credential, 0, 10, 1_300)
		if fetchErr != nil || len(fetched.Messages) != 1 {
			t.Fatalf("%s fetch=%+v err=%v", name, fetched, fetchErr)
		}
	}
	if fetched, fetchErr := store.Fetch(ctx, publisherAgent, 0, 10, 1_300); fetchErr != nil || len(fetched.Messages) != 0 {
		t.Fatalf("same-subscription publisher agent fetch=%+v err=%v", fetched, fetchErr)
	}
	accepted, err := store.Acknowledge(ctx, agentA, fixture.Envelope.MessageID, relay.AcknowledgmentAccepted, 1_300)
	if err != nil || accepted.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("accepted=%+v err=%v", accepted, err)
	}
	applied, err := store.Acknowledge(ctx, agentB, fixture.Envelope.MessageID, relay.AcknowledgmentApplied, 1_301)
	if err != nil || applied.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("cross-agent applied=%+v err=%v", applied, err)
	}
	if _, err := store.RevokeMember(ctx, admin, agentARegistration.MemberID, 1_400); err != nil {
		t.Fatal(err)
	}
	if fetched, fetchErr := store.Fetch(ctx, agentB, 0, 10, 1_400); fetchErr != nil || len(fetched.Messages) != 1 {
		t.Fatalf("remaining subscription agent fetch=%+v err=%v", fetched, fetchErr)
	}

	statusRequest := relay.SubscriptionStatusChangeRequest{
		RetryID: uuid.New(), Status: relay.SubscriptionRebootstrapRequired,
		ChangedAtMilliseconds: 1_500,
	}
	changed, err := store.ChangeSubscriptionStatus(ctx, admin, recipientSubscriptionID, statusRequest)
	if err != nil || changed.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("status change=%+v err=%v", changed, err)
	}
	statusRetry, err := store.ChangeSubscriptionStatus(ctx, admin, recipientSubscriptionID, statusRequest)
	if err != nil || statusRetry.Acceptance != relay.AcceptanceDuplicate || statusRetry.Subscription != changed.Subscription {
		t.Fatalf("status retry=%+v err=%v", statusRetry, err)
	}
	if _, err := store.Fetch(ctx, agentB, 0, 10, 1_500); !relay.ErrorHasCode(err, relay.CodeRebootstrapExpired) {
		t.Fatalf("unleased rebootstrap fetch err=%v", err)
	}
}

func token(seed byte) string {
	bytes := make([]byte, 32)
	for index := range bytes {
		bytes[index] = seed + byte(index)
	}
	return base64.RawURLEncoding.EncodeToString(bytes)
}
