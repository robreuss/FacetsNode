package postgres_test

import (
	"context"
	"encoding/base64"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	postgresstore "github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/testfixture"
)

func TestPostgresRelayPersistsSequencesAcknowledgmentsAndRevocation(t *testing.T) {
	databaseURL := os.Getenv("FACETS_NODE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("FACETS_NODE_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	fixture, err := testfixture.LoadRelayCarrier()
	if err != nil {
		t.Fatal(err)
	}
	fixtureCiphertextByteCount, err := fixture.Envelope.CiphertextByteCount()
	if err != nil {
		t.Fatal(err)
	}
	const concurrentCount = 20
	blobBytes := []byte("opaque-postgres-relay-blob")
	blobID := relay.BlobID(blobBytes)
	pool := openPool(t, ctx, databaseURL)
	if err := postgresstore.Migrate(ctx, pool); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `TRUNCATE relay_tenants CASCADE`); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	store := postgresstore.NewRelayStore(pool)
	admin := relay.AdministrationCredential{
		TenantID: fixture.Envelope.TenantID,
		DomainID: fixture.Envelope.DomainID,
		Token:    postgresRelayToken(128),
	}
	adminDigest, err := relay.AdministrationDigest(admin)
	if err != nil {
		pool.Close()
		t.Fatal(err)
	}
	domain := relay.DomainRegistration{
		Version:                 relay.SchemaVersion,
		TenantID:                admin.TenantID,
		DomainID:                admin.DomainID,
		AdministrationDigest:    adminDigest,
		CreatedAtMilliseconds:   1_000,
		MaximumMessageCount:     concurrentCount + 1,
		MaximumBlobCount:        1,
		MaximumMessageByteCount: fixtureCiphertextByteCount + concurrentCount + int64(len(blobBytes)),
		MaximumBlobByteCount:    fixtureCiphertextByteCount + concurrentCount + int64(len(blobBytes)),
	}
	publisherRegistration := fixture.PublisherRegistration
	publisherRegistration.Capabilities = []relay.Capability{
		relay.CapabilityPublishBlob,
		relay.CapabilityFetchMessage,
		relay.CapabilityPublishMessage,
	}
	_, acceptance, err := postgresProvisionTenant(ctx, store, domain, publisherRegistration, publisherRegistration.MemberID, 120)
	if err != nil || acceptance != relay.AcceptanceAccepted {
		pool.Close()
		t.Fatalf("create domain acceptance=%q err=%v", acceptance, err)
	}

	recipientCredential := fixture.RecipientAccess.Credential()
	recipientDigest, err := relay.AuthorizationDigest(recipientCredential)
	if err != nil {
		pool.Close()
		t.Fatal(err)
	}
	recipient := relay.MemberRegistration{
		Version:             relay.SchemaVersion,
		TenantID:            recipientCredential.TenantID,
		DomainID:            recipientCredential.DomainID,
		MemberID:            recipientCredential.MemberID,
		AuthorizationDigest: recipientDigest,
		Capabilities: []relay.Capability{
			relay.CapabilityFetchBlob,
			relay.CapabilityAcknowledgeMessage,
			relay.CapabilityFetchMessage,
		},
		CreatedAtMilliseconds: 1_500,
	}
	admissionCredential := relay.AdmissionCredential{
		TenantID:    admin.TenantID,
		DomainID:    admin.DomainID,
		AdmissionID: uuid.New(),
		Token:       postgresRelayToken(160),
	}
	admissionDigest, err := relay.AdmissionAuthorizationDigest(admissionCredential)
	if err != nil {
		pool.Close()
		t.Fatal(err)
	}
	admission := relay.MemberAdmission{
		Version:               relay.SchemaVersion,
		TenantID:              admin.TenantID,
		DomainID:              admin.DomainID,
		AdmissionID:           admissionCredential.AdmissionID,
		AuthorizationDigest:   admissionDigest,
		Capabilities:          recipient.Capabilities,
		CreatedAtMilliseconds: 1_500,
		ExpiresAtMilliseconds: 2_500,
	}
	recipientSubscriptionID := uuid.New()
	if created, createErr := store.CreateSubscription(ctx, admin, relay.SubscriptionCreateRequest{RetryID: uuid.New(), SubscriptionID: recipientSubscriptionID, CreatedAtMilliseconds: 1_500}); createErr != nil || created.Acceptance != relay.AcceptanceAccepted {
		pool.Close()
		t.Fatalf("create recipient subscription=%+v err=%v", created, createErr)
	}
	admissionCreated, err := store.CreateSubscriptionAdmission(ctx, admin, recipientSubscriptionID, admission, 1_500)
	if err != nil || admissionCreated.Acceptance != relay.AcceptanceAccepted {
		pool.Close()
		t.Fatalf("create admission result=%+v err=%v", admissionCreated, err)
	}
	admitted, err := store.ClaimSubscriptionAdmission(
		ctx,
		admissionCredential,
		relay.MemberAdmissionClaim{
			MemberID:            recipient.MemberID,
			AuthorizationDigest: recipient.AuthorizationDigest,
		},
		1_500,
	)
	if err != nil || admitted.Acceptance != relay.AcceptanceAccepted ||
		admitted.Member.SubscriptionID != recipientSubscriptionID ||
		!reflect.DeepEqual(admitted.Member.MemberRegistration, recipient) {
		pool.Close()
		t.Fatalf("claim admission result=%+v err=%v", admitted, err)
	}

	first, err := store.Publish(
		ctx,
		fixture.PublisherAccess.Credential(),
		fixture.Envelope,
		1_500,
	)
	if err != nil || first.Acceptance != relay.AcceptanceAccepted || first.Sequence != 1 {
		pool.Close()
		t.Fatalf("first publish=%+v err=%v", first, err)
	}
	retry, err := store.Publish(
		ctx,
		fixture.PublisherAccess.Credential(),
		fixture.Envelope,
		1_500,
	)
	if err != nil || retry.Acceptance != relay.AcceptanceDuplicate || retry.Sequence != 1 {
		pool.Close()
		t.Fatalf("retry=%+v err=%v", retry, err)
	}

	sequences := make(chan uint64, concurrentCount)
	errorsFound := make(chan error, concurrentCount)
	var group sync.WaitGroup
	for index := 0; index < concurrentCount; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			envelope := fixture.Envelope
			envelope.MessageID = uuid.New()
			envelope.Ciphertext = base64.RawURLEncoding.EncodeToString(
				[]byte{byte(index + 1)},
			)
			result, err := store.Publish(
				ctx,
				fixture.PublisherAccess.Credential(),
				envelope,
				1_500,
			)
			if err != nil {
				errorsFound <- err
				return
			}
			sequences <- result.Sequence
		}(index)
	}
	group.Wait()
	close(sequences)
	close(errorsFound)
	for err := range errorsFound {
		pool.Close()
		t.Fatal(err)
	}
	seen := map[uint64]bool{1: true}
	for sequence := range sequences {
		if seen[sequence] {
			pool.Close()
			t.Fatalf("duplicate sequence %d", sequence)
		}
		seen[sequence] = true
	}
	for sequence := uint64(1); sequence <= concurrentCount+1; sequence++ {
		if !seen[sequence] {
			pool.Close()
			t.Fatalf("missing sequence %d", sequence)
		}
	}
	overQuota := fixture.Envelope
	overQuota.MessageID = uuid.New()
	overQuota.Ciphertext = base64.RawURLEncoding.EncodeToString([]byte{1})
	if _, err := store.Publish(
		ctx,
		fixture.PublisherAccess.Credential(),
		overQuota,
		1_500,
	); !relay.ErrorHasCode(err, relay.CodeDomainFull) {
		pool.Close()
		t.Fatalf("publish beyond message-count quota err=%v", err)
	}
	if err := store.PrepareBlobPublish(
		ctx,
		fixture.PublisherAccess.Credential(),
		blobID,
		int64(len(blobBytes)),
		1_500,
	); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	blobPublished, err := store.CommitBlobPublish(
		ctx,
		fixture.PublisherAccess.Credential(),
		blobID,
		int64(len(blobBytes)),
		1_500,
	)
	if err != nil || blobPublished.Acceptance != relay.AcceptanceAccepted {
		pool.Close()
		t.Fatalf("blob publish=%+v err=%v", blobPublished, err)
	}
	blobRetry, err := store.CommitBlobPublish(
		ctx,
		fixture.PublisherAccess.Credential(),
		blobID,
		int64(len(blobBytes)),
		1_500,
	)
	if err != nil || blobRetry.Acceptance != relay.AcceptanceDuplicate {
		pool.Close()
		t.Fatalf("blob retry=%+v err=%v", blobRetry, err)
	}
	secondBlob := []byte("second")
	if err := store.PrepareBlobPublish(
		ctx,
		fixture.PublisherAccess.Credential(),
		relay.BlobID(secondBlob),
		int64(len(secondBlob)),
		1_500,
	); !relay.ErrorHasCode(err, relay.CodeDomainFull) {
		pool.Close()
		t.Fatalf("blob beyond count quota err=%v", err)
	}
	newAdmin := admin
	newAdmin.Token = postgresRelayToken(161)
	newAdminDigest, err := relay.AdministrationDigest(newAdmin)
	if err != nil {
		pool.Close()
		t.Fatal(err)
	}
	adminRotation := relay.CredentialRotation{
		RotationID:          uuid.New(),
		AuthorizationDigest: newAdminDigest,
	}
	adminRotated, err := store.RotateAdministrationCredential(
		ctx, admin, adminRotation, 1_700,
	)
	if err != nil || adminRotated.Acceptance != relay.AcceptanceAccepted {
		pool.Close()
		t.Fatalf("rotate admin=%+v err=%v", adminRotated, err)
	}
	newRecipientCredential := recipientCredential
	newRecipientCredential.Token = postgresRelayToken(162)
	newRecipientDigest, err := relay.AuthorizationDigest(newRecipientCredential)
	if err != nil {
		pool.Close()
		t.Fatal(err)
	}
	recipientRotation := relay.CredentialRotation{
		RotationID:          uuid.New(),
		AuthorizationDigest: newRecipientDigest,
	}
	recipientRotated, err := store.RotateMemberCredential(
		ctx, recipientCredential, recipientRotation, 1_700,
	)
	if err != nil || recipientRotated.Acceptance != relay.AcceptanceAccepted {
		pool.Close()
		t.Fatalf("rotate recipient=%+v err=%v", recipientRotated, err)
	}
	recipient.AuthorizationDigest = newRecipientDigest
	pool.Close()

	pool = openPool(t, ctx, databaseURL)
	defer pool.Close()
	store = postgresstore.NewRelayStore(pool)
	adminRetry, err := store.RotateAdministrationCredential(
		ctx, admin, adminRotation, 2_000,
	)
	if err != nil || adminRetry.Acceptance != relay.AcceptanceDuplicate ||
		adminRetry.RotatedAtMilliseconds != 1_700 {
		t.Fatalf("restart admin rotation retry=%+v err=%v", adminRetry, err)
	}
	recipientRotationRetry, err := store.RotateMemberCredential(
		ctx, recipientCredential, recipientRotation, 2_000,
	)
	if err != nil || recipientRotationRetry.Acceptance != relay.AcceptanceDuplicate ||
		recipientRotationRetry.RotatedAtMilliseconds != 1_700 {
		t.Fatalf("restart member rotation retry=%+v err=%v", recipientRotationRetry, err)
	}
	if _, err := store.CollectAdmissions(
		ctx, admin, 2_000,
	); !relay.ErrorHasCode(err, relay.CodeUnauthorized) {
		t.Fatalf("old admin remained authorized after restart err=%v", err)
	}
	if _, err := store.Fetch(
		ctx, recipientCredential, 0, 100, 2_000,
	); !relay.ErrorHasCode(err, relay.CodeUnauthorized) {
		t.Fatalf("old member remained authorized after restart err=%v", err)
	}
	admin = newAdmin
	recipientCredential = newRecipientCredential
	admissionRetry, err := store.ClaimSubscriptionAdmission(
		ctx,
		admissionCredential,
		relay.MemberAdmissionClaim{
			MemberID:            recipient.MemberID,
			AuthorizationDigest: recipient.AuthorizationDigest,
		},
		3_000,
	)
	if err != nil || admissionRetry.Acceptance != relay.AcceptanceDuplicate ||
		!reflect.DeepEqual(admissionRetry.Member.MemberRegistration, recipient) {
		t.Fatalf("restart admission retry=%+v err=%v", admissionRetry, err)
	}
	fetched, err := store.Fetch(ctx, recipientCredential, 0, 100, 1_500)
	if err != nil || len(fetched.Messages) != concurrentCount+1 ||
		fetched.NextSequence != concurrentCount+1 {
		t.Fatalf("restart fetch count=%d cursor=%d err=%v", len(fetched.Messages), fetched.NextSequence, err)
	}
	if fetched.Messages[0].Envelope != fixture.Envelope {
		t.Fatalf("portable fixture changed after restart")
	}
	blobMetadata, err := store.GetBlobMetadata(
		ctx, recipientCredential, blobID, 1_500,
	)
	if err != nil || blobMetadata.ByteCount != int64(len(blobBytes)) {
		t.Fatalf("restart blob metadata=%+v err=%v", blobMetadata, err)
	}
	if _, err := store.Acknowledge(
		ctx,
		recipientCredential,
		fixture.Envelope.MessageID,
		relay.AcknowledgmentAccepted,
		1_500,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Acknowledge(
		ctx,
		recipientCredential,
		fixture.Envelope.MessageID,
		relay.AcknowledgmentApplied,
		1_500,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RevokeMember(
		ctx, admin, recipientCredential.MemberID, 1_600,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Fetch(ctx, recipientCredential, 0, 100, 1_600); !relay.ErrorHasCode(err, relay.CodeMemberRevoked) {
		t.Fatalf("fetch after revocation err=%v", err)
	}
	earlyCollection, err := store.CollectAdmissions(
		ctx,
		admin,
		1_500+relay.AdmissionRecoveryWindowMilliseconds-1,
	)
	if err != nil || earlyCollection.CollectedCount != 0 {
		t.Fatalf("early admission collection=%+v err=%v", earlyCollection, err)
	}
	collectionTime := int64(1_500) + relay.AdmissionRecoveryWindowMilliseconds
	collection, err := store.CollectAdmissions(ctx, admin, collectionTime)
	if err != nil || collection.CollectedCount != 1 || collection.HasMore {
		t.Fatalf("admission collection=%+v err=%v", collection, err)
	}
	if _, err := store.ClaimSubscriptionAdmission(
		ctx,
		admissionCredential,
		relay.MemberAdmissionClaim{
			MemberID:            recipient.MemberID,
			AuthorizationDigest: recipient.AuthorizationDigest,
		},
		collectionTime,
	); !relay.ErrorHasCode(err, relay.CodeAdmissionNotFound) {
		t.Fatalf("collected admission remained retryable err=%v", err)
	}

	var messageCount, blobCount, lastSequence, auditCount int
	var messageByteCount, blobByteCount int64
	if err := pool.QueryRow(ctx, `
		SELECT message_count, message_byte_count, blob_count, blob_byte_count, last_sequence
		FROM relay_domains WHERE tenant_id = $1 AND domain_id = $2
	`, domain.TenantID, domain.DomainID).Scan(
		&messageCount,
		&messageByteCount,
		&blobCount,
		&blobByteCount,
		&lastSequence,
	); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM relay_audit_events
		WHERE tenant_id = $1 AND domain_id = $2
	`, domain.TenantID, domain.DomainID).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if messageCount != concurrentCount+1 ||
		blobCount != 1 ||
		messageByteCount != fixtureCiphertextByteCount+concurrentCount ||
		blobByteCount != int64(len(blobBytes)) ||
		lastSequence != concurrentCount+1 ||
		auditCount < concurrentCount+13 {
		t.Fatalf(
			"message_count=%d message_byte_count=%d blob_count=%d blob_byte_count=%d last_sequence=%d audit_count=%d",
			messageCount,
			messageByteCount,
			blobCount,
			blobByteCount,
			lastSequence,
			auditCount,
		)
	}
	result, err := pool.Exec(ctx, `
		DELETE FROM relay_domains WHERE tenant_id = $1 AND domain_id = $2
	`, domain.TenantID, domain.DomainID)
	if err != nil || result.RowsAffected() != 1 {
		t.Fatalf("delete relay domain rows=%d err=%v", result.RowsAffected(), err)
	}
	var remaining int
	if err := pool.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM relay_subscriptions WHERE tenant_id = $1 AND domain_id = $2) +
			(SELECT count(*) FROM relay_subscription_status_changes WHERE tenant_id = $1 AND domain_id = $2) +
			(SELECT count(*) FROM relay_member_admissions WHERE tenant_id = $1 AND domain_id = $2) +
			(SELECT count(*) FROM relay_credential_rotations WHERE tenant_id = $1 AND domain_id = $2) +
			(SELECT count(*) FROM relay_members WHERE tenant_id = $1 AND domain_id = $2) +
			(SELECT count(*) FROM relay_messages WHERE tenant_id = $1 AND domain_id = $2) +
			(SELECT count(*) FROM relay_acknowledgments WHERE tenant_id = $1 AND domain_id = $2) +
			(SELECT count(*) FROM relay_blobs WHERE tenant_id = $1 AND domain_id = $2) +
			(SELECT count(*) FROM relay_audit_events WHERE tenant_id = $1 AND domain_id = $2)
	`, domain.TenantID, domain.DomainID).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("relay domain deletion left %d dependent rows", remaining)
	}
}

func TestPostgresRelayTenantProvisioningPersistsAcrossPoolRestart(t *testing.T) {
	databaseURL := os.Getenv("FACETS_NODE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("FACETS_NODE_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool := openPool(t, ctx, databaseURL)
	if err := postgresstore.Migrate(ctx, pool); err != nil {
		pool.Close()
		t.Fatal(err)
	}

	tenantID := uuid.New()
	_, parent, parentMember := postgresRelayDomainAuthority(
		t, tenantID, uuid.New(), uuid.New(), 16, 48, 1_000,
	)
	store := postgresstore.NewRelayStore(pool)
	tenantCredential, acceptance, err := postgresProvisionTenant(ctx, store, parent, parentMember, parentMember.MemberID, 15)
	if err != nil || acceptance != relay.AcceptanceAccepted {
		pool.Close()
		t.Fatalf("create parent domain acceptance=%q err=%v", acceptance, err)
	}
	pool.Close()

	_, child, childMember := postgresRelayDomainAuthority(
		t, tenantID, uuid.New(), uuid.New(), 80, 112, 1_500,
	)
	pool = openPool(t, ctx, databaseURL)
	store = postgresstore.NewRelayStore(pool)
	childProvisioning := postgresDomainProvisioning(child, childMember, childMember.MemberID)
	acceptanceResult, err := store.ProvisionDomain(ctx, tenantCredential, childProvisioning, 2_000)
	acceptance = acceptanceResult.Acceptance
	if err != nil || acceptance != relay.AcceptanceAccepted {
		pool.Close()
		t.Fatalf("create delegated domain acceptance=%q err=%v", acceptance, err)
	}
	pool.Close()

	pool = openPool(t, ctx, databaseURL)
	defer pool.Close()
	store = postgresstore.NewRelayStore(pool)
	acceptanceResult, err = store.ProvisionDomain(ctx, tenantCredential, childProvisioning, 2_000)
	acceptance = acceptanceResult.Acceptance
	if err != nil || acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("retry delegated domain acceptance=%q err=%v", acceptance, err)
	}
	var domainCount int
	if err := pool.QueryRow(
		ctx,
		"SELECT count(*) FROM relay_domains WHERE tenant_id = $1",
		tenantID,
	).Scan(&domainCount); err != nil {
		t.Fatal(err)
	}
	if domainCount != 2 {
		t.Fatalf("tenant domain count=%d; want=2", domainCount)
	}

	unauthorized := tenantCredential
	unauthorized.Token = postgresRelayToken(144)
	_, third, thirdMember := postgresRelayDomainAuthority(
		t, tenantID, uuid.New(), uuid.New(), 176, 208, 2_000,
	)
	if _, err := store.ProvisionDomain(
		ctx, unauthorized, postgresDomainProvisioning(third, thirdMember, thirdMember.MemberID), 2_000,
	); !relay.ErrorHasCode(err, relay.CodeUnauthorized) {
		t.Fatalf("unauthorized delegated domain err=%v", err)
	}
}

func postgresRelayDomainAuthority(
	t *testing.T,
	tenantID uuid.UUID,
	domainID uuid.UUID,
	memberID uuid.UUID,
	administrationTokenSeed byte,
	memberTokenSeed byte,
	createdAtMilliseconds int64,
) (
	relay.AdministrationCredential,
	relay.DomainRegistration,
	relay.MemberRegistration,
) {
	t.Helper()
	administration := relay.AdministrationCredential{
		TenantID: tenantID,
		DomainID: domainID,
		Token:    postgresRelayToken(administrationTokenSeed),
	}
	administrationDigest, err := relay.AdministrationDigest(administration)
	if err != nil {
		t.Fatal(err)
	}
	memberCredential := relay.Credential{
		TenantID: tenantID,
		DomainID: domainID,
		MemberID: memberID,
		Token:    postgresRelayToken(memberTokenSeed),
	}
	memberDigest, err := relay.AuthorizationDigest(memberCredential)
	if err != nil {
		t.Fatal(err)
	}
	return administration, relay.DomainRegistration{
			Version:                 relay.SchemaVersion,
			TenantID:                tenantID,
			DomainID:                domainID,
			AdministrationDigest:    administrationDigest,
			CreatedAtMilliseconds:   createdAtMilliseconds,
			MaximumMessageCount:     relay.DefaultMaximumMessageCount,
			MaximumBlobCount:        relay.DefaultMaximumBlobCount,
			MaximumMessageByteCount: relay.DefaultMaximumMessageByteCount,
			MaximumBlobByteCount:    relay.DefaultMaximumBlobByteCount,
		}, relay.MemberRegistration{
			Version:               relay.SchemaVersion,
			TenantID:              tenantID,
			DomainID:              domainID,
			MemberID:              memberID,
			AuthorizationDigest:   memberDigest,
			Capabilities:          []relay.Capability{relay.CapabilityFetchMessage},
			CreatedAtMilliseconds: createdAtMilliseconds,
		}
}

func TestPostgresRelaySerializesOutstandingAdmissionLimit(t *testing.T) {
	databaseURL := os.Getenv("FACETS_NODE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("FACETS_NODE_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool := openPool(t, ctx, databaseURL)
	defer pool.Close()
	if err := postgresstore.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	store := postgresstore.NewRelayStore(pool)
	tenantID := uuid.New()
	domainID := uuid.New()
	admin := relay.AdministrationCredential{
		TenantID: tenantID,
		DomainID: domainID,
		Token:    postgresRelayToken(180),
	}
	adminDigest, err := relay.AdministrationDigest(admin)
	if err != nil {
		t.Fatal(err)
	}
	initialCredential := relay.Credential{
		TenantID: tenantID,
		DomainID: domainID,
		MemberID: uuid.New(),
		Token:    postgresRelayToken(181),
	}
	initialDigest, err := relay.AuthorizationDigest(initialCredential)
	if err != nil {
		t.Fatal(err)
	}
	domain := relay.DomainRegistration{
		Version:                 relay.SchemaVersion,
		TenantID:                tenantID,
		DomainID:                domainID,
		AdministrationDigest:    adminDigest,
		CreatedAtMilliseconds:   1_000,
		MaximumMessageCount:     10,
		MaximumBlobCount:        10,
		MaximumMessageByteCount: 1_024,
		MaximumBlobByteCount:    1_024,
	}
	initialMember := relay.MemberRegistration{
		Version:               relay.SchemaVersion,
		TenantID:              tenantID,
		DomainID:              domainID,
		MemberID:              initialCredential.MemberID,
		AuthorizationDigest:   initialDigest,
		Capabilities:          []relay.Capability{relay.CapabilityFetchMessage},
		CreatedAtMilliseconds: 1_000,
	}
	if _, _, err := postgresProvisionTenant(ctx, store, domain, initialMember, initialCredential.MemberID, 179); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(
			context.Background(),
			"DELETE FROM relay_domains WHERE tenant_id = $1 AND domain_id = $2",
			tenantID,
			domainID,
		)
	})

	const attemptCount = relay.MaximumOutstandingAdmissionCount + 1
	registrations := make([]relay.MemberAdmission, attemptCount)
	for index := range registrations {
		credential := relay.AdmissionCredential{
			TenantID:    tenantID,
			DomainID:    domainID,
			AdmissionID: uuid.New(),
			Token:       postgresRelayToken(byte(index)),
		}
		digest, err := relay.AdmissionAuthorizationDigest(credential)
		if err != nil {
			t.Fatal(err)
		}
		registrations[index] = relay.MemberAdmission{
			Version:               relay.SchemaVersion,
			TenantID:              tenantID,
			DomainID:              domainID,
			AdmissionID:           credential.AdmissionID,
			AuthorizationDigest:   digest,
			Capabilities:          []relay.Capability{relay.CapabilityFetchMessage},
			CreatedAtMilliseconds: 1_000,
			ExpiresAtMilliseconds: 2_000,
		}
	}
	type outcome struct {
		index      int
		acceptance relay.Acceptance
		err        error
	}
	outcomes := make(chan outcome, attemptCount)
	var group sync.WaitGroup
	for index, registration := range registrations {
		group.Add(1)
		go func(index int, registration relay.MemberAdmission) {
			defer group.Done()
			result, err := store.CreateSubscriptionAdmission(ctx, admin, initialCredential.MemberID, registration, 1_000)
			outcomes <- outcome{index: index, acceptance: result.Acceptance, err: err}
		}(index, registration)
	}
	group.Wait()
	close(outcomes)
	acceptedIndexes := make([]int, 0, relay.MaximumOutstandingAdmissionCount)
	domainFullCount := 0
	for outcome := range outcomes {
		switch {
		case outcome.err == nil && outcome.acceptance == relay.AcceptanceAccepted:
			acceptedIndexes = append(acceptedIndexes, outcome.index)
		case relay.ErrorHasCode(outcome.err, relay.CodeDomainFull):
			domainFullCount++
		default:
			t.Fatalf("unexpected admission outcome index=%d acceptance=%q err=%v",
				outcome.index, outcome.acceptance, outcome.err)
		}
	}
	if len(acceptedIndexes) != relay.MaximumOutstandingAdmissionCount ||
		domainFullCount != 1 {
		t.Fatalf("accepted=%d domain_full=%d", len(acceptedIndexes), domainFullCount)
	}
	retry, err := store.CreateSubscriptionAdmission(
		ctx, admin, initialCredential.MemberID, registrations[acceptedIndexes[0]], 1_000,
	)
	if err != nil || retry.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("capacity-bound exact retry=%+v err=%v", retry, err)
	}
}

func TestPostgresSubscriptionExactRetryFanoutAndSplitCounters(t *testing.T) {
	databaseURL := os.Getenv("FACETS_NODE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("FACETS_NODE_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool := openPool(t, ctx, databaseURL)
	defer pool.Close()
	if err := postgresstore.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	store := postgresstore.NewRelayStore(pool)
	tenantID, domainID := uuid.New(), uuid.New()
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM relay_tenants WHERE tenant_id=$1`, tenantID)
	})
	admin := relay.AdministrationCredential{TenantID: tenantID, DomainID: domainID, Token: postgresRelayToken(220)}
	adminDigest, err := relay.AdministrationDigest(admin)
	if err != nil {
		t.Fatal(err)
	}
	publisherCredential := relay.Credential{TenantID: tenantID, DomainID: domainID, MemberID: uuid.New(), Token: postgresRelayToken(221)}
	publisherDigest, err := relay.AuthorizationDigest(publisherCredential)
	if err != nil {
		t.Fatal(err)
	}
	domain := relay.DomainRegistration{
		Version: relay.SchemaVersion, TenantID: tenantID, DomainID: domainID,
		AdministrationDigest: adminDigest, CreatedAtMilliseconds: 1_000,
		MaximumMessageCount: 10, MaximumMessageByteCount: 4_096,
		MaximumBlobCount: 10, MaximumBlobByteCount: 4_096,
	}
	publisher := relay.MemberRegistration{
		Version: relay.SchemaVersion, TenantID: tenantID, DomainID: domainID,
		MemberID: publisherCredential.MemberID, AuthorizationDigest: publisherDigest,
		Capabilities: []relay.Capability{relay.CapabilityPublishMessage}, CreatedAtMilliseconds: 1_000,
	}
	tenantCredential, acceptance, err := postgresProvisionTenant(ctx, store, domain, publisher, publisher.MemberID, 219)
	if err != nil || acceptance != relay.AcceptanceAccepted {
		t.Fatalf("provision tenant acceptance=%q err=%v", acceptance, err)
	}

	subscriptionID := uuid.New()
	createRequest := relay.SubscriptionCreateRequest{RetryID: uuid.New(), SubscriptionID: subscriptionID, CreatedAtMilliseconds: 1_100}
	created, err := store.CreateSubscription(ctx, admin, createRequest)
	if err != nil || created.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("create subscription=%+v err=%v", created, err)
	}
	retried, err := store.CreateSubscription(ctx, admin, createRequest)
	if err != nil || retried.Acceptance != relay.AcceptanceDuplicate || retried.Subscription != created.Subscription {
		t.Fatalf("retry subscription=%+v err=%v", retried, err)
	}
	collision := createRequest
	collision.SubscriptionID = uuid.New()
	if _, err := store.CreateSubscription(ctx, admin, collision); !relay.ErrorHasCode(err, relay.CodeSubscriptionCollision) {
		t.Fatalf("subscription retry collision err=%v", err)
	}

	newAgent := func(seed byte) relay.Credential {
		credential := relay.Credential{TenantID: tenantID, DomainID: domainID, MemberID: uuid.New(), Token: postgresRelayToken(seed)}
		digest, digestErr := relay.AuthorizationDigest(credential)
		if digestErr != nil {
			t.Fatal(digestErr)
		}
		registration := relay.MemberRegistration{
			Version: relay.SchemaVersion, TenantID: tenantID, DomainID: domainID,
			MemberID: credential.MemberID, AuthorizationDigest: digest,
			Capabilities:          []relay.Capability{relay.CapabilityAcknowledgeMessage, relay.CapabilityFetchMessage},
			CreatedAtMilliseconds: 1_200,
		}
		if acceptance, createErr := store.CreateSubscriptionMember(ctx, admin, subscriptionID, registration, 1_200); createErr != nil || acceptance != relay.AcceptanceAccepted {
			t.Fatalf("create agent acceptance=%q err=%v", acceptance, createErr)
		}
		return credential
	}
	agentA, agentB := newAgent(222), newAgent(223)
	fixture, err := testfixture.LoadRelayCarrier()
	if err != nil {
		t.Fatal(err)
	}
	envelope := fixture.Envelope
	envelope.TenantID, envelope.DomainID = tenantID, domainID
	envelope.MessageID, envelope.PublisherMemberID = uuid.New(), publisherCredential.MemberID
	published, err := store.Publish(ctx, publisherCredential, envelope, 1_300)
	if err != nil || published.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("publish=%+v err=%v", published, err)
	}
	for _, agent := range []relay.Credential{agentA, agentB} {
		fetched, fetchErr := store.Fetch(ctx, agent, 0, 10, 1_300)
		if fetchErr != nil || len(fetched.Messages) != 1 {
			t.Fatalf("agent fetch=%+v err=%v", fetched, fetchErr)
		}
	}
	if _, err := store.Acknowledge(ctx, agentA, envelope.MessageID, relay.AcknowledgmentAccepted, 1_300); err != nil {
		t.Fatal(err)
	}
	if applied, err := store.Acknowledge(ctx, agentB, envelope.MessageID, relay.AcknowledgmentApplied, 1_301); err != nil || applied.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("cross-agent apply=%+v err=%v", applied, err)
	}
	domainStatus, err := store.GetDomainStatus(ctx, admin)
	if err != nil || domainStatus.MessageCount != 1 || domainStatus.MessageByteCount <= 0 || domainStatus.BlobByteCount != 0 || domainStatus.ActiveSubscriptionCount != 2 {
		t.Fatalf("domain status=%+v err=%v", domainStatus, err)
	}
	tenantStatus, err := store.GetTenantStatus(ctx, tenantCredential)
	if err != nil || tenantStatus.AggregateMessageCount != 1 || tenantStatus.AggregateMessageByteCount != domainStatus.MessageByteCount || tenantStatus.AggregateBlobByteCount != 0 {
		t.Fatalf("tenant status=%+v err=%v", tenantStatus, err)
	}
	statusRequest := relay.SubscriptionStatusChangeRequest{RetryID: uuid.New(), Status: relay.SubscriptionRebootstrapRequired, ChangedAtMilliseconds: 1_400}
	changed, err := store.ChangeSubscriptionStatus(ctx, admin, subscriptionID, statusRequest)
	if err != nil || changed.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("change status=%+v err=%v", changed, err)
	}
	statusRetry, err := store.ChangeSubscriptionStatus(ctx, admin, subscriptionID, statusRequest)
	if err != nil || statusRetry.Acceptance != relay.AcceptanceDuplicate || statusRetry.Subscription != changed.Subscription {
		t.Fatalf("status retry=%+v err=%v", statusRetry, err)
	}
}

func postgresRelayToken(seed byte) string {
	value := make([]byte, 32)
	for index := range value {
		value[index] = seed + byte(index)
	}
	return base64.RawURLEncoding.EncodeToString(value)
}

func postgresDomainProvisioning(
	domain relay.DomainRegistration,
	member relay.MemberRegistration,
	subscriptionID uuid.UUID,
) relay.DomainProvisioning {
	return relay.DomainProvisioning{
		Version: relay.SchemaVersion, RetryID: uuid.New(), Registration: domain,
		Subscription: relay.Subscription{
			Version: relay.SchemaVersion, TenantID: domain.TenantID, DomainID: domain.DomainID,
			SubscriptionID: subscriptionID, Status: relay.SubscriptionActive,
			CreatedAtMilliseconds: domain.CreatedAtMilliseconds,
			UpdatedAtMilliseconds: domain.CreatedAtMilliseconds,
		},
		InitialMember: member,
	}
}

func postgresProvisionTenant(
	ctx context.Context,
	store *postgresstore.RelayStore,
	domain relay.DomainRegistration,
	member relay.MemberRegistration,
	subscriptionID uuid.UUID,
	tokenSeed byte,
) (relay.TenantCredential, relay.Acceptance, error) {
	credential := relay.TenantCredential{TenantID: domain.TenantID, Token: postgresRelayToken(tokenSeed)}
	digest, err := relay.TenantAuthorizationDigest(credential)
	if err != nil {
		return relay.TenantCredential{}, "", err
	}
	provisioning := postgresDomainProvisioning(domain, member, subscriptionID)
	tenant := relay.TenantRegistration{
		Version: relay.SchemaVersion, RetryID: uuid.New(), TenantID: domain.TenantID,
		AuthorizationDigest: digest, CreatedAtMilliseconds: domain.CreatedAtMilliseconds,
		MaximumDomainCount:               256,
		MaximumAggregateMessageCount:     1_000_000,
		MaximumAggregateMessageByteCount: 1 << 40,
		MaximumAggregateBlobCount:        1_000_000,
		MaximumAggregateBlobByteCount:    1 << 40,
	}
	result, err := store.ProvisionTenant(ctx, tenant, provisioning)
	return credential, result.Acceptance, err
}
