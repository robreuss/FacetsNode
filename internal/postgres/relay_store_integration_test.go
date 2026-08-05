package postgres_test

import (
	"context"
	"encoding/base64"
	"os"
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
	if _, err := pool.Exec(ctx, `
		TRUNCATE relay_audit_events, relay_acknowledgments,
		         relay_messages, relay_blobs, relay_members, relay_domains
	`); err != nil {
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
		Version:                relay.SchemaVersion,
		TenantID:               admin.TenantID,
		DomainID:               admin.DomainID,
		AdministrationDigest:   adminDigest,
		CreatedAtMilliseconds:  1_000,
		MaximumMessageCount:    concurrentCount + 1,
		MaximumBlobCount:       1,
		MaximumStoredByteCount: fixtureCiphertextByteCount + concurrentCount + int64(len(blobBytes)),
	}
	publisherRegistration := fixture.PublisherRegistration
	publisherRegistration.Capabilities = []relay.Capability{
		relay.CapabilityPublishBlob,
		relay.CapabilityFetchMessage,
		relay.CapabilityPublishMessage,
	}
	acceptance, err := store.CreateDomain(ctx, domain, publisherRegistration)
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
		CreatedAtMilliseconds: 1_000,
	}
	acceptance, err = store.CreateMember(ctx, admin, recipient, 1_500)
	if err != nil || acceptance != relay.AcceptanceAccepted {
		pool.Close()
		t.Fatalf("create member acceptance=%q err=%v", acceptance, err)
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
	pool.Close()

	pool = openPool(t, ctx, databaseURL)
	defer pool.Close()
	store = postgresstore.NewRelayStore(pool)
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

	var messageCount, blobCount, lastSequence, auditCount int
	var storedByteCount int64
	if err := pool.QueryRow(ctx, `
		SELECT message_count, blob_count, stored_byte_count, last_sequence
		FROM relay_domains WHERE tenant_id = $1 AND domain_id = $2
	`, domain.TenantID, domain.DomainID).Scan(
		&messageCount,
		&blobCount,
		&storedByteCount,
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
		storedByteCount != fixtureCiphertextByteCount+concurrentCount+int64(len(blobBytes)) ||
		lastSequence != concurrentCount+1 ||
		auditCount != concurrentCount+8 {
		t.Fatalf(
			"message_count=%d blob_count=%d stored_byte_count=%d last_sequence=%d audit_count=%d",
			messageCount,
			blobCount,
			storedByteCount,
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

func postgresRelayToken(seed byte) string {
	value := make([]byte, 32)
	for index := range value {
		value[index] = seed + byte(index)
	}
	return base64.RawURLEncoding.EncodeToString(value)
}
