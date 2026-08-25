package postgres_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	postgresstore "github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/relay"
)

func TestPostgresBlobUploadExpiryCanBeFencedPerTenant(t *testing.T) {
	databaseURL := os.Getenv("FACETS_SERVER_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("FACETS_SERVER_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	lockDisposablePostgres(t, ctx, databaseURL)
	pool := openPool(t, ctx, databaseURL)
	defer pool.Close()
	if err := postgresstore.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `TRUNCATE relay_tenants CASCADE`); err != nil {
		t.Fatal(err)
	}
	store := postgresstore.NewRelayStore(pool, time.Second)
	firstTenant, firstUpload := postgresExpiringBlobUpload(
		t,
		ctx,
		store,
		17,
	)
	secondTenant, secondUpload := postgresExpiringBlobUpload(
		t,
		ctx,
		store,
		31,
	)

	candidates, err := store.ExpiredBlobUploadTenantCandidates(ctx, 2_000)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[uuid.UUID]bool, len(candidates))
	for _, candidate := range candidates {
		seen[candidate] = true
	}
	if !seen[firstTenant] || !seen[secondTenant] {
		t.Fatalf("tenant expiry candidates=%v", candidates)
	}

	expired, err := store.ExpireBlobUploadsForTenant(
		ctx,
		firstTenant,
		2_000,
		100,
		256,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(expired) != 1 || expired[0].Scope.TenantID != firstTenant ||
		expired[0].UploadID != firstUpload {
		t.Fatalf("first-tenant expiry=%+v", expired)
	}
	var firstState, secondState string
	if err := pool.QueryRow(ctx, `
		SELECT state FROM relay_blob_uploads
		WHERE tenant_id=$1 AND upload_id=$2
	`, firstTenant, firstUpload).Scan(&firstState); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `
		SELECT state FROM relay_blob_uploads
		WHERE tenant_id=$1 AND upload_id=$2
	`, secondTenant, secondUpload).Scan(&secondState); err != nil {
		t.Fatal(err)
	}
	if firstState != "expired" || secondState != "active" {
		t.Fatalf(
			"per-tenant expiry crossed scope: first=%q second=%q",
			firstState,
			secondState,
		)
	}
	if _, err := store.ExpireBlobUploadsForTenant(
		ctx,
		secondTenant,
		2_000,
		100,
		relay.MaximumBlobUploadExpiryBatchSize+1,
	); err == nil {
		t.Fatal("per-tenant expiry accepted an unbounded batch")
	}
}

func TestPostgresBlobUploadExpiryTenantDiscoveryIsNotHiddenByOneTenantBatch(
	t *testing.T,
) {
	databaseURL := os.Getenv("FACETS_SERVER_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("FACETS_SERVER_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	lockDisposablePostgres(t, ctx, databaseURL)
	pool := openPool(t, ctx, databaseURL)
	defer pool.Close()
	if err := postgresstore.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `TRUNCATE relay_tenants CASCADE`); err != nil {
		t.Fatal(err)
	}
	store := postgresstore.NewRelayStore(pool, time.Second)
	olderTenant, _ := postgresExpiringBlobUploads(
		t,
		ctx,
		store,
		47,
		relay.MaximumBlobUploadExpiryBatchSize+1,
		1_000,
	)
	laterTenant, _ := postgresExpiringBlobUploads(
		t,
		ctx,
		store,
		71,
		1,
		1_500,
	)

	candidates, err := store.ExpiredBlobUploadTenantCandidates(ctx, 3_000)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 2 || candidates[0] != olderTenant ||
		candidates[1] != laterTenant {
		t.Fatalf(
			"tenant candidates hidden by older upload batch: got=%v older=%s later=%s",
			candidates,
			olderTenant,
			laterTenant,
		)
	}
}

func TestPostgresBlobUploadExpiryReturnsCommittedPrefixAfterLaterFailure(
	t *testing.T,
) {
	databaseURL := os.Getenv("FACETS_SERVER_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("FACETS_SERVER_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	lockDisposablePostgres(t, ctx, databaseURL)
	pool := openPool(t, ctx, databaseURL)
	defer pool.Close()
	if err := postgresstore.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `TRUNCATE relay_tenants CASCADE`); err != nil {
		t.Fatal(err)
	}
	store := postgresstore.NewRelayStore(pool, time.Second)
	_, uploadIDs := postgresExpiringBlobUploads(t, ctx, store, 83, 2, 1_000)
	firstUpload, rejectedUpload := uploadIDs[0], uploadIDs[1]
	if rejectedUpload.String() < firstUpload.String() {
		firstUpload, rejectedUpload = rejectedUpload, firstUpload
	}
	if _, err := pool.Exec(ctx, `
		CREATE TABLE relay_blob_expiry_failures_for_test (
			upload_id uuid PRIMARY KEY
		);
	`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = pool.Exec(context.Background(), `
			DROP TRIGGER IF EXISTS reject_blob_expiry_for_test
				ON relay_blob_uploads;
			DROP FUNCTION IF EXISTS reject_blob_expiry_for_test();
			DROP TABLE IF EXISTS relay_blob_expiry_failures_for_test;
		`)
	}()
	if _, err := pool.Exec(ctx, `
		INSERT INTO relay_blob_expiry_failures_for_test (upload_id) VALUES ($1)
	`, rejectedUpload); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		CREATE FUNCTION reject_blob_expiry_for_test()
		RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF OLD.state='active' AND NEW.state='expired' AND EXISTS (
				SELECT 1 FROM relay_blob_expiry_failures_for_test
				WHERE upload_id=NEW.upload_id
			) THEN
				RAISE EXCEPTION 'injected later blob expiry failure';
			END IF;
			RETURN NEW;
		END;
		$$;
		CREATE TRIGGER reject_blob_expiry_for_test
		BEFORE UPDATE ON relay_blob_uploads
		FOR EACH ROW EXECUTE FUNCTION reject_blob_expiry_for_test();
	`); err != nil {
		t.Fatal(err)
	}

	expired, err := store.ExpireBlobUploads(ctx, 2_000, 100)
	if err == nil || len(expired) != 1 || expired[0].UploadID != firstUpload {
		t.Fatalf(
			"committed expiry prefix was lost: expired=%+v rejected=%s err=%v",
			expired,
			rejectedUpload,
			err,
		)
	}
}

func postgresExpiringBlobUpload(
	t *testing.T,
	ctx context.Context,
	store *postgresstore.RelayStore,
	tokenSeed byte,
) (uuid.UUID, uuid.UUID) {
	t.Helper()
	tenantID, uploads := postgresExpiringBlobUploads(
		t,
		ctx,
		store,
		tokenSeed,
		1,
		1_000,
	)
	return tenantID, uploads[0]
}

func postgresExpiringBlobUploads(
	t *testing.T,
	ctx context.Context,
	store *postgresstore.RelayStore,
	tokenSeed byte,
	uploadCount int,
	createdAtMilliseconds int64,
) (uuid.UUID, []uuid.UUID) {
	t.Helper()
	if uploadCount <= 0 {
		t.Fatal("expiring blob upload count must be positive")
	}
	tenantID := uuid.New()
	domainID := uuid.New()
	memberID := uuid.New()
	subscriptionID := uuid.New()
	publisher := relay.Credential{
		TenantID: tenantID,
		DomainID: domainID,
		MemberID: memberID,
		Token:    postgresRelayToken(tokenSeed),
	}
	publisherDigest, err := relay.AuthorizationDigest(publisher)
	if err != nil {
		t.Fatal(err)
	}
	admin := relay.AdministrationCredential{
		TenantID: tenantID,
		DomainID: domainID,
		Token:    postgresRelayToken(tokenSeed + 1),
	}
	adminDigest, err := relay.AdministrationDigest(admin)
	if err != nil {
		t.Fatal(err)
	}
	domain := relay.DomainRegistration{
		Version:                 relay.SchemaVersion,
		TenantID:                tenantID,
		DomainID:                domainID,
		AdministrationDigest:    adminDigest,
		CreatedAtMilliseconds:   createdAtMilliseconds,
		MaximumMessageCount:     1,
		MaximumMessageByteCount: 1,
		MaximumBlobCount:        uploadCount + 1,
		MaximumBlobByteCount:    int64(uploadCount + 1),
	}
	member := relay.MemberRegistration{
		Version:               relay.SchemaVersion,
		TenantID:              tenantID,
		DomainID:              domainID,
		MemberID:              memberID,
		AuthorizationDigest:   publisherDigest,
		Capabilities:          []relay.Capability{relay.CapabilityPublishBlob},
		CreatedAtMilliseconds: createdAtMilliseconds,
	}
	_, acceptance, err := postgresProvisionTenant(
		ctx,
		store,
		domain,
		member,
		subscriptionID,
		tokenSeed+2,
	)
	if err != nil || acceptance != relay.AcceptanceAccepted {
		t.Fatalf("provision tenant acceptance=%q err=%v", acceptance, err)
	}
	uploadIDs := make([]uuid.UUID, 0, uploadCount)
	for index := range uploadCount {
		upload := relay.BlobUploadRequest{
			RetryID:  uuid.New(),
			UploadID: uuid.New(),
			RelayBlobID: relay.BlobID([]byte{
				tokenSeed,
				byte(index >> 8),
				byte(index),
			}),
			ByteCount:             1,
			CreatedAtMilliseconds: createdAtMilliseconds,
		}
		created, err := store.CreateBlobUpload(
			ctx,
			publisher,
			upload,
			createdAtMilliseconds,
		)
		if err != nil || created.Acceptance != relay.AcceptanceAccepted {
			t.Fatalf("create blob upload %d=%+v err=%v", index, created, err)
		}
		uploadIDs = append(uploadIDs, upload.UploadID)
	}
	return tenantID, uploadIDs
}
