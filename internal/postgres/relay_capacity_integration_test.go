package postgres_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/devicesync"
	postgresstore "github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/storagecapacity"
)

type poolTestCapacity struct {
	mu          sync.Mutex
	free        int64
	unavailable bool
}

func TestPostgresSelfHostedCapacityIgnoresSpaceDefaultsButRetainsHostedLimits(t *testing.T) {
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
	store := postgresstore.NewRelayStore(pool)
	tenantCredential := relay.TenantCredential{TenantID: uuid.New(), Token: postgresRelayToken(81)}
	tenantDigest, err := relay.TenantAuthorizationDigest(tenantCredential)
	if err != nil {
		t.Fatal(err)
	}
	member := relay.Credential{TenantID: tenantCredential.TenantID, DomainID: uuid.New(), MemberID: uuid.New(), Token: postgresRelayToken(82)}
	memberDigest, err := relay.AuthorizationDigest(member)
	if err != nil {
		t.Fatal(err)
	}
	adminDigest, err := relay.AdministrationDigest(relay.AdministrationCredential{TenantID: member.TenantID, DomainID: member.DomainID, Token: postgresRelayToken(83)})
	if err != nil {
		t.Fatal(err)
	}
	domain := relay.DomainRegistration{Version: relay.SchemaVersion, TenantID: member.TenantID, DomainID: member.DomainID,
		AdministrationDigest: adminDigest, CreatedAtMilliseconds: 1_000, MaximumMessageCount: 1, MaximumMessageByteCount: 1,
		MaximumBlobCount: 1, MaximumBlobByteCount: 1 << 30}
	registration := relay.MemberRegistration{Version: relay.SchemaVersion, TenantID: member.TenantID, DomainID: member.DomainID,
		MemberID: member.MemberID, AuthorizationDigest: memberDigest, CreatedAtMilliseconds: 1_000,
		Capabilities: []relay.Capability{relay.CapabilityPublishBlob}}
	provisioning := postgresDomainProvisioning(domain, registration, uuid.New())
	issued := devicesync.DefaultServiceEntitlement().Apply(devicesync.PrincipalProvisioning{
		Tenant: relay.TenantRegistration{Version: relay.SchemaVersion, TenantID: member.TenantID, RetryID: uuid.New(),
			AuthorizationDigest: tenantDigest, CreatedAtMilliseconds: 1_000}, ControlDomain: provisioning})
	if _, err := store.ProvisionTenant(ctx, issued.Tenant, issued.ControlDomain); !errors.Is(err, storagecapacity.ErrUnavailable) {
		t.Fatalf("shared capacity silently disabled=%v", err)
	}
	if err := store.SetSharedCapacityProvider(&poolTestCapacity{free: 8 << 30}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ProvisionTenant(ctx, issued.Tenant, issued.ControlDomain); err != nil {
		t.Fatal(err)
	}
	// The server must normalize a subsequent client's requested Space default,
	// including exact retries. No quota row is manually changed for this proof.
	nextMember := member
	nextMember.DomainID = uuid.New()
	nextMember.MemberID = uuid.New()
	nextDomain := domain
	nextDomain.DomainID = nextMember.DomainID
	nextDomain.AdministrationDigest, err = relay.AdministrationDigest(relay.AdministrationCredential{TenantID: nextMember.TenantID, DomainID: nextMember.DomainID, Token: postgresRelayToken(84)})
	if err != nil {
		t.Fatal(err)
	}
	nextRegistration := registration
	nextRegistration.DomainID, nextRegistration.MemberID = nextMember.DomainID, nextMember.MemberID
	nextRegistration.AuthorizationDigest, err = relay.AuthorizationDigest(nextMember)
	if err != nil {
		t.Fatal(err)
	}
	next := postgresDomainProvisioning(nextDomain, nextRegistration, uuid.New())
	for _, expected := range []relay.Acceptance{relay.AcceptanceAccepted, relay.AcceptanceDuplicate} {
		result, err := store.ProvisionDomain(ctx, tenantCredential, next, 1_000)
		if err != nil || result.Acceptance != expected {
			t.Fatalf("domain retry=%+v %v", result, err)
		}
	}
	var storedCount int
	var storedBytes int64
	if err := pool.QueryRow(ctx, `SELECT maximum_blob_count,maximum_blob_byte_count FROM relay_domains WHERE tenant_id=$1 AND domain_id=$2`, nextMember.TenantID, nextMember.DomainID).Scan(&storedCount, &storedBytes); err != nil {
		t.Fatal(err)
	}
	if storedCount != 0 || storedBytes != 0 {
		t.Fatalf("client default became allocation: %d %d", storedCount, storedBytes)
	}
	directID := relay.BlobID([]byte("unreserved"))
	if err := store.PrepareBlobPublish(ctx, nextMember, directID, 10, 1_000); !relay.ErrorHasCode(err, relay.CodeInvalidBlobUpload) {
		t.Fatalf("unreserved direct preparation accepted: %v", err)
	}
	if _, err := store.CommitBlobPublish(ctx, nextMember, directID, 10, 1_000); !relay.ErrorHasCode(err, relay.CodeInvalidBlobUpload) {
		t.Fatalf("unreserved direct commit accepted: %v", err)
	}
	for index := range 5 {
		request := relay.BlobUploadRequest{RetryID: uuid.New(), UploadID: uuid.New(), RelayBlobID: relay.BlobID([]byte{byte(index)}),
			ByteCount: relay.MaximumBlobByteCount, CreatedAtMilliseconds: 1_000}
		if _, err := store.CreateBlobUpload(ctx, nextMember, request, 1_000); err != nil {
			t.Fatalf("shared storage blocked upload %d: %v", index, err)
		}
	}
	// Five bounded requests reserve 1.25 GiB of source data: the old 1-GiB
	// per-Space default and one-blob client default cannot reject this admission.
	if _, err := store.CreateBlobUpload(ctx, nextMember, relay.BlobUploadRequest{RetryID: uuid.New(), UploadID: uuid.New(),
		RelayBlobID: relay.BlobID([]byte("oversized")), ByteCount: relay.MaximumBlobByteCount + 1, CreatedAtMilliseconds: 1_000}, 1_000); err == nil {
		t.Fatal("per-request bound removed")
	}
	bounded := capacityPublisher(t, ctx, store, 91)
	boundedTenant := relay.TenantCredential{TenantID: bounded.TenantID, Token: postgresRelayToken(93)}
	invalid := next
	invalid.Registration.TenantID = bounded.TenantID
	invalid.Registration = invalid.Registration.WithSharedCapacity()
	invalid.InitialMember.TenantID = bounded.TenantID
	invalid.Subscription.TenantID = bounded.TenantID
	// Exercise the authorized production store, not a policy-only assertion:
	// a bounded tenant cannot remove its domain limits by requesting zeros.
	if _, err := store.ProvisionDomain(ctx, boundedTenant, invalid, 1_000); !relay.ErrorHasCode(err, relay.CodeInvalidDomain) {
		t.Fatalf("bounded tenant bypassed domain quota: %v", err)
	}
}

func (p *poolTestCapacity) Snapshot(context.Context) (storagecapacity.Snapshot, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.unavailable {
		return storagecapacity.Snapshot{}, storagecapacity.ErrUnavailable
	}
	return storagecapacity.Snapshot{TotalBytes: 10 << 30, AvailableBytes: p.free}, nil
}

func TestPostgresCapacityReservationReleasedByAuthorizedRevocation(t *testing.T) {
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
	store := postgresstore.NewRelayStore(pool)
	first, second := capacityPublisher(t, ctx, store, 101), capacityPublisher(t, ctx, store, 111)
	const blobBytes int64 = 1 << 20
	reservation, err := storagecapacity.UploadReservation(blobBytes, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	provider := &poolTestCapacity{free: storagecapacity.MinimumOperatingReserve + reservation}
	if err := store.SetSharedCapacityProvider(provider); err != nil {
		t.Fatal(err)
	}
	request := relay.BlobUploadRequest{RetryID: uuid.New(), UploadID: uuid.New(), RelayBlobID: relay.BlobID([]byte("cancel")), ByteCount: blobBytes, CreatedAtMilliseconds: 1_000}
	if _, err := store.CreateBlobUpload(ctx, first, request, 1_000); err != nil {
		t.Fatal(err)
	}
	other := request
	other.RetryID, other.UploadID = uuid.New(), uuid.New()
	if _, err := store.CreateBlobUpload(ctx, second, other, 1_000); !errors.Is(err, storagecapacity.ErrPressure) {
		t.Fatalf("over-allocation: %v", err)
	}
	var subscriptionID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT subscription_id FROM relay_members WHERE tenant_id=$1 AND domain_id=$2 AND member_id=$3`, first.TenantID, first.DomainID, first.MemberID).Scan(&subscriptionID); err != nil {
		t.Fatal(err)
	}
	admin := relay.AdministrationCredential{TenantID: first.TenantID, DomainID: first.DomainID, Token: postgresRelayToken(102)}
	revoke := relay.SubscriptionStatusChangeRequest{RetryID: uuid.New(), Status: relay.SubscriptionRevoked, ChangedAtMilliseconds: 1_100}
	wrong := admin
	wrong.Token = postgresRelayToken(112)
	if _, err := store.ChangeSubscriptionStatus(ctx, wrong, subscriptionID, revoke); !relay.ErrorHasCode(err, relay.CodeUnauthorized) {
		t.Fatalf("unauthorized cancellation: %v", err)
	}
	provider.set(0, true)
	for _, acceptance := range []relay.Acceptance{relay.AcceptanceAccepted, relay.AcceptanceDuplicate} {
		result, err := store.ChangeSubscriptionStatus(ctx, admin, subscriptionID, revoke)
		if err != nil || result.Acceptance != acceptance {
			t.Fatalf("revocation retry under pressure: %+v %v", result, err)
		}
	}
	var queued int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM relay_blob_upload_deletions WHERE tenant_id=$1 AND upload_id=$2`, first.TenantID, request.UploadID).Scan(&queued); err != nil || queued != 1 {
		t.Fatalf("cleanup queue=%d %v", queued, err)
	}
	provider.set(storagecapacity.MinimumOperatingReserve+reservation, false)
	reopened := postgresstore.NewRelayStore(pool)
	if err := reopened.SetSharedCapacityProvider(provider); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.CreateBlobUpload(ctx, second, other, 1_100); err != nil {
		t.Fatalf("revocation did not release durable reservation: %v", err)
	}
}
func (p *poolTestCapacity) set(free int64, unavailable bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.free = free
	p.unavailable = unavailable
}

func TestPostgresCapacityReservationsSpanAccountsAndInstancesAndSurviveReopen(t *testing.T) {
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
	first := postgresstore.NewRelayStore(pool, time.Second)
	second := postgresstore.NewRelayStore(pool, time.Second)
	credentials := []relay.Credential{capacityPublisher(t, ctx, first, 21), capacityPublisher(t, ctx, second, 31)}
	const blobBytes int64 = 1 << 20
	reservation, err := storagecapacity.UploadReservation(blobBytes, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	free := storagecapacity.MinimumOperatingReserve + 2*reservation
	provider := &poolTestCapacity{free: free}
	for _, store := range []*postgresstore.RelayStore{first, second} {
		if err := store.SetSharedCapacityProvider(provider); err != nil {
			t.Fatal(err)
		}
	}
	type attempt struct {
		credential relay.Credential
		request    relay.BlobUploadRequest
		err        error
	}
	results := make(chan attempt, 20)
	var workers sync.WaitGroup
	for index := range 20 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			credential := credentials[index%2]
			store := []*postgresstore.RelayStore{first, second}[index%2]
			request := relay.BlobUploadRequest{RetryID: uuid.New(), UploadID: uuid.New(),
				RelayBlobID: relay.BlobID([]byte{byte(index)}), ByteCount: blobBytes, CreatedAtMilliseconds: 1_000}
			_, err := store.CreateBlobUpload(ctx, credential, request, 1_000)
			results <- attempt{credential, request, err}
		}()
	}
	workers.Wait()
	close(results)
	var accepted []attempt
	for result := range results {
		if result.err == nil {
			accepted = append(accepted, result)
		} else if !errors.Is(result.err, storagecapacity.ErrPressure) {
			t.Fatal(result.err)
		}
	}
	if len(accepted) != 2 {
		t.Fatalf("oversubscribed shared pool: accepted=%d want=2", len(accepted))
	}
	// Reopening a store does not erase or double-charge reservations.
	reopened := postgresstore.NewRelayStore(pool, time.Second)
	if err := reopened.SetSharedCapacityProvider(provider); err != nil {
		t.Fatal(err)
	}
	extra := relay.BlobUploadRequest{RetryID: uuid.New(), UploadID: uuid.New(), RelayBlobID: relay.BlobID([]byte("extra")), ByteCount: blobBytes, CreatedAtMilliseconds: 1_000}
	if _, err := reopened.CreateBlobUpload(ctx, credentials[0], extra, 1_000); !errors.Is(err, storagecapacity.ErrPressure) {
		t.Fatalf("reopened reservations=%v", err)
	}
	provider.set(free, true)
	if _, err := reopened.CreateBlobUpload(ctx, credentials[0], extra, 1_000); !errors.Is(err, storagecapacity.ErrUnavailable) {
		t.Fatalf("unknown capacity=%v", err)
	}
	for _, item := range accepted {
		duplicate, err := reopened.CreateBlobUpload(ctx, item.credential, item.request, 1_000)
		if err != nil || duplicate.Acceptance != relay.AcceptanceDuplicate {
			t.Fatalf("exact retry under pressure=%+v %v", duplicate, err)
		}
		if _, err := reopened.GetBlobUpload(ctx, item.credential, item.request.UploadID, 1_000); err != nil {
			t.Fatalf("read unavailable=%v", err)
		}
	}
	// A failed staged write rolls back the new chunk fact/reservation. The
	// retry uses exactly the existing upload identifiers, not a replacement.
	provider.set(free+storagecapacity.ChunkMetadataAllowance, false)
	item := accepted[0]
	digest := sha256.Sum256([]byte("opaque test chunk"))
	chunk := relay.BlobUploadChunkRequest{UploadID: item.request.UploadID, Offset: 0, ByteCount: blobBytes, ChunkSHA256: hex.EncodeToString(digest[:])}
	fault := errors.New("interrupted write")
	if _, err := reopened.AppendBlobUploadChunk(ctx, item.credential, chunk, 1_000, func(relay.BlobUploadStatus) error { return fault }); !errors.Is(err, fault) {
		t.Fatalf("failed write=%v", err)
	}
	status, err := reopened.GetBlobUpload(ctx, item.credential, item.request.UploadID, 1_000)
	if err != nil || status.CommittedOffset != 0 {
		t.Fatalf("failed write committed=%+v %v", status, err)
	}
	if _, err := reopened.AppendBlobUploadChunk(ctx, item.credential, chunk, 1_000, func(relay.BlobUploadStatus) error { return nil }); err != nil {
		t.Fatal(err)
	}
	provider.set(free+storagecapacity.ChunkMetadataAllowance-blobBytes, false)
	finalize := relay.BlobUploadFinalizationRequest{RetryID: uuid.New(), UploadID: item.request.UploadID,
		RelayBlobID: item.request.RelayBlobID, ByteCount: blobBytes, FinalizedAtMilliseconds: 1_000}
	if _, err := reopened.FinalizeBlobUpload(ctx, item.credential, finalize, 1_000, func(relay.BlobUploadStatus) error { return nil }); err != nil {
		t.Fatal(err)
	}
	var active int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM relay_blob_uploads WHERE state='active'`).Scan(&active); err != nil || active != 1 {
		t.Fatalf("finalization reservation release=%d %v", active, err)
	}
	// Cleanup remains available with no capacity information. Both accounts
	// can own either race winner, so expire each through the supported store.
	provider.set(0, true)
	for _, credential := range credentials {
		if _, err := reopened.ExpireBlobUploadsForTenant(ctx, credential.TenantID, 2_001, 100, 256); err != nil {
			t.Fatal(err)
		}
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM relay_blob_uploads WHERE state='active'`).Scan(&active); err != nil || active != 0 {
		t.Fatalf("expiry reservation release=%d %v", active, err)
	}
	provider.set(free, false)
	if _, err := reopened.CreateBlobUpload(ctx, credentials[0], extra, 2_001); err != nil {
		t.Fatalf("capacity recovery=%v", err)
	}
}

func capacityPublisher(t *testing.T, ctx context.Context, store *postgresstore.RelayStore, seed byte) relay.Credential {
	t.Helper()
	credential := relay.Credential{TenantID: uuid.New(), DomainID: uuid.New(), MemberID: uuid.New(), Token: postgresRelayToken(seed)}
	digest, err := relay.AuthorizationDigest(credential)
	if err != nil {
		t.Fatal(err)
	}
	adminDigest, err := relay.AdministrationDigest(relay.AdministrationCredential{TenantID: credential.TenantID, DomainID: credential.DomainID, Token: postgresRelayToken(seed + 1)})
	if err != nil {
		t.Fatal(err)
	}
	domain := relay.DomainRegistration{Version: relay.SchemaVersion, TenantID: credential.TenantID, DomainID: credential.DomainID,
		AdministrationDigest: adminDigest, CreatedAtMilliseconds: 1_000,
		MaximumMessageCount: 100, MaximumMessageByteCount: 1 << 30, MaximumBlobCount: 100, MaximumBlobByteCount: 1 << 30}
	member := relay.MemberRegistration{Version: relay.SchemaVersion, TenantID: credential.TenantID, DomainID: credential.DomainID,
		MemberID: credential.MemberID, AuthorizationDigest: digest, CreatedAtMilliseconds: 1_000,
		Capabilities: []relay.Capability{relay.CapabilityPublishBlob}}
	if _, _, err := postgresProvisionTenant(ctx, store, domain, member, uuid.New(), seed+2); err != nil {
		t.Fatal(err)
	}
	return credential
}
