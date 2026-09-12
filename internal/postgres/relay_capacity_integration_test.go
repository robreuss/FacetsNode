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
	postgresstore "github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/storagecapacity"
)

type poolTestCapacity struct {
	mu          sync.Mutex
	free        int64
	unavailable bool
}

func (p *poolTestCapacity) Snapshot(context.Context) (storagecapacity.Snapshot, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.unavailable {
		return storagecapacity.Snapshot{}, storagecapacity.ErrUnavailable
	}
	return storagecapacity.Snapshot{TotalBytes: 10 << 30, AvailableBytes: p.free}, nil
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
