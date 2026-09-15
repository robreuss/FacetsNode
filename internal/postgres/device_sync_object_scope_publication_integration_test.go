package postgres_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/robreuss/FacetsNode/internal/devicesync"
	postgresstore "github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

func TestPostgresSyncObjectScopePublication(t *testing.T) {
	databaseURL := os.Getenv("FACETS_SYNC_CONSENT_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("FACETS_SYNC_CONSENT_TEST_DATABASE_URL is not set")
	}
	u, err := url.Parse(databaseURL)
	if err != nil || u.Path != "/facets_sync_consent_tests" {
		t.Fatal("requires dedicated disposable Sync consent database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	lockDisposablePostgres(t, ctx, databaseURL)
	pool, other := openPool(t, ctx, databaseURL), openPool(t, ctx, databaseURL)
	defer pool.Close()
	defer other.Close()
	if err := postgresstore.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}

	t.Run("current-participant-exact-intent-and-no-effects", func(t *testing.T) {
		f := newSyncPublicationFixture(t, ctx, pool, other)
		for _, c := range []devicesync.SpaceSponsorCredential{f.a, f.b} {
			lease, err := f.publication.Begin(ctx, c, f.request, f.binding)
			if err != nil {
				t.Fatal(err)
			}
			if err := lease.Revalidate(); err != nil {
				t.Fatal(err)
			}
			if _, err := json.Marshal(lease); err == nil {
				t.Fatal("serialized source handle")
			}
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
			if lease.Revalidate() == nil {
				t.Fatal("closed handle reusable")
			}
		}
		for _, change := range []func(*devicesync.SpaceSponsorCredential){
			func(c *devicesync.SpaceSponsorCredential) { c.Administration.Token = postgresRelayToken(99) },
			func(c *devicesync.SpaceSponsorCredential) { c.Control.Token = postgresRelayToken(99) },
			func(c *devicesync.SpaceSponsorCredential) { c.Space.Token = postgresRelayToken(99) },
			func(c *devicesync.SpaceSponsorCredential) { c.Control = relay.Credential{} },
			func(c *devicesync.SpaceSponsorCredential) { c.Space = relay.Credential{} },
		} {
			c := f.a
			change(&c)
			f.reject(t, ctx, c, f.request)
		}
		// Recompute every commitment coherently: syntactic consistency must not
		// substitute for the actual durable consent of current participants.
		for _, change := range []func(*serviceauthority.CustodyLinkIntent){
			func(i *serviceauthority.CustodyLinkIntent) { i.BackupAccountID = uuid.New() },
			func(i *serviceauthority.CustodyLinkIntent) { i.BackupTargetID = uuid.New() },
			func(i *serviceauthority.CustodyLinkIntent) { i.SyncSpaceID = uuid.New() },
			func(i *serviceauthority.CustodyLinkIntent) { i.SyncDomainID = uuid.New() },
			func(i *serviceauthority.CustodyLinkIntent) { i.ContentEpoch-- },
			func(i *serviceauthority.CustodyLinkIntent) { i.ContentScopeID = uuid.New() },
			func(i *serviceauthority.CustodyLinkIntent) { i.SyncBindingID = uuid.New() },
			func(i *serviceauthority.CustodyLinkIntent) { i.PoolID = uuid.New() },
			func(i *serviceauthority.CustodyLinkIntent) { i.LedgerID = uuid.New() },
			func(i *serviceauthority.CustodyLinkIntent) { i.LinkID = uuid.New() },
		} {
			i := f.request.Intent
			change(&i)
			f.reject(t, ctx, f.a, syncPublicationRequest(t, i))
		}
		f.assertCounts(t, ctx, 1, 1)
		var messages, uploads int
		if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM relay_messages),(SELECT count(*) FROM relay_blob_uploads)`).Scan(&messages, &uploads); err != nil {
			t.Fatal(err)
		}
		if messages != 0 || uploads != 0 {
			t.Fatal("source guard created data-plane effects")
		}
	})

	t.Run("withdrawal-blocks-behind-held-source-transaction", func(t *testing.T) {
		f := newSyncPublicationFixture(t, ctx, pool, other)
		lease, err := f.publication.Begin(ctx, f.a, f.request, f.binding)
		if err != nil {
			t.Fatal(err)
		}
		defer lease.Close()
		done := make(chan error, 1)
		go func() { done <- f.withdraw(ctx) }()
		waitForSyncConsentLock(t, ctx, pool)
		select {
		case err := <-done:
			t.Fatal("withdrawal escaped held lock", err)
		default:
		}
		if err := lease.Revalidate(); err != nil {
			t.Fatal(err)
		}
		if err := lease.Close(); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		f.reject(t, ctx, f.a, f.request)
		f.reject(t, ctx, f.b, f.request)
		if result, err := f.apply(ctx, f.a, f.m); err != nil || !result.Withdrawn {
			t.Fatal("old acceptance revived consent", result, err)
		}
		f.assertCounts(t, ctx, 1, 2)
	})

	t.Run("departure-and-space-revocation-do-not-confer-authority", func(t *testing.T) {
		f := newSyncPublicationFixture(t, ctx, pool, other)
		if _, err := f.other.RevokeDevice(ctx, f.authority.TenantCredential, devicesync.DeviceRevocation{Version: devicesync.SchemaVersion, RetryID: uuid.New(), PrincipalID: f.m.Consent.PrincipalID, DeviceID: f.a.Control.MemberID}, 6000); err != nil {
			t.Fatal(err)
		}
		// Revocation is terminal even before its timestamp after clock rollback.
		f.reject(t, ctx, f.a, f.request)
		lease, err := f.publication.Begin(ctx, f.b, f.request, f.binding)
		if err != nil {
			t.Fatal("origin unnecessarily required", err)
		}
		defer lease.Close()
		done := make(chan error, 1)
		go func() { _, err := f.other.RevokeMember(ctx, f.b.Administration, f.b.Space.MemberID, 6001); done <- err }()
		waitForSyncConsentLock(t, ctx, pool)
		if err := lease.Close(); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		f.reject(t, ctx, f.b, f.request)
	})

	t.Run("withdrawal-wins-preflight-reacquisition-gap", func(t *testing.T) {
		f := newSyncPublicationFixture(t, ctx, pool, other)
		arrived, proceed := make(chan struct{}), make(chan struct{})
		var once sync.Once
		var acquisitions atomic.Int64
		config := pool.Config()
		config.BeforeAcquire = func(acquireCtx context.Context, _ *pgx.Conn) bool {
			if acquisitions.Add(1) == 2 {
				close(arrived)
				select {
				case <-proceed:
				case <-acquireCtx.Done():
					return false
				}
			}
			return true
		}
		gapPool, err := pgxpool.NewWithConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer gapPool.Close()
		defer once.Do(func() { close(proceed) })
		store, err := postgresstore.NewDeviceSyncAuthorityBoundRelayStore(gapPool, f.binding.DeploymentID)
		if err != nil {
			t.Fatal(err)
		}
		f.publication.Store = store
		done := make(chan error, 1)
		go func() {
			l, e := f.publication.Begin(ctx, f.a, f.request, f.binding)
			if l != nil {
				_ = l.Close()
			}
			done <- e
		}()
		select {
		case <-arrived:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		err = f.withdraw(ctx)
		once.Do(func() { close(proceed) })
		if err != nil {
			t.Fatal(err)
		}
		if err := <-done; !errors.Is(err, devicesync.ErrObjectScopeConflict) {
			t.Fatal("stale preflight survived withdrawal", err)
		}
	})

	t.Run("cancellation-drains-database-and-registry", func(t *testing.T) {
		f := newSyncPublicationFixture(t, ctx, pool, other)
		requestCtx, stop := context.WithCancel(ctx)
		lease, err := f.publication.Begin(requestCtx, f.a, f.request, f.binding)
		if err != nil {
			stop()
			t.Fatal(err)
		}
		stop()
		wait, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		drain, err := f.publication.Registry.AcquireMigrationDrain(wait, f.binding.Scope)
		if err != nil {
			t.Fatal("scope lease leaked", err)
		}
		drain.Release()
		if lease.Revalidate() == nil {
			t.Fatal("cancelled handle usable")
		}
		if err := f.withdraw(wait); err != nil {
			t.Fatal("row locks leaked", err)
		}
	})

	t.Run("expiry-after-real-lock-wait-and-terminal-raw-handle", func(t *testing.T) {
		f := newSyncPublicationFixture(t, ctx, pool, other)
		if _, err := pool.Exec(ctx, `UPDATE relay_members SET expires_at_milliseconds=5100 WHERE tenant_id=$1 AND domain_id=$2 AND member_id=$3`, f.m.Consent.PrincipalID, f.a.Space.DomainID, f.a.Space.MemberID); err != nil {
			t.Fatal(err)
		}
		raw, err := f.store.BeginSyncObjectScopePublication(ctx, f.a, f.request, f.authorization(t))
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close(ctx)
		f.now.Store(5100)
		if raw.Revalidate(ctx, f.authorization(t)) == nil {
			t.Fatal("expired raw handle admitted")
		}
		f.now.Store(5000)
		if raw.Revalidate(ctx, f.authorization(t)) == nil {
			t.Fatal("raw handle revived")
		}
		blocker, err := other.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer blocker.Rollback(ctx)
		if _, err := blocker.Exec(ctx, `SELECT principal_id FROM device_sync_principals WHERE principal_id=$1 FOR UPDATE`, f.m.Consent.PrincipalID); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			l, e := f.publication.Begin(ctx, f.a, f.request, f.binding)
			if l != nil {
				_ = l.Close()
			}
			done <- e
		}()
		waitForSyncConsentLock(t, ctx, pool)
		f.now.Store(5100)
		if err := blocker.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err == nil {
			t.Fatal("reused authorization from before lock wait")
		}
	})

	t.Run("lost-backend-retains-admission-clock-and-allows-current-retry", func(t *testing.T) {
		f := newSyncPublicationFixture(t, ctx, pool, other)
		config := pool.Config()
		name := "sync-publication-crash-" + uuid.NewString()
		config.ConnConfig.RuntimeParams["application_name"] = name
		crashPool, err := pgxpool.NewWithConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer crashPool.Close()
		store, err := postgresstore.NewDeviceSyncAuthorityBoundRelayStore(crashPool, f.binding.DeploymentID)
		if err != nil {
			t.Fatal(err)
		}
		f.publication.Store = store
		f.now.Store(5500)
		lease, err := f.publication.Begin(ctx, f.a, f.request, f.binding)
		if err != nil {
			t.Fatal(err)
		}
		defer lease.Close()
		// Resolve the exact fixture connection before terminating it; a volatile
		// function in a WHERE clause has no guaranteed predicate evaluation order.
		var pid, count int
		if err := other.QueryRow(ctx, `SELECT coalesce(min(pid),0),count(*) FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1 AND state='idle in transaction'`, name).Scan(&pid, &count); err != nil || count != 1 {
			t.Fatal("expected exactly one held backend", count, err)
		}
		var killed bool
		if err := other.QueryRow(ctx, `SELECT pg_terminate_backend($1)`, pid).Scan(&killed); err != nil || !killed {
			t.Fatal("fixture backend not terminated", err)
		}
		if lease.Revalidate() == nil {
			t.Fatal("lost backend usable")
		}
		f.publication.Store = f.other
		f.now.Store(5499)
		f.reject(t, ctx, f.a, f.request)
		f.now.Store(5500)
		retry, err := f.publication.Begin(ctx, f.a, f.request, f.binding)
		if err != nil {
			t.Fatal("current retry after lost source handle", err)
		}
		if err := retry.Close(); err != nil {
			t.Fatal(err)
		}
		f.assertCounts(t, ctx, 1, 1)
	})

	t.Run("stored-consent-corruption-and-durable-readonly-fence", func(t *testing.T) {
		f := newSyncPublicationFixture(t, ctx, pool, other)
		if _, err := pool.Exec(ctx, `UPDATE device_sync_object_scope_consents SET canonical_consent=canonical_consent || decode('20','hex') WHERE principal_id=$1`, f.m.Consent.PrincipalID); err != nil {
			t.Fatal(err)
		}
		f.reject(t, ctx, f.a, f.request)
		f = newSyncPublicationFixture(t, ctx, pool, other)
		if _, err := pool.Exec(ctx, `UPDATE device_sync_scope_enforcement SET state='standby' WHERE principal_id=$1`, f.m.Consent.PrincipalID); err != nil {
			t.Fatal(err)
		}
		f.reject(t, ctx, f.a, f.request)
	})
}

type syncPublicationFixture struct {
	*syncConsentFixture
	request     devicesync.ObjectScopePublicationRequest
	publication *devicesync.ObjectScopePublicationCustody
}

func newSyncPublicationFixture(t *testing.T, ctx context.Context, pool, other *pgxpool.Pool) *syncPublicationFixture {
	t.Helper()
	f := newSyncConsentFixture(t, ctx, pool, other)
	c := f.m.Consent
	i := serviceauthority.CustodyLinkIntent{Version: 1, BackupAccountID: uuid.New(), BackupBindingID: uuid.New(), BackupSetID: uuid.New(), BackupTargetID: uuid.New(),
		ContentEpoch: c.ContentEpoch, ContentScopeID: c.ContentScopeID, LedgerID: c.LedgerID, LinkID: c.LinkID, PoolID: c.PoolID,
		SyncBindingID: c.BindingID, SyncDomainID: c.DomainID, SyncPrincipalID: c.PrincipalID, SyncSpaceID: c.SpaceID}
	r := syncPublicationRequest(t, i)
	f.m.Consent = r.Consent
	if _, err := f.apply(ctx, f.a, f.m); err != nil {
		t.Fatal(err)
	}
	return &syncPublicationFixture{syncConsentFixture: f, request: r, publication: &devicesync.ObjectScopePublicationCustody{Store: f.store, Registry: f.custody.Registry, Now: f.custody.Now}}
}
func syncPublicationRequest(t *testing.T, i serviceauthority.CustodyLinkIntent) devicesync.ObjectScopePublicationRequest {
	t.Helper()
	c, err := devicesync.NewObjectScopeConsent(i)
	if err != nil {
		t.Fatal(err)
	}
	r := devicesync.ObjectScopePublicationRequest{Intent: i, Consent: c, Request: serviceauthority.CustodyPeerRequest{Version: 1,
		OperationID: uuid.New(), Operation: serviceauthority.CustodyReserveObject, BodyByteCount: 1, BodySHA256: strings.Repeat("c", 64),
		Challenge: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), Target: serviceauthority.CustodyPeerTarget{
			BindingID: c.BindingID, ContentEpoch: c.ContentEpoch, ContentScopeID: c.ContentScopeID, LedgerID: c.LedgerID, PoolID: c.PoolID}}}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	return r
}
func (f *syncPublicationFixture) reject(t *testing.T, ctx context.Context, c devicesync.SpaceSponsorCredential, r devicesync.ObjectScopePublicationRequest) {
	t.Helper()
	l, err := f.publication.Begin(ctx, c, r, f.binding)
	if l != nil {
		_ = l.Close()
	}
	if err == nil || l != nil {
		t.Fatal("invalid publication source admitted", err)
	}
}
func (f *syncPublicationFixture) withdraw(ctx context.Context) error {
	m := f.m
	m.ParticipantDeviceID, m.RetryID, m.Withdraw = f.b.Control.MemberID, uuid.New(), true
	c := *f.custody
	c.Store = f.other
	_, err := c.Apply(ctx, f.b, m, f.binding)
	return err
}
