package postgres_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/robreuss/FacetsNode/internal/devicesync"
	postgresstore "github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

func TestPostgresSyncObjectScopeConsent(t *testing.T) {
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

	t.Run("current-participant-and-exact-scopes", func(t *testing.T) {
		f := newSyncConsentFixture(t, ctx, pool, other)
		for _, change := range []func(*devicesync.SpaceSponsorCredential){
			func(c *devicesync.SpaceSponsorCredential) { c.Administration.Token = postgresRelayToken(99) },
			func(c *devicesync.SpaceSponsorCredential) { c.Control.Token = postgresRelayToken(99) },
			func(c *devicesync.SpaceSponsorCredential) { c.Space.Token = postgresRelayToken(99) },
			func(c *devicesync.SpaceSponsorCredential) { c.Control = relay.Credential{} },
			func(c *devicesync.SpaceSponsorCredential) { c.Space = relay.Credential{} },
			func(c *devicesync.SpaceSponsorCredential) { c.Control.DomainID = c.Space.DomainID },
			func(c *devicesync.SpaceSponsorCredential) { c.Control.MemberID = uuid.New() },
		} {
			c := f.a
			change(&c)
			if _, err := f.apply(ctx, c, f.m); err == nil {
				t.Fatal("invalid credential accepted")
			}
		}
		for _, change := range []func(*devicesync.ObjectScopeConsentMutation){
			func(m *devicesync.ObjectScopeConsentMutation) { m.Consent.PrincipalID = uuid.New() },
			func(m *devicesync.ObjectScopeConsentMutation) { m.Consent.SpaceID = uuid.New() },
			func(m *devicesync.ObjectScopeConsentMutation) { m.Consent.DomainID = uuid.New() },
			func(m *devicesync.ObjectScopeConsentMutation) { m.ParticipantDeviceID = uuid.New() },
		} {
			m := f.m
			change(&m)
			if _, err := f.apply(ctx, f.a, m); err == nil {
				t.Fatal("foreign scope accepted")
			}
		}
		binding := f.binding
		binding.AuthorityRevision++
		if _, err := f.custody.Apply(ctx, f.a, f.m, binding); err == nil {
			t.Fatal("stale request admitted")
		}
		f.assertCounts(t, ctx, 0, 0)
		result, err := f.apply(ctx, f.a, f.m)
		if err != nil || result.Withdrawn {
			t.Fatal(result, err)
		}
		ref, _ := f.m.Consent.ReferenceDigest()
		if result.ReferenceDigest != ref {
			t.Fatal("wrong reference")
		}
		f.assertCounts(t, ctx, 1, 1)
		unbound := postgresstore.NewRelayStore(pool)
		if _, err := unbound.BeginObjectScopeConsentMutation(ctx, f.a, f.m, f.authorization(t)); err == nil {
			t.Fatal("unconfigured deployment admitted")
		}
	})

	t.Run("independent-participant-withdrawal-and-terminal-retry", func(t *testing.T) {
		f := newSyncConsentFixture(t, ctx, pool, other)
		m := f.m
		m.ParticipantDeviceID = f.b.Control.MemberID
		accepted, err := f.apply(ctx, f.b, m)
		if err != nil {
			t.Fatal(err)
		}
		f.now.Add(1)
		withdraw := f.m
		withdraw.Withdraw = true
		withdraw.RetryID = uuid.New()
		withdrawn, err := f.apply(ctx, f.a, withdraw)
		if err != nil || !withdrawn.Withdrawn {
			t.Fatal(withdrawn, err)
		}
		// Restarted store returns CURRENT withdrawn status, not an old active receipt.
		f.custody.Store = f.other
		retry, err := f.apply(ctx, f.b, m)
		if err != nil || !retry.Withdrawn || retry.AcceptedAtMilliseconds != accepted.AcceptedAtMilliseconds {
			t.Fatal(retry, err)
		}
		if _, err := f.apply(ctx, f.a, withdraw); err != nil {
			t.Fatal(err)
		}
		f.assertCounts(t, ctx, 1, 2)
		for _, change := range []func(*devicesync.ObjectScopeConsentMutation){
			func(m *devicesync.ObjectScopeConsentMutation) { m.RetryID = uuid.New() },
			func(m *devicesync.ObjectScopeConsentMutation) { m.Consent.ContentEpoch = 1 },
			func(m *devicesync.ObjectScopeConsentMutation) { m.Consent.ContentScopeID = uuid.New() },
			func(m *devicesync.ObjectScopeConsentMutation) { m.Consent.PoolID = uuid.New() },
			func(m *devicesync.ObjectScopeConsentMutation) { m.Consent.LedgerID = uuid.New() },
			func(m *devicesync.ObjectScopeConsentMutation) { m.Consent.LinkIntentDigest = strings.Repeat("b", 64) },
		} {
			copy := m
			change(&copy)
			if _, err := f.apply(ctx, f.b, copy); err == nil {
				t.Fatal("reinterpreted old operation accepted")
			}
		}
		// Fresh retry IDs do not permit reuse of any binding/link/intent identity.
		for _, keep := range []string{"binding", "link", "intent"} {
			copy := f.newMutation()
			copy.ParticipantDeviceID = f.b.Control.MemberID
			switch keep {
			case "binding":
				copy.Consent.BindingID = m.Consent.BindingID
			case "link":
				copy.Consent.LinkID = m.Consent.LinkID
			case "intent":
				copy.Consent.LinkIntentDigest = m.Consent.LinkIntentDigest
			}
			if _, err := f.apply(ctx, f.b, copy); !errors.Is(err, devicesync.ErrObjectScopeConflict) {
				t.Fatal(keep, err)
			}
		}
		// No data-plane change: both actual participant credentials still work.
		fresh := f.newMutation()
		fresh.ParticipantDeviceID = f.b.Control.MemberID
		if _, err := f.apply(ctx, f.b, fresh); err != nil {
			t.Fatal("withdrawal revoked participant", err)
		}
	})

	t.Run("departed-origin-is-not-continuing-authority", func(t *testing.T) {
		f := newSyncConsentFixture(t, ctx, pool, other)
		if _, err := f.apply(ctx, f.a, f.m); err != nil {
			t.Fatal(err)
		}
		if _, err := f.other.RevokeDevice(ctx, f.authority.TenantCredential, devicesync.DeviceRevocation{Version: devicesync.SchemaVersion, RetryID: uuid.New(), PrincipalID: f.m.Consent.PrincipalID, DeviceID: f.a.Control.MemberID}, 6000); err != nil {
			t.Fatal(err)
		}
		f.now.Store(6001)
		if _, err := f.apply(ctx, f.a, f.m); err == nil {
			t.Fatal("revoked participant replay accepted")
		}
		withdraw := f.m
		withdraw.ParticipantDeviceID = f.b.Control.MemberID
		withdraw.RetryID = uuid.New()
		withdraw.Withdraw = true
		if r, err := f.apply(ctx, f.b, withdraw); err != nil || !r.Withdrawn {
			t.Fatal("origin unnecessarily required", r, err)
		}
		if _, err := f.other.RevokeMember(ctx, f.b.Administration, f.b.Space.MemberID, 6002); err != nil {
			t.Fatal(err)
		}
		f.now.Store(6003)
		if _, err := f.apply(ctx, f.b, withdraw); err == nil {
			t.Fatal("group member without current Space authority accepted")
		}
	})

	t.Run("cancel-rollback-expiry-and-reopen", func(t *testing.T) {
		f := newSyncConsentFixture(t, ctx, pool, other)
		raw, err := f.store.BeginObjectScopeConsentMutation(ctx, f.a, f.m, f.authorization(t))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := json.Marshal(raw); err == nil {
			t.Fatal("transient credential transaction was serializable")
		}
		for _, rendered := range []string{fmt.Sprintf("%v", raw), fmt.Sprintf("%+v", raw), fmt.Sprintf("%#v", raw)} {
			if strings.Contains(rendered, f.a.Administration.Token) || strings.Contains(rendered, f.a.Control.Token) || strings.Contains(rendered, f.a.Space.Token) {
				t.Fatal("diagnostic representation exposed a bearer")
			}
		}
		if err := raw.Close(ctx); err != nil {
			t.Fatal(err)
		}
		if err := raw.Close(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := raw.Commit(ctx, f.authorization(t)); err == nil {
			t.Fatal("closed transaction revived")
		}
		f.assertCounts(t, ctx, 0, 0)
		// A lease acquired before credential expiry cannot commit afterwards.
		if _, err := pool.Exec(ctx, `UPDATE relay_members SET expires_at_milliseconds=5100 WHERE tenant_id=$1 AND member_id=$2`, f.m.Consent.PrincipalID, f.a.Control.MemberID); err != nil {
			t.Fatal(err)
		}
		raw, err = f.store.BeginObjectScopeConsentMutation(ctx, f.a, f.m, f.authorization(t))
		if err != nil {
			t.Fatal(err)
		}
		f.now.Store(5100)
		if _, err := raw.Commit(ctx, f.authorization(t)); err == nil {
			t.Fatal("expired credential committed")
		}
		f.now.Store(5000)
		if _, err := raw.Commit(ctx, f.authorization(t)); err == nil {
			t.Fatal("failed transaction revived with old clock")
		}
		f.assertCounts(t, ctx, 0, 0)
		// Leave a real row lock pending, cancel the coordinator, then reuse pool.
		blocker, err := other.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer blocker.Rollback(ctx)
		if _, err := blocker.Exec(ctx, `SELECT principal_id FROM device_sync_principals WHERE principal_id=$1 FOR UPDATE`, f.m.Consent.PrincipalID); err != nil {
			t.Fatal(err)
		}
		pending, cancel := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() { _, err := f.apply(pending, f.a, f.m); done <- err }()
		waitForSyncConsentLock(t, ctx, other)
		cancel()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("cancel succeeded")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("cancel did not release transaction")
		}
		if err := blocker.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		f.custody.Store = f.other
		if _, err := f.apply(ctx, f.a, f.m); err != nil {
			t.Fatal("reopen after cancelled admission", err)
		}
	})

	t.Run("read-only-missing-space-incarnation-and-clock-rollback", func(t *testing.T) {
		f := newSyncConsentFixture(t, ctx, pool, other)
		for _, domain := range []uuid.UUID{f.a.Control.DomainID, f.a.Space.DomainID} {
			var prior []string
			if err := pool.QueryRow(ctx, `SELECT capabilities FROM relay_members WHERE tenant_id=$1 AND domain_id=$2 AND member_id=$3`, f.m.Consent.PrincipalID, domain, f.a.Control.MemberID).Scan(&prior); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(ctx, `UPDATE relay_members SET capabilities=ARRAY['message_fetch'] WHERE tenant_id=$1 AND domain_id=$2 AND member_id=$3`, f.m.Consent.PrincipalID, domain, f.a.Control.MemberID); err != nil {
				t.Fatal(err)
			}
			if _, err := f.apply(ctx, f.a, f.m); err == nil {
				t.Fatal("read-only participant authorized consent")
			}
			if _, err := pool.Exec(ctx, `UPDATE relay_members SET capabilities=$4 WHERE tenant_id=$1 AND domain_id=$2 AND member_id=$3`, f.m.Consent.PrincipalID, domain, f.a.Control.MemberID, prior); err != nil {
				t.Fatal(err)
			}
		}
		outsider := uuid.New()
		control, _ := postgresEnrollDeviceSyncDevice(t, ctx, f.store, f.authority, outsider, 3700)
		unknown := f.a
		unknown.Control = control
		unknown.Space.MemberID = outsider
		m := f.m
		m.ParticipantDeviceID = outsider
		if _, err := f.apply(ctx, unknown, m); err == nil {
			t.Fatal("group-only device authorized Space consent")
		}
		if _, err := f.other.RevokeMember(ctx, f.a.Administration, f.a.Space.MemberID, 6000); err != nil {
			t.Fatal(err)
		}
		// Recorded revocation must deny even before its timestamp, with no
		// consent clock floor to accidentally make this assertion pass.
		f.now.Store(5000)
		if _, err := f.apply(ctx, f.a, f.m); err == nil {
			t.Fatal("clock rollback revived revoked member")
		}
		f.assertCounts(t, ctx, 0, 0)
	})

	t.Run("membership-revocation-waits-for-commit-across-pools", func(t *testing.T) {
		f := newSyncConsentFixture(t, ctx, pool, other)
		raw, err := f.store.BeginObjectScopeConsentMutation(ctx, f.a, f.m, f.authorization(t))
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close(ctx)
		done := make(chan error, 1)
		go func() { _, err := f.other.RevokeMember(ctx, f.a.Administration, f.a.Space.MemberID, 6000); done <- err }()
		waitForSyncConsentLock(t, ctx, pool)
		select {
		case err := <-done:
			t.Fatal("revocation escaped held rows", err)
		default:
		}
		if _, err := raw.Commit(ctx, f.authorization(t)); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("revocation did not drain")
		}
		f.now.Store(6001)
		if _, err := f.apply(ctx, f.a, f.m); err == nil {
			t.Fatal("revoked source reused consent receipt")
		}
	})

	t.Run("competing-consents-and-withdrawals", func(t *testing.T) {
		f := newSyncConsentFixture(t, ctx, pool, other)
		m1, m2 := f.m, f.m
		m2.RetryID = uuid.New()
		m2.ParticipantDeviceID = f.b.Control.MemberID
		var results [2]error
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _, results[0] = f.apply(ctx, f.a, m1) }()
		otherCustody := *f.custody
		otherCustody.Store = f.other
		go func() { defer wg.Done(); _, results[1] = otherCustody.Apply(ctx, f.b, m2, f.binding) }()
		wg.Wait()
		if (results[0] == nil) == (results[1] == nil) {
			t.Fatal("exactly one acceptance required", results)
		}
		for _, err := range results {
			if err != nil && !errors.Is(err, devicesync.ErrObjectScopeConflict) {
				t.Fatal(err)
			}
		}
		f.assertCounts(t, ctx, 1, 1)
		m1.Withdraw = true
		m2.Withdraw = true
		m1.RetryID = uuid.New()
		m2.RetryID = uuid.New()
		wg.Add(2)
		go func() { defer wg.Done(); _, results[0] = f.apply(ctx, f.a, m1) }()
		go func() { defer wg.Done(); _, results[1] = otherCustody.Apply(ctx, f.b, m2, f.binding) }()
		wg.Wait()
		if results[0] != nil || results[1] != nil {
			t.Fatal(results)
		}
		f.assertCounts(t, ctx, 1, 3)
		unknown := f.newMutation()
		unknown.Withdraw = true
		if _, err := f.apply(ctx, f.a, unknown); !errors.Is(err, devicesync.ErrObjectScopeNotFound) {
			t.Fatal("unknown withdrawal pretended success", err)
		}
		f.assertCounts(t, ctx, 1, 3)
	})

	t.Run("durable-fence-clock-and-corruption", func(t *testing.T) {
		f := newSyncConsentFixture(t, ctx, pool, other)
		if _, err := f.apply(ctx, f.a, f.m); err != nil {
			t.Fatal(err)
		}
		f.now.Store(4999)
		if _, err := f.apply(ctx, f.a, f.m); err == nil {
			t.Fatal("durable clock floor lost")
		}
		f.now.Store(5001)
		if _, err := pool.Exec(ctx, `UPDATE device_sync_scope_enforcement SET state='standby' WHERE principal_id=$1`, f.m.Consent.PrincipalID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.apply(ctx, f.a, f.m); err == nil {
			t.Fatal("stale in-memory authority overrode durable fence")
		}
		if _, err := pool.Exec(ctx, `UPDATE device_sync_scope_enforcement SET state='writable' WHERE principal_id=$1`, f.m.Consent.PrincipalID); err != nil {
			t.Fatal(err)
		}
		var canonical []byte
		if err := pool.QueryRow(ctx, `SELECT canonical_consent FROM device_sync_object_scope_consents`).Scan(&canonical); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `UPDATE device_sync_object_scope_consents SET canonical_consent='{}'::bytea`); err != nil {
			t.Fatal(err)
		}
		if _, err := f.apply(ctx, f.a, f.m); err == nil {
			t.Fatal("damaged stored consent trusted")
		}
		if _, err := pool.Exec(ctx, `UPDATE device_sync_object_scope_consents SET canonical_consent=$1`, canonical); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `UPDATE device_sync_object_scope_mutations SET canonical_mutation='{}'::bytea`); err != nil {
			t.Fatal(err)
		}
		if _, err := f.apply(ctx, f.a, f.m); err == nil {
			t.Fatal("damaged retry trusted")
		}
	})

	t.Run("connection-loss-before-commit-and-lost-response-after-commit", func(t *testing.T) {
		f := newSyncConsentFixture(t, ctx, pool, other)
		config, err := pgxpool.ParseConfig(databaseURL)
		if err != nil {
			t.Fatal(err)
		}
		name := "sync-consent-loss-" + uuid.NewString()
		config.ConnConfig.RuntimeParams["application_name"] = name
		isolated, err := pgxpool.NewWithConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer isolated.Close()
		store, err := postgresstore.NewDeviceSyncAuthorityBoundRelayStore(isolated, f.binding.DeploymentID)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := store.BeginObjectScopeConsentMutation(ctx, f.a, f.m, f.authorization(t))
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close(ctx)
		var pid, count int
		if err := other.QueryRow(ctx, `SELECT min(pid),count(*) FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1 AND state='idle in transaction'`, name).Scan(&pid, &count); err != nil || count != 1 {
			t.Fatal("exact fixture backend unavailable", count, err)
		}
		var terminated bool
		if err := other.QueryRow(ctx, `SELECT pg_terminate_backend($1)`, pid).Scan(&terminated); err != nil || !terminated {
			t.Fatal(err)
		}
		if _, err := raw.Commit(ctx, f.authorization(t)); err == nil {
			t.Fatal("lost transaction committed")
		}
		f.assertCounts(t, ctx, 0, 0)
		// The successful reply is deliberately discarded. Reopen/retry must
		// reconcile to that exact durable operation, not append another decision.
		if _, err := f.apply(ctx, f.a, f.m); err != nil {
			t.Fatal(err)
		}
		f.custody.Store = f.other
		if _, err := f.apply(ctx, f.a, f.m); err != nil {
			t.Fatal(err)
		}
		f.assertCounts(t, ctx, 1, 1)
	})
}

type syncConsentFixture struct {
	pool         *pgxpool.Pool
	store, other *postgresstore.RelayStore
	authority    postgresDeviceSyncAuthority
	a, b         devicesync.SpaceSponsorCredential
	m            devicesync.ObjectScopeConsentMutation
	binding      serviceauthority.RequestBinding
	custody      *devicesync.ObjectScopeConsentCustody
	now          atomic.Int64
}

func newSyncConsentFixture(t *testing.T, ctx context.Context, pool, other *pgxpool.Pool) *syncConsentFixture {
	t.Helper()
	if _, err := pool.Exec(ctx, `TRUNCATE device_sync_account_admissions,relay_tenants CASCADE`); err != nil {
		t.Fatal(err)
	}
	fixture := loadPostgresDeviceSyncEnforcementFixture(t)
	manifest := fixture.RollbackEvidence.ActivationEvidence.Preparation.CurrentManifest
	payload, err := manifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	signer := postgresFixtureDeploymentSigner(t, payload.ActiveDeployment)
	initial := postgresInitialServiceAuthorityBinding(t, fixture, manifest, signer, 1100)
	store, err := postgresstore.NewDeviceSyncAuthorityBoundRelayStore(pool, signer.DeploymentID())
	if err != nil {
		t.Fatal(err)
	}
	second, err := postgresstore.NewDeviceSyncAuthorityBoundRelayStore(other, signer.DeploymentID())
	if err != nil {
		t.Fatal(err)
	}
	principal, origin := payload.Scope.ScopeID, uuid.New()
	authority := postgresBootstrapDeviceSyncPrincipal(t, ctx, store, principal, origin, 1100, initial)
	if err := store.ActivateBoundDeviceSyncScope(ctx, principal, signer.DeploymentID(), initial.Revision(), initial.ManifestDigest(), 1100); err != nil {
		t.Fatal(err)
	}
	space := devicesync.SpaceProvisioning{Version: devicesync.SchemaVersion, RetryID: uuid.New(), PrincipalID: principal, SpaceID: uuid.New(), InitialDeviceID: origin, Domain: postgresDeviceSyncDomain(t, principal, uuid.New(), origin, uuid.New(), 3400, 31, 32), CreatedAtMilliseconds: 3400}
	if _, err := store.ProvisionSpace(ctx, authority.TenantCredential, space, 3400); err != nil {
		t.Fatal(err)
	}
	admin := relay.AdministrationCredential{TenantID: principal, DomainID: space.Domain.Registration.DomainID, Token: postgresRelayToken(31)}
	f := &syncConsentFixture{pool: pool, store: store, other: second, authority: authority, a: postgresSpaceSponsor(authority, space, admin)}
	bID := uuid.New()
	control, _ := postgresEnrollDeviceSyncDevice(t, ctx, store, authority, bID, 3500)
	cred := relay.AdmissionCredential{TenantID: principal, DomainID: admin.DomainID, AdmissionID: uuid.New(), Token: postgresRelayToken(41)}
	digest, err := relay.AdmissionAuthorizationDigest(cred)
	if err != nil {
		t.Fatal(err)
	}
	admission := devicesync.SpaceDeviceAdmission{Version: devicesync.SchemaVersion, RetryID: uuid.New(), PrincipalID: principal, SpaceID: space.SpaceID, DeviceID: bID, SubscriptionID: uuid.New(), CreatedAtMilliseconds: 3600,
		RelayAdmission: relay.MemberAdmission{Version: relay.SchemaVersion, TenantID: principal, DomainID: admin.DomainID, AdmissionID: cred.AdmissionID, AuthorizationDigest: digest, Capabilities: append([]relay.Capability(nil), space.Domain.InitialMember.Capabilities...), CreatedAtMilliseconds: 3600, ExpiresAtMilliseconds: 3600 + devicesync.MinimumAdmissionLifetimeMilliseconds}}
	if _, err := store.CreateSpaceDeviceAdmission(ctx, f.a, admission, 3600); err != nil {
		t.Fatal(err)
	}
	spaceCred := relay.Credential{TenantID: principal, DomainID: admin.DomainID, MemberID: bID, Token: postgresRelayToken(42)}
	digest, err = relay.AuthorizationDigest(spaceCred)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimSpaceDeviceAdmission(ctx, devicesync.SpaceDeviceAdmissionCredential{PrincipalID: principal, SpaceID: space.SpaceID, AdmissionID: cred.AdmissionID, Token: cred.Token}, devicesync.SpaceDeviceAdmissionClaim{Version: devicesync.SchemaVersion, PrincipalID: principal, SpaceID: space.SpaceID, DeviceID: bID, ClaimedAtMilliseconds: 3601, RelayClaim: relay.MemberAdmissionClaim{MemberID: bID, AuthorizationDigest: digest}}, 3601); err != nil {
		t.Fatal(err)
	}
	f.b = devicesync.SpaceSponsorCredential{Administration: admin, Control: control, Space: spaceCred}
	f.m = devicesync.ObjectScopeConsentMutation{Consent: devicesync.ObjectScopeConsent{Version: 1, PrincipalID: principal, SpaceID: space.SpaceID, DomainID: admin.DomainID, BindingID: uuid.New(), ContentEpoch: math.MaxUint64, ContentScopeID: uuid.New(), LedgerID: uuid.New(), LinkID: uuid.New(), LinkIntentDigest: strings.Repeat("a", 64), PoolID: uuid.New()}, ParticipantDeviceID: origin, RetryID: uuid.New()}
	registry := serviceauthority.NewBindingRegistry()
	digest, err = manifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Activate(payload.Scope, serviceauthority.CurrentBinding{Revision: payload.Revision, Digest: digest, DeploymentID: signer.DeploymentID(), Manifest: &manifest}); err != nil {
		t.Fatal(err)
	}
	f.binding = serviceauthority.RequestBinding{Scope: payload.Scope, AuthorityRevision: payload.Revision, AuthorityDigest: digest, DeploymentID: signer.DeploymentID(), RouteID: payload.TransportPolicy.ControlRouteIDs[0], TrafficClass: serviceauthority.TrafficControl}
	f.now.Store(5000)
	f.custody = &devicesync.ObjectScopeConsentCustody{Store: store, Registry: registry, Now: func() time.Time { return time.UnixMilli(f.now.Load()) }}
	return f
}

func (f *syncConsentFixture) apply(ctx context.Context, c devicesync.SpaceSponsorCredential, m devicesync.ObjectScopeConsentMutation) (devicesync.ObjectScopeConsentStatus, error) {
	return f.custody.Apply(ctx, c, m, f.binding)
}
func (f *syncConsentFixture) authorization(t *testing.T) serviceauthority.MutationAuthorization {
	t.Helper()
	a, err := f.custody.Registry.AuthorizeMutationAt(f.binding, f.custody.Now())
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func (f *syncConsentFixture) newMutation() devicesync.ObjectScopeConsentMutation {
	m := f.m
	m.RetryID = uuid.New()
	m.Consent.BindingID = uuid.New()
	m.Consent.LinkID = uuid.New()
	m.Consent.LinkIntentDigest = strings.ReplaceAll(uuid.NewString(), "-", "") + strings.ReplaceAll(uuid.NewString(), "-", "")
	return m
}
func (f *syncConsentFixture) assertCounts(t *testing.T, ctx context.Context, consents, mutations int) {
	t.Helper()
	var c, m int
	if err := f.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM device_sync_object_scope_consents),(SELECT count(*) FROM device_sync_object_scope_mutations)`).Scan(&c, &m); err != nil || c != consents || m != mutations {
		t.Fatalf("consents=%d mutations=%d err=%v", c, m, err)
	}
}
func waitForSyncConsentLock(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND pid<>pg_backend_pid()`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("expected database lock wait not observed")
}

// Populate via the production current-participant path, not raw authority rows.
// The migration fixture includes one active and one withdrawn consent, retries,
// canonical bytes containing full UInt64 epochs, and the committed clock floor.
func populatePostgresSyncConsentMigrationState(t *testing.T, ctx context.Context, pool *pgxpool.Pool, authority postgresDeviceSyncAuthority, device uuid.UUID) {
	t.Helper()
	fixture := loadPostgresDeviceSyncEnforcementFixture(t)
	manifest := fixture.RollbackEvidence.ActivationEvidence.Preparation.CurrentManifest
	payload, err := manifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := manifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	registry := serviceauthority.NewBindingRegistry()
	if err := registry.Activate(payload.Scope, serviceauthority.CurrentBinding{Revision: payload.Revision, Digest: digest, DeploymentID: payload.ActiveDeployment.DeploymentID, Manifest: &manifest}); err != nil {
		t.Fatal(err)
	}
	store, err := postgresstore.NewDeviceSyncAuthorityBoundRelayStore(pool, payload.ActiveDeployment.DeploymentID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetSharedCapacityProvider(&poolTestCapacity{free: 8 << 30}); err != nil {
		t.Fatal(err)
	}
	space := devicesync.SpaceProvisioning{Version: devicesync.SchemaVersion, RetryID: uuid.New(), PrincipalID: payload.Scope.ScopeID, SpaceID: uuid.New(), InitialDeviceID: device,
		Domain: postgresDeviceSyncDomain(t, payload.Scope.ScopeID, uuid.New(), device, uuid.New(), 1310, 31, 32), CreatedAtMilliseconds: 1310}
	if _, err := store.ProvisionSpace(ctx, authority.TenantCredential, space, 1310); err != nil {
		t.Fatal(err)
	}
	admin := relay.AdministrationCredential{TenantID: space.PrincipalID, DomainID: space.Domain.Registration.DomainID, Token: postgresRelayToken(31)}
	c := postgresSpaceSponsor(authority, space, admin)
	binding := serviceauthority.RequestBinding{Scope: payload.Scope, AuthorityRevision: payload.Revision, AuthorityDigest: digest, DeploymentID: payload.ActiveDeployment.DeploymentID, RouteID: payload.TransportPolicy.ControlRouteIDs[0], TrafficClass: serviceauthority.TrafficControl}
	custody := devicesync.ObjectScopeConsentCustody{Store: store, Registry: registry, Now: func() time.Time { return time.UnixMilli(1311) }}
	m := devicesync.ObjectScopeConsentMutation{Consent: devicesync.ObjectScopeConsent{Version: 1, PrincipalID: space.PrincipalID, SpaceID: space.SpaceID, DomainID: admin.DomainID, BindingID: uuid.New(), ContentEpoch: math.MaxUint64, ContentScopeID: uuid.New(), LedgerID: uuid.New(), LinkID: uuid.New(), LinkIntentDigest: strings.Repeat("a", 64), PoolID: uuid.New()}, ParticipantDeviceID: device, RetryID: uuid.New()}
	if _, err := custody.Apply(ctx, c, m, binding); err != nil {
		t.Fatal(err)
	}
	m.Withdraw = true
	m.RetryID = uuid.New()
	if _, err := custody.Apply(ctx, c, m, binding); err != nil {
		t.Fatal(err)
	}
	m.Withdraw = false
	m.RetryID = uuid.New()
	m.Consent.BindingID = uuid.New()
	m.Consent.LinkID = uuid.New()
	m.Consent.LinkIntentDigest = strings.Repeat("b", 64)
	if _, err := custody.Apply(ctx, c, m, binding); err != nil {
		t.Fatal(err)
	}
}
