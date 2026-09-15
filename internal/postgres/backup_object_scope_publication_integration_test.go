package postgres_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/robreuss/FacetsNode/internal/backupcustody"
	postgresstore "github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

func TestPostgresBackupObjectScopePublication(t *testing.T) {
	databaseURL := os.Getenv("FACETS_BACKUP_CONSENT_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("FACETS_BACKUP_CONSENT_TEST_DATABASE_URL is not set")
	}
	u, err := url.Parse(databaseURL)
	if err != nil || u.Path != "/facets_backup_consent_tests" {
		t.Fatal("requires dedicated disposable consent database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	lockDisposablePostgres(t, ctx, databaseURL)
	pool, other := openPool(t, ctx, databaseURL), openPool(t, ctx, databaseURL)
	defer pool.Close()
	defer other.Close()
	resetBackupCustodySchema(t, ctx, pool)

	t.Run("active-exact-scope-and-current-bearer", func(t *testing.T) {
		f := newPublicationFixture(t, ctx, pool, other)
		lease, err := f.custody.Begin(ctx, f.credential, f.request, f.binding)
		if err != nil {
			t.Fatal(err)
		}
		if err := lease.Revalidate(); err != nil {
			t.Fatal(err)
		}
		if err := lease.Close(); err != nil {
			t.Fatal(err)
		}
		if err := lease.Close(); err != nil {
			t.Fatal("close not idempotent", err)
		}
		if err := lease.Revalidate(); err == nil {
			t.Fatal("closed handle was usable")
		}
		wrongBearer, _ := backupcustody.NewTargetCredential(f.credential.Reference)
		f.rejected(t, ctx, wrongBearer, f.request, f.binding)
		for _, change := range []func(*backupcustody.ObjectScopePublicationRequest){
			func(r *backupcustody.ObjectScopePublicationRequest) { r.Consent.AccountID = uuid.New() },
			func(r *backupcustody.ObjectScopePublicationRequest) { r.Consent.TargetID = uuid.New() },
			func(r *backupcustody.ObjectScopePublicationRequest) { r.Consent.BackupSetID = uuid.New() },
			func(r *backupcustody.ObjectScopePublicationRequest) {
				r.Consent.ContentEpoch++
				r.Request.Target.ContentEpoch++
			},
			func(r *backupcustody.ObjectScopePublicationRequest) {
				r.Consent.ContentScopeID = uuid.New()
				r.Request.Target.ContentScopeID = r.Consent.ContentScopeID
			},
			func(r *backupcustody.ObjectScopePublicationRequest) {
				r.Consent.BindingID = uuid.New()
				r.Request.Target.BindingID = r.Consent.BindingID
			},
			func(r *backupcustody.ObjectScopePublicationRequest) {
				r.Consent.PoolID = uuid.New()
				r.Request.Target.PoolID = r.Consent.PoolID
			},
			func(r *backupcustody.ObjectScopePublicationRequest) {
				r.Consent.LedgerID = uuid.New()
				r.Request.Target.LedgerID = r.Consent.LedgerID
			},
			func(r *backupcustody.ObjectScopePublicationRequest) { r.Consent.LinkID = uuid.New() },
			func(r *backupcustody.ObjectScopePublicationRequest) {
				r.Consent.LinkIntentDigest = strings.Repeat("b", 64)
			},
		} {
			r := f.request
			change(&r)
			f.rejected(t, ctx, f.credential, r, f.binding)
		}
		stale := f.binding
		stale.AuthorityRevision++
		f.rejected(t, ctx, f.credential, f.request, stale)
		limits := publicationFixtureLimits()
		limits.MaximumControlRecords = 1
		boundedStore, err := postgresstore.NewBackupCustodyStore(pool, f.binding.DeploymentID, limits)
		if err != nil {
			t.Fatal(err)
		}
		f.custody.Store = boundedStore
		f.rejected(t, ctx, f.credential, f.request, f.binding)
	})

	t.Run("revocation-serialized-by-database-not-go-mutex", func(t *testing.T) {
		f := newPublicationFixture(t, ctx, pool, other)
		lease, err := f.custody.Begin(ctx, f.credential, f.request, f.binding)
		if err != nil {
			t.Fatal(err)
		}
		defer lease.Close()
		ref, _ := f.request.Consent.ReferenceDigest()
		revoke := f.command(t, backupcustody.ControlEffect{Kind: backupcustody.RevokeObjectScopeConsent, PriorObjectScopeConsentDigest: &ref})
		blocked, stop := context.WithTimeout(ctx, 150*time.Millisecond)
		_, err = f.otherControl.Submit(blocked, revoke, f.binding)
		stop()
		if err == nil || !errors.Is(blocked.Err(), context.DeadlineExceeded) {
			t.Fatalf("revocation bypassed held account lock: %v", err)
		}
		if err := lease.Revalidate(); err != nil {
			t.Fatal(err)
		}
		if err := lease.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := f.otherControl.Submit(ctx, revoke, f.binding); err != nil {
			t.Fatal(err)
		}
		f.rejected(t, ctx, f.credential, f.request, f.binding)
		if _, err := f.otherControl.Submit(ctx, f.consentCommand, f.binding); err != nil {
			t.Fatal(err)
		}
		f.rejected(t, ctx, f.credential, f.request, f.binding)
		// Withdrawal does not revoke this target's operational read credential.
		state := readConsentProjection(t, ctx, pool, f.request.Consent.AccountID, f.anchor)
		if _, active := state.ActiveGrant(f.credential.Reference.CredentialID); !active {
			t.Fatal("consent withdrawal revoked independent Backup credential")
		}
	})

	t.Run("credential-revocation-and-read-only-grant", func(t *testing.T) {
		f := newPublicationFixture(t, ctx, pool, other)
		digest, _ := f.credential.AuthorizationDigest()
		grant := backupcustody.CredentialGrant{Version: 1, Credential: f.credential.Reference, AuthorizationDigest: digest}
		ref, _ := grant.ReferenceDigest()
		revoke := f.command(t, backupcustody.ControlEffect{Kind: backupcustody.RevokeCredential, PriorGrantReferenceDigest: &ref})
		f.submit(t, ctx, revoke)
		f.rejected(t, ctx, f.credential, f.request, f.binding)
		r := f.credential.Reference
		r.Capabilities = []backupcustody.Capability{backupcustody.Read}
		r.CredentialID = uuid.New()
		readOnly, _ := backupcustody.NewTargetCredential(r)
		digest, _ = readOnly.AuthorizationDigest()
		grant = backupcustody.CredentialGrant{Version: 1, Credential: r, AuthorizationDigest: digest}
		f.submit(t, ctx, f.command(t, backupcustody.ControlEffect{Kind: backupcustody.GrantCredential, Grant: &grant}))
		f.rejected(t, ctx, readOnly, f.request, f.binding)
	})

	t.Run("revocation-wins-between-clock-commit-and-held-transaction", func(t *testing.T) {
		f := newPublicationFixture(t, ctx, pool, other)
		arrived, proceed := make(chan struct{}), make(chan struct{})
		var acquisitions atomic.Int64
		config := pool.Config()
		config.BeforeAcquire = func(acquireCtx context.Context, conn *pgx.Conn) bool {
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
		// Same production store and fixture limits, independent pool hook solely
		// to expose the otherwise tiny preflight-to-held-transaction gap.
		gapStore, err := postgresstore.NewBackupCustodyStore(gapPool, f.binding.DeploymentID, publicationFixtureLimits())
		if err != nil {
			t.Fatal(err)
		}
		f.custody.Store = gapStore
		result := make(chan error, 1)
		go func() {
			l, e := f.custody.Begin(ctx, f.credential, f.request, f.binding)
			if l != nil {
				_ = l.Close()
			}
			result <- e
		}()
		select {
		case <-arrived:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		ref, _ := f.request.Consent.ReferenceDigest()
		_, revokeErr := f.otherControl.Submit(ctx, f.command(t, backupcustody.ControlEffect{Kind: backupcustody.RevokeObjectScopeConsent, PriorObjectScopeConsentDigest: &ref}), f.binding)
		close(proceed)
		if revokeErr != nil {
			t.Fatal(revokeErr)
		}
		if err := <-result; !errors.Is(err, backupcustody.ErrUnauthorized) {
			t.Fatalf("historical preflight survived revocation: %v", err)
		}
	})

	t.Run("cancellation-releases-database-and-migration-drain", func(t *testing.T) {
		f := newPublicationFixture(t, ctx, pool, other)
		requestCtx, stop := context.WithCancel(ctx)
		lease, err := f.custody.Begin(requestCtx, f.credential, f.request, f.binding)
		if err != nil {
			t.Fatal(err)
		}
		stop()
		wait, done := context.WithTimeout(ctx, 2*time.Second)
		defer done()
		drain, err := f.custody.Registry.AcquireMigrationDrain(wait, f.binding.Scope)
		if err != nil {
			t.Fatal("cancellation leaked source scope lease", err)
		}
		drain.Release()
		if err := lease.Revalidate(); err == nil {
			t.Fatal("cancelled handle usable")
		}
		ref, _ := f.request.Consent.ReferenceDigest()
		if _, err := f.otherControl.Submit(wait, f.command(t, backupcustody.ControlEffect{Kind: backupcustody.RevokeObjectScopeConsent, PriorObjectScopeConsentDigest: &ref}), f.binding); err != nil {
			t.Fatal("cancellation leaked account transaction", err)
		}
	})

	t.Run("expiry-after-lock-wait-and-terminal-failure", func(t *testing.T) {
		f := newPublicationFixture(t, ctx, pool, other)
		lease, err := f.custody.Begin(ctx, f.credential, f.request, f.binding)
		if err != nil {
			t.Fatal(err)
		}
		f.clock.millis.Store(10_000)
		if err := lease.Revalidate(); !errors.Is(err, backupcustody.ErrUnauthorized) {
			t.Fatalf("expired credential: %v", err)
		}
		f.clock.millis.Store(1200)
		if err := lease.Revalidate(); err == nil {
			t.Fatal("failed handle revived after clock change")
		}
		f.rejected(t, ctx, f.credential, f.request, f.binding)
		// Force a real row wait and move time only once pg_stat_activity proves
		// the operation is waiting for a database lock, not a scheduling guess.
		f = newPublicationFixture(t, ctx, pool, other)
		tx, err := other.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err := tx.Exec(ctx, `SELECT account_id FROM backup_custody_accounts WHERE account_id=$1 FOR UPDATE`, f.request.Consent.AccountID); err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() {
			l, e := f.custody.Begin(ctx, f.credential, f.request, f.binding)
			if l != nil {
				_ = l.Close()
			}
			result <- e
		}()
		waitForPublicationLock(t, ctx, other)
		f.clock.millis.Store(10_000)
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err := <-result; !errors.Is(err, backupcustody.ErrUnauthorized) {
			t.Fatalf("expired lock-wait request admitted: %v", err)
		}
	})

	t.Run("durable-fence-corruption-and-admission-clock-floor", func(t *testing.T) {
		f := newPublicationFixture(t, ctx, pool, other)
		// Identify the fault-injected backend independently of its last SQL:
		// optimizations can change the last statement without changing custody.
		config := pool.Config()
		applicationName := "publication-crash-" + f.request.Consent.AccountID.String()
		config.ConnConfig.RuntimeParams["application_name"] = applicationName
		crashPool, err := pgxpool.NewWithConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer crashPool.Close()
		crashStore, err := postgresstore.NewBackupCustodyStore(crashPool, f.binding.DeploymentID, publicationFixtureLimits())
		if err != nil {
			t.Fatal(err)
		}
		f.custody.Store = crashStore
		f.clock.millis.Store(1500)
		lease, err := f.custody.Begin(ctx, f.credential, f.request, f.binding)
		if err != nil {
			t.Fatal(err)
		}
		defer lease.Close()
		// Terminate only the connection owning this fixture's held account lock.
		var pid, count int
		if err := other.QueryRow(ctx, `SELECT count(*),coalesce(min(pid),0) FROM pg_stat_activity WHERE datname=current_database() AND state='idle in transaction' AND application_name=$1`, applicationName).Scan(&count, &pid); err != nil || count != 1 {
			t.Fatalf("exact crash backend count=%d pid=%d err=%v", count, pid, err)
		}
		var killed bool
		if err := other.QueryRow(ctx, `SELECT pg_terminate_backend($1)`, pid).Scan(&killed); err != nil || !killed {
			t.Fatalf("disconnect fixture: %v", err)
		}
		if err := lease.Revalidate(); err == nil {
			t.Fatal("dead transaction authorized")
		}
		var high int64
		if err := other.QueryRow(ctx, `SELECT server_time_high_water_milliseconds FROM backup_custody_accounts WHERE account_id=$1`, f.request.Consent.AccountID).Scan(&high); err != nil || high < 1500 {
			t.Fatalf("admission floor lost after connection death: %d %v", high, err)
		}
		f.clock.millis.Store(1499)
		f.rejected(t, ctx, f.credential, f.request, f.binding)
		f.clock.millis.Store(1600)
		fresh, err := f.custody.Begin(ctx, f.credential, f.request, f.binding)
		if err != nil {
			t.Fatal("fresh retry after lost connection", err)
		}
		if err := fresh.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := other.Exec(ctx, `UPDATE backup_custody_accounts SET state='standby' WHERE account_id=$1`, f.request.Consent.AccountID); err != nil {
			t.Fatal(err)
		}
		f.rejected(t, ctx, f.credential, f.request, f.binding)
		f = newPublicationFixture(t, ctx, pool, other)
		if _, err := other.Exec(ctx, `UPDATE backup_custody_control_commands SET command_record=decode('00','hex') WHERE account_id=$1 AND sequence=2`, f.request.Consent.AccountID); err != nil {
			t.Fatal(err)
		}
		f.rejected(t, ctx, f.credential, f.request, f.binding)
	})
	var contentEffects int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM backup_custody_generations)+(SELECT count(*) FROM backup_custody_uploads)`).Scan(&contentEffects); err != nil || contentEffects != 0 {
		t.Fatalf("authorization produced content effects: %d %v", contentEffects, err)
	}
}

type publicationClock struct{ millis atomic.Int64 }

func (c *publicationClock) Now() time.Time { return time.UnixMilli(c.millis.Load()) }

type publicationFixture struct {
	custody        backupcustody.ObjectScopePublicationCustody
	otherControl   backupcustody.ControlCustody
	credential     backupcustody.TargetCredential
	request        backupcustody.ObjectScopePublicationRequest
	binding        serviceauthority.RequestBinding
	clock          *publicationClock
	owner          backupControlSigner
	anchor         backupcustody.ControlPossessionAnchor
	head           backupcustody.ControlCommandAcceptance
	consentCommand backupcustody.SignedControlCommand
}

func (f *publicationFixture) command(t *testing.T, effect backupcustody.ControlEffect) backupcustody.SignedControlCommand {
	t.Helper()
	return backupSignedControlCommand(t, f.owner, nil, backupcustody.ControlCommandPayload{Version: 1,
		AccountID: f.request.Consent.AccountID, CommandID: uuid.New(), ControlGeneration: f.owner.generation,
		ControlKeyID: f.owner.keyID, Sequence: f.head.Sequence + 1, PredecessorReferenceDigest: f.head.CommandReferenceDigest, Effect: effect})
}
func (f *publicationFixture) submit(t *testing.T, ctx context.Context, command backupcustody.SignedControlCommand) {
	t.Helper()
	var err error
	f.head, err = f.otherControl.Submit(ctx, command, f.binding)
	if err != nil {
		t.Fatal(err)
	}
}
func (f *publicationFixture) rejected(t *testing.T, ctx context.Context, c backupcustody.TargetCredential, r backupcustody.ObjectScopePublicationRequest, b serviceauthority.RequestBinding) {
	t.Helper()
	l, err := f.custody.Begin(ctx, c, r, b)
	if l != nil {
		_ = l.Close()
	}
	if err == nil {
		t.Fatal("unauthorized preparation admitted")
	}
}

func newPublicationFixture(t *testing.T, ctx context.Context, pool, other *pgxpool.Pool) *publicationFixture {
	t.Helper()
	account, deployment := uuid.New(), uuid.New()
	limits := publicationFixtureLimits()
	store, err := postgresstore.NewBackupCustodyStore(pool, deployment, limits)
	if err != nil {
		t.Fatal(err)
	}
	otherStore, err := postgresstore.NewBackupCustodyStore(other, deployment, limits)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, signer := backupPostgresEnrollment(t, account, deployment)
	manifest, _ := enrollment.Manifest.VerifiedPayload()
	digest, _ := enrollment.Manifest.ReferenceDigest()
	clock := &publicationClock{}
	clock.millis.Store(1100)
	registry := serviceauthority.NewBindingRegistry()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	journal, err := backupcustody.OpenPreparedAccountJournal(filepath.Join(parent, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	admission, err := backupcustody.NewAccountAdmissionCredential(backupcustody.AccountAdmissionReference{Version: 1,
		AccountID: account, AdmissionID: uuid.New(), ExpiresAtMilliseconds: 10_000,
		RequestNonce: base64.RawURLEncoding.EncodeToString(make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	owner := newBackupControlSigner(account, 1, 61)
	anchor := owner.anchor(t)
	provisioning := backupcustody.ProvisioningCustody{Store: store, Journal: journal, Registry: registry, Signer: signer, Clock: clock}
	if err := provisioning.ProvisionAccount(ctx, admission, uuid.New(), enrollment, anchor); err != nil {
		t.Fatal(err)
	}
	binding := serviceauthority.RequestBinding{Scope: serviceauthority.Scope{Kind: serviceauthority.ScopeBackupCustody, ScopeID: account},
		AuthorityRevision: 1, AuthorityDigest: digest, DeploymentID: deployment, RouteID: manifest.ActiveDeployment.Routes[0].RouteID, TrafficClass: serviceauthority.TrafficControl}
	otherRegistry := serviceauthority.NewBindingRegistry()
	if err := otherRegistry.Activate(binding.Scope, serviceauthority.CurrentBinding{Revision: 1, Digest: digest, DeploymentID: deployment, Manifest: &enrollment.Manifest}); err != nil {
		t.Fatal(err)
	}
	f := &publicationFixture{custody: backupcustody.ObjectScopePublicationCustody{Store: store, Registry: registry, Clock: clock},
		otherControl: backupcustody.ControlCustody{Store: otherStore, Registry: otherRegistry, Clock: clock},
		credential:   backupIntegrationTarget(t, account, uuid.New(), uuid.New()), binding: binding, clock: clock, owner: owner, anchor: anchor}
	f.submit(t, ctx, backupCreateTargetCommand(t, owner, anchor, f.credential, uuid.New(), 1))
	consent := backupcustody.ObjectScopeConsent{Version: 1, AccountID: account, TargetID: f.credential.Reference.TargetID,
		BackupSetID: f.credential.Reference.BackupSetID, BindingID: uuid.New(), ContentEpoch: 1, ContentScopeID: uuid.New(),
		LedgerID: uuid.New(), PoolID: uuid.New(), LinkID: uuid.New(), LinkIntentDigest: strings.Repeat("a", 64)}
	f.request = backupcustody.ObjectScopePublicationRequest{Consent: consent, Request: serviceauthority.CustodyPeerRequest{Version: 1,
		Operation: serviceauthority.CustodyReserveObject, OperationID: uuid.New(), BodyByteCount: 1, BodySHA256: strings.Repeat("c", 64),
		Challenge: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), Target: serviceauthority.CustodyPeerTarget{BindingID: consent.BindingID,
			ContentEpoch: consent.ContentEpoch, ContentScopeID: consent.ContentScopeID, PoolID: consent.PoolID, LedgerID: consent.LedgerID}}}
	f.consentCommand = f.command(t, backupcustody.ControlEffect{Kind: backupcustody.ConsentObjectScope, ObjectScopeConsent: &consent})
	f.submit(t, ctx, f.consentCommand)
	return f
}

func publicationFixtureLimits() postgresstore.BackupCustodyStoreLimits {
	return postgresstore.BackupCustodyStoreLimits{MaximumActiveUploads: 2, MaximumTargets: 2,
		MaximumGenerations: 4, MaximumRequests: 40, MaximumRetentionProofs: 4, MaximumControlRecords: 40,
		MaximumCredentialLifetimeMilliseconds: 10_000, MaximumChunksPerUpload: 4,
		MaximumChunkBytes: 1024, MaximumStagingBytes: 8192, MaximumCommittedBytes: 16384}
}

func waitForPublicationLock(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		var blocked bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%FROM backup_custody_accounts%')`).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			return
		}
		select {
		case <-tick.C:
		case <-timer.C:
			t.Fatal("operation never reached account row wait")
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
}
