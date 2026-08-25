package postgres_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	postgresstore "github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

func TestPostgresDeviceSyncMutationFenceBlocksMigrationWriteLockUntilRelease(t *testing.T) {
	databaseURL := os.Getenv("FACETS_SERVER_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("FACETS_SERVER_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	lockDisposablePostgres(t, ctx, databaseURL)
	adminPool := openPool(t, ctx, databaseURL)
	defer adminPool.Close()
	if err := postgresstore.Migrate(ctx, adminPool); err != nil {
		t.Fatal(err)
	}
	if _, err := adminPool.Exec(ctx, `
		TRUNCATE device_sync_account_admissions, relay_tenants CASCADE
	`); err != nil {
		t.Fatal(err)
	}
	guardPoolConfiguration, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	guardPoolConfiguration.MaxConns = 2
	guardPool, err := pgxpool.NewWithConfig(ctx, guardPoolConfiguration)
	if err != nil {
		t.Fatal(err)
	}
	defer guardPool.Close()
	if err := guardPool.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	oneConnectionConfiguration, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	oneConnectionConfiguration.MaxConns = 1
	oneConnectionPool, err := pgxpool.NewWithConfig(ctx, oneConnectionConfiguration)
	if err != nil {
		t.Fatal(err)
	}
	defer oneConnectionPool.Close()

	fixture := loadPostgresDeviceSyncEnforcementFixture(t)
	manifest := fixture.RollbackEvidence.ActivationEvidence.
		Preparation.CurrentManifest
	payload, err := manifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	manifestDigest, err := manifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	principalID := payload.Scope.ScopeID
	localSigner := postgresFixtureDeploymentSigner(t, payload.ActiveDeployment)
	if _, err := postgresstore.NewDeviceSyncAuthorityBoundRelayStore(
		oneConnectionPool, localSigner.DeploymentID(),
	); !errors.Is(err, serviceauthority.ErrInvalid) {
		t.Fatalf("one-connection authority-bound store error=%v", err)
	}
	initialAuthority := postgresInitialServiceAuthorityBinding(
		t, fixture, manifest, localSigner, 1_100,
	)
	bootstrapStore := postgresstore.NewRelayStore(adminPool)
	postgresBootstrapDeviceSyncPrincipal(
		t, ctx, bootstrapStore, principalID, uuid.New(), 1_100, initialAuthority,
	)
	if err := bootstrapStore.ActivateBoundDeviceSyncScope(
		ctx, principalID, localSigner.DeploymentID(),
		initialAuthority.Revision(), initialAuthority.ManifestDigest(), 1_100,
	); err != nil {
		t.Fatal(err)
	}

	store, err := postgresstore.NewDeviceSyncAuthorityBoundRelayStore(
		guardPool, localSigner.DeploymentID(),
	)
	if err != nil {
		t.Fatal(err)
	}
	registry := serviceauthority.NewBindingRegistry()
	manifestCopy := manifest
	if err := registry.Activate(payload.Scope, serviceauthority.CurrentBinding{
		Revision: payload.Revision, Digest: manifestDigest,
		DeploymentID: payload.ActiveDeployment.DeploymentID,
		Manifest:     &manifestCopy,
	}); err != nil {
		t.Fatal(err)
	}
	authorization, err := registry.AuthorizeMutationAt(
		serviceauthority.RequestBinding{
			Scope: payload.Scope, AuthorityRevision: payload.Revision,
			AuthorityDigest: manifestDigest,
			DeploymentID:    payload.ActiveDeployment.DeploymentID,
			RouteID:         payload.TransportPolicy.ControlRouteIDs[0],
			TrafficClass:    serviceauthority.TrafficControl,
		},
		time.UnixMilli(1_100),
	)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := store.AcquireDeviceSyncMutationFence(ctx, authorization)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lease.Release(context.Background()) })
	if acquired := guardPool.Stat().AcquiredConns(); acquired != 1 {
		t.Fatalf("mutation fence acquired connections=%d, want 1", acquired)
	}

	secondContext, cancelSecond := context.WithCancel(ctx)
	secondStarted := make(chan struct{})
	secondResult := make(chan error, 1)
	go func() {
		close(secondStarted)
		secondLease, err := store.AcquireDeviceSyncMutationFence(
			secondContext, authorization,
		)
		if secondLease != nil {
			_ = secondLease.Release(context.Background())
		}
		secondResult <- err
	}()
	<-secondStarted

	migrationBeginContext, cancelMigrationBegin := context.WithTimeout(
		ctx, 2*time.Second,
	)
	defer cancelMigrationBegin()
	migrationTx, err := guardPool.BeginTx(migrationBeginContext, pgx.TxOptions{
		IsoLevel: pgx.ReadCommitted,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = migrationTx.Rollback(context.Background()) }()
	var migrationBackendPID int32
	if err := migrationTx.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(
		&migrationBackendPID,
	); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	locked := make(chan error, 1)
	go func() {
		close(started)
		var state string
		err := migrationTx.QueryRow(ctx, `
			SELECT state
			FROM device_sync_scope_enforcement
			WHERE principal_id=$1
			FOR UPDATE
		`, principalID).Scan(&state)
		locked <- err
	}()
	<-started
	waitDeadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case err := <-locked:
			t.Fatalf("migration FOR UPDATE bypassed active mutation fence: %v", err)
		default:
		}
		var waitEventType string
		if err := adminPool.QueryRow(ctx, `
			SELECT COALESCE(wait_event_type, '')
			FROM pg_stat_activity
			WHERE pid=$1
		`, migrationBackendPID).Scan(&waitEventType); err != nil {
			t.Fatal(err)
		}
		if waitEventType == "Lock" {
			break
		}
		if time.Now().After(waitDeadline) {
			t.Fatal("migration FOR UPDATE was not observed waiting on the mutation fence")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancelSecond()
	if err := <-secondResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("saturated second fence admission error=%v", err)
	}
	if err := lease.Release(ctx); err != nil {
		t.Fatal(err)
	}
	if err := lease.Release(ctx); err != nil {
		t.Fatalf("idempotent mutation-fence release: %v", err)
	}
	select {
	case err := <-locked:
		if err != nil {
			t.Fatalf("migration FOR UPDATE after release: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("migration FOR UPDATE remained blocked after mutation-fence release")
	}
	if err := migrationTx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	// The deferred database invariant executes in the mutation's own
	// transaction. Even if PostgreSQL terminates the separate request-fence
	// session after the mutation has changed a row, a migration can fence the
	// scope and the later mutation commit must fail.
	failureLease, err := store.AcquireDeviceSyncMutationFence(ctx, authorization)
	if err != nil {
		t.Fatal(err)
	}
	var fenceBackendPID int32
	var fenceBackendCount int
	if err := adminPool.QueryRow(ctx, `
		SELECT count(*),COALESCE(min(pid),0)
		FROM pg_stat_activity
		WHERE datname=current_database()
		  AND application_name='facets-device-sync-mutation-fence'
		  AND state='idle in transaction'
	`).Scan(&fenceBackendCount, &fenceBackendPID); err != nil {
		t.Fatal(err)
	}
	if fenceBackendCount != 1 || fenceBackendPID == 0 {
		t.Fatalf(
			"active labeled fence sessions=%d pid=%d",
			fenceBackendCount,
			fenceBackendPID,
		)
	}
	pendingMutation, err := guardPool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pendingMutation.Rollback(context.Background()) }()
	if _, err := pendingMutation.Exec(ctx, `
		UPDATE relay_tenants
		SET updated_at=now()
		WHERE tenant_id=$1
	`, principalID); err != nil {
		t.Fatal(err)
	}
	var terminated bool
	if err := adminPool.QueryRow(
		ctx,
		"SELECT pg_terminate_backend($1)",
		fenceBackendPID,
	).Scan(&terminated); err != nil || !terminated {
		t.Fatalf("terminate fence backend=%v err=%v", terminated, err)
	}
	if _, err := adminPool.Exec(ctx, `
		UPDATE device_sync_scope_enforcement
		SET state='retired',active_export_write_fence_id=NULL,updated_at=now()
		WHERE principal_id=$1
	`, principalID); err != nil {
		t.Fatal(err)
	}
	commitErr := pendingMutation.Commit(ctx)
	if commitErr == nil || !strings.Contains(
		commitErr.Error(),
		"not writable in this transaction",
	) {
		t.Fatalf("mutation commit after lost fence=%v", commitErr)
	}
	_ = failureLease.Release(context.Background())
}
