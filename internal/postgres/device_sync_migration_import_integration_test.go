package postgres_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	postgresstore "github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

func TestPostgresPreparedDeviceSyncMigrationImportIsAtomicAndStandby(
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
	if _, err := pool.Exec(ctx, `
		TRUNCATE device_sync_account_admissions, relay_tenants CASCADE
	`); err != nil {
		t.Fatal(err)
	}

	fixture := loadPostgresDeviceSyncEnforcementFixture(t)
	preparation := fixture.RollbackEvidence.ActivationEvidence.Preparation
	snapshot := fixture.RollbackEvidence.ActivationEvidence.Snapshot
	snapshotPayload, err := snapshot.VerifiedPayload(nil)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := preparation.PreparationManifest.VerifiedPayload()
	if err != nil || prepared.Migration == nil || len(prepared.PreparedDeployments) != 1 {
		t.Fatalf("prepared payload=%+v err=%v", prepared, err)
	}
	principalID := snapshotPayload.Scope.ScopeID
	targetDeploymentID := prepared.PreparedDeployments[0].DeploymentID
	initial := postgresstore.DeviceSyncInitialAuthorityEvidence{
		Manifest:                preparation.CurrentManifest,
		ValidatedAtMilliseconds: 1_100,
	}
	store := postgresstore.NewRelayStore(pool)
	callbackCount := 0
	callbackFailure := errors.New("injected semantic import failure")
	if _, err := store.ImportPreparedDeviceSyncMigrationStandby(
		ctx, targetDeploymentID, preparation, snapshot,
		fixture.AuthorityAnchor, initial, 3_000,
		func(
			ctx context.Context,
			tx postgresstore.DeviceSyncStandbyImportTransaction,
			validated serviceauthority.ValidatedMigrationTransfer,
		) error {
			callbackCount++
			if err := materializeMinimalDeviceSyncImport(
				ctx, tx, validated.Snapshot.Scope.ScopeID,
			); err != nil {
				return err
			}
			return callbackFailure
		},
	); !errors.Is(err, callbackFailure) || callbackCount != 1 {
		t.Fatalf("failed import err=%v callbacks=%d", err, callbackCount)
	}
	assertNoDeviceSyncImportResidue(t, ctx, pool, principalID)
	if _, err := store.ImportPreparedDeviceSyncMigrationStandby(
		ctx, targetDeploymentID, preparation, snapshot,
		fixture.AuthorityAnchor, initial, 3_000,
		func(
			context.Context,
			postgresstore.DeviceSyncStandbyImportTransaction,
			serviceauthority.ValidatedMigrationTransfer,
		) error {
			return nil
		},
	); err == nil || !strings.Contains(
		err.Error(), "did not create exact semantic parents",
	) {
		t.Fatalf("incomplete semantic import error=%v", err)
	}
	assertNoDeviceSyncImportResidue(t, ctx, pool, principalID)

	imported, err := store.ImportPreparedDeviceSyncMigrationStandby(
		ctx, targetDeploymentID, preparation, snapshot,
		fixture.AuthorityAnchor, initial, 3_000,
		func(
			ctx context.Context,
			tx postgresstore.DeviceSyncStandbyImportTransaction,
			validated serviceauthority.ValidatedMigrationTransfer,
		) error {
			callbackCount++
			if validated.Snapshot.Scope.ScopeID != principalID ||
				validated.Migration.MigrationID != snapshotPayload.MigrationID {
				return errors.New("materializer received another migration")
			}
			return materializeMinimalDeviceSyncImport(ctx, tx, principalID)
		},
	)
	if err != nil || callbackCount != 2 || imported.PrincipalID != principalID ||
		imported.MigrationID != snapshotPayload.MigrationID ||
		imported.ImportingDeploymentID != targetDeploymentID ||
		imported.ExportingDeploymentID != prepared.ActiveDeployment.DeploymentID ||
		imported.StateCommitmentDigest != snapshotPayload.StateCommitmentDigest {
		t.Fatalf("imported=%+v err=%v callbacks=%d", imported, err, callbackCount)
	}
	state, err := store.GetDeviceSyncScopeEnforcement(ctx, principalID)
	if err != nil || state.State != postgresstore.DeviceSyncScopeStandby ||
		state.LocalDeploymentID == nil ||
		*state.LocalDeploymentID != targetDeploymentID || state.Authority == nil ||
		state.Authority.ActiveDeploymentID != prepared.ActiveDeployment.DeploymentID ||
		state.ActiveMigrationImportID == nil ||
		*state.ActiveMigrationImportID != snapshotPayload.MigrationID {
		t.Fatalf("prepared-target standby=%+v err=%v", state, err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE relay_tenants SET updated_at=now() WHERE tenant_id=$1
	`, principalID); err == nil || !strings.Contains(
		err.Error(), "not writable in this transaction",
	) {
		t.Fatalf("prepared-target standby allowed a semantic write: %v", err)
	}

	// Exact durable retries do not re-run semantic import and remain recoverable
	// after both the snapshot and target offer have expired.
	retried, err := store.ImportPreparedDeviceSyncMigrationStandby(
		ctx, targetDeploymentID, preparation, snapshot,
		fixture.AuthorityAnchor, initial, 20_001, nil,
	)
	if err != nil || callbackCount != 2 ||
		retried.ImportedAtMilliseconds != imported.ImportedAtMilliseconds ||
		retried.SnapshotReferenceDigest != imported.SnapshotReferenceDigest {
		t.Fatalf("expired exact retry=%+v err=%v callbacks=%d", retried, err, callbackCount)
	}
	conflictingInitial := initial
	conflictingInitial.ValidatedAtMilliseconds = 1_200
	if _, err := store.ImportPreparedDeviceSyncMigrationStandby(
		ctx, targetDeploymentID, preparation, snapshot,
		fixture.AuthorityAnchor, conflictingInitial, 20_001, nil,
	); !errors.Is(err, postgresstore.ErrDeviceSyncMigrationImportConflict) ||
		callbackCount != 2 {
		t.Fatalf("conflicting retry err=%v callbacks=%d", err, callbackCount)
	}

	if _, err := pool.Exec(ctx, `
		UPDATE device_sync_migration_imports
		SET state_commitment_digest=$2
		WHERE principal_id=$1
	`, principalID, strings.Repeat("e", 64)); err == nil ||
		!strings.Contains(err.Error(), "is immutable") {
		t.Fatalf("mutable import evidence error=%v", err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE device_sync_scope_enforcement
		SET transition_evidence_digest=$2
		WHERE principal_id=$1
	`, principalID, strings.Repeat("e", 64)); err == nil {
		t.Fatal("prepared-target standby accepted conflicting transition evidence")
	}
	if _, err := pool.Exec(ctx, `
		UPDATE device_sync_scope_enforcement
		SET active_migration_import_id=$2
		WHERE principal_id=$1
	`, principalID, uuid.New()); err == nil {
		t.Fatal("prepared-target standby accepted an unknown import identity")
	}

	sharedSpaceTenantID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO relay_tenants (
			tenant_id,version,provisioning_retry_id,
			provisioning_authorization_digest,created_at_milliseconds,
			maximum_domain_count,maximum_aggregate_message_count,
			maximum_aggregate_message_byte_count,maximum_aggregate_blob_count,
			maximum_aggregate_blob_byte_count
		) VALUES ($1,1,$2,$3,1000,1,1,1,1,1)
	`, sharedSpaceTenantID, uuid.New(), strings.Repeat("a", 64)); err != nil {
		t.Fatalf("insert Shared Spaces relay tenant: %v", err)
	}
	if result, err := pool.Exec(ctx, `
		DELETE FROM relay_tenants WHERE tenant_id=$1
	`, sharedSpaceTenantID); err != nil || result.RowsAffected() != 1 {
		t.Fatalf(
			"Shared Spaces relay tenant deletion affected=%d err=%v",
			result.RowsAffected(), err,
		)
	}
}

func materializeMinimalDeviceSyncImport(
	ctx context.Context,
	tx postgresstore.DeviceSyncStandbyImportTransaction,
	principalID uuid.UUID,
) error {
	admissionID := uuid.New()
	domainID := uuid.New()
	deviceID := uuid.New()
	subscriptionID := uuid.New()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO device_sync_account_admissions (
			admission_id,retry_id,version,authorization_digest,
			created_at_milliseconds,expires_at_milliseconds,
			claimed_at_milliseconds,claimed_principal_id
		) VALUES ($1,$2,1,$3,1000,10000,1100,$4)`,
			[]any{admissionID, uuid.New(), strings.Repeat("1", 64), principalID}},
		{`INSERT INTO relay_tenants (
			tenant_id,version,provisioning_retry_id,
			provisioning_authorization_digest,created_at_milliseconds,
			maximum_domain_count,maximum_aggregate_message_count,
			maximum_aggregate_message_byte_count,maximum_aggregate_blob_count,
			maximum_aggregate_blob_byte_count,domain_count
		) VALUES ($1,1,$2,$3,1000,10,100,100000,100,100000,1)`,
			[]any{principalID, uuid.New(), strings.Repeat("2", 64)}},
		{`INSERT INTO relay_domains (
			tenant_id,domain_id,provisioning_retry_id,version,
			administration_digest,created_at_milliseconds,
			maximum_message_count,maximum_message_byte_count,
			maximum_blob_count,maximum_blob_byte_count
		) VALUES ($1,$2,$3,1,$4,1000,100,100000,100,100000)`,
			[]any{principalID, domainID, uuid.New(), strings.Repeat("3", 64)}},
		{`INSERT INTO relay_subscriptions (
			tenant_id,domain_id,subscription_id,create_retry_id,version,
			status,start_sequence,created_at_milliseconds,
			updated_at_milliseconds
		) VALUES ($1,$2,$3,$4,1,'active',0,1000,1000)`,
			[]any{principalID, domainID, subscriptionID, uuid.New()}},
		{`INSERT INTO relay_members (
			tenant_id,domain_id,member_id,subscription_id,version,
			authorization_digest,capabilities,created_at_milliseconds
		) VALUES ($1,$2,$3,$4,1,$5,ARRAY['fetch','publish'],1000)`,
			[]any{principalID, domainID, deviceID, subscriptionID, strings.Repeat("4", 64)}},
		{`INSERT INTO device_sync_principals (
			principal_id,claim_retry_id,account_admission_id,tenant_id,
			control_domain_id,initial_device_id,created_at_milliseconds
		) VALUES ($1,$2,$3,$1,$4,$5,1100)`,
			[]any{principalID, uuid.New(), admissionID, domainID, deviceID}},
		{`INSERT INTO device_sync_devices (
			principal_id,device_id,tenant_id,control_domain_id,
			control_member_id,created_at_milliseconds
		) VALUES ($1,$2,$1,$3,$2,1100)`,
			[]any{principalID, deviceID, domainID}},
	}
	for _, statement := range statements {
		rows, err := tx.Execute(ctx, statement.query, statement.args...)
		if err != nil {
			return err
		}
		if rows != 1 {
			return errors.New("semantic import statement affected an unexpected row count")
		}
	}
	return nil
}

func assertNoDeviceSyncImportResidue(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	principalID uuid.UUID,
) {
	t.Helper()
	var count int
	if err := pool.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM relay_tenants WHERE tenant_id=$1) +
			(SELECT count(*) FROM device_sync_principals WHERE principal_id=$1) +
			(SELECT count(*) FROM device_sync_scope_enforcement WHERE principal_id=$1) +
			(SELECT count(*) FROM device_sync_migration_imports WHERE principal_id=$1)
	`, principalID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("failed import left %d durable scope rows", count)
	}
}
