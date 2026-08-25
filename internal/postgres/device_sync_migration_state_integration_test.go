package postgres_test

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	postgresstore "github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

func TestPostgresDeviceSyncMigrationStateRoundTrip(t *testing.T) {
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

	principalID := uuid.New()
	store := postgresstore.NewRelayStore(pool)
	postgresBootstrapDeviceSyncPrincipal(
		t, ctx, store, principalID, uuid.New(), 1_000,
	)
	firstState, firstInventory, firstDigests := exportPostgresDeviceSyncMigrationState(
		t, ctx, pool, principalID,
	)
	var enforcementState string
	var exportEvidenceCount int64
	if err := pool.QueryRow(ctx, `
		SELECT state FROM device_sync_scope_enforcement WHERE principal_id=$1
	`, principalID).Scan(&enforcementState); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM device_sync_migration_exports WHERE principal_id=$1
	`, principalID).Scan(&exportEvidenceCount); err != nil {
		t.Fatal(err)
	}
	if enforcementState != "standby" || exportEvidenceCount != 0 {
		t.Fatalf(
			"low-level artifact export changed authority state=%q evidence=%d",
			enforcementState, exportEvidenceCount,
		)
	}

	if _, err := pool.Exec(ctx, `
		TRUNCATE device_sync_account_admissions, relay_tenants CASCADE
	`); err != nil {
		t.Fatal(err)
	}
	importTransaction, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatal(err)
	}
	validated := serviceauthority.ValidatedMigrationTransfer{
		Snapshot: serviceauthority.MigrationSnapshotPayload{
			Scope: serviceauthority.Scope{
				Kind: serviceauthority.ScopeDeviceSync, ScopeID: principalID,
			},
			Artifacts: []serviceauthority.MigrationArtifactDescriptor{
				{
					ArtifactID:     uuid.New(),
					ByteCount:      firstDigests.StateArtifactByteCount,
					Kind:           serviceauthority.ArtifactServiceStateSnapshot,
					TransferDigest: firstDigests.StateArtifactSHA256.String(),
				},
				{
					ArtifactID:     uuid.New(),
					ByteCount:      firstDigests.BlobInventoryByteCount,
					Kind:           serviceauthority.ArtifactBlobInventory,
					TransferDigest: firstDigests.BlobInventorySHA256.String(),
				},
			},
			StateCommitmentDigest: firstDigests.StateCommitment.String(),
		},
	}
	if err := postgresstore.MaterializeValidatedDeviceSyncMigrationState(
		ctx, importTransaction, validated,
		postgresstore.DeviceSyncMigrationStagedArtifacts{
			ServiceState:  bytes.NewReader(firstState),
			BlobInventory: bytes.NewReader(firstInventory),
		},
	); err != nil {
		_ = importTransaction.Rollback(ctx)
		t.Fatal(err)
	}
	if _, err := importTransaction.Exec(ctx, `
		INSERT INTO device_sync_scope_enforcement (
			principal_id, tenant_id, state
		) VALUES ($1, $1, 'standby')
	`, principalID); err != nil {
		_ = importTransaction.Rollback(ctx)
		t.Fatal(err)
	}
	if err := importTransaction.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	secondState, secondInventory, secondDigests := exportPostgresDeviceSyncMigrationState(
		t, ctx, pool, principalID,
	)
	if !bytes.Equal(firstState, secondState) ||
		!bytes.Equal(firstInventory, secondInventory) ||
		firstDigests != secondDigests {
		t.Fatal("PostgreSQL export/import/export did not preserve canonical logical state")
	}
}

type postgresDeviceSyncMigrationBeginner interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

func exportPostgresDeviceSyncMigrationState(
	t *testing.T,
	ctx context.Context,
	database postgresDeviceSyncMigrationBeginner,
	principalID uuid.UUID,
) ([]byte, []byte, postgresstore.DeviceSyncMigrationArtifactDigests) {
	t.Helper()
	transaction, err := database.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	var state, inventory bytes.Buffer
	digests, err := postgresstore.ExportDeviceSyncMigrationState(
		ctx, transaction, principalID, &state, &inventory,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := postgresstore.ValidateDeviceSyncMigrationStateArtifact(
		ctx, bytes.NewReader(state.Bytes()), principalID, digests.StateArtifactSHA256,
	); err != nil {
		t.Fatal(err)
	}
	if err := postgresstore.ValidateDeviceSyncMigrationBlobInventory(
		ctx, bytes.NewReader(inventory.Bytes()), principalID, digests.BlobInventorySHA256,
	); err != nil {
		t.Fatal(err)
	}
	return state.Bytes(), inventory.Bytes(), digests
}
