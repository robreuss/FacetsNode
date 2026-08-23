package postgres_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/computepool"
	postgresstore "github.com/robreuss/FacetsNode/internal/postgres"
)

func TestPostgresComputePoolLifecycleIsIndependent(t *testing.T) {
	databaseURL := os.Getenv("FACETS_SERVER_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("FACETS_SERVER_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	lockDisposablePostgres(t, ctx, databaseURL)
	pool := openPool(t, ctx, databaseURL)
	defer pool.Close()
	if err := postgresstore.MigrateComputePool(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `TRUNCATE compute_pools CASCADE`); err != nil {
		t.Fatal(err)
	}

	store := postgresstore.NewComputePoolStore(pool)
	computePool, enrollment, offering := postgresComputePoolFixture()
	if err := store.CreatePool(ctx, computePool); err != nil {
		t.Fatal(err)
	}
	if err := store.PutWorkerEnrollment(ctx, 0, enrollment); err != nil {
		t.Fatal(err)
	}
	if err := store.PutOffering(ctx, 0, offering); err != nil {
		t.Fatal(err)
	}
	status, err := store.GetPoolStatus(ctx, computePool.PoolID)
	if err != nil || status.Validate() != nil || len(status.WorkerEnrollments) != 1 ||
		len(status.Offerings) != 1 {
		t.Fatalf("Compute Pool status=%+v error=%v", status, err)
	}
	if err := store.DeletePool(ctx, computePool.PoolID, computePool.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetPoolStatus(ctx, computePool.PoolID); !errors.Is(err, computepool.ErrNotFound) {
		t.Fatalf("deleted Compute Pool remained available: %v", err)
	}
	var enrollmentCount, offeringCount int
	if err := pool.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM compute_pool_worker_enrollments),
			(SELECT count(*) FROM compute_pool_offerings)
	`).Scan(&enrollmentCount, &offeringCount); err != nil {
		t.Fatal(err)
	}
	if enrollmentCount != 0 || offeringCount != 0 {
		t.Fatalf(
			"Pool-owned records survived deletion: enrollments=%d offerings=%d",
			enrollmentCount,
			offeringCount,
		)
	}
}

func postgresComputePoolFixture() (
	computepool.Pool,
	computepool.WorkerEnrollment,
	computepool.Offering,
) {
	poolID := uuid.MustParse("81000000-0000-0000-0000-000000000001")
	ceiling := computepool.ResourceCeiling{
		MaximumInputBytes: 1_048_576, MaximumOutputBytes: 1_048_576,
		MaximumMemoryBytes: 8_589_934_592, MaximumWallTimeMilliseconds: 300_000,
	}
	pool := computepool.Pool{
		Version: computepool.SchemaVersion, PoolID: poolID,
		OwnerAuthorityID:  uuid.MustParse("82000000-0000-0000-0000-000000000001"),
		AuthorityRevision: 1, AuthorityManifestDigest: stringOf("1", 64),
		DisplayName: "PostgreSQL Compute", Enabled: true, Revision: 1,
		CreatedAtMilliseconds: 1_000, UpdatedAtMilliseconds: 1_000,
	}
	enrollment := computepool.WorkerEnrollment{
		Version:      computepool.SchemaVersion,
		EnrollmentID: uuid.MustParse("83000000-0000-0000-0000-000000000001"),
		PoolID:       poolID, WorkerID: uuid.MustParse("84000000-0000-0000-0000-000000000001"),
		WorkerOwnerAuthorityID:  uuid.MustParse("85000000-0000-0000-0000-000000000001"),
		PublicSigningKeyEd25519: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		SigningKeyFingerprint:   "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925",
		ConsentRevision:         1, Enabled: true, Revision: 1,
		CreatedAtMilliseconds: 1_000, UpdatedAtMilliseconds: 1_000,
	}
	offering := computepool.Offering{
		Version:    computepool.SchemaVersion,
		OfferingID: uuid.MustParse("86000000-0000-0000-0000-000000000001"),
		PoolID:     poolID, WorkerEnrollmentID: enrollment.EnrollmentID,
		ProviderIdentifier: "example.provider", ModelIdentifiers: []string{"example.model"},
		AllowedOperations:    []string{"classify"},
		PlaintextBoundary:    computepool.PlaintextBoundaryExternalProvider,
		NetworkEgress:        computepool.NetworkEgressDirectInternet,
		RetentionDeclaration: "provider-retention-v1",
		TrainingDeclaration:  "provider-training-v1", PricingRevision: 1,
		ResourceCeiling: ceiling, Enabled: true, Revision: 1,
		CreatedAtMilliseconds: 1_000, UpdatedAtMilliseconds: 1_000,
	}
	return pool, enrollment, offering
}

func stringOf(value string, count int) string {
	result := ""
	for len(result) < count {
		result += value
	}
	return result
}
