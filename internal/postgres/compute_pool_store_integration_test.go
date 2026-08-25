package postgres_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/computepool"
	postgresstore "github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/testfixture"
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
	computePool, enrollment, card, offering := postgresComputePoolFixture()
	if err := store.CreatePool(ctx, computePool); err != nil {
		t.Fatal(err)
	}
	if err := store.PutWorkerEnrollment(ctx, 0, enrollment); err != nil {
		t.Fatal(err)
	}
	if err := store.PutWorkerCard(ctx, 0, card); err != nil {
		t.Fatal(err)
	}
	if err := store.PutOffering(ctx, 0, offering); err != nil {
		t.Fatal(err)
	}
	status, err := store.GetPoolStatus(ctx, computePool.PoolID)
	if err != nil || status.Validate() != nil || len(status.WorkerEnrollments) != 1 ||
		len(status.WorkerCards) != 1 || len(status.Offerings) != 1 {
		t.Fatalf("Compute Pool status=%+v error=%v", status, err)
	}
	if err := store.DeletePool(ctx, computePool.PoolID, computePool.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetPoolStatus(ctx, computePool.PoolID); !errors.Is(err, computepool.ErrNotFound) {
		t.Fatalf("deleted Compute Pool remained available: %v", err)
	}
	var enrollmentCount, cardCount, offeringCount int
	if err := pool.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM compute_pool_worker_enrollments),
			(SELECT count(*) FROM compute_pool_worker_cards),
			(SELECT count(*) FROM compute_pool_offerings)
	`).Scan(&enrollmentCount, &cardCount, &offeringCount); err != nil {
		t.Fatal(err)
	}
	if enrollmentCount != 0 || cardCount != 0 || offeringCount != 0 {
		t.Fatalf(
			"Pool-owned records survived deletion: enrollments=%d cards=%d offerings=%d",
			enrollmentCount,
			cardCount,
			offeringCount,
		)
	}
}

func postgresComputePoolFixture() (
	computepool.Pool,
	computepool.WorkerEnrollment,
	computepool.SignedWorkerCard,
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
	workerPrivateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	workerPublicKey := workerPrivateKey.Public().(ed25519.PublicKey)
	workerFingerprint := sha256.Sum256(workerPublicKey)
	enrollment := computepool.WorkerEnrollment{
		Version:      computepool.SchemaVersion,
		EnrollmentID: uuid.MustParse("83000000-0000-0000-0000-000000000001"),
		PoolID:       poolID, WorkerID: uuid.MustParse("84000000-0000-0000-0000-000000000001"),
		WorkerOwnerAuthorityID:  uuid.MustParse("85000000-0000-0000-0000-000000000001"),
		PublicSigningKeyEd25519: base64.RawURLEncoding.EncodeToString(workerPublicKey),
		SigningKeyFingerprint:   hex.EncodeToString(workerFingerprint[:]),
		ConsentRevision:         1, Enabled: true, Revision: 1,
		CreatedAtMilliseconds: 1_000, UpdatedAtMilliseconds: 1_000,
	}
	card := testfixture.ComputeWorkerCard(
		uuid.MustParse("85500000-0000-0000-0000-000000000001"),
		poolID,
		enrollment.EnrollmentID,
		enrollment.WorkerOwnerAuthorityID,
		"example.provider",
	)
	cardDigest, err := card.Digest()
	if err != nil {
		panic(err)
	}
	signedCard, err := computepool.NewSignedWorkerCard(card, workerPrivateKey)
	if err != nil {
		panic(err)
	}
	offering := computepool.Offering{
		Version:    computepool.SchemaVersion,
		OfferingID: uuid.MustParse("86000000-0000-0000-0000-000000000001"),
		PoolID:     poolID, WorkerEnrollmentID: enrollment.EnrollmentID,
		WorkerCardID: card.WorkerCardID, WorkerCardRevision: card.Revision,
		WorkerCardDigest:   cardDigest,
		ProviderIdentifier: "example.provider", ModelIdentifiers: []string{"example.model"},
		AllowedOperations: []string{"classify"},
		InteractionModes:  []computepool.InteractionMode{computepool.InteractionBatch},
		DataHandlingProfile: computepool.DataHandlingProfile{
			PlaintextBoundary:   computepool.PlaintextBoundaryPrivateInfrastructure,
			NetworkEgress:       computepool.NetworkEgressNone,
			RequestRetention:    computepool.RetentionPolicy{Mode: computepool.RetentionNone},
			ResultRetention:     computepool.RetentionPolicy{Mode: computepool.RetentionNone},
			DiagnosticRetention: computepool.RetentionPolicy{Mode: computepool.RetentionNone},
			TrainingUse:         computepool.TrainingProhibited, ToolAccess: computepool.ToolAccessNone,
			ProviderIdentifier: "example.provider",
		},
		PricingRevision: 1,
		ResourceCeiling: ceiling, Enabled: true, Revision: 1,
		CreatedAtMilliseconds: 1_000, UpdatedAtMilliseconds: 1_000,
	}
	return pool, enrollment, signedCard, offering
}

func stringOf(value string, count int) string {
	result := ""
	for len(result) < count {
		result += value
	}
	return result
}
