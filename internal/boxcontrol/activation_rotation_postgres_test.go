package boxcontrol

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Always isolate tables in a fresh schema, even when a test database is shared.
func TestPostgresActivationRotationIsAtomicAndPreservesIdentity(t *testing.T) {
	databaseURL := os.Getenv("FACETS_BOX_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("FACETS_BOX_TEST_DATABASE_URL is not set")
	}
	withFastArgon(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "claim_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	store := NewPostgresStore(pool)
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	prior, _ := HashActivationCode("OLD-ACTIVATION-CODE")
	first, _ := HashActivationCode("NEW-ACTIVATION-CODE")
	second, _ := HashActivationCode("OTHER-ACTIVATION-CODE")
	if err := store.Initialize(ctx, State{BoxID: id, ActivationVerifier: prior}); err != nil {
		t.Fatal(err)
	}
	if err := store.ReplaceActivationVerifier(ctx, uuid.New(), prior, first); err == nil {
		t.Fatal("wrong Box accepted")
	}
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, next := range []string{first, second} {
		wg.Add(1)
		go func(replacement string) {
			defer wg.Done()
			results <- store.ReplaceActivationVerifier(ctx, id, prior, replacement)
		}(next)
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatal("concurrent rotations did not have exactly one winner")
	}
	state, err := store.State(ctx)
	if err != nil || state.BoxID != id || state.Claimed() || verifySecret(state.ActivationVerifier, "OLD-ACTIVATION-CODE") {
		t.Fatal("rotation changed identity or retained old activation authority")
	}
	if !verifySecret(state.ActivationVerifier, "NEW-ACTIVATION-CODE") && !verifySecret(state.ActivationVerifier, "OTHER-ACTIVATION-CODE") {
		t.Fatal("winning activation code not accepted")
	}
	if err := store.Claim(ctx, prior, "owner", "Box", time.Now()); err == nil {
		t.Fatal("old verifier claimed Box")
	}
	if err := store.Claim(ctx, state.ActivationVerifier, "owner", "Box", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := store.ReplaceActivationVerifier(ctx, id, state.ActivationVerifier, prior); err == nil {
		t.Fatal("claimed Box rotated")
	}
}
