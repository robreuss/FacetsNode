package postgres_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	postgresstore "github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/rendezvous"
	"github.com/robreuss/FacetsNode/internal/testfixture"
)

func TestPostgresStorePersistsOpaqueMailboxAcrossPoolRestart(t *testing.T) {
	databaseURL := os.Getenv("FACETS_NODE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("FACETS_NODE_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	fixture, err := testfixture.LoadRendezvous()
	if err != nil {
		t.Fatal(err)
	}
	pool := openPool(t, ctx, databaseURL)
	if err := postgresstore.Migrate(ctx, pool); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "TRUNCATE pairing_messages, pairing_routes"); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	store := postgresstore.NewStore(pool)
	acceptance, err := store.CreateRoute(
		ctx,
		fixture.Registration,
		fixture.SponsorAccess.RouterAuthorizationToken,
		3_000,
	)
	if err != nil || acceptance != rendezvous.AcceptanceAccepted {
		pool.Close()
		t.Fatalf("create acceptance=%q err=%v", acceptance, err)
	}
	candidate := rendezvous.Credential{
		RouteID: fixture.Registration.RouteID,
		Role:    rendezvous.RoleCandidate,
		Token:   fixture.CandidateAccess.RouterAuthorizationToken,
	}
	acceptance, err = store.Publish(ctx, candidate, fixture.Envelope, 3_000)
	if err != nil || acceptance != rendezvous.AcceptanceAccepted {
		pool.Close()
		t.Fatalf("publish acceptance=%q err=%v", acceptance, err)
	}
	pool.Close()

	pool = openPool(t, ctx, databaseURL)
	defer pool.Close()
	restartedStore := postgresstore.NewStore(pool)
	sponsor := rendezvous.Credential{
		RouteID: fixture.Registration.RouteID,
		Role:    rendezvous.RoleSponsor,
		Token:   fixture.SponsorAccess.RouterAuthorizationToken,
	}
	messages, err := restartedStore.Fetch(ctx, sponsor, 3_000)
	if err != nil || len(messages) != 1 || messages[0] != fixture.Envelope {
		t.Fatalf("restart fetch count=%d err=%v", len(messages), err)
	}
	if err := restartedStore.Acknowledge(
		ctx, sponsor, fixture.Envelope.MessageID, 3_000,
	); err != nil {
		t.Fatal(err)
	}
	messages, err = restartedStore.Fetch(ctx, sponsor, 3_000)
	if err != nil || len(messages) != 0 {
		t.Fatalf("acknowledged fetch count=%d err=%v", len(messages), err)
	}
}

func openPool(t *testing.T, ctx context.Context, databaseURL string) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	return pool
}
