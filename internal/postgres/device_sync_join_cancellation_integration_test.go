package postgres_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/devicesync"
	postgresstore "github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/testfixture"
)

func TestPostgresDeviceSyncJoinCancellationPersists(t *testing.T) {
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
	fixture, err := testfixture.LoadDeviceSyncJoinRequestFixture()
	if err != nil {
		t.Fatal(err)
	}
	// Unique identifiers keep the test independent of unrelated fixture rows.
	fixture.Request.RequestID = uuid.New()
	fixture.Request.RetryID = uuid.New()
	request, err := fixture.Request.JoinRequest()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM device_sync_join_requests WHERE pin_authorization_digest=$1`, request.PINAuthorizationDigest); err != nil {
		t.Fatal(err)
	}
	store := postgresstore.NewRelayStore(pool)
	if _, err := store.CreateJoinRequest(ctx, request, request.CreatedAtMilliseconds); err != nil {
		t.Fatal(err)
	}
	credential := devicesync.JoinRequestCredential{RequestID: request.RequestID, Token: fixture.Request.PollingAuthorizationToken}
	wrong := credential
	wrong.RequestID = uuid.New()
	if err := store.CancelJoinRequest(ctx, wrong); !devicesync.ErrorHasCode(err, devicesync.CodeJoinRequestNotFound) {
		t.Fatalf("wrong request: %v", err)
	}
	wrong = credential
	wrong.Token = fixture.Request.CandidateBootstrapPrivateKey
	if err := store.CancelJoinRequest(ctx, wrong); !devicesync.ErrorHasCode(err, devicesync.CodeUnauthorized) {
		t.Fatalf("wrong credential: %v", err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := store.CancelJoinRequest(ctx, credential); err != nil {
			t.Fatal(err)
		}
	}
	// Reopen the store and verify cancellation is persisted, not process state.
	reopened := postgresstore.NewRelayStore(pool)
	if _, err := reopened.FetchJoinRequestBootstrap(ctx, credential, request.CreatedAtMilliseconds); !devicesync.ErrorHasCode(err, devicesync.CodeJoinRequestNotFound) {
		t.Fatalf("fetch after cancellation: %v", err)
	}
	if _, err := reopened.CreateJoinRequest(ctx, request, request.CreatedAtMilliseconds); !devicesync.ErrorHasCode(err, devicesync.CodeJoinRequestCollision) {
		t.Fatalf("request resurrection: %v", err)
	}
	var cancelled bool
	if err := pool.QueryRow(ctx, `SELECT cancelled FROM device_sync_join_requests WHERE request_id=$1`, request.RequestID).Scan(&cancelled); err != nil || !cancelled {
		t.Fatalf("cancelled=%v err=%v", cancelled, err)
	}
}
