package boxcontrol

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func sharedWorkerAccessStoreFixture(
	t *testing.T,
) (participantFixture, participantFixture, *MemoryStore, BoxSharedWorkerAdvertisement, BoxSharedWorkerAccessRequest, string) {
	t.Helper()
	owner, store, _, _ := sharedWorkerHTTPFixture(t)
	requester := newParticipantFixture(t)
	requester.anchor.BoxID = owner.anchor.BoxID
	requester.now = owner.now
	ctx := context.Background()
	if err := store.PinOwnerApprovedParticipant(ctx, BoxParticipantEnrollment{
		Anchor: requester.anchor, Device: requester.device,
		RootRecord: requester.root, GrantRecord: requester.grant,
	}, owner.now); err != nil {
		t.Fatal(err)
	}
	_, connectionDigest, err := RandomToken(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	connectionID := uuid.New()
	if err := store.CreateGrant(ctx, ConnectionGrant{
		GrantID: connectionID, TokenDigest: connectionDigest, DeviceName: "Requester Mac",
		CreatedAt: time.UnixMilli(owner.now), LastSeenAt: time.UnixMilli(owner.now),
		ExpiresAt: time.UnixMilli(owner.now).Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	worker := sharedWorkerAdvertisement(owner)
	if err := store.UpsertSharedWorker(ctx, worker, owner.now); err != nil {
		t.Fatal(err)
	}
	code := "135790"
	codeDigest, err := SharedWorkerAccessCodeDigest(code)
	if err != nil {
		t.Fatal(err)
	}
	request := BoxSharedWorkerAccessRequest{
		Version: 1, RequestID: uuid.New(), BoxID: owner.anchor.BoxID,
		WorkerID: worker.WorkerID, RequesterParticipantID: requester.anchor.ParticipantID,
		RequesterDeviceID:       requester.device.DeviceID,
		CapabilitiesDigest:      worker.CapabilitiesDigest,
		RequestedAtMilliseconds: owner.now - 1,
		ExpiresAtMilliseconds:   owner.now + 60_000,
		ConnectionGrantID:       connectionID, ConfirmationCodeDigest: codeDigest,
		Decision: SharedWorkerAccessPending,
	}
	return owner, requester, store, worker, request, code
}

func TestSharedWorkerAccessCodeDigestPortableVector(t *testing.T) {
	digest, err := SharedWorkerAccessCodeDigest("135790")
	if err != nil {
		t.Fatal(err)
	}
	const want = "91be4fd002acb3958c021e50c11cfeb583b1fc9c7dd0df586d65bcfcb3817ea1"
	if got := sharedWorkerAccessCodeDigestString(digest); got != want {
		t.Fatalf("portable access code digest: %s", got)
	}
}

func sharedWorkerAccessGrant(
	owner, requester participantFixture,
	worker BoxSharedWorkerAdvertisement,
	request BoxSharedWorkerAccessRequest,
	code string,
) BoxSharedWorkerAccessGrant {
	digest, _ := SharedWorkerAccessCodeDigest(code)
	return BoxSharedWorkerAccessGrant{
		Version: 1, GrantID: uuid.New(), RequestID: request.RequestID,
		BoxID: worker.BoxID, WorkerID: worker.WorkerID,
		OwnerParticipantID:     owner.anchor.ParticipantID,
		OwnerDeviceID:          owner.device.DeviceID,
		GranteeParticipantID:   requester.anchor.ParticipantID,
		CapabilitiesDigest:     worker.CapabilitiesDigest,
		ConfirmationCodeDigest: sharedWorkerAccessCodeDigestString(digest), Revision: 1,
		GrantedAtMilliseconds: owner.now,
		ExpiresAtMilliseconds: owner.now + 24*60*60*1000,
	}
}

func TestSharedWorkerAccessRequiresOwnerConfirmationAndExactCode(t *testing.T) {
	owner, requester, store, worker, request, code := sharedWorkerAccessStoreFixture(t)
	ctx := context.Background()
	if err := store.CreateSharedWorkerAccessRequest(ctx, request, owner.now); err != nil {
		t.Fatal(err)
	}
	if grants := store.activeSharedWorkerAccessGrants(requester.anchor.ParticipantID, owner.now); len(grants) != 0 {
		t.Fatalf("request alone created access: %+v", grants)
	}
	grant := sharedWorkerAccessGrant(owner, requester, worker, request, code)
	wrongDigest, _ := SharedWorkerAccessCodeDigest("024680")
	wrongGrant := grant
	wrongGrant.ConfirmationCodeDigest = sharedWorkerAccessCodeDigestString(wrongDigest)
	if err := store.ConfirmSharedWorkerAccess(ctx, wrongGrant, wrongDigest, owner.now); !errors.Is(err, ErrSharedWorkerAccessCode) {
		t.Fatalf("wrong code: %v", err)
	}
	codeDigest, _ := SharedWorkerAccessCodeDigest(code)
	if err := store.ConfirmSharedWorkerAccess(ctx, grant, codeDigest, owner.now); err != nil {
		t.Fatal(err)
	}
	status, err := store.SharedWorkerAccessRequest(ctx, request.RequestID, request.ConnectionGrantID, owner.now)
	if err != nil || status.Decision != SharedWorkerAccessApproved || status.Grant == nil ||
		status.Grant.GrantID != grant.GrantID {
		t.Fatalf("approved status: %v %+v", err, status)
	}
	if grants := store.activeSharedWorkerAccessGrants(requester.anchor.ParticipantID, owner.now); len(grants) != 1 || grants[0].WorkerID != worker.WorkerID {
		t.Fatalf("active grants: %+v", grants)
	}
	if err := store.RevokeSharedWorkerAccess(ctx, worker.BoxID, grant.GrantID,
		owner.anchor.ParticipantID, 2, owner.now+1); err != nil {
		t.Fatal(err)
	}
	if grants := store.activeSharedWorkerAccessGrants(requester.anchor.ParticipantID, owner.now+1); len(grants) != 0 {
		t.Fatalf("revoked grant remained active: %+v", grants)
	}
}

func TestSharedWorkerAccessLocksAfterFiveWrongCodes(t *testing.T) {
	owner, requester, store, worker, request, code := sharedWorkerAccessStoreFixture(t)
	ctx := context.Background()
	if err := store.CreateSharedWorkerAccessRequest(ctx, request, owner.now); err != nil {
		t.Fatal(err)
	}
	wrongDigest, _ := SharedWorkerAccessCodeDigest("024680")
	grant := sharedWorkerAccessGrant(owner, requester, worker, request, code)
	grant.ConfirmationCodeDigest = sharedWorkerAccessCodeDigestString(wrongDigest)
	for attempt := 1; attempt <= maximumSharedWorkerAccessCodeFailures; attempt++ {
		err := store.ConfirmSharedWorkerAccess(ctx, grant, wrongDigest, owner.now)
		want := ErrSharedWorkerAccessCode
		if attempt == maximumSharedWorkerAccessCodeFailures {
			want = ErrSharedWorkerAccessLocked
		}
		if !errors.Is(err, want) {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
	}
	codeDigest, _ := SharedWorkerAccessCodeDigest(code)
	grant.ConfirmationCodeDigest = sharedWorkerAccessCodeDigestString(codeDigest)
	if err := store.ConfirmSharedWorkerAccess(ctx, grant, codeDigest, owner.now); !errors.Is(err, ErrSharedWorkerAccess) {
		t.Fatalf("locked request accepted correct code: %v", err)
	}
	status, err := store.SharedWorkerAccessRequest(ctx, request.RequestID, request.ConnectionGrantID, owner.now)
	if err != nil || status.Decision != SharedWorkerAccessRejected {
		t.Fatalf("locked status: %v %+v", err, status)
	}
}

func TestPostgresSharedWorkerAccessSurvivesRestart(t *testing.T) {
	databaseURL := os.Getenv("FACETS_BOX_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("FACETS_BOX_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "shared_worker_access_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	openStore := func() (*PostgresStore, *pgxpool.Pool) {
		pool, err := pgxpool.NewWithConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		return NewPostgresStore(pool), pool
	}
	store, pool := openStore()
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	owner := newParticipantFixture(t)
	requester := newParticipantFixture(t)
	requester.anchor.BoxID = owner.anchor.BoxID
	requester.now = owner.now
	if err := store.Initialize(ctx, State{BoxID: owner.anchor.BoxID, ActivationVerifier: "activation"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Claim(ctx, "activation", "owner", "Box", time.UnixMilli(owner.now)); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []participantFixture{owner, requester} {
		if err := store.PinOwnerApprovedParticipant(ctx, BoxParticipantEnrollment{
			Anchor: fixture.anchor, Device: fixture.device,
			RootRecord: fixture.root, GrantRecord: fixture.grant,
		}, owner.now); err != nil {
			t.Fatal(err)
		}
	}
	connectionID := uuid.New()
	if err := store.CreateGrant(ctx, ConnectionGrant{
		GrantID: connectionID, DeviceName: "Requester Mac",
		CreatedAt: time.UnixMilli(owner.now), LastSeenAt: time.UnixMilli(owner.now),
		ExpiresAt: time.UnixMilli(owner.now).Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	worker := sharedWorkerAdvertisement(owner)
	if err := store.UpsertSharedWorker(ctx, worker, owner.now); err != nil {
		t.Fatal(err)
	}
	code := "135790"
	codeDigest, _ := SharedWorkerAccessCodeDigest(code)
	request := BoxSharedWorkerAccessRequest{
		Version: 1, RequestID: uuid.New(), BoxID: owner.anchor.BoxID,
		WorkerID: worker.WorkerID, RequesterParticipantID: requester.anchor.ParticipantID,
		RequesterDeviceID: requester.device.DeviceID, CapabilitiesDigest: worker.CapabilitiesDigest,
		RequestedAtMilliseconds: owner.now, ExpiresAtMilliseconds: owner.now + 60_000,
		ConnectionGrantID: connectionID, ConfirmationCodeDigest: codeDigest,
		Decision: SharedWorkerAccessPending,
	}
	if err := store.CreateSharedWorkerAccessRequest(ctx, request, owner.now); err != nil {
		t.Fatal(err)
	}
	pool.Close()
	store, pool = openStore()
	defer pool.Close()
	grant := sharedWorkerAccessGrant(owner, requester, worker, request, code)
	if err := store.ConfirmSharedWorkerAccess(ctx, grant, codeDigest, owner.now); err != nil {
		t.Fatal(err)
	}
	status, err := store.SharedWorkerAccessRequest(ctx, request.RequestID, connectionID, owner.now)
	if err != nil || status.Decision != SharedWorkerAccessApproved || status.Grant == nil ||
		status.Grant.GrantID != grant.GrantID {
		t.Fatalf("approved after restart: %v %+v", err, status)
	}
}
