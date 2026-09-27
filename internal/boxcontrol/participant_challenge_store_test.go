package boxcontrol

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type participantChallengeStoreForTest interface {
	IssueParticipantChallenge(context.Context, BoxParticipantChallenge, int64) error
	ConsumeParticipantChallenge(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID, int64) (bool, error)
}

func testParticipantChallenges(t *testing.T, store participantChallengeStoreForTest, boxID uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	challenge := BoxParticipantChallenge{
		BoxID: boxID, ParticipantID: uuid.New(), DeviceID: uuid.New(), ChallengeID: uuid.New(),
		IssuedAtMilliseconds: 1_000_000, ExpiresAtMilliseconds: 1_060_000,
	}
	if err := store.IssueParticipantChallenge(ctx, challenge, 1_000_000); err != nil {
		t.Fatal(err)
	}
	if err := store.IssueParticipantChallenge(ctx, challenge, 1_000_000); err == nil {
		t.Fatal("duplicate challenge ID was issued")
	}
	for _, wrong := range []struct {
		box, participant, device uuid.UUID
	}{
		{uuid.New(), challenge.ParticipantID, challenge.DeviceID},
		{boxID, uuid.New(), challenge.DeviceID},
		{boxID, challenge.ParticipantID, uuid.New()},
	} {
		consumed, err := store.ConsumeParticipantChallenge(ctx,
			wrong.box, wrong.participant, wrong.device, challenge.ChallengeID, 1_001_000)
		if err != nil || consumed {
			t.Fatal("wrong identity consumed the challenge", err)
		}
	}

	var wg sync.WaitGroup
	results := make(chan bool, 12)
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			consumed, err := store.ConsumeParticipantChallenge(ctx,
				boxID, challenge.ParticipantID, challenge.DeviceID, challenge.ChallengeID, 1_002_000)
			if err != nil {
				t.Errorf("consume challenge: %v", err)
			}
			results <- consumed
		}()
	}
	wg.Wait()
	close(results)
	winners := 0
	for consumed := range results {
		if consumed {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("concurrent consumption had %d winners; want 1", winners)
	}
	consumed, err := store.ConsumeParticipantChallenge(ctx,
		boxID, challenge.ParticipantID, challenge.DeviceID, challenge.ChallengeID, 1_003_000)
	if err != nil || consumed {
		t.Fatal("replay consumed the challenge", err)
	}

	expired := challenge
	expired.ChallengeID = uuid.New()
	if err := store.IssueParticipantChallenge(ctx, expired, 1_000_000); err != nil {
		t.Fatal(err)
	}
	consumed, err = store.ConsumeParticipantChallenge(ctx,
		boxID, expired.ParticipantID, expired.DeviceID, expired.ChallengeID, expired.ExpiresAtMilliseconds)
	if err != nil || consumed {
		t.Fatal("expired challenge was consumed", err)
	}
	tooLong := challenge
	tooLong.ChallengeID = uuid.New()
	tooLong.ExpiresAtMilliseconds = tooLong.IssuedAtMilliseconds + maximumParticipantProofAgeMilliseconds + 1
	if err := store.IssueParticipantChallenge(ctx, tooLong, tooLong.IssuedAtMilliseconds); err == nil {
		t.Fatal("overlong challenge was issued")
	}
	wrongBox := challenge
	wrongBox.ChallengeID = uuid.New()
	wrongBox.BoxID = uuid.New()
	if err := store.IssueParticipantChallenge(ctx, wrongBox, wrongBox.IssuedAtMilliseconds); err == nil {
		t.Fatal("challenge was issued for a different Box")
	}
}

func TestMemoryParticipantChallengesRequireClaimAndConsumeOnce(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	boxID := uuid.New()
	if err := store.Initialize(ctx, State{BoxID: boxID, ActivationVerifier: "activation"}); err != nil {
		t.Fatal(err)
	}
	challenge := BoxParticipantChallenge{
		BoxID: boxID, ParticipantID: uuid.New(), DeviceID: uuid.New(), ChallengeID: uuid.New(),
		IssuedAtMilliseconds: 1_000_000, ExpiresAtMilliseconds: 1_060_000,
	}
	if err := store.IssueParticipantChallenge(ctx, challenge, challenge.IssuedAtMilliseconds); err == nil {
		t.Fatal("unclaimed Box issued participant challenge")
	}
	if err := store.Claim(ctx, "activation", "owner", "Box", time.Now()); err != nil {
		t.Fatal(err)
	}
	testParticipantChallenges(t, store, boxID)
}

func TestBoxParticipantProofUsesIssuedMemoryChallenge(t *testing.T) {
	fixture := newParticipantFixture(t)
	store := NewMemoryStore()
	ctx := context.Background()
	if err := store.Initialize(ctx, State{BoxID: fixture.anchor.BoxID, ActivationVerifier: "activation"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Claim(ctx, "activation", "owner", "Box", time.Now()); err != nil {
		t.Fatal(err)
	}
	challenge := BoxParticipantChallenge{
		BoxID: fixture.anchor.BoxID, ParticipantID: fixture.anchor.ParticipantID,
		DeviceID: fixture.device.DeviceID, ChallengeID: fixture.challengeID,
		IssuedAtMilliseconds: fixture.now - 200, ExpiresAtMilliseconds: fixture.now + 30_000,
	}
	if err := store.IssueParticipantChallenge(ctx, challenge, fixture.now); err != nil {
		t.Fatal(err)
	}
	verifier, err := NewBoxParticipantProofVerifier(store)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.authorize(verifier, nil); err != nil {
		t.Fatal(err)
	}
	if err := fixture.authorize(verifier, nil); !errors.Is(err, ErrParticipantReplay) {
		t.Fatalf("replayed proof: got %v", err)
	}
}

func TestPostgresParticipantChallengeSurvivesRestartAndConsumesOnce(t *testing.T) {
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
	schema := "participant_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	boxID := uuid.New()
	if err := store.Initialize(ctx, State{BoxID: boxID, ActivationVerifier: "activation"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Claim(ctx, "activation", "owner", "Box", time.Now()); err != nil {
		t.Fatal(err)
	}
	testParticipantChallenges(t, store, boxID)

	challenge := BoxParticipantChallenge{
		BoxID: boxID, ParticipantID: uuid.New(), DeviceID: uuid.New(), ChallengeID: uuid.New(),
		IssuedAtMilliseconds: 2_000_000, ExpiresAtMilliseconds: 2_060_000,
	}
	if err := store.IssueParticipantChallenge(ctx, challenge, challenge.IssuedAtMilliseconds); err != nil {
		t.Fatal(err)
	}
	// A newly constructed service store sees the same unconsumed database row.
	restarted := NewPostgresStore(pool)
	consumed, err := restarted.ConsumeParticipantChallenge(ctx, boxID,
		challenge.ParticipantID, challenge.DeviceID, challenge.ChallengeID, 2_001_000)
	if err != nil || !consumed {
		t.Fatal("challenge did not survive store restart", err)
	}
	consumed, err = store.ConsumeParticipantChallenge(ctx, boxID,
		challenge.ParticipantID, challenge.DeviceID, challenge.ChallengeID, 2_002_000)
	if err != nil || consumed {
		t.Fatal("restart allowed challenge replay", err)
	}

	fixture := newParticipantFixture(t)
	enrollment := BoxParticipantEnrollment{
		Anchor: fixture.anchor, Device: fixture.device,
		RootRecord: fixture.root, GrantRecord: fixture.grant,
	}
	enrollment.Anchor.BoxID = boxID
	if err := store.PinOwnerApprovedParticipant(ctx, enrollment, fixture.now); err != nil {
		t.Fatal(err)
	}
	if err := restarted.PinOwnerApprovedParticipant(ctx, enrollment, fixture.now); err != nil {
		t.Fatalf("exact enrollment retry: %v", err)
	}
	pinned, err := restarted.PinnedParticipant(ctx, boxID,
		enrollment.Anchor.ParticipantID, enrollment.Device.DeviceID)
	if err != nil || !sameParticipantEnrollment(pinned, enrollment) {
		t.Fatal("pinned enrollment did not survive store restart", err)
	}
	modified := enrollment
	modified.Anchor.ApprovedAtMilliseconds++
	if err := restarted.PinOwnerApprovedParticipant(ctx, modified, fixture.now); !errors.Is(err, ErrParticipantAuthority) {
		t.Fatalf("changed enrollment replaced pin: %v", err)
	}
	duplicateRoot := cloneParticipantEnrollment(enrollment)
	duplicateRoot.Anchor.ParticipantID = uuid.New()
	duplicateRoot.Device.ParticipantID = duplicateRoot.Anchor.ParticipantID
	if err := restarted.PinOwnerApprovedParticipant(ctx, duplicateRoot, fixture.now); !errors.Is(err, ErrParticipantAuthority) {
		t.Fatalf("second participant reused scoped root: %v", err)
	}
}
