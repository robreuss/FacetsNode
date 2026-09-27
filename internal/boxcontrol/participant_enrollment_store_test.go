package boxcontrol

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMemoryPinsExactOwnerApprovedParticipantAndUsesStoredProofAuthority(t *testing.T) {
	fixture := newParticipantFixture(t)
	enrollment := BoxParticipantEnrollment{
		Anchor: fixture.anchor, Device: fixture.device,
		RootRecord: fixture.root, GrantRecord: fixture.grant,
	}
	store := NewMemoryStore()
	ctx := context.Background()
	if err := store.Initialize(ctx, State{BoxID: fixture.anchor.BoxID, ActivationVerifier: "activation"}); err != nil {
		t.Fatal(err)
	}
	if err := store.PinOwnerApprovedParticipant(ctx, enrollment, fixture.now); !errors.Is(err, ErrParticipantAuthority) {
		t.Fatalf("unclaimed Box pin: %v", err)
	}
	if err := store.Claim(ctx, "activation", "owner", "Box", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := store.PinOwnerApprovedParticipant(ctx, enrollment, fixture.now); err != nil {
		t.Fatal(err)
	}
	if err := store.PinOwnerApprovedParticipant(ctx, enrollment, fixture.now); err != nil {
		t.Fatalf("exact retry: %v", err)
	}
	pinned, err := store.PinnedParticipant(ctx, fixture.anchor.BoxID,
		fixture.anchor.ParticipantID, fixture.device.DeviceID)
	if err != nil || !sameParticipantEnrollment(pinned, enrollment) {
		t.Fatal("pinned authority changed", err)
	}
	pinned.RootRecord.Payload[0] ^= 1
	pinned, err = store.PinnedParticipant(ctx, fixture.anchor.BoxID,
		fixture.anchor.ParticipantID, fixture.device.DeviceID)
	if err != nil || !sameParticipantEnrollment(pinned, enrollment) {
		t.Fatal("caller mutated stored authority", err)
	}
	if _, err := store.PinnedParticipant(ctx, fixture.anchor.BoxID,
		fixture.anchor.ParticipantID, fixture.anchor.BoxScopedPrincipalID); !errors.Is(err, ErrParticipantAuthority) {
		t.Fatalf("wrong device read: %v", err)
	}
	if _, err := store.PinnedParticipant(ctx, fixture.device.DeviceID,
		fixture.anchor.ParticipantID, fixture.device.DeviceID); !errors.Is(err, ErrParticipantAuthority) {
		t.Fatalf("wrong Box read: %v", err)
	}
	modified := enrollment
	modified.Anchor.ApprovedAtMilliseconds++
	if err := store.PinOwnerApprovedParticipant(ctx, modified, fixture.now); !errors.Is(err, ErrParticipantAuthority) {
		t.Fatalf("changed approval replaced pin: %v", err)
	}
	badSignature := cloneParticipantEnrollment(enrollment)
	badSignature.GrantRecord.Signature.Signature = "invalid"
	if err := store.PinOwnerApprovedParticipant(ctx, badSignature, fixture.now); !errors.Is(err, ErrParticipantAuthority) {
		t.Fatalf("bad grant signature pinned: %v", err)
	}
	otherEnrollment := cloneParticipantEnrollment(enrollment)
	otherEnrollment.Anchor.ParticipantID = uuid.New()
	otherEnrollment.Device.ParticipantID = otherEnrollment.Anchor.ParticipantID
	if err := store.PinOwnerApprovedParticipant(ctx, otherEnrollment, fixture.now); !errors.Is(err, ErrParticipantAuthority) {
		t.Fatalf("second participant reused scoped Principal: %v", err)
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
	if err := verifier.Authorize(ctx, pinned.Anchor, pinned.Device, pinned.RootRecord,
		pinned.GrantRecord, nil, fixture.proof, fixture.challengeID, fixture.now); err != nil {
		t.Fatal(err)
	}
	if err := verifier.Authorize(ctx, pinned.Anchor, pinned.Device, pinned.RootRecord,
		pinned.GrantRecord, nil, fixture.proof, fixture.challengeID, fixture.now); !errors.Is(err, ErrParticipantReplay) {
		t.Fatalf("replayed stored proof: %v", err)
	}
}
