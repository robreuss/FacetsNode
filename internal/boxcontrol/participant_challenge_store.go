package boxcontrol

import (
	"context"

	"github.com/google/uuid"
)

// BoxParticipantChallenge is one Box-issued, short-lived proof challenge.
// Issuance is not participant enrollment: an owner-approved anchor and exact
// device grant are still required before a proof may be authorized.
type BoxParticipantChallenge struct {
	BoxID                 uuid.UUID
	ParticipantID         uuid.UUID
	DeviceID              uuid.UUID
	ChallengeID           uuid.UUID
	IssuedAtMilliseconds  int64
	ExpiresAtMilliseconds int64
}

func (challenge BoxParticipantChallenge) validAt(nowMilliseconds int64) bool {
	return challenge.BoxID != uuid.Nil && challenge.ParticipantID != uuid.Nil &&
		challenge.DeviceID != uuid.Nil && challenge.ChallengeID != uuid.Nil &&
		challenge.IssuedAtMilliseconds > 0 &&
		challenge.IssuedAtMilliseconds <= nowMilliseconds &&
		nowMilliseconds < challenge.ExpiresAtMilliseconds &&
		challenge.ExpiresAtMilliseconds-challenge.IssuedAtMilliseconds <= maximumParticipantProofAgeMilliseconds
}

type participantChallengeState struct {
	challenge              BoxParticipantChallenge
	consumedAtMilliseconds int64
}

func (store *MemoryStore) IssueParticipantChallenge(
	_ context.Context,
	challenge BoxParticipantChallenge,
	nowMilliseconds int64,
) error {
	if !challenge.validAt(nowMilliseconds) {
		return ErrParticipantAuthority
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.state == nil || !store.state.Claimed() || store.state.BoxID != challenge.BoxID {
		return ErrParticipantAuthority
	}
	enrollment, enrolled := store.participantEnrollments[challenge.ParticipantID]
	if !enrolled || enrollment.Anchor.BoxID != challenge.BoxID ||
		enrollment.Device.DeviceID != challenge.DeviceID ||
		!enrollment.validInitialAt(nowMilliseconds) {
		return ErrParticipantAuthority
	}
	if _, exists := store.participantChallenges[challenge.ChallengeID]; exists {
		return ErrParticipantAuthority
	}
	store.participantChallenges[challenge.ChallengeID] = participantChallengeState{challenge: challenge}
	return nil
}

func (store *MemoryStore) ConsumeParticipantChallenge(
	_ context.Context,
	boxID, participantID, deviceID, challengeID uuid.UUID,
	nowMilliseconds int64,
) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	state, exists := store.participantChallenges[challengeID]
	enrollment, enrolled := store.participantEnrollments[participantID]
	if !exists || state.consumedAtMilliseconds != 0 ||
		state.challenge.BoxID != boxID || state.challenge.ParticipantID != participantID ||
		state.challenge.DeviceID != deviceID || !state.challenge.validAt(nowMilliseconds) ||
		!enrolled || enrollment.Anchor.BoxID != boxID || enrollment.Device.DeviceID != deviceID ||
		!enrollment.validInitialAt(nowMilliseconds) {
		return false, nil
	}
	state.consumedAtMilliseconds = nowMilliseconds
	store.participantChallenges[challengeID] = state
	return true, nil
}
