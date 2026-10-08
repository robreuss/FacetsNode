package boxcontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/google/uuid"
)

const participantActionProofDomain = "Facets Box participant action proof v1\x00"

type BoxParticipantAction string

const (
	ParticipantActionAdvertiseWorker          BoxParticipantAction = "worker.advertise"
	ParticipantActionUpdateWorkerAvailability BoxParticipantAction = "worker.availability.update"
	ParticipantActionWithdrawWorker           BoxParticipantAction = "worker.withdraw"
	ParticipantActionRequestWorkerAccess      BoxParticipantAction = "worker.access.request"
	ParticipantActionGrantWorkerAccess        BoxParticipantAction = "worker.access.grant"
	ParticipantActionRevokeWorkerAccess       BoxParticipantAction = "worker.access.revoke"
)

func (action BoxParticipantAction) valid() bool {
	switch action {
	case ParticipantActionAdvertiseWorker,
		ParticipantActionUpdateWorkerAvailability,
		ParticipantActionWithdrawWorker,
		ParticipantActionRequestWorkerAccess,
		ParticipantActionGrantWorkerAccess,
		ParticipantActionRevokeWorkerAccess:
		return true
	default:
		return false
	}
}

// BoxParticipantActionProofPayload binds one enrolled participant device to
// one canonical Worker-directory or grant mutation. Identity alone never
// authorizes a different payload under the same challenge.
type BoxParticipantActionProofPayload struct {
	Version               int                  `json:"version"`
	BoxID                 uuid.UUID            `json:"boxID"`
	ParticipantID         uuid.UUID            `json:"participantID"`
	BoxScopedPrincipalID  uuid.UUID            `json:"boxScopedPrincipalID"`
	DeviceID              uuid.UUID            `json:"deviceID"`
	GrantID               uuid.UUID            `json:"grantID"`
	DeviceGeneration      uint64               `json:"deviceGeneration"`
	ChallengeID           uuid.UUID            `json:"challengeID"`
	Action                BoxParticipantAction `json:"action"`
	RequestDigest         string               `json:"requestDigest"`
	IssuedAtMilliseconds  int64                `json:"issuedAtMilliseconds"`
	ExpiresAtMilliseconds int64                `json:"expiresAtMilliseconds"`
}

type BoxSignedParticipantActionProof struct {
	Payload   []byte `json:"payload"`
	Signature string `json:"signature"`
}

func BoxParticipantRequestDigest(canonicalRequest []byte) string {
	digest := sha256.Sum256(canonicalRequest)
	return hex.EncodeToString(digest[:])
}

func validParticipantRequestDigest(value string) bool {
	if len(value) != 64 || value != string(bytes.ToLower([]byte(value))) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func canonicalParticipantActionProof(data []byte) bool {
	var object map[string]json.RawMessage
	if json.Unmarshal(data, &object) != nil || object == nil {
		return false
	}
	encoded, err := json.Marshal(object)
	return err == nil && bytes.Equal(data, encoded)
}

// AuthorizeAction verifies the exact Box-pinned participant, action, request
// digest, and fresh challenge before consuming that challenge atomically.
func (verifier *BoxParticipantProofVerifier) AuthorizeAction(
	ctx context.Context,
	anchor BoxParticipantAnchor,
	device BoxParticipantDevice,
	rootRecord BoxSignedPrincipalRecord,
	grantRecord BoxSignedPrincipalRecord,
	revocations []BoxSignedPrincipalRecord,
	proof BoxSignedParticipantActionProof,
	expectedChallengeID uuid.UUID,
	expectedAction BoxParticipantAction,
	canonicalRequest []byte,
	nowMilliseconds int64,
) error {
	if verifier == nil || verifier.store == nil {
		return ErrParticipantAuthority
	}
	pinned, err := verifier.store.PinnedParticipant(
		ctx, anchor.BoxID, anchor.ParticipantID, device.DeviceID,
	)
	if err != nil || !sameParticipantEnrollment(pinned, BoxParticipantEnrollment{
		Anchor: anchor, Device: device, RootRecord: rootRecord, GrantRecord: grantRecord,
	}) {
		return ErrParticipantAuthority
	}
	if err := verifyBoxParticipantActionProof(
		anchor, device, rootRecord, grantRecord, revocations, proof,
		expectedChallengeID, expectedAction, canonicalRequest, nowMilliseconds,
	); err != nil {
		return err
	}
	consumed, err := verifier.store.ConsumeParticipantChallenge(
		ctx, anchor.BoxID, anchor.ParticipantID, device.DeviceID,
		expectedChallengeID, nowMilliseconds,
	)
	if err != nil {
		return err
	}
	if !consumed {
		return ErrParticipantReplay
	}
	return nil
}

// AuthorizePresentedAction derives all public authority from the Box's pinned
// participant records. The caller supplies only the signed proof and exact
// operation bytes; it cannot invent or stale-copy an enrollment record.
func (verifier *BoxParticipantProofVerifier) AuthorizePresentedAction(
	ctx context.Context,
	proof BoxSignedParticipantActionProof,
	expectedChallengeID uuid.UUID,
	expectedAction BoxParticipantAction,
	canonicalRequest []byte,
	nowMilliseconds int64,
) (BoxParticipantEnrollment, error) {
	if verifier == nil || verifier.store == nil || expectedChallengeID == uuid.Nil {
		return BoxParticipantEnrollment{}, ErrParticipantAuthority
	}
	var payload BoxParticipantActionProofPayload
	if strictParticipantJSON(proof.Payload, &payload) != nil || payload.Version != 1 ||
		!canonicalParticipantActionProof(proof.Payload) ||
		payload.BoxID == uuid.Nil || payload.ParticipantID == uuid.Nil ||
		payload.DeviceID == uuid.Nil || payload.ChallengeID != expectedChallengeID {
		return BoxParticipantEnrollment{}, ErrParticipantAuthority
	}
	pinned, err := verifier.store.PinnedParticipant(
		ctx, payload.BoxID, payload.ParticipantID, payload.DeviceID,
	)
	if err != nil {
		return BoxParticipantEnrollment{}, ErrParticipantAuthority
	}
	if err := verifyBoxParticipantActionProof(
		pinned.Anchor, pinned.Device, pinned.RootRecord, pinned.GrantRecord, nil,
		proof, expectedChallengeID, expectedAction, canonicalRequest,
		nowMilliseconds,
	); err != nil {
		return BoxParticipantEnrollment{}, err
	}
	consumed, err := verifier.store.ConsumeParticipantChallenge(
		ctx, payload.BoxID, payload.ParticipantID, payload.DeviceID,
		expectedChallengeID, nowMilliseconds,
	)
	if err != nil {
		return BoxParticipantEnrollment{}, err
	}
	if !consumed {
		return BoxParticipantEnrollment{}, ErrParticipantReplay
	}
	return pinned, nil
}

func verifyBoxParticipantActionProof(
	anchor BoxParticipantAnchor,
	device BoxParticipantDevice,
	rootRecord BoxSignedPrincipalRecord,
	grantRecord BoxSignedPrincipalRecord,
	revocations []BoxSignedPrincipalRecord,
	proof BoxSignedParticipantActionProof,
	expectedChallengeID uuid.UUID,
	expectedAction BoxParticipantAction,
	canonicalRequest []byte,
	nowMilliseconds int64,
) error {
	deviceKey, grantNotBefore, err := verifyBoxParticipantIdentity(
		anchor, device, rootRecord, grantRecord, revocations, nowMilliseconds,
	)
	if err != nil || expectedChallengeID == uuid.Nil || !expectedAction.valid() {
		return ErrParticipantAuthority
	}
	var payload BoxParticipantActionProofPayload
	if strictParticipantJSON(proof.Payload, &payload) != nil || payload.Version != 1 ||
		!canonicalParticipantActionProof(proof.Payload) ||
		payload.BoxID != anchor.BoxID || payload.ParticipantID != anchor.ParticipantID ||
		payload.BoxScopedPrincipalID != anchor.BoxScopedPrincipalID ||
		payload.DeviceID != device.DeviceID || payload.GrantID != device.GrantID ||
		payload.DeviceGeneration != device.DeviceGeneration ||
		payload.ChallengeID != expectedChallengeID || payload.Action != expectedAction ||
		!payload.Action.valid() || !validParticipantRequestDigest(payload.RequestDigest) ||
		payload.RequestDigest != BoxParticipantRequestDigest(canonicalRequest) ||
		payload.IssuedAtMilliseconds < grantNotBefore ||
		payload.IssuedAtMilliseconds > nowMilliseconds ||
		payload.ExpiresAtMilliseconds <= nowMilliseconds ||
		payload.ExpiresAtMilliseconds-payload.IssuedAtMilliseconds > maximumParticipantProofAgeMilliseconds ||
		verifyParticipantSignature(
			proof.Signature, deviceKey, participantActionProofDomain, proof.Payload,
		) != nil {
		return ErrParticipantAuthority
	}
	return nil
}
