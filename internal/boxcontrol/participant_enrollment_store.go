package boxcontrol

import (
	"bytes"
	"context"
	"reflect"

	"github.com/google/uuid"
)

// BoxParticipantEnrollment contains only Box-scoped public authority. The
// private Principal ID/root and the device's private keys never enter this
// record. Calling PinOwnerApprovedParticipant requires separate Box-owner
// authorization; this internal store API does not perform that ceremony.
type BoxParticipantEnrollment struct {
	Anchor      BoxParticipantAnchor
	Device      BoxParticipantDevice
	RootRecord  BoxSignedPrincipalRecord
	GrantRecord BoxSignedPrincipalRecord
}

func (enrollment BoxParticipantEnrollment) validInitialAt(nowMilliseconds int64) bool {
	if enrollment.Anchor.RevokedAtMilliseconds != 0 ||
		enrollment.Device.RevokedThroughGeneration != 0 {
		return false
	}
	_, _, _, err := verifyBoxParticipantEnrollment(enrollment.Anchor, enrollment.Device,
		enrollment.RootRecord, enrollment.GrantRecord, nowMilliseconds)
	return err == nil
}

func cloneParticipantEnrollment(enrollment BoxParticipantEnrollment) BoxParticipantEnrollment {
	enrollment.RootRecord.Payload = bytes.Clone(enrollment.RootRecord.Payload)
	enrollment.GrantRecord.Payload = bytes.Clone(enrollment.GrantRecord.Payload)
	return enrollment
}

func sameParticipantEnrollment(left, right BoxParticipantEnrollment) bool {
	return reflect.DeepEqual(left, right)
}

func (store *MemoryStore) PinOwnerApprovedParticipant(
	_ context.Context,
	enrollment BoxParticipantEnrollment,
	nowMilliseconds int64,
) error {
	if !enrollment.validInitialAt(nowMilliseconds) {
		return ErrParticipantAuthority
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.state == nil || !store.state.Claimed() || store.state.BoxID != enrollment.Anchor.BoxID {
		return ErrParticipantAuthority
	}
	if existing, present := store.participantEnrollments[enrollment.Anchor.ParticipantID]; present {
		if sameParticipantEnrollment(existing, enrollment) {
			return nil
		}
		return ErrParticipantAuthority
	}
	for _, existing := range store.participantEnrollments {
		if existing.Anchor.BoxScopedPrincipalID == enrollment.Anchor.BoxScopedPrincipalID ||
			existing.Anchor.RootKeyFingerprint == enrollment.Anchor.RootKeyFingerprint ||
			existing.Device.DeviceID == enrollment.Device.DeviceID ||
			existing.Device.GrantID == enrollment.Device.GrantID ||
			existing.Device.SigningKeyFingerprint == enrollment.Device.SigningKeyFingerprint {
			return ErrParticipantAuthority
		}
	}
	store.participantEnrollments[enrollment.Anchor.ParticipantID] = cloneParticipantEnrollment(enrollment)
	return nil
}

func (store *MemoryStore) PinnedParticipant(
	_ context.Context,
	boxID, participantID, deviceID uuid.UUID,
) (BoxParticipantEnrollment, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	enrollment, present := store.participantEnrollments[participantID]
	if !present || store.state == nil || !store.state.Claimed() ||
		store.state.BoxID != boxID || enrollment.Anchor.BoxID != boxID ||
		enrollment.Device.DeviceID != deviceID {
		return BoxParticipantEnrollment{}, ErrParticipantAuthority
	}
	return cloneParticipantEnrollment(enrollment), nil
}

// RevokePinnedParticipant is an immediate Box-owner service cutoff. It does
// not revoke the Principal root at other Boxes or in the client's custody.
func (store *MemoryStore) RevokePinnedParticipant(
	_ context.Context,
	boxID, participantID uuid.UUID,
	nowMilliseconds int64,
) error {
	if boxID == uuid.Nil || participantID == uuid.Nil || nowMilliseconds <= 0 {
		return ErrParticipantAuthority
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	enrollment, present := store.participantEnrollments[participantID]
	if !present || store.state == nil || !store.state.Claimed() ||
		store.state.BoxID != boxID || enrollment.Anchor.BoxID != boxID {
		return ErrParticipantAuthority
	}
	if enrollment.Anchor.RevokedAtMilliseconds == 0 {
		enrollment.Anchor.RevokedAtMilliseconds = nowMilliseconds
		store.participantEnrollments[participantID] = enrollment
	}
	return nil
}

// RevokePinnedParticipantDevice cuts off one exact signed grant. The first
// enrollment pins only generation 1; later rotation needs signed history.
func (store *MemoryStore) RevokePinnedParticipantDevice(
	_ context.Context,
	boxID, participantID, deviceID uuid.UUID,
	nowMilliseconds int64,
) error {
	if boxID == uuid.Nil || participantID == uuid.Nil || deviceID == uuid.Nil || nowMilliseconds <= 0 {
		return ErrParticipantAuthority
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	enrollment, present := store.participantEnrollments[participantID]
	if !present || store.state == nil || !store.state.Claimed() ||
		store.state.BoxID != boxID || enrollment.Anchor.BoxID != boxID ||
		enrollment.Device.DeviceID != deviceID {
		return ErrParticipantAuthority
	}
	if enrollment.Device.RevokedThroughGeneration < enrollment.Device.DeviceGeneration {
		enrollment.Device.RevokedThroughGeneration = enrollment.Device.DeviceGeneration
		store.participantEnrollments[participantID] = enrollment
	}
	return nil
}
