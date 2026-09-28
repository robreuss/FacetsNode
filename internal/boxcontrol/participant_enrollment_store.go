package boxcontrol

import (
	"bytes"
	"context"
	"reflect"
	"sort"

	"github.com/google/uuid"
)

// BoxParticipantEnrollment contains only Box-scoped public authority. The
// private Principal ID/root and the device's private keys never enter this
// record. Calling PinOwnerApprovedParticipant requires separate Box-owner
// authorization; this internal store API does not perform that ceremony.
type BoxParticipantEnrollment struct {
	Anchor      BoxParticipantAnchor     `json:"anchor"`
	Device      BoxParticipantDevice     `json:"device"`
	RootRecord  BoxSignedPrincipalRecord `json:"rootRecord"`
	GrantRecord BoxSignedPrincipalRecord `json:"grantRecord"`
}

// BoxParticipantSummary is public authority projected for the Box Owner UI.
// The device name is self-asserted in the signed grant; it is not a Persona.
type BoxParticipantSummary struct {
	ParticipantID      uuid.UUID
	DeviceID           uuid.UUID
	DeviceName         string
	RootKeyFingerprint string
	ParticipantRevoked bool
	DeviceRevoked      bool
}

func participantSummary(enrollment BoxParticipantEnrollment) (BoxParticipantSummary, error) {
	var grant boxPrincipalDeviceGrant
	if strictParticipantJSON(enrollment.GrantRecord.Payload, &grant) != nil ||
		grant.DeviceID != enrollment.Device.DeviceID || grant.ID != enrollment.Device.GrantID {
		return BoxParticipantSummary{}, ErrParticipantAuthority
	}
	return BoxParticipantSummary{
		ParticipantID:      enrollment.Anchor.ParticipantID,
		DeviceID:           enrollment.Device.DeviceID,
		DeviceName:         grant.DeviceName,
		RootKeyFingerprint: enrollment.Anchor.RootKeyFingerprint,
		ParticipantRevoked: enrollment.Anchor.RevokedAtMilliseconds != 0,
		DeviceRevoked:      enrollment.Device.RevokedThroughGeneration >= enrollment.Device.DeviceGeneration,
	}, nil
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
	return store.pinParticipantLocked(enrollment)
}

// Caller holds store.mu and has verified the Box is claimed and the signed
// public enrollment is current. Shared with the atomic request decision path.
func (store *MemoryStore) pinParticipantLocked(enrollment BoxParticipantEnrollment) error {
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

func (store *MemoryStore) ListPinnedParticipants(_ context.Context, boxID uuid.UUID) ([]BoxParticipantSummary, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.state == nil || !store.state.Claimed() || store.state.BoxID != boxID {
		return nil, ErrParticipantAuthority
	}
	results := make([]BoxParticipantSummary, 0, len(store.participantEnrollments))
	for _, enrollment := range store.participantEnrollments {
		if enrollment.Anchor.BoxID != boxID {
			continue
		}
		summary, err := participantSummary(enrollment)
		if err != nil {
			return nil, err
		}
		results = append(results, summary)
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].ParticipantID.String() < results[j].ParticipantID.String()
	})
	return results, nil
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
