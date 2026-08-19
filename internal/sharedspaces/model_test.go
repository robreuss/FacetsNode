package sharedspaces_test

import (
	"testing"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/sharedspaces"
)

func TestSecurityModeIsFixedToSupportedValues(t *testing.T) {
	_, provisioning, _ := testSpaceProvisioning(t, 1_000, sharedspaces.SecurityModeE2EE)
	if err := provisioning.Validate(); err != nil {
		t.Fatalf("E2EE provisioning: %v", err)
	}
	provisioning.SecurityMode = sharedspaces.SecurityModeManaged
	if err := provisioning.Validate(); err != nil {
		t.Fatalf("managed provisioning: %v", err)
	}
	provisioning.SecurityMode = "hybrid"
	if err := provisioning.Validate(); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeInvalidSpace) {
		t.Fatalf("unsupported security mode err=%v", err)
	}
}

func TestInvitationRoleFreezesRelayCapabilities(t *testing.T) {
	_, provisioning, admin := testSpaceProvisioning(t, 2_000, sharedspaces.SecurityModeE2EE)
	invitation, _ := testInvitation(t, provisioning, admin, 2_100, sharedspaces.RoleReader)
	if err := invitation.Validate(); err != nil {
		t.Fatalf("reader invitation: %v", err)
	}
	invitation.RelayAdmission.Capabilities = sharedspaces.RoleParticipant.Capabilities()
	if err := invitation.Validate(); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeWrongScope) {
		t.Fatalf("expanded capabilities err=%v", err)
	}
	invitation.SpaceID = uuid.New()
	if err := invitation.Validate(); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeWrongScope) {
		t.Fatalf("wrong Space scope err=%v", err)
	}
}

func TestParticipantKeyGrantRejectsTamperingAndWrongScope(t *testing.T) {
	_, provisioning, admin := testSpaceProvisioning(t, 2_500, sharedspaces.SecurityModeE2EE)
	invitation, _ := testInvitation(t, provisioning, admin, 2_600, sharedspaces.RoleParticipant)
	if err := invitation.ValidateKeyGrant(sharedspaces.SecurityModeE2EE, sharedspaces.InitialKeyEpoch); err != nil {
		t.Fatalf("valid E2EE grant: %v", err)
	}

	tampered := invitation
	tamperedGrant := *invitation.KeyGrant
	tamperedGrant.Ciphertext += "A"
	tampered.KeyGrant = &tamperedGrant
	if err := tampered.Validate(); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeInvalidInvitation) {
		t.Fatalf("tampered grant err=%v", err)
	}

	wrongEpoch := invitation
	if err := wrongEpoch.ValidateKeyGrant(sharedspaces.SecurityModeE2EE, sharedspaces.InitialKeyEpoch+1); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeWrongKeyEpoch) {
		t.Fatalf("wrong epoch err=%v", err)
	}
	wrongParticipant := invitation
	wrongParticipant.ParticipantID = uuid.New()
	if err := wrongParticipant.ValidateKeyGrant(sharedspaces.SecurityModeE2EE, sharedspaces.InitialKeyEpoch); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeWrongScope) {
		t.Fatalf("wrong participant err=%v", err)
	}
	if err := invitation.ValidateKeyGrant(sharedspaces.SecurityModeManaged, sharedspaces.InitialKeyEpoch); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeInvalidInvitation) {
		t.Fatalf("managed grant err=%v", err)
	}
	missing := invitation
	missing.KeyGrant = nil
	if err := missing.ValidateKeyGrant(sharedspaces.SecurityModeE2EE, sharedspaces.InitialKeyEpoch); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeInvalidInvitation) {
		t.Fatalf("missing E2EE grant err=%v", err)
	}
}

func TestParticipantRevocationRejectsInvalidKeyEpochTransition(t *testing.T) {
	revocation := sharedspaces.ParticipantRevocation{
		Version:          sharedspaces.SchemaVersion,
		RetryID:          uuid.New(),
		SpaceID:          uuid.New(),
		ParticipantID:    uuid.New(),
		PreviousKeyEpoch: sharedspaces.InitialKeyEpoch,
		NextKeyEpoch:     sharedspaces.InitialKeyEpoch + 2,
	}
	if err := revocation.Validate(); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeInvalidParticipant) {
		t.Fatalf("invalid key epoch transition err=%v", err)
	}
}

func TestParticipantRevocationRequiresCompleteE2EEGrantSet(t *testing.T) {
	_, provisioning, _ := testSpaceProvisioning(t, 3_000, sharedspaces.SecurityModeE2EE)
	participantID := uuid.New()
	participants := []sharedspaces.Participant{
		{
			Version: sharedspaces.SchemaVersion, SpaceID: provisioning.SpaceID,
			ParticipantID: provisioning.InitialParticipantID,
			Kind:          sharedspaces.ParticipantPerson, Role: sharedspaces.RoleHost,
			CreatedAtMilliseconds: 3_000,
		},
		{
			Version: sharedspaces.SchemaVersion, SpaceID: provisioning.SpaceID,
			ParticipantID: participantID, Kind: sharedspaces.ParticipantPerson,
			Role: sharedspaces.RoleParticipant, CreatedAtMilliseconds: 3_100,
		},
	}
	revocation := sharedspaces.ParticipantRevocation{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(), SpaceID: provisioning.SpaceID,
		ParticipantID: participantID, PreviousKeyEpoch: sharedspaces.InitialKeyEpoch,
		NextKeyEpoch: sharedspaces.InitialKeyEpoch + 1,
	}
	if err := revocation.ValidateKeyGrants(
		sharedspaces.SecurityModeE2EE, participants, 3_200,
	); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeInvalidParticipant) {
		t.Fatalf("missing grant set err=%v", err)
	}
	hostGrant := testParticipantKeyGrant(
		t, provisioning.SpaceID, provisioning.InitialParticipantID,
		provisioning.InitialParticipantID, revocation.NextKeyEpoch, 3_200,
	)
	revocation.KeyGrants = []sharedspaces.ParticipantKeyGrant{*hostGrant}
	if err := revocation.ValidateKeyGrants(
		sharedspaces.SecurityModeE2EE, participants, 3_200,
	); err != nil {
		t.Fatalf("complete grant set err=%v", err)
	}
	revocation.KeyGrants = append(revocation.KeyGrants, *hostGrant)
	if err := revocation.ValidateKeyGrants(
		sharedspaces.SecurityModeE2EE, participants, 3_200,
	); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeInvalidParticipant) {
		t.Fatalf("duplicate grant recipient err=%v", err)
	}
	revocation.KeyGrants = []sharedspaces.ParticipantKeyGrant{*hostGrant}
	if err := revocation.ValidateKeyGrants(
		sharedspaces.SecurityModeManaged, participants, 3_200,
	); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeInvalidParticipant) {
		t.Fatalf("managed grant set err=%v", err)
	}
}
