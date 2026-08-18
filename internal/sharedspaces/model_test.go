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

func TestParticipantRevocationRejectsInvalidKeyEpochTransition(t *testing.T) {
	revocation := sharedspaces.ParticipantRevocation{
		Version:               sharedspaces.SchemaVersion,
		RetryID:               uuid.New(),
		SpaceID:               uuid.New(),
		ParticipantID:         uuid.New(),
		PreviousKeyEpoch:      sharedspaces.InitialKeyEpoch,
		NextKeyEpoch:          sharedspaces.InitialKeyEpoch + 2,
		RevokedAtMilliseconds: 1_000,
	}
	if err := revocation.Validate(); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeInvalidParticipant) {
		t.Fatalf("invalid key epoch transition err=%v", err)
	}
}
