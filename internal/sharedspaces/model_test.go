package sharedspaces_test

import (
	"reflect"
	"sort"
	"testing"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/relay"
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

func TestInteractionModeIsRequiredAndImmutableInProvisioning(t *testing.T) {
	_, provisioning, _ := testSpaceProvisioning(t, 1_500, sharedspaces.SecurityModeE2EE)
	for _, mode := range []sharedspaces.InteractionMode{
		sharedspaces.InteractionModeBroadcast,
		sharedspaces.InteractionModeCommunity,
		sharedspaces.InteractionModeCollaborative,
	} {
		candidate := provisioning
		candidate.InteractionMode = mode
		candidate.Domain.InitialMember.Capabilities = sharedspaces.RoleHost.Capabilities(mode)
		if err := candidate.Validate(); err != nil {
			t.Fatalf("interaction mode %q: %v", mode, err)
		}
	}
	provisioning.InteractionMode = ""
	if err := provisioning.Validate(); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeInvalidSpace) {
		t.Fatalf("missing interaction mode err=%v", err)
	}
	provisioning.InteractionMode = "custom"
	if err := provisioning.Validate(); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeInvalidSpace) {
		t.Fatalf("unsupported interaction mode err=%v", err)
	}
}

func TestInteractionModesDeriveRelayCapabilities(t *testing.T) {
	read := sortedCapabilities([]relay.Capability{
		relay.CapabilityAcknowledgeMessage,
		relay.CapabilityFetchBlob,
		relay.CapabilityFetchMessage,
	})
	communityPublish := sortedCapabilities(append(append([]relay.Capability{}, read...),
		relay.CapabilityPublishBlob,
		relay.CapabilityPublishMessage,
	))
	all := sortedCapabilities(append(append([]relay.Capability{}, communityPublish...),
		relay.CapabilityPublishCheckpoint,
	))
	cases := []struct {
		name string
		mode sharedspaces.InteractionMode
		role sharedspaces.Role
		want []relay.Capability
	}{
		{"broadcast host", sharedspaces.InteractionModeBroadcast, sharedspaces.RoleHost, all},
		{"broadcast moderator", sharedspaces.InteractionModeBroadcast, sharedspaces.RoleModerator, all},
		{"broadcast participant", sharedspaces.InteractionModeBroadcast, sharedspaces.RoleParticipant, read},
		{"broadcast reader", sharedspaces.InteractionModeBroadcast, sharedspaces.RoleReader, read},
		{"community host", sharedspaces.InteractionModeCommunity, sharedspaces.RoleHost, all},
		{"community participant", sharedspaces.InteractionModeCommunity, sharedspaces.RoleParticipant, communityPublish},
		{"community reader", sharedspaces.InteractionModeCommunity, sharedspaces.RoleReader, read},
		{"collaborative host", sharedspaces.InteractionModeCollaborative, sharedspaces.RoleHost, all},
		{"collaborative participant", sharedspaces.InteractionModeCollaborative, sharedspaces.RoleParticipant, all},
		{"collaborative reader", sharedspaces.InteractionModeCollaborative, sharedspaces.RoleReader, read},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got := test.role.Capabilities(test.mode)
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("capabilities=%v want=%v", got, test.want)
			}
		})
	}
	if got := sharedspaces.RoleParticipant.Capabilities("custom"); got != nil {
		t.Fatalf("unsupported mode capabilities=%v", got)
	}
}

func TestAuthorityEventRequiresFieldsForItsTransition(t *testing.T) {
	participantID := uuid.New()
	previousRole := sharedspaces.RoleReader
	currentRole := sharedspaces.RoleParticipant
	valid := sharedspaces.AuthorityEvent{
		Version: sharedspaces.SchemaVersion, Sequence: 1,
		EventID: uuid.New(), SpaceID: uuid.New(), DomainID: uuid.New(),
		EventType:            sharedspaces.AuthorityEventParticipantRoleChanged,
		SubjectParticipantID: &participantID,
		PreviousRole:         &previousRole, CurrentRole: &currentRole,
		OccurredAtMilliseconds: 1_000,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid authority event: %v", err)
	}
	missingPreviousRole := valid
	missingPreviousRole.PreviousRole = nil
	if err := missingPreviousRole.Validate(); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeInvalidAuthorityEvent) {
		t.Fatalf("missing previous role err=%v", err)
	}
	unexpectedInvitation := valid
	invitationID := uuid.New()
	unexpectedInvitation.InvitationID = &invitationID
	if err := unexpectedInvitation.Validate(); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeInvalidAuthorityEvent) {
		t.Fatalf("unexpected invitation err=%v", err)
	}
}

func sortedCapabilities(capabilities []relay.Capability) []relay.Capability {
	sort.Slice(capabilities, func(i, j int) bool { return capabilities[i] < capabilities[j] })
	return capabilities
}

func TestInvitationRoleFreezesRelayCapabilities(t *testing.T) {
	_, provisioning, admin := testSpaceProvisioning(t, 2_000, sharedspaces.SecurityModeE2EE)
	invitation, _ := testInvitation(t, provisioning, admin, 2_100, sharedspaces.RoleReader)
	if err := invitation.Validate(); err != nil {
		t.Fatalf("reader invitation: %v", err)
	}
	invitation.RelayAdmission.Capabilities = sharedspaces.RoleParticipant.Capabilities(provisioning.InteractionMode)
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
