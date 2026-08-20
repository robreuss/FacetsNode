package sharedspaces_test

import (
	"encoding/base64"
	"reflect"
	"sort"
	"testing"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/sharedspaces"
)

func TestSecurityModeIsFixedToSupportedValues(t *testing.T) {
	_, provisioning, _ := testSpaceProvisioning(t, 1_000, sharedspaces.SecurityModeSecure)
	if err := provisioning.Validate(); err != nil {
		t.Fatalf("Secure provisioning: %v", err)
	}
	provisioning.SecurityMode = sharedspaces.SecurityModePrivate
	if err := provisioning.Validate(); err != nil {
		t.Fatalf("Private provisioning: %v", err)
	}
	provisioning.SecurityMode = sharedspaces.SecurityModeManaged
	if err := provisioning.Validate(); err != nil {
		t.Fatalf("managed provisioning: %v", err)
	}
	provisioning.SecurityMode = "hybrid"
	if err := provisioning.Validate(); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeInvalidSpace) {
		t.Fatalf("unsupported security mode err=%v", err)
	}
	if !sharedspaces.SecurityModePrivate.ContentBlind() ||
		sharedspaces.SecurityModePrivate.RotatesKeyEpochOnRevocation() ||
		!sharedspaces.SecurityModeSecure.ContentBlind() ||
		!sharedspaces.SecurityModeSecure.RotatesKeyEpochOnRevocation() ||
		sharedspaces.SecurityModeManaged.ContentBlind() ||
		!sharedspaces.SecurityModeManaged.RotatesKeyEpochOnRevocation() {
		t.Fatalf("security profile properties do not match their contract")
	}
}

func TestComputePoolChangeAndResultValidation(t *testing.T) {
	spaceID := uuid.New()
	poolID := uuid.New()
	retryID := uuid.New()
	change := sharedspaces.ComputePoolChange{
		Version: sharedspaces.SchemaVersion, RetryID: retryID, SpaceID: spaceID,
		PoolID: poolID, DisplayName: "Nightly Research", Enabled: true,
		AllowedOperations: []string{"embeddings.generate", "text.classify"},
		ResourceCeiling: sharedspaces.ComputeResourceCeiling{
			MaximumInputBytes: 1 << 20, MaximumOutputBytes: 1 << 20,
			MaximumMemoryBytes: 1 << 30, MaximumWallTimeMilliseconds: 60_000,
		},
		PricingRevision: 1, DataSensitivityContract: "space-members-v1",
		ProcessingContract: "participant-device-v1", ChangedAtMilliseconds: 1_000,
	}
	if err := change.Validate(); err != nil {
		t.Fatalf("valid compute pool change: %v", err)
	}
	unsorted := change
	unsorted.AllowedOperations = []string{"text.classify", "embeddings.generate"}
	if err := unsorted.Validate(); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeInvalidComputePool) {
		t.Fatalf("unsorted operations err=%v", err)
	}

	result := sharedspaces.ComputePoolChangeResult{
		Acceptance: relay.AcceptanceAccepted, RetryID: retryID,
		Pool: sharedspaces.ComputePool{
			Version: sharedspaces.SchemaVersion, SpaceID: spaceID, PoolID: poolID,
			DisplayName: change.DisplayName, Enabled: true, Revision: 1,
			CreatedAtMilliseconds: 1_000, UpdatedAtMilliseconds: 1_000,
		},
		Binding: sharedspaces.SpaceComputeBinding{
			Version: sharedspaces.SchemaVersion, SpaceID: spaceID, PoolID: poolID,
			AllowedOperations: change.AllowedOperations, ResourceCeiling: change.ResourceCeiling,
			PricingRevision: 1, DataSensitivityContract: change.DataSensitivityContract,
			ProcessingContract: change.ProcessingContract, Revision: 1,
			CreatedAtMilliseconds: 1_000, UpdatedAtMilliseconds: 1_000,
		},
	}
	if err := result.Validate(); err != nil {
		t.Fatalf("valid compute pool result: %v", err)
	}
	result.Binding.Revision = 2
	if err := result.Validate(); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeInvalidComputePool) {
		t.Fatalf("mismatched result err=%v", err)
	}
}

func TestInteractionModeIsRequiredAndImmutableInProvisioning(t *testing.T) {
	_, provisioning, _ := testSpaceProvisioning(t, 1_500, sharedspaces.SecurityModeSecure)
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

func TestParticipantPresentationValidatesRecognitionMetadataAndStatusScope(t *testing.T) {
	spaceID := uuid.New()
	participantID := uuid.New()
	presentation := sharedspaces.ParticipantPresentation{
		Version: sharedspaces.SchemaVersion, SpaceID: spaceID,
		ParticipantID: participantID, DisplayName: "Ada Lovelace",
		Revision: 1, UpdatedAtMilliseconds: 1_000,
	}
	if err := presentation.Validate(); err != nil {
		t.Fatalf("valid participant presentation: %v", err)
	}

	invalidName := presentation
	invalidName.DisplayName = " Ada Lovelace "
	if err := invalidName.Validate(); !sharedspaces.ErrorHasCode(
		err, sharedspaces.CodeInvalidParticipantPresentation,
	) {
		t.Fatalf("untrimmed participant display name err=%v", err)
	}

	_, provisioning, _ := testSpaceProvisioning(t, 1_000, sharedspaces.SecurityModeSecure)
	status := sharedspaces.ParticipantStatus{
		Version: sharedspaces.SchemaVersion, SpaceID: provisioning.SpaceID,
		DomainID:     provisioning.Domain.Registration.DomainID,
		SecurityMode: provisioning.SecurityMode, InteractionMode: provisioning.InteractionMode,
		CurrentKeyEpoch: sharedspaces.InitialKeyEpoch,
		Participant: sharedspaces.Participant{
			Version: sharedspaces.SchemaVersion, SpaceID: provisioning.SpaceID,
			ParticipantID:  provisioning.InitialParticipantID,
			SubscriptionID: provisioning.Domain.Subscription.SubscriptionID,
			Kind:           provisioning.InitialParticipantKind, Role: sharedspaces.RoleHost,
			CreatedAtMilliseconds: provisioning.CreatedAtMilliseconds,
		},
		Capabilities:          sharedspaces.RoleHost.Capabilities(provisioning.InteractionMode),
		CreatedAtMilliseconds: provisioning.CreatedAtMilliseconds,
	}
	wrongScope := presentation
	wrongScope.SpaceID = provisioning.SpaceID
	status.Presentation = &wrongScope
	if err := status.Validate(); !sharedspaces.ErrorHasCode(
		err, sharedspaces.CodeInvalidParticipantPresentation,
	) {
		t.Fatalf("cross-participant presentation err=%v", err)
	}
}

func sortedCapabilities(capabilities []relay.Capability) []relay.Capability {
	sort.Slice(capabilities, func(i, j int) bool { return capabilities[i] < capabilities[j] })
	return capabilities
}

func TestInvitationRoleFreezesRelayCapabilities(t *testing.T) {
	_, provisioning, admin := testSpaceProvisioning(t, 2_000, sharedspaces.SecurityModeSecure)
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
	_, provisioning, admin := testSpaceProvisioning(t, 2_500, sharedspaces.SecurityModeSecure)
	invitation, _ := testInvitation(t, provisioning, admin, 2_600, sharedspaces.RoleParticipant)
	if err := invitation.ValidateKeyGrant(sharedspaces.SecurityModeSecure, sharedspaces.InitialKeyEpoch); err != nil {
		t.Fatalf("valid Secure grant: %v", err)
	}
	if err := invitation.ValidateKeyGrant(sharedspaces.SecurityModePrivate, sharedspaces.InitialKeyEpoch); err != nil {
		t.Fatalf("valid Private grant: %v", err)
	}

	tampered := invitation
	tamperedGrant := *invitation.KeyGrant
	tamperedGrant.Ciphertext += "A"
	tampered.KeyGrant = &tamperedGrant
	if err := tampered.Validate(); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeInvalidInvitation) {
		t.Fatalf("tampered grant err=%v", err)
	}

	wrongEpoch := invitation
	if err := wrongEpoch.ValidateKeyGrant(sharedspaces.SecurityModeSecure, sharedspaces.InitialKeyEpoch+1); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeWrongKeyEpoch) {
		t.Fatalf("wrong epoch err=%v", err)
	}
	wrongParticipant := invitation
	wrongParticipant.ParticipantID = uuid.New()
	if err := wrongParticipant.ValidateKeyGrant(sharedspaces.SecurityModeSecure, sharedspaces.InitialKeyEpoch); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeWrongScope) {
		t.Fatalf("wrong participant err=%v", err)
	}
	if err := invitation.ValidateKeyGrant(sharedspaces.SecurityModeManaged, sharedspaces.InitialKeyEpoch); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeInvalidInvitation) {
		t.Fatalf("managed grant err=%v", err)
	}
	missing := invitation
	missing.KeyGrant = nil
	if err := missing.ValidateKeyGrant(sharedspaces.SecurityModeSecure, sharedspaces.InitialKeyEpoch); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeInvalidInvitation) {
		t.Fatalf("missing Secure grant err=%v", err)
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

func TestParticipantRevocationRequiresCompleteSecureGrantSet(t *testing.T) {
	_, provisioning, _ := testSpaceProvisioning(t, 3_000, sharedspaces.SecurityModeSecure)
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
		sharedspaces.SecurityModeSecure, participants, 3_200,
	); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeInvalidParticipant) {
		t.Fatalf("missing grant set err=%v", err)
	}
	hostGrant := testParticipantKeyGrant(
		t, provisioning.SpaceID, provisioning.InitialParticipantID,
		provisioning.InitialParticipantID, revocation.NextKeyEpoch, 3_200,
	)
	revocation.KeyGrants = []sharedspaces.ParticipantKeyGrant{*hostGrant}
	if err := revocation.ValidateKeyGrants(
		sharedspaces.SecurityModeSecure, participants, 3_200,
	); err != nil {
		t.Fatalf("complete grant set err=%v", err)
	}
	revocation.KeyGrants = append(revocation.KeyGrants, *hostGrant)
	if err := revocation.ValidateKeyGrants(
		sharedspaces.SecurityModeSecure, participants, 3_200,
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

func TestParticipantRevocationForPrivateSpaceRetainsStaticKeyEpoch(t *testing.T) {
	_, provisioning, _ := testSpaceProvisioning(t, 3_300, sharedspaces.SecurityModePrivate)
	participantID := uuid.New()
	participants := []sharedspaces.Participant{
		{
			Version: sharedspaces.SchemaVersion, SpaceID: provisioning.SpaceID,
			ParticipantID: provisioning.InitialParticipantID,
			Kind:          sharedspaces.ParticipantPerson, Role: sharedspaces.RoleHost,
			CreatedAtMilliseconds: 3_300,
		},
		{
			Version: sharedspaces.SchemaVersion, SpaceID: provisioning.SpaceID,
			ParticipantID: participantID, Kind: sharedspaces.ParticipantPerson,
			Role: sharedspaces.RoleParticipant, CreatedAtMilliseconds: 3_310,
		},
	}
	revocation := sharedspaces.ParticipantRevocation{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(), SpaceID: provisioning.SpaceID,
		ParticipantID: participantID, PreviousKeyEpoch: sharedspaces.InitialKeyEpoch,
		NextKeyEpoch: sharedspaces.InitialKeyEpoch,
	}
	if err := revocation.ValidateKeyGrants(sharedspaces.SecurityModePrivate, participants, 3_320); err != nil {
		t.Fatalf("private static-key revocation: %v", err)
	}

	rotating := revocation
	rotating.NextKeyEpoch++
	if err := rotating.ValidateKeyGrants(sharedspaces.SecurityModePrivate, participants, 3_320); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeInvalidParticipant) {
		t.Fatalf("private key rotation err=%v", err)
	}
	withGrant := revocation
	withGrant.KeyGrants = []sharedspaces.ParticipantKeyGrant{*testParticipantKeyGrant(
		t, provisioning.SpaceID, provisioning.InitialParticipantID,
		provisioning.InitialParticipantID, sharedspaces.InitialKeyEpoch, 3_320,
	)}
	if err := withGrant.ValidateKeyGrants(sharedspaces.SecurityModePrivate, participants, 3_320); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeInvalidParticipant) {
		t.Fatalf("private replacement grant err=%v", err)
	}
}

func TestParticipantBootstrapRequiresExactlyOneModeAppropriateKey(t *testing.T) {
	_, provisioning, _ := testSpaceProvisioning(t, 3_500, sharedspaces.SecurityModeManaged)
	participant := sharedspaces.Participant{
		Version: sharedspaces.SchemaVersion, SpaceID: provisioning.SpaceID,
		ParticipantID:  provisioning.InitialParticipantID,
		SubscriptionID: provisioning.InitialParticipantID,
		Kind:           sharedspaces.ParticipantPerson, Role: sharedspaces.RoleHost,
		CreatedAtMilliseconds: provisioning.CreatedAtMilliseconds,
	}
	status := sharedspaces.ParticipantStatus{
		Version: sharedspaces.SchemaVersion, SpaceID: provisioning.SpaceID,
		DomainID:              provisioning.Domain.Registration.DomainID,
		SecurityMode:          sharedspaces.SecurityModeManaged,
		InteractionMode:       provisioning.InteractionMode,
		CurrentKeyEpoch:       sharedspaces.InitialKeyEpoch,
		Participant:           participant,
		Capabilities:          sharedspaces.RoleHost.Capabilities(provisioning.InteractionMode),
		CreatedAtMilliseconds: provisioning.CreatedAtMilliseconds,
	}
	bootstrap := sharedspaces.ParticipantBootstrap{
		Version: sharedspaces.SchemaVersion, Status: status,
		ManagedContentKey: &sharedspaces.ManagedContentKey{
			Version: sharedspaces.SchemaVersion, SpaceID: provisioning.SpaceID,
			ParticipantID: provisioning.InitialParticipantID,
			KeyEpoch:      sharedspaces.InitialKeyEpoch,
			Algorithm:     sharedspaces.ManagedContentKeyAlgorithm,
			KeyMaterial:   base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		},
	}
	if err := bootstrap.Validate(); err != nil {
		t.Fatalf("valid managed participant bootstrap: %v", err)
	}

	wrongScope := bootstrap
	wrongScope.ManagedContentKey = &sharedspaces.ManagedContentKey{
		Version: sharedspaces.SchemaVersion, SpaceID: uuid.New(),
		ParticipantID: provisioning.InitialParticipantID,
		KeyEpoch:      sharedspaces.InitialKeyEpoch,
		Algorithm:     sharedspaces.ManagedContentKeyAlgorithm,
		KeyMaterial:   base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	}
	if err := wrongScope.Validate(); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeInvalidParticipant) {
		t.Fatalf("wrong-scope managed key err=%v", err)
	}

	mixed := bootstrap
	mixed.KeyGrant = &sharedspaces.ParticipantKeyGrantResult{
		Version: sharedspaces.SchemaVersion, SpaceID: provisioning.SpaceID,
		ParticipantID:   provisioning.InitialParticipantID,
		CurrentKeyEpoch: sharedspaces.InitialKeyEpoch,
		KeyGrant: *testParticipantKeyGrant(
			t, provisioning.SpaceID, provisioning.InitialParticipantID,
			provisioning.InitialParticipantID, sharedspaces.InitialKeyEpoch, 3_500,
		),
	}
	if err := mixed.Validate(); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeInvalidParticipant) {
		t.Fatalf("mixed managed and content-blind keys err=%v", err)
	}

	secure := bootstrap
	secure.Status.SecurityMode = sharedspaces.SecurityModeSecure
	secure.ManagedContentKey = nil
	secure.KeyGrant = mixed.KeyGrant
	if err := secure.Validate(); err != nil {
		t.Fatalf("valid Secure participant bootstrap: %v", err)
	}
	secure.ManagedContentKey = bootstrap.ManagedContentKey
	if err := secure.Validate(); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeInvalidParticipant) {
		t.Fatalf("Secure bootstrap with managed key err=%v", err)
	}
}
