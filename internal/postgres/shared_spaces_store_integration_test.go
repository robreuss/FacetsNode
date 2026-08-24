package postgres_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"os"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/computepool"
	"github.com/robreuss/FacetsNode/internal/keycustody"
	postgresstore "github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
	"github.com/robreuss/FacetsNode/internal/sharedspaces"
	"github.com/robreuss/FacetsNode/internal/testfixture"
)

func TestPostgresSharedSpaceAuthorityAndRelayCommitAtomically(t *testing.T) {
	databaseURL := os.Getenv("FACETS_SERVER_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("FACETS_SERVER_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	lockDisposablePostgres(t, ctx, databaseURL)
	pool := openPool(t, ctx, databaseURL)
	defer pool.Close()
	if err := postgresstore.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `TRUNCATE relay_tenants CASCADE`); err != nil {
		t.Fatal(err)
	}

	store := postgresstore.NewSharedSpacesStore(pool)
	const now = int64(10_000)
	provisioning, admin := postgresSharedSpaceProvisioning(t, now)
	created, err := store.ProvisionSpace(ctx, provisioning, now)
	if err != nil || created.Acceptance != relay.AcceptanceAccepted ||
		created.InitialParticipant.Role != sharedspaces.RoleHost {
		t.Fatalf("provision=%+v err=%v", created, err)
	}
	retry, err := store.ProvisionSpace(ctx, provisioning, now+1)
	if err != nil || retry.Acceptance != relay.AcceptanceDuplicate ||
		retry.Relay.InitialDomain.DomainID != provisioning.Domain.Registration.DomainID {
		t.Fatalf("provision retry=%+v err=%v", retry, err)
	}
	status, err := store.GetSpaceStatus(ctx, admin)
	if err != nil || status.BootstrapReady || status.ActiveCheckpointEpoch != nil {
		t.Fatalf("status before bootstrap=%+v err=%v", status, err)
	}

	invitation, credential := postgresSharedSpaceInvitation(t, provisioning, admin, now+100)
	if _, err := store.CreateInvitation(ctx, admin, invitation, now+100); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeBootstrapNotReady) {
		t.Fatalf("invite before bootstrap err=%v", err)
	}
	relayStore := postgresstore.NewRelayStore(pool)
	hostCredential := relay.Credential{
		TenantID: provisioning.SpaceID, DomainID: provisioning.Domain.Registration.DomainID,
		MemberID: provisioning.InitialParticipantID, Token: postgresRelayToken(0x31),
	}
	fence, err := relayStore.CreateCheckpointFence(ctx, hostCredential, relay.CheckpointFenceRequest{
		RetryID: uuid.New(), FenceID: uuid.New(), RequestedAtMilliseconds: now + 50,
	}, now+50)
	if err != nil {
		t.Fatalf("bootstrap fence: %v", err)
	}
	checkpoint := relay.CheckpointCandidate{
		Version: relay.SchemaVersion, RetryID: uuid.New(), CheckpointID: uuid.New(),
		FenceID: fence.FenceID, TenantID: provisioning.SpaceID,
		DomainID:                provisioning.Domain.Registration.DomainID,
		PublisherSubscriptionID: provisioning.Domain.Subscription.SubscriptionID,
		KeyEpoch:                sharedspaces.InitialKeyEpoch,
		CoveredThroughCursor:    fence.BoundaryCursor,
		CreatedAtMilliseconds:   now + 50,
	}
	if _, err := store.StageCheckpoint(ctx, hostCredential, checkpoint, now+50); err != nil {
		t.Fatalf("bootstrap stage: %v", err)
	}
	if _, err := store.ActivateCheckpoint(ctx, admin, relay.CheckpointActivationRequest{
		RetryID: uuid.New(), CheckpointID: checkpoint.CheckpointID, ActivatedAtMilliseconds: now + 50,
	}, now+50); err != nil {
		t.Fatalf("bootstrap activation: %v", err)
	}
	cancelledInvitation, cancelledCredential := postgresSharedSpaceInvitation(t, provisioning, admin, now+60)
	if _, err := store.CreateInvitation(ctx, admin, cancelledInvitation, now+60); err != nil {
		t.Fatalf("invite for cancellation: %v", err)
	}
	cancellation := sharedspaces.InvitationCancellation{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(), SpaceID: provisioning.SpaceID,
		InvitationID: cancelledInvitation.InvitationID, CancelledAtMilliseconds: now + 70,
	}
	cancelled, err := store.CancelInvitation(ctx, admin, cancellation, now+70)
	if err != nil || cancelled.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("cancel invitation=%+v err=%v", cancelled, err)
	}
	cancelledRetry, err := store.CancelInvitation(ctx, admin, cancellation, now+71)
	if err != nil || cancelledRetry.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("cancel invitation retry=%+v err=%v", cancelledRetry, err)
	}
	cancelledMemberCredential := relay.Credential{
		TenantID: provisioning.SpaceID, DomainID: admin.DomainID,
		MemberID: cancelledInvitation.ParticipantID, Token: postgresRelayToken(0x62),
	}
	cancelledDigest, err := relay.AuthorizationDigest(cancelledMemberCredential)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimInvitation(ctx, cancelledCredential, sharedspaces.InvitationClaim{
		Version: sharedspaces.SchemaVersion, SpaceID: provisioning.SpaceID,
		ParticipantID: cancelledInvitation.ParticipantID,
		RelayClaim: relay.MemberAdmissionClaim{
			MemberID: cancelledInvitation.ParticipantID, AuthorizationDigest: cancelledDigest,
		},
		ClaimedAtMilliseconds: now + 80,
	}, now+80); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeInvitationCancelled) {
		t.Fatalf("claim cancelled invitation err=%v", err)
	}
	issued, err := store.CreateInvitation(ctx, admin, invitation, now+100)
	if err != nil || issued.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("invite=%+v err=%v", issued, err)
	}
	memberCredential := relay.Credential{
		TenantID: invitation.SpaceID, DomainID: invitation.RelayAdmission.DomainID,
		MemberID: invitation.ParticipantID, Token: postgresRelayToken(0x61),
	}
	memberDigest, err := relay.AuthorizationDigest(memberCredential)
	if err != nil {
		t.Fatal(err)
	}
	claim := sharedspaces.InvitationClaim{
		Version: sharedspaces.SchemaVersion, SpaceID: invitation.SpaceID,
		ParticipantID: invitation.ParticipantID,
		RelayClaim: relay.MemberAdmissionClaim{
			MemberID: invitation.ParticipantID, AuthorizationDigest: memberDigest,
		},
		ClaimedAtMilliseconds: now + 200,
	}
	claimed, err := store.ClaimInvitation(ctx, credential, claim, now+200)
	if err != nil || claimed.Acceptance != relay.AcceptanceAccepted ||
		claimed.CurrentKeyEpoch != sharedspaces.InitialKeyEpoch ||
		claimed.Participant.Role != sharedspaces.RoleParticipant {
		t.Fatalf("claim=%+v err=%v", claimed, err)
	}
	roster, err := postgresstore.NewSharedSpacesStore(pool).GetParticipantRoster(ctx, hostCredential, now+200)
	if err != nil || roster.AuthorityAttestation.Revision == 0 ||
		roster.CurrentKeyEpoch != sharedspaces.InitialKeyEpoch {
		t.Fatalf("persisted secure roster=%+v err=%v", roster, err)
	}
	wantRosterDigest, err := invitation.ActivationSecureRosterAttestation.Digest()
	if err != nil {
		t.Fatal(err)
	}
	gotRosterDigest, err := roster.AuthorityAttestation.Digest()
	if err != nil || gotRosterDigest != wantRosterDigest {
		t.Fatalf("persisted secure roster digest=%q want=%q err=%v", gotRosterDigest, wantRosterDigest, err)
	}
	deviceKeysByParticipant := make(map[uuid.UUID][]sharedspaces.ParticipantDeviceKey)
	for _, participant := range roster.AuthorityAttestation.Participants {
		deviceKeysByParticipant[participant.ParticipantID] = participant.DeviceKeys
	}
	if !reflect.DeepEqual(
		deviceKeysByParticipant[provisioning.InitialParticipantID],
		provisioning.InitialParticipantDeviceKeys,
	) || !reflect.DeepEqual(
		deviceKeysByParticipant[invitation.ParticipantID],
		invitation.ParticipantDeviceKeys,
	) {
		t.Fatalf("persisted participant device keys=%+v", deviceKeysByParticipant)
	}
	claimRetry, err := store.ClaimInvitation(ctx, credential, claim, now+201)
	if err != nil || claimRetry.Acceptance != relay.AcceptanceDuplicate ||
		claimRetry.CurrentKeyEpoch != sharedspaces.InitialKeyEpoch {
		t.Fatalf("claim retry=%+v err=%v", claimRetry, err)
	}
	invitationList, err := store.ListInvitations(ctx, admin, now+201)
	if err != nil {
		t.Fatalf("list invitations: %v", err)
	}
	invitationStates := map[uuid.UUID]sharedspaces.InvitationStatus{}
	for _, invitationStatus := range invitationList.Invitations {
		invitationStates[invitationStatus.InvitationID] = invitationStatus
	}
	if len(invitationStates) != 2 ||
		invitationStates[invitation.InvitationID].State != sharedspaces.InvitationClaimed ||
		invitationStates[invitation.InvitationID].ClaimedAtMilliseconds == nil ||
		invitationStates[cancelledInvitation.InvitationID].State != sharedspaces.InvitationCancelled ||
		invitationStates[cancelledInvitation.InvitationID].CancelledAtMilliseconds == nil {
		t.Fatalf("invitation list=%+v", invitationList)
	}
	presentationUpdate := sharedspaces.ParticipantPresentationUpdate{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(), SpaceID: invitation.SpaceID,
		ParticipantID: invitation.ParticipantID, PreviousRevision: 0, DisplayName: "Ada Lovelace",
		UpdatedAtMilliseconds: now + 205,
	}
	presentationResult, err := store.UpdateParticipantPresentation(
		ctx, memberCredential, presentationUpdate, now+205,
	)
	if err != nil || presentationResult.Acceptance != relay.AcceptanceAccepted ||
		presentationResult.Presentation.Revision != 1 ||
		presentationResult.Presentation.DisplayName != "Ada Lovelace" {
		t.Fatalf("participant presentation=%+v err=%v", presentationResult, err)
	}
	presentationRetry, err := store.UpdateParticipantPresentation(
		ctx, memberCredential, presentationUpdate, now+206,
	)
	if err != nil || presentationRetry.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("participant presentation retry=%+v err=%v", presentationRetry, err)
	}
	presentationCollision := presentationUpdate
	presentationCollision.RetryID = uuid.New()
	presentationCollision.DisplayName = "Countess of Lovelace"
	if _, err := store.UpdateParticipantPresentation(
		ctx, memberCredential, presentationCollision, now+207,
	); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeParticipantPresentationCollision) {
		t.Fatalf("participant presentation collision err=%v", err)
	}
	memberKeyGrant, err := store.GetParticipantKeyGrant(ctx, memberCredential, postgresParticipantDeviceID(memberCredential.MemberID), now+210)
	if err != nil || memberKeyGrant.KeyGrant.ParticipantID != invitation.ParticipantID ||
		memberKeyGrant.KeyGrant.KeyEpoch != sharedspaces.InitialKeyEpoch {
		t.Fatalf("member key grant=%+v err=%v", memberKeyGrant, err)
	}
	participantStatus, err := store.GetParticipantStatus(ctx, memberCredential, now+211)
	if err != nil || participantStatus.SecurityMode != sharedspaces.SecurityModeSecure ||
		participantStatus.InteractionMode != provisioning.InteractionMode ||
		participantStatus.CurrentKeyEpoch != sharedspaces.InitialKeyEpoch ||
		!participantStatus.BootstrapReady || participantStatus.ActiveCheckpointEpoch == nil ||
		*participantStatus.ActiveCheckpointEpoch != sharedspaces.InitialKeyEpoch ||
		participantStatus.Participant.ParticipantID != invitation.ParticipantID ||
		participantStatus.Participant.Role != sharedspaces.RoleParticipant ||
		participantStatus.Presentation == nil ||
		participantStatus.Presentation.DisplayName != "Ada Lovelace" ||
		!postgresSameCapabilities(
			participantStatus.Capabilities,
			sharedspaces.RoleParticipant.Capabilities(provisioning.InteractionMode),
		) {
		t.Fatalf("member participant status=%+v err=%v", participantStatus, err)
	}
	participantBootstrap, err := store.GetParticipantBootstrap(ctx, memberCredential, postgresParticipantDeviceID(memberCredential.MemberID), now+212)
	if err != nil || participantBootstrap.Status.Participant.ParticipantID != invitation.ParticipantID ||
		participantBootstrap.Status.CurrentKeyEpoch != sharedspaces.InitialKeyEpoch ||
		participantBootstrap.Status.Presentation == nil ||
		participantBootstrap.Status.Presentation.DisplayName != "Ada Lovelace" ||
		participantBootstrap.KeyGrant == nil ||
		participantBootstrap.Roster == nil ||
		participantBootstrap.Roster.CurrentKeyEpoch != participantBootstrap.Status.CurrentKeyEpoch ||
		len(participantBootstrap.Roster.Participants) != 2 ||
		participantBootstrap.KeyGrant.ParticipantID != invitation.ParticipantID ||
		participantBootstrap.KeyGrant.CurrentKeyEpoch != participantBootstrap.Status.CurrentKeyEpoch ||
		participantBootstrap.KeyGrant.KeyGrant.KeyEpoch != participantBootstrap.Status.CurrentKeyEpoch {
		t.Fatalf("member participant bootstrap=%+v err=%v", participantBootstrap, err)
	}
	demotion := sharedspaces.ParticipantRoleChange{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(), SpaceID: invitation.SpaceID,
		ParticipantID: invitation.ParticipantID, PreviousRole: sharedspaces.RoleParticipant,
		NextRole: sharedspaces.RoleReader, ChangedAtMilliseconds: now + 220,
	}
	demotion.SecureRosterAttestation = postgresRoleChangeRosterAttestation(
		t, provisioning, invitation, *invitation.ActivationSecureRosterAttestation,
		demotion.NextRole, demotion.ChangedAtMilliseconds,
	)
	demoted, err := store.ChangeParticipantRole(ctx, admin, demotion, now+220)
	if err != nil || demoted.Acceptance != relay.AcceptanceAccepted ||
		demoted.CurrentRole != sharedspaces.RoleReader {
		t.Fatalf("demotion=%+v err=%v", demoted, err)
	}
	demotedRetry, err := store.ChangeParticipantRole(ctx, admin, demotion, now+221)
	if err != nil || demotedRetry.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("demotion retry=%+v err=%v", demotedRetry, err)
	}
	promotion := sharedspaces.ParticipantRoleChange{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(), SpaceID: invitation.SpaceID,
		ParticipantID: invitation.ParticipantID, PreviousRole: sharedspaces.RoleReader,
		NextRole: sharedspaces.RoleParticipant, ChangedAtMilliseconds: now + 230,
	}
	promotion.SecureRosterAttestation = postgresRoleChangeRosterAttestation(
		t, provisioning, invitation, *demotion.SecureRosterAttestation,
		promotion.NextRole, promotion.ChangedAtMilliseconds,
	)
	promoted, err := store.ChangeParticipantRole(ctx, admin, promotion, now+230)
	if err != nil || promoted.Acceptance != relay.AcceptanceAccepted ||
		promoted.CurrentRole != sharedspaces.RoleParticipant {
		t.Fatalf("promotion=%+v err=%v", promoted, err)
	}
	thirdHostDeviceID := postgresParticipantTertiaryDeviceID(provisioning.InitialParticipantID)
	thirdHostDeviceKey := postgresParticipantDeviceKeyWithID(
		t, provisioning.SpaceID, provisioning.InitialParticipantID,
		thirdHostDeviceID, now+235,
	)
	deviceEnrollment := sharedspaces.ParticipantDeviceEnrollment{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(), SpaceID: provisioning.SpaceID,
		ParticipantID: provisioning.InitialParticipantID, DeviceKey: thirdHostDeviceKey,
		KeyGrant: postgresParticipantKeyGrantForDevice(
			t, provisioning.SpaceID, provisioning.InitialParticipantID,
			thirdHostDeviceID, provisioning.InitialParticipantID,
			sharedspaces.InitialKeyEpoch, now+235,
		),
		EnrolledAtMilliseconds: now + 235,
	}
	deviceEnrollment.SecureRosterAttestation = postgresDeviceEnrollmentRosterAttestation(
		t, provisioning, *promotion.SecureRosterAttestation,
		deviceEnrollment.ParticipantID, thirdHostDeviceKey, now+235,
	)
	enrolled, err := store.EnrollParticipantDevice(ctx, admin, deviceEnrollment, now+235)
	if err != nil || enrolled.Acceptance != relay.AcceptanceAccepted ||
		enrolled.DeviceID != thirdHostDeviceID {
		t.Fatalf("device enrollment=%+v err=%v", enrolled, err)
	}
	enrolledRetry, err := store.EnrollParticipantDevice(ctx, admin, deviceEnrollment, now+236)
	if err != nil || enrolledRetry.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("device enrollment retry=%+v err=%v", enrolledRetry, err)
	}
	thirdHostGrant, err := store.GetParticipantKeyGrant(
		ctx, hostCredential, thirdHostDeviceID, now+236,
	)
	if err != nil || thirdHostGrant.KeyGrant.RecipientDeviceID != thirdHostDeviceID {
		t.Fatalf("third host device grant=%+v err=%v", thirdHostGrant, err)
	}
	computePoolID := uuid.New()
	computeBindingID := uuid.New()
	computeChange := sharedspaces.SpaceComputeBindingChange{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(), SpaceID: provisioning.SpaceID,
		BindingID:                  computeBindingID,
		PoolAuthority:              postgresComputePoolAuthority(computePoolID),
		AllowedOperations:          []string{"facets.ai.classify", "facets.ai.embed"},
		EligibleRoleIdentifiers:    []string{string(sharedspaces.RoleHost)},
		AllowedProviderIdentifiers: []string{"facets.local"},
		ResourceCeiling: sharedspaces.ComputeResourceCeiling{
			MaximumInputBytes: 1 << 20, MaximumOutputBytes: 1 << 20,
			MaximumMemoryBytes: 1 << 30, MaximumWallTimeMilliseconds: 60_000,
		},
		BudgetCeiling:           testfixture.ComputeBudgetCeiling(),
		PricingRevision:         1,
		DataUseConstraints:      testfixture.ComputeDataUseConstraints("facets.local"),
		SourceAuthorityRevision: sharedspaces.InitialKeyEpoch,
		ChangedAtMilliseconds:   now + 240,
	}
	computeResult, err := store.ChangeComputeBinding(ctx, admin, computeChange, now+240)
	if err != nil || computeResult.Acceptance != relay.AcceptanceAccepted ||
		computeResult.Binding.Revision != 1 {
		t.Fatalf("compute binding=%+v err=%v", computeResult, err)
	}
	computeRetry, err := store.ChangeComputeBinding(ctx, admin, computeChange, now+241)
	if err != nil || computeRetry.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("compute binding retry=%+v err=%v", computeRetry, err)
	}

	status, err = store.GetSpaceStatus(ctx, admin)
	if err != nil || status.CurrentKeyEpoch != sharedspaces.InitialKeyEpoch ||
		!status.BootstrapReady || status.ActiveCheckpointEpoch == nil ||
		*status.ActiveCheckpointEpoch != sharedspaces.InitialKeyEpoch ||
		len(status.Participants) != 2 || status.Relay.ActiveSubscriptionCount != 2 ||
		len(status.Presentations) != 1 || len(status.ComputeBindings) != 1 ||
		status.Presentations[0].ParticipantID != invitation.ParticipantID ||
		status.Presentations[0].DisplayName != "Ada Lovelace" ||
		status.ComputeBindings[0].PoolAuthority.PoolID != computePoolID ||
		status.ComputeBindings[0].BindingID != computeBindingID {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	revocation := sharedspaces.ParticipantRevocation{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(),
		SpaceID: invitation.SpaceID, ParticipantID: invitation.ParticipantID,
		PreviousKeyEpoch: sharedspaces.InitialKeyEpoch, NextKeyEpoch: sharedspaces.InitialKeyEpoch + 1,
		KeyGrants: []sharedspaces.ParticipantKeyGrant{
			*postgresParticipantKeyGrant(
				t, invitation.SpaceID, provisioning.InitialParticipantID,
				provisioning.InitialParticipantID, sharedspaces.InitialKeyEpoch+1, now+300,
			),
			*postgresParticipantKeyGrantForDevice(
				t, invitation.SpaceID, provisioning.InitialParticipantID,
				postgresParticipantSecondaryDeviceID(provisioning.InitialParticipantID),
				provisioning.InitialParticipantID, sharedspaces.InitialKeyEpoch+1, now+300,
			),
			*postgresParticipantKeyGrantForDevice(
				t, invitation.SpaceID, provisioning.InitialParticipantID,
				thirdHostDeviceID, provisioning.InitialParticipantID,
				sharedspaces.InitialKeyEpoch+1, now+300,
			),
		},
	}
	previousRevocationDigest, err := deviceEnrollment.SecureRosterAttestation.Digest()
	if err != nil {
		t.Fatal(err)
	}
	remainingHost := postgresInitialSharedSpaceParticipant(provisioning)
	remainingHost.DeviceKeys = append(remainingHost.DeviceKeys, thirdHostDeviceKey)
	sort.Slice(remainingHost.DeviceKeys, func(left, right int) bool {
		return remainingHost.DeviceKeys[left].DeviceID.String() <
			remainingHost.DeviceKeys[right].DeviceID.String()
	})
	remainingParticipants := []sharedspaces.Participant{remainingHost}
	revocation.SecureRosterAttestation = postgresSecureRosterAttestation(
		t, provisioning, deviceEnrollment.SecureRosterAttestation.Revision+1,
		previousRevocationDigest, sharedspaces.InitialKeyEpoch+1, remainingParticipants,
		provisioning.InitialParticipantID, now+300,
	)
	revoked, err := store.RevokeParticipant(ctx, admin, revocation, now+300)
	if err != nil || revoked.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("revoke=%+v err=%v", revoked, err)
	}
	revokedRetry, err := store.RevokeParticipant(ctx, admin, revocation, now+301)
	if err != nil || revokedRetry.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("revoke retry=%+v err=%v", revokedRetry, err)
	}
	hostKeyGrant, err := store.GetParticipantKeyGrant(ctx, hostCredential, postgresParticipantDeviceID(hostCredential.MemberID), now+301)
	if err != nil || hostKeyGrant.KeyGrant.ParticipantID != provisioning.InitialParticipantID ||
		hostKeyGrant.KeyGrant.KeyEpoch != sharedspaces.InitialKeyEpoch+1 {
		t.Fatalf("host key grant=%+v err=%v", hostKeyGrant, err)
	}
	secondHostKeyGrant, err := store.GetParticipantKeyGrant(
		ctx, hostCredential, postgresParticipantSecondaryDeviceID(hostCredential.MemberID), now+301,
	)
	if err != nil || secondHostKeyGrant.KeyGrant.RecipientDeviceID != postgresParticipantSecondaryDeviceID(hostCredential.MemberID) {
		t.Fatalf("second host device key grant=%+v err=%v", secondHostKeyGrant, err)
	}
	thirdRotatedHostGrant, err := store.GetParticipantKeyGrant(
		ctx, hostCredential, thirdHostDeviceID, now+301,
	)
	if err != nil || thirdRotatedHostGrant.KeyGrant.RecipientDeviceID != thirdHostDeviceID ||
		thirdRotatedHostGrant.KeyGrant.KeyEpoch != sharedspaces.InitialKeyEpoch+1 {
		t.Fatalf("third rotated host device grant=%+v err=%v", thirdRotatedHostGrant, err)
	}
	status, err = store.GetSpaceStatus(ctx, admin)
	if err != nil || status.CurrentKeyEpoch != sharedspaces.InitialKeyEpoch+1 ||
		status.BootstrapReady || status.ActiveCheckpointEpoch == nil ||
		*status.ActiveCheckpointEpoch != sharedspaces.InitialKeyEpoch {
		t.Fatalf("status after revocation: %v", err)
	}
	retry, err = store.ProvisionSpace(ctx, provisioning, now+302)
	if err != nil || retry.Acceptance != relay.AcceptanceDuplicate ||
		retry.CurrentKeyEpoch != sharedspaces.InitialKeyEpoch+1 {
		t.Fatalf("provision retry after key rotation=%+v err=%v", retry, err)
	}
	if _, err := relayStore.Fetch(ctx, memberCredential, 0, 1, now+301); !relay.ErrorHasCode(err, relay.CodeMemberRevoked) {
		t.Fatalf("revoked participant relay access err=%v", err)
	}
	if _, err := store.GetParticipantStatus(ctx, memberCredential, now+301); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeParticipantRevoked) {
		t.Fatalf("revoked participant status err=%v", err)
	}
	if _, err := store.GetParticipantBootstrap(ctx, memberCredential, postgresParticipantDeviceID(memberCredential.MemberID), now+301); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeParticipantRevoked) {
		t.Fatalf("revoked participant bootstrap err=%v", err)
	}
	if _, err := store.UpdateParticipantPresentation(
		ctx, memberCredential, presentationUpdate, now+301,
	); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeParticipantRevoked) {
		t.Fatalf("revoked participant presentation err=%v", err)
	}
	authorityEvents, err := store.ListAuthorityEvents(ctx, admin, 0, 100)
	if err != nil || len(authorityEvents.Events) != 10 || authorityEvents.NextSequence == 0 {
		t.Fatalf("authority events=%+v err=%v", authorityEvents, err)
	}
	wantAuthorityEvents := []sharedspaces.AuthorityEventType{
		sharedspaces.AuthorityEventSpaceProvisioned,
		sharedspaces.AuthorityEventInvitationCreated,
		sharedspaces.AuthorityEventInvitationCancelled,
		sharedspaces.AuthorityEventInvitationCreated,
		sharedspaces.AuthorityEventInvitationClaimed,
		sharedspaces.AuthorityEventParticipantRoleChanged,
		sharedspaces.AuthorityEventParticipantRoleChanged,
		sharedspaces.AuthorityEventParticipantDeviceEnrolled,
		sharedspaces.AuthorityEventSpaceComputeBindingChanged,
		sharedspaces.AuthorityEventParticipantRevoked,
	}
	for index, eventType := range wantAuthorityEvents {
		if authorityEvents.Events[index].EventType != eventType {
			t.Fatalf("authority event %d type=%q want=%q", index, authorityEvents.Events[index].EventType, eventType)
		}
		if index > 0 && authorityEvents.Events[index].Sequence <= authorityEvents.Events[index-1].Sequence {
			t.Fatalf("authority event sequences are not strictly increasing: %+v", authorityEvents.Events)
		}
	}
	for _, index := range []int{0, 4, 5, 6, 7, 9} {
		if authorityEvents.Events[index].SecureRosterDigest == nil {
			t.Fatalf("secure authority event %d is missing roster digest: %+v", index, authorityEvents.Events[index])
		}
	}
	for _, index := range []int{1, 2, 3, 8} {
		if authorityEvents.Events[index].SecureRosterDigest != nil {
			t.Fatalf("non-roster authority event %d unexpectedly has digest: %+v", index, authorityEvents.Events[index])
		}
	}
	if authorityEvents.NextSequence != authorityEvents.Events[len(authorityEvents.Events)-1].Sequence {
		t.Fatalf("next sequence=%d want=%d", authorityEvents.NextSequence, authorityEvents.Events[len(authorityEvents.Events)-1].Sequence)
	}

	var participantCount, relayMemberCount, revokedSubscriptionCount int
	var cancellationCount, revokedAdmissionCount, cancelledSubscriptionCount, keyGrantCount int
	var computeBindingCount, computeChangeCount int
	if err := pool.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM shared_space_participants
			 WHERE space_id=$1 AND participant_id=$2 AND revoked_at_milliseconds=$3),
			(SELECT count(*) FROM relay_members
			 WHERE tenant_id=$1 AND domain_id=$4 AND member_id=$2 AND revoked_at_milliseconds=$3),
			(SELECT count(*) FROM relay_subscriptions
			 WHERE tenant_id=$1 AND domain_id=$4 AND subscription_id=$5 AND status='revoked'),
			(SELECT count(*) FROM shared_space_invitation_cancellations
			 WHERE space_id=$1 AND invitation_id=$6),
			(SELECT count(*) FROM relay_member_admissions
			 WHERE tenant_id=$1 AND domain_id=$4 AND admission_id=$6 AND revoked_at_milliseconds=$7),
			(SELECT count(*) FROM relay_subscriptions
			 WHERE tenant_id=$1 AND domain_id=$4 AND subscription_id=$8 AND status='revoked'),
			(SELECT count(*) FROM shared_space_participant_key_grants
			 WHERE space_id=$1),
			(SELECT count(*) FROM shared_space_compute_bindings
			 WHERE space_id=$1 AND binding_id=$9),
			(SELECT count(*) FROM shared_space_compute_binding_changes
			 WHERE space_id=$1 AND binding_id=$9)
	`, invitation.SpaceID, invitation.ParticipantID, revoked.RevokedAtMilliseconds,
		admin.DomainID, invitation.SubscriptionID, cancelledInvitation.InvitationID,
		cancellation.CancelledAtMilliseconds, cancelledInvitation.SubscriptionID, computeBindingID).Scan(
		&participantCount, &relayMemberCount, &revokedSubscriptionCount,
		&cancellationCount, &revokedAdmissionCount, &cancelledSubscriptionCount, &keyGrantCount,
		&computeBindingCount, &computeChangeCount,
	); err != nil {
		t.Fatal(err)
	}
	if participantCount != 1 || relayMemberCount != 1 || revokedSubscriptionCount != 1 ||
		cancellationCount != 1 || revokedAdmissionCount != 1 || cancelledSubscriptionCount != 1 ||
		keyGrantCount != 5 || computeBindingCount != 1 || computeChangeCount != 1 {
		t.Fatalf(
			"product=%d member=%d subscription=%d cancellation=%d admission=%d cancelled subscription=%d key grants=%d compute pools=%d compute changes=%d",
			participantCount, relayMemberCount, revokedSubscriptionCount,
			cancellationCount, revokedAdmissionCount, cancelledSubscriptionCount, keyGrantCount,
			computeBindingCount, computeChangeCount,
		)
	}
}

func TestPostgresManagedSharedSpaceKeyCustodyIsAtomicWithAuthority(t *testing.T) {
	databaseURL := os.Getenv("FACETS_SERVER_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("FACETS_SERVER_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	lockDisposablePostgres(t, ctx, databaseURL)
	pool := openPool(t, ctx, databaseURL)
	defer pool.Close()
	if err := postgresstore.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `TRUNCATE relay_tenants CASCADE`); err != nil {
		t.Fatal(err)
	}

	custodian, err := keycustody.NewManagedContentKeys(bytes.Repeat([]byte{0xa5}, keycustody.ContentKeySize))
	if err != nil {
		t.Fatal(err)
	}
	store := postgresstore.NewSharedSpacesStore(pool, custodian)
	const now = int64(20_000)
	provisioning, admin := postgresSharedSpaceProvisioning(t, now)
	provisioning.SecurityMode = sharedspaces.SecurityModeManaged
	provisioning.InitialSecureRosterAttestation = nil
	created, err := store.ProvisionSpace(ctx, provisioning, now)
	if err != nil || created.Acceptance != relay.AcceptanceAccepted ||
		created.SecurityMode != sharedspaces.SecurityModeManaged {
		t.Fatalf("managed provision=%+v err=%v", created, err)
	}

	relayStore := postgresstore.NewRelayStore(pool)
	hostCredential := relay.Credential{
		TenantID: provisioning.SpaceID, DomainID: provisioning.Domain.Registration.DomainID,
		MemberID: provisioning.InitialParticipantID, Token: postgresRelayToken(0x31),
	}
	activatePostgresSharedSpaceCheckpoint(
		t, ctx, relayStore, store, provisioning, admin, hostCredential, now+50,
	)

	invitation, invitationCredential := postgresSharedSpaceInvitation(t, provisioning, admin, now+100)
	if invitation.KeyGrant != nil {
		t.Fatalf("managed invitation unexpectedly includes E2EE grant=%+v", invitation.KeyGrant)
	}
	if _, err := store.CreateInvitation(ctx, admin, invitation, now+100); err != nil {
		t.Fatalf("managed invitation: %v", err)
	}
	memberCredential := relay.Credential{
		TenantID: provisioning.SpaceID, DomainID: admin.DomainID,
		MemberID: invitation.ParticipantID, Token: postgresRelayToken(0x61),
	}
	memberDigest, err := relay.AuthorizationDigest(memberCredential)
	if err != nil {
		t.Fatal(err)
	}
	claim := sharedspaces.InvitationClaim{
		Version: sharedspaces.SchemaVersion, SpaceID: provisioning.SpaceID,
		ParticipantID: invitation.ParticipantID,
		RelayClaim: relay.MemberAdmissionClaim{
			MemberID: invitation.ParticipantID, AuthorizationDigest: memberDigest,
		},
		ClaimedAtMilliseconds: now + 200,
	}
	claimed, err := store.ClaimInvitation(ctx, invitationCredential, claim, now+200)
	if err != nil || claimed.Acceptance != relay.AcceptanceAccepted || claimed.KeyGrant != nil {
		t.Fatalf("managed claim=%+v err=%v", claimed, err)
	}

	hostBootstrap, err := store.GetParticipantBootstrap(ctx, hostCredential, postgresParticipantDeviceID(hostCredential.MemberID), now+210)
	if err != nil {
		t.Fatalf("managed host bootstrap: %v", err)
	}
	memberBootstrap, err := store.GetParticipantBootstrap(ctx, memberCredential, postgresParticipantDeviceID(memberCredential.MemberID), now+211)
	if err != nil {
		t.Fatalf("managed member bootstrap: %v", err)
	}
	if hostBootstrap.ManagedContentKey == nil || memberBootstrap.ManagedContentKey == nil ||
		hostBootstrap.KeyGrant != nil || memberBootstrap.KeyGrant != nil ||
		hostBootstrap.ManagedContentKey.KeyMaterial != memberBootstrap.ManagedContentKey.KeyMaterial ||
		hostBootstrap.ManagedContentKey.KeyEpoch != sharedspaces.InitialKeyEpoch ||
		memberBootstrap.ManagedContentKey.KeyEpoch != sharedspaces.InitialKeyEpoch {
		t.Fatalf("managed bootstraps host=%+v member=%+v", hostBootstrap, memberBootstrap)
	}
	previousKeyMaterial := hostBootstrap.ManagedContentKey.KeyMaterial

	revocation := sharedspaces.ParticipantRevocation{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(),
		SpaceID: provisioning.SpaceID, ParticipantID: invitation.ParticipantID,
		PreviousKeyEpoch: sharedspaces.InitialKeyEpoch,
		NextKeyEpoch:     sharedspaces.InitialKeyEpoch + 1,
	}
	revoked, err := store.RevokeParticipant(ctx, admin, revocation, now+300)
	if err != nil || revoked.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("managed revoke=%+v err=%v", revoked, err)
	}
	if _, err := store.GetParticipantBootstrap(ctx, memberCredential, postgresParticipantDeviceID(memberCredential.MemberID), now+301); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeParticipantRevoked) {
		t.Fatalf("revoked managed participant bootstrap err=%v", err)
	}
	rotatedHostBootstrap, err := store.GetParticipantBootstrap(ctx, hostCredential, postgresParticipantDeviceID(hostCredential.MemberID), now+302)
	if err != nil || rotatedHostBootstrap.ManagedContentKey == nil ||
		rotatedHostBootstrap.ManagedContentKey.KeyEpoch != sharedspaces.InitialKeyEpoch+1 ||
		rotatedHostBootstrap.ManagedContentKey.KeyMaterial == previousKeyMaterial ||
		rotatedHostBootstrap.Status.BootstrapReady {
		t.Fatalf("rotated managed host bootstrap=%+v err=%v", rotatedHostBootstrap, err)
	}

	var managedKeyCount int
	if err := pool.QueryRow(ctx, `
		SELECT count(*)
		FROM shared_space_managed_content_keys
		WHERE space_id=$1
	`, provisioning.SpaceID).Scan(&managedKeyCount); err != nil {
		t.Fatal(err)
	}
	if managedKeyCount != 2 {
		t.Fatalf("managed content-key count=%d want=2", managedKeyCount)
	}
}

func TestPostgresSharedSpaceParticipantDeviceRevocationIsAtomic(t *testing.T) {
	databaseURL := os.Getenv("FACETS_SERVER_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("FACETS_SERVER_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	lockDisposablePostgres(t, ctx, databaseURL)
	pool := openPool(t, ctx, databaseURL)
	defer pool.Close()
	if err := postgresstore.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `TRUNCATE relay_tenants CASCADE`); err != nil {
		t.Fatal(err)
	}
	store := postgresstore.NewSharedSpacesStore(pool)
	relayStore := postgresstore.NewRelayStore(pool)
	const now = int64(40_000)
	provisioning, admin := postgresSharedSpaceProvisioning(t, now)
	if _, err := store.ProvisionSpace(ctx, provisioning, now); err != nil {
		t.Fatal(err)
	}
	hostCredential := relay.Credential{
		TenantID: provisioning.SpaceID, DomainID: provisioning.Domain.Registration.DomainID,
		MemberID: provisioning.InitialParticipantID, Token: postgresRelayToken(0x31),
	}
	activatePostgresSharedSpaceCheckpoint(
		t, ctx, relayStore, store, provisioning, admin, hostCredential, now+10,
	)
	secondDevice := postgresParticipantDeviceKeyWithID(
		t, provisioning.SpaceID, provisioning.InitialParticipantID,
		postgresParticipantTertiaryDeviceID(provisioning.InitialParticipantID), now+20,
	)
	enrollment := sharedspaces.ParticipantDeviceEnrollment{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(), SpaceID: provisioning.SpaceID,
		ParticipantID: provisioning.InitialParticipantID, DeviceKey: secondDevice,
		KeyGrant: postgresParticipantKeyGrantForDevice(
			t, provisioning.SpaceID, provisioning.InitialParticipantID, secondDevice.DeviceID,
			provisioning.InitialParticipantID, sharedspaces.InitialKeyEpoch, now+20,
		),
		EnrolledAtMilliseconds: now + 20,
	}
	enrollment.SecureRosterAttestation = postgresDeviceEnrollmentRosterAttestation(
		t, provisioning, *provisioning.InitialSecureRosterAttestation,
		enrollment.ParticipantID, secondDevice, now+20,
	)
	if _, err := store.EnrollParticipantDevice(ctx, admin, enrollment, now+20); err != nil {
		t.Fatal(err)
	}
	initialDevice := provisioning.InitialParticipantDeviceKeys[0]
	revocation := sharedspaces.ParticipantDeviceRevocation{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(), SpaceID: provisioning.SpaceID,
		ParticipantID: provisioning.InitialParticipantID, DeviceID: secondDevice.DeviceID,
		DeviceKey:        postgresRevokedParticipantDeviceKey(t, secondDevice, now+30),
		PreviousKeyEpoch: sharedspaces.InitialKeyEpoch,
		NextKeyEpoch:     sharedspaces.InitialKeyEpoch + 1,
	}
	for _, device := range provisioning.InitialParticipantDeviceKeys {
		revocation.KeyGrants = append(revocation.KeyGrants, *postgresParticipantKeyGrantForDevice(
			t, provisioning.SpaceID, provisioning.InitialParticipantID, device.DeviceID,
			provisioning.InitialParticipantID, sharedspaces.InitialKeyEpoch+1, now+30,
		))
	}
	revocation.SecureRosterAttestation = postgresDeviceRevocationRosterAttestation(
		t, provisioning, *enrollment.SecureRosterAttestation,
		revocation.DeviceKey, revocation.NextKeyEpoch, now+30,
	)
	result, err := store.RevokeParticipantDevice(ctx, admin, revocation, now+30)
	if err != nil || result.Acceptance != relay.AcceptanceAccepted ||
		result.CurrentKeyEpoch != sharedspaces.InitialKeyEpoch+1 {
		t.Fatalf("device revocation=%+v err=%v", result, err)
	}
	retry, err := store.RevokeParticipantDevice(ctx, admin, revocation, now+31)
	if err != nil || retry.Acceptance != relay.AcceptanceDuplicate ||
		retry.RevokedAtMilliseconds != now+30 {
		t.Fatalf("device revocation retry=%+v err=%v", retry, err)
	}
	status, err := store.GetParticipantStatus(ctx, hostCredential, now+31)
	if err != nil || status.BootstrapReady || status.CurrentKeyEpoch != sharedspaces.InitialKeyEpoch+1 {
		t.Fatalf("status after device revocation=%+v err=%v", status, err)
	}
	if _, err := store.GetParticipantKeyGrant(ctx, hostCredential, secondDevice.DeviceID, now+31); !sharedspaces.ErrorHasCode(
		err, sharedspaces.CodeKeyGrantNotFound,
	) {
		t.Fatalf("revoked device grant err=%v", err)
	}
	grant, err := store.GetParticipantKeyGrant(ctx, hostCredential, initialDevice.DeviceID, now+31)
	if err != nil || grant.CurrentKeyEpoch != sharedspaces.InitialKeyEpoch+1 {
		t.Fatalf("remaining device grant=%+v err=%v", grant, err)
	}
	events, err := store.ListAuthorityEvents(ctx, admin, 0, 10)
	if err != nil || len(events.Events) != 3 ||
		events.Events[2].EventType != sharedspaces.AuthorityEventParticipantDeviceRevoked {
		t.Fatalf("authority events=%+v err=%v", events, err)
	}
}

func activatePostgresSharedSpaceCheckpoint(
	t *testing.T,
	ctx context.Context,
	relayStore *postgresstore.RelayStore,
	store *postgresstore.SharedSpacesStore,
	provisioning sharedspaces.SpaceProvisioning,
	admin relay.AdministrationCredential,
	hostCredential relay.Credential,
	now int64,
) {
	t.Helper()
	fence, err := relayStore.CreateCheckpointFence(ctx, hostCredential, relay.CheckpointFenceRequest{
		RetryID: uuid.New(), FenceID: uuid.New(), RequestedAtMilliseconds: now,
	}, now)
	if err != nil {
		t.Fatalf("managed bootstrap fence: %v", err)
	}
	checkpoint := relay.CheckpointCandidate{
		Version: relay.SchemaVersion, RetryID: uuid.New(), CheckpointID: uuid.New(),
		FenceID: fence.FenceID, TenantID: provisioning.SpaceID,
		DomainID:                provisioning.Domain.Registration.DomainID,
		PublisherSubscriptionID: provisioning.Domain.Subscription.SubscriptionID,
		KeyEpoch:                sharedspaces.InitialKeyEpoch,
		CoveredThroughCursor:    fence.BoundaryCursor,
		CreatedAtMilliseconds:   now,
	}
	if _, err := store.StageCheckpoint(ctx, hostCredential, checkpoint, now); err != nil {
		t.Fatalf("managed bootstrap stage: %v", err)
	}
	if _, err := store.ActivateCheckpoint(ctx, admin, relay.CheckpointActivationRequest{
		RetryID: uuid.New(), CheckpointID: checkpoint.CheckpointID,
		ActivatedAtMilliseconds: now,
	}, now); err != nil {
		t.Fatalf("managed bootstrap activation: %v", err)
	}
}

func postgresSharedSpaceProvisioning(
	t *testing.T,
	now int64,
) (sharedspaces.SpaceProvisioning, relay.AdministrationCredential) {
	t.Helper()
	spaceID := uuid.New()
	domainID := uuid.New()
	hostID := uuid.New()
	tenantCredential := relay.TenantCredential{TenantID: spaceID, Token: postgresRelayToken(0x11)}
	tenantDigest, err := relay.TenantAuthorizationDigest(tenantCredential)
	if err != nil {
		t.Fatal(err)
	}
	admin := relay.AdministrationCredential{TenantID: spaceID, DomainID: domainID, Token: postgresRelayToken(0x21)}
	adminDigest, err := relay.AdministrationDigest(admin)
	if err != nil {
		t.Fatal(err)
	}
	hostCredential := relay.Credential{
		TenantID: spaceID, DomainID: domainID, MemberID: hostID, Token: postgresRelayToken(0x31),
	}
	hostDigest, err := relay.AuthorizationDigest(hostCredential)
	if err != nil {
		t.Fatal(err)
	}
	provisioning := sharedspaces.SpaceProvisioning{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(), SpaceID: spaceID,
		SecurityMode:                 sharedspaces.SecurityModeSecure,
		InteractionMode:              sharedspaces.InteractionModeCollaborative,
		InitialParticipantID:         hostID,
		InitialParticipantKind:       sharedspaces.ParticipantPerson,
		InitialParticipantSigningKey: postgresParticipantSigningKey(t, hostID),
		InitialParticipantDeviceKeys: []sharedspaces.ParticipantDeviceKey{
			postgresParticipantDeviceKey(t, spaceID, hostID, now),
			postgresParticipantDeviceKeyWithID(
				t, spaceID, hostID, postgresParticipantSecondaryDeviceID(hostID), now,
			),
		},
		Tenant: relay.TenantRegistration{
			Version: relay.SchemaVersion, RetryID: uuid.New(), TenantID: spaceID,
			AuthorizationDigest: tenantDigest, CreatedAtMilliseconds: now,
			MaximumDomainCount:               1,
			MaximumAggregateMessageCount:     relay.DefaultMaximumMessageCount,
			MaximumAggregateMessageByteCount: relay.DefaultMaximumMessageByteCount,
			MaximumAggregateBlobCount:        relay.DefaultMaximumBlobCount,
			MaximumAggregateBlobByteCount:    relay.DefaultMaximumBlobByteCount,
		},
		CreatedAtMilliseconds: now,
	}
	sort.Slice(provisioning.InitialParticipantDeviceKeys, func(left, right int) bool {
		return provisioning.InitialParticipantDeviceKeys[left].DeviceID.String() <
			provisioning.InitialParticipantDeviceKeys[right].DeviceID.String()
	})
	provisioning.Domain = relay.DomainProvisioning{
		Version: relay.SchemaVersion, RetryID: uuid.New(),
		Registration: relay.DomainRegistration{
			Version: relay.SchemaVersion, TenantID: spaceID, DomainID: domainID,
			AdministrationDigest: adminDigest, CreatedAtMilliseconds: now,
			MaximumMessageCount:     relay.DefaultMaximumMessageCount,
			MaximumMessageByteCount: relay.DefaultMaximumMessageByteCount,
			MaximumBlobCount:        relay.DefaultMaximumBlobCount,
			MaximumBlobByteCount:    relay.DefaultMaximumBlobByteCount,
		},
		Subscription: relay.Subscription{
			Version: relay.SchemaVersion, TenantID: spaceID, DomainID: domainID,
			SubscriptionID: uuid.New(), Status: relay.SubscriptionActive,
			CreatedAtMilliseconds: now, UpdatedAtMilliseconds: now,
		},
		InitialMember: relay.MemberRegistration{
			Version: relay.SchemaVersion, TenantID: spaceID, DomainID: domainID,
			MemberID: hostID, AuthorizationDigest: hostDigest,
			Capabilities:          sharedspaces.RoleHost.Capabilities(provisioning.InteractionMode),
			CreatedAtMilliseconds: now,
		},
	}
	provisioning.InitialSecureRosterAttestation = postgresSecureRosterAttestation(
		t, provisioning, 1, "", sharedspaces.InitialKeyEpoch,
		[]sharedspaces.Participant{postgresInitialSharedSpaceParticipant(provisioning)},
		hostID, now,
	)
	return provisioning, admin
}

func postgresSharedSpaceInvitation(
	t *testing.T,
	space sharedspaces.SpaceProvisioning,
	admin relay.AdministrationCredential,
	now int64,
) (sharedspaces.Invitation, sharedspaces.InvitationCredential) {
	t.Helper()
	invitationID := uuid.New()
	credential := sharedspaces.InvitationCredential{
		SpaceID: space.SpaceID, DomainID: admin.DomainID,
		InvitationID: invitationID, Token: postgresRelayToken(0x51),
	}
	digest, err := relay.AdmissionAuthorizationDigest(relay.AdmissionCredential{
		TenantID: credential.SpaceID, DomainID: credential.DomainID,
		AdmissionID: credential.InvitationID, Token: credential.Token,
	})
	if err != nil {
		t.Fatal(err)
	}
	participantID := uuid.New()
	invitation := sharedspaces.Invitation{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(), SpaceID: space.SpaceID,
		InvitationID: invitationID, ParticipantID: participantID, SubscriptionID: uuid.New(),
		Kind: sharedspaces.ParticipantPerson, Role: sharedspaces.RoleParticipant,
		ParticipantSigningKey: postgresParticipantSigningKey(t, participantID),
		ParticipantDeviceKeys: []sharedspaces.ParticipantDeviceKey{
			postgresParticipantDeviceKey(t, space.SpaceID, participantID, now),
		},
		InteractionMode: space.InteractionMode, CreatedAtMilliseconds: now,
		RelayAdmission: relay.MemberAdmission{
			Version: relay.SchemaVersion, TenantID: space.SpaceID, DomainID: admin.DomainID,
			AdmissionID: invitationID, AuthorizationDigest: digest,
			Capabilities:          sharedspaces.RoleParticipant.Capabilities(space.InteractionMode),
			CreatedAtMilliseconds: now, ExpiresAtMilliseconds: now + 60*60*1_000,
		},
	}
	if space.SecurityMode.ContentBlind() {
		invitation.KeyGrant = postgresParticipantKeyGrant(
			t, space.SpaceID, invitation.ParticipantID, space.InitialParticipantID,
			sharedspaces.InitialKeyEpoch, now,
		)
	}
	if space.SecurityMode == sharedspaces.SecurityModeSecure {
		host := postgresInitialSharedSpaceParticipant(space)
		participant := sharedspaces.Participant{
			Version: sharedspaces.SchemaVersion, SpaceID: space.SpaceID,
			ParticipantID: participantID, SubscriptionID: invitation.SubscriptionID,
			Kind: invitation.Kind, Role: invitation.Role,
			SigningKey:            invitation.ParticipantSigningKey,
			DeviceKeys:            invitation.ParticipantDeviceKeys,
			CreatedAtMilliseconds: now,
		}
		previousDigest, err := space.InitialSecureRosterAttestation.Digest()
		if err != nil {
			t.Fatal(err)
		}
		invitation.ActivationSecureRosterAttestation = postgresSecureRosterAttestation(
			t, space, space.InitialSecureRosterAttestation.Revision+1,
			previousDigest, sharedspaces.InitialKeyEpoch,
			postgresSortedParticipants([]sharedspaces.Participant{host, participant}),
			space.InitialParticipantID, now,
		)
	}
	return invitation, credential
}

func postgresInitialSharedSpaceParticipant(space sharedspaces.SpaceProvisioning) sharedspaces.Participant {
	return sharedspaces.Participant{
		Version: sharedspaces.SchemaVersion, SpaceID: space.SpaceID,
		ParticipantID:  space.InitialParticipantID,
		SubscriptionID: space.Domain.Subscription.SubscriptionID,
		Kind:           space.InitialParticipantKind, Role: sharedspaces.RoleHost,
		SigningKey:            space.InitialParticipantSigningKey,
		DeviceKeys:            space.InitialParticipantDeviceKeys,
		CreatedAtMilliseconds: space.CreatedAtMilliseconds,
	}
}

func postgresSortedParticipants(participants []sharedspaces.Participant) []sharedspaces.Participant {
	sorted := append([]sharedspaces.Participant(nil), participants...)
	sort.Slice(sorted, func(left, right int) bool {
		return sorted[left].ParticipantID.String() < sorted[right].ParticipantID.String()
	})
	return sorted
}

func postgresSecureRosterAttestation(
	t *testing.T,
	space sharedspaces.SpaceProvisioning,
	revision uint64,
	previousDigest string,
	keyEpoch uint64,
	participants []sharedspaces.Participant,
	issuerParticipantID uuid.UUID,
	createdAtMilliseconds int64,
) *sharedspaces.SecureRosterAttestation {
	t.Helper()
	privateKey := postgresParticipantSigningPrivateKey(t, issuerParticipantID)
	publicKey := elliptic.Marshal(elliptic.P256(), privateKey.PublicKey.X, privateKey.PublicKey.Y)
	fingerprint := sha256.Sum256(publicKey)
	attestation := sharedspaces.SecureRosterAttestation{
		Version: sharedspaces.SchemaVersion, SpaceID: space.SpaceID,
		DomainID: space.Domain.Registration.DomainID,
		Revision: revision, PreviousDigest: previousDigest, CurrentKeyEpoch: keyEpoch,
		Participants:          postgresSortedParticipants(participants),
		IssuerParticipantID:   issuerParticipantID,
		CreatedAtMilliseconds: createdAtMilliseconds,
		Signature: sharedspaces.ParticipantKeyGrantSignature{
			Algorithm:             sharedspaces.ParticipantKeyGrantSignatureAlgorithm,
			PublicSigningKeyX963:  base64.RawURLEncoding.EncodeToString(publicKey),
			SigningKeyFingerprint: hex.EncodeToString(fingerprint[:]),
		},
	}
	payload, err := attestation.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	attestation.Signature.Signature = base64.RawURLEncoding.EncodeToString(signature)
	return &attestation
}

func postgresRoleChangeRosterAttestation(
	t *testing.T,
	space sharedspaces.SpaceProvisioning,
	invitation sharedspaces.Invitation,
	previous sharedspaces.SecureRosterAttestation,
	nextRole sharedspaces.Role,
	changedAtMilliseconds int64,
) *sharedspaces.SecureRosterAttestation {
	t.Helper()
	previousDigest, err := previous.Digest()
	if err != nil {
		t.Fatal(err)
	}
	participants := append([]sharedspaces.Participant(nil), previous.Participants...)
	for index := range participants {
		if participants[index].ParticipantID == invitation.ParticipantID {
			participants[index].Role = nextRole
		}
	}
	return postgresSecureRosterAttestation(
		t, space, previous.Revision+1, previousDigest, previous.CurrentKeyEpoch,
		participants, space.InitialParticipantID, changedAtMilliseconds,
	)
}

func postgresDeviceEnrollmentRosterAttestation(
	t *testing.T,
	space sharedspaces.SpaceProvisioning,
	previous sharedspaces.SecureRosterAttestation,
	participantID uuid.UUID,
	deviceKey sharedspaces.ParticipantDeviceKey,
	enrolledAtMilliseconds int64,
) *sharedspaces.SecureRosterAttestation {
	t.Helper()
	previousDigest, err := previous.Digest()
	if err != nil {
		t.Fatal(err)
	}
	participants := append([]sharedspaces.Participant(nil), previous.Participants...)
	for index := range participants {
		if participants[index].ParticipantID != participantID {
			continue
		}
		participants[index].DeviceKeys = append(
			[]sharedspaces.ParticipantDeviceKey(nil), participants[index].DeviceKeys...,
		)
		participants[index].DeviceKeys = append(participants[index].DeviceKeys, deviceKey)
		sort.Slice(participants[index].DeviceKeys, func(left, right int) bool {
			return participants[index].DeviceKeys[left].DeviceID.String() <
				participants[index].DeviceKeys[right].DeviceID.String()
		})
	}
	return postgresSecureRosterAttestation(
		t, space, previous.Revision+1, previousDigest, previous.CurrentKeyEpoch,
		participants, space.InitialParticipantID, enrolledAtMilliseconds,
	)
}

func postgresDeviceRevocationRosterAttestation(
	t *testing.T,
	space sharedspaces.SpaceProvisioning,
	previous sharedspaces.SecureRosterAttestation,
	revokedDeviceKey sharedspaces.ParticipantDeviceKey,
	nextKeyEpoch uint64,
	createdAtMilliseconds int64,
) *sharedspaces.SecureRosterAttestation {
	t.Helper()
	previousDigest, err := previous.Digest()
	if err != nil {
		t.Fatal(err)
	}
	participants := append([]sharedspaces.Participant(nil), previous.Participants...)
	for participantIndex := range participants {
		participants[participantIndex].DeviceKeys = append(
			[]sharedspaces.ParticipantDeviceKey(nil), participants[participantIndex].DeviceKeys...,
		)
		if participants[participantIndex].ParticipantID != revokedDeviceKey.ParticipantID {
			continue
		}
		for deviceIndex := range participants[participantIndex].DeviceKeys {
			if participants[participantIndex].DeviceKeys[deviceIndex].DeviceID == revokedDeviceKey.DeviceID {
				participants[participantIndex].DeviceKeys[deviceIndex] = revokedDeviceKey
			}
		}
	}
	return postgresSecureRosterAttestation(
		t, space, previous.Revision+1, previousDigest, nextKeyEpoch,
		participants, space.InitialParticipantID, createdAtMilliseconds,
	)
}

func postgresParticipantKeyGrant(
	t *testing.T,
	spaceID uuid.UUID,
	participantID uuid.UUID,
	issuerParticipantID uuid.UUID,
	keyEpoch uint64,
	now int64,
) *sharedspaces.ParticipantKeyGrant {
	t.Helper()
	privateKey := postgresParticipantSigningPrivateKey(t, issuerParticipantID)
	publicKey := elliptic.Marshal(elliptic.P256(), privateKey.PublicKey.X, privateKey.PublicKey.Y)
	signingFingerprint := sha256.Sum256(publicKey)
	recipientDeviceKey := postgresParticipantDeviceKey(t, spaceID, participantID, now)
	grant := sharedspaces.ParticipantKeyGrant{
		Version: sharedspaces.SchemaVersion, SpaceID: spaceID,
		ParticipantID: participantID, RecipientDeviceID: recipientDeviceKey.DeviceID,
		IssuerParticipantID: issuerParticipantID,
		KeyEpoch:            keyEpoch, Algorithm: sharedspaces.ParticipantKeyGrantAlgorithm,
		RecipientAgreementKeyFingerprint: recipientDeviceKey.AgreementKeyFingerprint,
		EphemeralAgreementPublicKeyX963:  base64.RawURLEncoding.EncodeToString(publicKey),
		Nonce:                            base64.RawURLEncoding.EncodeToString(make([]byte, 12)),
		Ciphertext:                       base64.RawURLEncoding.EncodeToString([]byte("opaque wrapped content key")),
		AuthenticationTag:                base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
		CreatedAtMilliseconds:            now,
		Signature: sharedspaces.ParticipantKeyGrantSignature{
			Algorithm:             sharedspaces.ParticipantKeyGrantSignatureAlgorithm,
			PublicSigningKeyX963:  base64.RawURLEncoding.EncodeToString(publicKey),
			SigningKeyFingerprint: hex.EncodeToString(signingFingerprint[:]),
		},
	}
	payload, err := grant.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	grant.Signature.Signature = base64.RawURLEncoding.EncodeToString(signature)
	return &grant
}

func postgresParticipantDeviceID(participantID uuid.UUID) uuid.UUID {
	digest := sha256.Sum256(append([]byte("facets-shared-space-device:"), participantID[:]...))
	deviceID, err := uuid.FromBytes(digest[:16])
	if err != nil {
		panic(err)
	}
	return deviceID
}

func postgresParticipantSecondaryDeviceID(participantID uuid.UUID) uuid.UUID {
	digest := sha256.Sum256(append([]byte("facets-shared-space-secondary-device:"), participantID[:]...))
	deviceID, err := uuid.FromBytes(digest[:16])
	if err != nil {
		panic(err)
	}
	return deviceID
}

func postgresParticipantTertiaryDeviceID(participantID uuid.UUID) uuid.UUID {
	digest := sha256.Sum256(append([]byte("facets-shared-space-tertiary-device:"), participantID[:]...))
	deviceID, err := uuid.FromBytes(digest[:16])
	if err != nil {
		panic(err)
	}
	return deviceID
}

func postgresParticipantDeviceKey(
	t *testing.T,
	spaceID uuid.UUID,
	participantID uuid.UUID,
	createdAtMilliseconds int64,
) sharedspaces.ParticipantDeviceKey {
	t.Helper()
	return postgresParticipantDeviceKeyWithID(
		t, spaceID, participantID, postgresParticipantDeviceID(participantID), createdAtMilliseconds,
	)
}

func postgresParticipantDeviceKeyWithID(
	t *testing.T,
	spaceID uuid.UUID,
	participantID uuid.UUID,
	deviceID uuid.UUID,
	createdAtMilliseconds int64,
) sharedspaces.ParticipantDeviceKey {
	t.Helper()
	agreementPrivateKey := postgresParticipantSigningPrivateKey(t, deviceID)
	agreementPublicKey := elliptic.Marshal(
		elliptic.P256(), agreementPrivateKey.PublicKey.X, agreementPrivateKey.PublicKey.Y,
	)
	agreementFingerprint := sha256.Sum256(agreementPublicKey)
	signingPrivateKey := postgresParticipantSigningPrivateKey(t, participantID)
	signingPublicKey := elliptic.Marshal(
		elliptic.P256(), signingPrivateKey.PublicKey.X, signingPrivateKey.PublicKey.Y,
	)
	signingFingerprint := sha256.Sum256(signingPublicKey)
	key := sharedspaces.ParticipantDeviceKey{
		Version: sharedspaces.SchemaVersion, SpaceID: spaceID,
		ParticipantID: participantID, DeviceID: deviceID, Algorithm: "P256",
		AgreementPublicKeyX963:  base64.RawURLEncoding.EncodeToString(agreementPublicKey),
		AgreementKeyFingerprint: hex.EncodeToString(agreementFingerprint[:]),
		CreatedAtMilliseconds:   createdAtMilliseconds,
		Signature: sharedspaces.ParticipantKeyGrantSignature{
			Algorithm:             sharedspaces.ParticipantKeyGrantSignatureAlgorithm,
			PublicSigningKeyX963:  base64.RawURLEncoding.EncodeToString(signingPublicKey),
			SigningKeyFingerprint: hex.EncodeToString(signingFingerprint[:]),
		},
	}
	payload, err := key.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	r, s, err := ecdsa.Sign(rand.Reader, signingPrivateKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	key.Signature.Signature = base64.RawURLEncoding.EncodeToString(signature)
	return key
}

func postgresRevokedParticipantDeviceKey(
	t *testing.T,
	current sharedspaces.ParticipantDeviceKey,
	revokedAtMilliseconds int64,
) sharedspaces.ParticipantDeviceKey {
	t.Helper()
	key := current
	key.RevokedAtMilliseconds = &revokedAtMilliseconds
	privateKey := postgresParticipantSigningPrivateKey(t, key.ParticipantID)
	payload, err := key.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	key.Signature.Signature = base64.RawURLEncoding.EncodeToString(signature)
	return key
}

func postgresParticipantKeyGrantForDevice(
	t *testing.T,
	spaceID uuid.UUID,
	participantID uuid.UUID,
	recipientDeviceID uuid.UUID,
	issuerParticipantID uuid.UUID,
	keyEpoch uint64,
	now int64,
) *sharedspaces.ParticipantKeyGrant {
	grant := postgresParticipantKeyGrant(
		t, spaceID, participantID, issuerParticipantID, keyEpoch, now,
	)
	recipientDeviceKey := postgresParticipantDeviceKeyWithID(
		t, spaceID, participantID, recipientDeviceID, now,
	)
	grant.RecipientDeviceID = recipientDeviceID
	grant.RecipientAgreementKeyFingerprint = recipientDeviceKey.AgreementKeyFingerprint
	payload, err := grant.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	privateKey := postgresParticipantSigningPrivateKey(t, issuerParticipantID)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	grant.Signature.Signature = base64.RawURLEncoding.EncodeToString(signature)
	return grant
}

func postgresParticipantSigningPrivateKey(t *testing.T, participantID uuid.UUID) *ecdsa.PrivateKey {
	t.Helper()
	curve := elliptic.P256()
	digest := sha256.Sum256(participantID[:])
	maximum := new(big.Int).Sub(curve.Params().N, big.NewInt(1))
	privateScalar := new(big.Int).SetBytes(digest[:])
	privateScalar.Mod(privateScalar, maximum)
	privateScalar.Add(privateScalar, big.NewInt(1))
	x, y := curve.ScalarBaseMult(privateScalar.Bytes())
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y},
		D:         privateScalar,
	}
}

func postgresParticipantSigningKey(t *testing.T, participantID uuid.UUID) sharedspaces.ParticipantSigningKey {
	t.Helper()
	privateKey := postgresParticipantSigningPrivateKey(t, participantID)
	publicKey := elliptic.Marshal(elliptic.P256(), privateKey.PublicKey.X, privateKey.PublicKey.Y)
	fingerprint := sha256.Sum256(publicKey)
	return sharedspaces.ParticipantSigningKey{
		Algorithm:             sharedspaces.ParticipantKeyGrantSignatureAlgorithm,
		PublicKeyX963:         base64.RawURLEncoding.EncodeToString(publicKey),
		SigningKeyFingerprint: hex.EncodeToString(fingerprint[:]),
	}
}

func postgresComputePoolAuthority(poolID uuid.UUID) computepool.AuthorityReference {
	x, y := elliptic.P256().ScalarBaseMult(bytes.Repeat([]byte{0x74}, 32))
	publicKey := elliptic.Marshal(elliptic.P256(), x, y)
	fingerprint := sha256.Sum256(publicKey)
	return computepool.AuthorityReference{
		Version: computepool.SchemaVersion,
		PoolID:  poolID,
		TrustAnchor: computepool.AuthorityTrustAnchor{
			Version: computepool.SignatureSchemaVersion,
			Scope: serviceauthority.Scope{
				Kind: serviceauthority.ScopeComputePool, ScopeID: poolID,
			},
			SignerID:              uuid.MustParse("79797979-7979-4979-8979-797979797979"),
			PublicSigningKeyX963:  base64.RawURLEncoding.EncodeToString(publicKey),
			SigningKeyFingerprint: hex.EncodeToString(fingerprint[:]),
		},
		AcceptedManifestRevision: 2,
		AcceptedManifestDigest:   hex.EncodeToString(bytes.Repeat([]byte{0x75}, 32)),
	}
}

func postgresSameCapabilities(left, right []relay.Capability) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
