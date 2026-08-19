package sharedspaces_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/sharedspaces"
)

func TestMemoryStoreSharedSpaceParticipantLifecycle(t *testing.T) {
	ctx := context.Background()
	relayStore := relay.NewMemoryStore()
	store := sharedspaces.NewMemoryStore(relayStore)
	_, provisioning, admin := testSpaceProvisioning(t, 1_000, sharedspaces.SecurityModeE2EE)

	created, err := store.ProvisionSpace(ctx, provisioning, 1_000)
	if err != nil || created.Acceptance != relay.AcceptanceAccepted ||
		created.SecurityMode != sharedspaces.SecurityModeE2EE ||
		created.InitialParticipant.Role != sharedspaces.RoleHost {
		t.Fatalf("provision=%+v err=%v", created, err)
	}
	retry, err := store.ProvisionSpace(ctx, provisioning, 1_100)
	if err != nil || retry.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("provision retry=%+v err=%v", retry, err)
	}

	invitation, invitationCredential := testInvitation(
		t, provisioning, admin, 1_200, sharedspaces.RoleParticipant,
	)
	if _, err := store.CreateInvitation(ctx, admin, invitation, 1_200); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeBootstrapNotReady) {
		t.Fatalf("invitation before bootstrap err=%v", err)
	}
	hostCredential := relay.Credential{
		TenantID: provisioning.SpaceID, DomainID: provisioning.Domain.Registration.DomainID,
		MemberID: provisioning.InitialParticipantID, Token: testToken(0x31),
	}
	activateSharedSpaceCheckpoint(t, ctx, relayStore, store, provisioning, hostCredential, admin, sharedspaces.InitialKeyEpoch, 1_150)
	issued, err := store.CreateInvitation(ctx, admin, invitation, 1_200)
	if err != nil || issued.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("invitation=%+v err=%v", issued, err)
	}
	issuedRetry, err := store.CreateInvitation(ctx, admin, invitation, 1_200)
	if err != nil || issuedRetry.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("invitation retry=%+v err=%v", issuedRetry, err)
	}

	memberCredential := relay.Credential{
		TenantID: invitation.SpaceID, DomainID: invitation.RelayAdmission.DomainID,
		MemberID: invitation.ParticipantID, Token: testToken(0x61),
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
		ClaimedAtMilliseconds: 1_300,
	}
	claimed, err := store.ClaimInvitation(ctx, invitationCredential, claim, 1_300)
	if err != nil || claimed.Acceptance != relay.AcceptanceAccepted ||
		claimed.CurrentKeyEpoch != sharedspaces.InitialKeyEpoch ||
		claimed.Participant.Role != sharedspaces.RoleParticipant ||
		claimed.KeyGrant == nil || claimed.KeyGrant.ParticipantID != invitation.ParticipantID {
		t.Fatalf("claim=%+v err=%v", claimed, err)
	}
	claimRetry, err := store.ClaimInvitation(ctx, invitationCredential, claim, 1_300)
	if err != nil || claimRetry.Acceptance != relay.AcceptanceDuplicate ||
		claimRetry.CurrentKeyEpoch != sharedspaces.InitialKeyEpoch || claimRetry.KeyGrant == nil {
		t.Fatalf("claim retry=%+v err=%v", claimRetry, err)
	}
	presentationUpdate := sharedspaces.ParticipantPresentationUpdate{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(),
		SpaceID: provisioning.SpaceID, ParticipantID: invitation.ParticipantID,
		PreviousRevision: 0, DisplayName: "Ada Lovelace", UpdatedAtMilliseconds: 1_301,
	}
	presentationResult, err := store.UpdateParticipantPresentation(
		ctx, memberCredential, presentationUpdate, 1_301,
	)
	if err != nil || presentationResult.Acceptance != relay.AcceptanceAccepted ||
		presentationResult.Presentation.DisplayName != "Ada Lovelace" ||
		presentationResult.Presentation.Revision != 1 {
		t.Fatalf("participant presentation=%+v err=%v", presentationResult, err)
	}
	presentationRetry, err := store.UpdateParticipantPresentation(
		ctx, memberCredential, presentationUpdate, 1_301,
	)
	if err != nil || presentationRetry.Acceptance != relay.AcceptanceDuplicate ||
		presentationRetry.Presentation != presentationResult.Presentation {
		t.Fatalf("participant presentation retry=%+v err=%v", presentationRetry, err)
	}
	concurrentPresentation := presentationUpdate
	concurrentPresentation.RetryID = uuid.New()
	concurrentPresentation.DisplayName = "Ada King"
	if _, err := store.UpdateParticipantPresentation(
		ctx, memberCredential, concurrentPresentation, 1_301,
	); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeParticipantPresentationCollision) {
		t.Fatalf("concurrent participant presentation err=%v", err)
	}
	participantStatus, err := store.GetParticipantStatus(ctx, memberCredential, 1_301)
	if err != nil || participantStatus.SpaceID != provisioning.SpaceID ||
		participantStatus.DomainID != provisioning.Domain.Registration.DomainID ||
		participantStatus.SecurityMode != sharedspaces.SecurityModeE2EE ||
		participantStatus.InteractionMode != sharedspaces.InteractionModeCollaborative ||
		participantStatus.CurrentKeyEpoch != sharedspaces.InitialKeyEpoch ||
		!participantStatus.BootstrapReady || participantStatus.ActiveCheckpointEpoch == nil ||
		*participantStatus.ActiveCheckpointEpoch != sharedspaces.InitialKeyEpoch ||
		participantStatus.Participant.ParticipantID != invitation.ParticipantID ||
		participantStatus.Participant.Role != sharedspaces.RoleParticipant ||
		participantStatus.Presentation == nil ||
		participantStatus.Presentation.DisplayName != "Ada Lovelace" ||
		!sameTestCapabilities(
			participantStatus.Capabilities,
			sharedspaces.RoleParticipant.Capabilities(sharedspaces.InteractionModeCollaborative),
		) {
		t.Fatalf("participant status=%+v err=%v", participantStatus, err)
	}
	participantBootstrap, err := store.GetParticipantBootstrap(ctx, memberCredential, 1_301)
	if err != nil || !reflect.DeepEqual(participantBootstrap.Status, participantStatus) ||
		participantBootstrap.KeyGrant == nil ||
		participantBootstrap.KeyGrant.ParticipantID != invitation.ParticipantID ||
		participantBootstrap.KeyGrant.CurrentKeyEpoch != sharedspaces.InitialKeyEpoch ||
		participantBootstrap.KeyGrant.KeyGrant.KeyEpoch != participantBootstrap.Status.CurrentKeyEpoch {
		t.Fatalf("participant bootstrap=%+v err=%v", participantBootstrap, err)
	}
	wrongPresentationCredential := memberCredential
	wrongPresentationCredential.MemberID = provisioning.InitialParticipantID
	if _, err := store.UpdateParticipantPresentation(
		ctx, wrongPresentationCredential, presentationUpdate, 1_301,
	); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeWrongScope) {
		t.Fatalf("cross-participant presentation err=%v", err)
	}
	wrongStatusCredential := memberCredential
	wrongStatusCredential.DomainID = uuid.New()
	if _, err := store.GetParticipantStatus(ctx, wrongStatusCredential, 1_301); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeWrongScope) {
		t.Fatalf("cross-domain participant status err=%v", err)
	}
	invitationList, err := store.ListInvitations(ctx, admin, 1_300)
	if err != nil || invitationList.SpaceID != provisioning.SpaceID ||
		len(invitationList.Invitations) != 1 ||
		invitationList.Invitations[0].State != sharedspaces.InvitationClaimed ||
		invitationList.Invitations[0].ClaimedAtMilliseconds == nil ||
		*invitationList.Invitations[0].ClaimedAtMilliseconds != 1_300 ||
		invitationList.Invitations[0].CancelledAtMilliseconds != nil {
		t.Fatalf("invitation list after claim=%+v err=%v", invitationList, err)
	}

	status, err := store.GetSpaceStatus(ctx, admin)
	if err != nil || status.CurrentKeyEpoch != sharedspaces.InitialKeyEpoch ||
		!status.BootstrapReady || status.ActiveCheckpointEpoch == nil ||
		*status.ActiveCheckpointEpoch != sharedspaces.InitialKeyEpoch ||
		len(status.Participants) != 2 || len(status.Presentations) != 1 ||
		status.Presentations[0] != presentationResult.Presentation ||
		status.Relay.ActiveSubscriptionCount != 2 {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	fence, err := relayStore.CreateCheckpointFence(ctx, hostCredential, relay.CheckpointFenceRequest{
		RetryID: uuid.New(), FenceID: uuid.New(), RequestedAtMilliseconds: 1_350,
	}, 1_350)
	if err != nil {
		t.Fatalf("checkpoint fence err=%v", err)
	}
	stagedBeforeRotation := relay.CheckpointCandidate{
		Version: relay.SchemaVersion, RetryID: uuid.New(), CheckpointID: uuid.New(),
		FenceID: fence.FenceID, TenantID: provisioning.SpaceID,
		DomainID:                provisioning.Domain.Registration.DomainID,
		PublisherSubscriptionID: provisioning.Domain.Subscription.SubscriptionID,
		KeyEpoch:                sharedspaces.InitialKeyEpoch,
		CoveredThroughCursor:    fence.BoundaryCursor,
		CreatedAtMilliseconds:   1_351,
	}
	if _, err := store.StageCheckpoint(ctx, hostCredential, stagedBeforeRotation, 1_351); err != nil {
		t.Fatalf("stage checkpoint before rotation err=%v", err)
	}

	revocation := sharedspaces.ParticipantRevocation{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(), SpaceID: invitation.SpaceID,
		ParticipantID:    invitation.ParticipantID,
		PreviousKeyEpoch: sharedspaces.InitialKeyEpoch, NextKeyEpoch: sharedspaces.InitialKeyEpoch + 1,
		KeyGrants: []sharedspaces.ParticipantKeyGrant{*testParticipantKeyGrant(
			t, provisioning.SpaceID, provisioning.InitialParticipantID,
			provisioning.InitialParticipantID, sharedspaces.InitialKeyEpoch+1, 1_400,
		)},
	}
	revoked, err := store.RevokeParticipant(ctx, admin, revocation, 1_400)
	if err != nil || revoked.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("revoke=%+v err=%v", revoked, err)
	}
	if revoked.PreviousKeyEpoch != sharedspaces.InitialKeyEpoch ||
		revoked.CurrentKeyEpoch != sharedspaces.InitialKeyEpoch+1 {
		t.Fatalf("revocation did not rotate key epoch: %+v", revoked)
	}
	hostGrant, err := store.GetParticipantKeyGrant(ctx, hostCredential, 1_401)
	if err != nil || hostGrant.ParticipantID != provisioning.InitialParticipantID ||
		hostGrant.CurrentKeyEpoch != sharedspaces.InitialKeyEpoch+1 ||
		hostGrant.KeyGrant.KeyEpoch != sharedspaces.InitialKeyEpoch+1 {
		t.Fatalf("host key grant=%+v err=%v", hostGrant, err)
	}
	revokedRetry, err := store.RevokeParticipant(ctx, admin, revocation, 1_500)
	if err != nil || revokedRetry.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("revoke retry=%+v err=%v", revokedRetry, err)
	}
	if _, err := relayStore.Fetch(ctx, memberCredential, 0, 1, 1_500); !relay.ErrorHasCode(err, relay.CodeMemberRevoked) {
		t.Fatalf("revoked relay credential err=%v", err)
	}
	if _, err := store.GetParticipantStatus(ctx, memberCredential, 1_500); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeParticipantRevoked) {
		t.Fatalf("revoked participant status err=%v", err)
	}
	if _, err := store.GetParticipantBootstrap(ctx, memberCredential, 1_500); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeParticipantRevoked) {
		t.Fatalf("revoked participant bootstrap err=%v", err)
	}
	if _, err := store.ActivateCheckpoint(ctx, admin, relay.CheckpointActivationRequest{
		RetryID: uuid.New(), CheckpointID: stagedBeforeRotation.CheckpointID,
		ActivatedAtMilliseconds: 1_500,
	}, 1_500); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeWrongKeyEpoch) {
		t.Fatalf("stale checkpoint activation err=%v", err)
	}
	status, err = store.GetSpaceStatus(ctx, admin)
	if err != nil || status.BootstrapReady || status.ActiveCheckpointEpoch == nil ||
		*status.ActiveCheckpointEpoch != sharedspaces.InitialKeyEpoch {
		t.Fatalf("status awaiting rotated checkpoint=%+v err=%v", status, err)
	}
	hostStatus, err := store.GetParticipantStatus(ctx, hostCredential, 1_500)
	if err != nil || hostStatus.CurrentKeyEpoch != sharedspaces.InitialKeyEpoch+1 ||
		hostStatus.BootstrapReady || hostStatus.ActiveCheckpointEpoch == nil ||
		*hostStatus.ActiveCheckpointEpoch != sharedspaces.InitialKeyEpoch ||
		hostStatus.Participant.ParticipantID != provisioning.InitialParticipantID ||
		hostStatus.Participant.Role != sharedspaces.RoleHost {
		t.Fatalf("host participant status awaiting rotated checkpoint=%+v err=%v", hostStatus, err)
	}
	hostBootstrap, err := store.GetParticipantBootstrap(ctx, hostCredential, 1_500)
	if err != nil || !reflect.DeepEqual(hostBootstrap.Status, hostStatus) || hostBootstrap.KeyGrant == nil ||
		hostBootstrap.KeyGrant.CurrentKeyEpoch != sharedspaces.InitialKeyEpoch+1 ||
		hostBootstrap.KeyGrant.KeyGrant.KeyEpoch != hostBootstrap.Status.CurrentKeyEpoch {
		t.Fatalf("host participant bootstrap awaiting rotated checkpoint=%+v err=%v", hostBootstrap, err)
	}
	staleCandidate := stagedBeforeRotation
	staleCandidate.RetryID = uuid.New()
	staleCandidate.CheckpointID = uuid.New()
	staleCandidate.CreatedAtMilliseconds = 1_501
	if _, err := store.StageCheckpoint(ctx, hostCredential, staleCandidate, 1_501); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeWrongKeyEpoch) {
		t.Fatalf("stale checkpoint stage err=%v", err)
	}
	currentCandidate := staleCandidate
	currentCandidate.RetryID = uuid.New()
	currentCandidate.CheckpointID = uuid.New()
	currentCandidate.KeyEpoch = sharedspaces.InitialKeyEpoch + 1
	currentCandidate.CreatedAtMilliseconds = 1_502
	if _, err := store.StageCheckpoint(ctx, hostCredential, currentCandidate, 1_502); err != nil {
		t.Fatalf("current checkpoint stage err=%v", err)
	}
	if _, err := store.ActivateCheckpoint(ctx, admin, relay.CheckpointActivationRequest{
		RetryID: uuid.New(), CheckpointID: currentCandidate.CheckpointID,
		ActivatedAtMilliseconds: 1_503,
	}, 1_503); err != nil {
		t.Fatalf("current checkpoint activation err=%v", err)
	}
	status, err = store.GetSpaceStatus(ctx, admin)
	if err != nil || status.CurrentKeyEpoch != sharedspaces.InitialKeyEpoch+1 ||
		!status.BootstrapReady || status.ActiveCheckpointEpoch == nil ||
		*status.ActiveCheckpointEpoch != sharedspaces.InitialKeyEpoch+1 {
		t.Fatalf("status after revocation=%+v err=%v", status, err)
	}
	hostStatus, err = store.GetParticipantStatus(ctx, hostCredential, 1_504)
	if err != nil || !hostStatus.BootstrapReady || hostStatus.ActiveCheckpointEpoch == nil ||
		*hostStatus.ActiveCheckpointEpoch != sharedspaces.InitialKeyEpoch+1 {
		t.Fatalf("host participant status after rotated checkpoint=%+v err=%v", hostStatus, err)
	}
	staleEnvelope := testSharedEnvelope(provisioning, sharedspaces.InitialKeyEpoch, 1_600)
	if _, err := store.PublishEnvelope(ctx, hostCredential, staleEnvelope, 1_600); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeWrongKeyEpoch) {
		t.Fatalf("stale envelope publish err=%v", err)
	}
	currentEnvelope := testSharedEnvelope(provisioning, sharedspaces.InitialKeyEpoch+1, 1_600)
	if result, err := store.PublishEnvelope(ctx, hostCredential, currentEnvelope, 1_600); err != nil || result.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("current envelope publish=%+v err=%v", result, err)
	}

	firstPage, err := store.ListAuthorityEvents(ctx, admin, 0, 2)
	if err != nil || len(firstPage.Events) != 2 || firstPage.NextSequence != 2 ||
		firstPage.Events[0].EventType != sharedspaces.AuthorityEventSpaceProvisioned ||
		firstPage.Events[1].EventType != sharedspaces.AuthorityEventInvitationCreated {
		t.Fatalf("first authority event page=%+v err=%v", firstPage, err)
	}
	secondPage, err := store.ListAuthorityEvents(ctx, admin, firstPage.NextSequence, 2)
	if err != nil || len(secondPage.Events) != 2 || secondPage.NextSequence != 4 ||
		secondPage.Events[0].EventType != sharedspaces.AuthorityEventInvitationClaimed ||
		secondPage.Events[1].EventType != sharedspaces.AuthorityEventParticipantRevoked {
		t.Fatalf("second authority event page=%+v err=%v", secondPage, err)
	}
	emptyPage, err := store.ListAuthorityEvents(ctx, admin, secondPage.NextSequence, 2)
	if err != nil || len(emptyPage.Events) != 0 || emptyPage.NextSequence != secondPage.NextSequence {
		t.Fatalf("empty authority event page=%+v err=%v", emptyPage, err)
	}
	if _, err := store.ListAuthorityEvents(ctx, admin, 0, 0); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeInvalidAuthorityEvent) {
		t.Fatalf("invalid authority event page size err=%v", err)
	}
	wrongScope := admin
	wrongScope.DomainID = uuid.New()
	if _, err := store.ListAuthorityEvents(ctx, wrongScope, 0, 2); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeWrongScope) {
		t.Fatalf("wrong-scope authority event query err=%v", err)
	}
}

func TestMemoryStoreCancelsUnclaimedInvitation(t *testing.T) {
	ctx := context.Background()
	relayStore := relay.NewMemoryStore()
	store := sharedspaces.NewMemoryStore(relayStore)
	_, provisioning, admin := testSpaceProvisioning(t, 2_000, sharedspaces.SecurityModeE2EE)
	if _, err := store.ProvisionSpace(ctx, provisioning, 2_000); err != nil {
		t.Fatal(err)
	}
	hostCredential := relay.Credential{
		TenantID: provisioning.SpaceID, DomainID: provisioning.Domain.Registration.DomainID,
		MemberID: provisioning.InitialParticipantID, Token: testToken(0x31),
	}
	activateSharedSpaceCheckpoint(t, ctx, relayStore, store, provisioning, hostCredential, admin, sharedspaces.InitialKeyEpoch, 2_050)

	invitation, credential := testInvitation(t, provisioning, admin, 2_100, sharedspaces.RoleReader)
	if _, err := store.CreateInvitation(ctx, admin, invitation, 2_100); err != nil {
		t.Fatal(err)
	}
	cancellation := sharedspaces.InvitationCancellation{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(), SpaceID: invitation.SpaceID,
		InvitationID: invitation.InvitationID, CancelledAtMilliseconds: 2_200,
	}
	cancelled, err := store.CancelInvitation(ctx, admin, cancellation, 2_200)
	if err != nil || cancelled.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("cancel=%+v err=%v", cancelled, err)
	}
	cancelledRetry, err := store.CancelInvitation(ctx, admin, cancellation, 2_201)
	if err != nil || cancelledRetry.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("cancel retry=%+v err=%v", cancelledRetry, err)
	}
	invitationList, err := store.ListInvitations(ctx, admin, 2_201)
	if err != nil || len(invitationList.Invitations) != 1 ||
		invitationList.Invitations[0].State != sharedspaces.InvitationCancelled ||
		invitationList.Invitations[0].CancelledAtMilliseconds == nil ||
		*invitationList.Invitations[0].CancelledAtMilliseconds != 2_200 ||
		invitationList.Invitations[0].ClaimedAtMilliseconds != nil {
		t.Fatalf("invitation list after cancellation=%+v err=%v", invitationList, err)
	}

	memberCredential := relay.Credential{
		TenantID: invitation.SpaceID, DomainID: invitation.RelayAdmission.DomainID,
		MemberID: invitation.ParticipantID, Token: testToken(0x61),
	}
	digest, err := relay.AuthorizationDigest(memberCredential)
	if err != nil {
		t.Fatal(err)
	}
	claim := sharedspaces.InvitationClaim{
		Version: sharedspaces.SchemaVersion, SpaceID: invitation.SpaceID,
		ParticipantID: invitation.ParticipantID,
		RelayClaim: relay.MemberAdmissionClaim{
			MemberID: invitation.ParticipantID, AuthorizationDigest: digest,
		},
		ClaimedAtMilliseconds: 2_300,
	}
	if _, err := store.ClaimInvitation(ctx, credential, claim, 2_300); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeInvitationCancelled) {
		t.Fatalf("claim cancelled invitation err=%v", err)
	}
	if _, err := relayStore.ClaimSubscriptionAdmission(ctx, relay.AdmissionCredential{
		TenantID: credential.SpaceID, DomainID: credential.DomainID,
		AdmissionID: credential.InvitationID, Token: credential.Token,
	}, claim.RelayClaim, 2_300); !relay.ErrorHasCode(err, relay.CodeAdmissionRevoked) {
		t.Fatalf("claim revoked relay admission err=%v", err)
	}
	status, err := store.GetSpaceStatus(ctx, admin)
	if err != nil || len(status.Participants) != 1 || status.Participants[0].Role != sharedspaces.RoleHost {
		t.Fatalf("status after invitation cancellation=%+v err=%v", status, err)
	}
}

func TestMemoryStoreRejectsInvitationForAnotherInteractionModeAtomically(t *testing.T) {
	ctx := context.Background()
	relayStore := relay.NewMemoryStore()
	store := sharedspaces.NewMemoryStore(relayStore)
	_, provisioning, admin := testSpaceProvisioning(t, 2_700, sharedspaces.SecurityModeE2EE)
	if _, err := store.ProvisionSpace(ctx, provisioning, 2_700); err != nil {
		t.Fatal(err)
	}
	hostCredential := relay.Credential{
		TenantID: provisioning.SpaceID, DomainID: provisioning.Domain.Registration.DomainID,
		MemberID: provisioning.InitialParticipantID, Token: testToken(0x31),
	}
	activateSharedSpaceCheckpoint(t, ctx, relayStore, store, provisioning, hostCredential, admin, sharedspaces.InitialKeyEpoch, 2_750)

	invitation, _ := testInvitation(t, provisioning, admin, 2_800, sharedspaces.RoleParticipant)
	invitation.InteractionMode = sharedspaces.InteractionModeCommunity
	invitation.RelayAdmission.Capabilities = invitation.Role.Capabilities(invitation.InteractionMode)
	if err := invitation.Validate(); err != nil {
		t.Fatalf("cross-mode invitation fixture: %v", err)
	}
	if _, err := store.CreateInvitation(ctx, admin, invitation, 2_800); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeInvalidInvitation) {
		t.Fatalf("cross-mode invitation err=%v", err)
	}
	listed, err := store.ListInvitations(ctx, admin, 2_800)
	if err != nil || len(listed.Invitations) != 0 {
		t.Fatalf("rejected invitation mutated authority state list=%+v err=%v", listed, err)
	}
	status, err := store.GetSpaceStatus(ctx, admin)
	if err != nil || len(status.Participants) != 1 || status.Relay.ActiveSubscriptionCount != 1 {
		t.Fatalf("rejected invitation mutated Space or relay status=%+v err=%v", status, err)
	}
}

func TestMemoryStoreRejectsStaleRevocationKeyEpoch(t *testing.T) {
	ctx := context.Background()
	relayStore := relay.NewMemoryStore()
	store := sharedspaces.NewMemoryStore(relayStore)
	_, provisioning, admin := testSpaceProvisioning(t, 4_000, sharedspaces.SecurityModeE2EE)
	if _, err := store.ProvisionSpace(ctx, provisioning, 4_000); err != nil {
		t.Fatal(err)
	}
	hostCredential := relay.Credential{
		TenantID: provisioning.SpaceID, DomainID: provisioning.Domain.Registration.DomainID,
		MemberID: provisioning.InitialParticipantID, Token: testToken(0x31),
	}
	activateSharedSpaceCheckpoint(t, ctx, relayStore, store, provisioning, hostCredential, admin, sharedspaces.InitialKeyEpoch, 4_050)
	invitation, credential := testInvitation(t, provisioning, admin, 4_100, sharedspaces.RoleReader)
	if _, err := store.CreateInvitation(ctx, admin, invitation, 4_100); err != nil {
		t.Fatal(err)
	}
	memberCredential := relay.Credential{
		TenantID: invitation.SpaceID, DomainID: invitation.RelayAdmission.DomainID,
		MemberID: invitation.ParticipantID, Token: testToken(0x61),
	}
	digest, err := relay.AuthorizationDigest(memberCredential)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimInvitation(ctx, credential, sharedspaces.InvitationClaim{
		Version: sharedspaces.SchemaVersion, SpaceID: invitation.SpaceID,
		ParticipantID:         invitation.ParticipantID,
		RelayClaim:            relay.MemberAdmissionClaim{MemberID: invitation.ParticipantID, AuthorizationDigest: digest},
		ClaimedAtMilliseconds: 4_200,
	}, 4_200); err != nil {
		t.Fatal(err)
	}
	readerEnvelope := testSharedEnvelope(provisioning, sharedspaces.InitialKeyEpoch, 4_210)
	readerEnvelope.PublisherMemberID = invitation.ParticipantID
	if _, err := store.PublishEnvelope(ctx, memberCredential, readerEnvelope, 4_210); !relay.ErrorHasCode(err, relay.CodeMissingCapability) {
		t.Fatalf("reader publish err=%v", err)
	}
	promotion := sharedspaces.ParticipantRoleChange{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(), SpaceID: invitation.SpaceID,
		ParticipantID: invitation.ParticipantID, PreviousRole: sharedspaces.RoleReader,
		NextRole: sharedspaces.RoleParticipant, ChangedAtMilliseconds: 4_220,
	}
	promoted, err := store.ChangeParticipantRole(ctx, admin, promotion, 4_220)
	if err != nil || promoted.Acceptance != relay.AcceptanceAccepted ||
		promoted.CurrentRole != sharedspaces.RoleParticipant {
		t.Fatalf("promotion=%+v err=%v", promoted, err)
	}
	promotedRetry, err := store.ChangeParticipantRole(ctx, admin, promotion, 4_220)
	if err != nil || promotedRetry.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("promotion retry=%+v err=%v", promotedRetry, err)
	}
	participantEnvelope := readerEnvelope
	participantEnvelope.MessageID = uuid.New()
	participantEnvelope.CreatedAtMilliseconds = 4_230
	if result, err := store.PublishEnvelope(ctx, memberCredential, participantEnvelope, 4_230); err != nil ||
		result.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("participant publish=%+v err=%v", result, err)
	}
	demotion := sharedspaces.ParticipantRoleChange{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(), SpaceID: invitation.SpaceID,
		ParticipantID: invitation.ParticipantID, PreviousRole: sharedspaces.RoleParticipant,
		NextRole: sharedspaces.RoleReader, ChangedAtMilliseconds: 4_240,
	}
	demoted, err := store.ChangeParticipantRole(ctx, admin, demotion, 4_240)
	if err != nil || demoted.Acceptance != relay.AcceptanceAccepted ||
		demoted.CurrentRole != sharedspaces.RoleReader {
		t.Fatalf("demotion=%+v err=%v", demoted, err)
	}
	participantEnvelope.MessageID = uuid.New()
	participantEnvelope.CreatedAtMilliseconds = 4_250
	if _, err := store.PublishEnvelope(ctx, memberCredential, participantEnvelope, 4_250); !relay.ErrorHasCode(err, relay.CodeMissingCapability) {
		t.Fatalf("demoted participant publish err=%v", err)
	}
	status, err := store.GetSpaceStatus(ctx, admin)
	var changedParticipant *sharedspaces.Participant
	for index := range status.Participants {
		if status.Participants[index].ParticipantID == invitation.ParticipantID {
			changedParticipant = &status.Participants[index]
			break
		}
	}
	if err != nil || status.CurrentKeyEpoch != sharedspaces.InitialKeyEpoch ||
		len(status.Participants) != 2 || changedParticipant == nil ||
		changedParticipant.Role != sharedspaces.RoleReader {
		t.Fatalf("status after role changes=%+v err=%v", status, err)
	}
	stale := sharedspaces.ParticipantRevocation{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(), SpaceID: invitation.SpaceID,
		ParticipantID: invitation.ParticipantID, PreviousKeyEpoch: 2, NextKeyEpoch: 3,
	}
	if _, err := store.RevokeParticipant(ctx, admin, stale, 4_300); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeWrongKeyEpoch) {
		t.Fatalf("stale revocation err=%v", err)
	}
}

func activateSharedSpaceCheckpoint(
	t *testing.T,
	ctx context.Context,
	relayStore *relay.MemoryStore,
	store sharedspaces.Store,
	provisioning sharedspaces.SpaceProvisioning,
	hostCredential relay.Credential,
	admin relay.AdministrationCredential,
	keyEpoch uint64,
	now int64,
) {
	t.Helper()
	fence, err := relayStore.CreateCheckpointFence(ctx, hostCredential, relay.CheckpointFenceRequest{
		RetryID: uuid.New(), FenceID: uuid.New(), RequestedAtMilliseconds: now,
	}, now)
	if err != nil {
		t.Fatalf("create bootstrap checkpoint fence: %v", err)
	}
	candidate := relay.CheckpointCandidate{
		Version: relay.SchemaVersion, RetryID: uuid.New(), CheckpointID: uuid.New(),
		FenceID: fence.FenceID, TenantID: provisioning.SpaceID,
		DomainID:                provisioning.Domain.Registration.DomainID,
		PublisherSubscriptionID: provisioning.Domain.Subscription.SubscriptionID,
		KeyEpoch:                keyEpoch,
		CoveredThroughCursor:    fence.BoundaryCursor,
		CreatedAtMilliseconds:   now,
	}
	if _, err := store.StageCheckpoint(ctx, hostCredential, candidate, now); err != nil {
		t.Fatalf("stage bootstrap checkpoint: %v", err)
	}
	if _, err := store.ActivateCheckpoint(ctx, admin, relay.CheckpointActivationRequest{
		RetryID: uuid.New(), CheckpointID: candidate.CheckpointID, ActivatedAtMilliseconds: now,
	}, now); err != nil {
		t.Fatalf("activate bootstrap checkpoint: %v", err)
	}
}

func TestMemoryStoreRejectsCrossSpaceAuthorityAndInitialHostRevocation(t *testing.T) {
	ctx := context.Background()
	relayStore := relay.NewMemoryStore()
	store := sharedspaces.NewMemoryStore(relayStore)
	_, provisioning, admin := testSpaceProvisioning(t, 3_000, sharedspaces.SecurityModeManaged)
	if _, err := store.ProvisionSpace(ctx, provisioning, 3_000); err != nil {
		t.Fatal(err)
	}
	hostCredential := relay.Credential{
		TenantID: provisioning.SpaceID, DomainID: provisioning.Domain.Registration.DomainID,
		MemberID: provisioning.InitialParticipantID, Token: testToken(0x31),
	}
	participantStatus, err := store.GetParticipantStatus(ctx, hostCredential, 3_001)
	if err != nil || participantStatus.SecurityMode != sharedspaces.SecurityModeManaged ||
		participantStatus.BootstrapReady || participantStatus.ActiveCheckpointEpoch != nil ||
		participantStatus.Participant.Role != sharedspaces.RoleHost {
		t.Fatalf("managed participant status=%+v err=%v", participantStatus, err)
	}
	participantBootstrap, err := store.GetParticipantBootstrap(ctx, hostCredential, 3_001)
	var managedKey []byte
	var decodeErr error
	if participantBootstrap.ManagedContentKey != nil {
		managedKey, decodeErr = base64.RawURLEncoding.Strict().DecodeString(
			participantBootstrap.ManagedContentKey.KeyMaterial,
		)
	}
	if err != nil || decodeErr != nil || !reflect.DeepEqual(participantBootstrap.Status, participantStatus) ||
		participantBootstrap.KeyGrant != nil || participantBootstrap.ManagedContentKey == nil ||
		participantBootstrap.ManagedContentKey.SpaceID != provisioning.SpaceID ||
		participantBootstrap.ManagedContentKey.ParticipantID != provisioning.InitialParticipantID ||
		participantBootstrap.ManagedContentKey.KeyEpoch != sharedspaces.InitialKeyEpoch ||
		len(managedKey) != 32 {
		t.Fatalf("managed participant bootstrap=%+v err=%v", participantBootstrap, err)
	}
	invitation, _ := testInvitation(t, provisioning, admin, 3_100, sharedspaces.RoleReader)
	wrong := admin
	wrong.TenantID = uuid.New()
	if _, err := store.CreateInvitation(ctx, wrong, invitation, 3_100); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeWrongScope) {
		t.Fatalf("cross-Space invitation err=%v", err)
	}
	revocation := sharedspaces.ParticipantRevocation{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(), SpaceID: provisioning.SpaceID,
		ParticipantID:    provisioning.InitialParticipantID,
		PreviousKeyEpoch: sharedspaces.InitialKeyEpoch, NextKeyEpoch: sharedspaces.InitialKeyEpoch + 1,
	}
	if _, err := store.RevokeParticipant(ctx, admin, revocation, 3_200); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeInitialHost) {
		t.Fatalf("initial host revocation err=%v", err)
	}
}

func TestMemoryStoreRotatesManagedContentKeyOnParticipantRevocation(t *testing.T) {
	ctx := context.Background()
	relayStore := relay.NewMemoryStore()
	store := sharedspaces.NewMemoryStore(relayStore)
	_, provisioning, admin := testSpaceProvisioning(t, 6_000, sharedspaces.SecurityModeManaged)
	if _, err := store.ProvisionSpace(ctx, provisioning, 6_000); err != nil {
		t.Fatal(err)
	}
	hostCredential := relay.Credential{
		TenantID: provisioning.SpaceID, DomainID: provisioning.Domain.Registration.DomainID,
		MemberID: provisioning.InitialParticipantID, Token: testToken(0x31),
	}
	activateSharedSpaceCheckpoint(
		t, ctx, relayStore, store, provisioning, hostCredential, admin,
		sharedspaces.InitialKeyEpoch, 6_050,
	)
	invitation, invitationCredential := testInvitation(
		t, provisioning, admin, 6_100, sharedspaces.RoleParticipant,
	)
	if invitation.KeyGrant != nil {
		t.Fatal("managed invitation unexpectedly contains an E2EE key grant")
	}
	if _, err := store.CreateInvitation(ctx, admin, invitation, 6_100); err != nil {
		t.Fatal(err)
	}
	memberCredential := relay.Credential{
		TenantID: invitation.SpaceID, DomainID: invitation.RelayAdmission.DomainID,
		MemberID: invitation.ParticipantID, Token: testToken(0x71),
	}
	memberDigest, err := relay.AuthorizationDigest(memberCredential)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimInvitation(ctx, invitationCredential, sharedspaces.InvitationClaim{
		Version: sharedspaces.SchemaVersion, SpaceID: invitation.SpaceID,
		ParticipantID: invitation.ParticipantID,
		RelayClaim: relay.MemberAdmissionClaim{
			MemberID: invitation.ParticipantID, AuthorizationDigest: memberDigest,
		},
		ClaimedAtMilliseconds: 6_200,
	}, 6_200); err != nil {
		t.Fatal(err)
	}

	hostBefore, err := store.GetParticipantBootstrap(ctx, hostCredential, 6_201)
	if err != nil {
		t.Fatal(err)
	}
	memberBefore, err := store.GetParticipantBootstrap(ctx, memberCredential, 6_201)
	if err != nil {
		t.Fatal(err)
	}
	if hostBefore.ManagedContentKey == nil || memberBefore.ManagedContentKey == nil ||
		hostBefore.ManagedContentKey.KeyMaterial != memberBefore.ManagedContentKey.KeyMaterial ||
		hostBefore.ManagedContentKey.KeyEpoch != sharedspaces.InitialKeyEpoch {
		t.Fatalf("initial managed bootstrap host=%+v member=%+v", hostBefore, memberBefore)
	}

	revocation := sharedspaces.ParticipantRevocation{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(), SpaceID: invitation.SpaceID,
		ParticipantID: invitation.ParticipantID, PreviousKeyEpoch: sharedspaces.InitialKeyEpoch,
		NextKeyEpoch: sharedspaces.InitialKeyEpoch + 1,
	}
	if _, err := store.RevokeParticipant(ctx, admin, revocation, 6_300); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetParticipantBootstrap(ctx, memberCredential, 6_301); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeParticipantRevoked) {
		t.Fatalf("revoked managed participant bootstrap err=%v", err)
	}
	hostAfter, err := store.GetParticipantBootstrap(ctx, hostCredential, 6_301)
	if err != nil || hostAfter.ManagedContentKey == nil ||
		hostAfter.ManagedContentKey.KeyEpoch != sharedspaces.InitialKeyEpoch+1 ||
		hostAfter.ManagedContentKey.KeyMaterial == hostBefore.ManagedContentKey.KeyMaterial ||
		hostAfter.Status.BootstrapReady {
		t.Fatalf("rotated managed bootstrap=%+v err=%v", hostAfter, err)
	}
	if _, err := relayStore.Fetch(ctx, memberCredential, 0, 1, 6_301); !relay.ErrorHasCode(err, relay.CodeMemberRevoked) {
		t.Fatalf("revoked managed relay access err=%v", err)
	}
}

func TestMemoryStoreRejectsIncompleteE2EERevocationWithoutChangingAuthority(t *testing.T) {
	ctx := context.Background()
	relayStore := relay.NewMemoryStore()
	store := sharedspaces.NewMemoryStore(relayStore)
	_, provisioning, admin := testSpaceProvisioning(t, 5_000, sharedspaces.SecurityModeE2EE)
	if _, err := store.ProvisionSpace(ctx, provisioning, 5_000); err != nil {
		t.Fatal(err)
	}
	hostCredential := relay.Credential{
		TenantID: provisioning.SpaceID, DomainID: provisioning.Domain.Registration.DomainID,
		MemberID: provisioning.InitialParticipantID, Token: testToken(0x31),
	}
	activateSharedSpaceCheckpoint(
		t, ctx, relayStore, store, provisioning, hostCredential, admin,
		sharedspaces.InitialKeyEpoch, 5_050,
	)
	invitation, invitationCredential := testInvitation(
		t, provisioning, admin, 5_100, sharedspaces.RoleParticipant,
	)
	if _, err := store.CreateInvitation(ctx, admin, invitation, 5_100); err != nil {
		t.Fatal(err)
	}
	memberCredential := relay.Credential{
		TenantID: invitation.SpaceID, DomainID: invitation.RelayAdmission.DomainID,
		MemberID: invitation.ParticipantID, Token: testToken(0x71),
	}
	memberDigest, err := relay.AuthorizationDigest(memberCredential)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimInvitation(ctx, invitationCredential, sharedspaces.InvitationClaim{
		Version: sharedspaces.SchemaVersion, SpaceID: invitation.SpaceID,
		ParticipantID: invitation.ParticipantID,
		RelayClaim: relay.MemberAdmissionClaim{
			MemberID: invitation.ParticipantID, AuthorizationDigest: memberDigest,
		},
		ClaimedAtMilliseconds: 5_200,
	}, 5_200); err != nil {
		t.Fatal(err)
	}

	incomplete := sharedspaces.ParticipantRevocation{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(), SpaceID: invitation.SpaceID,
		ParticipantID:    invitation.ParticipantID,
		PreviousKeyEpoch: sharedspaces.InitialKeyEpoch,
		NextKeyEpoch:     sharedspaces.InitialKeyEpoch + 1,
	}
	if _, err := store.RevokeParticipant(ctx, admin, incomplete, 5_300); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeInvalidParticipant) {
		t.Fatalf("incomplete revocation err=%v", err)
	}
	status, err := store.GetSpaceStatus(ctx, admin)
	if err != nil || status.CurrentKeyEpoch != sharedspaces.InitialKeyEpoch ||
		len(status.Participants) != 2 || status.Relay.ActiveSubscriptionCount != 2 {
		t.Fatalf("authority changed after rejected revocation status=%+v err=%v", status, err)
	}
	if _, err := relayStore.Fetch(ctx, memberCredential, 0, 1, 5_301); err != nil {
		t.Fatalf("member authority changed after rejected revocation: %v", err)
	}
}

func testSpaceProvisioning(
	t *testing.T,
	now int64,
	mode sharedspaces.SecurityMode,
) (relay.TenantCredential, sharedspaces.SpaceProvisioning, relay.AdministrationCredential) {
	t.Helper()
	spaceID := uuid.New()
	domainID := uuid.New()
	hostID := uuid.New()
	subscriptionID := uuid.New()
	tenantCredential := relay.TenantCredential{TenantID: spaceID, Token: testToken(0x11)}
	tenantDigest, err := relay.TenantAuthorizationDigest(tenantCredential)
	if err != nil {
		t.Fatal(err)
	}
	admin := relay.AdministrationCredential{TenantID: spaceID, DomainID: domainID, Token: testToken(0x21)}
	adminDigest, err := relay.AdministrationDigest(admin)
	if err != nil {
		t.Fatal(err)
	}
	hostCredential := relay.Credential{
		TenantID: spaceID, DomainID: domainID, MemberID: hostID, Token: testToken(0x31),
	}
	hostDigest, err := relay.AuthorizationDigest(hostCredential)
	if err != nil {
		t.Fatal(err)
	}
	provisioning := sharedspaces.SpaceProvisioning{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(), SpaceID: spaceID,
		SecurityMode: mode, InteractionMode: sharedspaces.InteractionModeCollaborative,
		InitialParticipantID:   hostID,
		InitialParticipantKind: sharedspaces.ParticipantPerson,
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
			SubscriptionID: subscriptionID, Status: relay.SubscriptionActive,
			CreatedAtMilliseconds: now, UpdatedAtMilliseconds: now,
		},
		InitialMember: relay.MemberRegistration{
			Version: relay.SchemaVersion, TenantID: spaceID, DomainID: domainID,
			MemberID: hostID, AuthorizationDigest: hostDigest,
			Capabilities:          sharedspaces.RoleHost.Capabilities(provisioning.InteractionMode),
			CreatedAtMilliseconds: now,
		},
	}
	return tenantCredential, provisioning, admin
}

func testSharedEnvelope(
	provisioning sharedspaces.SpaceProvisioning,
	keyEpoch uint64,
	createdAtMilliseconds int64,
) relay.Envelope {
	return relay.Envelope{
		Version: relay.SchemaVersion, Algorithm: relay.EnvelopeAlgorithm,
		TenantID: provisioning.SpaceID, DomainID: provisioning.Domain.Registration.DomainID,
		MessageID: uuid.New(), PublisherMemberID: provisioning.InitialParticipantID,
		KeyEpoch: keyEpoch, CreatedAtMilliseconds: createdAtMilliseconds,
		Nonce:             base64.RawURLEncoding.EncodeToString(make([]byte, 12)),
		Ciphertext:        base64.RawURLEncoding.EncodeToString([]byte("opaque Shared Space payload")),
		AuthenticationTag: base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
	}
}

func testInvitation(
	t *testing.T,
	space sharedspaces.SpaceProvisioning,
	admin relay.AdministrationCredential,
	now int64,
	role sharedspaces.Role,
) (sharedspaces.Invitation, sharedspaces.InvitationCredential) {
	t.Helper()
	invitationID := uuid.New()
	credential := sharedspaces.InvitationCredential{
		SpaceID: space.SpaceID, DomainID: admin.DomainID,
		InvitationID: invitationID, Token: testToken(0x51),
	}
	digest, err := relay.AdmissionAuthorizationDigest(relay.AdmissionCredential{
		TenantID: credential.SpaceID, DomainID: credential.DomainID,
		AdmissionID: credential.InvitationID, Token: credential.Token,
	})
	if err != nil {
		t.Fatal(err)
	}
	invitation := sharedspaces.Invitation{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(), SpaceID: space.SpaceID,
		InvitationID: invitationID, ParticipantID: uuid.New(), SubscriptionID: uuid.New(),
		Kind: sharedspaces.ParticipantPerson, Role: role,
		InteractionMode: space.InteractionMode, CreatedAtMilliseconds: now,
		RelayAdmission: relay.MemberAdmission{
			Version: relay.SchemaVersion, TenantID: space.SpaceID, DomainID: admin.DomainID,
			AdmissionID: invitationID, AuthorizationDigest: digest,
			Capabilities: role.Capabilities(space.InteractionMode), CreatedAtMilliseconds: now,
			ExpiresAtMilliseconds: now + 60*60*1_000,
		},
	}
	if space.SecurityMode == sharedspaces.SecurityModeE2EE {
		invitation.KeyGrant = testParticipantKeyGrant(
			t, space.SpaceID, invitation.ParticipantID, space.InitialParticipantID,
			sharedspaces.InitialKeyEpoch, now,
		)
	}
	return invitation, credential
}

func testParticipantKeyGrant(
	t *testing.T,
	spaceID uuid.UUID,
	participantID uuid.UUID,
	issuerParticipantID uuid.UUID,
	keyEpoch uint64,
	now int64,
) *sharedspaces.ParticipantKeyGrant {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := elliptic.Marshal(elliptic.P256(), privateKey.PublicKey.X, privateKey.PublicKey.Y)
	signingFingerprint := sha256.Sum256(publicKey)
	recipientFingerprint := sha256.Sum256([]byte("recipient agreement key"))
	grant := sharedspaces.ParticipantKeyGrant{
		Version: sharedspaces.SchemaVersion, SpaceID: spaceID,
		ParticipantID: participantID, IssuerParticipantID: issuerParticipantID,
		KeyEpoch: keyEpoch, Algorithm: sharedspaces.ParticipantKeyGrantAlgorithm,
		RecipientAgreementKeyFingerprint: hex.EncodeToString(recipientFingerprint[:]),
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

func testToken(seed byte) string {
	value := make([]byte, 32)
	for index := range value {
		value[index] = seed + byte(index)
	}
	return base64.RawURLEncoding.EncodeToString(value)
}

func sameTestCapabilities(left, right []relay.Capability) bool {
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
