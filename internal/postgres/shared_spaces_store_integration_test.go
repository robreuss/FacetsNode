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
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/keycustody"
	postgresstore "github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/sharedspaces"
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
	memberKeyGrant, err := store.GetParticipantKeyGrant(ctx, memberCredential, now+210)
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
	participantBootstrap, err := store.GetParticipantBootstrap(ctx, memberCredential, now+212)
	if err != nil || participantBootstrap.Status.Participant.ParticipantID != invitation.ParticipantID ||
		participantBootstrap.Status.CurrentKeyEpoch != sharedspaces.InitialKeyEpoch ||
		participantBootstrap.Status.Presentation == nil ||
		participantBootstrap.Status.Presentation.DisplayName != "Ada Lovelace" ||
		participantBootstrap.KeyGrant == nil ||
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
	computePoolID := uuid.New()
	computeChange := sharedspaces.ComputePoolChange{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(), SpaceID: provisioning.SpaceID,
		PoolID: computePoolID, DisplayName: "Space batch workers", Enabled: true,
		AllowedOperations: []string{"facets.ai.classify", "facets.ai.embed"},
		ResourceCeiling: sharedspaces.ComputeResourceCeiling{
			MaximumInputBytes: 1 << 20, MaximumOutputBytes: 1 << 20,
			MaximumMemoryBytes: 1 << 30, MaximumWallTimeMilliseconds: 60_000,
		},
		PricingRevision: 1, DataSensitivityContract: "space-members-v1",
		ProcessingContract: "participant-device-v1", ChangedAtMilliseconds: now + 240,
	}
	computeResult, err := store.ChangeComputePool(ctx, admin, computeChange, now+240)
	if err != nil || computeResult.Acceptance != relay.AcceptanceAccepted ||
		computeResult.Pool.Revision != 1 || computeResult.Binding.Revision != 1 {
		t.Fatalf("compute pool=%+v err=%v", computeResult, err)
	}
	computeRetry, err := store.ChangeComputePool(ctx, admin, computeChange, now+241)
	if err != nil || computeRetry.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("compute pool retry=%+v err=%v", computeRetry, err)
	}

	status, err = store.GetSpaceStatus(ctx, admin)
	if err != nil || status.CurrentKeyEpoch != sharedspaces.InitialKeyEpoch ||
		!status.BootstrapReady || status.ActiveCheckpointEpoch == nil ||
		*status.ActiveCheckpointEpoch != sharedspaces.InitialKeyEpoch ||
		len(status.Participants) != 2 || status.Relay.ActiveSubscriptionCount != 2 ||
		len(status.Presentations) != 1 || len(status.ComputePools) != 1 ||
		len(status.ComputeBindings) != 1 ||
		status.Presentations[0].ParticipantID != invitation.ParticipantID ||
		status.Presentations[0].DisplayName != "Ada Lovelace" ||
		status.ComputePools[0].PoolID != computePoolID ||
		status.ComputeBindings[0].PoolID != computePoolID {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	revocation := sharedspaces.ParticipantRevocation{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(),
		SpaceID: invitation.SpaceID, ParticipantID: invitation.ParticipantID,
		PreviousKeyEpoch: sharedspaces.InitialKeyEpoch, NextKeyEpoch: sharedspaces.InitialKeyEpoch + 1,
		KeyGrants: []sharedspaces.ParticipantKeyGrant{*postgresParticipantKeyGrant(
			t, invitation.SpaceID, provisioning.InitialParticipantID,
			provisioning.InitialParticipantID, sharedspaces.InitialKeyEpoch+1, now+300,
		)},
	}
	previousRevocationDigest, err := promotion.SecureRosterAttestation.Digest()
	if err != nil {
		t.Fatal(err)
	}
	remainingParticipants := []sharedspaces.Participant{postgresInitialSharedSpaceParticipant(provisioning)}
	revocation.SecureRosterAttestation = postgresSecureRosterAttestation(
		t, provisioning, promotion.SecureRosterAttestation.Revision+1,
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
	hostKeyGrant, err := store.GetParticipantKeyGrant(ctx, hostCredential, now+301)
	if err != nil || hostKeyGrant.KeyGrant.ParticipantID != provisioning.InitialParticipantID ||
		hostKeyGrant.KeyGrant.KeyEpoch != sharedspaces.InitialKeyEpoch+1 {
		t.Fatalf("host key grant=%+v err=%v", hostKeyGrant, err)
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
	if _, err := store.GetParticipantBootstrap(ctx, memberCredential, now+301); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeParticipantRevoked) {
		t.Fatalf("revoked participant bootstrap err=%v", err)
	}
	if _, err := store.UpdateParticipantPresentation(
		ctx, memberCredential, presentationUpdate, now+301,
	); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeParticipantRevoked) {
		t.Fatalf("revoked participant presentation err=%v", err)
	}
	authorityEvents, err := store.ListAuthorityEvents(ctx, admin, 0, 100)
	if err != nil || len(authorityEvents.Events) != 9 || authorityEvents.NextSequence == 0 {
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
	if authorityEvents.NextSequence != authorityEvents.Events[len(authorityEvents.Events)-1].Sequence {
		t.Fatalf("next sequence=%d want=%d", authorityEvents.NextSequence, authorityEvents.Events[len(authorityEvents.Events)-1].Sequence)
	}

	var participantCount, relayMemberCount, revokedSubscriptionCount int
	var cancellationCount, revokedAdmissionCount, cancelledSubscriptionCount, keyGrantCount int
	var computePoolCount, computeChangeCount int
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
			(SELECT count(*) FROM shared_space_compute_pools
			 WHERE space_id=$1 AND pool_id=$9),
			(SELECT count(*) FROM shared_space_compute_pool_changes
			 WHERE space_id=$1 AND pool_id=$9)
	`, invitation.SpaceID, invitation.ParticipantID, revoked.RevokedAtMilliseconds,
		admin.DomainID, invitation.SubscriptionID, cancelledInvitation.InvitationID,
		cancellation.CancelledAtMilliseconds, cancelledInvitation.SubscriptionID, computePoolID).Scan(
		&participantCount, &relayMemberCount, &revokedSubscriptionCount,
		&cancellationCount, &revokedAdmissionCount, &cancelledSubscriptionCount, &keyGrantCount,
		&computePoolCount, &computeChangeCount,
	); err != nil {
		t.Fatal(err)
	}
	if participantCount != 1 || relayMemberCount != 1 || revokedSubscriptionCount != 1 ||
		cancellationCount != 1 || revokedAdmissionCount != 1 || cancelledSubscriptionCount != 1 ||
		keyGrantCount != 2 || computePoolCount != 1 || computeChangeCount != 1 {
		t.Fatalf(
			"product=%d member=%d subscription=%d cancellation=%d admission=%d cancelled subscription=%d key grants=%d compute pools=%d compute changes=%d",
			participantCount, relayMemberCount, revokedSubscriptionCount,
			cancellationCount, revokedAdmissionCount, cancelledSubscriptionCount, keyGrantCount,
			computePoolCount, computeChangeCount,
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

	hostBootstrap, err := store.GetParticipantBootstrap(ctx, hostCredential, now+210)
	if err != nil {
		t.Fatalf("managed host bootstrap: %v", err)
	}
	memberBootstrap, err := store.GetParticipantBootstrap(ctx, memberCredential, now+211)
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
	if _, err := store.GetParticipantBootstrap(ctx, memberCredential, now+301); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeParticipantRevoked) {
		t.Fatalf("revoked managed participant bootstrap err=%v", err)
	}
	rotatedHostBootstrap, err := store.GetParticipantBootstrap(ctx, hostCredential, now+302)
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
		InteractionMode:       space.InteractionMode, CreatedAtMilliseconds: now,
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
