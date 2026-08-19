package postgres_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

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
	memberKeyGrant, err := store.GetParticipantKeyGrant(ctx, memberCredential, now+210)
	if err != nil || memberKeyGrant.KeyGrant.ParticipantID != invitation.ParticipantID ||
		memberKeyGrant.KeyGrant.KeyEpoch != sharedspaces.InitialKeyEpoch {
		t.Fatalf("member key grant=%+v err=%v", memberKeyGrant, err)
	}
	demotion := sharedspaces.ParticipantRoleChange{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(), SpaceID: invitation.SpaceID,
		ParticipantID: invitation.ParticipantID, PreviousRole: sharedspaces.RoleParticipant,
		NextRole: sharedspaces.RoleReader, ChangedAtMilliseconds: now + 220,
	}
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
	promoted, err := store.ChangeParticipantRole(ctx, admin, promotion, now+230)
	if err != nil || promoted.Acceptance != relay.AcceptanceAccepted ||
		promoted.CurrentRole != sharedspaces.RoleParticipant {
		t.Fatalf("promotion=%+v err=%v", promoted, err)
	}

	status, err = store.GetSpaceStatus(ctx, admin)
	if err != nil || status.CurrentKeyEpoch != sharedspaces.InitialKeyEpoch ||
		!status.BootstrapReady || status.ActiveCheckpointEpoch == nil ||
		*status.ActiveCheckpointEpoch != sharedspaces.InitialKeyEpoch ||
		len(status.Participants) != 2 || status.Relay.ActiveSubscriptionCount != 2 {
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
	authorityEvents, err := store.ListAuthorityEvents(ctx, admin, 0, 100)
	if err != nil || len(authorityEvents.Events) != 8 || authorityEvents.NextSequence == 0 {
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
			 WHERE space_id=$1)
	`, invitation.SpaceID, invitation.ParticipantID, revoked.RevokedAtMilliseconds,
		admin.DomainID, invitation.SubscriptionID, cancelledInvitation.InvitationID,
		cancellation.CancelledAtMilliseconds, cancelledInvitation.SubscriptionID).Scan(
		&participantCount, &relayMemberCount, &revokedSubscriptionCount,
		&cancellationCount, &revokedAdmissionCount, &cancelledSubscriptionCount, &keyGrantCount,
	); err != nil {
		t.Fatal(err)
	}
	if participantCount != 1 || relayMemberCount != 1 || revokedSubscriptionCount != 1 ||
		cancellationCount != 1 || revokedAdmissionCount != 1 || cancelledSubscriptionCount != 1 ||
		keyGrantCount != 2 {
		t.Fatalf(
			"product=%d member=%d subscription=%d cancellation=%d admission=%d cancelled subscription=%d key grants=%d",
			participantCount, relayMemberCount, revokedSubscriptionCount,
			cancellationCount, revokedAdmissionCount, cancelledSubscriptionCount, keyGrantCount,
		)
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
		SecurityMode:           sharedspaces.SecurityModeE2EE,
		InteractionMode:        sharedspaces.InteractionModeCollaborative,
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
	invitation := sharedspaces.Invitation{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(), SpaceID: space.SpaceID,
		InvitationID: invitationID, ParticipantID: uuid.New(), SubscriptionID: uuid.New(),
		Kind: sharedspaces.ParticipantPerson, Role: sharedspaces.RoleParticipant,
		InteractionMode: space.InteractionMode, CreatedAtMilliseconds: now,
		RelayAdmission: relay.MemberAdmission{
			Version: relay.SchemaVersion, TenantID: space.SpaceID, DomainID: admin.DomainID,
			AdmissionID: invitationID, AuthorizationDigest: digest,
			Capabilities:          sharedspaces.RoleParticipant.Capabilities(space.InteractionMode),
			CreatedAtMilliseconds: now, ExpiresAtMilliseconds: now + 60*60*1_000,
		},
	}
	if space.SecurityMode == sharedspaces.SecurityModeE2EE {
		invitation.KeyGrant = postgresParticipantKeyGrant(
			t, space.SpaceID, invitation.ParticipantID, space.InitialParticipantID,
			sharedspaces.InitialKeyEpoch, now,
		)
	}
	return invitation, credential
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
