package sharedspaces_test

import (
	"context"
	"encoding/base64"
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
		claimed.Participant.Role != sharedspaces.RoleParticipant {
		t.Fatalf("claim=%+v err=%v", claimed, err)
	}
	claimRetry, err := store.ClaimInvitation(ctx, invitationCredential, claim, 1_300)
	if err != nil || claimRetry.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("claim retry=%+v err=%v", claimRetry, err)
	}

	status, err := store.GetSpaceStatus(ctx, admin)
	if err != nil || status.CurrentKeyEpoch != sharedspaces.InitialKeyEpoch ||
		len(status.Participants) != 2 || status.Relay.ActiveSubscriptionCount != 2 {
		t.Fatalf("status=%+v err=%v", status, err)
	}

	revocation := sharedspaces.ParticipantRevocation{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(), SpaceID: invitation.SpaceID,
		ParticipantID:    invitation.ParticipantID,
		PreviousKeyEpoch: sharedspaces.InitialKeyEpoch, NextKeyEpoch: sharedspaces.InitialKeyEpoch + 1,
	}
	revoked, err := store.RevokeParticipant(ctx, admin, revocation, 1_400)
	if err != nil || revoked.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("revoke=%+v err=%v", revoked, err)
	}
	if revoked.PreviousKeyEpoch != sharedspaces.InitialKeyEpoch ||
		revoked.CurrentKeyEpoch != sharedspaces.InitialKeyEpoch+1 {
		t.Fatalf("revocation did not rotate key epoch: %+v", revoked)
	}
	revokedRetry, err := store.RevokeParticipant(ctx, admin, revocation, 1_500)
	if err != nil || revokedRetry.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("revoke retry=%+v err=%v", revokedRetry, err)
	}
	if _, err := relayStore.Fetch(ctx, memberCredential, 0, 1, 1_500); !relay.ErrorHasCode(err, relay.CodeMemberRevoked) {
		t.Fatalf("revoked relay credential err=%v", err)
	}
	status, err = store.GetSpaceStatus(ctx, admin)
	if err != nil || status.CurrentKeyEpoch != sharedspaces.InitialKeyEpoch+1 {
		t.Fatalf("status after revocation=%+v err=%v", status, err)
	}
}

func TestMemoryStoreRejectsStaleRevocationKeyEpoch(t *testing.T) {
	ctx := context.Background()
	store := sharedspaces.NewMemoryStore(relay.NewMemoryStore())
	_, provisioning, admin := testSpaceProvisioning(t, 4_000, sharedspaces.SecurityModeE2EE)
	if _, err := store.ProvisionSpace(ctx, provisioning, 4_000); err != nil {
		t.Fatal(err)
	}
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
	stale := sharedspaces.ParticipantRevocation{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(), SpaceID: invitation.SpaceID,
		ParticipantID: invitation.ParticipantID, PreviousKeyEpoch: 2, NextKeyEpoch: 3,
	}
	if _, err := store.RevokeParticipant(ctx, admin, stale, 4_300); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeWrongKeyEpoch) {
		t.Fatalf("stale revocation err=%v", err)
	}
}

func TestMemoryStoreRejectsCrossSpaceAuthorityAndInitialHostRevocation(t *testing.T) {
	ctx := context.Background()
	store := sharedspaces.NewMemoryStore(relay.NewMemoryStore())
	_, provisioning, admin := testSpaceProvisioning(t, 3_000, sharedspaces.SecurityModeManaged)
	if _, err := store.ProvisionSpace(ctx, provisioning, 3_000); err != nil {
		t.Fatal(err)
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
		SecurityMode: mode, InitialParticipantID: hostID,
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
			Capabilities: sharedspaces.RoleHost.Capabilities(), CreatedAtMilliseconds: now,
		},
	}
	return tenantCredential, provisioning, admin
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
		Kind: sharedspaces.ParticipantPerson, Role: role, CreatedAtMilliseconds: now,
		RelayAdmission: relay.MemberAdmission{
			Version: relay.SchemaVersion, TenantID: space.SpaceID, DomainID: admin.DomainID,
			AdmissionID: invitationID, AuthorizationDigest: digest,
			Capabilities: role.Capabilities(), CreatedAtMilliseconds: now,
			ExpiresAtMilliseconds: now + 60*60*1_000,
		},
	}
	return invitation, credential
}

func testToken(seed byte) string {
	value := make([]byte, 32)
	for index := range value {
		value[index] = seed + byte(index)
	}
	return base64.RawURLEncoding.EncodeToString(value)
}
