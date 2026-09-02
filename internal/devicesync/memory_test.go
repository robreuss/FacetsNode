package devicesync_test

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/devicesync"
	"github.com/robreuss/FacetsNode/internal/relay"
)

func TestMemoryStoreClaimsAdmissionExactlyOnceAndRetriesExactly(t *testing.T) {
	ctx := context.Background()
	store := devicesync.NewMemoryStore(relay.NewMemoryStore())
	credential, admission := testAdmission(t, 1_000)
	created, err := store.CreateAccountAdmission(ctx, admission, 1_000)
	if err != nil || created.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("create=%+v err=%v", created, err)
	}
	duplicate, err := store.CreateAccountAdmission(ctx, admission, 1_000)
	if err != nil || duplicate.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("duplicate create=%+v err=%v", duplicate, err)
	}
	provisioning := testPrincipalProvisioning(t, 1_100)
	claimed, err := store.ClaimAccountAdmission(ctx, credential, provisioning, 1_100)
	if err != nil || claimed.Acceptance != relay.AcceptanceAccepted ||
		claimed.PrincipalID != provisioning.PrincipalID || claimed.DeviceID != provisioning.InitialDeviceID {
		t.Fatalf("claim=%+v err=%v", claimed, err)
	}
	retry, err := store.ClaimAccountAdmission(ctx, credential, provisioning, 1_200)
	if err != nil || retry.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("claim retry=%+v err=%v", retry, err)
	}
	clockRollbackRetry, err := store.ClaimAccountAdmission(
		ctx, credential, provisioning, 1_000,
	)
	if err != nil || clockRollbackRetry.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("clock-rollback claim retry=%+v err=%v", clockRollbackRetry, err)
	}
	changed := provisioning
	changed.RetryID = uuid.New()
	if _, err := store.ClaimAccountAdmission(ctx, credential, changed, 1_200); !devicesync.ErrorHasCode(err, devicesync.CodeAdmissionClaimed) {
		t.Fatalf("changed claim err=%v", err)
	}
}

func TestMemoryStoreRejectsWrongAndExpiredAdmissionCredentials(t *testing.T) {
	ctx := context.Background()
	store := devicesync.NewMemoryStore(relay.NewMemoryStore())
	credential, admission := testAdmission(t, 1_000)
	if _, err := store.CreateAccountAdmission(ctx, admission, 1_000); err != nil {
		t.Fatal(err)
	}
	wrong := credential
	wrong.Token = testToken(0x77)
	if _, err := store.ClaimAccountAdmission(ctx, wrong, testPrincipalProvisioning(t, 1_100), 1_100); !devicesync.ErrorHasCode(err, devicesync.CodeUnauthorized) {
		t.Fatalf("wrong credential err=%v", err)
	}
	if _, err := store.ClaimAccountAdmission(
		ctx, credential, testPrincipalProvisioning(t, admission.ExpiresAtMilliseconds),
		admission.ExpiresAtMilliseconds,
	); !devicesync.ErrorHasCode(err, devicesync.CodeAdmissionExpired) {
		t.Fatalf("expired credential err=%v", err)
	}
}

func TestMemoryStoreAdmitsAdditionalDeviceTransportExactlyOnce(t *testing.T) {
	ctx := context.Background()
	store := devicesync.NewMemoryStore(relay.NewMemoryStore())
	accountCredential, accountAdmission := testAdmission(t, 1_000)
	if _, err := store.CreateAccountAdmission(ctx, accountAdmission, 1_000); err != nil {
		t.Fatal(err)
	}
	principal := testPrincipalProvisioning(t, 1_100)
	if _, err := store.ClaimAccountAdmission(ctx, accountCredential, principal, 1_100); err != nil {
		t.Fatal(err)
	}
	admin := relay.AdministrationCredential{
		TenantID: principal.PrincipalID,
		DomainID: principal.ControlDomain.Registration.DomainID,
		Token:    testToken(0x20),
	}
	credential, admission := testDeviceAdmission(t, principal, 1_200)
	created, err := store.CreateDeviceAdmission(ctx, admin, admission, 1_200)
	if err != nil || created.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("create=%+v err=%v", created, err)
	}
	duplicate, err := store.CreateDeviceAdmission(ctx, admin, admission, 1_200)
	if err != nil || duplicate.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("duplicate=%+v err=%v", duplicate, err)
	}
	memberCredential := relay.Credential{
		TenantID: principal.PrincipalID,
		DomainID: principal.ControlDomain.Registration.DomainID,
		MemberID: admission.DeviceID,
		Token:    testToken(0x71),
	}
	memberDigest, err := relay.AuthorizationDigest(memberCredential)
	if err != nil {
		t.Fatal(err)
	}
	claim := devicesync.DeviceAdmissionClaim{
		Version: devicesync.SchemaVersion, PrincipalID: principal.PrincipalID,
		DeviceID: admission.DeviceID,
		RelayClaim: relay.MemberAdmissionClaim{
			MemberID: admission.DeviceID, AuthorizationDigest: memberDigest,
		},
		ClaimedAtMilliseconds: 1_300,
	}
	claimed, err := store.ClaimDeviceAdmission(ctx, credential, claim, 1_300)
	if err != nil || claimed.Acceptance != relay.AcceptanceAccepted ||
		claimed.Member.MemberRegistration.MemberID != admission.DeviceID {
		t.Fatalf("claim=%+v err=%v", claimed, err)
	}
	retry, err := store.ClaimDeviceAdmission(ctx, credential, claim, 1_300)
	if err != nil || retry.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("claim retry=%+v err=%v", retry, err)
	}
	changed := claim
	changed.RelayClaim.AuthorizationDigest = testDigest(t, relay.Credential{
		TenantID: principal.PrincipalID, DomainID: admin.DomainID,
		MemberID: admission.DeviceID, Token: testToken(0x72),
	})
	if _, err := store.ClaimDeviceAdmission(ctx, credential, changed, 1_300); !devicesync.ErrorHasCode(err, devicesync.CodeAdmissionClaimed) {
		t.Fatalf("changed claim err=%v", err)
	}
}

func TestMemoryStoreRejectsDeviceAdmissionForAnotherPrincipal(t *testing.T) {
	ctx := context.Background()
	store := devicesync.NewMemoryStore(relay.NewMemoryStore())
	accountCredential, accountAdmission := testAdmission(t, 1_000)
	_, _ = store.CreateAccountAdmission(ctx, accountAdmission, 1_000)
	principal := testPrincipalProvisioning(t, 1_100)
	_, _ = store.ClaimAccountAdmission(ctx, accountCredential, principal, 1_100)
	_, admission := testDeviceAdmission(t, principal, 1_200)
	wrong := relay.AdministrationCredential{
		TenantID: uuid.New(), DomainID: principal.ControlDomain.Registration.DomainID,
		Token: testToken(0x20),
	}
	if _, err := store.CreateDeviceAdmission(ctx, wrong, admission, 1_200); !devicesync.ErrorHasCode(err, devicesync.CodeWrongScope) {
		t.Fatalf("wrong principal err=%v", err)
	}
}

func TestMemoryStoreProvisionsOpaqueSpaceDomainExactlyOnce(t *testing.T) {
	ctx := context.Background()
	store := devicesync.NewMemoryStore(relay.NewMemoryStore())
	principal := bootstrapMemoryPrincipal(t, store, 1_000)
	credential, provisioning := testSpaceProvisioning(t, principal, 1_200)

	created, err := store.ProvisionSpace(ctx, credential, provisioning, 1_200)
	if err != nil || created.Acceptance != relay.AcceptanceAccepted ||
		created.PrincipalID != principal.PrincipalID || created.SpaceID != provisioning.SpaceID ||
		created.Domain.DomainID != provisioning.Domain.Registration.DomainID {
		t.Fatalf("created=%+v err=%v", created, err)
	}
	retry, err := store.ProvisionSpace(ctx, credential, provisioning, 1_300)
	if err != nil || retry.Acceptance != relay.AcceptanceDuplicate ||
		retry.Domain.DomainID != created.Domain.DomainID {
		t.Fatalf("retry=%+v err=%v", retry, err)
	}

	changed := provisioning
	changed.SpaceID = uuid.New()
	if _, err := store.ProvisionSpace(ctx, credential, changed, 1_300); !devicesync.ErrorHasCode(err, devicesync.CodeSpaceCollision) {
		t.Fatalf("changed retry err=%v", err)
	}
}

func TestMemoryStoreRejectsSpaceProvisioningByUnenrolledDevice(t *testing.T) {
	ctx := context.Background()
	store := devicesync.NewMemoryStore(relay.NewMemoryStore())
	principal := bootstrapMemoryPrincipal(t, store, 2_000)
	credential, provisioning := testSpaceProvisioning(t, principal, 2_200)
	provisioning.InitialDeviceID = uuid.New()
	provisioning.Domain.InitialMember.MemberID = provisioning.InitialDeviceID
	memberCredential := relay.Credential{
		TenantID: principal.PrincipalID, DomainID: provisioning.Domain.Registration.DomainID,
		MemberID: provisioning.InitialDeviceID, Token: testToken(0x43),
	}
	provisioning.Domain.InitialMember.AuthorizationDigest = testDigest(t, memberCredential)

	if _, err := store.ProvisionSpace(ctx, credential, provisioning, 2_200); !devicesync.ErrorHasCode(err, devicesync.CodeUnauthorized) {
		t.Fatalf("unenrolled initial device err=%v", err)
	}
}

func TestMemoryStoreAdmitsEnrolledDeviceToSpaceExactlyOnce(t *testing.T) {
	ctx := context.Background()
	store := devicesync.NewMemoryStore(relay.NewMemoryStore())
	principal := bootstrapMemoryPrincipal(t, store, 3_000)
	deviceID := enrollMemoryDevice(t, store, principal, 3_200)
	_, space := testSpaceProvisioning(t, principal, 3_400)
	if _, err := store.ProvisionSpace(
		ctx,
		relay.TenantCredential{TenantID: principal.PrincipalID, Token: testToken(0x10)},
		space,
		3_400,
	); err != nil {
		t.Fatal(err)
	}
	admin := relay.AdministrationCredential{
		TenantID: principal.PrincipalID,
		DomainID: space.Domain.Registration.DomainID,
		Token:    testToken(0x41),
	}
	credential, admission := testSpaceDeviceAdmission(t, space, deviceID, 3_500)
	created, err := store.CreateSpaceDeviceAdmission(ctx, admin, admission, 3_500)
	if err != nil || created.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("create=%+v err=%v", created, err)
	}
	duplicate, err := store.CreateSpaceDeviceAdmission(ctx, admin, admission, 3_500)
	if err != nil || duplicate.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("duplicate=%+v err=%v", duplicate, err)
	}
	memberDigest := testDigest(t, relay.Credential{
		TenantID: principal.PrincipalID, DomainID: admin.DomainID,
		MemberID: deviceID, Token: testToken(0x74),
	})
	claim := devicesync.SpaceDeviceAdmissionClaim{
		Version: devicesync.SchemaVersion, PrincipalID: principal.PrincipalID,
		SpaceID: space.SpaceID, DeviceID: deviceID,
		RelayClaim: relay.MemberAdmissionClaim{
			MemberID: deviceID, AuthorizationDigest: memberDigest,
		},
		ClaimedAtMilliseconds: 3_600,
	}
	claimed, err := store.ClaimSpaceDeviceAdmission(ctx, credential, claim, 3_600)
	if err != nil || claimed.Acceptance != relay.AcceptanceAccepted ||
		claimed.SpaceID != space.SpaceID || claimed.DeviceID != deviceID {
		t.Fatalf("claim=%+v err=%v", claimed, err)
	}
	retry, err := store.ClaimSpaceDeviceAdmission(ctx, credential, claim, 3_600)
	if err != nil || retry.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("claim retry=%+v err=%v", retry, err)
	}
}

func TestMemoryStoreReportsContentBlindPrincipalStatus(t *testing.T) {
	ctx := context.Background()
	store := devicesync.NewMemoryStore(relay.NewMemoryStore())
	principal := bootstrapMemoryPrincipal(t, store, 5_000)
	deviceID := enrollMemoryDevice(t, store, principal, 5_200)
	credential, space := testSpaceProvisioning(t, principal, 5_400)
	if _, err := store.ProvisionSpace(ctx, credential, space, 5_400); err != nil {
		t.Fatal(err)
	}
	enrollMemoryDeviceInSpace(t, store, space, deviceID, 5_500)

	status, err := store.GetPrincipalStatus(ctx, credential)
	if err != nil {
		t.Fatal(err)
	}
	if status.Version != devicesync.SchemaVersion ||
		status.PrincipalID != principal.PrincipalID ||
		status.ControlDomainID != principal.ControlDomain.Registration.DomainID {
		t.Fatalf("unexpected principal status: %+v", status)
	}
	if len(status.Devices) != 2 {
		t.Fatalf("device status count=%d status=%+v", len(status.Devices), status)
	}
	if status.Devices[0].DeviceID.String() > status.Devices[1].DeviceID.String() {
		t.Fatalf("device status is not deterministic: %+v", status.Devices)
	}
	if status.Devices[0].ControlSubscriptionID == status.Devices[1].ControlSubscriptionID {
		t.Fatalf("devices share a control subscription: %+v", status.Devices)
	}
	if status.Devices[0].RevokedAtMilliseconds != nil || status.Devices[1].RevokedAtMilliseconds != nil {
		t.Fatalf("new devices unexpectedly revoked: %+v", status.Devices)
	}
	if len(status.Spaces) != 1 || status.Spaces[0].SpaceID != space.SpaceID ||
		status.Spaces[0].DomainID != space.Domain.Registration.DomainID ||
		len(status.Spaces[0].Devices) != 2 {
		t.Fatalf("unexpected Space status: %+v", status.Spaces)
	}
	if status.Spaces[0].Devices[0].DeviceID.String() > status.Spaces[0].Devices[1].DeviceID.String() {
		t.Fatalf("Space device status is not deterministic: %+v", status.Spaces[0].Devices)
	}
	if status.Spaces[0].Devices[0].SubscriptionID == status.Spaces[0].Devices[1].SubscriptionID {
		t.Fatalf("Space devices share a subscription: %+v", status.Spaces[0].Devices)
	}

	wrong := credential
	wrong.Token = testToken(0x7f)
	if _, err := store.GetPrincipalStatus(ctx, wrong); !relay.ErrorHasCode(err, relay.CodeUnauthorized) {
		t.Fatalf("wrong principal credential err=%v", err)
	}
}

func TestMemoryStorePublishesDiscoverableSyncGroupForAuthorizedPrincipal(t *testing.T) {
	relayStore := relay.NewMemoryStore()
	store := devicesync.NewMemoryStore(relayStore)
	principal := bootstrapMemoryPrincipal(t, store, 8_000)
	profile := devicesync.DiscoveryProfile{
		Version:             devicesync.SchemaVersion,
		PrincipalID:         principal.PrincipalID,
		SetDiscriminator:    strings.Repeat("a", 32),
		DisplayName:         "Rob's Devices",
		Revision:            2,
		UpdatedMilliseconds: 8_100,
	}
	credential := relay.TenantCredential{
		TenantID: principal.PrincipalID,
		Token:    testToken(0x10),
	}
	if err := store.PublishDiscoveryProfile(context.Background(), credential, profile); err != nil {
		t.Fatal(err)
	}
	profiles, err := store.ListDiscoveryProfiles(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(profiles, []devicesync.DiscoveryProfile{profile}) {
		t.Fatalf("profiles=%+v", profiles)
	}
	wrong := profile
	wrong.PrincipalID = uuid.New()
	if err := store.PublishDiscoveryProfile(context.Background(), credential, wrong); !devicesync.ErrorHasCode(err, devicesync.CodeWrongScope) {
		t.Fatalf("wrong principal err=%v", err)
	}
}

func TestMemoryStoreRevokesDeviceAcrossPrincipalAndSpaceAtomically(t *testing.T) {
	ctx := context.Background()
	relayStore := relay.NewMemoryStore()
	store := devicesync.NewMemoryStore(relayStore)
	principal := bootstrapMemoryPrincipal(t, store, 6_000)
	deviceID := enrollMemoryDevice(t, store, principal, 6_200)
	credential, space := testSpaceProvisioning(t, principal, 6_400)
	if _, err := store.ProvisionSpace(ctx, credential, space, 6_400); err != nil {
		t.Fatal(err)
	}
	enrollMemoryDeviceInSpace(t, store, space, deviceID, 6_500)

	revocation := devicesync.DeviceRevocation{
		Version: devicesync.SchemaVersion, RetryID: uuid.New(),
		PrincipalID: principal.PrincipalID, DeviceID: deviceID,
	}
	result, err := store.RevokeDevice(ctx, credential, revocation, 6_700)
	if err != nil || result.Acceptance != relay.AcceptanceAccepted ||
		result.PrincipalID != principal.PrincipalID || result.DeviceID != deviceID ||
		result.RevokedAtMilliseconds != 6_700 || len(result.Memberships) != 2 {
		t.Fatalf("revoke=%+v err=%v", result, err)
	}
	if result.Memberships[0].DomainID.String() > result.Memberships[1].DomainID.String() {
		t.Fatalf("revoked memberships are not deterministic: %+v", result.Memberships)
	}
	retry, err := store.RevokeDevice(ctx, credential, revocation, 6_800)
	if err != nil || retry.Acceptance != relay.AcceptanceDuplicate ||
		retry.RevokedAtMilliseconds != result.RevokedAtMilliseconds ||
		len(retry.Memberships) != len(result.Memberships) {
		t.Fatalf("revoke retry=%+v err=%v", retry, err)
	}

	controlCredential := relay.Credential{
		TenantID: principal.PrincipalID,
		DomainID: principal.ControlDomain.Registration.DomainID,
		MemberID: deviceID,
		Token:    testToken(0x71),
	}
	if _, err := relayStore.Fetch(ctx, controlCredential, 0, 1, 6_800); !relay.ErrorHasCode(err, relay.CodeMemberRevoked) {
		t.Fatalf("revoked control credential err=%v", err)
	}
	spaceCredential := relay.Credential{
		TenantID: principal.PrincipalID,
		DomainID: space.Domain.Registration.DomainID,
		MemberID: deviceID,
		Token:    testToken(0x74),
	}
	if _, err := relayStore.Fetch(ctx, spaceCredential, 0, 1, 6_800); !relay.ErrorHasCode(err, relay.CodeMemberRevoked) {
		t.Fatalf("revoked Space credential err=%v", err)
	}

	status, err := store.GetPrincipalStatus(ctx, credential)
	if err != nil {
		t.Fatal(err)
	}
	if revokedAt := deviceRevokedAt(status.Devices, deviceID); revokedAt == nil || *revokedAt != 6_700 {
		t.Fatalf("principal device status did not expose revocation: %+v", status.Devices)
	}
	if len(status.Spaces) != 1 {
		t.Fatalf("unexpected Space status: %+v", status.Spaces)
	}
	if revokedAt := spaceDeviceRevokedAt(status.Spaces[0].Devices, deviceID); revokedAt == nil || *revokedAt != 6_700 {
		t.Fatalf("Space device status did not expose revocation: %+v", status.Spaces[0].Devices)
	}

	changedRetry := revocation
	changedRetry.RetryID = uuid.New()
	if _, err := store.RevokeDevice(ctx, credential, changedRetry, 6_800); !devicesync.ErrorHasCode(err, devicesync.CodeDeviceRevoked) {
		t.Fatalf("second revocation err=%v", err)
	}
	initialRevocation := devicesync.DeviceRevocation{
		Version: devicesync.SchemaVersion, RetryID: uuid.New(),
		PrincipalID: principal.PrincipalID, DeviceID: principal.InitialDeviceID,
	}
	if _, err := store.RevokeDevice(ctx, credential, initialRevocation, 6_800); !devicesync.ErrorHasCode(err, devicesync.CodeLastDevice) {
		t.Fatalf("last-device revocation err=%v", err)
	}
	if _, err := relayStore.Fetch(ctx, relay.Credential{
		TenantID: principal.PrincipalID,
		DomainID: principal.ControlDomain.Registration.DomainID,
		MemberID: principal.InitialDeviceID,
		Token:    testToken(0x30),
	}, 0, 1, 6_800); err != nil {
		t.Fatalf("failed last-device revocation fenced the surviving device: %v", err)
	}
}

func deviceRevokedAt(devices []devicesync.DeviceStatus, deviceID uuid.UUID) *int64 {
	for _, device := range devices {
		if device.DeviceID == deviceID {
			return device.RevokedAtMilliseconds
		}
	}
	return nil
}

func spaceDeviceRevokedAt(devices []devicesync.SpaceDeviceStatus, deviceID uuid.UUID) *int64 {
	for _, device := range devices {
		if device.DeviceID == deviceID {
			return device.RevokedAtMilliseconds
		}
	}
	return nil
}

func TestMemoryStoreRejectsSpaceAdmissionForUnenrolledDeviceAndWrongDomain(t *testing.T) {
	ctx := context.Background()
	store := devicesync.NewMemoryStore(relay.NewMemoryStore())
	principal := bootstrapMemoryPrincipal(t, store, 4_000)
	_, space := testSpaceProvisioning(t, principal, 4_200)
	if _, err := store.ProvisionSpace(
		ctx,
		relay.TenantCredential{TenantID: principal.PrincipalID, Token: testToken(0x10)},
		space,
		4_200,
	); err != nil {
		t.Fatal(err)
	}
	_, admission := testSpaceDeviceAdmission(t, space, uuid.New(), 4_300)
	spaceAdmin := relay.AdministrationCredential{
		TenantID: principal.PrincipalID, DomainID: space.Domain.Registration.DomainID,
		Token: testToken(0x41),
	}
	if _, err := store.CreateSpaceDeviceAdmission(ctx, spaceAdmin, admission, 4_300); !devicesync.ErrorHasCode(err, devicesync.CodeUnauthorized) {
		t.Fatalf("unenrolled device err=%v", err)
	}

	deviceID := enrollMemoryDevice(t, store, principal, 4_400)
	_, admission = testSpaceDeviceAdmission(t, space, deviceID, 4_500)
	controlAdmin := relay.AdministrationCredential{
		TenantID: principal.PrincipalID,
		DomainID: principal.ControlDomain.Registration.DomainID,
		Token:    testToken(0x20),
	}
	if _, err := store.CreateSpaceDeviceAdmission(ctx, controlAdmin, admission, 4_500); !devicesync.ErrorHasCode(err, devicesync.CodeWrongScope) {
		t.Fatalf("wrong domain err=%v", err)
	}
}

func bootstrapMemoryPrincipal(
	t *testing.T,
	store *devicesync.MemoryStore,
	createdAt int64,
) devicesync.PrincipalProvisioning {
	t.Helper()
	credential, admission := testAdmission(t, createdAt)
	if _, err := store.CreateAccountAdmission(context.Background(), admission, createdAt); err != nil {
		t.Fatal(err)
	}
	principal := testPrincipalProvisioning(t, createdAt+100)
	if _, err := store.ClaimAccountAdmission(context.Background(), credential, principal, createdAt+100); err != nil {
		t.Fatal(err)
	}
	return principal
}

func enrollMemoryDevice(
	t *testing.T,
	store *devicesync.MemoryStore,
	principal devicesync.PrincipalProvisioning,
	createdAt int64,
) uuid.UUID {
	t.Helper()
	credential, admission := testDeviceAdmission(t, principal, createdAt)
	admin := relay.AdministrationCredential{
		TenantID: principal.PrincipalID,
		DomainID: principal.ControlDomain.Registration.DomainID,
		Token:    testToken(0x20),
	}
	if _, err := store.CreateDeviceAdmission(context.Background(), admin, admission, createdAt); err != nil {
		t.Fatal(err)
	}
	digest := testDigest(t, relay.Credential{
		TenantID: principal.PrincipalID, DomainID: admin.DomainID,
		MemberID: admission.DeviceID, Token: testToken(0x71),
	})
	claim := devicesync.DeviceAdmissionClaim{
		Version: devicesync.SchemaVersion, PrincipalID: principal.PrincipalID,
		DeviceID: admission.DeviceID,
		RelayClaim: relay.MemberAdmissionClaim{
			MemberID: admission.DeviceID, AuthorizationDigest: digest,
		},
		ClaimedAtMilliseconds: createdAt + 100,
	}
	if _, err := store.ClaimDeviceAdmission(context.Background(), credential, claim, createdAt+100); err != nil {
		t.Fatal(err)
	}
	return admission.DeviceID
}

func enrollMemoryDeviceInSpace(
	t *testing.T,
	store *devicesync.MemoryStore,
	space devicesync.SpaceProvisioning,
	deviceID uuid.UUID,
	createdAt int64,
) {
	t.Helper()
	credential, admission := testSpaceDeviceAdmission(t, space, deviceID, createdAt)
	admin := relay.AdministrationCredential{
		TenantID: space.PrincipalID,
		DomainID: space.Domain.Registration.DomainID,
		Token:    testToken(0x41),
	}
	if _, err := store.CreateSpaceDeviceAdmission(
		context.Background(), admin, admission, createdAt,
	); err != nil {
		t.Fatal(err)
	}
	digest := testDigest(t, relay.Credential{
		TenantID: space.PrincipalID, DomainID: admin.DomainID,
		MemberID: deviceID, Token: testToken(0x74),
	})
	if _, err := store.ClaimSpaceDeviceAdmission(
		context.Background(), credential,
		devicesync.SpaceDeviceAdmissionClaim{
			Version: devicesync.SchemaVersion, PrincipalID: space.PrincipalID,
			SpaceID: space.SpaceID, DeviceID: deviceID,
			RelayClaim: relay.MemberAdmissionClaim{
				MemberID: deviceID, AuthorizationDigest: digest,
			},
			ClaimedAtMilliseconds: createdAt + 100,
		},
		createdAt+100,
	); err != nil {
		t.Fatal(err)
	}
}

func testAdmission(t *testing.T, createdAt int64) (devicesync.AdmissionCredential, devicesync.AccountAdmission) {
	t.Helper()
	credential := devicesync.AdmissionCredential{AdmissionID: uuid.New(), Token: testToken(0x51)}
	digest, err := devicesync.AdmissionAuthorizationDigest(credential)
	if err != nil {
		t.Fatal(err)
	}
	return credential, devicesync.AccountAdmission{
		Version: devicesync.SchemaVersion, RetryID: uuid.New(), AdmissionID: credential.AdmissionID,
		AuthorizationDigest: digest, CreatedAtMilliseconds: createdAt,
		ExpiresAtMilliseconds: createdAt + devicesync.MinimumAdmissionLifetimeMilliseconds,
	}
}

func testPrincipalProvisioning(t *testing.T, createdAt int64) devicesync.PrincipalProvisioning {
	t.Helper()
	principalID := uuid.New()
	deviceID := uuid.New()
	domainID := uuid.New()
	tenantCredential := relay.TenantCredential{TenantID: principalID, Token: testToken(0x10)}
	adminCredential := relay.AdministrationCredential{TenantID: principalID, DomainID: domainID, Token: testToken(0x20)}
	memberCredential := relay.Credential{TenantID: principalID, DomainID: domainID, MemberID: deviceID, Token: testToken(0x30)}
	tenantDigest, err := relay.TenantAuthorizationDigest(tenantCredential)
	if err != nil {
		t.Fatal(err)
	}
	adminDigest, err := relay.AdministrationDigest(adminCredential)
	if err != nil {
		t.Fatal(err)
	}
	memberDigest, err := relay.AuthorizationDigest(memberCredential)
	if err != nil {
		t.Fatal(err)
	}
	capabilities := []relay.Capability{
		relay.CapabilityFetchBlob,
		relay.CapabilityPublishBlob,
		relay.CapabilityPublishCheckpoint,
		relay.CapabilityAcknowledgeMessage,
		relay.CapabilityFetchMessage,
		relay.CapabilityPublishMessage,
	}
	domain := relay.DomainProvisioning{
		Version: relay.SchemaVersion, RetryID: uuid.New(),
		Registration: relay.DomainRegistration{
			Version: relay.SchemaVersion, TenantID: principalID, DomainID: domainID,
			AdministrationDigest: adminDigest, CreatedAtMilliseconds: createdAt,
			MaximumMessageCount:     relay.DefaultMaximumMessageCount,
			MaximumMessageByteCount: relay.DefaultMaximumMessageByteCount,
			MaximumBlobCount:        relay.DefaultMaximumBlobCount,
			MaximumBlobByteCount:    relay.DefaultMaximumBlobByteCount,
		},
		Subscription: relay.Subscription{
			Version: relay.SchemaVersion, TenantID: principalID, DomainID: domainID,
			SubscriptionID: uuid.New(), Status: relay.SubscriptionActive,
			CreatedAtMilliseconds: createdAt, UpdatedAtMilliseconds: createdAt,
		},
		InitialMember: relay.MemberRegistration{
			Version: relay.SchemaVersion, TenantID: principalID, DomainID: domainID,
			MemberID: deviceID, AuthorizationDigest: memberDigest,
			Capabilities: capabilities, CreatedAtMilliseconds: createdAt,
		},
	}
	return devicesync.PrincipalProvisioning{
		Version: devicesync.SchemaVersion, RetryID: uuid.New(), PrincipalID: principalID,
		InitialDeviceID: deviceID,
		Tenant: relay.TenantRegistration{
			Version: relay.SchemaVersion, RetryID: uuid.New(), TenantID: principalID,
			AuthorizationDigest: tenantDigest, CreatedAtMilliseconds: createdAt,
			MaximumDomainCount:               relay.DefaultMaximumDomainCountPerTenant,
			MaximumAggregateMessageCount:     relay.DefaultMaximumMessageCountPerTenant,
			MaximumAggregateMessageByteCount: relay.DefaultMaximumMessageBytesPerTenant,
			MaximumAggregateBlobCount:        relay.DefaultMaximumBlobCountPerTenant,
			MaximumAggregateBlobByteCount:    relay.DefaultMaximumBlobBytesPerTenant,
		},
		ControlDomain: domain, CreatedAtMilliseconds: createdAt,
	}
}

func testDeviceAdmission(
	t *testing.T,
	principal devicesync.PrincipalProvisioning,
	createdAt int64,
) (devicesync.DeviceAdmissionCredential, devicesync.DeviceAdmission) {
	t.Helper()
	deviceID := uuid.New()
	credential := relay.AdmissionCredential{
		TenantID:    principal.PrincipalID,
		DomainID:    principal.ControlDomain.Registration.DomainID,
		AdmissionID: uuid.New(),
		Token:       testToken(0x61),
	}
	digest, err := relay.AdmissionAuthorizationDigest(credential)
	if err != nil {
		t.Fatal(err)
	}
	admission := devicesync.DeviceAdmission{
		Version: devicesync.SchemaVersion, RetryID: uuid.New(),
		PrincipalID: principal.PrincipalID, DeviceID: deviceID,
		SubscriptionID: uuid.New(),
		RelayAdmission: relay.MemberAdmission{
			Version: relay.SchemaVersion, TenantID: principal.PrincipalID,
			DomainID: credential.DomainID, AdmissionID: credential.AdmissionID,
			AuthorizationDigest: digest,
			Capabilities: append([]relay.Capability(nil),
				principal.ControlDomain.InitialMember.Capabilities...),
			CreatedAtMilliseconds: createdAt,
			ExpiresAtMilliseconds: createdAt + devicesync.MinimumAdmissionLifetimeMilliseconds,
		},
		CreatedAtMilliseconds: createdAt,
	}
	return devicesync.DeviceAdmissionCredential{
		PrincipalID: principal.PrincipalID, AdmissionID: credential.AdmissionID,
		Token: credential.Token,
	}, admission
}

func testSpaceProvisioning(
	t *testing.T,
	principal devicesync.PrincipalProvisioning,
	createdAt int64,
) (relay.TenantCredential, devicesync.SpaceProvisioning) {
	t.Helper()
	domainID := uuid.New()
	administrationCredential := relay.AdministrationCredential{
		TenantID: principal.PrincipalID, DomainID: domainID, Token: testToken(0x41),
	}
	memberCredential := relay.Credential{
		TenantID: principal.PrincipalID, DomainID: domainID,
		MemberID: principal.InitialDeviceID, Token: testToken(0x42),
	}
	administrationDigest, err := relay.AdministrationDigest(administrationCredential)
	if err != nil {
		t.Fatal(err)
	}
	memberDigest, err := relay.AuthorizationDigest(memberCredential)
	if err != nil {
		t.Fatal(err)
	}
	domain := relay.DomainProvisioning{
		Version: relay.SchemaVersion, RetryID: uuid.New(),
		Registration: relay.DomainRegistration{
			Version: relay.SchemaVersion, TenantID: principal.PrincipalID, DomainID: domainID,
			AdministrationDigest: administrationDigest, CreatedAtMilliseconds: createdAt,
			MaximumMessageCount:     relay.DefaultMaximumMessageCount,
			MaximumMessageByteCount: relay.DefaultMaximumMessageByteCount,
			MaximumBlobCount:        relay.DefaultMaximumBlobCount,
			MaximumBlobByteCount:    relay.DefaultMaximumBlobByteCount,
		},
		Subscription: relay.Subscription{
			Version: relay.SchemaVersion, TenantID: principal.PrincipalID, DomainID: domainID,
			SubscriptionID: uuid.New(), Status: relay.SubscriptionActive,
			CreatedAtMilliseconds: createdAt, UpdatedAtMilliseconds: createdAt,
		},
		InitialMember: relay.MemberRegistration{
			Version: relay.SchemaVersion, TenantID: principal.PrincipalID, DomainID: domainID,
			MemberID: principal.InitialDeviceID, AuthorizationDigest: memberDigest,
			Capabilities:          append([]relay.Capability(nil), principal.ControlDomain.InitialMember.Capabilities...),
			CreatedAtMilliseconds: createdAt,
		},
	}
	return relay.TenantCredential{TenantID: principal.PrincipalID, Token: testToken(0x10)}, devicesync.SpaceProvisioning{
		Version: devicesync.SchemaVersion, RetryID: uuid.New(), PrincipalID: principal.PrincipalID,
		SpaceID: uuid.New(), InitialDeviceID: principal.InitialDeviceID,
		Domain: domain, CreatedAtMilliseconds: createdAt,
	}
}

func testSpaceDeviceAdmission(
	t *testing.T,
	space devicesync.SpaceProvisioning,
	deviceID uuid.UUID,
	createdAt int64,
) (devicesync.SpaceDeviceAdmissionCredential, devicesync.SpaceDeviceAdmission) {
	t.Helper()
	credential := relay.AdmissionCredential{
		TenantID: space.PrincipalID, DomainID: space.Domain.Registration.DomainID,
		AdmissionID: uuid.New(), Token: testToken(0x73),
	}
	digest, err := relay.AdmissionAuthorizationDigest(credential)
	if err != nil {
		t.Fatal(err)
	}
	admission := devicesync.SpaceDeviceAdmission{
		Version: devicesync.SchemaVersion, RetryID: uuid.New(),
		PrincipalID: space.PrincipalID, SpaceID: space.SpaceID, DeviceID: deviceID,
		SubscriptionID: uuid.New(),
		RelayAdmission: relay.MemberAdmission{
			Version: relay.SchemaVersion, TenantID: space.PrincipalID,
			DomainID: credential.DomainID, AdmissionID: credential.AdmissionID,
			AuthorizationDigest:   digest,
			Capabilities:          append([]relay.Capability(nil), space.Domain.InitialMember.Capabilities...),
			CreatedAtMilliseconds: createdAt,
			ExpiresAtMilliseconds: createdAt + devicesync.MinimumAdmissionLifetimeMilliseconds,
		},
		CreatedAtMilliseconds: createdAt,
	}
	return devicesync.SpaceDeviceAdmissionCredential{
		PrincipalID: space.PrincipalID, SpaceID: space.SpaceID,
		AdmissionID: credential.AdmissionID, Token: credential.Token,
	}, admission
}

func testDigest(t *testing.T, credential relay.Credential) string {
	t.Helper()
	digest, err := relay.AuthorizationDigest(credential)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}
