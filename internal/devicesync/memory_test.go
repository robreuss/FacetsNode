package devicesync_test

import (
	"context"
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
		SubscriptionID: principal.ControlDomain.Subscription.SubscriptionID,
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

func testDigest(t *testing.T, credential relay.Credential) string {
	t.Helper()
	digest, err := relay.AuthorizationDigest(credential)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}
