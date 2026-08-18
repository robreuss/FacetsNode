package postgres_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/devicesync"
	postgresstore "github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/relay"
)

func TestPostgresDeviceSyncSpaceAndRelayDomainCommitAtomically(t *testing.T) {
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
	if _, err := pool.Exec(ctx, `
		TRUNCATE device_sync_account_admissions, relay_tenants CASCADE
	`); err != nil {
		t.Fatal(err)
	}
	store := postgresstore.NewRelayStore(pool)
	const now = int64(10_000)
	principalID := uuid.New()
	initialDeviceID := uuid.New()
	authority := postgresBootstrapDeviceSyncPrincipal(
		t, ctx, store, principalID, initialDeviceID, now,
	)

	spaceID := uuid.New()
	space := devicesync.SpaceProvisioning{
		Version: devicesync.SchemaVersion, RetryID: uuid.New(),
		PrincipalID: principalID, SpaceID: spaceID,
		InitialDeviceID: initialDeviceID,
		Domain: postgresDeviceSyncDomain(
			t, principalID, uuid.New(), initialDeviceID, uuid.New(), now, 31, 32,
		),
		CreatedAtMilliseconds: now,
	}
	created, err := store.ProvisionSpace(ctx, authority.TenantCredential, space, now)
	if err != nil || created.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("provision Space=%+v err=%v", created, err)
	}
	retry, err := store.ProvisionSpace(ctx, authority.TenantCredential, space, now)
	if err != nil || retry.Acceptance != relay.AcceptanceDuplicate ||
		retry.Domain.DomainID != created.Domain.DomainID {
		t.Fatalf("retry Space=%+v err=%v", retry, err)
	}
	var bindingCount, domainCount, initialMembershipCount int
	if err := pool.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM device_sync_spaces
			 WHERE principal_id=$1 AND space_id=$2 AND domain_id=$3),
			(SELECT count(*) FROM relay_domains
			 WHERE tenant_id=$1 AND domain_id=$3),
			(SELECT count(*) FROM device_sync_space_devices
			 WHERE principal_id=$1 AND space_id=$2 AND device_id=$4)
	`, principalID, spaceID, space.Domain.Registration.DomainID, initialDeviceID).Scan(
		&bindingCount, &domainCount, &initialMembershipCount,
	); err != nil {
		t.Fatal(err)
	}
	if bindingCount != 1 || domainCount != 1 || initialMembershipCount != 1 {
		t.Fatalf(
			"binding count=%d domain count=%d initial membership count=%d",
			bindingCount, domainCount, initialMembershipCount,
		)
	}

	additionalDeviceID := uuid.New()
	postgresEnrollDeviceSyncDevice(
		t, ctx, store, authority, additionalDeviceID, now+1,
	)
	spaceAdmissionCredential := relay.AdmissionCredential{
		TenantID: principalID, DomainID: space.Domain.Registration.DomainID,
		AdmissionID: uuid.New(), Token: postgresRelayToken(41),
	}
	spaceAdmissionDigest, err := relay.AdmissionAuthorizationDigest(spaceAdmissionCredential)
	if err != nil {
		t.Fatal(err)
	}
	spaceAdmission := devicesync.SpaceDeviceAdmission{
		Version: devicesync.SchemaVersion, RetryID: uuid.New(),
		PrincipalID: principalID, SpaceID: spaceID, DeviceID: additionalDeviceID,
		SubscriptionID: space.Domain.Subscription.SubscriptionID,
		RelayAdmission: relay.MemberAdmission{
			Version: relay.SchemaVersion, TenantID: principalID,
			DomainID:            spaceAdmissionCredential.DomainID,
			AdmissionID:         spaceAdmissionCredential.AdmissionID,
			AuthorizationDigest: spaceAdmissionDigest,
			Capabilities: append(
				[]relay.Capability(nil), space.Domain.InitialMember.Capabilities...,
			),
			CreatedAtMilliseconds: now + 2,
			ExpiresAtMilliseconds: now + 2 + devicesync.MinimumAdmissionLifetimeMilliseconds,
		},
		CreatedAtMilliseconds: now + 2,
	}
	spaceAdministrationCredential := relay.AdministrationCredential{
		TenantID: principalID, DomainID: space.Domain.Registration.DomainID,
		Token: postgresRelayToken(31),
	}
	spaceAdmissionCreated, err := store.CreateSpaceDeviceAdmission(
		ctx, spaceAdministrationCredential, spaceAdmission, now+2,
	)
	if err != nil || spaceAdmissionCreated.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("create Space device admission=%+v err=%v", spaceAdmissionCreated, err)
	}
	spaceMemberCredential := relay.Credential{
		TenantID: principalID, DomainID: space.Domain.Registration.DomainID,
		MemberID: additionalDeviceID, Token: postgresRelayToken(42),
	}
	spaceMemberDigest, err := relay.AuthorizationDigest(spaceMemberCredential)
	if err != nil {
		t.Fatal(err)
	}
	spaceClaim := devicesync.SpaceDeviceAdmissionClaim{
		Version: devicesync.SchemaVersion, PrincipalID: principalID,
		SpaceID: spaceID, DeviceID: additionalDeviceID,
		RelayClaim: relay.MemberAdmissionClaim{
			MemberID: additionalDeviceID, AuthorizationDigest: spaceMemberDigest,
		},
		ClaimedAtMilliseconds: now + 3,
	}
	spaceClaimed, err := store.ClaimSpaceDeviceAdmission(
		ctx,
		devicesync.SpaceDeviceAdmissionCredential{
			PrincipalID: principalID, SpaceID: spaceID,
			AdmissionID: spaceAdmissionCredential.AdmissionID,
			Token:       spaceAdmissionCredential.Token,
		},
		spaceClaim,
		now+3,
	)
	if err != nil || spaceClaimed.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("claim Space device admission=%+v err=%v", spaceClaimed, err)
	}
	spaceClaimRetry, err := store.ClaimSpaceDeviceAdmission(
		ctx,
		devicesync.SpaceDeviceAdmissionCredential{
			PrincipalID: principalID, SpaceID: spaceID,
			AdmissionID: spaceAdmissionCredential.AdmissionID,
			Token:       spaceAdmissionCredential.Token,
		},
		spaceClaim,
		now+3,
	)
	if err != nil || spaceClaimRetry.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("retry Space device claim=%+v err=%v", spaceClaimRetry, err)
	}
	var spaceDeviceCount, relayMemberCount int
	if err := pool.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM device_sync_space_devices
			 WHERE principal_id=$1 AND space_id=$2 AND device_id=$3),
			(SELECT count(*) FROM relay_members
			 WHERE tenant_id=$1 AND domain_id=$4 AND member_id=$3)
	`, principalID, spaceID, additionalDeviceID, space.Domain.Registration.DomainID).Scan(
		&spaceDeviceCount, &relayMemberCount,
	); err != nil {
		t.Fatal(err)
	}
	if spaceDeviceCount != 1 || relayMemberCount != 1 {
		t.Fatalf(
			"Space device count=%d relay member count=%d",
			spaceDeviceCount, relayMemberCount,
		)
	}

	collision := space
	collision.SpaceID = uuid.New()
	if _, err := store.ProvisionSpace(ctx, authority.TenantCredential, collision, now); !devicesync.ErrorHasCode(err, devicesync.CodeSpaceCollision) {
		t.Fatalf("changed retry error=%v", err)
	}

	orphan := devicesync.SpaceProvisioning{
		Version: devicesync.SchemaVersion, RetryID: uuid.New(),
		PrincipalID: principalID, SpaceID: uuid.New(),
		InitialDeviceID: initialDeviceID,
		Domain: postgresDeviceSyncDomain(
			t, principalID, uuid.New(), initialDeviceID, uuid.New(), now, 33, 34,
		),
		CreatedAtMilliseconds: now,
	}
	if provisioned, err := store.ProvisionDomain(
		ctx, authority.TenantCredential, orphan.Domain, now,
	); err != nil || provisioned.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("pre-provision relay domain=%+v err=%v", provisioned, err)
	}
	if _, err := store.ProvisionSpace(ctx, authority.TenantCredential, orphan, now); !devicesync.ErrorHasCode(err, devicesync.CodeSpaceCollision) {
		t.Fatalf("orphan relay adoption error=%v", err)
	}
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM device_sync_spaces
		WHERE principal_id=$1 AND space_id=$2
	`, principalID, orphan.SpaceID).Scan(&bindingCount); err != nil {
		t.Fatal(err)
	}
	if bindingCount != 0 {
		t.Fatalf("orphan relay domain acquired %d Device Sync bindings", bindingCount)
	}
}

type postgresDeviceSyncAuthority struct {
	TenantCredential                relay.TenantCredential
	ControlDomain                   relay.DomainProvisioning
	ControlAdministrationCredential relay.AdministrationCredential
}

func postgresBootstrapDeviceSyncPrincipal(
	t *testing.T,
	ctx context.Context,
	store *postgresstore.RelayStore,
	principalID uuid.UUID,
	initialDeviceID uuid.UUID,
	now int64,
) postgresDeviceSyncAuthority {
	t.Helper()
	admissionCredential := devicesync.AdmissionCredential{
		AdmissionID: uuid.New(), Token: postgresRelayToken(21),
	}
	admissionDigest, err := devicesync.AdmissionAuthorizationDigest(admissionCredential)
	if err != nil {
		t.Fatal(err)
	}
	admission := devicesync.AccountAdmission{
		Version: devicesync.SchemaVersion, RetryID: uuid.New(),
		AdmissionID:           admissionCredential.AdmissionID,
		AuthorizationDigest:   admissionDigest,
		CreatedAtMilliseconds: now,
		ExpiresAtMilliseconds: now + devicesync.MinimumAdmissionLifetimeMilliseconds,
	}
	if result, err := store.CreateAccountAdmission(ctx, admission, now); err != nil || result.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("create account admission=%+v err=%v", result, err)
	}

	tenantCredential := relay.TenantCredential{
		TenantID: principalID, Token: postgresRelayToken(22),
	}
	tenantDigest, err := relay.TenantAuthorizationDigest(tenantCredential)
	if err != nil {
		t.Fatal(err)
	}
	controlDomain := postgresDeviceSyncDomain(
		t, principalID, uuid.New(), initialDeviceID, uuid.New(), now, 23, 24,
	)
	controlAdministrationCredential := relay.AdministrationCredential{
		TenantID: principalID, DomainID: controlDomain.Registration.DomainID,
		Token: postgresRelayToken(23),
	}
	claim := devicesync.PrincipalProvisioning{
		Version: devicesync.SchemaVersion, RetryID: uuid.New(),
		PrincipalID: principalID, InitialDeviceID: initialDeviceID,
		Tenant: relay.TenantRegistration{
			Version: relay.SchemaVersion, RetryID: uuid.New(),
			TenantID: principalID, AuthorizationDigest: tenantDigest,
			CreatedAtMilliseconds:            now,
			MaximumDomainCount:               relay.DefaultMaximumDomainCountPerTenant,
			MaximumAggregateMessageCount:     relay.DefaultMaximumMessageCountPerTenant,
			MaximumAggregateMessageByteCount: relay.DefaultMaximumMessageBytesPerTenant,
			MaximumAggregateBlobCount:        relay.DefaultMaximumBlobCountPerTenant,
			MaximumAggregateBlobByteCount:    relay.DefaultMaximumBlobBytesPerTenant,
		},
		ControlDomain: controlDomain, CreatedAtMilliseconds: now,
	}
	if result, err := store.ClaimAccountAdmission(
		ctx, admissionCredential, claim, now,
	); err != nil || result.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("claim account admission=%+v err=%v", result, err)
	}
	return postgresDeviceSyncAuthority{
		TenantCredential: tenantCredential, ControlDomain: controlDomain,
		ControlAdministrationCredential: controlAdministrationCredential,
	}
}

func postgresEnrollDeviceSyncDevice(
	t *testing.T,
	ctx context.Context,
	store *postgresstore.RelayStore,
	authority postgresDeviceSyncAuthority,
	deviceID uuid.UUID,
	now int64,
) {
	t.Helper()
	credential := relay.AdmissionCredential{
		TenantID:    authority.TenantCredential.TenantID,
		DomainID:    authority.ControlDomain.Registration.DomainID,
		AdmissionID: uuid.New(), Token: postgresRelayToken(35),
	}
	digest, err := relay.AdmissionAuthorizationDigest(credential)
	if err != nil {
		t.Fatal(err)
	}
	admission := devicesync.DeviceAdmission{
		Version: devicesync.SchemaVersion, RetryID: uuid.New(),
		PrincipalID: credential.TenantID, DeviceID: deviceID,
		SubscriptionID: authority.ControlDomain.Subscription.SubscriptionID,
		RelayAdmission: relay.MemberAdmission{
			Version: relay.SchemaVersion, TenantID: credential.TenantID,
			DomainID: credential.DomainID, AdmissionID: credential.AdmissionID,
			AuthorizationDigest: digest,
			Capabilities: append(
				[]relay.Capability(nil), authority.ControlDomain.InitialMember.Capabilities...,
			),
			CreatedAtMilliseconds: now,
			ExpiresAtMilliseconds: now + devicesync.MinimumAdmissionLifetimeMilliseconds,
		},
		CreatedAtMilliseconds: now,
	}
	created, err := store.CreateDeviceAdmission(
		ctx, authority.ControlAdministrationCredential, admission, now,
	)
	if err != nil || created.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("create device admission=%+v err=%v", created, err)
	}
	memberCredential := relay.Credential{
		TenantID: credential.TenantID, DomainID: credential.DomainID,
		MemberID: deviceID, Token: postgresRelayToken(36),
	}
	memberDigest, err := relay.AuthorizationDigest(memberCredential)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimDeviceAdmission(
		ctx,
		devicesync.DeviceAdmissionCredential{
			PrincipalID: credential.TenantID, AdmissionID: credential.AdmissionID,
			Token: credential.Token,
		},
		devicesync.DeviceAdmissionClaim{
			Version: devicesync.SchemaVersion, PrincipalID: credential.TenantID,
			DeviceID: deviceID,
			RelayClaim: relay.MemberAdmissionClaim{
				MemberID: deviceID, AuthorizationDigest: memberDigest,
			},
			ClaimedAtMilliseconds: now,
		},
		now,
	)
	if err != nil || claimed.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("claim device admission=%+v err=%v", claimed, err)
	}
}

func postgresDeviceSyncDomain(
	t *testing.T,
	tenantID uuid.UUID,
	domainID uuid.UUID,
	memberID uuid.UUID,
	subscriptionID uuid.UUID,
	now int64,
	adminSeed byte,
	memberSeed byte,
) relay.DomainProvisioning {
	t.Helper()
	admin := relay.AdministrationCredential{
		TenantID: tenantID, DomainID: domainID, Token: postgresRelayToken(adminSeed),
	}
	adminDigest, err := relay.AdministrationDigest(admin)
	if err != nil {
		t.Fatal(err)
	}
	member := relay.Credential{
		TenantID: tenantID, DomainID: domainID, MemberID: memberID,
		Token: postgresRelayToken(memberSeed),
	}
	memberDigest, err := relay.AuthorizationDigest(member)
	if err != nil {
		t.Fatal(err)
	}
	return relay.DomainProvisioning{
		Version: relay.SchemaVersion, RetryID: uuid.New(),
		Registration: relay.DomainRegistration{
			Version: relay.SchemaVersion, TenantID: tenantID, DomainID: domainID,
			AdministrationDigest: adminDigest, CreatedAtMilliseconds: now,
			MaximumMessageCount:     relay.DefaultMaximumMessageCount,
			MaximumMessageByteCount: relay.DefaultMaximumMessageByteCount,
			MaximumBlobCount:        relay.DefaultMaximumBlobCount,
			MaximumBlobByteCount:    relay.DefaultMaximumBlobByteCount,
		},
		Subscription: relay.Subscription{
			Version: relay.SchemaVersion, TenantID: tenantID, DomainID: domainID,
			SubscriptionID: subscriptionID, Status: relay.SubscriptionActive,
			CreatedAtMilliseconds: now, UpdatedAtMilliseconds: now,
		},
		InitialMember: relay.MemberRegistration{
			Version: relay.SchemaVersion, TenantID: tenantID, DomainID: domainID,
			MemberID: memberID, AuthorizationDigest: memberDigest,
			Capabilities: []relay.Capability{
				relay.CapabilityFetchBlob,
				relay.CapabilityPublishBlob,
				relay.CapabilityPublishCheckpoint,
				relay.CapabilityAcknowledgeMessage,
				relay.CapabilityFetchMessage,
				relay.CapabilityPublishMessage,
			},
			CreatedAtMilliseconds: now,
		},
	}
}
