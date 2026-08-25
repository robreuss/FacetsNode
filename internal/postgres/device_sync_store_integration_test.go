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
	const now = int64(1_100)
	fixture := loadPostgresDeviceSyncEnforcementFixture(t)
	manifest := fixture.RollbackEvidence.ActivationEvidence.
		Preparation.CurrentManifest
	payload, err := manifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	localSigner := postgresFixtureDeploymentSigner(
		t, payload.ActiveDeployment,
	)
	initialAuthority := postgresInitialServiceAuthorityBinding(
		t, fixture, manifest, localSigner, now,
	)
	principalID := payload.Scope.ScopeID
	initialDeviceID := uuid.New()
	authority := postgresBootstrapDeviceSyncPrincipal(
		t, ctx, store, principalID, initialDeviceID, now, initialAuthority,
	)
	if err := store.ActivateBoundDeviceSyncScope(
		ctx,
		principalID,
		localSigner.DeploymentID(),
		initialAuthority.Revision(),
		initialAuthority.ManifestDigest(),
		now,
	); err != nil {
		t.Fatal(err)
	}

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
	additionalControlCredential, additionalControlSubscriptionID := postgresEnrollDeviceSyncDevice(
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
		SubscriptionID: uuid.New(),
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

	revocation := devicesync.DeviceRevocation{
		Version: devicesync.SchemaVersion, RetryID: uuid.New(),
		PrincipalID: principalID, DeviceID: additionalDeviceID,
	}
	revoked, err := store.RevokeDevice(
		ctx, authority.TenantCredential, revocation, now+4,
	)
	if err != nil || revoked.Acceptance != relay.AcceptanceAccepted ||
		len(revoked.Memberships) != 2 {
		t.Fatalf("revoke Device Sync device=%+v err=%v", revoked, err)
	}
	revocationRetry, err := store.RevokeDevice(
		ctx, authority.TenantCredential, revocation, now+4,
	)
	if err != nil || revocationRetry.Acceptance != relay.AcceptanceDuplicate ||
		len(revocationRetry.Memberships) != 2 {
		t.Fatalf("retry Device Sync device revocation=%+v err=%v", revocationRetry, err)
	}
	var productRevocationCount, relayRevocationCount, revokedSubscriptionCount int
	if err := pool.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM device_sync_device_revocations
			 WHERE principal_id=$1 AND device_id=$2),
			(SELECT count(*) FROM relay_tenant_membership_revocation_items
			 WHERE tenant_id=$1 AND retry_id=$3),
			(SELECT count(*) FROM relay_subscriptions
			 WHERE tenant_id=$1 AND subscription_id=ANY($4) AND status='revoked')
	`, principalID, additionalDeviceID, revocation.RetryID,
		[]uuid.UUID{additionalControlSubscriptionID, spaceAdmission.SubscriptionID},
	).Scan(&productRevocationCount, &relayRevocationCount, &revokedSubscriptionCount); err != nil {
		t.Fatal(err)
	}
	if productRevocationCount != 1 || relayRevocationCount != 2 || revokedSubscriptionCount != 2 {
		t.Fatalf(
			"product revocations=%d relay revocations=%d revoked subscriptions=%d",
			productRevocationCount, relayRevocationCount, revokedSubscriptionCount,
		)
	}
	if _, err := store.Fetch(ctx, additionalControlCredential, 0, 1, now+4); !relay.ErrorHasCode(err, relay.CodeMemberRevoked) {
		t.Fatalf("revoked control member fetch error=%v", err)
	}
	if _, err := store.Fetch(ctx, spaceMemberCredential, 0, 1, now+4); !relay.ErrorHasCode(err, relay.CodeMemberRevoked) {
		t.Fatalf("revoked Space member fetch error=%v", err)
	}
	status, err := store.GetPrincipalStatus(ctx, authority.TenantCredential)
	if err != nil {
		t.Fatal(err)
	}
	if !postgresPrincipalDeviceRevoked(status, additionalDeviceID) ||
		!postgresSpaceDeviceRevoked(status, spaceID, additionalDeviceID) {
		t.Fatalf("revoked device is missing from content-blind status: %+v", status)
	}

	// A Device Sync service restart must preserve both product-level enrollment
	// state and the underlying opaque relay authorization state. Reopen the
	// store to exercise the persisted path rather than merely reusing in-memory
	// transaction state from the original handle.
	restartedStore := postgresstore.NewRelayStore(pool)
	restartedStatus, err := restartedStore.GetPrincipalStatus(ctx, authority.TenantCredential)
	if err != nil {
		t.Fatalf("get Device Sync status after restart: %v", err)
	}
	if !postgresPrincipalDeviceRevoked(restartedStatus, additionalDeviceID) ||
		!postgresSpaceDeviceRevoked(restartedStatus, spaceID, additionalDeviceID) {
		t.Fatalf("restarted status lost Device Sync revocation: %+v", restartedStatus)
	}
	if _, err := restartedStore.Fetch(ctx, additionalControlCredential, 0, 1, now+4); !relay.ErrorHasCode(err, relay.CodeMemberRevoked) {
		t.Fatalf("restarted revoked control member fetch error=%v", err)
	}
	if _, err := restartedStore.Fetch(ctx, spaceMemberCredential, 0, 1, now+4); !relay.ErrorHasCode(err, relay.CodeMemberRevoked) {
		t.Fatalf("restarted revoked Space member fetch error=%v", err)
	}
	if _, err := restartedStore.Fetch(ctx, relay.Credential{
		TenantID: principalID, DomainID: authority.ControlDomain.Registration.DomainID,
		MemberID: initialDeviceID, Token: postgresRelayToken(24),
	}, 0, 1, now+4); err != nil {
		t.Fatalf("restarted active control member fetch: %v", err)
	}
	if retried, err := restartedStore.RevokeDevice(
		ctx, authority.TenantCredential, revocation, now+4,
	); err != nil || retried.Acceptance != relay.AcceptanceDuplicate || len(retried.Memberships) != 2 {
		t.Fatalf("restarted Device Sync revocation retry=%+v err=%v", retried, err)
	}
	changedRetry := revocation
	changedRetry.RetryID = uuid.New()
	if _, err := store.RevokeDevice(
		ctx, authority.TenantCredential, changedRetry, now+5,
	); !devicesync.ErrorHasCode(err, devicesync.CodeDeviceRevoked) {
		t.Fatalf("changed device revocation retry error=%v", err)
	}
	lastDevice := devicesync.DeviceRevocation{
		Version: devicesync.SchemaVersion, RetryID: uuid.New(),
		PrincipalID: principalID, DeviceID: initialDeviceID,
	}
	if _, err := store.RevokeDevice(
		ctx, authority.TenantCredential, lastDevice, now+5,
	); !devicesync.ErrorHasCode(err, devicesync.CodeLastDevice) {
		t.Fatalf("last Device Sync device revocation error=%v", err)
	}
}

type postgresDeviceSyncAuthority struct {
	TenantCredential                relay.TenantCredential
	ControlDomain                   relay.DomainProvisioning
	ControlAdministrationCredential relay.AdministrationCredential
	AdmissionCredential             devicesync.AdmissionCredential
	PrincipalProvisioning           devicesync.PrincipalProvisioning
}

func postgresBootstrapDeviceSyncPrincipal(
	t *testing.T,
	ctx context.Context,
	store *postgresstore.RelayStore,
	principalID uuid.UUID,
	initialDeviceID uuid.UUID,
	now int64,
	initialAuthorities ...*devicesync.InitialServiceAuthorityBinding,
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
	var result devicesync.PrincipalProvisioningResult
	if len(initialAuthorities) == 0 {
		result, err = store.ClaimAccountAdmission(
			ctx, admissionCredential, claim, now,
		)
	} else if len(initialAuthorities) == 1 {
		result, err = store.ClaimAccountAdmissionWithAuthority(
			ctx, admissionCredential, claim, initialAuthorities[0], now,
		)
	} else {
		t.Fatal("at most one initial service authority binding is supported")
	}
	if err != nil || result.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("claim account admission=%+v err=%v", result, err)
	}
	return postgresDeviceSyncAuthority{
		TenantCredential: tenantCredential, ControlDomain: controlDomain,
		ControlAdministrationCredential: controlAdministrationCredential,
		AdmissionCredential:             admissionCredential, PrincipalProvisioning: claim,
	}
}

func postgresEnrollDeviceSyncDevice(
	t *testing.T,
	ctx context.Context,
	store *postgresstore.RelayStore,
	authority postgresDeviceSyncAuthority,
	deviceID uuid.UUID,
	now int64,
) (relay.Credential, uuid.UUID) {
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
	controlSubscriptionID := uuid.New()
	admission := devicesync.DeviceAdmission{
		Version: devicesync.SchemaVersion, RetryID: uuid.New(),
		PrincipalID: credential.TenantID, DeviceID: deviceID,
		SubscriptionID: controlSubscriptionID,
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
	return memberCredential, controlSubscriptionID
}

func postgresPrincipalDeviceRevoked(status devicesync.PrincipalStatus, deviceID uuid.UUID) bool {
	for _, device := range status.Devices {
		if device.DeviceID == deviceID {
			return device.RevokedAtMilliseconds != nil
		}
	}
	return false
}

func postgresSpaceDeviceRevoked(
	status devicesync.PrincipalStatus,
	spaceID uuid.UUID,
	deviceID uuid.UUID,
) bool {
	for _, space := range status.Spaces {
		if space.SpaceID != spaceID {
			continue
		}
		for _, device := range space.Devices {
			if device.DeviceID == deviceID {
				return device.RevokedAtMilliseconds != nil
			}
		}
	}
	return false
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
