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
	tenantCredential := postgresBootstrapDeviceSyncPrincipal(
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
	created, err := store.ProvisionSpace(ctx, tenantCredential, space, now)
	if err != nil || created.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("provision Space=%+v err=%v", created, err)
	}
	retry, err := store.ProvisionSpace(ctx, tenantCredential, space, now)
	if err != nil || retry.Acceptance != relay.AcceptanceDuplicate ||
		retry.Domain.DomainID != created.Domain.DomainID {
		t.Fatalf("retry Space=%+v err=%v", retry, err)
	}
	var bindingCount, domainCount int
	if err := pool.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM device_sync_spaces
			 WHERE principal_id=$1 AND space_id=$2 AND domain_id=$3),
			(SELECT count(*) FROM relay_domains
			 WHERE tenant_id=$1 AND domain_id=$3)
	`, principalID, spaceID, space.Domain.Registration.DomainID).Scan(
		&bindingCount, &domainCount,
	); err != nil {
		t.Fatal(err)
	}
	if bindingCount != 1 || domainCount != 1 {
		t.Fatalf("binding count=%d domain count=%d", bindingCount, domainCount)
	}

	collision := space
	collision.SpaceID = uuid.New()
	if _, err := store.ProvisionSpace(ctx, tenantCredential, collision, now); !devicesync.ErrorHasCode(err, devicesync.CodeSpaceCollision) {
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
		ctx, tenantCredential, orphan.Domain, now,
	); err != nil || provisioned.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("pre-provision relay domain=%+v err=%v", provisioned, err)
	}
	if _, err := store.ProvisionSpace(ctx, tenantCredential, orphan, now); !devicesync.ErrorHasCode(err, devicesync.CodeSpaceCollision) {
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

func postgresBootstrapDeviceSyncPrincipal(
	t *testing.T,
	ctx context.Context,
	store *postgresstore.RelayStore,
	principalID uuid.UUID,
	initialDeviceID uuid.UUID,
	now int64,
) relay.TenantCredential {
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
	return tenantCredential
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
