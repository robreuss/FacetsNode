package postgres_test

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/devicesync"
	postgresstore "github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/relay"
)

func TestPostgresParticipantSponsorshipCancellationAndTakeover(t *testing.T) {
	databaseURL := os.Getenv("FACETS_SERVER_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("FACETS_SERVER_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	lockDisposablePostgres(t, ctx, databaseURL)
	pool := openPool(t, ctx, databaseURL)
	defer pool.Close()
	if err := postgresstore.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `TRUNCATE device_sync_account_admissions, relay_tenants CASCADE`); err != nil {
		t.Fatal(err)
	}
	s := postgresstore.NewRelayStore(pool)
	fixture := loadPostgresDeviceSyncEnforcementFixture(t)
	manifest := fixture.RollbackEvidence.ActivationEvidence.Preparation.CurrentManifest
	payload, err := manifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	signer := postgresFixtureDeploymentSigner(t, payload.ActiveDeployment)
	initial := postgresInitialServiceAuthorityBinding(t, fixture, manifest, signer, 1100)
	principal, origin := payload.Scope.ScopeID, uuid.New()
	authority := postgresBootstrapDeviceSyncPrincipal(t, ctx, s, principal, origin, 1100, initial)
	if err := s.ActivateBoundDeviceSyncScope(ctx, principal, signer.DeploymentID(), initial.Revision(), initial.ManifestDigest(), 1100); err != nil {
		t.Fatal(err)
	}
	space := devicesync.SpaceProvisioning{Version: devicesync.SchemaVersion, RetryID: uuid.New(), PrincipalID: principal, SpaceID: uuid.New(), InitialDeviceID: origin,
		Domain: postgresDeviceSyncDomain(t, principal, uuid.New(), origin, uuid.New(), 3400, 31, 32), CreatedAtMilliseconds: 3400}
	if _, err := s.ProvisionSpace(ctx, authority.TenantCredential, space, 3400); err != nil {
		t.Fatal(err)
	}
	admin := relay.AdministrationCredential{TenantID: principal, DomainID: space.Domain.Registration.DomainID, Token: postgresRelayToken(31)}
	sponsorA := postgresSpaceSponsor(authority, space, admin)
	makeAttempt := func(device uuid.UUID, now int64) (devicesync.SpaceDeviceAdmissionCredential, devicesync.SpaceDeviceAdmission, devicesync.SpaceDeviceAdmissionClaim) {
		credential := relay.AdmissionCredential{TenantID: principal, DomainID: admin.DomainID, AdmissionID: uuid.New(), Token: postgresRelayToken(41)}
		digest, err := relay.AdmissionAuthorizationDigest(credential)
		if err != nil {
			t.Fatal(err)
		}
		memberDigest, err := relay.AuthorizationDigest(relay.Credential{TenantID: principal, DomainID: admin.DomainID, MemberID: device, Token: postgresRelayToken(42)})
		if err != nil {
			t.Fatal(err)
		}
		return devicesync.SpaceDeviceAdmissionCredential{PrincipalID: principal, SpaceID: space.SpaceID, AdmissionID: credential.AdmissionID, Token: credential.Token},
			devicesync.SpaceDeviceAdmission{Version: devicesync.SchemaVersion, RetryID: uuid.New(), PrincipalID: principal, SpaceID: space.SpaceID, DeviceID: device, SubscriptionID: uuid.New(), CreatedAtMilliseconds: now,
				RelayAdmission: relay.MemberAdmission{Version: relay.SchemaVersion, TenantID: principal, DomainID: admin.DomainID, AdmissionID: credential.AdmissionID, AuthorizationDigest: digest,
					Capabilities: append([]relay.Capability(nil), space.Domain.InitialMember.Capabilities...), CreatedAtMilliseconds: now, ExpiresAtMilliseconds: now + devicesync.MinimumAdmissionLifetimeMilliseconds}},
			devicesync.SpaceDeviceAdmissionClaim{Version: devicesync.SchemaVersion, PrincipalID: principal, SpaceID: space.SpaceID, DeviceID: device, ClaimedAtMilliseconds: now + 1,
				RelayClaim: relay.MemberAdmissionClaim{MemberID: device, AuthorizationDigest: memberDigest}}
	}
	makeCancellation := func(a devicesync.SpaceDeviceAdmission, sponsor uuid.UUID) devicesync.SpaceDeviceAdmissionCancellation {
		return devicesync.SpaceDeviceAdmissionCancellation{PrincipalID: principal, SpaceID: space.SpaceID, AdmissionID: a.RelayAdmission.AdmissionID, RetryID: a.RetryID, DeviceID: a.DeviceID, SponsorDeviceID: sponsor}
	}
	b := uuid.New()
	bControl, _ := postgresEnrollDeviceSyncDevice(t, ctx, s, authority, b, 3500)
	bCredential, bAdmission, bClaim := makeAttempt(b, 3600)
	if _, err := s.CreateSpaceDeviceAdmission(ctx, sponsorA, bAdmission, 3600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimSpaceDeviceAdmission(ctx, bCredential, bClaim, 3601); err != nil {
		t.Fatal(err)
	}
	sponsorB := devicesync.SpaceSponsorCredential{Administration: admin, Control: bControl,
		Space: relay.Credential{TenantID: principal, DomainID: admin.DomainID, MemberID: b, Token: postgresRelayToken(42)}}

	// An authenticated losing attempt cannot cancel another sponsor's pending
	// attempt. After its bounded lease, the replacement fences the old bearer.
	c := uuid.New()
	postgresEnrollDeviceSyncDevice(t, ctx, s, authority, c, 3700)
	oldCredential, old, oldClaim := makeAttempt(c, 3800)
	if _, err := s.CreateSpaceDeviceAdmission(ctx, sponsorA, old, 3800); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CancelSpaceDeviceAdmission(ctx, sponsorB, makeCancellation(old, b), 3900); err == nil {
		t.Fatal("cross-sponsor cancellation accepted")
	}
	_, early, _ := makeAttempt(c, 3900)
	if _, err := s.CreateSpaceDeviceAdmission(ctx, sponsorB, early, 3900); !devicesync.ErrorHasCode(err, devicesync.CodeDeviceCollision) {
		t.Fatalf("early takeover=%v", err)
	}
	takeoverAt := int64(3800) + devicesync.SpaceSponsorshipLeaseMilliseconds
	currentCredential, current, currentClaim := makeAttempt(c, takeoverAt)
	if _, err := s.CreateSpaceDeviceAdmission(ctx, sponsorB, current, takeoverAt); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimSpaceDeviceAdmission(ctx, oldCredential, oldClaim, takeoverAt+1); err == nil {
		t.Fatal("obsolete grant claimed")
	}
	if _, err := s.ClaimSpaceDeviceAdmission(ctx, currentCredential, currentClaim, takeoverAt+1); err != nil {
		t.Fatal(err)
	}
	if result, err := s.CancelSpaceDeviceAdmission(ctx, sponsorB, makeCancellation(current, b), takeoverAt+2); err != nil || result.Cancelled {
		t.Fatalf("claimed cancellation=%+v %v", result, err)
	}

	// Reopen the store before retrying a cancel-before-prepare fence.
	d := uuid.New()
	postgresEnrollDeviceSyncDevice(t, ctx, s, authority, d, takeoverAt+10)
	_, delayed, _ := makeAttempt(d, takeoverAt+11)
	cancellation := makeCancellation(delayed, b)
	if result, err := s.CancelSpaceDeviceAdmission(ctx, sponsorB, cancellation, takeoverAt+12); err != nil || !result.Cancelled {
		t.Fatalf("cancellation=%+v %v", result, err)
	}
	reopened := postgresstore.NewRelayStore(pool)
	if result, err := reopened.CancelSpaceDeviceAdmission(ctx, sponsorB, cancellation, takeoverAt+13); err != nil || !result.Cancelled {
		t.Fatalf("reopened cancellation=%+v %v", result, err)
	}
	if _, err := reopened.CreateSpaceDeviceAdmission(ctx, sponsorB, delayed, takeoverAt+14); err == nil {
		t.Fatal("reopen lost cancellation fence")
	}

	// The same target cannot be both cancelled and successfully claimed, even
	// when the operations use separate SQL transactions and connections.
	for i := 0; i < 10; i++ {
		device := uuid.New()
		now := takeoverAt + 100 + int64(i)*10
		postgresEnrollDeviceSyncDevice(t, ctx, s, authority, device, now)
		credential, admission, claim := makeAttempt(device, now+1)
		if _, err := s.CreateSpaceDeviceAdmission(ctx, sponsorB, admission, now+1); err != nil {
			t.Fatal(err)
		}
		request := makeCancellation(admission, b)
		var wg sync.WaitGroup
		var claimErr, cancelErr error
		var result devicesync.SpaceDeviceAdmissionCancellationResult
		wg.Add(2)
		go func() { defer wg.Done(); _, claimErr = s.ClaimSpaceDeviceAdmission(ctx, credential, claim, now+2) }()
		go func() {
			defer wg.Done()
			result, cancelErr = reopened.CancelSpaceDeviceAdmission(ctx, sponsorB, request, now+2)
		}()
		wg.Wait()
		if cancelErr != nil || result.Cancelled == (claimErr == nil) {
			t.Fatalf("claim=%v cancel=%+v %v", claimErr, result, cancelErr)
		}
	}
}
