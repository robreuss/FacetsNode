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

func TestPostgresSpaceReadmissionAtomicRenewalAndReplay(t *testing.T) {
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
	for _, inactive := range []relay.SubscriptionStatus{relay.SubscriptionRevoked, relay.SubscriptionRebootstrapRequired} {
		t.Run(string(inactive), func(t *testing.T) {
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
			principal, origin, device := payload.Scope.ScopeID, uuid.New(), uuid.New()
			authority := postgresBootstrapDeviceSyncPrincipal(t, ctx, s, principal, origin, 1100, initial)
			if err := s.ActivateBoundDeviceSyncScope(ctx, principal, signer.DeploymentID(), initial.Revision(), initial.ManifestDigest(), 1100); err != nil {
				t.Fatal(err)
			}
			postgresEnrollDeviceSyncDevice(t, ctx, s, authority, device, 3200)
			space := devicesync.SpaceProvisioning{Version: devicesync.SchemaVersion, RetryID: uuid.New(), PrincipalID: principal, SpaceID: uuid.New(), InitialDeviceID: origin,
				Domain: postgresDeviceSyncDomain(t, principal, uuid.New(), origin, uuid.New(), 3400, 31, 32), CreatedAtMilliseconds: 3400}
			if _, err := s.ProvisionSpace(ctx, authority.TenantCredential, space, 3400); err != nil {
				t.Fatal(err)
			}
			admin := relay.AdministrationCredential{TenantID: principal, DomainID: space.Domain.Registration.DomainID, Token: postgresRelayToken(31)}
			makeAdmission := func(now int64) (devicesync.SpaceDeviceAdmissionCredential, devicesync.SpaceDeviceAdmission) {
				c := relay.AdmissionCredential{TenantID: principal, DomainID: admin.DomainID, AdmissionID: uuid.New(), Token: postgresRelayToken(41)}
				digest, err := relay.AdmissionAuthorizationDigest(c)
				if err != nil {
					t.Fatal(err)
				}
				return devicesync.SpaceDeviceAdmissionCredential{PrincipalID: principal, SpaceID: space.SpaceID, AdmissionID: c.AdmissionID, Token: c.Token},
					devicesync.SpaceDeviceAdmission{Version: devicesync.SchemaVersion, RetryID: uuid.New(), PrincipalID: principal, SpaceID: space.SpaceID, DeviceID: device, SubscriptionID: uuid.New(), CreatedAtMilliseconds: now,
						RelayAdmission: relay.MemberAdmission{Version: relay.SchemaVersion, TenantID: principal, DomainID: admin.DomainID, AdmissionID: c.AdmissionID, AuthorizationDigest: digest,
							Capabilities: append([]relay.Capability(nil), space.Domain.InitialMember.Capabilities...), CreatedAtMilliseconds: now, ExpiresAtMilliseconds: now + devicesync.MinimumAdmissionLifetimeMilliseconds}}
			}
			makeClaim := func(now int64, token byte) devicesync.SpaceDeviceAdmissionClaim {
				digest, err := relay.AuthorizationDigest(relay.Credential{TenantID: principal, DomainID: admin.DomainID, MemberID: device, Token: postgresRelayToken(token)})
				if err != nil {
					t.Fatal(err)
				}
				return devicesync.SpaceDeviceAdmissionClaim{Version: devicesync.SchemaVersion, PrincipalID: principal, SpaceID: space.SpaceID, DeviceID: device, ClaimedAtMilliseconds: now,
					RelayClaim: relay.MemberAdmissionClaim{MemberID: device, AuthorizationDigest: digest}}
			}
			oldCredential, oldAdmission := makeAdmission(3500)
			oldClaim := makeClaim(3600, 42)
			if _, err := s.CreateSpaceDeviceAdmission(ctx, admin, oldAdmission, 3500); err != nil {
				t.Fatal(err)
			}
			if _, err := s.ClaimSpaceDeviceAdmission(ctx, oldCredential, oldClaim, 3600); err != nil {
				t.Fatal(err)
			}
			_, activeCollision := makeAdmission(3650)
			if _, err := s.CreateSpaceDeviceAdmission(ctx, admin, activeCollision, 3650); !devicesync.ErrorHasCode(err, devicesync.CodeDeviceCollision) {
				t.Fatalf("active collision=%v", err)
			}
			if _, err := s.ChangeSubscriptionStatus(ctx, admin, oldAdmission.SubscriptionID, relay.SubscriptionStatusChangeRequest{RetryID: uuid.New(), Status: inactive, ChangedAtMilliseconds: 3700}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.ClaimSpaceDeviceAdmission(ctx, oldCredential, oldClaim, 3600); err == nil {
				t.Fatal("inactive old claim replay accepted")
			}
			credentials := make([]devicesync.SpaceDeviceAdmissionCredential, 2)
			admissions := make([]devicesync.SpaceDeviceAdmission, 2)
			for i := range credentials {
				credentials[i], admissions[i] = makeAdmission(3800)
			}
			var wg sync.WaitGroup
			errors := make([]error, 2)
			for i := range credentials {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					_, errors[i] = s.CreateSpaceDeviceAdmission(ctx, admin, admissions[i], 3800)
				}(i)
			}
			wg.Wait()
			winner := -1
			for i, err := range errors {
				if err == nil {
					if winner >= 0 {
						t.Fatal("two pending admission winners")
					}
					winner = i
				} else if !devicesync.ErrorHasCode(err, devicesync.CodeDeviceCollision) {
					t.Fatal(err)
				}
			}
			if winner < 0 {
				t.Fatal("no admission winner")
			}
			if _, err := s.ClaimSpaceDeviceAdmission(ctx, credentials[winner], makeClaim(3900, 42), 3900); !relay.ErrorHasCode(err, relay.CodeMemberCollision) {
				t.Fatalf("old bearer reused=%v", err)
			}
			claims := []devicesync.SpaceDeviceAdmissionClaim{makeClaim(3900, 43), makeClaim(3900, 44)}
			for i := range claims {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					_, errors[i] = s.ClaimSpaceDeviceAdmission(ctx, credentials[winner], claims[i], 3900)
				}(i)
			}
			wg.Wait()
			claimWinner := -1
			for i, err := range errors {
				if err == nil {
					if claimWinner >= 0 {
						t.Fatal("two different claims won")
					}
					claimWinner = i
				} else if !relay.ErrorHasCode(err, relay.CodeAdmissionClaimed) {
					t.Fatal(err)
				}
			}
			if claimWinner < 0 {
				t.Fatal("no claim winner")
			}
			duplicate, err := s.ClaimSpaceDeviceAdmission(ctx, credentials[winner], claims[claimWinner], 3900)
			if err != nil || duplicate.Acceptance != relay.AcceptanceDuplicate || duplicate.Member.SubscriptionID != admissions[winner].SubscriptionID {
				t.Fatalf("duplicate=%+v err=%v", duplicate, err)
			}
			if _, err := s.ClaimSpaceDeviceAdmission(ctx, oldCredential, oldClaim, 3600); err == nil {
				t.Fatal("superseded claim replay accepted")
			}
			oldSub, err := s.GetSubscription(ctx, admin, oldAdmission.SubscriptionID)
			if err != nil || oldSub.Status != inactive {
				t.Fatalf("old subscription revived=%+v err=%v", oldSub, err)
			}
			var current, relayCurrent uuid.UUID
			if err := pool.QueryRow(ctx, `SELECT d.subscription_id,m.subscription_id FROM device_sync_space_devices d JOIN relay_members m
				 ON m.tenant_id=d.principal_id AND m.domain_id=d.domain_id AND m.member_id=d.member_id
				 WHERE d.principal_id=$1 AND d.space_id=$2 AND d.device_id=$3`, principal, space.SpaceID, device).Scan(&current, &relayCurrent); err != nil {
				t.Fatal(err)
			}
			if current != admissions[winner].SubscriptionID || relayCurrent != current {
				t.Fatalf("binding mismatch current=%s relay=%s", current, relayCurrent)
			}
			if _, err := s.ChangeSubscriptionStatus(ctx, admin, current, relay.SubscriptionStatusChangeRequest{RetryID: uuid.New(), Status: relay.SubscriptionRevoked, ChangedAtMilliseconds: 4000}); err != nil {
				t.Fatal(err)
			}
			pendingCredential, pending := makeAdmission(4100)
			if _, err := s.CreateSpaceDeviceAdmission(ctx, admin, pending, 4100); err != nil {
				t.Fatal(err)
			}
			if _, err := s.RevokeDevice(ctx, authority.TenantCredential, devicesync.DeviceRevocation{Version: devicesync.SchemaVersion, RetryID: uuid.New(), PrincipalID: principal, DeviceID: device}, 4200); err != nil {
				t.Fatal(err)
			}
			if _, err := s.ClaimSpaceDeviceAdmission(ctx, pendingCredential, makeClaim(4300, 45), 4300); !devicesync.ErrorHasCode(err, devicesync.CodeUnauthorized) {
				t.Fatalf("revoked group claim=%v", err)
			}
			_, another := makeAdmission(4400)
			if _, err := s.CreateSpaceDeviceAdmission(ctx, admin, another, 4400); !devicesync.ErrorHasCode(err, devicesync.CodeUnauthorized) {
				t.Fatalf("revoked group admission=%v", err)
			}
			var claimed *int64
			if err := pool.QueryRow(ctx, `SELECT claimed_at_milliseconds FROM relay_member_admissions WHERE tenant_id=$1 AND domain_id=$2 AND admission_id=$3`, principal, admin.DomainID, pendingCredential.AdmissionID).Scan(&claimed); err != nil {
				t.Fatal(err)
			}
			if claimed != nil {
				t.Fatal("rejected group claim partially mutated relay admission")
			}
		})
	}
}
