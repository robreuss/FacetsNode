package devicesync_test

import (
	"context"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/devicesync"
	"github.com/robreuss/FacetsNode/internal/relay"
)

func TestMemorySpaceReadmissionReplacesOnlyInactiveTransport(t *testing.T) {
	for _, inactive := range []relay.SubscriptionStatus{relay.SubscriptionRevoked, relay.SubscriptionRebootstrapRequired} {
		t.Run(string(inactive), func(t *testing.T) {
			ctx := context.Background()
			r := relay.NewMemoryStore()
			s := devicesync.NewMemoryStore(r)
			principal := bootstrapMemoryPrincipal(t, s, 3000)
			device := enrollMemoryDevice(t, s, principal, 3200)
			tenant, space := testSpaceProvisioning(t, principal, 3400)
			if _, err := s.ProvisionSpace(ctx, tenant, space, 3400); err != nil {
				t.Fatal(err)
			}
			admin := relay.AdministrationCredential{TenantID: space.PrincipalID, DomainID: space.Domain.Registration.DomainID, Token: testToken(0x41)}
			oldCredential, oldAdmission := testSpaceDeviceAdmission(t, space, device, 3500)
			oldClaim := readmissionClaim(t, space, device, 0x74, 3600)
			if _, err := s.CreateSpaceDeviceAdmission(ctx, admin, oldAdmission, 3500); err != nil {
				t.Fatal(err)
			}
			if _, err := s.ClaimSpaceDeviceAdmission(ctx, oldCredential, oldClaim, 3600); err != nil {
				t.Fatal(err)
			}
			badCredential := oldCredential
			badCredential.Token = testToken(0x99)
			if _, err := s.ClaimSpaceDeviceAdmission(ctx, badCredential, oldClaim, 3600); err == nil {
				t.Fatal("claimed retry bypassed bearer authentication")
			}

			newCredential, newAdmission := testSpaceDeviceAdmission(t, space, device, 3800)
			if _, err := s.CreateSpaceDeviceAdmission(ctx, admin, newAdmission, 3800); !devicesync.ErrorHasCode(err, devicesync.CodeDeviceCollision) {
				t.Fatalf("active collision=%v", err)
			}
			if _, err := r.ChangeSubscriptionStatus(ctx, admin, oldAdmission.SubscriptionID, relay.SubscriptionStatusChangeRequest{RetryID: uuid.New(), Status: inactive, ChangedAtMilliseconds: 3700}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.ClaimSpaceDeviceAdmission(ctx, oldCredential, oldClaim, 3600); err == nil {
				t.Fatal("inactive exact claim replay accepted")
			}
			if _, err := s.CreateSpaceDeviceAdmission(ctx, admin, newAdmission, 3800); err != nil {
				t.Fatal(err)
			}
			newClaim := readmissionClaim(t, space, device, 0x75, 3900)
			reusedToken := newClaim
			reusedToken.RelayClaim.AuthorizationDigest = oldClaim.RelayClaim.AuthorizationDigest
			if _, err := s.ClaimSpaceDeviceAdmission(ctx, newCredential, reusedToken, 3900); !relay.ErrorHasCode(err, relay.CodeMemberCollision) {
				t.Fatalf("old transport bearer reused=%v", err)
			}
			renewed, err := s.ClaimSpaceDeviceAdmission(ctx, newCredential, newClaim, 3900)
			if err != nil || renewed.Acceptance != relay.AcceptanceAccepted || renewed.Member.SubscriptionID != newAdmission.SubscriptionID {
				t.Fatalf("renew=%+v err=%v", renewed, err)
			}
			if _, err := s.ClaimSpaceDeviceAdmission(ctx, oldCredential, oldClaim, 3600); err == nil {
				t.Fatal("superseded claim replay accepted")
			}
			duplicate, err := s.ClaimSpaceDeviceAdmission(ctx, newCredential, newClaim, 3900)
			if err != nil || duplicate.Acceptance != relay.AcceptanceDuplicate || duplicate.Member.SubscriptionID != newAdmission.SubscriptionID {
				t.Fatalf("current retry=%+v err=%v", duplicate, err)
			}
			old, err := r.GetSubscription(ctx, admin, oldAdmission.SubscriptionID)
			if err != nil || old.Status != inactive {
				t.Fatalf("old subscription revived: %+v err=%v", old, err)
			}
			status, err := s.GetPrincipalStatus(ctx, tenant)
			if err != nil || len(status.Spaces) != 1 || len(status.Spaces[0].Devices) != 2 {
				t.Fatalf("status duplicates history: %+v err=%v", status, err)
			}
			for _, d := range status.Spaces[0].Devices {
				if d.DeviceID == device && d.SubscriptionID != newAdmission.SubscriptionID {
					t.Fatalf("status points to superseded subscription: %+v", d)
				}
			}
			revoked, err := s.RevokeDevice(ctx, tenant, devicesync.DeviceRevocation{Version: devicesync.SchemaVersion, RetryID: uuid.New(), PrincipalID: space.PrincipalID, DeviceID: device}, 4000)
			if err != nil || len(revoked.Memberships) != 2 {
				t.Fatalf("revoke renewed current mapping=%+v err=%v", revoked, err)
			}
			if _, err := s.ClaimSpaceDeviceAdmission(ctx, newCredential, newClaim, 3900); !devicesync.ErrorHasCode(err, devicesync.CodeUnauthorized) {
				t.Fatalf("revoked group retry=%v", err)
			}
		})
	}
}

func TestMemorySpaceReadmissionFirstWinnerAndRevokedGroup(t *testing.T) {
	ctx := context.Background()
	r := relay.NewMemoryStore()
	s := devicesync.NewMemoryStore(r)
	principal := bootstrapMemoryPrincipal(t, s, 3000)
	device := enrollMemoryDevice(t, s, principal, 3200)
	tenant, space := testSpaceProvisioning(t, principal, 3400)
	if _, err := s.ProvisionSpace(ctx, tenant, space, 3400); err != nil {
		t.Fatal(err)
	}
	admin := relay.AdministrationCredential{TenantID: space.PrincipalID, DomainID: space.Domain.Registration.DomainID, Token: testToken(0x41)}
	oldCredential, oldAdmission := testSpaceDeviceAdmission(t, space, device, 3500)
	if _, err := s.CreateSpaceDeviceAdmission(ctx, admin, oldAdmission, 3500); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimSpaceDeviceAdmission(ctx, oldCredential, readmissionClaim(t, space, device, 0x74, 3600), 3600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ChangeSubscriptionStatus(ctx, admin, oldAdmission.SubscriptionID, relay.SubscriptionStatusChangeRequest{RetryID: uuid.New(), Status: relay.SubscriptionRevoked, ChangedAtMilliseconds: 3700}); err != nil {
		t.Fatal(err)
	}
	credentials := make([]devicesync.SpaceDeviceAdmissionCredential, 2)
	admissions := make([]devicesync.SpaceDeviceAdmission, 2)
	for i := range credentials {
		credentials[i], admissions[i] = testSpaceDeviceAdmission(t, space, device, 3800)
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
				t.Fatal("two concurrent admissions won")
			}
			winner = i
		} else if !devicesync.ErrorHasCode(err, devicesync.CodeDeviceCollision) {
			t.Fatal(err)
		}
	}
	if winner < 0 {
		t.Fatal("neither admission won")
	}
	claims := []devicesync.SpaceDeviceAdmissionClaim{readmissionClaim(t, space, device, 0x75, 3900), readmissionClaim(t, space, device, 0x76, 3900)}
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
				t.Fatal("two different transport claims won")
			}
			claimWinner = i
		} else if !devicesync.ErrorHasCode(err, devicesync.CodeAdmissionClaimed) {
			t.Fatal(err)
		}
	}
	if claimWinner < 0 {
		t.Fatal("neither claim won")
	}
	if duplicate, err := s.ClaimSpaceDeviceAdmission(ctx, credentials[winner], claims[claimWinner], 3900); err != nil || duplicate.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("winner replay=%+v err=%v", duplicate, err)
	}
	if _, err := r.ChangeSubscriptionStatus(ctx, admin, admissions[winner].SubscriptionID, relay.SubscriptionStatusChangeRequest{RetryID: uuid.New(), Status: relay.SubscriptionRevoked, ChangedAtMilliseconds: 4000}); err != nil {
		t.Fatal(err)
	}
	pendingCredential, pending := testSpaceDeviceAdmission(t, space, device, 4100)
	if _, err := s.CreateSpaceDeviceAdmission(ctx, admin, pending, 4100); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RevokeDevice(ctx, tenant, devicesync.DeviceRevocation{Version: devicesync.SchemaVersion, RetryID: uuid.New(), PrincipalID: space.PrincipalID, DeviceID: device}, 4200); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimSpaceDeviceAdmission(ctx, pendingCredential, readmissionClaim(t, space, device, 0x77, 4300), 4300); !devicesync.ErrorHasCode(err, devicesync.CodeUnauthorized) {
		t.Fatalf("group revoked between preparation and claim=%v", err)
	}
	_, another := testSpaceDeviceAdmission(t, space, device, 4400)
	if _, err := s.CreateSpaceDeviceAdmission(ctx, admin, another, 4400); !devicesync.ErrorHasCode(err, devicesync.CodeUnauthorized) {
		t.Fatalf("revoked group creates admission=%v", err)
	}
}

func readmissionClaim(t *testing.T, space devicesync.SpaceProvisioning, device uuid.UUID, token byte, now int64) devicesync.SpaceDeviceAdmissionClaim {
	t.Helper()
	return devicesync.SpaceDeviceAdmissionClaim{Version: devicesync.SchemaVersion, PrincipalID: space.PrincipalID, SpaceID: space.SpaceID, DeviceID: device,
		RelayClaim: relay.MemberAdmissionClaim{MemberID: device, AuthorizationDigest: testDigest(t, relay.Credential{TenantID: space.PrincipalID, DomainID: space.Domain.Registration.DomainID, MemberID: device, Token: testToken(token)})}, ClaimedAtMilliseconds: now}
}

func TestMemorySpacePendingCancellationAllowsOnlyFreshFirstWinner(t *testing.T) {
	for _, inactive := range []relay.SubscriptionStatus{relay.SubscriptionRevoked, relay.SubscriptionRebootstrapRequired} {
		t.Run(string(inactive), func(t *testing.T) {
			ctx := context.Background()
			r := relay.NewMemoryStore()
			s := devicesync.NewMemoryStore(r)
			principal := bootstrapMemoryPrincipal(t, s, 3000)
			device := enrollMemoryDevice(t, s, principal, 3200)
			tenant, space := testSpaceProvisioning(t, principal, 3400)
			if _, err := s.ProvisionSpace(ctx, tenant, space, 3400); err != nil {
				t.Fatal(err)
			}
			admin := relay.AdministrationCredential{TenantID: space.PrincipalID, DomainID: space.Domain.Registration.DomainID, Token: testToken(0x41)}
			retiredCredential, retired := testSpaceDeviceAdmission(t, space, device, 3500)
			if _, err := s.CreateSpaceDeviceAdmission(ctx, admin, retired, 3500); err != nil {
				t.Fatal(err)
			}
			_, competing := testSpaceDeviceAdmission(t, space, device, 3510)
			if _, err := s.CreateSpaceDeviceAdmission(ctx, admin, competing, 3510); !devicesync.ErrorHasCode(err, devicesync.CodeDeviceCollision) {
				t.Fatalf("active pending admission was displaced: %v", err)
			}
			if _, err := r.ChangeSubscriptionStatus(ctx, admin, retired.SubscriptionID, relay.SubscriptionStatusChangeRequest{RetryID: uuid.New(), Status: inactive, ChangedAtMilliseconds: 3520}); err != nil {
				t.Fatal(err)
			}
			wrongAdmin := admin
			wrongAdmin.Token = testToken(0x99)
			if _, err := s.CreateSpaceDeviceAdmission(ctx, wrongAdmin, competing, 3530); err == nil {
				t.Fatal("unauthenticated pending replacement accepted")
			}
			credentials := make([]devicesync.SpaceDeviceAdmissionCredential, 2)
			admissions := make([]devicesync.SpaceDeviceAdmission, 2)
			for i := range credentials {
				credentials[i], admissions[i] = testSpaceDeviceAdmission(t, space, device, 3530)
			}
			var wg sync.WaitGroup
			errors := make([]error, 2)
			for i := range admissions {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					_, errors[i] = s.CreateSpaceDeviceAdmission(ctx, admin, admissions[i], 3530)
				}(i)
			}
			wg.Wait()
			winner := -1
			for i, err := range errors {
				if err == nil {
					if winner >= 0 {
						t.Fatal("two cancelled-admission replacements won")
					}
					winner = i
				} else if !devicesync.ErrorHasCode(err, devicesync.CodeDeviceCollision) {
					t.Fatal(err)
				}
			}
			if winner < 0 {
				t.Fatal("no pending replacement won")
			}
			claim := readmissionClaim(t, space, device, 0x74, 3600)
			if _, err := s.ClaimSpaceDeviceAdmission(ctx, retiredCredential, claim, 3600); !devicesync.ErrorHasCode(err, devicesync.CodeAdmissionNotFound) {
				t.Fatalf("retired binding claim: %v", err)
			}
			if _, err := r.ClaimSubscriptionAdmission(ctx, relay.AdmissionCredential{TenantID: space.PrincipalID, DomainID: admin.DomainID, AdmissionID: retiredCredential.AdmissionID, Token: retiredCredential.Token}, claim.RelayClaim, 3600); err == nil {
				t.Fatal("retired relay admission revived")
			}
			if old, err := r.GetSubscription(ctx, admin, retired.SubscriptionID); err != nil || old.Status != inactive {
				t.Fatalf("retired subscription tombstone=%+v err=%v", old, err)
			}
			if _, err := s.CreateSpaceDeviceAdmission(ctx, admin, retired, 3600); err == nil {
				t.Fatal("old retry revived retired binding")
			}
			result, err := s.ClaimSpaceDeviceAdmission(ctx, credentials[winner], claim, 3600)
			if err != nil || result.Member.SubscriptionID != admissions[winner].SubscriptionID {
				t.Fatalf("replacement claim=%+v err=%v", result, err)
			}
		})
	}
}
