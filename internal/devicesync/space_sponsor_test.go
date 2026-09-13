package devicesync_test

import (
	"context"
	"reflect"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/devicesync"
	"github.com/robreuss/FacetsNode/internal/relay"
)

func TestSpaceCancellationFencesDelayedPrepareWithoutRevokingWinner(t *testing.T) {
	for _, prepared := range []bool{false, true} {
		for _, claimed := range []bool{false, true} {
			if claimed && !prepared {
				continue
			}
			ctx := context.Background()
			r := relay.NewMemoryStore()
			s := devicesync.NewMemoryStore(r)
			p := bootstrapMemoryPrincipal(t, s, 3000)
			device := enrollMemoryDevice(t, s, p, 3200)
			tenant, space := testSpaceProvisioning(t, p, 3400)
			if _, err := s.ProvisionSpace(ctx, tenant, space, 3400); err != nil {
				t.Fatal(err)
			}
			admin := relay.AdministrationCredential{TenantID: p.PrincipalID, DomainID: space.Domain.Registration.DomainID, Token: testToken(0x41)}
			sponsor := testSpaceSponsor(p, space, admin)
			credential, admission := testSpaceDeviceAdmission(t, space, device, 3500)
			if prepared {
				if _, err := s.CreateSpaceDeviceAdmission(ctx, sponsor, admission, 3500); err != nil {
					t.Fatal(err)
				}
			}
			if claimed {
				if _, err := s.ClaimSpaceDeviceAdmission(ctx, credential, readmissionClaim(t, space, device, 0x74, 3600), 3600); err != nil {
					t.Fatal(err)
				}
			}
			cancel := devicesync.SpaceDeviceAdmissionCancellation{PrincipalID: p.PrincipalID, SpaceID: space.SpaceID, DeviceID: device,
				AdmissionID: admission.RelayAdmission.AdmissionID, RetryID: admission.RetryID, SponsorDeviceID: p.InitialDeviceID}
			for i := 0; i < 2; i++ {
				result, err := s.CancelSpaceDeviceAdmission(ctx, sponsor, cancel, 3700+int64(i))
				if err != nil || result.Cancelled == claimed {
					t.Fatalf("cancel prepared=%v claimed=%v: %+v %v", prepared, claimed, result, err)
				}
			}
			if !claimed {
				if _, err := s.CreateSpaceDeviceAdmission(ctx, sponsor, admission, 3800); err == nil {
					t.Fatal("late prepare revived cancelled work")
				}
				if _, err := s.ClaimSpaceDeviceAdmission(ctx, credential, readmissionClaim(t, space, device, 0x74, 3800), 3800); err == nil {
					t.Fatal("late claim accepted cancelled work")
				}
			} else {
				current, err := r.GetSubscription(ctx, admin, admission.SubscriptionID)
				if err != nil || current.Status != relay.SubscriptionActive {
					t.Fatalf("cancel revoked claimed membership: %+v %v", current, err)
				}
			}
		}
	}
}

func TestSpaceCancellationAndClaimHaveOneWinner(t *testing.T) {
	for i := 0; i < 20; i++ {
		ctx := context.Background()
		r := relay.NewMemoryStore()
		s := devicesync.NewMemoryStore(r)
		p := bootstrapMemoryPrincipal(t, s, 3000)
		device := enrollMemoryDevice(t, s, p, 3200)
		tenant, space := testSpaceProvisioning(t, p, 3400)
		if _, err := s.ProvisionSpace(ctx, tenant, space, 3400); err != nil {
			t.Fatal(err)
		}
		admin := relay.AdministrationCredential{TenantID: p.PrincipalID, DomainID: space.Domain.Registration.DomainID, Token: testToken(0x41)}
		sponsor := testSpaceSponsor(p, space, admin)
		credential, admission := testSpaceDeviceAdmission(t, space, device, 3500)
		if _, err := s.CreateSpaceDeviceAdmission(ctx, sponsor, admission, 3500); err != nil {
			t.Fatal(err)
		}
		cancel := devicesync.SpaceDeviceAdmissionCancellation{PrincipalID: p.PrincipalID, SpaceID: space.SpaceID, DeviceID: device,
			AdmissionID: admission.RelayAdmission.AdmissionID, RetryID: admission.RetryID, SponsorDeviceID: p.InitialDeviceID}
		claim := readmissionClaim(t, space, device, 0x74, 3600)
		var wg sync.WaitGroup
		var claimErr, cancelErr error
		var result devicesync.SpaceDeviceAdmissionCancellationResult
		wg.Add(2)
		go func() { defer wg.Done(); _, claimErr = s.ClaimSpaceDeviceAdmission(ctx, credential, claim, 3600) }()
		go func() { defer wg.Done(); result, cancelErr = s.CancelSpaceDeviceAdmission(ctx, sponsor, cancel, 3600) }()
		wg.Wait()
		if cancelErr != nil || result.Cancelled == (claimErr == nil) {
			t.Fatalf("claim=%v cancel=%+v %v", claimErr, result, cancelErr)
		}
	}
}

func TestSpaceSponsorAuthenticatesEveryCredentialBeforeExactRetry(t *testing.T) {
	ctx := context.Background()
	r := relay.NewMemoryStore()
	s := devicesync.NewMemoryStore(r)
	p := bootstrapMemoryPrincipal(t, s, 3000)
	device := enrollMemoryDevice(t, s, p, 3200)
	tenant, space := testSpaceProvisioning(t, p, 3400)
	if _, err := s.ProvisionSpace(ctx, tenant, space, 3400); err != nil {
		t.Fatal(err)
	}
	admin := relay.AdministrationCredential{TenantID: p.PrincipalID, DomainID: space.Domain.Registration.DomainID, Token: testToken(0x41)}
	sponsor := testSpaceSponsor(p, space, admin)
	_, admission := testSpaceDeviceAdmission(t, space, device, 3500)
	accepted, err := s.CreateSpaceDeviceAdmission(ctx, sponsor, admission, 3500)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"administration", "control", "space", "identity", "scope"} {
		t.Run(mutation, func(t *testing.T) {
			invalid := sponsor
			switch mutation {
			case "administration":
				invalid.Administration.Token = testToken(0x99)
			case "control":
				invalid.Control.Token = testToken(0x99)
			case "space":
				invalid.Space.Token = testToken(0x99)
			case "identity":
				invalid.Control.MemberID = device
			case "scope":
				invalid.Space.DomainID = uuid.New()
			}
			if _, err := s.CreateSpaceDeviceAdmission(ctx, invalid, admission, 3510); err == nil {
				t.Fatal("retry bypassed sponsor authentication")
			}
		})
	}
	// HTTP stamps receipt time; later retries retain the accepted timestamp.
	retry := admission
	retry.CreatedAtMilliseconds = 3600
	retry.RelayAdmission.CreatedAtMilliseconds = 3600
	duplicate, err := s.CreateSpaceDeviceAdmission(ctx, sponsor, retry, 3600)
	if err != nil || duplicate.Acceptance != relay.AcceptanceDuplicate || !reflect.DeepEqual(duplicate.Admission, accepted.Admission) {
		t.Fatalf("retry: %+v %v", duplicate, err)
	}
}

func TestReceivedParticipantSponsorsAndReadmitsOriginalDevice(t *testing.T) {
	ctx := context.Background()
	r := relay.NewMemoryStore()
	s := devicesync.NewMemoryStore(r)
	p := bootstrapMemoryPrincipal(t, s, 3000)
	b := enrollMemoryDevice(t, s, p, 3200)
	tenant, space := testSpaceProvisioning(t, p, 3400)
	if _, err := s.ProvisionSpace(ctx, tenant, space, 3400); err != nil {
		t.Fatal(err)
	}
	enrollMemoryDeviceInSpace(t, s, p, space, b, 3500)
	admin := relay.AdministrationCredential{TenantID: p.PrincipalID, DomainID: space.Domain.Registration.DomainID, Token: testToken(0x41)}
	sponsor := devicesync.SpaceSponsorCredential{Administration: admin,
		Control: relay.Credential{TenantID: p.PrincipalID, DomainID: p.ControlDomain.Registration.DomainID, MemberID: b, Token: testToken(0x71)},
		Space:   relay.Credential{TenantID: p.PrincipalID, DomainID: space.Domain.Registration.DomainID, MemberID: b, Token: testToken(0x74)}}
	c := enrollMemoryDevice(t, s, p, 3700)
	credential, admission := testSpaceDeviceAdmission(t, space, c, 3900)
	if _, err := s.CreateSpaceDeviceAdmission(ctx, sponsor, admission, 3900); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimSpaceDeviceAdmission(ctx, credential, readmissionClaim(t, space, c, 0x76, 4000), 4000); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ChangeSubscriptionStatus(ctx, admin, space.Domain.Subscription.SubscriptionID, relay.SubscriptionStatusChangeRequest{
		RetryID: uuid.New(), Status: relay.SubscriptionRevoked, ChangedAtMilliseconds: 4100}); err != nil {
		t.Fatal(err)
	}
	credential, admission = testSpaceDeviceAdmission(t, space, p.InitialDeviceID, 4200)
	if _, err := s.CreateSpaceDeviceAdmission(ctx, sponsor, admission, 4200); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimSpaceDeviceAdmission(ctx, credential, readmissionClaim(t, space, p.InitialDeviceID, 0x77, 4300), 4300); err != nil {
		t.Fatal(err)
	}
	status, err := s.GetPrincipalStatus(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, device := range status.Spaces[0].Devices {
		if device.DeviceID == p.InitialDeviceID {
			count++
			if device.SubscriptionID != admission.SubscriptionID {
				t.Fatal("stale origin binding")
			}
		}
	}
	if count != 1 {
		t.Fatalf("origin membership duplicated: %d", count)
	}
}

func TestPendingGrantRejectsSponsorCredentialRotationAndExpiredOwnershipCanBeTakenOver(t *testing.T) {
	ctx := context.Background()
	r := relay.NewMemoryStore()
	s := devicesync.NewMemoryStore(r)
	p := bootstrapMemoryPrincipal(t, s, 3000)
	b := enrollMemoryDevice(t, s, p, 3200)
	tenant, space := testSpaceProvisioning(t, p, 3400)
	if _, err := s.ProvisionSpace(ctx, tenant, space, 3400); err != nil {
		t.Fatal(err)
	}
	enrollMemoryDeviceInSpace(t, s, p, space, b, 3500)
	c := enrollMemoryDevice(t, s, p, 3700)
	admin := relay.AdministrationCredential{TenantID: p.PrincipalID, DomainID: space.Domain.Registration.DomainID, Token: testToken(0x41)}
	sponsor := testSpaceSponsor(p, space, admin)
	oldCredential, old := testSpaceDeviceAdmission(t, space, c, 3900)
	if _, err := s.CreateSpaceDeviceAdmission(ctx, sponsor, old, 3900); err != nil {
		t.Fatal(err)
	}
	rotated := sponsor.Space
	rotated.Token = testToken(0x88)
	if _, err := r.RotateMemberCredential(ctx, sponsor.Space, relay.CredentialRotation{RotationID: uuid.New(), AuthorizationDigest: testDigest(t, rotated)}, 4000); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimSpaceDeviceAdmission(ctx, oldCredential, readmissionClaim(t, space, c, 0x76, 4100), 4100); err == nil {
		t.Fatal("stale sponsor incarnation granted access")
	}
	other := devicesync.SpaceSponsorCredential{Administration: admin,
		Control: relay.Credential{TenantID: p.PrincipalID, DomainID: p.ControlDomain.Registration.DomainID, MemberID: b, Token: testToken(0x71)},
		Space:   relay.Credential{TenantID: p.PrincipalID, DomainID: space.Domain.Registration.DomainID, MemberID: b, Token: testToken(0x74)}}
	_, proposed := testSpaceDeviceAdmission(t, space, c, 4200)
	if _, err := s.CreateSpaceDeviceAdmission(ctx, other, proposed, 4200); !devicesync.ErrorHasCode(err, devicesync.CodeDeviceCollision) {
		t.Fatalf("early takeover: %v", err)
	}
	now := int64(3900 + devicesync.SpaceSponsorshipLeaseMilliseconds)
	credential, proposed := testSpaceDeviceAdmission(t, space, c, now)
	if _, err := s.CreateSpaceDeviceAdmission(ctx, other, proposed, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimSpaceDeviceAdmission(ctx, oldCredential, readmissionClaim(t, space, c, 0x76, now+1), now+1); err == nil {
		t.Fatal("retired grant survived takeover")
	}
	if _, err := s.ClaimSpaceDeviceAdmission(ctx, credential, readmissionClaim(t, space, c, 0x77, now+2), now+2); err != nil {
		t.Fatal(err)
	}
}
