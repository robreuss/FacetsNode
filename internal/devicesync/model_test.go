package devicesync_test

import (
	"encoding/base64"
	"testing"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/devicesync"
	"github.com/robreuss/FacetsNode/internal/relay"
)

func TestAdmissionAuthorizationDigestIsScopedAndStrict(t *testing.T) {
	token := testToken(0x41)
	left := devicesync.AdmissionCredential{AdmissionID: uuid.New(), Token: token}
	right := devicesync.AdmissionCredential{AdmissionID: uuid.New(), Token: token}
	leftDigest, err := devicesync.AdmissionAuthorizationDigest(left)
	if err != nil {
		t.Fatal(err)
	}
	rightDigest, err := devicesync.AdmissionAuthorizationDigest(right)
	if err != nil {
		t.Fatal(err)
	}
	if leftDigest == rightDigest {
		t.Fatal("admission digest did not bind the admission scope")
	}
	if _, err := devicesync.AdmissionAuthorizationDigest(devicesync.AdmissionCredential{
		AdmissionID: left.AdmissionID, Token: base64.RawURLEncoding.EncodeToString(make([]byte, 31)),
	}); err == nil {
		t.Fatal("short admission token was accepted")
	}
}

func TestAccountAdmissionRejectsPartialClaimState(t *testing.T) {
	credential := devicesync.AdmissionCredential{AdmissionID: uuid.New(), Token: testToken(0x42)}
	digest, err := devicesync.AdmissionAuthorizationDigest(credential)
	if err != nil {
		t.Fatal(err)
	}
	claimedAt := int64(1_500)
	admission := devicesync.AccountAdmission{
		Version: devicesync.SchemaVersion, RetryID: uuid.New(), AdmissionID: credential.AdmissionID,
		AuthorizationDigest: digest, CreatedAtMilliseconds: 1_000,
		ExpiresAtMilliseconds: 1_000 + devicesync.MinimumAdmissionLifetimeMilliseconds,
		ClaimedAtMilliseconds: &claimedAt,
	}
	if err := admission.Validate(); !devicesync.ErrorHasCode(err, devicesync.CodeInvalidAdmission) {
		t.Fatalf("partial claim err=%v", err)
	}
}

func TestAccountAdmissionDefaultsAndAppliesServiceEntitlement(t *testing.T) {
	admission := devicesync.AccountAdmission{}
	if got, want := admission.EffectiveServiceEntitlement(), devicesync.DefaultServiceEntitlement(); got != want {
		t.Fatalf("default entitlement=%+v want=%+v", got, want)
	}

	entitlement := devicesync.ServiceEntitlement{
		Version: devicesync.SchemaVersion,
		PlanID:  "hosted-plus",
		TenantQuota: relay.TenantQuota{
			MaximumDomainCount:               2,
			MaximumAggregateMessageCount:     3,
			MaximumAggregateMessageByteCount: 4,
			MaximumAggregateBlobCount:        5,
			MaximumAggregateBlobByteCount:    6,
		},
	}
	provisioning := entitlement.Apply(devicesync.PrincipalProvisioning{
		Tenant: relay.TenantRegistration{
			MaximumDomainCount:               100,
			MaximumAggregateMessageCount:     100,
			MaximumAggregateMessageByteCount: 100,
			MaximumAggregateBlobCount:        100,
			MaximumAggregateBlobByteCount:    100,
		},
	})
	if provisioning.Tenant.MaximumDomainCount != entitlement.TenantQuota.MaximumDomainCount ||
		provisioning.Tenant.MaximumAggregateMessageCount != entitlement.TenantQuota.MaximumAggregateMessageCount ||
		provisioning.Tenant.MaximumAggregateMessageByteCount != entitlement.TenantQuota.MaximumAggregateMessageByteCount ||
		provisioning.Tenant.MaximumAggregateBlobCount != entitlement.TenantQuota.MaximumAggregateBlobCount ||
		provisioning.Tenant.MaximumAggregateBlobByteCount != entitlement.TenantQuota.MaximumAggregateBlobByteCount {
		t.Fatalf("tenant registration did not receive entitlement quota: %+v", provisioning.Tenant)
	}
}

func testToken(seed byte) string {
	bytes := make([]byte, 32)
	for index := range bytes {
		bytes[index] = seed + byte(index)
	}
	return base64.RawURLEncoding.EncodeToString(bytes)
}
