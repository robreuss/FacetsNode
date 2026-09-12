package devicesync_test

import (
	"reflect"
	"testing"

	"github.com/robreuss/FacetsNode/internal/devicesync"
	"github.com/robreuss/FacetsNode/internal/relay"
)

func TestSelfHostedDefaultUsesSharedCapacityAndHostedLimitsRemainExplicit(t *testing.T) {
	shared := devicesync.DefaultServiceEntitlement()
	if err := shared.Validate(); err != nil || !shared.TenantQuota.UsesSharedCapacity() {
		t.Fatal(shared, err)
	}
	input := devicesync.PrincipalProvisioning{ControlDomain: relay.DomainProvisioning{Registration: relay.DomainRegistration{
		MaximumMessageCount: 100, MaximumMessageByteCount: 1 << 30, MaximumBlobCount: 100, MaximumBlobByteCount: 1 << 30,
	}}}
	applied := shared.Apply(input)
	if !applied.Tenant.UsesSharedCapacity() || !applied.ControlDomain.Registration.UsesSharedCapacity() {
		t.Fatal("self-hosted default imposed an allocation")
	}
	hosted := shared
	hosted.PlanID = "hosted-plus"
	if err := hosted.Validate(); err == nil {
		t.Fatal("hosted unlimited entitlement accepted")
	}
	hosted.TenantQuota = relay.TenantQuota{MaximumDomainCount: 10, MaximumAggregateMessageCount: 10,
		MaximumAggregateMessageByteCount: 1 << 30, MaximumAggregateBlobCount: 10, MaximumAggregateBlobByteCount: 1 << 30}
	if err := hosted.Validate(); err != nil {
		t.Fatal(err)
	}
	applied = hosted.Apply(input)
	if applied.Tenant.UsesSharedCapacity() || !reflect.DeepEqual(applied.ControlDomain, input.ControlDomain) {
		t.Fatal("explicit hosted limits were erased")
	}
	hosted.TenantQuota.MaximumAggregateBlobCount = 0
	if err := hosted.Validate(); err == nil {
		t.Fatal("partial quota accepted")
	}
}
