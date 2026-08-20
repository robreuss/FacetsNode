package devicesync

import (
	"strings"

	"github.com/robreuss/FacetsNode/internal/relay"
)

// ServiceEntitlement is the service-issued, durable commercial and capacity
// boundary for one Device Sync principal. It is created only by an operator or
// a hosted admission service; a bootstrap claimant cannot select or enlarge
// its limits. It contains no content, content key, Space name, or user-facing
// identity material.
//
// PlanID is deliberately an opaque service label at this layer. The billing
// ledger will eventually own product catalogues and subscription state, while
// Device Sync needs only this immutable quota snapshot to make an admission
// deterministic and retry-safe.
type ServiceEntitlement struct {
	Version     int               `json:"version"`
	PlanID      string            `json:"planID"`
	TenantQuota relay.TenantQuota `json:"tenantQuota"`
}

func DefaultServiceEntitlement() ServiceEntitlement {
	return ServiceEntitlement{
		Version: SchemaVersion,
		PlanID:  "self-hosted",
		TenantQuota: relay.TenantQuota{
			MaximumDomainCount:               relay.DefaultMaximumDomainCountPerTenant,
			MaximumAggregateMessageCount:     relay.DefaultMaximumMessageCountPerTenant,
			MaximumAggregateMessageByteCount: relay.DefaultMaximumMessageBytesPerTenant,
			MaximumAggregateBlobCount:        relay.DefaultMaximumBlobCountPerTenant,
			MaximumAggregateBlobByteCount:    relay.DefaultMaximumBlobBytesPerTenant,
		},
	}
}

func (e ServiceEntitlement) Validate() error {
	if e.Version != SchemaVersion || !validServicePlanID(e.PlanID) ||
		e.TenantQuota.MaximumDomainCount <= 0 ||
		e.TenantQuota.MaximumAggregateMessageCount <= 0 ||
		e.TenantQuota.MaximumAggregateMessageByteCount <= 0 ||
		e.TenantQuota.MaximumAggregateBlobCount <= 0 ||
		e.TenantQuota.MaximumAggregateBlobByteCount <= 0 {
		return NewProtocolError(CodeInvalidAdmission, "Device Sync service entitlement is invalid")
	}
	return nil
}

func validServicePlanID(value string) bool {
	if len(value) == 0 || len(value) > 64 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '-' || character == '_' || character == '.') {
			return false
		}
	}
	return true
}

func (a AccountAdmission) EffectiveServiceEntitlement() ServiceEntitlement {
	if a.Entitlement == (ServiceEntitlement{}) {
		return DefaultServiceEntitlement()
	}
	return a.Entitlement
}

func (a AccountAdmission) WithEffectiveServiceEntitlement() AccountAdmission {
	a.Entitlement = a.EffectiveServiceEntitlement()
	return a
}

func (e ServiceEntitlement) Apply(provisioning PrincipalProvisioning) PrincipalProvisioning {
	provisioning.Tenant.MaximumDomainCount = e.TenantQuota.MaximumDomainCount
	provisioning.Tenant.MaximumAggregateMessageCount = e.TenantQuota.MaximumAggregateMessageCount
	provisioning.Tenant.MaximumAggregateMessageByteCount = e.TenantQuota.MaximumAggregateMessageByteCount
	provisioning.Tenant.MaximumAggregateBlobCount = e.TenantQuota.MaximumAggregateBlobCount
	provisioning.Tenant.MaximumAggregateBlobByteCount = e.TenantQuota.MaximumAggregateBlobByteCount
	return provisioning
}
