package devicesync

import (
	"context"

	"github.com/robreuss/FacetsNode/internal/relay"
)

type Store interface {
	CreateAccountAdmission(context.Context, AccountAdmission, int64) (AdmissionCreateResult, error)
	ClaimAccountAdmission(context.Context, AdmissionCredential, PrincipalProvisioning, int64) (PrincipalProvisioningResult, error)
	CreateDeviceAdmission(context.Context, relay.AdministrationCredential, DeviceAdmission, int64) (DeviceAdmissionCreateResult, error)
	ClaimDeviceAdmission(context.Context, DeviceAdmissionCredential, DeviceAdmissionClaim, int64) (DeviceAdmissionClaimResult, error)
	ProvisionSpace(context.Context, relay.TenantCredential, SpaceProvisioning, int64) (SpaceProvisioningResult, error)
	CreateSpaceDeviceAdmission(context.Context, relay.AdministrationCredential, SpaceDeviceAdmission, int64) (SpaceDeviceAdmissionCreateResult, error)
	ClaimSpaceDeviceAdmission(context.Context, SpaceDeviceAdmissionCredential, SpaceDeviceAdmissionClaim, int64) (SpaceDeviceAdmissionClaimResult, error)
	GetPrincipalStatus(context.Context, relay.TenantCredential) (PrincipalStatus, error)
	RevokeDevice(context.Context, relay.TenantCredential, DeviceRevocation, int64) (DeviceRevocationResult, error)
}
