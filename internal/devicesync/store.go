package devicesync

import "context"

type Store interface {
	CreateAccountAdmission(context.Context, AccountAdmission, int64) (AdmissionCreateResult, error)
	ClaimAccountAdmission(context.Context, AdmissionCredential, PrincipalProvisioning, int64) (PrincipalProvisioningResult, error)
}
