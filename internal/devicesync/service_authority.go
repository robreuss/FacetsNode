package devicesync

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

type InitialServiceAuthorityBinding = serviceauthority.InitialBinding

func NewInitialServiceAuthorityBinding(
	enrollment serviceauthority.InitialEnrollment,
	localSigner *serviceauthority.DeploymentSigner,
	expectedScope serviceauthority.Scope,
	nowMilliseconds int64,
) (*InitialServiceAuthorityBinding, error) {
	return serviceauthority.NewInitialBinding(
		enrollment, localSigner, expectedScope, nowMilliseconds,
	)
}

func InitialServiceAuthorityBindingsEqual(
	left *InitialServiceAuthorityBinding,
	right *InitialServiceAuthorityBinding,
) bool {
	return serviceauthority.InitialBindingsEqual(left, right)
}

type AuthorityBoundAccountStore interface {
	ClaimAccountAdmissionWithAuthority(
		context.Context,
		AdmissionCredential,
		PrincipalProvisioning,
		*InitialServiceAuthorityBinding,
		int64,
	) (PrincipalProvisioningResult, error)
	ActivateBoundDeviceSyncScope(
		context.Context,
		uuid.UUID,
		uuid.UUID,
		uint64,
		string,
		int64,
	) error
}

var ErrInitialServiceAuthorityConflict = errors.New(
	"initial Device Sync service authority conflicts with committed authority",
)
