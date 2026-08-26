package sharedspaces

import (
	"context"
	"encoding/hex"
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

type AuthorityBoundStore interface {
	ProvisionSpaceWithAuthority(
		context.Context,
		SpaceProvisioning,
		*InitialServiceAuthorityBinding,
		int64,
	) (SpaceProvisioningResult, error)
	ActivateBoundSharedSpaceScope(
		context.Context,
		uuid.UUID,
		uuid.UUID,
		uint64,
		string,
		int64,
	) error
}

var ErrInitialServiceAuthorityConflict = errors.New(
	"initial Shared Space service authority conflicts with committed authority",
)

func ValidServiceAuthorityDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == value
}
