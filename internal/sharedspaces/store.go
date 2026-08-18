package sharedspaces

import (
	"context"

	"github.com/robreuss/FacetsNode/internal/relay"
)

type Store interface {
	ProvisionSpace(context.Context, SpaceProvisioning, int64) (SpaceProvisioningResult, error)
	CreateInvitation(context.Context, relay.AdministrationCredential, Invitation, int64) (InvitationCreateResult, error)
	ClaimInvitation(context.Context, InvitationCredential, InvitationClaim, int64) (InvitationClaimResult, error)
	GetSpaceStatus(context.Context, relay.AdministrationCredential) (SpaceStatus, error)
	RevokeParticipant(context.Context, relay.AdministrationCredential, ParticipantRevocation, int64) (ParticipantRevocationResult, error)
}
