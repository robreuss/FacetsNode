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
	PublishEnvelope(context.Context, relay.Credential, relay.Envelope, int64) (relay.PublishResult, error)
	StageCheckpoint(context.Context, relay.Credential, relay.CheckpointCandidate, int64) (relay.CheckpointStageResponse, error)
	ActivateCheckpoint(context.Context, relay.AdministrationCredential, relay.CheckpointActivationRequest, int64) (relay.CheckpointActivationResponse, error)
}
