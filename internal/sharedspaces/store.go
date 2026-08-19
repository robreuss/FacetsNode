package sharedspaces

import (
	"context"

	"github.com/robreuss/FacetsNode/internal/relay"
)

type Store interface {
	ProvisionSpace(context.Context, SpaceProvisioning, int64) (SpaceProvisioningResult, error)
	CreateInvitation(context.Context, relay.AdministrationCredential, Invitation, int64) (InvitationCreateResult, error)
	ClaimInvitation(context.Context, InvitationCredential, InvitationClaim, int64) (InvitationClaimResult, error)
	CancelInvitation(context.Context, relay.AdministrationCredential, InvitationCancellation, int64) (InvitationCancellationResult, error)
	ListInvitations(context.Context, relay.AdministrationCredential, int64) (InvitationList, error)
	GetSpaceStatus(context.Context, relay.AdministrationCredential) (SpaceStatus, error)
	ListAuthorityEvents(context.Context, relay.AdministrationCredential, uint64, int) (AuthorityEventPage, error)
	ChangeParticipantRole(context.Context, relay.AdministrationCredential, ParticipantRoleChange, int64) (ParticipantRoleChangeResult, error)
	RevokeParticipant(context.Context, relay.AdministrationCredential, ParticipantRevocation, int64) (ParticipantRevocationResult, error)
	GetParticipantBootstrap(context.Context, relay.Credential, int64) (ParticipantBootstrap, error)
	GetParticipantStatus(context.Context, relay.Credential, int64) (ParticipantStatus, error)
	GetParticipantKeyGrant(context.Context, relay.Credential, int64) (ParticipantKeyGrantResult, error)
	PublishEnvelope(context.Context, relay.Credential, relay.Envelope, int64) (relay.PublishResult, error)
	StageCheckpoint(context.Context, relay.Credential, relay.CheckpointCandidate, int64) (relay.CheckpointStageResponse, error)
	ActivateCheckpoint(context.Context, relay.AdministrationCredential, relay.CheckpointActivationRequest, int64) (relay.CheckpointActivationResponse, error)
}
