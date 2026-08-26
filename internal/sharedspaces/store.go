package sharedspaces

import (
	"context"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/relay"
)

type Store interface {
	CreateProvisioningAdmission(context.Context, ProvisioningAdmission, int64) (ProvisioningAdmissionCreateResult, error)
	ClaimProvisioningAdmission(context.Context, ProvisioningAdmissionCredential, ProvisioningAdmissionClaim, int64) (ProvisioningAdmissionClaimResult, error)
	ProvisionSpace(context.Context, SpaceProvisioning, int64) (SpaceProvisioningResult, error)
	CreateInvitation(context.Context, relay.AdministrationCredential, Invitation, int64) (InvitationCreateResult, error)
	ClaimInvitation(context.Context, InvitationCredential, InvitationClaim, int64) (InvitationClaimResult, error)
	CancelInvitation(context.Context, relay.AdministrationCredential, InvitationCancellation, int64) (InvitationCancellationResult, error)
	ListInvitations(context.Context, relay.AdministrationCredential, int64) (InvitationList, error)
	GetSpaceStatus(context.Context, relay.AdministrationCredential) (SpaceStatus, error)
	ListAuthorityEvents(context.Context, relay.AdministrationCredential, uint64, int) (AuthorityEventPage, error)
	ChangeParticipantRole(context.Context, relay.AdministrationCredential, ParticipantRoleChange, int64) (ParticipantRoleChangeResult, error)
	EnrollParticipantDevice(context.Context, relay.AdministrationCredential, ParticipantDeviceEnrollment, int64) (ParticipantDeviceEnrollmentResult, error)
	RevokeParticipantDevice(context.Context, relay.AdministrationCredential, ParticipantDeviceRevocation, int64) (ParticipantDeviceRevocationResult, error)
	RevokeParticipant(context.Context, relay.AdministrationCredential, ParticipantRevocation, int64) (ParticipantRevocationResult, error)
	GetParticipantBootstrap(context.Context, relay.Credential, uuid.UUID, int64) (ParticipantBootstrap, error)
	GetParticipantStatus(context.Context, relay.Credential, int64) (ParticipantStatus, error)
	GetParticipantRoster(context.Context, relay.Credential, int64) (ParticipantRoster, error)
	ListSecureRosterAttestations(context.Context, relay.Credential, uint64, int, int64) (SecureRosterAttestationPage, error)
	UpdateParticipantPresentation(context.Context, relay.Credential, ParticipantPresentationUpdate, int64) (ParticipantPresentationUpdateResult, error)
	ChangeComputeBinding(context.Context, relay.AdministrationCredential, SpaceComputeBindingChange, int64) (SpaceComputeBindingChangeResult, error)
	AuthorizeComputeCapability(context.Context, relay.Credential, ComputeCapabilityRequest, int64) (ComputeCapabilityAuthorization, error)
	GetParticipantKeyGrant(context.Context, relay.Credential, uuid.UUID, int64) (ParticipantKeyGrantResult, error)
	PublishEnvelope(context.Context, relay.Credential, relay.Envelope, int64) (relay.PublishResult, error)
	StageCheckpoint(context.Context, relay.Credential, relay.CheckpointCandidate, int64) (relay.CheckpointStageResponse, error)
	ActivateCheckpoint(context.Context, relay.AdministrationCredential, relay.CheckpointActivationRequest, int64) (relay.CheckpointActivationResponse, error)
}
