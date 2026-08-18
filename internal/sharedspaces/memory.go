package sharedspaces

import (
	"context"
	"reflect"
	"sort"
	"sync"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/relay"
)

type memorySpace struct {
	provisioning          SpaceProvisioning
	result                relay.TenantProvisioningResult
	participants          map[uuid.UUID]Participant
	keyEpoch              uint64
	activeCheckpointEpoch uint64
}

type memoryInvitation struct {
	invitation Invitation
	result     *InvitationClaimResult
}

type MemoryStore struct {
	mu                  sync.Mutex
	relay               relay.Store
	spaces              map[uuid.UUID]*memorySpace
	spaceRetries        map[uuid.UUID]uuid.UUID
	invitations         map[uuid.UUID]memoryInvitation
	invitationRetries   map[uuid.UUID]uuid.UUID
	revocationRequests  map[uuid.UUID]ParticipantRevocation
	revocationResponses map[uuid.UUID]ParticipantRevocationResult
	checkpointEpochs    map[uuid.UUID]uint64
}

func NewMemoryStore(relayStore relay.Store) *MemoryStore {
	return &MemoryStore{
		relay: relayStore, spaces: make(map[uuid.UUID]*memorySpace),
		spaceRetries:        make(map[uuid.UUID]uuid.UUID),
		invitations:         make(map[uuid.UUID]memoryInvitation),
		invitationRetries:   make(map[uuid.UUID]uuid.UUID),
		revocationRequests:  make(map[uuid.UUID]ParticipantRevocation),
		revocationResponses: make(map[uuid.UUID]ParticipantRevocationResult),
		checkpointEpochs:    make(map[uuid.UUID]uint64),
	}
}

func (s *MemoryStore) ProvisionSpace(
	ctx context.Context,
	provisioning SpaceProvisioning,
	nowMilliseconds int64,
) (SpaceProvisioningResult, error) {
	if err := provisioning.Validate(); err != nil {
		return SpaceProvisioningResult{}, err
	}
	if provisioning.CreatedAtMilliseconds > nowMilliseconds {
		return SpaceProvisioningResult{}, NewProtocolError(CodeInvalidSpace, "Shared Space starts in the future")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if spaceID, found := s.spaceRetries[provisioning.RetryID]; found {
		existing := s.spaces[spaceID]
		if existing != nil && reflect.DeepEqual(existing.provisioning, provisioning) {
			return spaceProvisioningResult(existing, relay.AcceptanceDuplicate), nil
		}
		return SpaceProvisioningResult{}, NewProtocolError(CodeSpaceCollision, "Shared Space retry ID was reused")
	}
	if existing := s.spaces[provisioning.SpaceID]; existing != nil {
		if reflect.DeepEqual(existing.provisioning, provisioning) {
			return spaceProvisioningResult(existing, relay.AcceptanceDuplicate), nil
		}
		return SpaceProvisioningResult{}, NewProtocolError(CodeSpaceCollision, "Shared Space ID was reused")
	}
	relayResult, err := s.relay.ProvisionTenant(ctx, provisioning.Tenant, provisioning.Domain)
	if err != nil {
		return SpaceProvisioningResult{}, err
	}
	participant := Participant{
		Version: SchemaVersion, SpaceID: provisioning.SpaceID,
		ParticipantID:  provisioning.InitialParticipantID,
		SubscriptionID: provisioning.Domain.Subscription.SubscriptionID,
		Kind:           provisioning.InitialParticipantKind, Role: RoleHost,
		CreatedAtMilliseconds: provisioning.CreatedAtMilliseconds,
	}
	space := &memorySpace{
		provisioning: provisioning, result: relayResult,
		participants: map[uuid.UUID]Participant{participant.ParticipantID: participant},
		keyEpoch:     InitialKeyEpoch,
	}
	s.spaces[provisioning.SpaceID] = space
	s.spaceRetries[provisioning.RetryID] = provisioning.SpaceID
	return spaceProvisioningResult(space, relay.AcceptanceAccepted), nil
}

func spaceProvisioningResult(space *memorySpace, acceptance relay.Acceptance) SpaceProvisioningResult {
	initial := space.participants[space.provisioning.InitialParticipantID]
	return SpaceProvisioningResult{
		Acceptance: acceptance, RetryID: space.provisioning.RetryID,
		SpaceID: space.provisioning.SpaceID, SecurityMode: space.provisioning.SecurityMode,
		CurrentKeyEpoch:    space.keyEpoch,
		InitialParticipant: initial, Relay: space.result,
	}
}

func (s *MemoryStore) CreateInvitation(
	ctx context.Context,
	credential relay.AdministrationCredential,
	invitation Invitation,
	nowMilliseconds int64,
) (InvitationCreateResult, error) {
	if err := invitation.Validate(); err != nil {
		return InvitationCreateResult{}, err
	}
	if invitation.CreatedAtMilliseconds > nowMilliseconds ||
		invitation.RelayAdmission.ExpiresAtMilliseconds <= nowMilliseconds {
		return InvitationCreateResult{}, NewProtocolError(CodeInvalidInvitation, "Shared Space invitation is not currently issuable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	space := s.spaces[invitation.SpaceID]
	if space == nil {
		return InvitationCreateResult{}, NewProtocolError(CodeSpaceNotFound, "Shared Space was not found")
	}
	if credential.TenantID != invitation.SpaceID ||
		credential.DomainID != space.provisioning.Domain.Registration.DomainID ||
		invitation.RelayAdmission.DomainID != credential.DomainID {
		return InvitationCreateResult{}, NewProtocolError(CodeWrongScope, "invitation belongs to another Shared Space")
	}
	if invitationID, found := s.invitationRetries[invitation.RetryID]; found {
		existing := s.invitations[invitationID]
		if reflect.DeepEqual(existing.invitation, invitation) {
			return InvitationCreateResult{Acceptance: relay.AcceptanceDuplicate, Invitation: existing.invitation}, nil
		}
		return InvitationCreateResult{}, NewProtocolError(CodeInvitationCollision, "invitation retry ID was reused")
	}
	if existing, found := s.invitations[invitation.InvitationID]; found {
		if reflect.DeepEqual(existing.invitation, invitation) {
			return InvitationCreateResult{Acceptance: relay.AcceptanceDuplicate, Invitation: existing.invitation}, nil
		}
		return InvitationCreateResult{}, NewProtocolError(CodeInvitationCollision, "invitation ID was reused")
	}
	if space.activeCheckpointEpoch != space.keyEpoch {
		return InvitationCreateResult{}, NewProtocolError(
			CodeBootstrapNotReady,
			"Shared Space does not have an activated checkpoint for the current key epoch",
		)
	}
	if participant, found := space.participants[invitation.ParticipantID]; found && participant.RevokedAtMilliseconds == nil {
		return InvitationCreateResult{}, NewProtocolError(CodeParticipantCollision, "participant is already active")
	}
	subscription, err := s.relay.CreateSubscription(ctx, credential, relay.SubscriptionCreateRequest{
		RetryID: invitation.RetryID, SubscriptionID: invitation.SubscriptionID,
		CreatedAtMilliseconds: invitation.CreatedAtMilliseconds,
	})
	if err != nil {
		return InvitationCreateResult{}, err
	}
	created, err := s.relay.CreateSubscriptionAdmission(
		ctx, credential, subscription.Subscription.SubscriptionID,
		invitation.RelayAdmission, nowMilliseconds,
	)
	if err != nil {
		return InvitationCreateResult{}, err
	}
	record := memoryInvitation{invitation: invitation}
	s.invitations[invitation.InvitationID] = record
	s.invitationRetries[invitation.RetryID] = invitation.InvitationID
	return InvitationCreateResult{Acceptance: created.Acceptance, Invitation: invitation}, nil
}

func (s *MemoryStore) ClaimInvitation(
	ctx context.Context,
	credential InvitationCredential,
	claim InvitationClaim,
	nowMilliseconds int64,
) (InvitationClaimResult, error) {
	if err := claim.Validate(); err != nil {
		return InvitationClaimResult{}, err
	}
	if credential.SpaceID != claim.SpaceID || credential.InvitationID == uuid.Nil {
		return InvitationClaimResult{}, NewProtocolError(CodeWrongScope, "invitation credential belongs to another Shared Space")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, found := s.invitations[credential.InvitationID]
	if !found {
		return InvitationClaimResult{}, NewProtocolError(CodeInvitationNotFound, "Shared Space invitation was not found")
	}
	if record.invitation.SpaceID != claim.SpaceID || record.invitation.ParticipantID != claim.ParticipantID ||
		credential.DomainID != record.invitation.RelayAdmission.DomainID {
		return InvitationClaimResult{}, NewProtocolError(CodeWrongScope, "invitation claim scope differs")
	}
	if record.result != nil {
		if record.result.Participant.ParticipantID == claim.ParticipantID &&
			record.result.Member.MemberRegistration.AuthorizationDigest == claim.RelayClaim.AuthorizationDigest {
			result := *record.result
			result.Acceptance = relay.AcceptanceDuplicate
			return result, nil
		}
		return InvitationClaimResult{}, NewProtocolError(CodeInvitationClaimed, "Shared Space invitation was already claimed")
	}
	relayResult, err := s.relay.ClaimSubscriptionAdmission(ctx, relay.AdmissionCredential{
		TenantID: credential.SpaceID, DomainID: credential.DomainID,
		AdmissionID: credential.InvitationID, Token: credential.Token,
	}, claim.RelayClaim, nowMilliseconds)
	if err != nil {
		return InvitationClaimResult{}, err
	}
	participant := Participant{
		Version: SchemaVersion, SpaceID: claim.SpaceID, ParticipantID: claim.ParticipantID,
		SubscriptionID: record.invitation.SubscriptionID, Kind: record.invitation.Kind,
		Role: record.invitation.Role, CreatedAtMilliseconds: nowMilliseconds,
	}
	space := s.spaces[claim.SpaceID]
	if space == nil {
		return InvitationClaimResult{}, NewProtocolError(CodeSpaceNotFound, "Shared Space was not found")
	}
	space.participants[participant.ParticipantID] = participant
	result := InvitationClaimResult{
		Acceptance: relayResult.Acceptance, CurrentKeyEpoch: space.keyEpoch,
		Participant: participant, Member: relayResult.Member,
	}
	record.result = &result
	s.invitations[credential.InvitationID] = record
	return result, nil
}

func (s *MemoryStore) GetSpaceStatus(
	ctx context.Context,
	credential relay.AdministrationCredential,
) (SpaceStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	space := s.spaces[credential.TenantID]
	if space == nil {
		return SpaceStatus{}, NewProtocolError(CodeSpaceNotFound, "Shared Space was not found")
	}
	if credential.DomainID != space.provisioning.Domain.Registration.DomainID {
		return SpaceStatus{}, NewProtocolError(CodeWrongScope, "status credential belongs to another Shared Space")
	}
	relayStatus, err := s.relay.GetDomainStatus(ctx, credential)
	if err != nil {
		return SpaceStatus{}, err
	}
	participants := make([]Participant, 0, len(space.participants))
	for _, participant := range space.participants {
		participants = append(participants, participant)
	}
	sort.Slice(participants, func(left, right int) bool {
		return participants[left].ParticipantID.String() < participants[right].ParticipantID.String()
	})
	var activeCheckpointEpoch *uint64
	if space.activeCheckpointEpoch != 0 {
		epoch := space.activeCheckpointEpoch
		activeCheckpointEpoch = &epoch
	}
	return SpaceStatus{
		Version: SchemaVersion, SpaceID: space.provisioning.SpaceID,
		SecurityMode:          space.provisioning.SecurityMode,
		CurrentKeyEpoch:       space.keyEpoch,
		BootstrapReady:        space.activeCheckpointEpoch == space.keyEpoch,
		ActiveCheckpointEpoch: activeCheckpointEpoch,
		DomainID:              space.provisioning.Domain.Registration.DomainID,
		InitialParticipantID:  space.provisioning.InitialParticipantID,
		Participants:          participants, Relay: relayStatus,
		CreatedAtMilliseconds: space.provisioning.CreatedAtMilliseconds,
	}, nil
}

func (s *MemoryStore) RevokeParticipant(
	ctx context.Context,
	credential relay.AdministrationCredential,
	revocation ParticipantRevocation,
	nowMilliseconds int64,
) (ParticipantRevocationResult, error) {
	if err := revocation.Validate(); err != nil {
		return ParticipantRevocationResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	space := s.spaces[revocation.SpaceID]
	if space == nil {
		return ParticipantRevocationResult{}, NewProtocolError(CodeSpaceNotFound, "Shared Space was not found")
	}
	if credential.TenantID != revocation.SpaceID ||
		credential.DomainID != space.provisioning.Domain.Registration.DomainID {
		return ParticipantRevocationResult{}, NewProtocolError(CodeWrongScope, "revocation belongs to another Shared Space")
	}
	if revocation.ParticipantID == space.provisioning.InitialParticipantID {
		return ParticipantRevocationResult{}, NewProtocolError(CodeInitialHost, "initial host cannot be revoked")
	}
	if existing, found := s.revocationResponses[revocation.RetryID]; found {
		if s.revocationRequests[revocation.RetryID] == revocation {
			existing.Acceptance = relay.AcceptanceDuplicate
			return existing, nil
		}
		return ParticipantRevocationResult{}, NewProtocolError(CodeParticipantCollision, "participant revocation retry ID was reused")
	}
	if revocation.PreviousKeyEpoch != space.keyEpoch {
		return ParticipantRevocationResult{}, NewProtocolError(CodeWrongKeyEpoch, "participant revocation key epoch is stale")
	}
	participant, found := space.participants[revocation.ParticipantID]
	if !found {
		return ParticipantRevocationResult{}, NewProtocolError(CodeParticipantNotFound, "participant was not found")
	}
	if participant.RevokedAtMilliseconds != nil {
		return ParticipantRevocationResult{}, NewProtocolError(CodeParticipantRevoked, "participant is already revoked")
	}
	acceptance, err := s.relay.RevokeMember(ctx, credential, revocation.ParticipantID, nowMilliseconds)
	if err != nil {
		return ParticipantRevocationResult{}, err
	}
	participant.RevokedAtMilliseconds = &nowMilliseconds
	space.participants[participant.ParticipantID] = participant
	space.keyEpoch = revocation.NextKeyEpoch
	result := ParticipantRevocationResult{
		Acceptance: acceptance, RetryID: revocation.RetryID, SpaceID: revocation.SpaceID,
		ParticipantID:         revocation.ParticipantID,
		PreviousKeyEpoch:      revocation.PreviousKeyEpoch,
		CurrentKeyEpoch:       revocation.NextKeyEpoch,
		RevokedAtMilliseconds: nowMilliseconds,
	}
	s.revocationRequests[revocation.RetryID] = revocation
	s.revocationResponses[revocation.RetryID] = result
	return result, nil
}

func (s *MemoryStore) PublishEnvelope(
	ctx context.Context,
	credential relay.Credential,
	envelope relay.Envelope,
	nowMilliseconds int64,
) (relay.PublishResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	space := s.spaces[credential.TenantID]
	if space == nil {
		return relay.PublishResult{}, NewProtocolError(CodeSpaceNotFound, "Shared Space was not found")
	}
	if credential.DomainID != space.provisioning.Domain.Registration.DomainID ||
		envelope.TenantID != credential.TenantID || envelope.DomainID != credential.DomainID {
		return relay.PublishResult{}, NewProtocolError(CodeWrongScope, "envelope belongs to another Shared Space")
	}
	if envelope.KeyEpoch != space.keyEpoch {
		return relay.PublishResult{}, NewProtocolError(CodeWrongKeyEpoch, "envelope key epoch is not current")
	}
	return s.relay.Publish(ctx, credential, envelope, nowMilliseconds)
}

func (s *MemoryStore) StageCheckpoint(
	ctx context.Context,
	credential relay.Credential,
	candidate relay.CheckpointCandidate,
	nowMilliseconds int64,
) (relay.CheckpointStageResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	space := s.spaces[credential.TenantID]
	if space == nil {
		return relay.CheckpointStageResponse{}, NewProtocolError(CodeSpaceNotFound, "Shared Space was not found")
	}
	if credential.DomainID != space.provisioning.Domain.Registration.DomainID ||
		candidate.TenantID != credential.TenantID || candidate.DomainID != credential.DomainID {
		return relay.CheckpointStageResponse{}, NewProtocolError(CodeWrongScope, "checkpoint belongs to another Shared Space")
	}
	if candidate.KeyEpoch != space.keyEpoch {
		return relay.CheckpointStageResponse{}, NewProtocolError(CodeWrongKeyEpoch, "checkpoint key epoch is not current")
	}
	result, err := s.relay.StageCheckpoint(ctx, credential, candidate, nowMilliseconds)
	if err != nil {
		return relay.CheckpointStageResponse{}, err
	}
	s.checkpointEpochs[candidate.CheckpointID] = candidate.KeyEpoch
	return result, nil
}

func (s *MemoryStore) ActivateCheckpoint(
	ctx context.Context,
	credential relay.AdministrationCredential,
	request relay.CheckpointActivationRequest,
	nowMilliseconds int64,
) (relay.CheckpointActivationResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	space := s.spaces[credential.TenantID]
	if space == nil {
		return relay.CheckpointActivationResponse{}, NewProtocolError(CodeSpaceNotFound, "Shared Space was not found")
	}
	if credential.DomainID != space.provisioning.Domain.Registration.DomainID {
		return relay.CheckpointActivationResponse{}, NewProtocolError(CodeWrongScope, "checkpoint belongs to another Shared Space")
	}
	if s.checkpointEpochs[request.CheckpointID] != space.keyEpoch {
		return relay.CheckpointActivationResponse{}, NewProtocolError(CodeWrongKeyEpoch, "checkpoint key epoch is not current")
	}
	result, err := s.relay.ActivateCheckpoint(ctx, credential, request, nowMilliseconds)
	if err != nil {
		return relay.CheckpointActivationResponse{}, err
	}
	space.activeCheckpointEpoch = space.keyEpoch
	return result, nil
}
