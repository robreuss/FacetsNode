package sharedspaces

import (
	"context"
	"encoding/base64"
	"reflect"
	"sort"
	"sync"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/keycustody"
	"github.com/robreuss/FacetsNode/internal/relay"
)

type memorySpace struct {
	provisioning          SpaceProvisioning
	result                relay.TenantProvisioningResult
	participants          map[uuid.UUID]Participant
	presentations         map[uuid.UUID]ParticipantPresentation
	keyGrants             map[uint64]map[uuid.UUID]ParticipantKeyGrant
	managedContentKeys    map[uint64][]byte
	computePools          map[uuid.UUID]ComputePool
	computeBindings       map[uuid.UUID]SpaceComputeBinding
	keyEpoch              uint64
	activeCheckpointEpoch uint64
}

type memoryInvitation struct {
	invitation   Invitation
	result       *InvitationClaimResult
	cancellation *InvitationCancellationResult
}

type MemoryStore struct {
	mu                              sync.Mutex
	relay                           relay.Store
	spaces                          map[uuid.UUID]*memorySpace
	spaceRetries                    map[uuid.UUID]uuid.UUID
	invitations                     map[uuid.UUID]memoryInvitation
	invitationRetries               map[uuid.UUID]uuid.UUID
	invitationCancellationRequests  map[uuid.UUID]InvitationCancellation
	invitationCancellationResponses map[uuid.UUID]InvitationCancellationResult
	revocationRequests              map[uuid.UUID]ParticipantRevocation
	revocationResponses             map[uuid.UUID]ParticipantRevocationResult
	roleChangeRequests              map[uuid.UUID]ParticipantRoleChange
	roleChangeResponses             map[uuid.UUID]ParticipantRoleChangeResult
	presentationUpdateRequests      map[uuid.UUID]ParticipantPresentationUpdate
	presentationUpdateResponses     map[uuid.UUID]ParticipantPresentationUpdateResult
	computePoolChangeRequests       map[uuid.UUID]ComputePoolChange
	computePoolChangeResponses      map[uuid.UUID]ComputePoolChangeResult
	checkpointEpochs                map[uuid.UUID]uint64
	authorityEvents                 map[uuid.UUID][]AuthorityEvent
	nextAuthoritySequences          map[uuid.UUID]uint64
	managedContentKeys              *keycustody.ManagedContentKeys
}

func NewMemoryStore(relayStore relay.Store, custodians ...*keycustody.ManagedContentKeys) *MemoryStore {
	var custodian *keycustody.ManagedContentKeys
	if len(custodians) > 0 {
		custodian = custodians[0]
	} else {
		custodian, _ = keycustody.NewEphemeralManagedContentKeys()
	}
	return &MemoryStore{
		relay: relayStore, spaces: make(map[uuid.UUID]*memorySpace),
		spaceRetries:                    make(map[uuid.UUID]uuid.UUID),
		invitations:                     make(map[uuid.UUID]memoryInvitation),
		invitationRetries:               make(map[uuid.UUID]uuid.UUID),
		invitationCancellationRequests:  make(map[uuid.UUID]InvitationCancellation),
		invitationCancellationResponses: make(map[uuid.UUID]InvitationCancellationResult),
		revocationRequests:              make(map[uuid.UUID]ParticipantRevocation),
		revocationResponses:             make(map[uuid.UUID]ParticipantRevocationResult),
		roleChangeRequests:              make(map[uuid.UUID]ParticipantRoleChange),
		roleChangeResponses:             make(map[uuid.UUID]ParticipantRoleChangeResult),
		presentationUpdateRequests:      make(map[uuid.UUID]ParticipantPresentationUpdate),
		presentationUpdateResponses:     make(map[uuid.UUID]ParticipantPresentationUpdateResult),
		computePoolChangeRequests:       make(map[uuid.UUID]ComputePoolChange),
		computePoolChangeResponses:      make(map[uuid.UUID]ComputePoolChangeResult),
		checkpointEpochs:                make(map[uuid.UUID]uint64),
		authorityEvents:                 make(map[uuid.UUID][]AuthorityEvent),
		nextAuthoritySequences:          make(map[uuid.UUID]uint64),
		managedContentKeys:              custodian,
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
	var managedWrappedKey []byte
	if provisioning.SecurityMode == SecurityModeManaged {
		if s.managedContentKeys == nil {
			return SpaceProvisioningResult{}, NewProtocolError(CodeInvalidSpace, "managed Shared Space key custody is unavailable")
		}
		_, generatedWrappedKey, generateErr := s.managedContentKeys.Generate(provisioning.SpaceID, InitialKeyEpoch)
		if generateErr != nil {
			return SpaceProvisioningResult{}, generateErr
		}
		managedWrappedKey = generatedWrappedKey
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
		participants:       map[uuid.UUID]Participant{participant.ParticipantID: participant},
		presentations:      make(map[uuid.UUID]ParticipantPresentation),
		keyGrants:          make(map[uint64]map[uuid.UUID]ParticipantKeyGrant),
		managedContentKeys: make(map[uint64][]byte),
		computePools:       make(map[uuid.UUID]ComputePool),
		computeBindings:    make(map[uuid.UUID]SpaceComputeBinding),
		keyEpoch:           InitialKeyEpoch,
	}
	if managedWrappedKey != nil {
		space.managedContentKeys[InitialKeyEpoch] = managedWrappedKey
	}
	s.spaces[provisioning.SpaceID] = space
	s.spaceRetries[provisioning.RetryID] = provisioning.SpaceID
	s.appendAuthorityEvent(AuthorityEvent{
		EventID: provisioning.RetryID, SpaceID: provisioning.SpaceID,
		DomainID:             provisioning.Domain.Registration.DomainID,
		EventType:            AuthorityEventSpaceProvisioned,
		SubjectParticipantID: &participant.ParticipantID,
		CurrentRole:          rolePointer(RoleHost), CurrentKeyEpoch: uint64Pointer(InitialKeyEpoch),
		OccurredAtMilliseconds: provisioning.CreatedAtMilliseconds,
	})
	return spaceProvisioningResult(space, relay.AcceptanceAccepted), nil
}

func spaceProvisioningResult(space *memorySpace, acceptance relay.Acceptance) SpaceProvisioningResult {
	initial := space.participants[space.provisioning.InitialParticipantID]
	return SpaceProvisioningResult{
		Acceptance: acceptance, RetryID: space.provisioning.RetryID,
		SpaceID: space.provisioning.SpaceID, SecurityMode: space.provisioning.SecurityMode,
		InteractionMode:    space.provisioning.InteractionMode,
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
	if invitation.InteractionMode != space.provisioning.InteractionMode {
		return InvitationCreateResult{}, NewProtocolError(CodeInvalidInvitation, "invitation interaction mode differs from its Shared Space")
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
	if err := invitation.ValidateKeyGrant(space.provisioning.SecurityMode, space.keyEpoch); err != nil {
		return InvitationCreateResult{}, err
	}
	if invitation.KeyGrant != nil {
		issuer, found := space.participants[invitation.KeyGrant.IssuerParticipantID]
		if !found || issuer.RevokedAtMilliseconds != nil ||
			(issuer.Role != RoleHost && issuer.Role != RoleModerator) {
			return InvitationCreateResult{}, NewProtocolError(
				CodeUnauthorized,
				"participant key grant issuer is not an active Shared Space host or moderator",
			)
		}
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
	s.appendAuthorityEvent(AuthorityEvent{
		EventID: invitation.RetryID, SpaceID: invitation.SpaceID,
		DomainID: credential.DomainID, EventType: AuthorityEventInvitationCreated,
		SubjectParticipantID: &invitation.ParticipantID, InvitationID: &invitation.InvitationID,
		CurrentRole: &invitation.Role, CurrentKeyEpoch: uint64Pointer(space.keyEpoch),
		OccurredAtMilliseconds: invitation.CreatedAtMilliseconds,
	})
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
	if record.cancellation != nil {
		return InvitationClaimResult{}, NewProtocolError(CodeInvitationCancelled, "Shared Space invitation was cancelled")
	}
	space := s.spaces[claim.SpaceID]
	if space == nil {
		return InvitationClaimResult{}, NewProtocolError(CodeSpaceNotFound, "Shared Space was not found")
	}
	if err := record.invitation.ValidateKeyGrant(space.provisioning.SecurityMode, space.keyEpoch); err != nil {
		return InvitationClaimResult{}, err
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
	space.participants[participant.ParticipantID] = participant
	if record.invitation.KeyGrant != nil {
		if space.keyGrants[space.keyEpoch] == nil {
			space.keyGrants[space.keyEpoch] = make(map[uuid.UUID]ParticipantKeyGrant)
		}
		space.keyGrants[space.keyEpoch][participant.ParticipantID] = *record.invitation.KeyGrant
	}
	result := InvitationClaimResult{
		Acceptance: relayResult.Acceptance, CurrentKeyEpoch: space.keyEpoch,
		KeyGrant: record.invitation.KeyGrant, Participant: participant, Member: relayResult.Member,
	}
	record.result = &result
	s.invitations[credential.InvitationID] = record
	s.appendAuthorityEvent(AuthorityEvent{
		EventID: credential.InvitationID, SpaceID: claim.SpaceID,
		DomainID: credential.DomainID, EventType: AuthorityEventInvitationClaimed,
		SubjectParticipantID: &participant.ParticipantID, InvitationID: &credential.InvitationID,
		CurrentRole: &participant.Role, CurrentKeyEpoch: uint64Pointer(space.keyEpoch),
		OccurredAtMilliseconds: claim.ClaimedAtMilliseconds,
	})
	return result, nil
}

func (s *MemoryStore) CancelInvitation(
	ctx context.Context,
	credential relay.AdministrationCredential,
	cancellation InvitationCancellation,
	nowMilliseconds int64,
) (InvitationCancellationResult, error) {
	if err := cancellation.Validate(); err != nil {
		return InvitationCancellationResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	space := s.spaces[cancellation.SpaceID]
	if space == nil {
		return InvitationCancellationResult{}, NewProtocolError(CodeSpaceNotFound, "Shared Space was not found")
	}
	if credential.TenantID != cancellation.SpaceID || credential.DomainID != space.provisioning.Domain.Registration.DomainID {
		return InvitationCancellationResult{}, NewProtocolError(CodeWrongScope, "invitation cancellation belongs to another Shared Space")
	}
	if existing, found := s.invitationCancellationResponses[cancellation.RetryID]; found {
		if reflect.DeepEqual(s.invitationCancellationRequests[cancellation.RetryID], cancellation) {
			existing.Acceptance = relay.AcceptanceDuplicate
			return existing, nil
		}
		return InvitationCancellationResult{}, NewProtocolError(CodeInvitationCancellationCollision, "invitation cancellation retry ID was reused")
	}
	record, found := s.invitations[cancellation.InvitationID]
	if !found {
		return InvitationCancellationResult{}, NewProtocolError(CodeInvitationNotFound, "Shared Space invitation was not found")
	}
	if record.invitation.SpaceID != cancellation.SpaceID {
		return InvitationCancellationResult{}, NewProtocolError(CodeWrongScope, "invitation cancellation belongs to another Shared Space")
	}
	if record.result != nil {
		return InvitationCancellationResult{}, NewProtocolError(CodeInvitationClaimed, "claimed Shared Space invitation cannot be cancelled")
	}
	if record.cancellation != nil {
		return InvitationCancellationResult{}, NewProtocolError(CodeInvitationCancellationCollision, "Shared Space invitation was already cancelled by another request")
	}
	if cancellation.CancelledAtMilliseconds < record.invitation.CreatedAtMilliseconds || cancellation.CancelledAtMilliseconds > nowMilliseconds {
		return InvitationCancellationResult{}, NewProtocolError(CodeInvalidInvitation, "Shared Space invitation cancellation time is invalid")
	}
	acceptance, err := s.relay.RevokeAdmission(ctx, credential, cancellation.InvitationID, cancellation.CancelledAtMilliseconds)
	if err != nil {
		return InvitationCancellationResult{}, err
	}
	if _, err := s.relay.ChangeSubscriptionStatus(
		ctx, credential, record.invitation.SubscriptionID,
		relay.SubscriptionStatusChangeRequest{
			RetryID: cancellation.RetryID, Status: relay.SubscriptionRevoked,
			ChangedAtMilliseconds: cancellation.CancelledAtMilliseconds,
		},
	); err != nil {
		return InvitationCancellationResult{}, err
	}
	result := InvitationCancellationResult{
		Acceptance: acceptance, RetryID: cancellation.RetryID, SpaceID: cancellation.SpaceID,
		InvitationID: cancellation.InvitationID, CancelledAtMilliseconds: cancellation.CancelledAtMilliseconds,
	}
	record.cancellation = &result
	s.invitations[cancellation.InvitationID] = record
	s.invitationCancellationRequests[cancellation.RetryID] = cancellation
	s.invitationCancellationResponses[cancellation.RetryID] = result
	s.appendAuthorityEvent(AuthorityEvent{
		EventID: cancellation.RetryID, SpaceID: cancellation.SpaceID,
		DomainID: credential.DomainID, EventType: AuthorityEventInvitationCancelled,
		SubjectParticipantID:   &record.invitation.ParticipantID,
		InvitationID:           &cancellation.InvitationID,
		OccurredAtMilliseconds: cancellation.CancelledAtMilliseconds,
	})
	return result, nil
}

func (s *MemoryStore) ListInvitations(
	ctx context.Context,
	credential relay.AdministrationCredential,
	nowMilliseconds int64,
) (InvitationList, error) {
	if nowMilliseconds < 0 {
		return InvitationList{}, NewProtocolError(CodeInvalidInvitation, "invitation status time is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	space := s.spaces[credential.TenantID]
	if space == nil {
		return InvitationList{}, NewProtocolError(CodeSpaceNotFound, "Shared Space was not found")
	}
	if credential.DomainID != space.provisioning.Domain.Registration.DomainID {
		return InvitationList{}, NewProtocolError(CodeWrongScope, "invitation status credential belongs to another Shared Space")
	}
	if _, err := s.relay.GetDomainStatus(ctx, credential); err != nil {
		return InvitationList{}, err
	}
	statuses := make([]InvitationStatus, 0, len(s.invitations))
	for _, record := range s.invitations {
		if record.invitation.SpaceID != credential.TenantID {
			continue
		}
		state := InvitationPending
		var claimedAt, cancelledAt *int64
		if record.result != nil {
			state = InvitationClaimed
			value := record.result.Participant.CreatedAtMilliseconds
			claimedAt = &value
		} else if record.cancellation != nil {
			state = InvitationCancelled
			value := record.cancellation.CancelledAtMilliseconds
			cancelledAt = &value
		} else if record.invitation.RelayAdmission.ExpiresAtMilliseconds <= nowMilliseconds {
			state = InvitationExpired
		}
		statuses = append(statuses, InvitationStatus{
			Version: record.invitation.Version, SpaceID: record.invitation.SpaceID,
			InvitationID: record.invitation.InvitationID, ParticipantID: record.invitation.ParticipantID,
			SubscriptionID: record.invitation.SubscriptionID, Kind: record.invitation.Kind,
			Role: record.invitation.Role, InteractionMode: record.invitation.InteractionMode, State: state,
			CreatedAtMilliseconds: record.invitation.CreatedAtMilliseconds,
			ExpiresAtMilliseconds: record.invitation.RelayAdmission.ExpiresAtMilliseconds,
			ClaimedAtMilliseconds: claimedAt, CancelledAtMilliseconds: cancelledAt,
		})
	}
	sort.Slice(statuses, func(left, right int) bool {
		return statuses[left].InvitationID.String() < statuses[right].InvitationID.String()
	})
	return InvitationList{Version: SchemaVersion, SpaceID: credential.TenantID, Invitations: statuses}, nil
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
	presentations := make([]ParticipantPresentation, 0, len(space.presentations))
	for _, presentation := range space.presentations {
		presentations = append(presentations, presentation)
	}
	sort.Slice(presentations, func(left, right int) bool {
		return presentations[left].ParticipantID.String() < presentations[right].ParticipantID.String()
	})
	computePools := make([]ComputePool, 0, len(space.computePools))
	for _, pool := range space.computePools {
		computePools = append(computePools, pool)
	}
	sort.Slice(computePools, func(left, right int) bool {
		return computePools[left].PoolID.String() < computePools[right].PoolID.String()
	})
	computeBindings := make([]SpaceComputeBinding, 0, len(space.computeBindings))
	for _, binding := range space.computeBindings {
		binding.AllowedOperations = append([]string(nil), binding.AllowedOperations...)
		computeBindings = append(computeBindings, binding)
	}
	sort.Slice(computeBindings, func(left, right int) bool {
		return computeBindings[left].PoolID.String() < computeBindings[right].PoolID.String()
	})
	var activeCheckpointEpoch *uint64
	if space.activeCheckpointEpoch != 0 {
		epoch := space.activeCheckpointEpoch
		activeCheckpointEpoch = &epoch
	}
	return SpaceStatus{
		Version: SchemaVersion, SpaceID: space.provisioning.SpaceID,
		SecurityMode:          space.provisioning.SecurityMode,
		InteractionMode:       space.provisioning.InteractionMode,
		CurrentKeyEpoch:       space.keyEpoch,
		BootstrapReady:        space.activeCheckpointEpoch == space.keyEpoch,
		ActiveCheckpointEpoch: activeCheckpointEpoch,
		DomainID:              space.provisioning.Domain.Registration.DomainID,
		InitialParticipantID:  space.provisioning.InitialParticipantID,
		Participants:          participants, Presentations: presentations,
		ComputePools: computePools, ComputeBindings: computeBindings, Relay: relayStatus,
		CreatedAtMilliseconds: space.provisioning.CreatedAtMilliseconds,
	}, nil
}

func (s *MemoryStore) ChangeComputePool(
	ctx context.Context,
	credential relay.AdministrationCredential,
	change ComputePoolChange,
	nowMilliseconds int64,
) (ComputePoolChangeResult, error) {
	if err := change.Validate(); err != nil {
		return ComputePoolChangeResult{}, err
	}
	if change.ChangedAtMilliseconds > nowMilliseconds {
		return ComputePoolChangeResult{}, NewProtocolError(CodeInvalidComputePool, "Shared Space compute pool change starts in the future")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	space := s.spaces[change.SpaceID]
	if space == nil {
		return ComputePoolChangeResult{}, NewProtocolError(CodeSpaceNotFound, "Shared Space was not found")
	}
	if credential.TenantID != change.SpaceID ||
		credential.DomainID != space.provisioning.Domain.Registration.DomainID {
		return ComputePoolChangeResult{}, NewProtocolError(CodeWrongScope, "compute pool belongs to another Shared Space")
	}
	if _, err := s.relay.GetDomainStatus(ctx, credential); err != nil {
		return ComputePoolChangeResult{}, err
	}
	if existing, found := s.computePoolChangeRequests[change.RetryID]; found {
		if reflect.DeepEqual(existing, change) {
			result := s.computePoolChangeResponses[change.RetryID]
			result.Acceptance = relay.AcceptanceDuplicate
			return result, nil
		}
		return ComputePoolChangeResult{}, NewProtocolError(CodeComputePoolCollision, "compute pool retry ID was reused")
	}
	existingPool, poolFound := space.computePools[change.PoolID]
	existingBinding, bindingFound := space.computeBindings[change.PoolID]
	if poolFound != bindingFound {
		return ComputePoolChangeResult{}, NewProtocolError(CodeComputePoolCollision, "compute pool authority state is inconsistent")
	}
	if !poolFound {
		if change.PreviousPoolRevision != 0 {
			return ComputePoolChangeResult{}, NewProtocolError(CodeComputePoolNotFound, "compute pool was not found")
		}
	} else if existingPool.Revision != change.PreviousPoolRevision ||
		existingBinding.Revision != change.PreviousBindingRevision {
		return ComputePoolChangeResult{}, NewProtocolError(CodeComputePoolCollision, "compute pool revision changed")
	}
	createdAt := change.ChangedAtMilliseconds
	if poolFound {
		createdAt = existingPool.CreatedAtMilliseconds
	}
	nextRevision := change.PreviousPoolRevision + 1
	pool := ComputePool{
		Version: SchemaVersion, SpaceID: change.SpaceID, PoolID: change.PoolID,
		DisplayName: change.DisplayName, Enabled: change.Enabled, Revision: nextRevision,
		CreatedAtMilliseconds: createdAt, UpdatedAtMilliseconds: change.ChangedAtMilliseconds,
	}
	binding := SpaceComputeBinding{
		Version: SchemaVersion, SpaceID: change.SpaceID, PoolID: change.PoolID,
		AllowedOperations: append([]string(nil), change.AllowedOperations...),
		ResourceCeiling:   change.ResourceCeiling, PricingRevision: change.PricingRevision,
		DataSensitivityContract: change.DataSensitivityContract,
		ProcessingContract:      change.ProcessingContract,
		Revision:                nextRevision, CreatedAtMilliseconds: createdAt,
		UpdatedAtMilliseconds: change.ChangedAtMilliseconds,
	}
	result := ComputePoolChangeResult{
		Acceptance: relay.AcceptanceAccepted, RetryID: change.RetryID,
		Pool: pool, Binding: binding,
	}
	space.computePools[change.PoolID] = pool
	space.computeBindings[change.PoolID] = binding
	s.computePoolChangeRequests[change.RetryID] = change
	s.computePoolChangeResponses[change.RetryID] = result
	s.appendAuthorityEvent(AuthorityEvent{
		EventID: change.RetryID, SpaceID: change.SpaceID, DomainID: credential.DomainID,
		EventType: AuthorityEventSpaceComputeBindingChanged, ComputePoolID: &change.PoolID,
		PreviousBindingRevision: &change.PreviousBindingRevision,
		CurrentBindingRevision:  &nextRevision,
		OccurredAtMilliseconds:  change.ChangedAtMilliseconds,
	})
	return result, nil
}

func (s *MemoryStore) AuthorizeComputeCapability(
	ctx context.Context,
	credential relay.Credential,
	request ComputeCapabilityRequest,
	nowMilliseconds int64,
) (ComputeCapabilityAuthorization, error) {
	if err := request.Validate(); err != nil {
		return ComputeCapabilityAuthorization{}, err
	}
	if credential.TenantID != request.SpaceID || credential.DomainID == uuid.Nil ||
		credential.MemberID == uuid.Nil {
		return ComputeCapabilityAuthorization{}, NewProtocolError(
			CodeWrongScope, "compute capability credential scope is invalid",
		)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	space := s.spaces[request.SpaceID]
	if space == nil {
		return ComputeCapabilityAuthorization{}, NewProtocolError(
			CodeSpaceNotFound, "Shared Space was not found",
		)
	}
	if credential.DomainID != space.provisioning.Domain.Registration.DomainID {
		return ComputeCapabilityAuthorization{}, NewProtocolError(
			CodeWrongScope, "compute capability belongs to another Shared Space",
		)
	}
	participant, found := space.participants[credential.MemberID]
	if !found {
		return ComputeCapabilityAuthorization{}, NewProtocolError(
			CodeParticipantNotFound, "participant was not found",
		)
	}
	if participant.RevokedAtMilliseconds != nil {
		return ComputeCapabilityAuthorization{}, NewProtocolError(
			CodeParticipantRevoked, "participant is revoked",
		)
	}
	if _, err := s.relay.Fetch(ctx, credential, 0, 1, nowMilliseconds); err != nil {
		return ComputeCapabilityAuthorization{}, err
	}
	pool, poolFound := space.computePools[request.PoolID]
	binding, bindingFound := space.computeBindings[request.PoolID]
	if !poolFound || !bindingFound {
		return ComputeCapabilityAuthorization{}, NewProtocolError(
			CodeComputePoolNotFound, "compute pool was not found",
		)
	}
	return AuthorizeComputeCapability(
		request, participant.ParticipantID, space.keyEpoch, pool, binding, nowMilliseconds,
	)
}

func (s *MemoryStore) ListAuthorityEvents(
	ctx context.Context,
	credential relay.AdministrationCredential,
	afterSequence uint64,
	limit int,
) (AuthorityEventPage, error) {
	if limit < 1 || limit > MaximumAuthorityEventPageSize {
		return AuthorityEventPage{}, NewProtocolError(CodeInvalidAuthorityEvent, "Shared Space authority event page size is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	space := s.spaces[credential.TenantID]
	if space == nil {
		return AuthorityEventPage{}, NewProtocolError(CodeSpaceNotFound, "Shared Space was not found")
	}
	if credential.DomainID != space.provisioning.Domain.Registration.DomainID {
		return AuthorityEventPage{}, NewProtocolError(CodeWrongScope, "authority event credential belongs to another Shared Space")
	}
	if _, err := s.relay.GetDomainStatus(ctx, credential); err != nil {
		return AuthorityEventPage{}, err
	}
	events := make([]AuthorityEvent, 0, limit)
	nextSequence := afterSequence
	for _, event := range s.authorityEvents[credential.TenantID] {
		if event.Sequence <= afterSequence {
			continue
		}
		events = append(events, event)
		nextSequence = event.Sequence
		if len(events) == limit {
			break
		}
	}
	return AuthorityEventPage{
		Version: SchemaVersion, SpaceID: credential.TenantID,
		Events: events, NextSequence: nextSequence,
	}, nil
}

func (s *MemoryStore) ChangeParticipantRole(
	ctx context.Context,
	credential relay.AdministrationCredential,
	change ParticipantRoleChange,
	nowMilliseconds int64,
) (ParticipantRoleChangeResult, error) {
	if err := change.Validate(); err != nil {
		return ParticipantRoleChangeResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	space := s.spaces[change.SpaceID]
	if space == nil {
		return ParticipantRoleChangeResult{}, NewProtocolError(CodeSpaceNotFound, "Shared Space was not found")
	}
	if credential.TenantID != change.SpaceID ||
		credential.DomainID != space.provisioning.Domain.Registration.DomainID {
		return ParticipantRoleChangeResult{}, NewProtocolError(CodeWrongScope, "role change belongs to another Shared Space")
	}
	if change.ParticipantID == space.provisioning.InitialParticipantID ||
		change.PreviousRole == RoleHost || change.NextRole == RoleHost {
		return ParticipantRoleChangeResult{}, NewProtocolError(CodeInitialHost, "initial host role cannot be changed")
	}
	if existing, found := s.roleChangeResponses[change.RetryID]; found {
		if reflect.DeepEqual(s.roleChangeRequests[change.RetryID], change) {
			existing.Acceptance = relay.AcceptanceDuplicate
			return existing, nil
		}
		return ParticipantRoleChangeResult{}, NewProtocolError(
			CodeParticipantRoleCollision, "participant role change retry ID was reused",
		)
	}
	participant, found := space.participants[change.ParticipantID]
	if !found {
		return ParticipantRoleChangeResult{}, NewProtocolError(CodeParticipantNotFound, "participant was not found")
	}
	if participant.RevokedAtMilliseconds != nil {
		return ParticipantRoleChangeResult{}, NewProtocolError(CodeParticipantRevoked, "participant is revoked")
	}
	if change.ChangedAtMilliseconds > nowMilliseconds ||
		change.ChangedAtMilliseconds < participant.CreatedAtMilliseconds {
		return ParticipantRoleChangeResult{}, NewProtocolError(CodeInvalidParticipant, "participant role change time is invalid")
	}
	if participant.Role != change.PreviousRole {
		return ParticipantRoleChangeResult{}, NewProtocolError(
			CodeParticipantRoleCollision, "participant role changed concurrently",
		)
	}
	relayResult, err := s.relay.ChangeMemberCapabilities(ctx, credential, relay.MemberCapabilityChange{
		Version: relay.SchemaVersion, RetryID: change.RetryID, MemberID: change.ParticipantID,
		PreviousCapabilities:  change.PreviousRole.Capabilities(space.provisioning.InteractionMode),
		NextCapabilities:      change.NextRole.Capabilities(space.provisioning.InteractionMode),
		ChangedAtMilliseconds: change.ChangedAtMilliseconds,
	}, nowMilliseconds)
	if err != nil {
		return ParticipantRoleChangeResult{}, err
	}
	participant.Role = change.NextRole
	space.participants[participant.ParticipantID] = participant
	result := ParticipantRoleChangeResult{
		Acceptance: relayResult.Acceptance, RetryID: change.RetryID, SpaceID: change.SpaceID,
		ParticipantID: change.ParticipantID, PreviousRole: change.PreviousRole,
		CurrentRole: change.NextRole, ChangedAtMilliseconds: change.ChangedAtMilliseconds,
	}
	s.roleChangeRequests[change.RetryID] = change
	s.roleChangeResponses[change.RetryID] = result
	s.appendAuthorityEvent(AuthorityEvent{
		EventID: change.RetryID, SpaceID: change.SpaceID,
		DomainID: credential.DomainID, EventType: AuthorityEventParticipantRoleChanged,
		SubjectParticipantID: &change.ParticipantID,
		PreviousRole:         &change.PreviousRole, CurrentRole: &change.NextRole,
		OccurredAtMilliseconds: change.ChangedAtMilliseconds,
	})
	return result, nil
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
		if s.revocationRequests[revocation.RetryID].Equivalent(revocation) {
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
	participants := make([]Participant, 0, len(space.participants))
	for _, candidate := range space.participants {
		participants = append(participants, candidate)
	}
	if err := revocation.ValidateKeyGrants(
		space.provisioning.SecurityMode, participants, nowMilliseconds,
	); err != nil {
		return ParticipantRevocationResult{}, err
	}
	var managedWrappedKey []byte
	if space.provisioning.SecurityMode == SecurityModeManaged {
		if s.managedContentKeys == nil {
			return ParticipantRevocationResult{}, NewProtocolError(CodeInvalidSpace, "managed Shared Space key custody is unavailable")
		}
		_, generatedWrappedKey, generateErr := s.managedContentKeys.Generate(revocation.SpaceID, revocation.NextKeyEpoch)
		if generateErr != nil {
			return ParticipantRevocationResult{}, generateErr
		}
		managedWrappedKey = generatedWrappedKey
	}
	acceptance, err := s.relay.RevokeMember(ctx, credential, revocation.ParticipantID, nowMilliseconds)
	if err != nil {
		return ParticipantRevocationResult{}, err
	}
	participant.RevokedAtMilliseconds = &nowMilliseconds
	space.participants[participant.ParticipantID] = participant
	space.keyEpoch = revocation.NextKeyEpoch
	if managedWrappedKey != nil {
		space.managedContentKeys[revocation.NextKeyEpoch] = managedWrappedKey
	} else if len(revocation.KeyGrants) > 0 {
		space.keyGrants[revocation.NextKeyEpoch] = make(map[uuid.UUID]ParticipantKeyGrant, len(revocation.KeyGrants))
		for _, grant := range revocation.KeyGrants {
			space.keyGrants[revocation.NextKeyEpoch][grant.ParticipantID] = grant
		}
	}
	result := ParticipantRevocationResult{
		Acceptance: acceptance, RetryID: revocation.RetryID, SpaceID: revocation.SpaceID,
		ParticipantID:         revocation.ParticipantID,
		PreviousKeyEpoch:      revocation.PreviousKeyEpoch,
		CurrentKeyEpoch:       revocation.NextKeyEpoch,
		RevokedAtMilliseconds: nowMilliseconds,
	}
	s.revocationRequests[revocation.RetryID] = revocation
	s.revocationResponses[revocation.RetryID] = result
	s.appendAuthorityEvent(AuthorityEvent{
		EventID: revocation.RetryID, SpaceID: revocation.SpaceID,
		DomainID: credential.DomainID, EventType: AuthorityEventParticipantRevoked,
		SubjectParticipantID: &revocation.ParticipantID,
		PreviousKeyEpoch:     &revocation.PreviousKeyEpoch, CurrentKeyEpoch: &revocation.NextKeyEpoch,
		OccurredAtMilliseconds: nowMilliseconds,
	})
	return result, nil
}

func (s *MemoryStore) appendAuthorityEvent(event AuthorityEvent) {
	next := s.nextAuthoritySequences[event.SpaceID] + 1
	event.Version = SchemaVersion
	event.Sequence = next
	s.nextAuthoritySequences[event.SpaceID] = next
	s.authorityEvents[event.SpaceID] = append(s.authorityEvents[event.SpaceID], event)
}

func rolePointer(role Role) *Role { return &role }

func uint64Pointer(value uint64) *uint64 { return &value }

func (s *MemoryStore) GetParticipantStatus(
	ctx context.Context,
	credential relay.Credential,
	nowMilliseconds int64,
) (ParticipantStatus, error) {
	if credential.TenantID == uuid.Nil || credential.DomainID == uuid.Nil || credential.MemberID == uuid.Nil {
		return ParticipantStatus{}, NewProtocolError(CodeWrongScope, "participant status credential scope is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	space := s.spaces[credential.TenantID]
	if space == nil {
		return ParticipantStatus{}, NewProtocolError(CodeSpaceNotFound, "Shared Space was not found")
	}
	if credential.DomainID != space.provisioning.Domain.Registration.DomainID {
		return ParticipantStatus{}, NewProtocolError(CodeWrongScope, "participant status belongs to another Shared Space")
	}
	participant, found := space.participants[credential.MemberID]
	if !found {
		return ParticipantStatus{}, NewProtocolError(CodeParticipantNotFound, "participant was not found")
	}
	if participant.RevokedAtMilliseconds != nil {
		return ParticipantStatus{}, NewProtocolError(CodeParticipantRevoked, "participant is revoked")
	}
	// Fetch authenticates the relay credential and active membership without
	// exposing another participant or changing Shared Space authority state.
	if _, err := s.relay.Fetch(ctx, credential, 0, 1, nowMilliseconds); err != nil {
		return ParticipantStatus{}, err
	}
	var activeCheckpointEpoch *uint64
	if space.activeCheckpointEpoch != 0 {
		epoch := space.activeCheckpointEpoch
		activeCheckpointEpoch = &epoch
	}
	status := ParticipantStatus{
		Version: SchemaVersion, SpaceID: space.provisioning.SpaceID,
		DomainID: credential.DomainID, SecurityMode: space.provisioning.SecurityMode,
		InteractionMode: space.provisioning.InteractionMode, CurrentKeyEpoch: space.keyEpoch,
		BootstrapReady:        activeCheckpointEpoch != nil && *activeCheckpointEpoch == space.keyEpoch,
		ActiveCheckpointEpoch: activeCheckpointEpoch,
		Participant:           participant,
		Capabilities:          participant.Role.Capabilities(space.provisioning.InteractionMode),
		CreatedAtMilliseconds: space.provisioning.CreatedAtMilliseconds,
	}
	if presentation, found := space.presentations[credential.MemberID]; found {
		status.Presentation = &presentation
	}
	if err := status.Validate(); err != nil {
		return ParticipantStatus{}, err
	}
	return status, nil
}

func (s *MemoryStore) GetParticipantRoster(
	ctx context.Context,
	credential relay.Credential,
	nowMilliseconds int64,
) (ParticipantRoster, error) {
	if credential.TenantID == uuid.Nil || credential.DomainID == uuid.Nil || credential.MemberID == uuid.Nil {
		return ParticipantRoster{}, NewProtocolError(CodeWrongScope, "participant roster credential scope is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	space := s.spaces[credential.TenantID]
	if space == nil {
		return ParticipantRoster{}, NewProtocolError(CodeSpaceNotFound, "Shared Space was not found")
	}
	if credential.DomainID != space.provisioning.Domain.Registration.DomainID {
		return ParticipantRoster{}, NewProtocolError(CodeWrongScope, "participant roster belongs to another Shared Space")
	}
	if space.provisioning.SecurityMode != SecurityModeSecure {
		return ParticipantRoster{}, NewProtocolError(
			CodeParticipantRosterUnavailable,
			"participant roster is available only for Secure Shared Spaces",
		)
	}
	participant, found := space.participants[credential.MemberID]
	if !found {
		return ParticipantRoster{}, NewProtocolError(CodeParticipantNotFound, "participant was not found")
	}
	if participant.RevokedAtMilliseconds != nil {
		return ParticipantRoster{}, NewProtocolError(CodeParticipantRevoked, "participant is revoked")
	}
	if _, err := s.relay.Fetch(ctx, credential, 0, 1, nowMilliseconds); err != nil {
		return ParticipantRoster{}, err
	}
	participants := make([]Participant, 0, len(space.participants))
	for _, candidate := range space.participants {
		if candidate.RevokedAtMilliseconds == nil {
			participants = append(participants, candidate)
		}
	}
	sort.Slice(participants, func(left, right int) bool {
		return participants[left].ParticipantID.String() < participants[right].ParticipantID.String()
	})
	presentations := make([]ParticipantPresentation, 0, len(participants))
	for _, candidate := range participants {
		if presentation, found := space.presentations[candidate.ParticipantID]; found {
			presentations = append(presentations, presentation)
		}
	}
	sort.Slice(presentations, func(left, right int) bool {
		return presentations[left].ParticipantID.String() < presentations[right].ParticipantID.String()
	})
	roster := ParticipantRoster{
		Version: SchemaVersion, SpaceID: space.provisioning.SpaceID,
		DomainID: credential.DomainID, SecurityMode: space.provisioning.SecurityMode,
		AuthoritySequence: s.nextAuthoritySequences[space.provisioning.SpaceID],
		Participants:      participants, Presentations: presentations,
		CreatedAtMilliseconds: space.provisioning.CreatedAtMilliseconds,
	}
	if err := roster.Validate(); err != nil {
		return ParticipantRoster{}, err
	}
	return roster, nil
}

func (s *MemoryStore) UpdateParticipantPresentation(
	ctx context.Context,
	credential relay.Credential,
	update ParticipantPresentationUpdate,
	nowMilliseconds int64,
) (ParticipantPresentationUpdateResult, error) {
	if err := update.Validate(); err != nil {
		return ParticipantPresentationUpdateResult{}, err
	}
	if credential.TenantID == uuid.Nil || credential.DomainID == uuid.Nil ||
		credential.MemberID == uuid.Nil {
		return ParticipantPresentationUpdateResult{}, NewProtocolError(
			CodeWrongScope, "participant presentation credential scope is invalid",
		)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	space := s.spaces[update.SpaceID]
	if space == nil {
		return ParticipantPresentationUpdateResult{}, NewProtocolError(
			CodeSpaceNotFound, "Shared Space was not found",
		)
	}
	if credential.TenantID != update.SpaceID ||
		credential.DomainID != space.provisioning.Domain.Registration.DomainID ||
		credential.MemberID != update.ParticipantID {
		return ParticipantPresentationUpdateResult{}, NewProtocolError(
			CodeWrongScope, "participant presentation belongs to another participant",
		)
	}
	participant, found := space.participants[update.ParticipantID]
	if !found {
		return ParticipantPresentationUpdateResult{}, NewProtocolError(
			CodeParticipantNotFound, "participant was not found",
		)
	}
	if participant.RevokedAtMilliseconds != nil {
		return ParticipantPresentationUpdateResult{}, NewProtocolError(
			CodeParticipantRevoked, "participant is revoked",
		)
	}
	if _, err := s.relay.Fetch(ctx, credential, 0, 1, nowMilliseconds); err != nil {
		return ParticipantPresentationUpdateResult{}, err
	}
	if existing, found := s.presentationUpdateResponses[update.RetryID]; found {
		if reflect.DeepEqual(s.presentationUpdateRequests[update.RetryID], update) {
			existing.Acceptance = relay.AcceptanceDuplicate
			return existing, nil
		}
		return ParticipantPresentationUpdateResult{}, NewProtocolError(
			CodeParticipantPresentationCollision,
			"participant presentation retry ID was reused",
		)
	}
	if update.UpdatedAtMilliseconds > nowMilliseconds ||
		update.UpdatedAtMilliseconds < participant.CreatedAtMilliseconds {
		return ParticipantPresentationUpdateResult{}, NewProtocolError(
			CodeInvalidParticipantPresentation,
			"participant presentation update time is invalid",
		)
	}
	currentRevision := uint64(0)
	if current, found := space.presentations[update.ParticipantID]; found {
		currentRevision = current.Revision
	}
	if update.PreviousRevision != currentRevision {
		return ParticipantPresentationUpdateResult{}, NewProtocolError(
			CodeParticipantPresentationCollision,
			"participant presentation changed concurrently",
		)
	}
	presentation := ParticipantPresentation{
		Version: SchemaVersion, SpaceID: update.SpaceID,
		ParticipantID: update.ParticipantID, DisplayName: update.DisplayName,
		Revision: currentRevision + 1, UpdatedAtMilliseconds: update.UpdatedAtMilliseconds,
	}
	result := ParticipantPresentationUpdateResult{
		Acceptance: relay.AcceptanceAccepted, RetryID: update.RetryID,
		Presentation: presentation,
	}
	space.presentations[update.ParticipantID] = presentation
	s.presentationUpdateRequests[update.RetryID] = update
	s.presentationUpdateResponses[update.RetryID] = result
	return result, nil
}

func (s *MemoryStore) GetParticipantBootstrap(
	ctx context.Context,
	credential relay.Credential,
	nowMilliseconds int64,
) (ParticipantBootstrap, error) {
	if credential.TenantID == uuid.Nil || credential.DomainID == uuid.Nil || credential.MemberID == uuid.Nil {
		return ParticipantBootstrap{}, NewProtocolError(CodeWrongScope, "participant bootstrap credential scope is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	space := s.spaces[credential.TenantID]
	if space == nil {
		return ParticipantBootstrap{}, NewProtocolError(CodeSpaceNotFound, "Shared Space was not found")
	}
	if credential.DomainID != space.provisioning.Domain.Registration.DomainID {
		return ParticipantBootstrap{}, NewProtocolError(CodeWrongScope, "participant bootstrap belongs to another Shared Space")
	}
	participant, found := space.participants[credential.MemberID]
	if !found {
		return ParticipantBootstrap{}, NewProtocolError(CodeParticipantNotFound, "participant was not found")
	}
	if participant.RevokedAtMilliseconds != nil {
		return ParticipantBootstrap{}, NewProtocolError(CodeParticipantRevoked, "participant is revoked")
	}
	if _, err := s.relay.Fetch(ctx, credential, 0, 1, nowMilliseconds); err != nil {
		return ParticipantBootstrap{}, err
	}
	var activeCheckpointEpoch *uint64
	if space.activeCheckpointEpoch != 0 {
		epoch := space.activeCheckpointEpoch
		activeCheckpointEpoch = &epoch
	}
	status := ParticipantStatus{
		Version: SchemaVersion, SpaceID: space.provisioning.SpaceID,
		DomainID: credential.DomainID, SecurityMode: space.provisioning.SecurityMode,
		InteractionMode: space.provisioning.InteractionMode, CurrentKeyEpoch: space.keyEpoch,
		BootstrapReady:        activeCheckpointEpoch != nil && *activeCheckpointEpoch == space.keyEpoch,
		ActiveCheckpointEpoch: activeCheckpointEpoch,
		Participant:           participant,
		Capabilities:          participant.Role.Capabilities(space.provisioning.InteractionMode),
		CreatedAtMilliseconds: space.provisioning.CreatedAtMilliseconds,
	}
	if presentation, found := space.presentations[credential.MemberID]; found {
		status.Presentation = &presentation
	}
	result := ParticipantBootstrap{Version: SchemaVersion, Status: status}
	if space.provisioning.SecurityMode.ContentBlind() {
		grant, found := space.keyGrants[space.keyEpoch][credential.MemberID]
		if !found {
			return ParticipantBootstrap{}, NewProtocolError(CodeKeyGrantNotFound, "current participant key grant was not found")
		}
		result.KeyGrant = &ParticipantKeyGrantResult{
			Version: SchemaVersion, SpaceID: credential.TenantID,
			ParticipantID: credential.MemberID, CurrentKeyEpoch: space.keyEpoch,
			KeyGrant: grant,
		}
	} else {
		wrapped, found := space.managedContentKeys[space.keyEpoch]
		if !found || s.managedContentKeys == nil {
			return ParticipantBootstrap{}, NewProtocolError(CodeKeyGrantNotFound, "current managed content key was not found")
		}
		plaintext, err := s.managedContentKeys.Unwrap(space.provisioning.SpaceID, space.keyEpoch, wrapped)
		if err != nil {
			return ParticipantBootstrap{}, err
		}
		result.ManagedContentKey = &ManagedContentKey{
			Version: SchemaVersion, SpaceID: credential.TenantID,
			ParticipantID: credential.MemberID, KeyEpoch: space.keyEpoch,
			Algorithm:   ManagedContentKeyAlgorithm,
			KeyMaterial: base64.RawURLEncoding.EncodeToString(plaintext),
		}
	}
	if err := result.Validate(); err != nil {
		return ParticipantBootstrap{}, err
	}
	return result, nil
}

func (s *MemoryStore) GetParticipantKeyGrant(
	ctx context.Context,
	credential relay.Credential,
	nowMilliseconds int64,
) (ParticipantKeyGrantResult, error) {
	if credential.TenantID == uuid.Nil || credential.DomainID == uuid.Nil || credential.MemberID == uuid.Nil {
		return ParticipantKeyGrantResult{}, NewProtocolError(CodeWrongScope, "participant key grant credential scope is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	space := s.spaces[credential.TenantID]
	if space == nil {
		return ParticipantKeyGrantResult{}, NewProtocolError(CodeSpaceNotFound, "Shared Space was not found")
	}
	if credential.DomainID != space.provisioning.Domain.Registration.DomainID {
		return ParticipantKeyGrantResult{}, NewProtocolError(CodeWrongScope, "participant key grant belongs to another Shared Space")
	}
	participant, found := space.participants[credential.MemberID]
	if !found {
		return ParticipantKeyGrantResult{}, NewProtocolError(CodeParticipantNotFound, "participant was not found")
	}
	if participant.RevokedAtMilliseconds != nil {
		return ParticipantKeyGrantResult{}, NewProtocolError(CodeParticipantRevoked, "participant is revoked")
	}
	if !space.provisioning.SecurityMode.ContentBlind() {
		return ParticipantKeyGrantResult{}, NewProtocolError(CodeKeyGrantNotFound, "managed Shared Spaces do not have participant key grants")
	}
	if _, err := s.relay.Fetch(ctx, credential, 0, 1, nowMilliseconds); err != nil {
		return ParticipantKeyGrantResult{}, err
	}
	grant, found := space.keyGrants[space.keyEpoch][credential.MemberID]
	if !found {
		return ParticipantKeyGrantResult{}, NewProtocolError(CodeKeyGrantNotFound, "current participant key grant was not found")
	}
	return ParticipantKeyGrantResult{
		Version: SchemaVersion, SpaceID: credential.TenantID,
		ParticipantID: credential.MemberID, CurrentKeyEpoch: space.keyEpoch,
		KeyGrant: grant,
	}, nil
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
