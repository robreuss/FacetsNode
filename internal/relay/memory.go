package relay

import (
	"context"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

type domainKey struct {
	tenantID uuid.UUID
	domainID uuid.UUID
}

type memoryMessage struct {
	message               Message
	byteCount             int64
	publisherMember       uuid.UUID
	publisherSubscription uuid.UUID
	acknowledgments       map[uuid.UUID]AcknowledgmentStage
	checkpointFenceID     *uuid.UUID
}

type memoryFenceMessageTombstone struct {
	publisherMember uuid.UUID
	digest          string
	sequence        uint64
}

type memoryDomain struct {
	provisioningRetryID     uuid.UUID
	registration            DomainRegistration
	subscriptions           map[uuid.UUID]Subscription
	subscriptionCreates     map[uuid.UUID]SubscriptionCreateRequest
	subscriptionChanges     map[uuid.UUID]memorySubscriptionChange
	rebootstrapRequests     map[uuid.UUID]memorySubscriptionRebootstrapRequest
	rebootstrapCompletions  map[uuid.UUID]memorySubscriptionRebootstrapCompletion
	memberSubscriptions     map[uuid.UUID]uuid.UUID
	admissionSubscriptions  map[uuid.UUID]uuid.UUID
	members                 map[uuid.UUID]MemberRegistration
	admissions              map[uuid.UUID]MemberAdmission
	messages                []*memoryMessage
	messageByID             map[uuid.UUID]*memoryMessage
	blobs                   map[string]BlobMetadata
	rotations               map[uuid.UUID]memoryCredentialRotation
	capabilityChanges       map[uuid.UUID]memoryMemberCapabilityChange
	nextSequence            uint64
	messageBytes            int64
	blobBytes               int64
	checkpoints             map[uuid.UUID]*memoryCheckpoint
	checkpointStageRetries  map[uuid.UUID]uuid.UUID
	checkpointActivations   map[uuid.UUID]memoryCheckpointActivation
	checkpointCollections   map[uuid.UUID]memoryCheckpointCollection
	activatedCheckpoints    []uuid.UUID
	checkpointOrdinal       uint64
	checkpointFences        map[uuid.UUID]*memoryCheckpointFence
	checkpointFenceRetries  map[uuid.UUID]uuid.UUID
	checkpointFenceAborts   map[uuid.UUID]memoryFenceAbort
	fenceMessageTombstones  map[uuid.UUID]memoryFenceMessageTombstone
	blobFenceIDs            map[string]uuid.UUID
	blobUploads             map[uuid.UUID]*memoryBlobUpload
	blobUploadCreates       map[uuid.UUID]uuid.UUID
	blobUploadFinalizations map[uuid.UUID]memoryBlobUploadFinalization
	reservedBlobCount       int64
	reservedBlobBytes       int64
}

type memorySubscriptionChange struct {
	subscriptionID uuid.UUID
	request        SubscriptionStatusChangeRequest
	result         Subscription
}

type memorySubscriptionRebootstrapRequest struct {
	subscriptionID uuid.UUID
	request        SubscriptionRebootstrapRequest
	result         Subscription
}

type memorySubscriptionRebootstrapCompletion struct {
	subscriptionID        uuid.UUID
	recoveryStartSequence uint64
	request               SubscriptionRebootstrapCompletion
	result                Subscription
}

type memoryTenant struct {
	registration          TenantRegistration
	rotations             map[uuid.UUID]memoryTenantRotation
	membershipRevocations map[uuid.UUID]TenantMembershipRevocation
}

type memoryTenantRotation struct {
	previousAuthorizationDigest string
	newAuthorizationDigest      string
	rotatedAtMilliseconds       int64
}

type memoryCredentialRotation struct {
	subjectType                 string
	subjectID                   uuid.UUID
	previousAuthorizationDigest string
	newAuthorizationDigest      string
	rotatedAtMilliseconds       int64
}

type memoryMemberCapabilityChange struct {
	request MemberCapabilityChange
	result  MemberCapabilityChangeResult
}

const (
	administrationRotationSubject = "administration"
	memberRotationSubject         = "member"
)

type MemoryStore struct {
	mu              sync.RWMutex
	tenants         map[uuid.UUID]*memoryTenant
	domains         map[domainKey]*memoryDomain
	checkpointFence time.Duration
}

func NewMemoryStore(checkpointFenceTTL ...time.Duration) *MemoryStore {
	ttl := time.Duration(DefaultCheckpointFenceLifetimeMilliseconds) * time.Millisecond
	if len(checkpointFenceTTL) > 0 && checkpointFenceTTL[0] >= time.Duration(MinimumCheckpointFenceLifetimeMilliseconds)*time.Millisecond && checkpointFenceTTL[0] <= time.Duration(MaximumCheckpointFenceLifetimeMilliseconds)*time.Millisecond {
		ttl = checkpointFenceTTL[0]
	}
	return &MemoryStore{
		tenants:         make(map[uuid.UUID]*memoryTenant),
		domains:         make(map[domainKey]*memoryDomain),
		checkpointFence: ttl,
	}
}

// CreateDomain is retained only for focused legacy store tests. Production
// provisioning uses ProvisionTenant or ProvisionDomain and always authenticates
// the client-generated tenant credential.
func (s *MemoryStore) CreateDomain(
	_ context.Context,
	registration DomainRegistration,
	initialMember MemberRegistration,
) (Acceptance, error) {
	subscription := Subscription{
		Version: SchemaVersion, TenantID: registration.TenantID,
		DomainID: registration.DomainID, SubscriptionID: initialMember.MemberID,
		Status: SubscriptionActive, CreatedAtMilliseconds: registration.CreatedAtMilliseconds,
		UpdatedAtMilliseconds: registration.CreatedAtMilliseconds,
	}
	provisioning := DomainProvisioning{
		Version: SchemaVersion, RetryID: initialMember.MemberID,
		Registration: registration, Subscription: subscription, InitialMember: initialMember,
	}
	if err := provisioning.Validate(); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := domainKey{registration.TenantID, registration.DomainID}
	if existing := s.domains[key]; existing != nil {
		if domainProvisioningEqual(existing, provisioning) {
			return AcceptanceDuplicate, nil
		}
		return "", protocolError(CodeDomainCollision, "domain ID was reused")
	}
	if s.tenants[registration.TenantID] == nil {
		s.tenants[registration.TenantID] = &memoryTenant{
			registration: TenantRegistration{
				Version: SchemaVersion, RetryID: registration.DomainID,
				TenantID:                         registration.TenantID,
				AuthorizationDigest:              registration.AdministrationDigest,
				CreatedAtMilliseconds:            registration.CreatedAtMilliseconds,
				MaximumDomainCount:               DefaultMaximumDomainCountPerTenant,
				MaximumAggregateMessageCount:     DefaultMaximumMessageCountPerTenant,
				MaximumAggregateMessageByteCount: DefaultMaximumMessageBytesPerTenant,
				MaximumAggregateBlobCount:        DefaultMaximumBlobCountPerTenant,
				MaximumAggregateBlobByteCount:    DefaultMaximumBlobBytesPerTenant,
			},
			rotations:             make(map[uuid.UUID]memoryTenantRotation),
			membershipRevocations: make(map[uuid.UUID]TenantMembershipRevocation),
		}
	}
	s.createDomainLocked(provisioning)
	return AcceptanceAccepted, nil
}

func (s *MemoryStore) ProvisionTenant(
	_ context.Context,
	tenant TenantRegistration,
	initialDomain DomainProvisioning,
) (TenantProvisioningResult, error) {
	if err := tenant.Validate(); err != nil {
		return TenantProvisioningResult{}, err
	}
	if err := initialDomain.Validate(); err != nil {
		return TenantProvisioningResult{}, err
	}
	if tenant.TenantID != initialDomain.Registration.TenantID ||
		tenant.CreatedAtMilliseconds != initialDomain.Registration.CreatedAtMilliseconds {
		return TenantProvisioningResult{}, protocolError(CodeWrongScope, "initial domain belongs to another tenant")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for tenantID, existing := range s.tenants {
		if tenantID != tenant.TenantID && existing.registration.RetryID == tenant.RetryID {
			return TenantProvisioningResult{}, protocolError(CodeTenantCollision, "tenant retry ID was reused")
		}
	}
	if existing, ok := s.tenants[tenant.TenantID]; ok {
		domain := s.domains[domainKey{tenant.TenantID, initialDomain.Registration.DomainID}]
		if existing.registration == tenant && domainProvisioningEqual(domain, initialDomain) {
			return tenantProvisioningResult(tenant, initialDomain, AcceptanceDuplicate), nil
		}
		return TenantProvisioningResult{}, protocolError(CodeTenantCollision, "tenant ID or retry ID was reused")
	}
	s.tenants[tenant.TenantID] = &memoryTenant{
		registration:          tenant,
		rotations:             make(map[uuid.UUID]memoryTenantRotation),
		membershipRevocations: make(map[uuid.UUID]TenantMembershipRevocation),
	}
	s.createDomainLocked(initialDomain)
	return tenantProvisioningResult(tenant, initialDomain, AcceptanceAccepted), nil
}

func (s *MemoryStore) ProvisionDomain(
	_ context.Context,
	credential TenantCredential,
	provisioning DomainProvisioning,
	nowMilliseconds int64,
) (DomainProvisioningResult, error) {
	if err := provisioning.Validate(); err != nil {
		return DomainProvisioningResult{}, err
	}
	if provisioning.Registration.TenantID != credential.TenantID ||
		provisioning.Registration.CreatedAtMilliseconds > nowMilliseconds {
		return DomainProvisioningResult{}, protocolError(CodeWrongScope, "domain belongs to another tenant")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tenant, ok := s.tenants[credential.TenantID]
	if !ok {
		return DomainProvisioningResult{}, protocolError(CodeTenantNotFound, "tenant was not found")
	}
	if err := tenant.registration.Authorize(credential); err != nil {
		return DomainProvisioningResult{}, err
	}
	key := domainKey{credential.TenantID, provisioning.Registration.DomainID}
	if existing := s.domains[key]; existing != nil {
		if domainProvisioningEqual(existing, provisioning) {
			return domainProvisioningResult(provisioning, AcceptanceDuplicate), nil
		}
		return DomainProvisioningResult{}, protocolError(CodeDomainCollision, "domain ID was reused")
	}
	for key, existing := range s.domains {
		if key.tenantID == credential.TenantID && existing.provisioningRetryID == provisioning.RetryID {
			return DomainProvisioningResult{}, protocolError(CodeDomainCollision, "domain retry ID was reused")
		}
	}
	domainCount := 0
	for domainKey := range s.domains {
		if domainKey.tenantID == credential.TenantID {
			domainCount++
		}
	}
	if domainCount >= tenant.registration.MaximumDomainCount {
		return DomainProvisioningResult{}, protocolError(CodeTenantFull, "tenant reached its domain limit")
	}
	s.createDomainLocked(provisioning)
	return domainProvisioningResult(provisioning, AcceptanceAccepted), nil
}

func (s *MemoryStore) createDomainLocked(
	provisioning DomainProvisioning,
) {
	registration := provisioning.Registration
	initialMember := provisioning.InitialMember
	key := domainKey{registration.TenantID, registration.DomainID}
	s.domains[key] = &memoryDomain{
		provisioningRetryID: provisioning.RetryID,
		registration:        registration,
		subscriptions: map[uuid.UUID]Subscription{
			provisioning.Subscription.SubscriptionID: provisioning.Subscription,
		},
		subscriptionCreates:    make(map[uuid.UUID]SubscriptionCreateRequest),
		subscriptionChanges:    make(map[uuid.UUID]memorySubscriptionChange),
		rebootstrapRequests:    make(map[uuid.UUID]memorySubscriptionRebootstrapRequest),
		rebootstrapCompletions: make(map[uuid.UUID]memorySubscriptionRebootstrapCompletion),
		memberSubscriptions: map[uuid.UUID]uuid.UUID{
			initialMember.MemberID: provisioning.Subscription.SubscriptionID,
		},
		admissionSubscriptions: make(map[uuid.UUID]uuid.UUID),
		members: map[uuid.UUID]MemberRegistration{
			initialMember.MemberID: initialMember,
		},
		admissions:              make(map[uuid.UUID]MemberAdmission),
		messageByID:             make(map[uuid.UUID]*memoryMessage),
		blobs:                   make(map[string]BlobMetadata),
		rotations:               make(map[uuid.UUID]memoryCredentialRotation),
		capabilityChanges:       make(map[uuid.UUID]memoryMemberCapabilityChange),
		checkpoints:             make(map[uuid.UUID]*memoryCheckpoint),
		checkpointStageRetries:  make(map[uuid.UUID]uuid.UUID),
		checkpointActivations:   make(map[uuid.UUID]memoryCheckpointActivation),
		checkpointCollections:   make(map[uuid.UUID]memoryCheckpointCollection),
		checkpointFences:        make(map[uuid.UUID]*memoryCheckpointFence),
		checkpointFenceRetries:  make(map[uuid.UUID]uuid.UUID),
		checkpointFenceAborts:   make(map[uuid.UUID]memoryFenceAbort),
		fenceMessageTombstones:  make(map[uuid.UUID]memoryFenceMessageTombstone),
		blobFenceIDs:            make(map[string]uuid.UUID),
		blobUploads:             make(map[uuid.UUID]*memoryBlobUpload),
		blobUploadCreates:       make(map[uuid.UUID]uuid.UUID),
		blobUploadFinalizations: make(map[uuid.UUID]memoryBlobUploadFinalization),
	}
}

func domainProvisioningEqual(domain *memoryDomain, provisioning DomainProvisioning) bool {
	if domain == nil || domain.provisioningRetryID != provisioning.RetryID ||
		domain.registration != provisioning.Registration {
		return false
	}
	return subscriptionEqual(domain.subscriptions[provisioning.Subscription.SubscriptionID], provisioning.Subscription) &&
		memberEqual(domain.members[provisioning.InitialMember.MemberID], provisioning.InitialMember) &&
		domain.memberSubscriptions[provisioning.InitialMember.MemberID] == provisioning.Subscription.SubscriptionID
}

func subscriptionEqual(left, right Subscription) bool {
	return left.Version == right.Version && left.TenantID == right.TenantID &&
		left.DomainID == right.DomainID && left.SubscriptionID == right.SubscriptionID &&
		left.Status == right.Status && left.CreatedAtMilliseconds == right.CreatedAtMilliseconds &&
		left.UpdatedAtMilliseconds == right.UpdatedAtMilliseconds &&
		((left.StartCursor == nil && right.StartCursor == nil) ||
			(left.StartCursor != nil && right.StartCursor != nil && *left.StartCursor == *right.StartCursor))
}

func domainProvisioningResult(p DomainProvisioning, acceptance Acceptance) DomainProvisioningResult {
	return DomainProvisioningResult{
		Acceptance:                        acceptance,
		RetryID:                           p.RetryID,
		TenantID:                          p.Registration.TenantID,
		DomainID:                          p.Registration.DomainID,
		SubscriptionID:                    p.Subscription.SubscriptionID,
		MemberID:                          p.InitialMember.MemberID,
		AdministrationAuthorizationDigest: p.Registration.AdministrationDigest,
		MemberAuthorizationDigest:         p.InitialMember.AuthorizationDigest,
	}
}

func tenantProvisioningResult(t TenantRegistration, p DomainProvisioning, acceptance Acceptance) TenantProvisioningResult {
	return TenantProvisioningResult{
		Acceptance:                            acceptance,
		RetryID:                               t.RetryID,
		TenantProvisioningAuthorizationDigest: t.AuthorizationDigest,
		InitialDomain:                         domainProvisioningResult(p, acceptance),
	}
}

func (s *MemoryStore) RotateTenantCredential(
	_ context.Context,
	credential TenantCredential,
	rotation TenantCredentialRotation,
) (TenantCredentialRotationResult, error) {
	if err := rotation.Validate(); err != nil {
		return TenantCredentialRotationResult{}, err
	}
	actualDigest, err := TenantAuthorizationDigest(credential)
	if err != nil {
		return TenantCredentialRotationResult{}, protocolError(CodeUnauthorized, "tenant credential is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tenant := s.tenants[credential.TenantID]
	if tenant == nil {
		return TenantCredentialRotationResult{}, protocolError(CodeTenantNotFound, "tenant was not found")
	}
	if existing, ok := tenant.rotations[rotation.RotationID]; ok {
		if (digestEqual(actualDigest, existing.previousAuthorizationDigest) ||
			digestEqual(actualDigest, existing.newAuthorizationDigest)) &&
			rotation.TenantID == credential.TenantID &&
			rotation.ReplacementAuthorizationDigest == existing.newAuthorizationDigest &&
			rotation.RotatedAtMilliseconds == existing.rotatedAtMilliseconds {
			return TenantCredentialRotationResult{Acceptance: AcceptanceDuplicate, RotationID: rotation.RotationID, TenantID: credential.TenantID, AuthorizationDigest: existing.newAuthorizationDigest, RotatedAtMilliseconds: existing.rotatedAtMilliseconds}, nil
		}
		return TenantCredentialRotationResult{}, protocolError(CodeCredentialRotationCollision, "tenant rotation ID was reused")
	}
	if rotation.TenantID != credential.TenantID {
		return TenantCredentialRotationResult{}, protocolError(CodeWrongScope, "rotation belongs to another tenant")
	}
	if err := tenant.registration.Authorize(credential); err != nil {
		return TenantCredentialRotationResult{}, err
	}
	if rotation.RotatedAtMilliseconds < tenant.registration.CreatedAtMilliseconds ||
		digestEqual(rotation.ReplacementAuthorizationDigest, tenant.registration.AuthorizationDigest) {
		return TenantCredentialRotationResult{}, protocolError(CodeInvalidCredentialRotation, "tenant credential rotation is invalid")
	}
	for _, used := range tenant.rotations {
		if digestEqual(rotation.ReplacementAuthorizationDigest, used.previousAuthorizationDigest) ||
			digestEqual(rotation.ReplacementAuthorizationDigest, used.newAuthorizationDigest) {
			return TenantCredentialRotationResult{}, protocolError(CodeCredentialReuse, "tenant credential digest was already used")
		}
	}
	tenant.rotations[rotation.RotationID] = memoryTenantRotation{previousAuthorizationDigest: tenant.registration.AuthorizationDigest, newAuthorizationDigest: rotation.ReplacementAuthorizationDigest, rotatedAtMilliseconds: rotation.RotatedAtMilliseconds}
	tenant.registration.AuthorizationDigest = rotation.ReplacementAuthorizationDigest
	return TenantCredentialRotationResult{Acceptance: AcceptanceAccepted, RotationID: rotation.RotationID, TenantID: credential.TenantID, AuthorizationDigest: rotation.ReplacementAuthorizationDigest, RotatedAtMilliseconds: rotation.RotatedAtMilliseconds}, nil
}

func (s *MemoryStore) RotateAdministrationCredential(
	_ context.Context,
	credential AdministrationCredential,
	rotation CredentialRotation,
	nowMilliseconds int64,
) (CredentialRotationResult, error) {
	if err := rotation.Validate(); err != nil {
		return CredentialRotationResult{}, err
	}
	actualDigest, err := AdministrationDigest(credential)
	if err != nil {
		return CredentialRotationResult{}, protocolError(
			CodeUnauthorized,
			"administration credential is invalid",
		)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	domain, ok := s.domains[domainKey{credential.TenantID, credential.DomainID}]
	if !ok {
		return CredentialRotationResult{}, protocolError(CodeDomainNotFound, "domain was not found")
	}
	if existing, ok := domain.rotations[rotation.RotationID]; ok {
		return memoryRotationRetryResult(
			existing,
			administrationRotationSubject,
			credential.DomainID,
			actualDigest,
			rotation,
		)
	}
	if err := domain.registration.Authorize(credential); err != nil {
		return CredentialRotationResult{}, err
	}
	if nowMilliseconds < domain.registration.CreatedAtMilliseconds {
		return CredentialRotationResult{}, protocolError(
			CodeInvalidCredentialRotation,
			"credential rotation precedes domain creation",
		)
	}
	if rotationDigestWasUsed(
		domain.rotations,
		administrationRotationSubject,
		credential.DomainID,
		rotation.AuthorizationDigest,
	) || rotation.AuthorizationDigest == domain.registration.AdministrationDigest {
		return CredentialRotationResult{}, protocolError(
			CodeCredentialReuse,
			"administration credential digest was already used",
		)
	}
	if err := ensureCredentialRotationCapacity(
		domain.rotations,
		administrationRotationSubject,
		credential.DomainID,
	); err != nil {
		return CredentialRotationResult{}, err
	}
	domain.rotations[rotation.RotationID] = memoryCredentialRotation{
		subjectType:                 administrationRotationSubject,
		subjectID:                   credential.DomainID,
		previousAuthorizationDigest: domain.registration.AdministrationDigest,
		newAuthorizationDigest:      rotation.AuthorizationDigest,
		rotatedAtMilliseconds:       nowMilliseconds,
	}
	domain.registration.AdministrationDigest = rotation.AuthorizationDigest
	return CredentialRotationResult{
		Acceptance:            AcceptanceAccepted,
		RotationID:            rotation.RotationID,
		AuthorizationDigest:   rotation.AuthorizationDigest,
		RotatedAtMilliseconds: nowMilliseconds,
	}, nil
}

func (s *MemoryStore) RotateMemberCredential(
	_ context.Context,
	credential Credential,
	rotation CredentialRotation,
	nowMilliseconds int64,
) (CredentialRotationResult, error) {
	if err := rotation.Validate(); err != nil {
		return CredentialRotationResult{}, err
	}
	actualDigest, err := AuthorizationDigest(credential)
	if err != nil {
		return CredentialRotationResult{}, protocolError(
			CodeUnauthorized,
			"member credential is invalid",
		)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	domain, ok := s.domains[domainKey{credential.TenantID, credential.DomainID}]
	if !ok {
		return CredentialRotationResult{}, protocolError(CodeDomainNotFound, "domain was not found")
	}
	if existing, ok := domain.rotations[rotation.RotationID]; ok {
		return memoryRotationRetryResult(
			existing,
			memberRotationSubject,
			credential.MemberID,
			actualDigest,
			rotation,
		)
	}
	member, ok := domain.members[credential.MemberID]
	if !ok {
		return CredentialRotationResult{}, protocolError(CodeMemberNotFound, "member was not found")
	}
	if err := member.VerifyCredential(credential, nowMilliseconds); err != nil {
		return CredentialRotationResult{}, err
	}
	if rotationDigestWasUsed(
		domain.rotations,
		memberRotationSubject,
		credential.MemberID,
		rotation.AuthorizationDigest,
	) || rotation.AuthorizationDigest == member.AuthorizationDigest {
		return CredentialRotationResult{}, protocolError(
			CodeCredentialReuse,
			"member credential digest was already used",
		)
	}
	if err := ensureCredentialRotationCapacity(
		domain.rotations,
		memberRotationSubject,
		credential.MemberID,
	); err != nil {
		return CredentialRotationResult{}, err
	}
	domain.rotations[rotation.RotationID] = memoryCredentialRotation{
		subjectType:                 memberRotationSubject,
		subjectID:                   credential.MemberID,
		previousAuthorizationDigest: member.AuthorizationDigest,
		newAuthorizationDigest:      rotation.AuthorizationDigest,
		rotatedAtMilliseconds:       nowMilliseconds,
	}
	member.AuthorizationDigest = rotation.AuthorizationDigest
	domain.members[credential.MemberID] = member
	return CredentialRotationResult{
		Acceptance:            AcceptanceAccepted,
		RotationID:            rotation.RotationID,
		AuthorizationDigest:   rotation.AuthorizationDigest,
		RotatedAtMilliseconds: nowMilliseconds,
	}, nil
}

func (s *MemoryStore) CreateSubscriptionAdmission(
	_ context.Context,
	credential AdministrationCredential,
	subscriptionID uuid.UUID,
	registration MemberAdmission,
	nowMilliseconds int64,
) (SubscriptionAdmissionCreateResult, error) {
	if err := registration.Validate(); err != nil {
		return SubscriptionAdmissionCreateResult{}, err
	}
	if registration.RevokedAtMilliseconds != nil ||
		registration.ClaimedAtMilliseconds != nil ||
		registration.ClaimedMemberID != nil {
		return SubscriptionAdmissionCreateResult{}, protocolError(
			CodeInvalidAdmission,
			"new admission already has terminal state",
		)
	}
	if subscriptionID == uuid.Nil {
		return SubscriptionAdmissionCreateResult{}, protocolError(CodeInvalidSubscription, "admission subscription is invalid")
	}
	if registration.CreatedAtMilliseconds > nowMilliseconds ||
		registration.ExpiresAtMilliseconds <= nowMilliseconds {
		return SubscriptionAdmissionCreateResult{}, protocolError(CodeInvalidAdmission, "admission is not currently issuable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	domain, err := s.authorizedDomain(credential)
	if err != nil {
		return SubscriptionAdmissionCreateResult{}, err
	}
	if registration.TenantID != credential.TenantID ||
		registration.DomainID != credential.DomainID {
		return SubscriptionAdmissionCreateResult{}, protocolError(CodeWrongScope, "admission belongs to another domain")
	}
	if existing, ok := domain.admissions[registration.AdmissionID]; ok {
		if admissionCreationEqual(existing, registration) &&
			domain.admissionSubscriptions[registration.AdmissionID] == subscriptionID {
			return SubscriptionAdmissionCreateResult{
				Acceptance: AcceptanceDuplicate,
				Admission: SubscriptionMemberAdmission{
					SubscriptionID: subscriptionID,
					Admission:      existing,
				},
			}, nil
		}
		return SubscriptionAdmissionCreateResult{}, protocolError(CodeAdmissionCollision, "admission ID was reused")
	}
	if len(domain.admissions) >= MaximumRetainedAdmissionCount {
		return SubscriptionAdmissionCreateResult{}, protocolError(
			CodeDomainFull,
			"domain reached its retained admission limit",
		)
	}
	if countOutstandingAdmissions(domain.admissions, nowMilliseconds) >=
		MaximumOutstandingAdmissionCount {
		return SubscriptionAdmissionCreateResult{}, protocolError(
			CodeDomainFull,
			"domain reached its outstanding admission limit",
		)
	}
	if subscription, ok := domain.subscriptions[subscriptionID]; !ok ||
		subscription.Status != SubscriptionActive {
		return SubscriptionAdmissionCreateResult{}, protocolError(CodeSubscriptionNotFound, "active subscription was not found")
	}
	domain.admissions[registration.AdmissionID] = registration
	domain.admissionSubscriptions[registration.AdmissionID] = subscriptionID
	return SubscriptionAdmissionCreateResult{
		Acceptance: AcceptanceAccepted,
		Admission: SubscriptionMemberAdmission{
			SubscriptionID: subscriptionID,
			Admission:      registration,
		},
	}, nil
}

// CreateAdmission remains an internal test helper. Public HTTP uses the
// subscription-aware wrapper and never infers a subscription from admission ID.
func (s *MemoryStore) CreateAdmission(
	ctx context.Context,
	credential AdministrationCredential,
	registration MemberAdmission,
	nowMilliseconds int64,
) (AdmissionCreateResult, error) {
	if err := s.ensureTestSubscription(
		credential, registration.AdmissionID, registration.CreatedAtMilliseconds,
	); err != nil {
		return AdmissionCreateResult{}, err
	}
	result, err := s.CreateSubscriptionAdmission(
		ctx, credential, registration.AdmissionID, registration, nowMilliseconds,
	)
	if err != nil {
		return AdmissionCreateResult{}, err
	}
	return AdmissionCreateResult{
		Acceptance: result.Acceptance,
		Admission:  result.Admission.Admission,
	}, nil
}

func (s *MemoryStore) ClaimSubscriptionAdmission(
	_ context.Context,
	credential AdmissionCredential,
	claim MemberAdmissionClaim,
	nowMilliseconds int64,
) (SubscriptionAdmissionClaimResult, error) {
	if err := claim.Validate(); err != nil {
		return SubscriptionAdmissionClaimResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	domain, ok := s.domains[domainKey{credential.TenantID, credential.DomainID}]
	if !ok {
		return SubscriptionAdmissionClaimResult{}, protocolError(CodeDomainNotFound, "domain was not found")
	}
	admission, ok := domain.admissions[credential.AdmissionID]
	if !ok {
		return SubscriptionAdmissionClaimResult{}, protocolError(CodeAdmissionNotFound, "admission was not found")
	}
	if err := admission.VerifyCredential(credential); err != nil {
		return SubscriptionAdmissionClaimResult{}, err
	}
	if admission.ClaimedMemberID != nil {
		member := domain.members[*admission.ClaimedMemberID]
		if *admission.ClaimedMemberID == claim.MemberID &&
			member.AuthorizationDigest == claim.AuthorizationDigest {
			return SubscriptionAdmissionClaimResult{
				Acceptance: AcceptanceDuplicate,
				Member: SubscriptionMemberRegistration{
					SubscriptionID:     domain.memberSubscriptions[member.MemberID],
					MemberRegistration: member,
				},
			}, nil
		}
		return SubscriptionAdmissionClaimResult{}, protocolError(CodeAdmissionClaimed, "admission was already claimed")
	}
	if err := admission.RequireActive(nowMilliseconds); err != nil {
		return SubscriptionAdmissionClaimResult{}, err
	}
	if _, exists := domain.members[claim.MemberID]; exists {
		return SubscriptionAdmissionClaimResult{}, protocolError(CodeMemberCollision, "member ID was reused")
	}
	if err := ensureMemberCapacity(domain.members, nowMilliseconds); err != nil {
		return SubscriptionAdmissionClaimResult{}, err
	}
	member := MemberRegistration{
		Version:               SchemaVersion,
		TenantID:              admission.TenantID,
		DomainID:              admission.DomainID,
		MemberID:              claim.MemberID,
		AuthorizationDigest:   claim.AuthorizationDigest,
		Capabilities:          append([]Capability(nil), admission.Capabilities...),
		CreatedAtMilliseconds: nowMilliseconds,
		ExpiresAtMilliseconds: admission.MemberExpiresAtMilliseconds,
	}
	if err := member.Validate(); err != nil {
		return SubscriptionAdmissionClaimResult{}, err
	}
	claimedAt := nowMilliseconds
	claimedMemberID := claim.MemberID
	admission.ClaimedAtMilliseconds = &claimedAt
	admission.ClaimedMemberID = &claimedMemberID
	domain.members[member.MemberID] = member
	subscriptionID := domain.admissionSubscriptions[admission.AdmissionID]
	domain.memberSubscriptions[member.MemberID] = subscriptionID
	domain.admissions[admission.AdmissionID] = admission
	return SubscriptionAdmissionClaimResult{
		Acceptance: AcceptanceAccepted,
		Member: SubscriptionMemberRegistration{
			SubscriptionID:     subscriptionID,
			MemberRegistration: member,
		},
	}, nil
}

func (s *MemoryStore) ClaimAdmission(
	ctx context.Context,
	credential AdmissionCredential,
	claim MemberAdmissionClaim,
	nowMilliseconds int64,
) (AdmissionClaimResult, error) {
	result, err := s.ClaimSubscriptionAdmission(ctx, credential, claim, nowMilliseconds)
	if err != nil {
		return AdmissionClaimResult{}, err
	}
	return AdmissionClaimResult{
		Acceptance: result.Acceptance,
		Member:     result.Member.MemberRegistration,
	}, nil
}

func (s *MemoryStore) CollectAdmissions(
	_ context.Context,
	credential AdministrationCredential,
	nowMilliseconds int64,
) (AdmissionCollectionResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	domain, err := s.authorizedDomain(credential)
	if err != nil {
		return AdmissionCollectionResult{}, err
	}
	cutoff := admissionCollectionCutoff(nowMilliseconds)
	eligible := make([]uuid.UUID, 0)
	if nowMilliseconds > AdmissionRecoveryWindowMilliseconds {
		for admissionID, admission := range domain.admissions {
			if admissionCollectibleAt(admission, cutoff) {
				eligible = append(eligible, admissionID)
			}
		}
	}
	sort.Slice(eligible, func(left, right int) bool {
		return eligible[left].String() < eligible[right].String()
	})
	hasMore := len(eligible) > MaximumAdmissionCollectionBatch
	if hasMore {
		eligible = eligible[:MaximumAdmissionCollectionBatch]
	}
	for _, admissionID := range eligible {
		delete(domain.admissions, admissionID)
	}
	return AdmissionCollectionResult{
		CollectedCount:             len(eligible),
		HasMore:                    hasMore,
		EligibleBeforeMilliseconds: cutoff,
	}, nil
}

func (s *MemoryStore) RevokeAdmission(
	_ context.Context,
	credential AdministrationCredential,
	admissionID uuid.UUID,
	nowMilliseconds int64,
) (Acceptance, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	domain, err := s.authorizedDomain(credential)
	if err != nil {
		return "", err
	}
	admission, ok := domain.admissions[admissionID]
	if !ok {
		return "", protocolError(CodeAdmissionNotFound, "admission was not found")
	}
	if admission.ClaimedMemberID != nil {
		return "", protocolError(CodeAdmissionClaimed, "claimed admission cannot be revoked")
	}
	if admission.RevokedAtMilliseconds != nil {
		return AcceptanceDuplicate, nil
	}
	if nowMilliseconds < admission.CreatedAtMilliseconds {
		return "", protocolError(CodeInvalidAdmission, "revocation precedes admission")
	}
	admission.RevokedAtMilliseconds = &nowMilliseconds
	domain.admissions[admissionID] = admission
	return AcceptanceAccepted, nil
}

func (s *MemoryStore) CreateSubscriptionMember(
	_ context.Context,
	credential AdministrationCredential,
	subscriptionID uuid.UUID,
	registration MemberRegistration,
	nowMilliseconds int64,
) (Acceptance, error) {
	if err := registration.Validate(); err != nil {
		return "", err
	}
	if registration.CreatedAtMilliseconds > nowMilliseconds {
		return "", protocolError(CodeInvalidMember, "member starts in the future")
	}
	if subscriptionID == uuid.Nil {
		return "", protocolError(CodeInvalidSubscription, "member subscription is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	domain, err := s.authorizedDomain(credential)
	if err != nil {
		return "", err
	}
	if registration.TenantID != credential.TenantID ||
		registration.DomainID != credential.DomainID {
		return "", protocolError(CodeWrongScope, "member belongs to another domain")
	}
	if existing, ok := domain.members[registration.MemberID]; ok {
		if memberEqual(existing, registration) &&
			domain.memberSubscriptions[registration.MemberID] == subscriptionID {
			return AcceptanceDuplicate, nil
		}
		return "", protocolError(CodeMemberCollision, "member ID was reused")
	}
	if registration.ExpiresAtMilliseconds != nil &&
		*registration.ExpiresAtMilliseconds <= nowMilliseconds {
		return "", protocolError(CodeInvalidMember, "member is not currently issuable")
	}
	if err := ensureMemberCapacity(domain.members, nowMilliseconds); err != nil {
		return "", err
	}
	if subscription, ok := domain.subscriptions[subscriptionID]; !ok ||
		subscription.Status != SubscriptionActive {
		return "", protocolError(CodeSubscriptionNotFound, "active subscription was not found")
	}
	domain.members[registration.MemberID] = registration
	domain.memberSubscriptions[registration.MemberID] = subscriptionID
	return AcceptanceAccepted, nil
}

func (s *MemoryStore) CreateMember(
	ctx context.Context,
	credential AdministrationCredential,
	registration MemberRegistration,
	nowMilliseconds int64,
) (Acceptance, error) {
	if err := s.ensureTestSubscription(
		credential, registration.MemberID, registration.CreatedAtMilliseconds,
	); err != nil {
		return "", err
	}
	return s.CreateSubscriptionMember(
		ctx, credential, registration.MemberID, registration, nowMilliseconds,
	)
}

func (s *MemoryStore) ensureTestSubscription(
	credential AdministrationCredential,
	subscriptionID uuid.UUID,
	createdAtMilliseconds int64,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	domain, err := s.authorizedDomain(credential)
	if err != nil {
		return err
	}
	if domain.subscriptions[subscriptionID].SubscriptionID == uuid.Nil {
		domain.subscriptions[subscriptionID] = Subscription{
			Version: SchemaVersion, TenantID: credential.TenantID,
			DomainID: credential.DomainID, SubscriptionID: subscriptionID,
			Status: SubscriptionActive, CreatedAtMilliseconds: createdAtMilliseconds,
			UpdatedAtMilliseconds: createdAtMilliseconds,
		}
	}
	return nil
}

func memoryRotationRetryResult(
	existing memoryCredentialRotation,
	subjectType string,
	subjectID uuid.UUID,
	actualDigest string,
	rotation CredentialRotation,
) (CredentialRotationResult, error) {
	if actualDigest != existing.previousAuthorizationDigest &&
		actualDigest != existing.newAuthorizationDigest {
		return CredentialRotationResult{}, protocolError(
			CodeUnauthorized,
			"credential is not authorized for this rotation",
		)
	}
	if existing.subjectType != subjectType || existing.subjectID != subjectID ||
		existing.newAuthorizationDigest != rotation.AuthorizationDigest {
		return CredentialRotationResult{}, protocolError(
			CodeCredentialRotationCollision,
			"credential rotation ID was reused",
		)
	}
	return CredentialRotationResult{
		Acceptance:            AcceptanceDuplicate,
		RotationID:            rotation.RotationID,
		AuthorizationDigest:   existing.newAuthorizationDigest,
		RotatedAtMilliseconds: existing.rotatedAtMilliseconds,
	}, nil
}

func rotationDigestWasUsed(
	rotations map[uuid.UUID]memoryCredentialRotation,
	subjectType string,
	subjectID uuid.UUID,
	digest string,
) bool {
	for _, rotation := range rotations {
		if rotation.subjectType == subjectType && rotation.subjectID == subjectID &&
			(rotation.previousAuthorizationDigest == digest ||
				rotation.newAuthorizationDigest == digest) {
			return true
		}
	}
	return false
}

func ensureCredentialRotationCapacity(
	rotations map[uuid.UUID]memoryCredentialRotation,
	subjectType string,
	subjectID uuid.UUID,
) error {
	if len(rotations) >= MaximumCredentialRotationsPerDomain {
		return protocolError(CodeDomainFull, "domain reached its credential rotation limit")
	}
	subjectCount := 0
	for _, rotation := range rotations {
		if rotation.subjectType == subjectType && rotation.subjectID == subjectID {
			subjectCount++
		}
	}
	if subjectCount >= MaximumCredentialRotationsPerSubject {
		return protocolError(CodeDomainFull, "subject reached its credential rotation limit")
	}
	return nil
}

func ensureMemberCapacity(
	members map[uuid.UUID]MemberRegistration,
	nowMilliseconds int64,
) error {
	if len(members) >= MaximumRetainedMemberCountPerDomain {
		return protocolError(CodeDomainFull, "domain reached its retained member limit")
	}
	activeCount := 0
	for _, member := range members {
		if memberActiveAt(member, nowMilliseconds) {
			activeCount++
		}
	}
	if activeCount >= MaximumActiveMemberCountPerDomain {
		return protocolError(CodeDomainFull, "domain reached its active member limit")
	}
	return nil
}

func memberActiveAt(member MemberRegistration, nowMilliseconds int64) bool {
	return nowMilliseconds >= member.CreatedAtMilliseconds &&
		(member.ExpiresAtMilliseconds == nil || nowMilliseconds < *member.ExpiresAtMilliseconds) &&
		(member.RevokedAtMilliseconds == nil || nowMilliseconds < *member.RevokedAtMilliseconds)
}

func countOutstandingAdmissions(
	admissions map[uuid.UUID]MemberAdmission,
	nowMilliseconds int64,
) int {
	count := 0
	for _, admission := range admissions {
		if admission.ClaimedAtMilliseconds == nil &&
			(admission.RevokedAtMilliseconds == nil || nowMilliseconds < *admission.RevokedAtMilliseconds) &&
			nowMilliseconds >= admission.CreatedAtMilliseconds &&
			nowMilliseconds < admission.ExpiresAtMilliseconds {
			count++
		}
	}
	return count
}

func admissionCollectionCutoff(nowMilliseconds int64) int64 {
	if nowMilliseconds <= AdmissionRecoveryWindowMilliseconds {
		return 0
	}
	return nowMilliseconds - AdmissionRecoveryWindowMilliseconds
}

func admissionCollectibleAt(admission MemberAdmission, cutoff int64) bool {
	terminalAt := admission.ExpiresAtMilliseconds
	if admission.RevokedAtMilliseconds != nil {
		terminalAt = *admission.RevokedAtMilliseconds
	}
	if admission.ClaimedAtMilliseconds != nil {
		terminalAt = *admission.ClaimedAtMilliseconds
	}
	return terminalAt <= cutoff
}

func (s *MemoryStore) RevokeMember(
	_ context.Context,
	credential AdministrationCredential,
	memberID uuid.UUID,
	nowMilliseconds int64,
) (Acceptance, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	domain, err := s.authorizedDomain(credential)
	if err != nil {
		return "", err
	}
	member, ok := domain.members[memberID]
	if !ok {
		return "", protocolError(CodeMemberNotFound, "member was not found")
	}
	if member.RevokedAtMilliseconds != nil {
		return AcceptanceDuplicate, nil
	}
	if nowMilliseconds < member.CreatedAtMilliseconds {
		return "", protocolError(CodeInvalidMember, "revocation precedes membership")
	}
	member.RevokedAtMilliseconds = &nowMilliseconds
	domain.members[memberID] = member
	return AcceptanceAccepted, nil
}

func (s *MemoryStore) ChangeMemberCapabilities(
	_ context.Context,
	credential AdministrationCredential,
	change MemberCapabilityChange,
	nowMilliseconds int64,
) (MemberCapabilityChangeResult, error) {
	if err := change.Validate(); err != nil {
		return MemberCapabilityChangeResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	domain, err := s.authorizedDomain(credential)
	if err != nil {
		return MemberCapabilityChangeResult{}, err
	}
	if existing, found := domain.capabilityChanges[change.RetryID]; found {
		if !reflect.DeepEqual(existing.request, change) {
			return MemberCapabilityChangeResult{}, protocolError(
				CodeMemberCapabilityCollision, "member capability retry ID was reused",
			)
		}
		result := existing.result
		result.Acceptance = AcceptanceDuplicate
		return result, nil
	}
	member, found := domain.members[change.MemberID]
	if !found {
		return MemberCapabilityChangeResult{}, protocolError(CodeMemberNotFound, "member was not found")
	}
	if !memberActiveAt(member, nowMilliseconds) {
		if member.RevokedAtMilliseconds != nil && nowMilliseconds >= *member.RevokedAtMilliseconds {
			return MemberCapabilityChangeResult{}, protocolError(CodeMemberRevoked, "member is revoked")
		}
		return MemberCapabilityChangeResult{}, protocolError(CodeMemberExpired, "member is not active")
	}
	if change.ChangedAtMilliseconds > nowMilliseconds ||
		change.ChangedAtMilliseconds < member.CreatedAtMilliseconds {
		return MemberCapabilityChangeResult{}, protocolError(CodeInvalidMember, "member capability change time is invalid")
	}
	if !capabilitiesEqual(member.Capabilities, change.PreviousCapabilities) {
		return MemberCapabilityChangeResult{}, protocolError(
			CodeMemberCapabilityCollision, "member capabilities changed concurrently",
		)
	}
	member.Capabilities = append([]Capability(nil), change.NextCapabilities...)
	domain.members[member.MemberID] = member
	result := MemberCapabilityChangeResult{
		Acceptance: AcceptanceAccepted, RetryID: change.RetryID, MemberID: change.MemberID,
		PreviousCapabilities:  append([]Capability(nil), change.PreviousCapabilities...),
		CurrentCapabilities:   append([]Capability(nil), change.NextCapabilities...),
		ChangedAtMilliseconds: change.ChangedAtMilliseconds,
	}
	domain.capabilityChanges[change.RetryID] = memoryMemberCapabilityChange{
		request: change, result: result,
	}
	return result, nil
}

func (s *MemoryStore) CreateSubscription(
	_ context.Context,
	credential AdministrationCredential,
	request SubscriptionCreateRequest,
) (SubscriptionCreateResponse, error) {
	if err := request.Validate(); err != nil {
		return SubscriptionCreateResponse{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	domain, err := s.authorizedDomain(credential)
	if err != nil {
		return SubscriptionCreateResponse{}, err
	}
	if existingRequest, ok := domain.subscriptionCreates[request.RetryID]; ok {
		if existingRequest == request {
			return SubscriptionCreateResponse{
				Acceptance: AcceptanceDuplicate, RetryID: request.RetryID,
				Subscription: domain.subscriptions[request.SubscriptionID],
			}, nil
		}
		return SubscriptionCreateResponse{}, protocolError(CodeSubscriptionCollision, "subscription retry ID was reused")
	}
	if _, ok := domain.subscriptions[request.SubscriptionID]; ok {
		return SubscriptionCreateResponse{}, protocolError(CodeSubscriptionCollision, "subscription ID was reused")
	}
	if request.CreatedAtMilliseconds < domain.registration.CreatedAtMilliseconds {
		return SubscriptionCreateResponse{}, protocolError(CodeInvalidSubscription, "subscription predates its domain")
	}
	subscription := Subscription{
		Version: SchemaVersion, TenantID: credential.TenantID, DomainID: credential.DomainID,
		SubscriptionID: request.SubscriptionID, Status: SubscriptionActive,
		CreatedAtMilliseconds: request.CreatedAtMilliseconds,
		UpdatedAtMilliseconds: request.CreatedAtMilliseconds,
	}
	subscription.StartCursor = latestCheckpointStartCursor(domain)
	domain.subscriptions[request.SubscriptionID] = subscription
	domain.subscriptionCreates[request.RetryID] = request
	return SubscriptionCreateResponse{
		Acceptance: AcceptanceAccepted, RetryID: request.RetryID, Subscription: subscription,
	}, nil
}

func (s *MemoryStore) GetSubscription(
	_ context.Context,
	credential AdministrationCredential,
	subscriptionID uuid.UUID,
) (Subscription, error) {
	if subscriptionID == uuid.Nil {
		return Subscription{}, protocolError(CodeInvalidSubscription, "subscription ID is invalid")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	domain, err := s.authorizedDomain(credential)
	if err != nil {
		return Subscription{}, err
	}
	subscription, ok := domain.subscriptions[subscriptionID]
	if !ok {
		return Subscription{}, protocolError(CodeSubscriptionNotFound, "subscription was not found")
	}
	return subscription, nil
}

func (s *MemoryStore) ChangeSubscriptionStatus(
	_ context.Context,
	credential AdministrationCredential,
	subscriptionID uuid.UUID,
	request SubscriptionStatusChangeRequest,
) (SubscriptionStatusChangeResponse, error) {
	if subscriptionID == uuid.Nil {
		return SubscriptionStatusChangeResponse{}, protocolError(CodeInvalidSubscription, "subscription ID is invalid")
	}
	if err := request.Validate(); err != nil {
		return SubscriptionStatusChangeResponse{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	domain, err := s.authorizedDomain(credential)
	if err != nil {
		return SubscriptionStatusChangeResponse{}, err
	}
	if existing, ok := domain.subscriptionChanges[request.RetryID]; ok {
		if existing.subscriptionID == subscriptionID && existing.request == request {
			return SubscriptionStatusChangeResponse{
				Acceptance: AcceptanceDuplicate, RetryID: request.RetryID,
				Subscription: existing.result,
			}, nil
		}
		return SubscriptionStatusChangeResponse{}, protocolError(CodeSubscriptionCollision, "subscription status retry ID was reused")
	}
	subscription, ok := domain.subscriptions[subscriptionID]
	if !ok {
		return SubscriptionStatusChangeResponse{}, protocolError(CodeSubscriptionNotFound, "subscription was not found")
	}
	if subscription.Status == SubscriptionRevoked {
		return SubscriptionStatusChangeResponse{}, protocolError(CodeSubscriptionNotFound, "revoked subscription cannot be changed")
	}
	if request.ChangedAtMilliseconds < subscription.CreatedAtMilliseconds ||
		request.ChangedAtMilliseconds < subscription.UpdatedAtMilliseconds {
		return SubscriptionStatusChangeResponse{}, protocolError(CodeInvalidSubscription, "subscription update is out of order")
	}
	subscription.Status = request.Status
	if request.Status == SubscriptionRebootstrapRequired {
		subscription.StartCursor = latestCheckpointStartCursor(domain)
	} else {
		subscription.StartCursor = nil
	}
	subscription.UpdatedAtMilliseconds = request.ChangedAtMilliseconds
	domain.subscriptions[subscriptionID] = subscription
	domain.subscriptionChanges[request.RetryID] = memorySubscriptionChange{
		subscriptionID: subscriptionID, request: request, result: subscription,
	}
	return SubscriptionStatusChangeResponse{
		Acceptance: AcceptanceAccepted, RetryID: request.RetryID, Subscription: subscription,
	}, nil
}

// RequestSubscriptionRebootstrap lets a member fence only its own replica at
// the latest activated checkpoint boundary.  The caller can continue to read
// and acknowledge the retained checkpoint tail, but cannot publish until it
// completes the corresponding recovery.
func (s *MemoryStore) RequestSubscriptionRebootstrap(
	_ context.Context,
	credential Credential,
	request SubscriptionRebootstrapRequest,
	nowMilliseconds int64,
) (SubscriptionRebootstrapResponse, error) {
	if err := request.Validate(); err != nil {
		return SubscriptionRebootstrapResponse{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	domain, err := s.authorizedMember(credential, CapabilityFetchMessage, nowMilliseconds)
	if err != nil {
		return SubscriptionRebootstrapResponse{}, err
	}
	subscription, err := readableMemberSubscription(domain, credential.MemberID)
	if err != nil {
		return SubscriptionRebootstrapResponse{}, err
	}
	if existing, ok := domain.rebootstrapRequests[request.RetryID]; ok {
		if existing.subscriptionID == subscription.SubscriptionID && existing.request == request {
			return SubscriptionRebootstrapResponse{
				Acceptance: AcceptanceDuplicate, RetryID: request.RetryID,
				CheckpointID: request.CheckpointID, RootMessageID: request.RootMessageID,
				Subscription: existing.result,
			}, nil
		}
		return SubscriptionRebootstrapResponse{}, protocolError(CodeSubscriptionCollision, "subscription rebootstrap retry ID was reused")
	}
	if subscription.Status == SubscriptionRevoked {
		return SubscriptionRebootstrapResponse{}, protocolError(CodeSubscriptionNotFound, "revoked subscription cannot rebootstrap")
	}
	checkpoint := domain.checkpoints[request.CheckpointID]
	if checkpoint == nil || checkpoint.state != "activated" ||
		!checkpointRetainsMessage(checkpoint, request.RootMessageID) {
		return SubscriptionRebootstrapResponse{}, protocolError(CodeCheckpointUnavailable, "authorized recovery checkpoint/root is unavailable")
	}
	if subscription.Status == SubscriptionRebootstrapRequired {
		if subscription.StartCursor == nil {
			return SubscriptionRebootstrapResponse{}, protocolError(CodeInvalidSubscription, "rebootstrap subscription has no checkpoint cursor")
		}
		startSequence, err := DecodeCursor(*subscription.StartCursor)
		selectionMatches, selectionExists := rebootstrapSelectionMatches(
			domain, subscription.SubscriptionID, request,
		)
		checkpointIsLatest := len(domain.activatedCheckpoints) > 0 &&
			domain.activatedCheckpoints[len(domain.activatedCheckpoints)-1] == request.CheckpointID
		if err != nil || startSequence != checkpoint.startSequence ||
			!selectionMatches || (!selectionExists && !checkpointIsLatest) {
			return SubscriptionRebootstrapResponse{}, protocolError(CodeSubscriptionCollision, "subscription recovery is already bound to another checkpoint/root")
		}
		domain.rebootstrapRequests[request.RetryID] = memorySubscriptionRebootstrapRequest{
			subscriptionID: subscription.SubscriptionID, request: request, result: subscription,
		}
		return SubscriptionRebootstrapResponse{
			Acceptance: AcceptanceAccepted, RetryID: request.RetryID,
			CheckpointID: request.CheckpointID, RootMessageID: request.RootMessageID,
			Subscription: subscription,
		}, nil
	}
	if len(domain.activatedCheckpoints) == 0 ||
		domain.activatedCheckpoints[len(domain.activatedCheckpoints)-1] != request.CheckpointID {
		return SubscriptionRebootstrapResponse{}, protocolError(CodeCheckpointUnavailable, "authorized recovery checkpoint is not the latest activated checkpoint")
	}
	startCursor := EncodeCursor(checkpoint.startSequence)
	for _, message := range domain.messages {
		if message.message.Sequence > checkpoint.startSequence {
			delete(message.acknowledgments, subscription.SubscriptionID)
		}
	}
	subscription.Status = SubscriptionRebootstrapRequired
	subscription.StartCursor = &startCursor
	subscription.UpdatedAtMilliseconds = nowMilliseconds
	domain.subscriptions[subscription.SubscriptionID] = subscription
	domain.rebootstrapRequests[request.RetryID] = memorySubscriptionRebootstrapRequest{
		subscriptionID: subscription.SubscriptionID, request: request, result: subscription,
	}
	return SubscriptionRebootstrapResponse{
		Acceptance: AcceptanceAccepted, RetryID: request.RetryID,
		CheckpointID: request.CheckpointID, RootMessageID: request.RootMessageID,
		Subscription: subscription,
	}, nil
}

// CompleteSubscriptionRebootstrap restores publication only after every
// readable envelope in the recovery tail has an applied receipt for this
// subscription. This includes messages the same subscription published before
// it entered recovery. The relay checks delivery state only; it never parses
// the encrypted content.
func (s *MemoryStore) CompleteSubscriptionRebootstrap(
	_ context.Context,
	credential Credential,
	completion SubscriptionRebootstrapCompletion,
	nowMilliseconds int64,
) (SubscriptionRebootstrapCompletionResponse, error) {
	if err := completion.Validate(); err != nil {
		return SubscriptionRebootstrapCompletionResponse{}, err
	}
	throughSequence, err := DecodeCursor(completion.CompletedThroughCursor)
	if err != nil {
		return SubscriptionRebootstrapCompletionResponse{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	domain, err := s.authorizedMember(credential, CapabilityAcknowledgeMessage, nowMilliseconds)
	if err != nil {
		return SubscriptionRebootstrapCompletionResponse{}, err
	}
	refreshMemoryFence(domain, nowMilliseconds)
	subscription, err := readableMemberSubscription(domain, credential.MemberID)
	if err != nil {
		return SubscriptionRebootstrapCompletionResponse{}, err
	}
	if existing, ok := domain.rebootstrapCompletions[completion.RetryID]; ok {
		if existing.subscriptionID == subscription.SubscriptionID && existing.request == completion {
			return SubscriptionRebootstrapCompletionResponse{
				Acceptance: AcceptanceDuplicate, RetryID: completion.RetryID,
				RequestRetryID: completion.RequestRetryID,
				CheckpointID:   completion.CheckpointID, RootMessageID: completion.RootMessageID,
				Subscription: existing.result,
			}, nil
		}
		return SubscriptionRebootstrapCompletionResponse{}, protocolError(CodeSubscriptionCollision, "subscription rebootstrap completion retry ID was reused")
	}
	if subscription.Status != SubscriptionRebootstrapRequired || subscription.StartCursor == nil {
		return SubscriptionRebootstrapCompletionResponse{}, protocolError(CodeInvalidSubscription, "subscription is not awaiting rebootstrap completion")
	}
	recoveryRequest, ok := domain.rebootstrapRequests[completion.RequestRetryID]
	if !ok || recoveryRequest.subscriptionID != subscription.SubscriptionID ||
		recoveryRequest.request.CheckpointID != completion.CheckpointID ||
		recoveryRequest.request.RootMessageID != completion.RootMessageID {
		return SubscriptionRebootstrapCompletionResponse{}, protocolError(CodeSubscriptionCollision, "rebootstrap completion does not match its authorized checkpoint/root")
	}
	startSequence, err := DecodeCursor(*subscription.StartCursor)
	if err != nil {
		return SubscriptionRebootstrapCompletionResponse{}, err
	}
	if throughSequence < startSequence || throughSequence > domain.nextSequence {
		return SubscriptionRebootstrapCompletionResponse{}, protocolError(CodeInvalidCursor, "rebootstrap completion cursor is outside the retained history")
	}
	for _, message := range domain.messages {
		if message.message.Sequence <= startSequence || message.message.Sequence > throughSequence {
			continue
		}
		if message.checkpointFenceID != nil {
			fence := domain.checkpointFences[*message.checkpointFenceID]
			if fence == nil || fence.state.Status != CheckpointFenceActivated {
				continue
			}
		}
		if message.acknowledgments[subscription.SubscriptionID] != AcknowledgmentApplied {
			return SubscriptionRebootstrapCompletionResponse{}, protocolError(CodeRebootstrapIncomplete, "rebootstrap tail has not been durably applied")
		}
	}
	subscription.Status = SubscriptionActive
	subscription.StartCursor = nil
	subscription.UpdatedAtMilliseconds = nowMilliseconds
	domain.subscriptions[subscription.SubscriptionID] = subscription
	domain.rebootstrapCompletions[completion.RetryID] = memorySubscriptionRebootstrapCompletion{
		subscriptionID:        subscription.SubscriptionID,
		recoveryStartSequence: startSequence,
		request:               completion,
		result:                subscription,
	}
	return SubscriptionRebootstrapCompletionResponse{
		Acceptance: AcceptanceAccepted, RetryID: completion.RetryID,
		RequestRetryID: completion.RequestRetryID,
		CheckpointID:   completion.CheckpointID, RootMessageID: completion.RootMessageID,
		Subscription: subscription,
	}, nil
}

func checkpointRetainsMessage(checkpoint *memoryCheckpoint, messageID uuid.UUID) bool {
	for _, retainedID := range checkpoint.candidate.RetainedMessageIDs {
		if retainedID == messageID {
			return true
		}
	}
	return false
}

func rebootstrapSelectionMatches(
	domain *memoryDomain,
	subscriptionID uuid.UUID,
	request SubscriptionRebootstrapRequest,
) (matches bool, exists bool) {
	for _, existing := range domain.rebootstrapRequests {
		if existing.subscriptionID != subscriptionID {
			continue
		}
		exists = true
		if existing.request.CheckpointID != request.CheckpointID ||
			existing.request.RootMessageID != request.RootMessageID {
			return false, true
		}
	}
	return true, exists
}

func (s *MemoryStore) RevokeTenantMemberships(
	_ context.Context,
	credential TenantCredential,
	revocation TenantMembershipRevocation,
) (TenantMembershipRevocationResult, error) {
	if err := revocation.Validate(); err != nil {
		return TenantMembershipRevocationResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tenant := s.tenants[credential.TenantID]
	if tenant == nil {
		return TenantMembershipRevocationResult{}, protocolError(CodeTenantNotFound, "tenant was not found")
	}
	if err := tenant.registration.Authorize(credential); err != nil {
		return TenantMembershipRevocationResult{}, err
	}
	if existing, ok := tenant.membershipRevocations[revocation.RetryID]; ok {
		if tenantMembershipRevocationEqual(existing, revocation) {
			return TenantMembershipRevocationResult{
				Acceptance: AcceptanceDuplicate, RetryID: existing.RetryID,
				RevokedAtMilliseconds: existing.RevokedAtMilliseconds,
				Memberships:           append([]TenantMembershipRevocationItem(nil), existing.Memberships...),
			}, nil
		}
		return TenantMembershipRevocationResult{}, protocolError(CodeMemberCollision, "tenant membership revocation retry ID was reused")
	}
	// Validate the complete target set before changing any domain.
	for _, target := range revocation.Memberships {
		domain := s.domains[domainKey{credential.TenantID, target.DomainID}]
		if domain == nil {
			return TenantMembershipRevocationResult{}, protocolError(CodeDomainNotFound, "revocation domain was not found")
		}
		member, memberFound := domain.members[target.MemberID]
		subscription, subscriptionFound := domain.subscriptions[target.SubscriptionID]
		if !memberFound || domain.memberSubscriptions[target.MemberID] != target.SubscriptionID {
			return TenantMembershipRevocationResult{}, protocolError(CodeMemberNotFound, "revocation member was not found")
		}
		if !subscriptionFound || subscription.Status == SubscriptionRevoked {
			return TenantMembershipRevocationResult{}, protocolError(CodeSubscriptionNotFound, "active revocation subscription was not found")
		}
		if member.RevokedAtMilliseconds != nil {
			return TenantMembershipRevocationResult{}, protocolError(CodeMemberRevoked, "revocation member was already revoked")
		}
		if revocation.RevokedAtMilliseconds < member.CreatedAtMilliseconds ||
			revocation.RevokedAtMilliseconds < subscription.CreatedAtMilliseconds ||
			revocation.RevokedAtMilliseconds < subscription.UpdatedAtMilliseconds {
			return TenantMembershipRevocationResult{}, protocolError(CodeInvalidMember, "tenant membership revocation is out of order")
		}
	}
	for _, target := range revocation.Memberships {
		domain := s.domains[domainKey{credential.TenantID, target.DomainID}]
		member := domain.members[target.MemberID]
		member.RevokedAtMilliseconds = &revocation.RevokedAtMilliseconds
		domain.members[target.MemberID] = member
		subscription := domain.subscriptions[target.SubscriptionID]
		subscription.Status = SubscriptionRevoked
		subscription.StartCursor = nil
		subscription.UpdatedAtMilliseconds = revocation.RevokedAtMilliseconds
		domain.subscriptions[target.SubscriptionID] = subscription
	}
	tenant.membershipRevocations[revocation.RetryID] = TenantMembershipRevocation{
		Version: revocation.Version, RetryID: revocation.RetryID,
		RevokedAtMilliseconds: revocation.RevokedAtMilliseconds,
		Memberships:           append([]TenantMembershipRevocationItem(nil), revocation.Memberships...),
	}
	return TenantMembershipRevocationResult{
		Acceptance: AcceptanceAccepted, RetryID: revocation.RetryID,
		RevokedAtMilliseconds: revocation.RevokedAtMilliseconds,
		Memberships:           append([]TenantMembershipRevocationItem(nil), revocation.Memberships...),
	}, nil
}

func tenantMembershipRevocationEqual(left, right TenantMembershipRevocation) bool {
	if left.Version != right.Version || left.RetryID != right.RetryID ||
		left.RevokedAtMilliseconds != right.RevokedAtMilliseconds ||
		len(left.Memberships) != len(right.Memberships) {
		return false
	}
	for index := range left.Memberships {
		if left.Memberships[index] != right.Memberships[index] {
			return false
		}
	}
	return true
}

func (s *MemoryStore) GetTenantStatus(_ context.Context, credential TenantCredential) (TenantStatus, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tenant := s.tenants[credential.TenantID]
	if tenant == nil {
		return TenantStatus{}, protocolError(CodeTenantNotFound, "tenant was not found")
	}
	if err := tenant.registration.Authorize(credential); err != nil {
		return TenantStatus{}, err
	}
	messages, messageBytes, blobs, blobBytes := s.tenantUsageLocked(credential.TenantID)
	domains := 0
	for key := range s.domains {
		if key.tenantID == credential.TenantID {
			domains++
		}
	}
	return TenantStatus{
		TenantID: credential.TenantID, DomainCount: int64(domains),
		AggregateMessageCount: int64(messages), AggregateMessageByteCount: messageBytes,
		AggregateBlobCount: int64(blobs), AggregateBlobByteCount: blobBytes,
		ReservedBlobCount:     s.tenantReservedBlobCountLocked(credential.TenantID),
		ReservedBlobByteCount: s.tenantReservedBlobBytesLocked(credential.TenantID),
		Quota: TenantQuota{
			MaximumDomainCount:               tenant.registration.MaximumDomainCount,
			MaximumAggregateMessageCount:     tenant.registration.MaximumAggregateMessageCount,
			MaximumAggregateMessageByteCount: tenant.registration.MaximumAggregateMessageByteCount,
			MaximumAggregateBlobCount:        tenant.registration.MaximumAggregateBlobCount,
			MaximumAggregateBlobByteCount:    tenant.registration.MaximumAggregateBlobByteCount,
		},
	}, nil
}

func (s *MemoryStore) GetDomainStatus(_ context.Context, credential AdministrationCredential) (DomainStatus, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	domain, err := s.authorizedDomain(credential)
	if err != nil {
		return DomainStatus{}, err
	}
	active := int64(0)
	for _, subscription := range domain.subscriptions {
		if subscription.Status == SubscriptionActive {
			active++
		}
	}
	var oldest *string
	if len(domain.messages) > 0 {
		cursor := EncodeCursor(domain.messages[0].message.Sequence - 1)
		oldest = &cursor
	}
	var latestCheckpointID *uuid.UUID
	if len(domain.activatedCheckpoints) > 0 {
		value := domain.activatedCheckpoints[len(domain.activatedCheckpoints)-1]
		latestCheckpointID = &value
	}
	return DomainStatus{
		TenantID: credential.TenantID, DomainID: credential.DomainID,
		MessageCount: int64(len(domain.messages)), MessageByteCount: domain.messageBytes,
		BlobCount: int64(len(domain.blobs)), BlobByteCount: domain.blobBytes,
		ReservedBlobCount:       domain.reservedBlobCount,
		ReservedBlobByteCount:   domain.reservedBlobBytes,
		ActiveSubscriptionCount: active, OldestUncollectedCursor: oldest,
		LatestActivatedCheckpointID: latestCheckpointID,
		Quota: DomainQuota{
			MaximumMessageCount:     domain.registration.MaximumMessageCount,
			MaximumMessageByteCount: domain.registration.MaximumMessageByteCount,
			MaximumBlobCount:        domain.registration.MaximumBlobCount,
			MaximumBlobByteCount:    domain.registration.MaximumBlobByteCount,
		},
	}, nil
}

func (s *MemoryStore) Publish(
	_ context.Context,
	credential Credential,
	envelope Envelope,
	nowMilliseconds int64,
) (PublishResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	domain, err := s.authorizedMember(
		credential,
		CapabilityPublishMessage,
		nowMilliseconds,
	)
	if err != nil {
		return PublishResult{}, err
	}
	if err := envelope.ValidateForPublish(credential); err != nil {
		return PublishResult{}, err
	}
	publisherSubscription, err := activeMemberSubscription(domain, credential.MemberID)
	if err != nil {
		return PublishResult{}, err
	}
	if existing, ok := domain.messageByID[envelope.MessageID]; ok {
		if existing.publisherMember == credential.MemberID &&
			existing.message.Envelope == envelope {
			return PublishResult{
				Acceptance: AcceptanceDuplicate,
				Sequence:   existing.message.Sequence,
			}, nil
		}
		return PublishResult{}, protocolError(
			CodeMessageCollision,
			"message ID was reused with different content",
		)
	}
	if tombstone, ok := domain.fenceMessageTombstones[envelope.MessageID]; ok {
		digest, digestErr := envelope.ReferenceDigest()
		if digestErr != nil {
			return PublishResult{}, digestErr
		}
		if tombstone.publisherMember == credential.MemberID && tombstone.digest == digest {
			return PublishResult{Acceptance: AcceptanceDuplicate, Sequence: tombstone.sequence}, nil
		}
		return PublishResult{}, protocolError(CodeMessageCollision, "message ID was reused with different content")
	}
	if err := memoryFenceAllowsWrite(domain, publisherSubscription.SubscriptionID, nowMilliseconds); err != nil {
		return PublishResult{}, err
	}
	if len(domain.messages) >= domain.registration.MaximumMessageCount {
		return PublishResult{}, protocolError(CodeDomainFull, "domain reached its message limit")
	}
	ciphertextByteCount, err := envelope.CiphertextByteCount()
	if err != nil {
		return PublishResult{}, err
	}
	if ciphertextByteCount > domain.registration.MaximumMessageByteCount-domain.messageBytes {
		return PublishResult{}, protocolError(CodeDomainFull, "domain reached its message-byte limit")
	}
	if err := s.ensureTenantMessageCapacityLocked(
		credential.TenantID, ciphertextByteCount,
	); err != nil {
		return PublishResult{}, err
	}
	domain.nextSequence++
	stored := &memoryMessage{
		message: Message{
			Sequence: domain.nextSequence,
			Envelope: envelope,
		},
		publisherMember:       credential.MemberID,
		byteCount:             ciphertextByteCount,
		publisherSubscription: publisherSubscription.SubscriptionID,
		acknowledgments:       make(map[uuid.UUID]AcknowledgmentStage),
	}
	if fence := memoryActiveFenceForSubscription(domain, publisherSubscription.SubscriptionID); fence != nil {
		fenceID := fence.state.FenceID
		stored.checkpointFenceID = &fenceID
	}
	domain.messages = append(domain.messages, stored)
	domain.messageByID[envelope.MessageID] = stored
	domain.messageBytes += ciphertextByteCount
	return PublishResult{
		Acceptance: AcceptanceAccepted,
		Sequence:   stored.message.Sequence,
	}, nil
}

func (s *MemoryStore) Fetch(
	_ context.Context,
	credential Credential,
	afterSequence uint64,
	limit int,
	nowMilliseconds int64,
) (FetchResult, error) {
	if limit <= 0 || limit > MaximumPageSize || afterSequence > MaximumSequence {
		return FetchResult{}, protocolError(CodeInvalidCursor, "page limit is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	domain, err := s.authorizedMember(
		credential,
		CapabilityFetchMessage,
		nowMilliseconds,
	)
	if err != nil {
		return FetchResult{}, err
	}
	refreshMemoryFence(domain, nowMilliseconds)
	subscription, err := readableMemberSubscription(domain, credential.MemberID)
	if err != nil {
		return FetchResult{}, err
	}
	if subscription.StartCursor != nil {
		start, cursorErr := DecodeCursor(*subscription.StartCursor)
		if cursorErr != nil {
			return FetchResult{}, cursorErr
		}
		if subscription.Status == SubscriptionRebootstrapRequired {
			// The caller's old cursor belongs to a replica that has been
			// discarded.  The authoritative checkpoint boundary wins.
			afterSequence = start
		} else if start > afterSequence {
			afterSequence = start
		}
	}
	result := FetchResult{Messages: make([]Message, 0, limit)}
	visibleHighWatermark := domain.nextSequence
	for _, fence := range domain.checkpointFences {
		if fence.state.Status == CheckpointFenceActive {
			if boundary, cursorErr := DecodeCursor(fence.state.BoundaryCursor); cursorErr == nil && boundary < visibleHighWatermark {
				visibleHighWatermark = boundary
			}
		}
	}
	for _, stored := range domain.messages {
		if stored.message.Sequence <= afterSequence {
			continue
		}
		if memorySubscriptionHasAuthorizedRecovery(domain, subscription) &&
			stored.acknowledgments[subscription.SubscriptionID] == AcknowledgmentApplied {
			continue
		}
		if stored.publisherSubscription == subscription.SubscriptionID &&
			!memoryOwnMessageIsInAuthorizedRecovery(domain, subscription, stored) {
			continue
		}
		if stored.checkpointFenceID != nil {
			fence := domain.checkpointFences[*stored.checkpointFenceID]
			if fence == nil || fence.state.Status != CheckpointFenceActivated {
				continue
			}
		}
		result.Messages = append(result.Messages, stored.message)
		result.NextSequence = stored.message.Sequence
		if len(result.Messages) == limit {
			return result, nil
		}
	}
	result.NextSequence = visibleHighWatermark
	if afterSequence > result.NextSequence {
		result.NextSequence = afterSequence
	}
	return result, nil
}

func (s *MemoryStore) GetMessage(
	_ context.Context,
	credential Credential,
	messageID uuid.UUID,
	nowMilliseconds int64,
) (Message, error) {
	if messageID == uuid.Nil {
		return Message{}, protocolError(CodeMessageNotFound, "message was not found")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	domain, err := s.authorizedMember(
		credential,
		CapabilityFetchMessage,
		nowMilliseconds,
	)
	if err != nil {
		return Message{}, err
	}
	refreshMemoryFence(domain, nowMilliseconds)
	subscription, err := readableMemberSubscription(domain, credential.MemberID)
	if err != nil {
		return Message{}, err
	}
	stored, found := domain.messageByID[messageID]
	if !found || stored.publisherSubscription == subscription.SubscriptionID {
		return Message{}, protocolError(CodeMessageNotFound, "message was not found")
	}
	if stored.checkpointFenceID != nil {
		fence := domain.checkpointFences[*stored.checkpointFenceID]
		if fence == nil || fence.state.Status != CheckpointFenceActivated {
			return Message{}, protocolError(CodeMessageNotFound, "message was not found")
		}
	}
	return stored.message, nil
}

func (s *MemoryStore) Acknowledge(
	_ context.Context,
	credential Credential,
	messageID uuid.UUID,
	stage AcknowledgmentStage,
	nowMilliseconds int64,
) (AcknowledgmentResult, error) {
	if !stage.Valid() {
		return AcknowledgmentResult{}, protocolError(
			CodeInvalidAcknowledgment,
			"acknowledgment stage is invalid",
		)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	domain, err := s.authorizedMember(
		credential,
		CapabilityAcknowledgeMessage,
		nowMilliseconds,
	)
	if err != nil {
		return AcknowledgmentResult{}, err
	}
	subscription, err := readableMemberSubscription(domain, credential.MemberID)
	if err != nil {
		return AcknowledgmentResult{}, err
	}
	message, ok := domain.messageByID[messageID]
	if !ok {
		return AcknowledgmentResult{}, protocolError(CodeMessageNotFound, "message was not found")
	}
	if message.publisherSubscription == subscription.SubscriptionID &&
		!memoryOwnMessageIsInAuthorizedRecovery(domain, subscription, message) {
		return AcknowledgmentResult{}, protocolError(
			CodeInvalidAcknowledgment,
			"publisher cannot acknowledge its message",
		)
	}
	existing, hasExisting := message.acknowledgments[subscription.SubscriptionID]
	if hasExisting && (existing == stage || existing == AcknowledgmentApplied) {
		return AcknowledgmentResult{
			Acceptance: AcceptanceDuplicate,
			Stage:      existing,
		}, nil
	}
	if stage == AcknowledgmentApplied && !hasExisting {
		return AcknowledgmentResult{}, protocolError(
			CodeInvalidAcknowledgment,
			"applied requires a durable accepted acknowledgment",
		)
	}
	message.acknowledgments[subscription.SubscriptionID] = stage
	return AcknowledgmentResult{
		Acceptance: AcceptanceAccepted,
		Stage:      stage,
	}, nil
}

func memoryOwnMessageIsInAuthorizedRecovery(
	domain *memoryDomain,
	subscription Subscription,
	message *memoryMessage,
) bool {
	if !memorySubscriptionHasAuthorizedRecovery(domain, subscription) {
		return false
	}
	startSequence, err := DecodeCursor(*subscription.StartCursor)
	return err == nil && message.message.Sequence > startSequence
}

func memorySubscriptionHasAuthorizedRecovery(
	domain *memoryDomain,
	subscription Subscription,
) bool {
	if subscription.Status != SubscriptionRebootstrapRequired || subscription.StartCursor == nil {
		return false
	}
	for _, request := range domain.rebootstrapRequests {
		if request.subscriptionID == subscription.SubscriptionID &&
			request.result.Status == SubscriptionRebootstrapRequired &&
			request.result.StartCursor != nil &&
			*request.result.StartCursor == *subscription.StartCursor &&
			request.result.UpdatedAtMilliseconds == subscription.UpdatedAtMilliseconds {
			return true
		}
	}
	return false
}

func (s *MemoryStore) PrepareBlobPublish(
	_ context.Context,
	credential Credential,
	blobID string,
	byteCount int64,
	nowMilliseconds int64,
) error {
	if err := validateBlobRequest(blobID, byteCount); err != nil {
		return err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	domain, err := s.authorizedMember(
		credential,
		CapabilityPublishBlob,
		nowMilliseconds,
	)
	if err != nil {
		return err
	}
	if existing, ok := domain.blobs[blobID]; ok {
		if existing.ByteCount == byteCount {
			return nil
		}
		return protocolError(CodeBlobCollision, "blob ID was reused with a different length")
	}
	return ensureBlobCapacity(domain, byteCount)
}

func (s *MemoryStore) CommitBlobPublish(
	_ context.Context,
	credential Credential,
	blobID string,
	byteCount int64,
	nowMilliseconds int64,
) (BlobPublishResult, error) {
	if err := validateBlobRequest(blobID, byteCount); err != nil {
		return BlobPublishResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	domain, err := s.authorizedMember(
		credential,
		CapabilityPublishBlob,
		nowMilliseconds,
	)
	if err != nil {
		return BlobPublishResult{}, err
	}
	if existing, ok := domain.blobs[blobID]; ok {
		if existing.ByteCount == byteCount {
			return BlobPublishResult{
				Acceptance: AcceptanceDuplicate,
				ByteCount:  byteCount,
			}, nil
		}
		return BlobPublishResult{}, protocolError(
			CodeBlobCollision,
			"blob ID was reused with a different length",
		)
	}
	subscription, err := activeMemberSubscription(domain, credential.MemberID)
	if err != nil {
		return BlobPublishResult{}, err
	}
	if err := memoryFenceAllowsWrite(domain, subscription.SubscriptionID, nowMilliseconds); err != nil {
		return BlobPublishResult{}, err
	}
	if err := ensureBlobCapacity(domain, byteCount); err != nil {
		return BlobPublishResult{}, err
	}
	if err := s.ensureTenantBlobCapacityLocked(credential.TenantID, byteCount); err != nil {
		return BlobPublishResult{}, err
	}
	metadata := BlobMetadata{
		TenantID:              credential.TenantID,
		DomainID:              credential.DomainID,
		BlobID:                blobID,
		PublisherMemberID:     credential.MemberID,
		ByteCount:             byteCount,
		CreatedAtMilliseconds: nowMilliseconds,
	}
	if err := metadata.Validate(); err != nil {
		return BlobPublishResult{}, err
	}
	domain.blobs[blobID] = metadata
	if fence := memoryActiveFenceForSubscription(domain, subscription.SubscriptionID); fence != nil {
		domain.blobFenceIDs[blobID] = fence.state.FenceID
	}
	domain.blobBytes += byteCount
	return BlobPublishResult{
		Acceptance: AcceptanceAccepted,
		ByteCount:  byteCount,
	}, nil
}

func (s *MemoryStore) GetBlobMetadata(
	_ context.Context,
	credential Credential,
	blobID string,
	nowMilliseconds int64,
) (BlobMetadata, error) {
	if err := ValidateBlobID(blobID); err != nil {
		return BlobMetadata{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	domain, err := s.authorizedMember(
		credential,
		CapabilityFetchBlob,
		nowMilliseconds,
	)
	if err != nil {
		return BlobMetadata{}, err
	}
	metadata, ok := domain.blobs[blobID]
	if !ok {
		return BlobMetadata{}, protocolError(CodeBlobNotFound, "blob was not found")
	}
	if fenceID, fenced := domain.blobFenceIDs[blobID]; fenced {
		fence := domain.checkpointFences[fenceID]
		if fence == nil || fence.state.Status != CheckpointFenceActivated {
			return BlobMetadata{}, protocolError(CodeBlobNotFound, "blob was not found")
		}
	}
	return metadata, nil
}

func validateBlobRequest(blobID string, byteCount int64) error {
	if err := ValidateBlobID(blobID); err != nil {
		return err
	}
	if byteCount < 0 || byteCount > MaximumBlobByteCount {
		return protocolError(CodeInvalidBlob, "blob byte count is invalid")
	}
	return nil
}

func ensureBlobCapacity(domain *memoryDomain, byteCount int64) error {
	if len(domain.blobs) >= domain.registration.MaximumBlobCount {
		return protocolError(CodeDomainFull, "domain reached its blob limit")
	}
	if byteCount > domain.registration.MaximumBlobByteCount-domain.blobBytes {
		return protocolError(CodeDomainFull, "domain reached its blob-byte limit")
	}
	return nil
}

func activeMemberSubscription(domain *memoryDomain, memberID uuid.UUID) (Subscription, error) {
	subscription, err := readableMemberSubscription(domain, memberID)
	if err != nil {
		return Subscription{}, err
	}
	if subscription.Status != SubscriptionActive {
		return Subscription{}, protocolError(CodeInvalidSubscription, "subscription is not active")
	}
	return subscription, nil
}

// readableMemberSubscription is intentionally narrower than an active
// subscription: a rebootstrap-required member may read and acknowledge the
// retained checkpoint/tail, but may not publish new content.
func readableMemberSubscription(domain *memoryDomain, memberID uuid.UUID) (Subscription, error) {
	subscriptionID, ok := domain.memberSubscriptions[memberID]
	if !ok || subscriptionID == uuid.Nil {
		return Subscription{}, protocolError(CodeInvalidSubscription, "member has no subscription")
	}
	subscription, ok := domain.subscriptions[subscriptionID]
	if !ok {
		return Subscription{}, protocolError(CodeSubscriptionNotFound, "subscription was not found")
	}
	if subscription.Status != SubscriptionActive && subscription.Status != SubscriptionRebootstrapRequired {
		return Subscription{}, protocolError(CodeInvalidSubscription, "subscription is not readable")
	}
	return subscription, nil
}

func latestCheckpointStartCursor(domain *memoryDomain) *string {
	if len(domain.activatedCheckpoints) == 0 {
		return nil
	}
	checkpoint := domain.checkpoints[domain.activatedCheckpoints[len(domain.activatedCheckpoints)-1]]
	if checkpoint == nil || checkpoint.state != "activated" {
		return nil
	}
	value := EncodeCursor(checkpoint.startSequence)
	return &value
}

func (s *MemoryStore) tenantUsageLocked(tenantID uuid.UUID) (int, int64, int, int64) {
	messageCount := 0
	messageBytes := int64(0)
	blobCount := 0
	blobBytes := int64(0)
	for key, domain := range s.domains {
		if key.tenantID != tenantID {
			continue
		}
		messageCount += len(domain.messages)
		messageBytes += domain.messageBytes
		blobCount += len(domain.blobs)
		blobBytes += domain.blobBytes
	}
	return messageCount, messageBytes, blobCount, blobBytes
}

func (s *MemoryStore) ensureTenantMessageCapacityLocked(
	tenantID uuid.UUID,
	additionalBytes int64,
) error {
	tenant := s.tenants[tenantID]
	if tenant == nil {
		return protocolError(CodeTenantNotFound, "tenant was not found")
	}
	messages, messageBytes, _, _ := s.tenantUsageLocked(tenantID)
	if messages >= tenant.registration.MaximumAggregateMessageCount ||
		additionalBytes > tenant.registration.MaximumAggregateMessageByteCount-messageBytes {
		return protocolError(CodeTenantFull, "tenant reached its message or byte limit")
	}
	return nil
}

func (s *MemoryStore) ensureTenantBlobCapacityLocked(
	tenantID uuid.UUID,
	additionalBytes int64,
) error {
	tenant := s.tenants[tenantID]
	if tenant == nil {
		return protocolError(CodeTenantNotFound, "tenant was not found")
	}
	_, _, blobs, blobBytes := s.tenantUsageLocked(tenantID)
	reservedCount := s.tenantReservedBlobCountLocked(tenantID)
	reservedBytes := s.tenantReservedBlobBytesLocked(tenantID)
	if int64(blobs)+reservedCount >= int64(tenant.registration.MaximumAggregateBlobCount) ||
		additionalBytes > tenant.registration.MaximumAggregateBlobByteCount-blobBytes-reservedBytes {
		return protocolError(CodeTenantFull, "tenant reached its blob or byte limit")
	}
	return nil
}

func (s *MemoryStore) tenantReservedBlobCountLocked(tenantID uuid.UUID) int64 {
	var count int64
	for key, domain := range s.domains {
		if key.tenantID == tenantID {
			count += domain.reservedBlobCount
		}
	}
	return count
}

func (s *MemoryStore) tenantReservedBlobBytesLocked(tenantID uuid.UUID) int64 {
	var count int64
	for key, domain := range s.domains {
		if key.tenantID == tenantID {
			count += domain.reservedBlobBytes
		}
	}
	return count
}

func (s *MemoryStore) authorizedDomain(
	credential AdministrationCredential,
) (*memoryDomain, error) {
	domain, ok := s.domains[domainKey{credential.TenantID, credential.DomainID}]
	if !ok {
		return nil, protocolError(CodeDomainNotFound, "domain was not found")
	}
	if err := domain.registration.Authorize(credential); err != nil {
		return nil, err
	}
	return domain, nil
}

func (s *MemoryStore) authorizedMember(
	credential Credential,
	capability Capability,
	nowMilliseconds int64,
) (*memoryDomain, error) {
	domain, ok := s.domains[domainKey{credential.TenantID, credential.DomainID}]
	if !ok {
		return nil, protocolError(CodeDomainNotFound, "domain was not found")
	}
	member, ok := domain.members[credential.MemberID]
	if !ok {
		return nil, protocolError(CodeMemberNotFound, "member was not found")
	}
	if err := member.Authorize(credential, capability, nowMilliseconds); err != nil {
		return nil, err
	}
	return domain, nil
}

func memberEqual(lhs, rhs MemberRegistration) bool {
	if lhs.Version != rhs.Version || lhs.TenantID != rhs.TenantID ||
		lhs.DomainID != rhs.DomainID || lhs.MemberID != rhs.MemberID ||
		lhs.AuthorizationDigest != rhs.AuthorizationDigest ||
		lhs.CreatedAtMilliseconds != rhs.CreatedAtMilliseconds ||
		!optionalInt64Equal(lhs.ExpiresAtMilliseconds, rhs.ExpiresAtMilliseconds) ||
		!optionalInt64Equal(lhs.RevokedAtMilliseconds, rhs.RevokedAtMilliseconds) ||
		len(lhs.Capabilities) != len(rhs.Capabilities) {
		return false
	}
	for index := range lhs.Capabilities {
		if lhs.Capabilities[index] != rhs.Capabilities[index] {
			return false
		}
	}
	return true
}

func admissionCreationEqual(lhs, rhs MemberAdmission) bool {
	if lhs.Version != rhs.Version || lhs.TenantID != rhs.TenantID ||
		lhs.DomainID != rhs.DomainID || lhs.AdmissionID != rhs.AdmissionID ||
		lhs.AuthorizationDigest != rhs.AuthorizationDigest ||
		lhs.ExpiresAtMilliseconds != rhs.ExpiresAtMilliseconds ||
		!optionalInt64Equal(lhs.MemberExpiresAtMilliseconds, rhs.MemberExpiresAtMilliseconds) ||
		len(lhs.Capabilities) != len(rhs.Capabilities) {
		return false
	}
	for index := range lhs.Capabilities {
		if lhs.Capabilities[index] != rhs.Capabilities[index] {
			return false
		}
	}
	return true
}

func optionalInt64Equal(lhs, rhs *int64) bool {
	return lhs == nil && rhs == nil ||
		lhs != nil && rhs != nil && *lhs == *rhs
}
