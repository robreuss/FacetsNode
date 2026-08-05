package relay

import (
	"context"
	"sort"
	"sync"

	"github.com/google/uuid"
)

type domainKey struct {
	tenantID uuid.UUID
	domainID uuid.UUID
}

type memoryMessage struct {
	message         Message
	publisherMember uuid.UUID
	acknowledgments map[uuid.UUID]AcknowledgmentStage
}

type memoryDomain struct {
	registration DomainRegistration
	members      map[uuid.UUID]MemberRegistration
	admissions   map[uuid.UUID]MemberAdmission
	messages     []*memoryMessage
	messageByID  map[uuid.UUID]*memoryMessage
	blobs        map[string]BlobMetadata
	rotations    map[uuid.UUID]memoryCredentialRotation
	nextSequence uint64
	storedBytes  int64
}

type memoryCredentialRotation struct {
	subjectType                 string
	subjectID                   uuid.UUID
	previousAuthorizationDigest string
	newAuthorizationDigest      string
	rotatedAtMilliseconds       int64
}

const (
	administrationRotationSubject = "administration"
	memberRotationSubject         = "member"
)

type MemoryStore struct {
	mu      sync.RWMutex
	domains map[domainKey]*memoryDomain
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{domains: make(map[domainKey]*memoryDomain)}
}

func (s *MemoryStore) CreateDomain(
	_ context.Context,
	registration DomainRegistration,
	initialMember MemberRegistration,
) (Acceptance, error) {
	if err := registration.Validate(); err != nil {
		return "", err
	}
	if err := initialMember.Validate(); err != nil {
		return "", err
	}
	if initialMember.TenantID != registration.TenantID ||
		initialMember.DomainID != registration.DomainID ||
		initialMember.CreatedAtMilliseconds < registration.CreatedAtMilliseconds {
		return "", protocolError(CodeWrongScope, "initial member belongs to another domain")
	}
	key := domainKey{registration.TenantID, registration.DomainID}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.domains[key]; ok {
		member := existing.members[initialMember.MemberID]
		if existing.registration == registration && memberEqual(member, initialMember) {
			return AcceptanceDuplicate, nil
		}
		return "", protocolError(CodeDomainCollision, "domain ID was reused")
	}
	s.domains[key] = &memoryDomain{
		registration: registration,
		members: map[uuid.UUID]MemberRegistration{
			initialMember.MemberID: initialMember,
		},
		admissions:  make(map[uuid.UUID]MemberAdmission),
		messageByID: make(map[uuid.UUID]*memoryMessage),
		blobs:       make(map[string]BlobMetadata),
		rotations:   make(map[uuid.UUID]memoryCredentialRotation),
	}
	return AcceptanceAccepted, nil
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

func (s *MemoryStore) CreateAdmission(
	_ context.Context,
	credential AdministrationCredential,
	registration MemberAdmission,
	nowMilliseconds int64,
) (AdmissionCreateResult, error) {
	if err := registration.Validate(); err != nil {
		return AdmissionCreateResult{}, err
	}
	if registration.RevokedAtMilliseconds != nil ||
		registration.ClaimedAtMilliseconds != nil ||
		registration.ClaimedMemberID != nil {
		return AdmissionCreateResult{}, protocolError(
			CodeInvalidAdmission,
			"new admission already has terminal state",
		)
	}
	if registration.CreatedAtMilliseconds > nowMilliseconds ||
		registration.ExpiresAtMilliseconds <= nowMilliseconds {
		return AdmissionCreateResult{}, protocolError(CodeInvalidAdmission, "admission is not currently issuable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	domain, err := s.authorizedDomain(credential)
	if err != nil {
		return AdmissionCreateResult{}, err
	}
	if registration.TenantID != credential.TenantID ||
		registration.DomainID != credential.DomainID {
		return AdmissionCreateResult{}, protocolError(CodeWrongScope, "admission belongs to another domain")
	}
	if existing, ok := domain.admissions[registration.AdmissionID]; ok {
		if admissionCreationEqual(existing, registration) {
			return AdmissionCreateResult{
				Acceptance: AcceptanceDuplicate,
				Admission:  existing,
			}, nil
		}
		return AdmissionCreateResult{}, protocolError(CodeAdmissionCollision, "admission ID was reused")
	}
	if len(domain.admissions) >= MaximumRetainedAdmissionCount {
		return AdmissionCreateResult{}, protocolError(
			CodeDomainFull,
			"domain reached its retained admission limit",
		)
	}
	if countOutstandingAdmissions(domain.admissions, nowMilliseconds) >=
		MaximumOutstandingAdmissionCount {
		return AdmissionCreateResult{}, protocolError(
			CodeDomainFull,
			"domain reached its outstanding admission limit",
		)
	}
	domain.admissions[registration.AdmissionID] = registration
	return AdmissionCreateResult{
		Acceptance: AcceptanceAccepted,
		Admission:  registration,
	}, nil
}

func (s *MemoryStore) ClaimAdmission(
	_ context.Context,
	credential AdmissionCredential,
	claim MemberAdmissionClaim,
	nowMilliseconds int64,
) (AdmissionClaimResult, error) {
	if err := claim.Validate(); err != nil {
		return AdmissionClaimResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	domain, ok := s.domains[domainKey{credential.TenantID, credential.DomainID}]
	if !ok {
		return AdmissionClaimResult{}, protocolError(CodeDomainNotFound, "domain was not found")
	}
	admission, ok := domain.admissions[credential.AdmissionID]
	if !ok {
		return AdmissionClaimResult{}, protocolError(CodeAdmissionNotFound, "admission was not found")
	}
	if err := admission.VerifyCredential(credential); err != nil {
		return AdmissionClaimResult{}, err
	}
	if admission.ClaimedMemberID != nil {
		member := domain.members[*admission.ClaimedMemberID]
		if *admission.ClaimedMemberID == claim.MemberID &&
			member.AuthorizationDigest == claim.AuthorizationDigest {
			return AdmissionClaimResult{
				Acceptance: AcceptanceDuplicate,
				Member:     member,
			}, nil
		}
		return AdmissionClaimResult{}, protocolError(CodeAdmissionClaimed, "admission was already claimed")
	}
	if err := admission.RequireActive(nowMilliseconds); err != nil {
		return AdmissionClaimResult{}, err
	}
	if _, exists := domain.members[claim.MemberID]; exists {
		return AdmissionClaimResult{}, protocolError(CodeMemberCollision, "member ID was reused")
	}
	if err := ensureMemberCapacity(domain.members, nowMilliseconds); err != nil {
		return AdmissionClaimResult{}, err
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
		return AdmissionClaimResult{}, err
	}
	claimedAt := nowMilliseconds
	claimedMemberID := claim.MemberID
	admission.ClaimedAtMilliseconds = &claimedAt
	admission.ClaimedMemberID = &claimedMemberID
	domain.members[member.MemberID] = member
	domain.admissions[admission.AdmissionID] = admission
	return AdmissionClaimResult{
		Acceptance: AcceptanceAccepted,
		Member:     member,
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

func (s *MemoryStore) CreateMember(
	_ context.Context,
	credential AdministrationCredential,
	registration MemberRegistration,
	nowMilliseconds int64,
) (Acceptance, error) {
	if err := registration.Validate(); err != nil {
		return "", err
	}
	if registration.CreatedAtMilliseconds > nowMilliseconds {
		return "", protocolError(CodeInvalidMember, "member starts in the future")
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
		if memberEqual(existing, registration) {
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
	domain.members[registration.MemberID] = registration
	return AcceptanceAccepted, nil
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
	if len(domain.messages) >= domain.registration.MaximumMessageCount {
		return PublishResult{}, protocolError(CodeDomainFull, "domain reached its message limit")
	}
	ciphertextByteCount, err := envelope.CiphertextByteCount()
	if err != nil {
		return PublishResult{}, err
	}
	if ciphertextByteCount > domain.registration.MaximumStoredByteCount-domain.storedBytes {
		return PublishResult{}, protocolError(CodeDomainFull, "domain reached its stored-byte limit")
	}
	domain.nextSequence++
	stored := &memoryMessage{
		message: Message{
			Sequence: domain.nextSequence,
			Envelope: envelope,
		},
		publisherMember: credential.MemberID,
		acknowledgments: make(map[uuid.UUID]AcknowledgmentStage),
	}
	domain.messages = append(domain.messages, stored)
	domain.messageByID[envelope.MessageID] = stored
	domain.storedBytes += ciphertextByteCount
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
	s.mu.RLock()
	defer s.mu.RUnlock()
	domain, err := s.authorizedMember(
		credential,
		CapabilityFetchMessage,
		nowMilliseconds,
	)
	if err != nil {
		return FetchResult{}, err
	}
	result := FetchResult{Messages: make([]Message, 0, limit)}
	for _, stored := range domain.messages {
		if stored.message.Sequence <= afterSequence ||
			stored.publisherMember == credential.MemberID {
			continue
		}
		result.Messages = append(result.Messages, stored.message)
		result.NextSequence = stored.message.Sequence
		if len(result.Messages) == limit {
			return result, nil
		}
	}
	result.NextSequence = domain.nextSequence
	if afterSequence > result.NextSequence {
		result.NextSequence = afterSequence
	}
	return result, nil
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
	message, ok := domain.messageByID[messageID]
	if !ok {
		return AcknowledgmentResult{}, protocolError(CodeMessageNotFound, "message was not found")
	}
	if message.publisherMember == credential.MemberID {
		return AcknowledgmentResult{}, protocolError(
			CodeInvalidAcknowledgment,
			"publisher cannot acknowledge its message",
		)
	}
	existing, hasExisting := message.acknowledgments[credential.MemberID]
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
	message.acknowledgments[credential.MemberID] = stage
	return AcknowledgmentResult{
		Acceptance: AcceptanceAccepted,
		Stage:      stage,
	}, nil
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
	if err := ensureBlobCapacity(domain, byteCount); err != nil {
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
	domain.storedBytes += byteCount
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
	if byteCount > domain.registration.MaximumStoredByteCount-domain.storedBytes {
		return protocolError(CodeDomainFull, "domain reached its stored-byte limit")
	}
	return nil
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
