package relay

import (
	"context"
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
	messages     []*memoryMessage
	messageByID  map[uuid.UUID]*memoryMessage
	blobs        map[string]BlobMetadata
	nextSequence uint64
	storedBytes  int64
}

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
		messageByID: make(map[uuid.UUID]*memoryMessage),
		blobs:       make(map[string]BlobMetadata),
	}
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
	domain.members[registration.MemberID] = registration
	return AcceptanceAccepted, nil
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

func optionalInt64Equal(lhs, rhs *int64) bool {
	return lhs == nil && rhs == nil ||
		lhs != nil && rhs != nil && *lhs == *rhs
}
