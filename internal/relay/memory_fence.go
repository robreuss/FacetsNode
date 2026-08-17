package relay

import (
	"context"

	"github.com/google/uuid"
)

type memoryCheckpointFence struct {
	request              CheckpointFenceRequest
	state                CheckpointFenceState
	holderSubscriptionID uuid.UUID
}
type memoryFenceAbort struct {
	request CheckpointFenceAbortRequest
	result  CheckpointFenceAbortResponse
}

func (s *MemoryStore) CreateCheckpointFence(_ context.Context, credential Credential, request CheckpointFenceRequest, now int64) (CheckpointFenceResponse, error) {
	if err := request.Validate(); err != nil {
		return CheckpointFenceResponse{}, err
	}
	if request.RequestedAtMilliseconds > now {
		return CheckpointFenceResponse{}, protocolError(CodeInvalidCheckpointFence, "fence request is in the future")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	domain, err := s.authorizedMember(credential, CapabilityPublishCheckpoint, now)
	if err != nil {
		return CheckpointFenceResponse{}, err
	}
	subscription, err := activeMemberSubscription(domain, credential.MemberID)
	if err != nil {
		return CheckpointFenceResponse{}, err
	}
	refreshMemoryFence(domain, now)
	if existingID, ok := domain.checkpointFenceRetries[request.RetryID]; ok {
		existing := domain.checkpointFences[existingID]
		if existing != nil && existing.request == request && existing.holderSubscriptionID == subscription.SubscriptionID {
			return fenceResponse(existing, request.RetryID, AcceptanceDuplicate), nil
		}
		return CheckpointFenceResponse{}, protocolError(CodeCheckpointFenceCollision, "fence retry ID was reused")
	}
	if domain.checkpointFences[request.FenceID] != nil {
		return CheckpointFenceResponse{}, protocolError(CodeCheckpointFenceCollision, "fence ID was reused")
	}
	for _, fence := range domain.checkpointFences {
		if fence.state.Status == CheckpointFenceActive {
			return CheckpointFenceResponse{}, protocolError(CodeCheckpointFenceActive, "domain already has an active fence")
		}
	}
	state := CheckpointFenceState{FenceID: request.FenceID, Status: CheckpointFenceActive, BoundaryCursor: EncodeCursor(domain.nextSequence), AcquiredAtMilliseconds: now, ExpiresAtMilliseconds: now + s.checkpointFence.Milliseconds()}
	fence := &memoryCheckpointFence{request: request, state: state, holderSubscriptionID: subscription.SubscriptionID}
	domain.checkpointFences[request.FenceID] = fence
	domain.checkpointFenceRetries[request.RetryID] = request.FenceID
	return fenceResponse(fence, request.RetryID, AcceptanceAccepted), nil
}

func (s *MemoryStore) GetCheckpointFence(_ context.Context, credential Credential, fenceID uuid.UUID, now int64) (CheckpointFenceState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	domain, err := s.authorizedMember(credential, CapabilityPublishCheckpoint, now)
	if err != nil {
		return CheckpointFenceState{}, err
	}
	subscription, err := activeMemberSubscription(domain, credential.MemberID)
	if err != nil {
		return CheckpointFenceState{}, err
	}
	refreshMemoryFence(domain, now)
	fence := domain.checkpointFences[fenceID]
	if fence == nil {
		return CheckpointFenceState{}, protocolError(CodeCheckpointFenceNotFound, "fence was not found")
	}
	if fence.holderSubscriptionID != subscription.SubscriptionID {
		return CheckpointFenceState{}, protocolError(CodeWrongScope, "fence belongs to another subscription")
	}
	return fence.state, nil
}

func (s *MemoryStore) AbortCheckpointFence(_ context.Context, credential Credential, request CheckpointFenceAbortRequest, now int64) (CheckpointFenceAbortResponse, error) {
	if err := request.Validate(); err != nil {
		return CheckpointFenceAbortResponse{}, err
	}
	if request.AbortedAtMilliseconds > now {
		return CheckpointFenceAbortResponse{}, protocolError(CodeInvalidCheckpointFence, "fence abort is in the future")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	domain, err := s.authorizedMember(credential, CapabilityPublishCheckpoint, now)
	if err != nil {
		return CheckpointFenceAbortResponse{}, err
	}
	subscription, err := activeMemberSubscription(domain, credential.MemberID)
	if err != nil {
		return CheckpointFenceAbortResponse{}, err
	}
	if existing, ok := domain.checkpointFenceAborts[request.RetryID]; ok {
		fence := domain.checkpointFences[request.FenceID]
		if existing.request == request && fence != nil && fence.holderSubscriptionID == subscription.SubscriptionID {
			result := existing.result
			result.Acceptance = AcceptanceDuplicate
			return result, nil
		}
		return CheckpointFenceAbortResponse{}, protocolError(CodeCheckpointFenceCollision, "fence abort retry ID was reused")
	}
	refreshMemoryFence(domain, now)
	fence := domain.checkpointFences[request.FenceID]
	if fence == nil {
		return CheckpointFenceAbortResponse{}, protocolError(CodeCheckpointFenceNotFound, "fence was not found")
	}
	if fence.holderSubscriptionID != subscription.SubscriptionID {
		return CheckpointFenceAbortResponse{}, protocolError(CodeWrongScope, "fence belongs to another subscription")
	}
	if fence.state.Status != CheckpointFenceActive {
		return CheckpointFenceAbortResponse{}, protocolError(CodeCheckpointFenceCollision, "fence is not active")
	}
	fence.state.Status = CheckpointFenceAborted
	invalidateMemoryFenceCandidate(domain, request.FenceID)
	cleanupMemoryFenceAuthority(domain, request.FenceID)
	result := CheckpointFenceAbortResponse{Acceptance: AcceptanceAccepted, RetryID: request.RetryID, FenceID: request.FenceID, Status: CheckpointFenceAborted}
	domain.checkpointFenceAborts[request.RetryID] = memoryFenceAbort{request: request, result: result}
	return result, nil
}

func refreshMemoryFence(domain *memoryDomain, now int64) {
	for _, fence := range domain.checkpointFences {
		if fence.state.Status == CheckpointFenceActive && now >= fence.state.ExpiresAtMilliseconds {
			fence.state.Status = CheckpointFenceExpired
			invalidateMemoryFenceCandidate(domain, fence.state.FenceID)
			cleanupMemoryFenceAuthority(domain, fence.state.FenceID)
		}
	}
}
func memoryActiveFenceForSubscription(domain *memoryDomain, subscriptionID uuid.UUID) *memoryCheckpointFence {
	for _, fence := range domain.checkpointFences {
		if fence.state.Status == CheckpointFenceActive && fence.holderSubscriptionID == subscriptionID {
			return fence
		}
	}
	return nil
}
func cleanupMemoryFenceAuthority(domain *memoryDomain, fenceID uuid.UUID) {
	kept := domain.messages[:0]
	for _, message := range domain.messages {
		if message.checkpointFenceID == nil || *message.checkpointFenceID != fenceID {
			kept = append(kept, message)
			continue
		}
		digest, err := message.message.Envelope.ReferenceDigest()
		if err == nil {
			domain.fenceMessageTombstones[message.message.Envelope.MessageID] = memoryFenceMessageTombstone{publisherMember: message.publisherMember, digest: digest, sequence: message.message.Sequence}
		}
		delete(domain.messageByID, message.message.Envelope.MessageID)
		domain.messageBytes -= message.byteCount
	}
	domain.messages = kept
	for blobID, associatedFenceID := range domain.blobFenceIDs {
		if associatedFenceID != fenceID {
			continue
		}
		if blob, ok := domain.blobs[blobID]; ok {
			domain.blobBytes -= blob.ByteCount
			delete(domain.blobs, blobID)
		}
		delete(domain.blobFenceIDs, blobID)
	}
}
func invalidateMemoryFenceCandidate(domain *memoryDomain, fenceID uuid.UUID) {
	for _, checkpoint := range domain.checkpoints {
		if checkpoint.candidate.FenceID == fenceID && checkpoint.state == "staged" {
			checkpoint.state = "invalidated"
			checkpoint.candidate.RetainedMessageIDs = nil
			checkpoint.candidate.RetainedBlobIDs = nil
		}
	}
}
func memoryFenceAllowsWrite(domain *memoryDomain, subscriptionID uuid.UUID, now int64) error {
	refreshMemoryFence(domain, now)
	for _, fence := range domain.checkpointFences {
		if fence.state.Status == CheckpointFenceActive && fence.holderSubscriptionID != subscriptionID {
			return protocolError(CodeCheckpointFenceActive, "another subscription holds the checkpoint fence")
		}
	}
	return nil
}
func fenceResponse(fence *memoryCheckpointFence, retryID uuid.UUID, acceptance Acceptance) CheckpointFenceResponse {
	return CheckpointFenceResponse{Acceptance: acceptance, RetryID: retryID, FenceID: fence.state.FenceID, BoundaryCursor: fence.state.BoundaryCursor, AcquiredAtMilliseconds: fence.state.AcquiredAtMilliseconds, ExpiresAtMilliseconds: fence.state.ExpiresAtMilliseconds}
}
