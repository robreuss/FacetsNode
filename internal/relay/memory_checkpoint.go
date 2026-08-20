package relay

import (
	"context"
	"sort"

	"github.com/google/uuid"
)

type memoryCheckpoint struct {
	candidate         CheckpointCandidate
	candidateDigest   string
	publisherMemberID uuid.UUID
	coveredThrough    uint64
	state             string
	activationOrdinal uint64
	activationRequest CheckpointActivationRequest
	startSequence     uint64
	required          map[uuid.UUID]struct{}
	deletionMessages  map[uuid.UUID]*memoryMessage
	deletionBlobs     map[string]BlobMetadata
}

type memoryCheckpointActivation struct {
	checkpointID uuid.UUID
	request      CheckpointActivationRequest
	result       CheckpointActivationResponse
}

type memoryCheckpointCollection struct {
	request CheckpointCollectionRequest
	result  CheckpointCollectionResponse
}

func (s *MemoryStore) StageCheckpoint(_ context.Context, credential Credential, candidate CheckpointCandidate, nowMilliseconds int64) (CheckpointStageResponse, error) {
	if err := candidate.Validate(); err != nil {
		return CheckpointStageResponse{}, err
	}
	if candidate.TenantID != credential.TenantID || candidate.DomainID != credential.DomainID || candidate.CreatedAtMilliseconds > nowMilliseconds {
		return CheckpointStageResponse{}, protocolError(CodeWrongScope, "checkpoint candidate scope or time is invalid")
	}
	coveredThrough, err := DecodeCursor(candidate.CoveredThroughCursor)
	if err != nil {
		return CheckpointStageResponse{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	domain, err := s.authorizedMember(credential, CapabilityPublishCheckpoint, nowMilliseconds)
	if err != nil {
		return CheckpointStageResponse{}, err
	}
	subscription, err := activeMemberSubscription(domain, credential.MemberID)
	if err != nil {
		return CheckpointStageResponse{}, err
	}
	if subscription.SubscriptionID != candidate.PublisherSubscriptionID || coveredThrough > domain.nextSequence {
		return CheckpointStageResponse{}, protocolError(CodeInvalidCheckpoint, "checkpoint publisher or covered cursor is invalid")
	}
	if existingID, ok := domain.checkpointStageRetries[candidate.RetryID]; ok {
		existing := domain.checkpoints[existingID]
		if existing != nil && existing.candidateDigest == CheckpointCandidateDigest(candidate) && existing.candidate.PublisherSubscriptionID == subscription.SubscriptionID {
			return CheckpointStageResponse{Acceptance: AcceptanceDuplicate, RetryID: candidate.RetryID, CheckpointID: candidate.CheckpointID}, nil
		}
		return CheckpointStageResponse{}, protocolError(CodeCheckpointCollision, "checkpoint retry ID was reused")
	}
	refreshMemoryFence(domain, nowMilliseconds)
	fence := domain.checkpointFences[candidate.FenceID]
	if fence == nil || fence.state.Status != CheckpointFenceActive || nowMilliseconds >= fence.state.ExpiresAtMilliseconds ||
		fence.holderSubscriptionID != subscription.SubscriptionID || candidate.CoveredThroughCursor != fence.state.BoundaryCursor {
		return CheckpointStageResponse{}, protocolError(CodeInvalidCheckpointFence, "checkpoint candidate does not match an active fence")
	}
	if _, ok := domain.checkpoints[candidate.CheckpointID]; ok {
		return CheckpointStageResponse{}, protocolError(CodeCheckpointCollision, "checkpoint ID was reused")
	}
	if !memoryFenceSuffixMatches(domain, fence, candidate.RetainedMessageIDs) {
		return CheckpointStageResponse{}, protocolError(CodeInvalidCheckpoint, "retained messages are not the exact fenced holder suffix")
	}
	for _, blobID := range candidate.RetainedBlobIDs {
		if _, ok := domain.blobs[blobID]; !ok {
			return CheckpointStageResponse{}, protocolError(CodeInvalidCheckpoint, "retained blob is missing")
		}
	}
	domain.checkpoints[candidate.CheckpointID] = &memoryCheckpoint{
		candidate: candidate, publisherMemberID: credential.MemberID,
		candidateDigest: CheckpointCandidateDigest(candidate),
		coveredThrough:  coveredThrough, state: "staged",
	}
	domain.checkpointStageRetries[candidate.RetryID] = candidate.CheckpointID
	return CheckpointStageResponse{Acceptance: AcceptanceAccepted, RetryID: candidate.RetryID, CheckpointID: candidate.CheckpointID}, nil
}

func (s *MemoryStore) ActivateCheckpoint(_ context.Context, credential AdministrationCredential, request CheckpointActivationRequest, nowMilliseconds int64) (CheckpointActivationResponse, error) {
	if err := request.Validate(); err != nil {
		return CheckpointActivationResponse{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	domain, err := s.authorizedDomain(credential)
	if err != nil {
		return CheckpointActivationResponse{}, err
	}
	if existing, ok := domain.checkpointActivations[request.RetryID]; ok {
		if existing.checkpointID == request.CheckpointID && existing.request == request {
			result := existing.result
			result.Acceptance = AcceptanceDuplicate
			return result, nil
		}
		return CheckpointActivationResponse{}, protocolError(CodeCheckpointCollision, "checkpoint activation retry ID was reused")
	}
	checkpoint := domain.checkpoints[request.CheckpointID]
	if checkpoint == nil {
		return CheckpointActivationResponse{}, protocolError(CodeCheckpointNotFound, "checkpoint was not found")
	}
	refreshMemoryFence(domain, nowMilliseconds)
	fence := domain.checkpointFences[checkpoint.candidate.FenceID]
	if checkpoint.state != "staged" || request.ActivatedAtMilliseconds < checkpoint.candidate.CreatedAtMilliseconds {
		if fence != nil && (fence.state.Status == CheckpointFenceExpired || fence.state.Status == CheckpointFenceAborted) {
			return CheckpointActivationResponse{}, protocolError(CodeInvalidCheckpointFence, "checkpoint fence is no longer activatable")
		}
		return CheckpointActivationResponse{}, protocolError(CodeCheckpointCollision, "checkpoint was already activated or activation time is invalid")
	}
	if fence == nil || fence.state.Status != CheckpointFenceActive || !memoryFenceSuffixMatches(domain, fence, checkpoint.candidate.RetainedMessageIDs) {
		return CheckpointActivationResponse{}, protocolError(CodeInvalidCheckpointFence, "checkpoint fence is no longer activatable")
	}
	retainedMessages := make(map[uuid.UUID]struct{})
	retainedBlobs := make(map[string]struct{})
	addRetained := func(item *memoryCheckpoint) {
		if item == nil {
			return
		}
		for _, id := range item.candidate.RetainedMessageIDs {
			retainedMessages[id] = struct{}{}
		}
		for _, id := range item.candidate.RetainedBlobIDs {
			retainedBlobs[id] = struct{}{}
		}
	}
	addRetained(checkpoint)
	if len(domain.activatedCheckpoints) > 0 {
		addRetained(domain.checkpoints[domain.activatedCheckpoints[len(domain.activatedCheckpoints)-1]])
	}
	checkpoint.required = make(map[uuid.UUID]struct{})
	for id, subscription := range domain.subscriptions {
		if subscription.Status == SubscriptionActive {
			checkpoint.required[id] = struct{}{}
		}
	}
	checkpoint.deletionMessages = make(map[uuid.UUID]*memoryMessage)
	for _, message := range domain.messages {
		if message.message.Sequence <= checkpoint.coveredThrough {
			if _, retained := retainedMessages[message.message.Envelope.MessageID]; !retained {
				checkpoint.deletionMessages[message.message.Envelope.MessageID] = message
			}
		}
	}
	checkpoint.deletionBlobs = make(map[string]BlobMetadata)
	for id, blob := range domain.blobs {
		if _, retained := retainedBlobs[id]; !retained {
			checkpoint.deletionBlobs[id] = blob
		}
	}
	checkpoint.startSequence = checkpoint.coveredThrough
	domain.checkpointOrdinal++
	checkpoint.activationOrdinal = domain.checkpointOrdinal
	checkpoint.activationRequest = request
	checkpoint.state = "activated"
	fence.state.Status = CheckpointFenceActivated
	domain.activatedCheckpoints = append(domain.activatedCheckpoints, request.CheckpointID)
	if len(domain.activatedCheckpoints) > 2 {
		retiredID := domain.activatedCheckpoints[len(domain.activatedCheckpoints)-3]
		retired := domain.checkpoints[retiredID]
		retired.state = "retired"
		retired.candidate.RetainedMessageIDs = nil
		retired.candidate.RetainedBlobIDs = nil
		retired.required = nil
		retired.deletionMessages = nil
		retired.deletionBlobs = nil
	}
	result := CheckpointActivationResponse{Acceptance: AcceptanceAccepted, RetryID: request.RetryID, CheckpointID: request.CheckpointID, ActivatedAtMilliseconds: request.ActivatedAtMilliseconds, StartCursor: EncodeCursor(checkpoint.startSequence)}
	domain.checkpointActivations[request.RetryID] = memoryCheckpointActivation{checkpointID: request.CheckpointID, request: request, result: result}
	return result, nil
}

func memoryFenceSuffixMatches(domain *memoryDomain, fence *memoryCheckpointFence, retained []uuid.UUID) bool {
	boundary, err := DecodeCursor(fence.state.BoundaryCursor)
	if err != nil {
		return false
	}
	expected := make([]uuid.UUID, 0)
	for _, message := range domain.messages {
		if message.publisherSubscription == fence.holderSubscriptionID && message.message.Sequence > boundary {
			expected = append(expected, message.message.Envelope.MessageID)
		}
	}
	sort.Slice(expected, func(i, j int) bool { return expected[i].String() < expected[j].String() })
	if len(expected) != len(retained) {
		return false
	}
	for index := range expected {
		if expected[index] != retained[index] {
			return false
		}
	}
	return true
}

func (s *MemoryStore) DryRunCheckpointCollection(_ context.Context, credential AdministrationCredential, request CheckpointDryRunRequest) (CheckpointDryRunResponse, error) {
	if err := request.Validate(); err != nil {
		return CheckpointDryRunResponse{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	domain, err := s.authorizedDomain(credential)
	if err != nil {
		return CheckpointDryRunResponse{}, err
	}
	return memoryCheckpointPlan(domain, request.CheckpointID)
}

func (s *MemoryStore) CollectCheckpoint(_ context.Context, credential AdministrationCredential, request CheckpointCollectionRequest) (CheckpointCollectionResponse, error) {
	if err := request.Validate(); err != nil {
		return CheckpointCollectionResponse{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	domain, err := s.authorizedDomain(credential)
	if err != nil {
		return CheckpointCollectionResponse{}, err
	}
	checkpoint := domain.checkpoints[request.CheckpointID]
	if checkpoint == nil {
		return CheckpointCollectionResponse{}, protocolError(CodeCheckpointNotFound, "checkpoint was not found")
	}
	if request.RequestedAtMilliseconds < checkpoint.activationRequest.ActivatedAtMilliseconds {
		return CheckpointCollectionResponse{}, protocolError(CodeInvalidCheckpoint, "checkpoint collection predates activation")
	}
	if existing, ok := domain.checkpointCollections[request.RetryID]; ok {
		if existing.request == request {
			result := existing.result
			result.Duplicate = true
			return result, nil
		}
		return CheckpointCollectionResponse{}, protocolError(CodeCheckpointCollision, "checkpoint collection retry ID was reused")
	}
	plan, err := memoryCheckpointPlan(domain, request.CheckpointID)
	if err != nil {
		return CheckpointCollectionResponse{}, err
	}
	if plan.PlanDigest != request.PlanDigest {
		return CheckpointCollectionResponse{}, protocolError(CodeCollectionPlanStale, "collection plan changed")
	}
	if !plan.Eligible {
		return CheckpointCollectionResponse{}, protocolError(CodeCheckpointNotEligible, "checkpoint lacks required custody")
	}
	messages := make([]*memoryMessage, 0, len(checkpoint.deletionMessages))
	for _, message := range checkpoint.deletionMessages {
		messages = append(messages, message)
	}
	sort.Slice(messages, func(i, j int) bool { return messages[i].message.Sequence < messages[j].message.Sequence })
	if int64(len(messages)) > request.MaximumMessageCount {
		messages = messages[:request.MaximumMessageCount]
	}
	selectedMessages := make(map[uuid.UUID]struct{}, len(messages))
	result := CheckpointCollectionResponse{RetryID: request.RetryID, CheckpointID: request.CheckpointID, PlanDigest: request.PlanDigest}
	for _, message := range messages {
		id := message.message.Envelope.MessageID
		selectedMessages[id] = struct{}{}
		delete(domain.messageByID, id)
		delete(checkpoint.deletionMessages, id)
		result.DeletedMessageCount++
		result.DeletedMessageByteCount += message.byteCount
		domain.messageBytes -= message.byteCount
	}
	if len(selectedMessages) > 0 {
		retained := domain.messages[:0]
		for _, message := range domain.messages {
			if _, selected := selectedMessages[message.message.Envelope.MessageID]; !selected {
				retained = append(retained, message)
			}
		}
		domain.messages = retained
	}
	blobIDs := make([]string, 0, len(checkpoint.deletionBlobs))
	for id := range checkpoint.deletionBlobs {
		blobIDs = append(blobIDs, id)
	}
	sort.Strings(blobIDs)
	if int64(len(blobIDs)) > request.MaximumBlobCount {
		blobIDs = blobIDs[:request.MaximumBlobCount]
	}
	for _, id := range blobIDs {
		blob := checkpoint.deletionBlobs[id]
		delete(checkpoint.deletionBlobs, id)
		delete(domain.blobs, id)
		result.DeletedBlobCount++
		result.DeletedBlobByteCount += blob.ByteCount
		domain.blobBytes -= blob.ByteCount
	}
	result.Completed = len(checkpoint.deletionMessages) == 0 && len(checkpoint.deletionBlobs) == 0
	domain.checkpointCollections[request.RetryID] = memoryCheckpointCollection{request: request, result: result}
	return result, nil
}

func memoryCheckpointPlan(domain *memoryDomain, checkpointID uuid.UUID) (CheckpointDryRunResponse, error) {
	checkpoint := domain.checkpoints[checkpointID]
	if checkpoint == nil {
		return CheckpointDryRunResponse{}, protocolError(CodeCheckpointNotFound, "checkpoint was not found")
	}
	if checkpoint.state != "activated" || len(domain.activatedCheckpoints) == 0 || domain.activatedCheckpoints[len(domain.activatedCheckpoints)-1] != checkpointID {
		return CheckpointDryRunResponse{}, protocolError(CodeCheckpointNotEligible, "only the latest activated checkpoint is collectable")
	}
	messages := make([]CheckpointPlanMessage, 0, len(checkpoint.deletionMessages))
	blobs := make([]CheckpointPlanBlob, 0, len(checkpoint.deletionBlobs))
	missing := make([]uuid.UUID, 0)
	for id := range checkpoint.required {
		subscription := domain.subscriptions[id]
		if subscription.Status != SubscriptionActive {
			continue
		}
		missingForSubscription := false
		for _, message := range checkpoint.deletionMessages {
			if message.publisherSubscription == id {
				continue
			}
			if memoryRebootstrapCompletionCovers(domain, id, message.message.Sequence) {
				continue
			}
			if _, ok := message.acknowledgments[id]; !ok {
				missingForSubscription = true
				break
			}
		}
		if missingForSubscription {
			missing = append(missing, id)
		}
	}
	sort.Slice(missing, func(i, j int) bool { return missing[i].String() < missing[j].String() })
	response := CheckpointDryRunResponse{CheckpointID: checkpointID, MissingCustodySubscriptionIDs: missing, Eligible: len(missing) == 0}
	for _, message := range checkpoint.deletionMessages {
		messages = append(messages, CheckpointPlanMessage{Sequence: message.message.Sequence, MessageID: message.message.Envelope.MessageID, ByteCount: message.byteCount})
		response.MessageCount++
		response.MessageByteCount += message.byteCount
	}
	for _, blob := range checkpoint.deletionBlobs {
		blobs = append(blobs, CheckpointPlanBlob{BlobID: blob.BlobID, ByteCount: blob.ByteCount})
		response.BlobCount++
		response.BlobByteCount += blob.ByteCount
	}
	response.PlanDigest = CheckpointPlanDigest(checkpoint.candidate.TenantID, checkpoint.candidate.DomainID, checkpointID, checkpoint.activationOrdinal, messages, blobs)
	return response, nil
}

// memoryRebootstrapCompletionCovers records checkpoint provenance, rather than
// weakening receipt custody. A device that completed a rebootstrap from an
// activated checkpoint has reconstructed all messages at or before that
// checkpoint's start sequence. Later messages still require their own applied
// acknowledgement before retention may collect them.
func memoryRebootstrapCompletionCovers(domain *memoryDomain, subscriptionID uuid.UUID, sequence uint64) bool {
	for _, completion := range domain.rebootstrapCompletions {
		if completion.subscriptionID == subscriptionID && completion.recoveryStartSequence >= sequence {
			return true
		}
	}
	return false
}
