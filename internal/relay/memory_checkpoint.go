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
		if existing != nil && existing.candidateDigest == CheckpointCandidateDigest(candidate) && existing.publisherMemberID == credential.MemberID {
			return CheckpointStageResponse{Acceptance: AcceptanceDuplicate, RetryID: candidate.RetryID, CheckpointID: candidate.CheckpointID}, nil
		}
		return CheckpointStageResponse{}, protocolError(CodeCheckpointCollision, "checkpoint retry ID was reused")
	}
	if _, ok := domain.checkpoints[candidate.CheckpointID]; ok {
		return CheckpointStageResponse{}, protocolError(CodeCheckpointCollision, "checkpoint ID was reused")
	}
	for _, messageID := range candidate.RetainedMessageIDs {
		message := domain.messageByID[messageID]
		if message == nil || message.message.Sequence > coveredThrough {
			return CheckpointStageResponse{}, protocolError(CodeInvalidCheckpoint, "retained message is missing or beyond coverage")
		}
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

func (s *MemoryStore) ActivateCheckpoint(_ context.Context, credential AdministrationCredential, request CheckpointActivationRequest) (CheckpointActivationResponse, error) {
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
	if checkpoint.state != "staged" || request.ActivatedAtMilliseconds < checkpoint.candidate.CreatedAtMilliseconds {
		return CheckpointActivationResponse{}, protocolError(CodeCheckpointCollision, "checkpoint was already activated or activation time is invalid")
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
	for _, id := range checkpoint.candidate.RetainedMessageIDs {
		sequence := domain.messageByID[id].message.Sequence
		if sequence > 0 && (checkpoint.startSequence == checkpoint.coveredThrough || sequence-1 < checkpoint.startSequence) {
			checkpoint.startSequence = sequence - 1
		}
	}
	domain.checkpointOrdinal++
	checkpoint.activationOrdinal = domain.checkpointOrdinal
	checkpoint.activationRequest = request
	checkpoint.state = "activated"
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
