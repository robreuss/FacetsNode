package relay

import (
	"context"

	"github.com/google/uuid"
)

type memoryBlobUpload struct {
	request           BlobUploadRequest
	status            BlobUploadStatus
	subscriptionID    uuid.UUID
	publisherMemberID uuid.UUID
	chunks            map[int64]BlobUploadChunkRequest
}

type memoryBlobUploadFinalization struct {
	request BlobUploadFinalizationRequest
	result  BlobUploadFinalizationResponse
}

func (s *MemoryStore) CreateBlobUpload(
	_ context.Context,
	credential Credential,
	request BlobUploadRequest,
	nowMilliseconds int64,
) (BlobUploadCreateResponse, error) {
	if err := request.Validate(); err != nil {
		return BlobUploadCreateResponse{}, err
	}
	if request.CreatedAtMilliseconds > nowMilliseconds {
		return BlobUploadCreateResponse{}, protocolError(CodeInvalidBlobUpload, "blob upload creation is in the future")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	domain, err := s.authorizedMember(credential, CapabilityPublishBlob, nowMilliseconds)
	if err != nil {
		return BlobUploadCreateResponse{}, err
	}
	subscription, err := activeMemberSubscription(domain, credential.MemberID)
	if err != nil {
		return BlobUploadCreateResponse{}, err
	}
	if existingID, ok := domain.blobUploadCreates[request.RetryID]; ok {
		existing := domain.blobUploads[existingID]
		if existing != nil && existing.request == request && existing.subscriptionID == subscription.SubscriptionID {
			return BlobUploadCreateResponse{Acceptance: AcceptanceDuplicate, RetryID: request.RetryID, Status: existing.status}, nil
		}
		return BlobUploadCreateResponse{}, protocolError(CodeBlobUploadCollision, "blob upload retry ID was reused")
	}
	if err := memoryFenceAllowsWrite(domain, subscription.SubscriptionID, nowMilliseconds); err != nil {
		return BlobUploadCreateResponse{}, err
	}
	if existing := domain.blobUploads[request.UploadID]; existing != nil {
		return BlobUploadCreateResponse{}, protocolError(CodeBlobUploadCollision, "blob upload ID was reused")
	}
	if blob, ok := domain.blobs[request.RelayBlobID]; ok {
		if blob.ByteCount != request.ByteCount {
			return BlobUploadCreateResponse{}, protocolError(CodeBlobCollision, "blob ID was reused with a different length")
		}
		return BlobUploadCreateResponse{}, protocolError(CodeBlobUploadCollision, "blob is already published")
	}
	if int64(len(domain.blobs))+domain.reservedBlobCount >= int64(domain.registration.MaximumBlobCount) ||
		request.ByteCount > domain.registration.MaximumBlobByteCount-domain.blobBytes-domain.reservedBlobBytes {
		return BlobUploadCreateResponse{}, protocolError(CodeDomainFull, "domain reached its blob quota")
	}
	if err := s.ensureTenantBlobCapacityLocked(credential.TenantID, request.ByteCount); err != nil {
		return BlobUploadCreateResponse{}, err
	}
	status := BlobUploadStatus{
		UploadID: request.UploadID, RelayBlobID: request.RelayBlobID,
		ByteCount: request.ByteCount, CreatedAtMilliseconds: request.CreatedAtMilliseconds,
		UpdatedAtMilliseconds: request.CreatedAtMilliseconds,
	}
	domain.blobUploads[request.UploadID] = &memoryBlobUpload{
		request: request, status: status, subscriptionID: subscription.SubscriptionID,
		publisherMemberID: credential.MemberID, chunks: make(map[int64]BlobUploadChunkRequest),
	}
	domain.blobUploadCreates[request.RetryID] = request.UploadID
	domain.reservedBlobCount++
	domain.reservedBlobBytes += request.ByteCount
	return BlobUploadCreateResponse{Acceptance: AcceptanceAccepted, RetryID: request.RetryID, Status: status}, nil
}

func (s *MemoryStore) GetBlobUpload(
	_ context.Context, credential Credential, uploadID uuid.UUID, nowMilliseconds int64,
) (BlobUploadStatus, error) {
	if uploadID == uuid.Nil {
		return BlobUploadStatus{}, protocolError(CodeInvalidBlobUpload, "blob upload ID is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	domain, err := s.authorizedMember(credential, CapabilityPublishBlob, nowMilliseconds)
	if err != nil {
		return BlobUploadStatus{}, err
	}
	upload := domain.blobUploads[uploadID]
	if upload == nil {
		return BlobUploadStatus{}, protocolError(CodeBlobUploadNotFound, "blob upload was not found")
	}
	subscription, err := activeMemberSubscription(domain, credential.MemberID)
	if err != nil || subscription.SubscriptionID != upload.subscriptionID {
		return BlobUploadStatus{}, protocolError(CodeWrongScope, "blob upload belongs to another subscription")
	}
	return upload.status, nil
}

func (s *MemoryStore) AppendBlobUploadChunk(
	_ context.Context, credential Credential, request BlobUploadChunkRequest,
	nowMilliseconds int64, write func(BlobUploadStatus) error,
) (BlobUploadStatus, error) {
	if err := request.Validate(); err != nil {
		return BlobUploadStatus{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	domain, err := s.authorizedMember(credential, CapabilityPublishBlob, nowMilliseconds)
	if err != nil {
		return BlobUploadStatus{}, err
	}
	upload := domain.blobUploads[request.UploadID]
	if upload == nil {
		return BlobUploadStatus{}, protocolError(CodeBlobUploadNotFound, "blob upload was not found")
	}
	subscription, err := activeMemberSubscription(domain, credential.MemberID)
	if err != nil || subscription.SubscriptionID != upload.subscriptionID {
		return BlobUploadStatus{}, protocolError(CodeWrongScope, "blob upload belongs to another subscription")
	}
	if existing, ok := upload.chunks[request.Offset]; ok {
		if existing == request {
			return upload.status, nil
		}
		return BlobUploadStatus{}, protocolError(CodeBlobUploadCollision, "blob upload chunk offset was reused")
	}
	if err := memoryFenceAllowsWrite(domain, subscription.SubscriptionID, nowMilliseconds); err != nil {
		return BlobUploadStatus{}, err
	}
	if upload.status.Finalized || request.Offset != upload.status.CommittedOffset ||
		request.ByteCount > upload.status.ByteCount-request.Offset {
		return BlobUploadStatus{}, protocolError(CodeInvalidBlobUpload, "blob upload chunk is not contiguous")
	}
	if write == nil {
		return BlobUploadStatus{}, protocolError(CodeInvalidBlobUpload, "blob upload writer is missing")
	}
	if err := write(upload.status); err != nil {
		return BlobUploadStatus{}, err
	}
	upload.chunks[request.Offset] = request
	upload.status.CommittedOffset += request.ByteCount
	upload.status.UpdatedAtMilliseconds = nowMilliseconds
	return upload.status, nil
}

func (s *MemoryStore) FinalizeBlobUpload(
	_ context.Context, credential Credential, request BlobUploadFinalizationRequest,
	nowMilliseconds int64, publish func(BlobUploadStatus) error,
) (BlobUploadFinalizationResponse, error) {
	if err := request.Validate(); err != nil {
		return BlobUploadFinalizationResponse{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	domain, err := s.authorizedMember(credential, CapabilityPublishBlob, nowMilliseconds)
	if err != nil {
		return BlobUploadFinalizationResponse{}, err
	}
	if existing, ok := domain.blobUploadFinalizations[request.RetryID]; ok {
		if existing.request == request {
			result := existing.result
			result.Acceptance = AcceptanceDuplicate
			return result, nil
		}
		return BlobUploadFinalizationResponse{}, protocolError(CodeBlobUploadCollision, "blob upload finalization retry ID was reused")
	}
	upload := domain.blobUploads[request.UploadID]
	if upload == nil {
		return BlobUploadFinalizationResponse{}, protocolError(CodeBlobUploadNotFound, "blob upload was not found")
	}
	subscription, err := activeMemberSubscription(domain, credential.MemberID)
	if err != nil || subscription.SubscriptionID != upload.subscriptionID {
		return BlobUploadFinalizationResponse{}, protocolError(CodeWrongScope, "blob upload belongs to another subscription")
	}
	if err := memoryFenceAllowsWrite(domain, subscription.SubscriptionID, nowMilliseconds); err != nil {
		return BlobUploadFinalizationResponse{}, err
	}
	if request.RelayBlobID != upload.status.RelayBlobID || request.ByteCount != upload.status.ByteCount ||
		upload.status.CommittedOffset != upload.status.ByteCount {
		return BlobUploadFinalizationResponse{}, protocolError(CodeInvalidBlobUpload, "blob upload finalization does not match staged content")
	}
	existing, published := domain.blobs[request.RelayBlobID]
	if published && existing.ByteCount != request.ByteCount {
		return BlobUploadFinalizationResponse{}, protocolError(CodeBlobCollision, "blob ID was reused with a different length")
	}
	if !published {
		if publish == nil {
			return BlobUploadFinalizationResponse{}, protocolError(CodeInvalidBlobUpload, "blob upload publisher is missing")
		}
		if err := publish(upload.status); err != nil {
			return BlobUploadFinalizationResponse{}, err
		}
		domain.blobs[request.RelayBlobID] = BlobMetadata{
			TenantID: credential.TenantID, DomainID: credential.DomainID,
			BlobID: request.RelayBlobID, PublisherMemberID: upload.publisherMemberID,
			ByteCount: request.ByteCount, CreatedAtMilliseconds: nowMilliseconds,
		}
		if fence := memoryActiveFenceForSubscription(domain, subscription.SubscriptionID); fence != nil {
			domain.blobFenceIDs[request.RelayBlobID] = fence.state.FenceID
		}
		domain.blobBytes += request.ByteCount
	}
	domain.reservedBlobCount--
	domain.reservedBlobBytes -= request.ByteCount
	upload.status.Finalized = true
	upload.status.UpdatedAtMilliseconds = nowMilliseconds
	result := BlobUploadFinalizationResponse{
		Acceptance: AcceptanceAccepted, RetryID: request.RetryID, UploadID: request.UploadID,
		RelayBlobID: request.RelayBlobID, ByteCount: request.ByteCount,
	}
	domain.blobUploadFinalizations[request.RetryID] = memoryBlobUploadFinalization{request: request, result: result}
	return result, nil
}
