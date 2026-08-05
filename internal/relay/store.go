package relay

import (
	"context"

	"github.com/google/uuid"
)

type Store interface {
	CreateDomain(
		ctx context.Context,
		registration DomainRegistration,
		initialMember MemberRegistration,
	) (Acceptance, error)
	CreateMember(
		ctx context.Context,
		credential AdministrationCredential,
		registration MemberRegistration,
		nowMilliseconds int64,
	) (Acceptance, error)
	RevokeMember(
		ctx context.Context,
		credential AdministrationCredential,
		memberID uuid.UUID,
		nowMilliseconds int64,
	) (Acceptance, error)
	Publish(
		ctx context.Context,
		credential Credential,
		envelope Envelope,
		nowMilliseconds int64,
	) (PublishResult, error)
	Fetch(
		ctx context.Context,
		credential Credential,
		afterSequence uint64,
		limit int,
		nowMilliseconds int64,
	) (FetchResult, error)
	Acknowledge(
		ctx context.Context,
		credential Credential,
		messageID uuid.UUID,
		stage AcknowledgmentStage,
		nowMilliseconds int64,
	) (AcknowledgmentResult, error)
	PrepareBlobPublish(
		ctx context.Context,
		credential Credential,
		blobID string,
		byteCount int64,
		nowMilliseconds int64,
	) error
	CommitBlobPublish(
		ctx context.Context,
		credential Credential,
		blobID string,
		byteCount int64,
		nowMilliseconds int64,
	) (BlobPublishResult, error)
	GetBlobMetadata(
		ctx context.Context,
		credential Credential,
		blobID string,
		nowMilliseconds int64,
	) (BlobMetadata, error)
}
