package relay

import (
	"context"

	"github.com/google/uuid"
)

type Store interface {
	ProvisionTenant(
		ctx context.Context,
		tenant TenantRegistration,
		initialDomain DomainProvisioning,
	) (TenantProvisioningResult, error)
	ProvisionDomain(
		ctx context.Context,
		credential TenantCredential,
		domain DomainProvisioning,
		nowMilliseconds int64,
	) (DomainProvisioningResult, error)
	RotateTenantCredential(
		ctx context.Context,
		credential TenantCredential,
		rotation TenantCredentialRotation,
	) (TenantCredentialRotationResult, error)
	GetTenantStatus(context.Context, TenantCredential) (TenantStatus, error)
	CreateSubscription(
		context.Context,
		AdministrationCredential,
		SubscriptionCreateRequest,
	) (SubscriptionCreateResponse, error)
	GetSubscription(
		context.Context,
		AdministrationCredential,
		uuid.UUID,
	) (Subscription, error)
	ChangeSubscriptionStatus(
		context.Context,
		AdministrationCredential,
		uuid.UUID,
		SubscriptionStatusChangeRequest,
	) (SubscriptionStatusChangeResponse, error)
	GetDomainStatus(context.Context, AdministrationCredential) (DomainStatus, error)
	CreateCheckpointFence(context.Context, Credential, CheckpointFenceRequest, int64) (CheckpointFenceResponse, error)
	GetCheckpointFence(context.Context, Credential, uuid.UUID, int64) (CheckpointFenceState, error)
	AbortCheckpointFence(context.Context, Credential, CheckpointFenceAbortRequest, int64) (CheckpointFenceAbortResponse, error)
	StageCheckpoint(context.Context, Credential, CheckpointCandidate, int64) (CheckpointStageResponse, error)
	ActivateCheckpoint(context.Context, AdministrationCredential, CheckpointActivationRequest, int64) (CheckpointActivationResponse, error)
	DryRunCheckpointCollection(context.Context, AdministrationCredential, CheckpointDryRunRequest) (CheckpointDryRunResponse, error)
	CollectCheckpoint(context.Context, AdministrationCredential, CheckpointCollectionRequest) (CheckpointCollectionResponse, error)
	CreateSubscriptionMember(
		ctx context.Context,
		credential AdministrationCredential,
		subscriptionID uuid.UUID,
		registration MemberRegistration,
		nowMilliseconds int64,
	) (Acceptance, error)
	RotateAdministrationCredential(
		ctx context.Context,
		credential AdministrationCredential,
		rotation CredentialRotation,
		nowMilliseconds int64,
	) (CredentialRotationResult, error)
	RotateMemberCredential(
		ctx context.Context,
		credential Credential,
		rotation CredentialRotation,
		nowMilliseconds int64,
	) (CredentialRotationResult, error)
	CreateSubscriptionAdmission(
		ctx context.Context,
		credential AdministrationCredential,
		subscriptionID uuid.UUID,
		registration MemberAdmission,
		nowMilliseconds int64,
	) (SubscriptionAdmissionCreateResult, error)
	ClaimSubscriptionAdmission(
		ctx context.Context,
		credential AdmissionCredential,
		claim MemberAdmissionClaim,
		nowMilliseconds int64,
	) (SubscriptionAdmissionClaimResult, error)
	RevokeAdmission(
		ctx context.Context,
		credential AdministrationCredential,
		admissionID uuid.UUID,
		nowMilliseconds int64,
	) (Acceptance, error)
	CollectAdmissions(
		ctx context.Context,
		credential AdministrationCredential,
		nowMilliseconds int64,
	) (AdmissionCollectionResult, error)
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
	CreateBlobUpload(context.Context, Credential, BlobUploadRequest, int64) (BlobUploadCreateResponse, error)
	GetBlobUpload(context.Context, Credential, uuid.UUID, int64) (BlobUploadStatus, error)
	AppendBlobUploadChunk(context.Context, Credential, BlobUploadChunkRequest, int64, func(BlobUploadStatus) error) (BlobUploadStatus, error)
	FinalizeBlobUpload(context.Context, Credential, BlobUploadFinalizationRequest, int64, func(BlobUploadStatus) error) (BlobUploadFinalizationResponse, error)
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

type BlobUploadExpiry struct {
	Scope    BlobScope
	UploadID uuid.UUID
}

type BlobMaintenanceStore interface {
	ExpireBlobUploads(context.Context, int64, int64) ([]BlobUploadExpiry, error)
	DeleteBlobIfUnauthorized(context.Context, BlobFileCandidate, int64, int64, func() error) (bool, error)
	DeleteBlobUploadIfUnauthorized(context.Context, BlobUploadFileCandidate, int64, int64, func() error) (bool, error)
}
