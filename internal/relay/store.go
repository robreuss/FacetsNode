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
