package relay

import (
	"errors"
	"fmt"
)

type ErrorCode string

const (
	CodeInvalidDomain               ErrorCode = "invalid_domain"
	CodeInvalidTenant               ErrorCode = "invalid_tenant"
	CodeInvalidSubscription         ErrorCode = "invalid_subscription"
	CodeInvalidMember               ErrorCode = "invalid_member"
	CodeInvalidAdmission            ErrorCode = "invalid_admission"
	CodeInvalidEnvelope             ErrorCode = "invalid_envelope"
	CodeInvalidBlob                 ErrorCode = "invalid_blob"
	CodeInvalidBlobUpload           ErrorCode = "invalid_blob_upload"
	CodeInvalidCursor               ErrorCode = "invalid_cursor"
	CodeInvalidAcknowledgment       ErrorCode = "invalid_acknowledgment"
	CodeInvalidCheckpoint           ErrorCode = "invalid_checkpoint"
	CodeInvalidCheckpointFence      ErrorCode = "invalid_checkpoint_fence"
	CodeCheckpointFenceNotFound     ErrorCode = "checkpoint_fence_not_found"
	CodeCheckpointFenceCollision    ErrorCode = "checkpoint_fence_collision"
	CodeCheckpointFenceActive       ErrorCode = "checkpoint_fence_active"
	CodeCheckpointNotFound          ErrorCode = "checkpoint_not_found"
	CodeCheckpointCollision         ErrorCode = "checkpoint_collision"
	CodeCheckpointNotEligible       ErrorCode = "checkpoint_not_eligible"
	CodeCheckpointUnavailable       ErrorCode = "checkpoint_unavailable"
	CodeRebootstrapIncomplete       ErrorCode = "rebootstrap_incomplete"
	CodeCollectionPlanStale         ErrorCode = "collection_plan_stale"
	CodeInvalidCredentialRotation   ErrorCode = "invalid_credential_rotation"
	CodeUnauthorized                ErrorCode = "unauthorized"
	CodeWrongScope                  ErrorCode = "wrong_scope"
	CodeDomainNotFound              ErrorCode = "domain_not_found"
	CodeTenantNotFound              ErrorCode = "tenant_not_found"
	CodeSubscriptionNotFound        ErrorCode = "subscription_not_found"
	CodeMemberNotFound              ErrorCode = "member_not_found"
	CodeAdmissionNotFound           ErrorCode = "admission_not_found"
	CodeMemberExpired               ErrorCode = "member_expired"
	CodeMemberRevoked               ErrorCode = "member_revoked"
	CodeAdmissionExpired            ErrorCode = "admission_expired"
	CodeAdmissionRevoked            ErrorCode = "admission_revoked"
	CodeMissingCapability           ErrorCode = "missing_capability"
	CodeDomainCollision             ErrorCode = "domain_collision"
	CodeTenantCollision             ErrorCode = "tenant_collision"
	CodeSubscriptionCollision       ErrorCode = "subscription_collision"
	CodeMemberCollision             ErrorCode = "member_collision"
	CodeAdmissionCollision          ErrorCode = "admission_collision"
	CodeAdmissionClaimed            ErrorCode = "admission_claimed"
	CodeCredentialRotationCollision ErrorCode = "credential_rotation_collision"
	CodeMemberCapabilityCollision   ErrorCode = "member_capability_collision"
	CodeCredentialReuse             ErrorCode = "credential_reuse"
	CodeMessageCollision            ErrorCode = "message_collision"
	CodeBlobCollision               ErrorCode = "blob_collision"
	CodeMessageNotFound             ErrorCode = "message_not_found"
	CodeBlobNotFound                ErrorCode = "blob_not_found"
	CodeBlobUploadNotFound          ErrorCode = "blob_upload_not_found"
	CodeBlobUploadCollision         ErrorCode = "blob_upload_collision"
	CodeDomainFull                  ErrorCode = "domain_full"
	CodeTenantFull                  ErrorCode = "tenant_full"
)

type ProtocolError struct {
	Code ErrorCode
	Err  error
}

func (e *ProtocolError) Error() string {
	if e.Err == nil {
		return string(e.Code)
	}
	return fmt.Sprintf("%s: %v", e.Code, e.Err)
}

func (e *ProtocolError) Unwrap() error {
	return e.Err
}

func protocolError(code ErrorCode, message string) error {
	return &ProtocolError{Code: code, Err: errors.New(message)}
}

func NewProtocolError(code ErrorCode, message string) error {
	return protocolError(code, message)
}

func ErrorHasCode(err error, code ErrorCode) bool {
	var protocol *ProtocolError
	return errors.As(err, &protocol) && protocol.Code == code
}
