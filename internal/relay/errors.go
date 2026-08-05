package relay

import (
	"errors"
	"fmt"
)

type ErrorCode string

const (
	CodeInvalidDomain               ErrorCode = "invalid_domain"
	CodeInvalidMember               ErrorCode = "invalid_member"
	CodeInvalidAdmission            ErrorCode = "invalid_admission"
	CodeInvalidEnvelope             ErrorCode = "invalid_envelope"
	CodeInvalidBlob                 ErrorCode = "invalid_blob"
	CodeInvalidCursor               ErrorCode = "invalid_cursor"
	CodeInvalidAcknowledgment       ErrorCode = "invalid_acknowledgment"
	CodeInvalidCredentialRotation   ErrorCode = "invalid_credential_rotation"
	CodeUnauthorized                ErrorCode = "unauthorized"
	CodeWrongScope                  ErrorCode = "wrong_scope"
	CodeDomainNotFound              ErrorCode = "domain_not_found"
	CodeMemberNotFound              ErrorCode = "member_not_found"
	CodeAdmissionNotFound           ErrorCode = "admission_not_found"
	CodeMemberExpired               ErrorCode = "member_expired"
	CodeMemberRevoked               ErrorCode = "member_revoked"
	CodeAdmissionExpired            ErrorCode = "admission_expired"
	CodeAdmissionRevoked            ErrorCode = "admission_revoked"
	CodeMissingCapability           ErrorCode = "missing_capability"
	CodeDomainCollision             ErrorCode = "domain_collision"
	CodeMemberCollision             ErrorCode = "member_collision"
	CodeAdmissionCollision          ErrorCode = "admission_collision"
	CodeAdmissionClaimed            ErrorCode = "admission_claimed"
	CodeCredentialRotationCollision ErrorCode = "credential_rotation_collision"
	CodeCredentialReuse             ErrorCode = "credential_reuse"
	CodeMessageCollision            ErrorCode = "message_collision"
	CodeBlobCollision               ErrorCode = "blob_collision"
	CodeMessageNotFound             ErrorCode = "message_not_found"
	CodeBlobNotFound                ErrorCode = "blob_not_found"
	CodeDomainFull                  ErrorCode = "domain_full"
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
