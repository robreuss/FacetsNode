package devicesync

import (
	"errors"
	"fmt"
)

type ErrorCode string

const (
	CodeInvalidAdmission   ErrorCode = "invalid_device_sync_admission"
	CodeInvalidPrincipal   ErrorCode = "invalid_device_sync_principal"
	CodeUnauthorized       ErrorCode = "device_sync_unauthorized"
	CodeWrongScope         ErrorCode = "device_sync_wrong_scope"
	CodeAdmissionNotFound  ErrorCode = "device_sync_admission_not_found"
	CodeAdmissionExpired   ErrorCode = "device_sync_admission_expired"
	CodeAdmissionClaimed   ErrorCode = "device_sync_admission_claimed"
	CodeAdmissionCollision ErrorCode = "device_sync_admission_collision"
	CodePrincipalCollision ErrorCode = "device_sync_principal_collision"
	CodeDeviceCollision    ErrorCode = "device_sync_device_collision"
	CodeInvalidSpace       ErrorCode = "invalid_device_sync_space"
	CodeSpaceCollision     ErrorCode = "device_sync_space_collision"
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

func (e *ProtocolError) Unwrap() error { return e.Err }

func NewProtocolError(code ErrorCode, message string) error {
	return &ProtocolError{Code: code, Err: errors.New(message)}
}

func ErrorHasCode(err error, code ErrorCode) bool {
	var protocol *ProtocolError
	return errors.As(err, &protocol) && protocol.Code == code
}
