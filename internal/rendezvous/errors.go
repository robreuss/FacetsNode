package rendezvous

import (
	"errors"
	"fmt"
)

type ErrorCode string

const (
	CodeInvalidRegistration   ErrorCode = "invalid_registration"
	CodeInvalidEnvelope       ErrorCode = "invalid_envelope"
	CodeUnauthorized          ErrorCode = "unauthorized"
	CodeWrongRoute            ErrorCode = "wrong_route"
	CodeRouteNotFound         ErrorCode = "route_not_found"
	CodeRouteExpired          ErrorCode = "route_expired"
	CodeRouteClosed           ErrorCode = "route_closed"
	CodeRouteCollision        ErrorCode = "route_collision"
	CodeMessageExpired        ErrorCode = "message_expired"
	CodeMessageCollision      ErrorCode = "message_collision"
	CodeMessageNotFound       ErrorCode = "message_not_found"
	CodeInvalidAcknowledgment ErrorCode = "invalid_acknowledgment"
	CodeMailboxFull           ErrorCode = "mailbox_full"
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
