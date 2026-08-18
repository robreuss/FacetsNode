package sharedspaces

import (
	"errors"
	"fmt"
)

type ErrorCode string

const (
	CodeInvalidSpace         ErrorCode = "invalid_shared_space"
	CodeSpaceCollision       ErrorCode = "shared_space_collision"
	CodeSpaceNotFound        ErrorCode = "shared_space_not_found"
	CodeInvalidInvitation    ErrorCode = "invalid_shared_space_invitation"
	CodeInvitationCollision  ErrorCode = "shared_space_invitation_collision"
	CodeInvitationNotFound   ErrorCode = "shared_space_invitation_not_found"
	CodeInvitationClaimed    ErrorCode = "shared_space_invitation_claimed"
	CodeInvalidParticipant   ErrorCode = "invalid_shared_space_participant"
	CodeParticipantCollision ErrorCode = "shared_space_participant_collision"
	CodeParticipantNotFound  ErrorCode = "shared_space_participant_not_found"
	CodeParticipantRevoked   ErrorCode = "shared_space_participant_revoked"
	CodeInitialHost          ErrorCode = "shared_space_initial_host"
	CodeUnauthorized         ErrorCode = "shared_space_unauthorized"
	CodeWrongScope           ErrorCode = "shared_space_wrong_scope"
	CodeWrongKeyEpoch        ErrorCode = "shared_space_wrong_key_epoch"
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
