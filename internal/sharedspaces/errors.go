package sharedspaces

import (
	"errors"
	"fmt"
)

type ErrorCode string

const (
	CodeInvalidSpace                     ErrorCode = "invalid_shared_space"
	CodeSpaceCollision                   ErrorCode = "shared_space_collision"
	CodeSpaceNotFound                    ErrorCode = "shared_space_not_found"
	CodeInvalidInvitation                ErrorCode = "invalid_shared_space_invitation"
	CodeInvitationCollision              ErrorCode = "shared_space_invitation_collision"
	CodeInvitationNotFound               ErrorCode = "shared_space_invitation_not_found"
	CodeInvitationClaimed                ErrorCode = "shared_space_invitation_claimed"
	CodeInvitationCancelled              ErrorCode = "shared_space_invitation_cancelled"
	CodeInvitationCancellationCollision  ErrorCode = "shared_space_invitation_cancellation_collision"
	CodeInvalidParticipant               ErrorCode = "invalid_shared_space_participant"
	CodeInvalidParticipantPresentation   ErrorCode = "invalid_shared_space_participant_presentation"
	CodeParticipantCollision             ErrorCode = "shared_space_participant_collision"
	CodeParticipantPresentationCollision ErrorCode = "shared_space_participant_presentation_collision"
	CodeParticipantRoleCollision         ErrorCode = "shared_space_participant_role_collision"
	CodeParticipantNotFound              ErrorCode = "shared_space_participant_not_found"
	CodeParticipantRevoked               ErrorCode = "shared_space_participant_revoked"
	CodeParticipantRosterUnavailable     ErrorCode = "shared_space_participant_roster_unavailable"
	CodeInitialHost                      ErrorCode = "shared_space_initial_host"
	CodeUnauthorized                     ErrorCode = "shared_space_unauthorized"
	CodeWrongScope                       ErrorCode = "shared_space_wrong_scope"
	CodeWrongKeyEpoch                    ErrorCode = "shared_space_wrong_key_epoch"
	CodeKeyGrantNotFound                 ErrorCode = "shared_space_key_grant_not_found"
	CodeBootstrapNotReady                ErrorCode = "shared_space_bootstrap_not_ready"
	CodeInvalidAuthorityEvent            ErrorCode = "invalid_shared_space_authority_event"
	CodeInvalidComputePool               ErrorCode = "invalid_shared_space_compute_pool"
	CodeComputePoolCollision             ErrorCode = "shared_space_compute_pool_collision"
	CodeComputePoolNotFound              ErrorCode = "shared_space_compute_pool_not_found"
	CodeInvalidComputeCapability         ErrorCode = "invalid_shared_space_compute_capability"
	CodeComputeCapabilityUnauthorized    ErrorCode = "shared_space_compute_capability_unauthorized"
	CodeComputeCapabilityExpired         ErrorCode = "shared_space_compute_capability_expired"
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
