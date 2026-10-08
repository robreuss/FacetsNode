package boxcontrol

import (
	"context"
	"crypto/sha256"
	"errors"
	"math"
	"sort"

	"github.com/google/uuid"
)

const (
	sharedWorkerAccessRequestLifetimeMilliseconds = int64(10 * 60 * 1000)
	sharedWorkerAccessGrantLifetimeMilliseconds   = int64(180 * 24 * 60 * 60 * 1000)
	maximumSharedWorkerAccessCodeFailures         = 5
)

var (
	ErrSharedWorkerAccess              = errors.New("BOX-WORKER-ACCESS: Worker access request or grant is invalid")
	ErrSharedWorkerAccessCode          = errors.New("BOX-WORKER-ACCESS-CODE: confirmation code is invalid")
	ErrSharedWorkerAccessLocked        = errors.New("BOX-WORKER-ACCESS-LOCKED: confirmation attempts are exhausted")
	ErrSharedWorkerAccessCodeCollision = errors.New("BOX-WORKER-ACCESS-CODE-COLLISION: generate another confirmation code")
)

type BoxSharedWorkerAccessDecision string

const (
	SharedWorkerAccessPending  BoxSharedWorkerAccessDecision = "pending"
	SharedWorkerAccessApproved BoxSharedWorkerAccessDecision = "approved"
	SharedWorkerAccessRejected BoxSharedWorkerAccessDecision = "rejected"
	SharedWorkerAccessExpired  BoxSharedWorkerAccessDecision = "expired"
	SharedWorkerAccessRevoked  BoxSharedWorkerAccessDecision = "revoked"
)

// BoxSharedWorkerAccessRequest is the exact signed request for one participant
// to use one advertised Worker at one capabilities revision. The confirmation
// code digest and connection grant are server-only custody fields.
type BoxSharedWorkerAccessRequest struct {
	Version                 int                           `json:"version"`
	RequestID               uuid.UUID                     `json:"requestID"`
	BoxID                   uuid.UUID                     `json:"boxID"`
	WorkerID                uuid.UUID                     `json:"workerID"`
	RequesterParticipantID  uuid.UUID                     `json:"requesterParticipantID"`
	RequesterDeviceID       uuid.UUID                     `json:"requesterDeviceID"`
	CapabilitiesDigest      string                        `json:"capabilitiesDigest"`
	RequestedAtMilliseconds int64                         `json:"requestedAtMilliseconds"`
	ExpiresAtMilliseconds   int64                         `json:"expiresAtMilliseconds"`
	ConnectionGrantID       uuid.UUID                     `json:"-"`
	ConfirmationCodeDigest  [32]byte                      `json:"-"`
	FailedCodeAttempts      int                           `json:"-"`
	Decision                BoxSharedWorkerAccessDecision `json:"-"`
	DecidedAtMilliseconds   int64                         `json:"-"`
	GrantID                 uuid.UUID                     `json:"-"`
}

func (value BoxSharedWorkerAccessRequest) validAt(nowMilliseconds int64) bool {
	return value.Version == 1 && value.RequestID != uuid.Nil && value.BoxID != uuid.Nil &&
		value.WorkerID != uuid.Nil && value.RequesterParticipantID != uuid.Nil &&
		value.RequesterDeviceID != uuid.Nil && value.ConnectionGrantID != uuid.Nil &&
		validParticipantRequestDigest(value.CapabilitiesDigest) &&
		value.RequestedAtMilliseconds > 0 && value.RequestedAtMilliseconds <= nowMilliseconds &&
		value.ExpiresAtMilliseconds > nowMilliseconds &&
		value.ExpiresAtMilliseconds-value.RequestedAtMilliseconds <= sharedWorkerAccessRequestLifetimeMilliseconds &&
		value.Decision == SharedWorkerAccessPending && value.FailedCodeAttempts == 0 &&
		value.DecidedAtMilliseconds == 0 && value.GrantID == uuid.Nil
}

type BoxSharedWorkerAccessGrant struct {
	Version                int       `json:"version"`
	GrantID                uuid.UUID `json:"grantID"`
	RequestID              uuid.UUID `json:"requestID"`
	BoxID                  uuid.UUID `json:"boxID"`
	WorkerID               uuid.UUID `json:"workerID"`
	OwnerParticipantID     uuid.UUID `json:"ownerParticipantID"`
	OwnerDeviceID          uuid.UUID `json:"ownerDeviceID"`
	GranteeParticipantID   uuid.UUID `json:"granteeParticipantID"`
	CapabilitiesDigest     string    `json:"capabilitiesDigest"`
	ConfirmationCodeDigest string    `json:"confirmationCodeDigest"`
	Revision               uint64    `json:"revision"`
	GrantedAtMilliseconds  int64     `json:"grantedAtMilliseconds"`
	ExpiresAtMilliseconds  int64     `json:"expiresAtMilliseconds"`
	RevokedAtMilliseconds  int64     `json:"revokedAtMilliseconds,omitempty"`
}

func (value BoxSharedWorkerAccessGrant) validAt(nowMilliseconds int64) bool {
	return value.Version == 1 && value.GrantID != uuid.Nil && value.RequestID != uuid.Nil &&
		value.BoxID != uuid.Nil && value.WorkerID != uuid.Nil &&
		value.OwnerParticipantID != uuid.Nil && value.OwnerDeviceID != uuid.Nil &&
		value.GranteeParticipantID != uuid.Nil &&
		value.OwnerParticipantID != value.GranteeParticipantID &&
		validParticipantRequestDigest(value.CapabilitiesDigest) &&
		validParticipantRequestDigest(value.ConfirmationCodeDigest) &&
		value.Revision > 0 && value.Revision <= math.MaxInt64 && value.GrantedAtMilliseconds > 0 &&
		value.GrantedAtMilliseconds <= nowMilliseconds &&
		value.ExpiresAtMilliseconds > nowMilliseconds &&
		value.ExpiresAtMilliseconds-value.GrantedAtMilliseconds <= sharedWorkerAccessGrantLifetimeMilliseconds &&
		value.RevokedAtMilliseconds == 0
}

type BoxSharedWorkerAccessRequestStatus struct {
	Version               int                           `json:"version"`
	RequestID             uuid.UUID                     `json:"requestID"`
	Decision              BoxSharedWorkerAccessDecision `json:"decision"`
	ExpiresAtMilliseconds int64                         `json:"expiresAtMilliseconds"`
	DecidedAtMilliseconds int64                         `json:"decidedAtMilliseconds"`
	Grant                 *BoxSharedWorkerAccessGrant   `json:"grant,omitempty"`
}

func SharedWorkerAccessCodeDigest(value string) ([32]byte, error) {
	value, err := NormalizeApprovalCode(value)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256([]byte("facets-box-worker-access-code-v1\x00" + value)), nil
}

func sharedWorkerAccessCodeDigestString(value [32]byte) string {
	return hexDigest(value[:])
}

func hexDigest(value []byte) string {
	const alphabet = "0123456789abcdef"
	result := make([]byte, len(value)*2)
	for index, byteValue := range value {
		result[index*2] = alphabet[byteValue>>4]
		result[index*2+1] = alphabet[byteValue&0x0f]
	}
	return string(result)
}

func (store *MemoryStore) CreateSharedWorkerAccessRequest(
	_ context.Context,
	value BoxSharedWorkerAccessRequest,
	nowMilliseconds int64,
) error {
	if !value.validAt(nowMilliseconds) {
		return ErrSharedWorkerAccess
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	worker, exists := store.sharedWorkers[value.WorkerID]
	requester, enrolled := store.participantEnrollments[value.RequesterParticipantID]
	if !exists || !enrolled || store.state == nil || !store.state.Claimed() ||
		store.state.BoxID != value.BoxID || worker.BoxID != value.BoxID ||
		worker.ExpiresAtMilliseconds <= nowMilliseconds ||
		worker.CapabilitiesDigest != value.CapabilitiesDigest ||
		requester.Device.DeviceID != value.RequesterDeviceID ||
		!requester.validInitialAt(nowMilliseconds) ||
		worker.OwnerParticipantID == value.RequesterParticipantID {
		return ErrSharedWorkerAccess
	}
	if _, exists := store.sharedWorkerRequests[value.RequestID]; exists {
		return ErrSharedWorkerAccess
	}
	for _, existing := range store.sharedWorkerRequests {
		if existing.Decision == SharedWorkerAccessPending &&
			existing.ExpiresAtMilliseconds > nowMilliseconds &&
			existing.ConfirmationCodeDigest == value.ConfirmationCodeDigest {
			return ErrSharedWorkerAccessCodeCollision
		}
	}
	store.sharedWorkerRequests[value.RequestID] = value
	return nil
}

func (store *MemoryStore) SharedWorkerAccessRequest(
	_ context.Context,
	requestID, connectionGrantID uuid.UUID,
	nowMilliseconds int64,
) (BoxSharedWorkerAccessRequestStatus, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	value, exists := store.sharedWorkerRequests[requestID]
	if !exists || value.ConnectionGrantID != connectionGrantID {
		return BoxSharedWorkerAccessRequestStatus{}, ErrSharedWorkerAccess
	}
	if value.Decision == SharedWorkerAccessPending && value.ExpiresAtMilliseconds <= nowMilliseconds {
		value.Decision = SharedWorkerAccessExpired
		value.DecidedAtMilliseconds = nowMilliseconds
		store.sharedWorkerRequests[requestID] = value
	}
	status := BoxSharedWorkerAccessRequestStatus{
		Version: 1, RequestID: value.RequestID, Decision: value.Decision,
		ExpiresAtMilliseconds: value.ExpiresAtMilliseconds,
		DecidedAtMilliseconds: value.DecidedAtMilliseconds,
	}
	if value.GrantID != uuid.Nil {
		grant, exists := store.sharedWorkerGrants[value.GrantID]
		if !exists {
			return BoxSharedWorkerAccessRequestStatus{}, ErrSharedWorkerAccess
		}
		copy := grant
		status.Grant = &copy
	}
	return status, nil
}

func (store *MemoryStore) ConfirmSharedWorkerAccess(
	_ context.Context,
	grant BoxSharedWorkerAccessGrant,
	codeDigest [32]byte,
	nowMilliseconds int64,
) error {
	if !grant.validAt(nowMilliseconds) {
		return ErrSharedWorkerAccess
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	request, exists := store.sharedWorkerRequests[grant.RequestID]
	worker, workerExists := store.sharedWorkers[grant.WorkerID]
	owner, ownerExists := store.participantEnrollments[grant.OwnerParticipantID]
	grantee, granteeExists := store.participantEnrollments[grant.GranteeParticipantID]
	if !exists || request.Decision != SharedWorkerAccessPending ||
		request.ExpiresAtMilliseconds <= nowMilliseconds || !workerExists ||
		worker.ExpiresAtMilliseconds <= nowMilliseconds || !ownerExists || !granteeExists ||
		worker.BoxID != grant.BoxID || worker.OwnerParticipantID != grant.OwnerParticipantID ||
		worker.OwnerDeviceID != grant.OwnerDeviceID || worker.CapabilitiesDigest != grant.CapabilitiesDigest ||
		request.BoxID != grant.BoxID || request.WorkerID != grant.WorkerID ||
		request.RequesterParticipantID != grant.GranteeParticipantID ||
		request.CapabilitiesDigest != grant.CapabilitiesDigest ||
		owner.Device.DeviceID != grant.OwnerDeviceID || !owner.validInitialAt(nowMilliseconds) ||
		grantee.Device.DeviceID != request.RequesterDeviceID || !grantee.validInitialAt(nowMilliseconds) ||
		sharedWorkerAccessCodeDigestString(codeDigest) != grant.ConfirmationCodeDigest {
		return ErrSharedWorkerAccess
	}
	if request.ConfirmationCodeDigest != codeDigest {
		request.FailedCodeAttempts++
		if request.FailedCodeAttempts >= maximumSharedWorkerAccessCodeFailures {
			request.Decision = SharedWorkerAccessRejected
			request.DecidedAtMilliseconds = nowMilliseconds
			store.sharedWorkerRequests[request.RequestID] = request
			return ErrSharedWorkerAccessLocked
		}
		store.sharedWorkerRequests[request.RequestID] = request
		return ErrSharedWorkerAccessCode
	}
	if _, exists := store.sharedWorkerGrants[grant.GrantID]; exists {
		return ErrSharedWorkerAccess
	}
	for _, existing := range store.sharedWorkerGrants {
		if existing.RequestID == grant.RequestID {
			return ErrSharedWorkerAccess
		}
	}
	request.Decision = SharedWorkerAccessApproved
	request.DecidedAtMilliseconds = nowMilliseconds
	request.GrantID = grant.GrantID
	store.sharedWorkerRequests[request.RequestID] = request
	store.sharedWorkerGrants[grant.GrantID] = grant
	return nil
}

func (store *MemoryStore) RevokeSharedWorkerAccess(
	_ context.Context,
	boxID, grantID, ownerParticipantID uuid.UUID,
	revision uint64,
	nowMilliseconds int64,
) error {
	if boxID == uuid.Nil || grantID == uuid.Nil || ownerParticipantID == uuid.Nil ||
		revision == 0 || nowMilliseconds <= 0 {
		return ErrSharedWorkerAccess
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	grant, exists := store.sharedWorkerGrants[grantID]
	if !exists || grant.BoxID != boxID || grant.OwnerParticipantID != ownerParticipantID ||
		grant.RevokedAtMilliseconds != 0 || revision <= grant.Revision {
		return ErrSharedWorkerAccess
	}
	grant.Revision = revision
	grant.RevokedAtMilliseconds = nowMilliseconds
	store.sharedWorkerGrants[grantID] = grant
	request := store.sharedWorkerRequests[grant.RequestID]
	request.Decision = SharedWorkerAccessRevoked
	request.DecidedAtMilliseconds = nowMilliseconds
	store.sharedWorkerRequests[request.RequestID] = request
	return nil
}

func (store *MemoryStore) activeSharedWorkerAccessGrants(
	participantID uuid.UUID,
	nowMilliseconds int64,
) []BoxSharedWorkerAccessGrant {
	store.mu.Lock()
	defer store.mu.Unlock()
	var result []BoxSharedWorkerAccessGrant
	for _, grant := range store.sharedWorkerGrants {
		if grant.GranteeParticipantID == participantID &&
			grant.RevokedAtMilliseconds == 0 && grant.ExpiresAtMilliseconds > nowMilliseconds {
			result = append(result, grant)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].GrantID.String() < result[j].GrantID.String()
	})
	return result
}
