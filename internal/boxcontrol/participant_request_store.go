package boxcontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"reflect"
	"sort"
	"strconv"
	"time"

	"github.com/google/uuid"
)

const participantRequestLifetimeMilliseconds = int64(30 * 60 * 1000)
const maximumPendingParticipantRequests = 256
const maximumPendingRequestsPerConnection = 4

func participantPresentationDigest(presentation BoxParticipantPresentation) string {
	// The unambiguous NUL-delimited UTF-8 form is portable across Swift and Go.
	// Valid presentations exclude control characters, including NUL.
	message := "facets-box-participant-presentation-v1\x00" +
		presentation.ParticipantID.String() + "\x00" + presentation.DisplayName + "\x00" +
		strconv.FormatUint(presentation.Revision, 10)
	digest := sha256.Sum256([]byte(message))
	return hex.EncodeToString(digest[:])
}

type BoxParticipantEnrollmentRequest struct {
	RequestID             uuid.UUID                  `json:"requestID"`
	ConnectionGrantID     uuid.UUID                  `json:"-"`
	ConnectionDeviceName  string                     `json:"-"`
	Enrollment            BoxParticipantEnrollment   `json:"enrollment"`
	Presentation          BoxParticipantPresentation `json:"presentation"`
	Proof                 BoxSignedParticipantProof  `json:"proof"`
	RequestedAtMillis     int64                      `json:"requestedAtMilliseconds"`
	ExpiresAtMillis       int64                      `json:"expiresAtMilliseconds"`
	Decision              string                     `json:"decision"`
	DecidedAtMilliseconds int64                      `json:"decidedAtMilliseconds"`
}

func (request BoxParticipantEnrollmentRequest) validSubmissionAt(now int64) bool {
	if request.RequestID == uuid.Nil || request.ConnectionGrantID == uuid.Nil ||
		request.RequestedAtMillis <= 0 || request.RequestedAtMillis > now ||
		request.RequestedAtMillis > math.MaxInt64-participantRequestLifetimeMilliseconds ||
		now-request.RequestedAtMillis > maximumParticipantProofAgeMilliseconds ||
		request.ExpiresAtMillis != request.RequestedAtMillis+participantRequestLifetimeMilliseconds ||
		request.Decision != "pending" || request.DecidedAtMilliseconds != 0 ||
		request.Enrollment.Anchor.ApprovedAtMilliseconds != 0 ||
		request.Enrollment.Anchor.RevokedAtMilliseconds != 0 ||
		request.Enrollment.Device.RevokedThroughGeneration != 0 ||
		request.Presentation.ParticipantID != request.Enrollment.Anchor.ParticipantID ||
		request.Presentation.Validate() != nil {
		return false
	}
	proposal := cloneParticipantEnrollment(request.Enrollment)
	proposal.Anchor.ApprovedAtMilliseconds = now
	if verifyBoxParticipantProof(proposal.Anchor, proposal.Device,
		proposal.RootRecord, proposal.GrantRecord, nil, request.Proof,
		request.RequestID, now) != nil {
		return false
	}
	var proof BoxParticipantProofPayload
	return strictParticipantJSON(request.Proof.Payload, &proof) == nil &&
		proof.PresentationDigest == participantPresentationDigest(request.Presentation)
}

func cloneParticipantRequest(request BoxParticipantEnrollmentRequest) BoxParticipantEnrollmentRequest {
	request.Enrollment = cloneParticipantEnrollment(request.Enrollment)
	request.Proof.Payload = bytes.Clone(request.Proof.Payload)
	return request
}

func sameParticipantRequestCore(left, right BoxParticipantEnrollmentRequest) bool {
	return left.RequestID == right.RequestID &&
		left.ConnectionGrantID == right.ConnectionGrantID &&
		left.RequestedAtMillis == right.RequestedAtMillis &&
		left.ExpiresAtMillis == right.ExpiresAtMillis &&
		reflect.DeepEqual(left.Enrollment, right.Enrollment) &&
		reflect.DeepEqual(left.Presentation, right.Presentation) &&
		reflect.DeepEqual(left.Proof, right.Proof)
}

func (store *MemoryStore) CreateParticipantEnrollmentRequest(
	_ context.Context, request BoxParticipantEnrollmentRequest, now int64,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.state == nil || !store.state.Claimed() ||
		store.state.BoxID != request.Enrollment.Anchor.BoxID {
		return ErrParticipantAuthority
	}
	grant, exists := store.grants[request.ConnectionGrantID]
	if !exists || !grant.RevokedAt.IsZero() || !grant.ExpiresAt.After(time.UnixMilli(now)) {
		return ErrParticipantAuthority
	}
	request.ConnectionDeviceName = grant.DeviceName
	if existing, exists := store.participantRequests[request.RequestID]; exists {
		if sameParticipantRequestCore(existing, request) {
			return nil
		}
		return ErrParticipantAuthority
	}
	boxPending, connectionPending := 0, 0
	for _, existing := range store.participantRequests {
		if existing.Enrollment.Anchor.BoxID != request.Enrollment.Anchor.BoxID ||
			existing.Decision != "pending" || existing.ExpiresAtMillis <= now {
			continue
		}
		boxPending++
		if existing.ConnectionGrantID == request.ConnectionGrantID {
			connectionPending++
		}
	}
	if boxPending >= maximumPendingParticipantRequests || connectionPending >= maximumPendingRequestsPerConnection {
		return ErrParticipantAuthority
	}
	if !request.validSubmissionAt(now) {
		return ErrParticipantAuthority
	}
	store.participantRequests[request.RequestID] = cloneParticipantRequest(request)
	return nil
}

func (store *MemoryStore) ParticipantEnrollmentRequest(
	_ context.Context, requestID, grantID uuid.UUID, now int64,
) (BoxParticipantEnrollmentRequest, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	request, exists := store.participantRequests[requestID]
	grant, active := store.grants[grantID]
	if !exists || request.ConnectionGrantID != grantID || !active ||
		!grant.RevokedAt.IsZero() || !grant.ExpiresAt.After(time.UnixMilli(now)) {
		return BoxParticipantEnrollmentRequest{}, ErrParticipantAuthority
	}
	result := cloneParticipantRequest(request)
	if result.Decision == "pending" && now >= result.ExpiresAtMillis {
		result.Decision = "expired"
	}
	return result, nil
}

func (store *MemoryStore) PendingParticipantEnrollmentRequests(
	_ context.Context, boxID uuid.UUID, now int64,
) ([]BoxParticipantEnrollmentRequest, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.state == nil || !store.state.Claimed() || store.state.BoxID != boxID {
		return nil, ErrParticipantAuthority
	}
	results := make([]BoxParticipantEnrollmentRequest, 0)
	for _, request := range store.participantRequests {
		grant, exists := store.grants[request.ConnectionGrantID]
		if request.Enrollment.Anchor.BoxID == boxID && request.Decision == "pending" &&
			now < request.ExpiresAtMillis && exists && grant.RevokedAt.IsZero() &&
			grant.ExpiresAt.After(time.UnixMilli(now)) {
			results = append(results, cloneParticipantRequest(request))
		}
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].RequestedAtMillis < results[j].RequestedAtMillis
	})
	return results, nil
}

func (store *MemoryStore) DecideParticipantEnrollmentRequest(
	_ context.Context, boxID, requestID uuid.UUID, approve bool, now int64,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	request, exists := store.participantRequests[requestID]
	if !exists || store.state == nil || !store.state.Claimed() || store.state.BoxID != boxID ||
		request.Enrollment.Anchor.BoxID != boxID || request.Decision != "pending" ||
		now <= 0 || now >= request.ExpiresAtMillis {
		return ErrParticipantAuthority
	}
	grant, exists := store.grants[request.ConnectionGrantID]
	if !exists || !grant.RevokedAt.IsZero() || !grant.ExpiresAt.After(time.UnixMilli(now)) {
		return ErrParticipantAuthority
	}
	if approve {
		request.Enrollment.Anchor.ApprovedAtMilliseconds = now
		if !request.Enrollment.validInitialAt(now) ||
			store.pinParticipantLocked(request.Enrollment) != nil {
			return ErrParticipantAuthority
		}
		request.Decision = "approved"
	} else {
		request.Decision = "rejected"
	}
	request.DecidedAtMilliseconds = now
	store.participantRequests[requestID] = request
	return nil
}
