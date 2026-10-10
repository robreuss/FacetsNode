package storagecapacity

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math"
	"strings"

	"github.com/google/uuid"
)

const AuthorityProtocolVersion = 1

var ErrInvalidAuthorityContract = errors.New("invalid storage capacity authority contract")

type ServiceKind string

const (
	ServiceJobCustody    ServiceKind = "job_custody"
	ServiceBackupCustody ServiceKind = "backup_custody"
	ServiceDeviceSync    ServiceKind = "device_sync"
	ServiceSharedSpaces  ServiceKind = "shared_spaces"
	ServiceComputePool   ServiceKind = "compute_pool"
)

func (value ServiceKind) valid() bool {
	switch value {
	case ServiceJobCustody, ServiceBackupCustody, ServiceDeviceSync, ServiceSharedSpaces, ServiceComputePool:
		return true
	default:
		return false
	}
}

// ServiceBinding is supplied by the authenticated private service transport.
// It intentionally contains no Space, account, object, participant, path, Job,
// or content identity.
type ServiceBinding struct {
	Kind       ServiceKind `json:"kind"`
	InstanceID uuid.UUID   `json:"instanceID"`
}

func (value ServiceBinding) Validate() error {
	if !value.Kind.valid() || value.InstanceID == uuid.Nil {
		return ErrInvalidAuthorityContract
	}
	return nil
}

type ReservationState string

const (
	ReservationReserved  ReservationState = "reserved"
	ReservationCommitted ReservationState = "committed"
	ReservationReleased  ReservationState = "released"
	ReservationExpired   ReservationState = "expired"
)

func (value ReservationState) valid() bool {
	switch value {
	case ReservationReserved, ReservationCommitted, ReservationReleased, ReservationExpired:
		return true
	default:
		return false
	}
}

// ReservationRequest is an idempotent, content-blind request for a worst-case
// additional physical footprint. ReservationID and OperationID are random
// protocol identities, not semantic resource identities.
type ReservationRequest struct {
	ProtocolVersion       int            `json:"protocolVersion"`
	PoolID                uuid.UUID      `json:"poolID"`
	ReservationID         uuid.UUID      `json:"reservationID"`
	OperationID           uuid.UUID      `json:"operationID"`
	Service               ServiceBinding `json:"service"`
	ByteCeiling           int64          `json:"byteCeiling"`
	IssuedAtMilliseconds  int64          `json:"issuedAtMilliseconds"`
	ExpiresAtMilliseconds int64          `json:"expiresAtMilliseconds"`
}

func (value ReservationRequest) Validate() error {
	if value.ProtocolVersion != AuthorityProtocolVersion || value.PoolID == uuid.Nil ||
		value.ReservationID == uuid.Nil || value.OperationID == uuid.Nil ||
		value.Service.Validate() != nil || value.ByteCeiling <= 0 ||
		value.IssuedAtMilliseconds <= 0 || value.ExpiresAtMilliseconds <= value.IssuedAtMilliseconds {
		return ErrInvalidAuthorityContract
	}
	return nil
}

// ReservationRecord is the durable authority fact. TokenDigest authenticates
// later private calls without persisting the bearer token itself.
type ReservationRecord struct {
	ProtocolVersion       int              `json:"protocolVersion"`
	PoolID                uuid.UUID        `json:"poolID"`
	ReservationID         uuid.UUID        `json:"reservationID"`
	Service               ServiceBinding   `json:"service"`
	ByteCeiling           int64            `json:"byteCeiling"`
	ExpiresAtMilliseconds int64            `json:"expiresAtMilliseconds"`
	State                 ReservationState `json:"state"`
	Revision              uint64           `json:"revision"`
	TokenDigest           string           `json:"tokenDigest"`
	UpdatedAtMilliseconds int64            `json:"updatedAtMilliseconds"`
}

func NewReservationRecord(
	request ReservationRequest,
	bearerToken string,
) (ReservationRecord, error) {
	if request.Validate() != nil || !validReservationToken(bearerToken) {
		return ReservationRecord{}, ErrInvalidAuthorityContract
	}
	return ReservationRecord{
		ProtocolVersion:       AuthorityProtocolVersion,
		PoolID:                request.PoolID,
		ReservationID:         request.ReservationID,
		Service:               request.Service,
		ByteCeiling:           request.ByteCeiling,
		ExpiresAtMilliseconds: request.ExpiresAtMilliseconds,
		State:                 ReservationReserved,
		Revision:              1,
		TokenDigest:           reservationTokenDigest(bearerToken),
		UpdatedAtMilliseconds: request.IssuedAtMilliseconds,
	}, nil
}

func (value ReservationRecord) Validate() error {
	if value.ProtocolVersion != AuthorityProtocolVersion || value.PoolID == uuid.Nil ||
		value.ReservationID == uuid.Nil || value.Service.Validate() != nil ||
		value.ByteCeiling <= 0 || value.ExpiresAtMilliseconds <= 0 ||
		!value.State.valid() || value.Revision == 0 || !validDigest(value.TokenDigest) ||
		value.UpdatedAtMilliseconds <= 0 {
		return ErrInvalidAuthorityContract
	}
	return nil
}

func (value ReservationRecord) ActiveBytes() int64 {
	if value.State == ReservationReserved {
		return value.ByteCeiling
	}
	return 0
}

type ReservationDecisionKind string

const (
	DecisionCommit  ReservationDecisionKind = "commit"
	DecisionRelease ReservationDecisionKind = "release"
	DecisionExpire  ReservationDecisionKind = "expire"
)

type ReservationDecision struct {
	ProtocolVersion        int                     `json:"protocolVersion"`
	ReservationID          uuid.UUID               `json:"reservationID"`
	OperationID            uuid.UUID               `json:"operationID"`
	ExpectedRevision       uint64                  `json:"expectedRevision"`
	Kind                   ReservationDecisionKind `json:"kind"`
	ObservedAtMilliseconds int64                   `json:"observedAtMilliseconds"`
	BearerToken            string                  `json:"bearerToken"`
}

func (decision ReservationDecision) Apply(
	current ReservationRecord,
) (ReservationRecord, error) {
	if current.Validate() != nil || decision.ProtocolVersion != AuthorityProtocolVersion ||
		decision.ReservationID != current.ReservationID || decision.OperationID == uuid.Nil ||
		decision.ExpectedRevision != current.Revision || decision.ObservedAtMilliseconds < current.UpdatedAtMilliseconds ||
		!validReservationToken(decision.BearerToken) || reservationTokenDigest(decision.BearerToken) != current.TokenDigest ||
		current.State != ReservationReserved || current.Revision == math.MaxUint64 {
		return ReservationRecord{}, ErrInvalidAuthorityContract
	}
	next := current
	switch decision.Kind {
	case DecisionCommit:
		if decision.ObservedAtMilliseconds >= current.ExpiresAtMilliseconds {
			return ReservationRecord{}, ErrInvalidAuthorityContract
		}
		next.State = ReservationCommitted
	case DecisionRelease:
		next.State = ReservationReleased
	case DecisionExpire:
		if decision.ObservedAtMilliseconds < current.ExpiresAtMilliseconds {
			return ReservationRecord{}, ErrInvalidAuthorityContract
		}
		next.State = ReservationExpired
	default:
		return ReservationRecord{}, ErrInvalidAuthorityContract
	}
	next.Revision++
	next.UpdatedAtMilliseconds = decision.ObservedAtMilliseconds
	return next, nil
}

type ReadinessState string

const (
	ReadinessReady               ReadinessState = "ready"
	ReadinessStoragePressure     ReadinessState = "storagePressure"
	ReadinessCapacityUnavailable ReadinessState = "capacityUnavailable"
	ReadinessDegraded            ReadinessState = "degraded"
)

func (value ReadinessState) valid() bool {
	switch value {
	case ReadinessReady, ReadinessStoragePressure, ReadinessCapacityUnavailable, ReadinessDegraded:
		return true
	default:
		return false
	}
}

// ReadinessSnapshot is the authority-internal/owner projection. Participant
// callers receive Coarse, which omits exact byte counts and pool identity.
type ReadinessSnapshot struct {
	ProtocolVersion        int            `json:"protocolVersion"`
	PoolID                 uuid.UUID      `json:"poolID"`
	Revision               uint64         `json:"revision"`
	State                  ReadinessState `json:"state"`
	ObservedAtMilliseconds int64          `json:"observedAtMilliseconds"`
	TotalBytes             int64          `json:"totalBytes"`
	AvailableBytes         int64          `json:"availableBytes"`
	ReservedBytes          int64          `json:"reservedBytes"`
	OperatingReserveBytes  int64          `json:"operatingReserveBytes"`
	AdmissibleBytes        int64          `json:"admissibleBytes"`
}

func (value ReadinessSnapshot) Validate() error {
	if value.ProtocolVersion != AuthorityProtocolVersion || value.PoolID == uuid.Nil ||
		value.Revision == 0 || !value.State.valid() || value.ObservedAtMilliseconds <= 0 ||
		value.TotalBytes < 0 || value.AvailableBytes < 0 || value.ReservedBytes < 0 ||
		value.OperatingReserveBytes < 0 || value.AdmissibleBytes < 0 ||
		value.AvailableBytes > value.TotalBytes || value.OperatingReserveBytes > value.TotalBytes ||
		value.AdmissibleBytes > value.AvailableBytes {
		return ErrInvalidAuthorityContract
	}
	if value.State == ReadinessCapacityUnavailable &&
		(value.TotalBytes != 0 || value.AvailableBytes != 0 || value.AdmissibleBytes != 0) {
		return ErrInvalidAuthorityContract
	}
	return nil
}

type CoarseReadinessSnapshot struct {
	ProtocolVersion        int            `json:"protocolVersion"`
	Revision               uint64         `json:"revision"`
	State                  ReadinessState `json:"state"`
	ObservedAtMilliseconds int64          `json:"observedAtMilliseconds"`
}

type ReadinessEventKind string

const (
	ReadinessEventPressure            ReadinessEventKind = "pressure"
	ReadinessEventCapacityUnavailable ReadinessEventKind = "capacityUnavailable"
	ReadinessEventRecovered           ReadinessEventKind = "recovered"
)

func (value ReadinessEventKind) valid() bool {
	switch value {
	case ReadinessEventPressure, ReadinessEventCapacityUnavailable, ReadinessEventRecovered:
		return true
	default:
		return false
	}
}

// ReadinessEvent is an owner-only, content-blind transition record. Its exact
// byte counts must not be exposed through participant readiness APIs.
type ReadinessEvent struct {
	ProtocolVersion int                `json:"protocolVersion"`
	Sequence        uint64             `json:"sequence"`
	EventID         uuid.UUID          `json:"eventID"`
	Kind            ReadinessEventKind `json:"kind"`
	Snapshot        ReadinessSnapshot  `json:"snapshot"`
}

func (value ReadinessEvent) Validate() error {
	if value.ProtocolVersion != AuthorityProtocolVersion || value.Sequence == 0 || value.EventID == uuid.Nil ||
		!value.Kind.valid() || value.Snapshot.Validate() != nil {
		return ErrInvalidAuthorityContract
	}
	switch value.Kind {
	case ReadinessEventPressure:
		if value.Snapshot.State != ReadinessStoragePressure && value.Snapshot.State != ReadinessDegraded {
			return ErrInvalidAuthorityContract
		}
	case ReadinessEventCapacityUnavailable:
		if value.Snapshot.State != ReadinessCapacityUnavailable {
			return ErrInvalidAuthorityContract
		}
	case ReadinessEventRecovered:
		if value.Snapshot.State != ReadinessReady {
			return ErrInvalidAuthorityContract
		}
	}
	return nil
}

func (value ReadinessSnapshot) Coarse() (CoarseReadinessSnapshot, error) {
	if value.Validate() != nil {
		return CoarseReadinessSnapshot{}, ErrInvalidAuthorityContract
	}
	return CoarseReadinessSnapshot{
		ProtocolVersion:        value.ProtocolVersion,
		Revision:               value.Revision,
		State:                  value.State,
		ObservedAtMilliseconds: value.ObservedAtMilliseconds,
	}, nil
}

func validReservationToken(value string) bool {
	if strings.Contains(value, "=") {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func NewReservationToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// ReservationTokenDigest validates and hashes a canonical bearer token for
// durable comparison. Callers persist only this digest, never the token.
func ReservationTokenDigest(value string) (string, error) {
	if !validReservationToken(value) {
		return "", ErrInvalidAuthorityContract
	}
	return reservationTokenDigest(value), nil
}

func reservationTokenDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}
