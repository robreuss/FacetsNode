package storagecapacity

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestReservationContractIsContentBlindAndTerminal(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	request := ReservationRequest{
		ProtocolVersion:       AuthorityProtocolVersion,
		PoolID:                uuid.New(),
		ReservationID:         uuid.New(),
		OperationID:           uuid.New(),
		Service:               ServiceBinding{Kind: ServiceJobCustody, InstanceID: uuid.New()},
		ByteCeiling:           4096,
		IssuedAtMilliseconds:  1_000,
		ExpiresAtMilliseconds: 2_000,
	}
	record, err := NewReservationRecord(request, token)
	if err != nil || record.ActiveBytes() != request.ByteCeiling || record.TokenDigest == token {
		t.Fatalf("reserved record=%+v err=%v", record, err)
	}
	wire, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"space", "path", "object", "prompt", "title", "participant", "account", token} {
		if strings.Contains(strings.ToLower(string(wire)), strings.ToLower(forbidden)) {
			t.Fatalf("reservation contract exposed %q: %s", forbidden, wire)
		}
	}

	committed, err := (ReservationDecision{
		ProtocolVersion:        AuthorityProtocolVersion,
		ReservationID:          request.ReservationID,
		OperationID:            uuid.New(),
		ExpectedRevision:       1,
		Kind:                   DecisionCommit,
		ObservedAtMilliseconds: 1_500,
		BearerToken:            token,
	}).Apply(record)
	if err != nil || committed.State != ReservationCommitted || committed.ActiveBytes() != 0 || committed.Revision != 2 {
		t.Fatalf("committed=%+v err=%v", committed, err)
	}
	if _, err := (ReservationDecision{
		ProtocolVersion:        AuthorityProtocolVersion,
		ReservationID:          request.ReservationID,
		OperationID:            uuid.New(),
		ExpectedRevision:       2,
		Kind:                   DecisionRelease,
		ObservedAtMilliseconds: 1_600,
		BearerToken:            token,
	}).Apply(committed); !errors.Is(err, ErrInvalidAuthorityContract) {
		t.Fatalf("terminal reservation changed: %v", err)
	}
}

func TestReservationDecisionRequiresExactTokenRevisionAndExpiryFence(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString([]byte("01234567890123456789012345678901"))
	request := ReservationRequest{
		ProtocolVersion:       AuthorityProtocolVersion,
		PoolID:                uuid.New(),
		ReservationID:         uuid.New(),
		OperationID:           uuid.New(),
		Service:               ServiceBinding{Kind: ServiceBackupCustody, InstanceID: uuid.New()},
		ByteCeiling:           1,
		IssuedAtMilliseconds:  10,
		ExpiresAtMilliseconds: 20,
	}
	record, err := NewReservationRecord(request, token)
	if err != nil {
		t.Fatal(err)
	}
	base := ReservationDecision{
		ProtocolVersion:        AuthorityProtocolVersion,
		ReservationID:          request.ReservationID,
		OperationID:            uuid.New(),
		ExpectedRevision:       1,
		Kind:                   DecisionExpire,
		ObservedAtMilliseconds: 20,
		BearerToken:            token,
	}
	for name, mutate := range map[string]func(*ReservationDecision){
		"wrong token": func(value *ReservationDecision) {
			value.BearerToken = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
		},
		"wrong revision":    func(value *ReservationDecision) { value.ExpectedRevision = 2 },
		"early expiry":      func(value *ReservationDecision) { value.ObservedAtMilliseconds = 19 },
		"wrong reservation": func(value *ReservationDecision) { value.ReservationID = uuid.New() },
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			if _, err := changed.Apply(record); !errors.Is(err, ErrInvalidAuthorityContract) {
				t.Fatalf("invalid decision accepted: %v", err)
			}
		})
	}
	expired, err := base.Apply(record)
	if err != nil || expired.State != ReservationExpired || expired.ActiveBytes() != 0 {
		t.Fatalf("expired=%+v err=%v", expired, err)
	}
}

func TestReadinessSeparatesOwnerBytesFromCoarseProjection(t *testing.T) {
	snapshot := ReadinessSnapshot{
		ProtocolVersion:        AuthorityProtocolVersion,
		PoolID:                 uuid.New(),
		Revision:               7,
		State:                  ReadinessStoragePressure,
		ObservedAtMilliseconds: 1_000,
		TotalBytes:             100,
		AvailableBytes:         30,
		ReservedBytes:          20,
		OperatingReserveBytes:  10,
		AdmissibleBytes:        0,
	}
	coarse, err := snapshot.Coarse()
	if err != nil || coarse.Revision != snapshot.Revision || coarse.State != snapshot.State ||
		coarse.RetryAfterMilliseconds != DefaultReadinessRetryAfterMilliseconds || coarse.Validate() != nil {
		t.Fatalf("coarse=%+v err=%v", coarse, err)
	}
	wire, err := json.Marshal(coarse)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"poolID", "totalBytes", "availableBytes", "reservedBytes", "admissibleBytes"} {
		if strings.Contains(string(wire), forbidden) {
			t.Fatalf("coarse readiness exposed %s: %s", forbidden, wire)
		}
	}

	unavailable := snapshot
	unavailable.State = ReadinessCapacityUnavailable
	if unavailable.Validate() == nil {
		t.Fatal("unavailable readiness exposed stale byte counts")
	}
	unavailable.TotalBytes = 0
	unavailable.AvailableBytes = 0
	unavailable.OperatingReserveBytes = 0
	if unavailable.Validate() != nil {
		t.Fatal("redacted unavailable readiness rejected")
	}
	ready := snapshot
	ready.State = ReadinessReady
	ready.AdmissibleBytes = 1
	coarse, err = ready.Coarse()
	if err != nil || coarse.RetryAfterMilliseconds != 0 || coarse.Validate() != nil {
		t.Fatalf("ready coarse=%+v err=%v", coarse, err)
	}
}

func TestReadinessEventsBindOnlyValidStateTransitions(t *testing.T) {
	snapshot := ReadinessSnapshot{
		ProtocolVersion:        AuthorityProtocolVersion,
		PoolID:                 uuid.New(),
		Revision:               1,
		State:                  ReadinessStoragePressure,
		ObservedAtMilliseconds: 1_000,
		TotalBytes:             100,
		AvailableBytes:         10,
		ReservedBytes:          0,
		OperatingReserveBytes:  10,
		AdmissibleBytes:        0,
	}
	event := ReadinessEvent{
		ProtocolVersion: AuthorityProtocolVersion,
		Sequence:        1,
		EventID:         uuid.New(),
		Kind:            ReadinessEventPressure,
		Snapshot:        snapshot,
	}
	if err := event.Validate(); err != nil {
		t.Fatal(err)
	}
	event.Kind = ReadinessEventRecovered
	if event.Validate() == nil {
		t.Fatal("recovery event accepted a pressure snapshot")
	}
	event.Kind = ReadinessEventCapacityUnavailable
	event.Snapshot.State = ReadinessCapacityUnavailable
	event.Snapshot.TotalBytes = 0
	event.Snapshot.AvailableBytes = 0
	event.Snapshot.OperatingReserveBytes = 0
	if err := event.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestAuthorityContractsRejectUnknownServiceMalformedTokenAndInvalidTime(t *testing.T) {
	request := ReservationRequest{
		ProtocolVersion:       AuthorityProtocolVersion,
		PoolID:                uuid.New(),
		ReservationID:         uuid.New(),
		OperationID:           uuid.New(),
		Service:               ServiceBinding{Kind: "other", InstanceID: uuid.New()},
		ByteCeiling:           1,
		IssuedAtMilliseconds:  10,
		ExpiresAtMilliseconds: 10,
	}
	if request.Validate() == nil {
		t.Fatal("invalid authority request accepted")
	}
	request.Service.Kind = ServiceDeviceSync
	request.ExpiresAtMilliseconds = 11
	if _, err := NewReservationRecord(request, "not-a-token"); !errors.Is(err, ErrInvalidAuthorityContract) {
		t.Fatalf("malformed bearer accepted: %v", err)
	}
}

func TestReservationTokensAreCanonicalAndFresh(t *testing.T) {
	first, err := NewReservationToken()
	if err != nil || !validReservationToken(first) {
		t.Fatalf("first token: %q %v", first, err)
	}
	second, err := NewReservationToken()
	if err != nil || !validReservationToken(second) || second == first {
		t.Fatalf("second token: %q %v", second, err)
	}
	digest, err := ReservationTokenDigest(first)
	if err != nil || digest != reservationTokenDigest(first) || digest == first {
		t.Fatalf("digest: %q %v", digest, err)
	}
	if _, err := ReservationTokenDigest("not-a-token"); !errors.Is(err, ErrInvalidAuthorityContract) {
		t.Fatalf("malformed token digest accepted: %v", err)
	}
}
