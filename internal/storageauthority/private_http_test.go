package storageauthority

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/serviceauthority"
	"github.com/robreuss/FacetsNode/internal/storagecapacity"
)

type privateHTTPFixture struct {
	handler  *PrivateHTTPHandler
	service  *recordingCapacityService
	signer   *serviceauthority.DeploymentSigner
	binding  storagecapacity.ServiceBinding
	identity serviceauthority.CapacityPeerIdentity
	poolID   uuid.UUID
	now      time.Time
}

type recordingCapacityService struct {
	binding         storagecapacity.ServiceBinding
	reserve         storagecapacity.ReservationRequest
	reserveToken    string
	recheckID       uuid.UUID
	recheckRevision uint64
	recheckToken    string
	recheckAt       int64
	decision        storagecapacity.ReservationDecision
	reservationID   uuid.UUID
	readiness       storagecapacity.CoarseReadinessSnapshot
	state           storagecapacity.ReservationState
	revision        uint64
	decisionErrOnce bool
	err             error
}

func (service *recordingCapacityService) Reserve(_ context.Context, request storagecapacity.ReservationRequest, token string) (storagecapacity.ReservationRecord, error) {
	service.reserve, service.reserveToken = request, token
	if service.err != nil {
		return storagecapacity.ReservationRecord{}, service.err
	}
	service.state, service.revision = storagecapacity.ReservationReserved, 1
	return testPrivateRecord(request.ReservationID, request.ByteCeiling, request.ExpiresAtMilliseconds, request.IssuedAtMilliseconds), nil
}

func (service *recordingCapacityService) Recheck(_ context.Context, id uuid.UUID, revision uint64, token string, observed int64) error {
	service.recheckID, service.recheckRevision, service.recheckToken, service.recheckAt = id, revision, token, observed
	return service.err
}

func (service *recordingCapacityService) Decide(_ context.Context, decision storagecapacity.ReservationDecision) (storagecapacity.ReservationRecord, error) {
	service.decision = decision
	if service.err != nil {
		return storagecapacity.ReservationRecord{}, service.err
	}
	bytes, expires := int64(4096), int64(20_000)
	if service.reserve.ReservationID == decision.ReservationID {
		bytes, expires = service.reserve.ByteCeiling, service.reserve.ExpiresAtMilliseconds
	}
	record := testPrivateRecord(decision.ReservationID, bytes, expires, decision.ObservedAtMilliseconds)
	record.Revision = decision.ExpectedRevision + 1
	if decision.Kind == storagecapacity.DecisionCommit {
		record.State = storagecapacity.ReservationCommitted
	} else {
		record.State = storagecapacity.ReservationReleased
	}
	service.state, service.revision = record.State, record.Revision
	if service.decisionErrOnce {
		service.decisionErrOnce = false
		return storagecapacity.ReservationRecord{}, ErrUnavailable
	}
	return record, nil
}

func (service *recordingCapacityService) Reservation(_ context.Context, id uuid.UUID) (storagecapacity.ReservationRecord, error) {
	service.reservationID = id
	if service.err != nil {
		return storagecapacity.ReservationRecord{}, service.err
	}
	bytes, expires := int64(4096), int64(20_000)
	if service.reserve.ReservationID == id {
		bytes, expires = service.reserve.ByteCeiling, service.reserve.ExpiresAtMilliseconds
	}
	record := testPrivateRecord(id, bytes, expires, 11_000)
	if service.state != "" {
		record.State = service.state
	}
	if service.revision != 0 {
		record.Revision = service.revision
	}
	return record, nil
}

func (service *recordingCapacityService) CoarseReadiness(context.Context) (storagecapacity.CoarseReadinessSnapshot, error) {
	if service.err != nil {
		return storagecapacity.CoarseReadinessSnapshot{}, service.err
	}
	return service.readiness, nil
}

func testPrivateRecord(id uuid.UUID, bytes, expires, updated int64) storagecapacity.ReservationRecord {
	return storagecapacity.ReservationRecord{
		ProtocolVersion: storagecapacity.AuthorityProtocolVersion,
		PoolID:          uuid.New(), ReservationID: id,
		Service:     storagecapacity.ServiceBinding{Kind: storagecapacity.ServiceJobCustody, InstanceID: uuid.New()},
		ByteCeiling: bytes, ExpiresAtMilliseconds: expires,
		State: storagecapacity.ReservationReserved, Revision: 1,
		TokenDigest: strings.Repeat("a", 64), UpdatedAtMilliseconds: updated,
	}
}

func newPrivateHTTPFixture(t *testing.T) privateHTTPFixture {
	t.Helper()
	deploymentID := uuid.New()
	seed := make([]byte, 32)
	seed[31] = 11
	signer, err := serviceauthority.NewDeploymentSigner(deploymentID, seed)
	if err != nil {
		t.Fatal(err)
	}
	binding := storagecapacity.ServiceBinding{Kind: storagecapacity.ServiceJobCustody, InstanceID: deploymentID}
	identity := serviceauthority.CapacityPeerIdentity{
		Service: binding, PublicSigningKeyX963: signer.PublicSigningKeyX963(),
		SigningKeyFingerprint: signer.SigningKeyFingerprint(), Version: serviceauthority.SchemaVersion,
	}
	peers, err := NewCapacityPeerRegistry([]serviceauthority.CapacityPeerIdentity{identity})
	if err != nil {
		t.Fatal(err)
	}
	service := &recordingCapacityService{binding: binding, readiness: storagecapacity.CoarseReadinessSnapshot{
		ProtocolVersion: storagecapacity.AuthorityProtocolVersion, Revision: 3,
		State: storagecapacity.ReadinessReady, ObservedAtMilliseconds: 9_000,
	}}
	now := time.UnixMilli(10_000)
	handler := &PrivateHTTPHandler{
		peers: peers, now: func() time.Time { return now }, poolID: uuid.New(),
		service: func(received storagecapacity.ServiceBinding) (capacityService, error) {
			if received != binding {
				return nil, ErrRejected
			}
			return service, nil
		},
	}
	return privateHTTPFixture{handler: handler, service: service, signer: signer, binding: binding, identity: identity, poolID: handler.poolID, now: now}
}

func (fixture privateHTTPFixture) envelope(t *testing.T, operation serviceauthority.CapacityPeerOperation, operationID uuid.UUID, body any) []byte {
	t.Helper()
	envelope, err := NewPrivateCapacityEnvelopeAt(fixture.signer, fixture.binding, fixture.poolID, operation, operationID, body, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func (fixture privateHTTPFixture) post(t *testing.T, path string, envelope []byte) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(envelope))
	response := httptest.NewRecorder()
	fixture.handler.Handler().ServeHTTP(response, request)
	return response
}

func TestPrivateCapacityHTTPAuthenticatesAndBindsExactReserve(t *testing.T) {
	fixture := newPrivateHTTPFixture(t)
	body := PrivateReserveRequest{
		ProtocolVersion: 1, ReservationID: uuid.New(), OperationID: uuid.New(),
		ByteCeiling: 8192, IssuedAtMilliseconds: 10_000,
		ExpiresAtMilliseconds: 20_000, BearerToken: testReservationToken(t),
	}
	response := fixture.post(t, "/v1/reservations/reserve", fixture.envelope(t, serviceauthority.CapacityReserve, body.OperationID, body))
	if response.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", response.Code, response.Body.String())
	}
	if fixture.service.reserve.Service != fixture.binding || fixture.service.reserve.PoolID != fixture.poolID ||
		fixture.service.reserve.ReservationID != body.ReservationID || fixture.service.reserve.OperationID != body.OperationID ||
		fixture.service.reserveToken != body.BearerToken {
		t.Fatalf("wrong bound reserve: %+v", fixture.service.reserve)
	}
	if strings.Contains(response.Body.String(), body.BearerToken) || strings.Contains(response.Body.String(), strings.Repeat("a", 64)) ||
		strings.Contains(response.Body.String(), fixture.poolID.String()) || strings.Contains(response.Body.String(), fixture.binding.InstanceID.String()) {
		t.Fatal("private response exposed token, digest, pool, or service identity")
	}
}

func TestPrivateCapacityHTTPRoutesRecheckDecisionReadAndCoarseReadiness(t *testing.T) {
	fixture := newPrivateHTTPFixture(t)
	token := testReservationToken(t)
	recheck := PrivateRecheckRequest{ProtocolVersion: 1, ReservationID: uuid.New(), OperationID: uuid.New(), ExpectedRevision: 2, ObservedAtMilliseconds: 11_000, BearerToken: token}
	response := fixture.post(t, "/v1/reservations/recheck", fixture.envelope(t, serviceauthority.CapacityRecheck, recheck.OperationID, recheck))
	if response.Code != http.StatusNoContent || fixture.service.recheckID != recheck.ReservationID || fixture.service.recheckRevision != recheck.ExpectedRevision || fixture.service.recheckToken != token || fixture.service.recheckAt != recheck.ObservedAtMilliseconds {
		t.Fatalf("recheck status=%d", response.Code)
	}
	decision := PrivateDecisionRequest{ProtocolVersion: 1, ReservationID: recheck.ReservationID, OperationID: uuid.New(), ExpectedRevision: 2, Kind: storagecapacity.DecisionRelease, ObservedAtMilliseconds: 12_000, BearerToken: token}
	response = fixture.post(t, "/v1/reservations/decide", fixture.envelope(t, serviceauthority.CapacityDecide, decision.OperationID, decision))
	if response.Code != http.StatusOK || fixture.service.decision.OperationID != decision.OperationID || fixture.service.decision.Kind != decision.Kind {
		t.Fatalf("decision status=%d", response.Code)
	}
	read := PrivateReservationRequest{ProtocolVersion: 1, ReservationID: recheck.ReservationID, OperationID: uuid.New()}
	response = fixture.post(t, "/v1/reservations/get", fixture.envelope(t, serviceauthority.CapacityRead, read.OperationID, read))
	if response.Code != http.StatusOK || fixture.service.reservationID != read.ReservationID {
		t.Fatalf("read status=%d", response.Code)
	}
	readiness := PrivateReadinessRequest{ProtocolVersion: 1, OperationID: uuid.New()}
	response = fixture.post(t, "/v1/readiness/query", fixture.envelope(t, serviceauthority.CapacityReadiness, readiness.OperationID, readiness))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"state":"ready"`) || strings.Contains(response.Body.String(), "availableBytes") {
		t.Fatalf("coarse readiness status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestPrivateCapacityHTTPRejectsTamperingWrongOperationAndExpiredProof(t *testing.T) {
	fixture := newPrivateHTTPFixture(t)
	body := PrivateReserveRequest{ProtocolVersion: 1, ReservationID: uuid.New(), OperationID: uuid.New(), ByteCeiling: 8192, IssuedAtMilliseconds: 10_000, ExpiresAtMilliseconds: 20_000, BearerToken: testReservationToken(t)}
	valid := fixture.envelope(t, serviceauthority.CapacityReserve, body.OperationID, body)
	var envelope PrivateCapacityEnvelope
	if err := json.Unmarshal(valid, &envelope); err != nil {
		t.Fatal(err)
	}
	var changed PrivateReserveRequest
	if err := json.Unmarshal(envelope.Body, &changed); err != nil {
		t.Fatal(err)
	}
	changed.ByteCeiling++
	envelope.Body, _ = json.Marshal(changed)
	tampered, _ := json.Marshal(envelope)
	if response := fixture.post(t, "/v1/reservations/reserve", tampered); response.Code != http.StatusForbidden {
		t.Fatalf("tamper status=%d", response.Code)
	}
	if response := fixture.post(t, "/v1/reservations/decide", valid); response.Code != http.StatusBadRequest && response.Code != http.StatusForbidden {
		t.Fatalf("wrong operation status=%d", response.Code)
	}
	fixture.handler.now = func() time.Time { return fixture.now.Add(serviceauthority.CapacityPeerProofLifetime) }
	if response := fixture.post(t, "/v1/reservations/reserve", valid); response.Code != http.StatusForbidden {
		t.Fatalf("expired status=%d", response.Code)
	}
}

func TestPrivateCapacityHTTPMapsOnlyCoarse507AndAuthorityErrors(t *testing.T) {
	for _, test := range []struct {
		err  error
		code string
		want int
	}{
		{storagecapacity.ErrPressure, "storage_pressure", http.StatusInsufficientStorage},
		{storagecapacity.ErrUnavailable, "capacity_unavailable", http.StatusInsufficientStorage},
		{ErrConflict, "reservation_conflict", http.StatusConflict},
		{ErrRejected, "reservation_rejected", http.StatusConflict},
		{ErrInvalid, "invalid_request", http.StatusBadRequest},
		{errors.New("database failed"), "authority_unavailable", http.StatusServiceUnavailable},
	} {
		t.Run(test.code, func(t *testing.T) {
			fixture := newPrivateHTTPFixture(t)
			fixture.service.err = test.err
			body := PrivateReserveRequest{ProtocolVersion: 1, ReservationID: uuid.New(), OperationID: uuid.New(), ByteCeiling: 8192, IssuedAtMilliseconds: 10_000, ExpiresAtMilliseconds: 20_000, BearerToken: testReservationToken(t)}
			response := fixture.post(t, "/v1/reservations/reserve", fixture.envelope(t, serviceauthority.CapacityReserve, body.OperationID, body))
			if response.Code != test.want || !strings.Contains(response.Body.String(), `"code":"`+test.code+`"`) {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if test.want == http.StatusInsufficientStorage && (!strings.Contains(response.Body.String(), "retryAfterMilliseconds") || strings.Contains(response.Body.String(), "availableBytes")) {
				t.Fatalf("unstructured or detailed 507: %s", response.Body.String())
			}
		})
	}
}

func TestCapacityPeerRegistryRejectsDuplicateServiceOrReusedKey(t *testing.T) {
	fixture := newPrivateHTTPFixture(t)
	if _, err := NewCapacityPeerRegistry(nil); err == nil {
		t.Fatal("empty registry accepted")
	}
	if _, err := NewCapacityPeerRegistry([]serviceauthority.CapacityPeerIdentity{fixture.identity, fixture.identity}); err == nil {
		t.Fatal("duplicate service accepted")
	}
	reused := fixture.identity
	reused.Service = storagecapacity.ServiceBinding{Kind: storagecapacity.ServiceBackupCustody, InstanceID: uuid.New()}
	if _, err := NewCapacityPeerRegistry([]serviceauthority.CapacityPeerIdentity{fixture.identity, reused}); err == nil {
		t.Fatal("one deployment key authorized as two services")
	}
}

func TestCapacityPeerRegistryFileRequiresCanonicalOwnerControlledRegularFile(t *testing.T) {
	fixture := newPrivateHTTPFixture(t)
	directory := t.TempDir()
	path := filepath.Join(directory, "capacity-peers.json")
	value := CapacityPeerRegistryFile{Identities: []serviceauthority.CapacityPeerIdentity{fixture.identity}, Version: serviceauthority.SchemaVersion}
	canonical, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(canonical, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	registry, err := LoadCapacityPeerRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	body := PrivateReadinessRequest{ProtocolVersion: 1, OperationID: uuid.New()}
	envelope := fixture.envelope(t, serviceauthority.CapacityReadiness, body.OperationID, body)
	var decoded PrivateCapacityEnvelope
	if err := json.Unmarshal(envelope, &decoded); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(body)
	expected, _ := serviceauthority.NewCapacityPeerRequest(serviceauthority.CapacityReadiness, body.OperationID, fixture.poolID, raw)
	if _, err := registry.VerifyAt(decoded.Proof, expected, raw, fixture.now); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(path, 0o622); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCapacityPeerRegistry(path); err == nil {
		t.Fatal("group-writable peer registry accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append([]byte{' '}, append(canonical, '\n')...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCapacityPeerRegistry(path); err == nil {
		t.Fatal("noncanonical peer registry accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(directory, "missing"), path); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCapacityPeerRegistry(path); err == nil {
		t.Fatal("peer registry symlink accepted")
	}
}

func testReservationToken(t *testing.T) string {
	t.Helper()
	token, err := storagecapacity.NewReservationToken()
	if err != nil {
		t.Fatal(err)
	}
	return token
}
