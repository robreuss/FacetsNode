package storageauthority

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/storagecapacity"
)

func TestPrivateCapacityClientRoundTripsAuthenticatedTLSRequests(t *testing.T) {
	fixture := newPrivateHTTPFixture(t)
	server := httptest.NewTLSServer(fixture.handler.Handler())
	defer server.Close()
	client, err := NewPrivateHTTPClient(server.URL, server.Client(), fixture.signer, fixture.binding, fixture.poolID)
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return fixture.now }
	token := testReservationToken(t)
	reserve := PrivateReserveRequest{ProtocolVersion: 1, ReservationID: uuid.New(), OperationID: uuid.New(), ByteCeiling: 8192, IssuedAtMilliseconds: 10_000, ExpiresAtMilliseconds: 20_000, BearerToken: token}
	reserved, err := client.Reserve(context.Background(), reserve)
	if err != nil || reserved.ReservationID != reserve.ReservationID || fixture.service.reserve.Service != fixture.binding {
		t.Fatalf("reserve: %+v %v", reserved, err)
	}
	recheck := PrivateRecheckRequest{ProtocolVersion: 1, ReservationID: reserve.ReservationID, OperationID: uuid.New(), ExpectedRevision: 1, ObservedAtMilliseconds: 11_000, BearerToken: token}
	if err := client.Recheck(context.Background(), recheck); err != nil {
		t.Fatal(err)
	}
	decision := PrivateDecisionRequest{ProtocolVersion: 1, ReservationID: reserve.ReservationID, OperationID: uuid.New(), ExpectedRevision: 1, Kind: storagecapacity.DecisionRelease, ObservedAtMilliseconds: 12_000, BearerToken: token}
	if _, err := client.Decide(context.Background(), decision); err != nil {
		t.Fatal(err)
	}
	read := PrivateReservationRequest{ProtocolVersion: 1, ReservationID: reserve.ReservationID, OperationID: uuid.New()}
	if _, err := client.Reservation(context.Background(), read); err != nil {
		t.Fatal(err)
	}
	readiness, err := client.Readiness(context.Background(), PrivateReadinessRequest{ProtocolVersion: 1, OperationID: uuid.New()})
	if err != nil || readiness.State != storagecapacity.ReadinessReady || readiness.Revision != 3 {
		t.Fatalf("readiness: %+v %v", readiness, err)
	}
}

func TestPrivateCapacityClientPreservesStructured507AndRetryGuidance(t *testing.T) {
	fixture := newPrivateHTTPFixture(t)
	fixture.service.err = storagecapacity.ErrPressure
	server := httptest.NewTLSServer(fixture.handler.Handler())
	defer server.Close()
	client, err := NewPrivateHTTPClient(server.URL, server.Client(), fixture.signer, fixture.binding, fixture.poolID)
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return fixture.now }
	request := PrivateReserveRequest{ProtocolVersion: 1, ReservationID: uuid.New(), OperationID: uuid.New(), ByteCeiling: 8192, IssuedAtMilliseconds: 10_000, ExpiresAtMilliseconds: 20_000, BearerToken: testReservationToken(t)}
	_, err = client.Reserve(context.Background(), request)
	if !errors.Is(err, storagecapacity.ErrPressure) {
		t.Fatalf("wrong error: %v", err)
	}
	var remote *PrivateRemoteError
	if !errors.As(err, &remote) || remote.StatusCode != http.StatusInsufficientStorage ||
		remote.Response.RetryAfterMilliseconds == nil || *remote.Response.RetryAfterMilliseconds != storagecapacity.DefaultReadinessRetryAfterMilliseconds ||
		remote.Response.State == nil || *remote.Response.State != storagecapacity.ReadinessStoragePressure {
		t.Fatalf("missing structured retry: %+v", remote)
	}
}

func TestPrivateCapacityClientRequiresTLSAndMatchingDeploymentIdentity(t *testing.T) {
	fixture := newPrivateHTTPFixture(t)
	if _, err := NewPrivateHTTPClient("http://capacity.local", &http.Client{}, fixture.signer, fixture.binding, fixture.poolID); err == nil {
		t.Fatal("plaintext transport accepted")
	}
	wrong := fixture.binding
	wrong.InstanceID = uuid.New()
	if _, err := NewPrivateHTTPClient("https://capacity.local", &http.Client{}, fixture.signer, wrong, fixture.poolID); err == nil {
		t.Fatal("signer authorized a different service instance")
	}
}

func TestPrivateCapacityLeaseOwnsReserveRecheckAndTerminalLifecycle(t *testing.T) {
	fixture := newPrivateHTTPFixture(t)
	now := fixture.now
	fixture.handler.now = func() time.Time { return now }
	server := httptest.NewTLSServer(fixture.handler.Handler())
	defer server.Close()
	client, err := NewPrivateHTTPClient(server.URL, server.Client(), fixture.signer, fixture.binding, fixture.poolID)
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return now }
	lease, err := client.Acquire(context.Background(), 12_345, 10*time.Second)
	if err != nil || fixture.service.reserve.ByteCeiling != 12_345 || fixture.service.reserve.Service != fixture.binding {
		t.Fatalf("acquire lease=%+v reserve=%+v err=%v", lease, fixture.service.reserve, err)
	}
	now = now.Add(time.Second)
	if err := lease.Recheck(context.Background()); err != nil || fixture.service.recheckID != fixture.service.reserve.ReservationID {
		t.Fatalf("recheck id=%s err=%v", fixture.service.recheckID, err)
	}
	now = now.Add(time.Second)
	if err := lease.Commit(context.Background()); err != nil || fixture.service.state != storagecapacity.ReservationCommitted {
		t.Fatalf("commit state=%s err=%v", fixture.service.state, err)
	}
	if err := lease.Release(context.Background()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("terminal lease reused: %v", err)
	}

	now = fixture.now
	releaseLease, err := client.Acquire(context.Background(), 4_096, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	if err := releaseLease.Release(context.Background()); err != nil || fixture.service.state != storagecapacity.ReservationReleased {
		t.Fatalf("release state=%s err=%v", fixture.service.state, err)
	}
}

func TestPrivateCapacityLeaseRejectsInvalidBoundsBeforeRemoteAdmission(t *testing.T) {
	fixture := newPrivateHTTPFixture(t)
	server := httptest.NewTLSServer(fixture.handler.Handler())
	defer server.Close()
	client, err := NewPrivateHTTPClient(server.URL, server.Client(), fixture.signer, fixture.binding, fixture.poolID)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		bytes    int64
		lifetime time.Duration
	}{
		{0, time.Minute}, {1, 0}, {1, MaximumPrivateReservationLifetime + time.Second},
	} {
		if _, err := client.Acquire(context.Background(), item.bytes, item.lifetime); !errors.Is(err, ErrInvalid) {
			t.Fatalf("Acquire(%d,%s) err=%v", item.bytes, item.lifetime, err)
		}
	}
	if fixture.service.reserve.ReservationID != uuid.Nil {
		t.Fatal("invalid lease reached authority")
	}
}

func TestPrivateCapacityLeaseReconcilesLostTerminalResponse(t *testing.T) {
	fixture := newPrivateHTTPFixture(t)
	now := fixture.now
	fixture.handler.now = func() time.Time { return now }
	server := httptest.NewTLSServer(fixture.handler.Handler())
	defer server.Close()
	client, err := NewPrivateHTTPClient(server.URL, server.Client(), fixture.signer, fixture.binding, fixture.poolID)
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return now }
	lease, err := client.Acquire(context.Background(), 8_192, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	fixture.service.decisionErrOnce = true
	now = now.Add(time.Second)
	if err := lease.Commit(context.Background()); err != nil {
		t.Fatalf("lost commit response was not reconciled: %v", err)
	}
	if fixture.service.reservationID != fixture.service.reserve.ReservationID ||
		fixture.service.state != storagecapacity.ReservationCommitted {
		t.Fatalf("reconciliation state=%s read=%s reserve=%s", fixture.service.state, fixture.service.reservationID, fixture.service.reserve.ReservationID)
	}
}
