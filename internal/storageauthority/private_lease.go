package storageauthority

import (
	"context"
	"errors"
	"math"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/storagecapacity"
)

const (
	MinimumPrivateReservationLifetime = time.Second
	MaximumPrivateReservationLifetime = 24 * time.Hour
)

// PrivateReservationLease is the service-side lifecycle for one content-blind
// physical-capacity reservation. It deliberately carries no semantic resource
// identity. A caller persists its own work state; unresolved reservations are
// fail-safe and remain charged until the authority expires them.
type PrivateReservationLease struct {
	mu     sync.Mutex
	client *PrivateHTTPClient
	view   PrivateReservationView
	token  string
	closed bool
}

// Acquire reserves a worst-case additional physical footprint before a
// service promises or writes durable bytes. The authority remains the sole
// source of reservation state.
func (client *PrivateHTTPClient) Acquire(
	ctx context.Context,
	byteCeiling int64,
	lifetime time.Duration,
) (*PrivateReservationLease, error) {
	if client == nil || client.now == nil || client.newID == nil || client.newToken == nil ||
		ctx == nil || byteCeiling <= 0 || lifetime < MinimumPrivateReservationLifetime ||
		lifetime > MaximumPrivateReservationLifetime {
		return nil, ErrInvalid
	}
	now := client.now()
	issued := now.UnixMilli()
	if issued <= 0 || lifetime.Milliseconds() <= 0 || issued > math.MaxInt64-lifetime.Milliseconds() {
		return nil, ErrInvalid
	}
	reservationID, operationID := client.newID(), client.newID()
	token, err := client.newToken()
	if err != nil || reservationID == uuid.Nil || operationID == uuid.Nil {
		return nil, ErrUnavailable
	}
	request := PrivateReserveRequest{
		ProtocolVersion: storagecapacity.AuthorityProtocolVersion,
		ReservationID:   reservationID, OperationID: operationID,
		ByteCeiling: byteCeiling, IssuedAtMilliseconds: issued,
		ExpiresAtMilliseconds: issued + lifetime.Milliseconds(), BearerToken: token,
	}
	view, err := client.Reserve(ctx, request)
	if err != nil {
		return nil, err
	}
	if !validPrivateReservationView(view) || view.ReservationID != reservationID ||
		view.ByteCeiling != byteCeiling || view.ExpiresAtMilliseconds != request.ExpiresAtMilliseconds ||
		view.State != storagecapacity.ReservationReserved {
		return nil, ErrInvalid
	}
	return &PrivateReservationLease{client: client, view: view, token: token}, nil
}

func (lease *PrivateReservationLease) Recheck(ctx context.Context) error {
	if lease == nil {
		return ErrInvalid
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.invalidLocked(ctx) {
		return ErrInvalid
	}
	observed := lease.client.now().UnixMilli()
	if observed < lease.view.UpdatedAtMilliseconds || observed >= lease.view.ExpiresAtMilliseconds {
		return ErrUnavailable
	}
	return lease.client.Recheck(ctx, PrivateRecheckRequest{
		ProtocolVersion: storagecapacity.AuthorityProtocolVersion,
		ReservationID:   lease.view.ReservationID, OperationID: lease.client.newID(),
		ExpectedRevision: lease.view.Revision, ObservedAtMilliseconds: observed,
		BearerToken: lease.token,
	})
}

func (lease *PrivateReservationLease) Commit(ctx context.Context) error {
	return lease.decide(ctx, storagecapacity.DecisionCommit)
}

func (lease *PrivateReservationLease) Release(ctx context.Context) error {
	return lease.decide(ctx, storagecapacity.DecisionRelease)
}

func (lease *PrivateReservationLease) decide(
	ctx context.Context,
	kind storagecapacity.ReservationDecisionKind,
) error {
	if lease == nil {
		return ErrInvalid
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.invalidLocked(ctx) {
		return ErrInvalid
	}
	observed := lease.client.now().UnixMilli()
	if observed < lease.view.UpdatedAtMilliseconds ||
		(kind == storagecapacity.DecisionCommit && observed >= lease.view.ExpiresAtMilliseconds) {
		return ErrUnavailable
	}
	operationID := lease.client.newID()
	if operationID == uuid.Nil {
		return ErrUnavailable
	}
	request := PrivateDecisionRequest{
		ProtocolVersion: storagecapacity.AuthorityProtocolVersion,
		ReservationID:   lease.view.ReservationID, OperationID: operationID,
		ExpectedRevision: lease.view.Revision, Kind: kind,
		ObservedAtMilliseconds: observed, BearerToken: lease.token,
	}
	view, err := lease.client.Decide(ctx, request)
	if err != nil && errors.Is(err, ErrUnavailable) {
		view, err = lease.client.Reservation(ctx, PrivateReservationRequest{
			ProtocolVersion: storagecapacity.AuthorityProtocolVersion,
			ReservationID:   lease.view.ReservationID, OperationID: lease.client.newID(),
		})
		if err == nil && view.State == storagecapacity.ReservationReserved {
			view, err = lease.client.Decide(ctx, request)
		}
	}
	if err != nil {
		return err
	}
	expectedState := storagecapacity.ReservationCommitted
	if kind == storagecapacity.DecisionRelease {
		expectedState = storagecapacity.ReservationReleased
	}
	if !validPrivateReservationView(view) || view.ReservationID != lease.view.ReservationID ||
		view.ByteCeiling != lease.view.ByteCeiling || view.State != expectedState ||
		view.Revision != lease.view.Revision+1 {
		return ErrInvalid
	}
	lease.view = view
	lease.closed = true
	return nil
}

func (lease *PrivateReservationLease) invalidLocked(ctx context.Context) bool {
	return lease == nil || lease.client == nil || lease.client.now == nil ||
		lease.client.newID == nil || ctx == nil || lease.closed ||
		!validPrivateReservationView(lease.view) || lease.token == ""
}

func validPrivateReservationView(view PrivateReservationView) bool {
	validState := view.State == storagecapacity.ReservationReserved ||
		view.State == storagecapacity.ReservationCommitted ||
		view.State == storagecapacity.ReservationReleased ||
		view.State == storagecapacity.ReservationExpired
	return view.ProtocolVersion == storagecapacity.AuthorityProtocolVersion &&
		view.ReservationID != uuid.Nil && view.ByteCeiling > 0 &&
		view.ExpiresAtMilliseconds > 0 && validState &&
		view.Revision > 0 && view.UpdatedAtMilliseconds > 0
}
