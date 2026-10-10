package storageauthority

import (
	"context"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/storagecapacity"
)

// BoundService is the least-authority view exposed after a private transport
// has independently authenticated one durable service binding. It performs no
// authentication itself. It prevents an authenticated service from operating
// on another service's reservations even if a reservation token is disclosed.
// Owner readiness and event methods are deliberately absent.
type BoundService struct {
	ledger  *Ledger
	binding storagecapacity.ServiceBinding
}

func BindService(
	ledger *Ledger,
	binding storagecapacity.ServiceBinding,
) (*BoundService, error) {
	if ledger == nil || binding.Validate() != nil {
		return nil, ErrInvalid
	}
	return &BoundService{ledger: ledger, binding: binding}, nil
}

func (service *BoundService) Reserve(
	ctx context.Context,
	request storagecapacity.ReservationRequest,
	bearerToken string,
) (storagecapacity.ReservationRecord, error) {
	if service == nil || service.ledger == nil || request.Service != service.binding {
		return storagecapacity.ReservationRecord{}, ErrRejected
	}
	return service.ledger.Reserve(ctx, request, bearerToken)
}

func (service *BoundService) Recheck(
	ctx context.Context,
	reservationID uuid.UUID,
	expectedRevision uint64,
	bearerToken string,
	observedAtMilliseconds int64,
) error {
	if _, err := service.authorizedReservation(ctx, reservationID); err != nil {
		return err
	}
	return service.ledger.Recheck(ctx, reservationID, expectedRevision, bearerToken, observedAtMilliseconds)
}

func (service *BoundService) Decide(
	ctx context.Context,
	decision storagecapacity.ReservationDecision,
) (storagecapacity.ReservationRecord, error) {
	if _, err := service.authorizedReservation(ctx, decision.ReservationID); err != nil {
		return storagecapacity.ReservationRecord{}, err
	}
	return service.ledger.Decide(ctx, decision)
}

func (service *BoundService) Reservation(
	ctx context.Context,
	reservationID uuid.UUID,
) (storagecapacity.ReservationRecord, error) {
	return service.authorizedReservation(ctx, reservationID)
}

func (service *BoundService) CoarseReadiness(
	ctx context.Context,
) (storagecapacity.CoarseReadinessSnapshot, error) {
	if service == nil || service.ledger == nil {
		return storagecapacity.CoarseReadinessSnapshot{}, ErrInvalid
	}
	return service.ledger.CoarseReadiness(ctx)
}

func (service *BoundService) authorizedReservation(
	ctx context.Context,
	reservationID uuid.UUID,
) (storagecapacity.ReservationRecord, error) {
	if service == nil || service.ledger == nil || service.binding.Validate() != nil ||
		ctx == nil || reservationID == uuid.Nil {
		return storagecapacity.ReservationRecord{}, ErrInvalid
	}
	record, err := service.ledger.Reservation(ctx, reservationID)
	if err != nil {
		return storagecapacity.ReservationRecord{}, err
	}
	if record.Service != service.binding {
		return storagecapacity.ReservationRecord{}, ErrRejected
	}
	return record, nil
}
