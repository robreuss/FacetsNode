package serverapp

import (
	"context"
	"errors"
	"time"

	"github.com/robreuss/FacetsNode/internal/jobcustody"
	"github.com/robreuss/FacetsNode/internal/storageauthority"
	"github.com/robreuss/FacetsNode/internal/storagecapacity"
)

// jobCustodyCapacityAuthority adapts the authenticated, content-blind private
// capacity service to Job Custody's service-local staging contract. The
// service binding used to construct client must be ServiceJobCustody; the
// adapter deliberately has no account, Space, Job, object, or path identity.
type jobCustodyCapacityAuthority struct {
	client   *storageauthority.PrivateHTTPClient
	lifetime time.Duration
}

func (authority jobCustodyCapacityAuthority) Reserve(
	ctx context.Context,
	byteCeiling int64,
) (jobcustody.CapacityReservation, error) {
	if authority.client == nil {
		return nil, jobcustody.ErrInvalid
	}
	lease, err := authority.client.Acquire(ctx, byteCeiling, authority.lifetime)
	if err != nil {
		return nil, jobCustodyCapacityError(err)
	}
	return jobCustodyCapacityReservation{lease: lease}, nil
}

type jobCustodyCapacityReservation struct {
	lease *storageauthority.PrivateReservationLease
}

func (reservation jobCustodyCapacityReservation) Recheck(ctx context.Context) error {
	if reservation.lease == nil {
		return jobcustody.ErrInvalid
	}
	return jobCustodyCapacityError(reservation.lease.Recheck(ctx))
}

func (reservation jobCustodyCapacityReservation) Commit(ctx context.Context) error {
	if reservation.lease == nil {
		return jobcustody.ErrInvalid
	}
	return jobCustodyCapacityError(reservation.lease.Commit(ctx))
}

func (reservation jobCustodyCapacityReservation) Release(ctx context.Context) error {
	if reservation.lease == nil {
		return jobcustody.ErrInvalid
	}
	return jobCustodyCapacityError(reservation.lease.Release(ctx))
}

func jobCustodyCapacityError(err error) error {
	if errors.Is(err, storageauthority.ErrUnavailable) {
		return storagecapacity.ErrUnavailable
	}
	return err
}
