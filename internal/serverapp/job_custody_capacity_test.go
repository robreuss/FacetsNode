package serverapp

import (
	"context"
	"errors"
	"testing"

	"github.com/robreuss/FacetsNode/internal/jobcustody"
	"github.com/robreuss/FacetsNode/internal/storageauthority"
	"github.com/robreuss/FacetsNode/internal/storagecapacity"
)

func TestJobCustodyCapacityTransportOutageIsCoarseCapacityUnavailable(t *testing.T) {
	if err := jobCustodyCapacityError(storageauthority.ErrUnavailable); !errors.Is(err, storagecapacity.ErrUnavailable) {
		t.Fatalf("transport outage mapped to %v", err)
	}
	if err := jobCustodyCapacityError(storageauthority.ErrInvalid); !errors.Is(err, storageauthority.ErrInvalid) {
		t.Fatalf("authority contract failure was hidden: %v", err)
	}
}

func TestJobCustodyCapacityAdapterRejectsMissingAuthority(t *testing.T) {
	authority := jobCustodyCapacityAuthority{}
	if _, err := authority.Reserve(context.Background(), 1); !errors.Is(err, jobcustody.ErrInvalid) {
		t.Fatalf("missing capacity client mapped to %v", err)
	}
	reservation := jobCustodyCapacityReservation{}
	for name, operation := range map[string]func(context.Context) error{
		"recheck": reservation.Recheck,
		"commit":  reservation.Commit,
		"release": reservation.Release,
	} {
		t.Run(name, func(t *testing.T) {
			if err := operation(context.Background()); !errors.Is(err, jobcustody.ErrInvalid) {
				t.Fatalf("missing lease mapped to %v", err)
			}
		})
	}
}
