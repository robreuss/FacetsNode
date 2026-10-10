package backupcustody

import "context"

// CapacityAuthority is the content-blind physical storage admission boundary.
// Account and upload identity remain exclusively in Backup custody and are
// never passed to the shared authority.
type CapacityAuthority interface {
	Reserve(context.Context, int64) (CapacityReservation, error)
}

type CapacityReservation interface {
	Recheck(context.Context) error
	Commit(context.Context) error
	Release(context.Context) error
}
