package devicesync

import (
	"context"

	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

// MutationFenceLease keeps the durable Device Sync scope writable for one
// already-authorized mutation. Release is idempotent and must be called after
// the mutation has committed or failed.
type MutationFenceLease interface {
	Release(context.Context) error
}

// MutationFenceStore independently checks sealed registry evidence against
// the durable per-scope authority and holds the cross-process migration lock.
type MutationFenceStore interface {
	AcquireDeviceSyncMutationFence(
		context.Context,
		serviceauthority.MutationAuthorization,
	) (MutationFenceLease, error)
}
