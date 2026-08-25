package httpapi

import (
	"context"

	"github.com/robreuss/FacetsNode/internal/devicesync"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

// setUnboundDeviceSyncStoreForTesting preserves the pure in-memory handler
// unit-test harness. Production construction must use SetDeviceSyncStore,
// which requires service authority and an authority-bound store.
func setUnboundDeviceSyncStoreForTesting(server *Server, store devicesync.Store) {
	server.deviceSyncStore = store
	setUnboundDeviceSyncMutationFenceForTesting(server)
}

func setUnboundDeviceSyncMutationFenceForTesting(server *Server) {
	server.deviceSyncMutationFenceStore = unboundDeviceSyncMutationFenceStoreForTesting{}
}

type unboundDeviceSyncMutationFenceStoreForTesting struct{}

func (unboundDeviceSyncMutationFenceStoreForTesting) AcquireDeviceSyncMutationFence(
	context.Context,
	serviceauthority.MutationAuthorization,
) (devicesync.MutationFenceLease, error) {
	return unboundDeviceSyncMutationFenceLeaseForTesting{}, nil
}

type unboundDeviceSyncMutationFenceLeaseForTesting struct{}

func (unboundDeviceSyncMutationFenceLeaseForTesting) Release(context.Context) error {
	return nil
}
