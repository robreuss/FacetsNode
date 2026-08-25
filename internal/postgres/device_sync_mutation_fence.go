package postgres

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/robreuss/FacetsNode/internal/devicesync"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

var _ devicesync.MutationFenceStore = (*RelayStore)(nil)

type postgresDeviceSyncMutationFence struct {
	tx            pgx.Tx
	permitChannel chan struct{}
	releaseOnce   sync.Once
	releaseErr    error
}

// AcquireDeviceSyncMutationFence independently validates sealed in-process
// registry evidence against this store's configured deployment identity and
// the durable Device Sync authority. The explicit Read Committed transaction
// retains its FOR SHARE row lock until the returned lease is released, so a
// migration's FOR UPDATE fence waits for every admitted mutation to finish.
func (s *RelayStore) AcquireDeviceSyncMutationFence(
	ctx context.Context,
	authorization serviceauthority.MutationAuthorization,
) (devicesync.MutationFenceLease, error) {
	if ctx == nil || s == nil || s.deviceSyncLocalDeploymentID == uuid.Nil {
		return nil, serviceauthority.ErrInvalid
	}
	if err := authorization.ValidateFor(
		serviceauthority.ScopeDeviceSync,
		s.deviceSyncLocalDeploymentID,
	); err != nil {
		return nil, err
	}
	if s.pool == nil || s.deviceSyncFencePermits == nil ||
		cap(s.deviceSyncFencePermits) == 0 {
		return nil, errors.New("Device Sync mutation fence store is not configured")
	}
	if err := acquireDeviceSyncFencePermit(ctx, s.deviceSyncFencePermits); err != nil {
		return nil, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		releaseDeviceSyncFencePermit(s.deviceSyncFencePermits)
		return nil, fmt.Errorf("begin Device Sync mutation fence: %w", err)
	}
	lease := &postgresDeviceSyncMutationFence{
		tx: tx, permitChannel: s.deviceSyncFencePermits,
	}
	if _, err := tx.Exec(
		ctx,
		"SELECT set_config('application_name', $1, true)",
		"facets-device-sync-mutation-fence",
	); err != nil {
		if rollbackErr := lease.Release(ctx); rollbackErr != nil {
			return nil, errors.Join(err, fmt.Errorf(
				"release unlabeled Device Sync mutation fence: %w", rollbackErr,
			))
		}
		return nil, fmt.Errorf("label Device Sync mutation fence: %w", err)
	}
	if _, err := lockDeviceSyncScopeForMutation(
		ctx,
		tx,
		authorization.Scope().ScopeID,
		s.deviceSyncLocalDeploymentID,
		authorization.AuthorityRevision(),
		authorization.AuthorityManifestDigest(),
		authorization.AuthorizedAtMilliseconds(),
	); err != nil {
		if rollbackErr := lease.Release(ctx); rollbackErr != nil {
			return nil, errors.Join(err, fmt.Errorf(
				"release rejected Device Sync mutation fence: %w", rollbackErr,
			))
		}
		return nil, err
	}
	return lease, nil
}

func acquireDeviceSyncFencePermit(ctx context.Context, permits chan struct{}) error {
	if ctx == nil || permits == nil || cap(permits) == 0 {
		return serviceauthority.ErrInvalid
	}
	select {
	case permits <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func releaseDeviceSyncFencePermit(permits chan struct{}) {
	<-permits
}

// Release rolls back the lock-only transaction. sync.Once makes concurrent or
// repeated cleanup safe; pgx releases the pooled connection after Rollback.
func (lease *postgresDeviceSyncMutationFence) Release(ctx context.Context) error {
	if lease == nil || lease.tx == nil || lease.permitChannel == nil {
		return serviceauthority.ErrInvalid
	}
	lease.releaseOnce.Do(func() {
		releaseParent := context.Background()
		if ctx != nil {
			releaseParent = context.WithoutCancel(ctx)
		}
		releaseContext, cancel := context.WithTimeout(releaseParent, 5*time.Second)
		defer cancel()
		lease.releaseErr = lease.tx.Rollback(releaseContext)
		if errors.Is(lease.releaseErr, pgx.ErrTxClosed) {
			lease.releaseErr = nil
		}
		releaseDeviceSyncFencePermit(lease.permitChannel)
	})
	return lease.releaseErr
}
