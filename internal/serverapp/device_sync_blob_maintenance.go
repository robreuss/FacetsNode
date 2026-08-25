package serverapp

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/devicesync"
	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

type deviceSyncBlobMaintenanceBackend interface {
	relay.BlobMaintenanceStore
	ExpiredBlobUploadTenantCandidates(context.Context, int64) ([]uuid.UUID, error)
	ExpireBlobUploadsForTenant(
		context.Context,
		uuid.UUID,
		int64,
		int64,
		int,
	) ([]relay.BlobUploadExpiry, error)
}

// deviceSyncBlobMaintenanceStore applies the same in-process and durable
// authority boundary as HTTP mutations to background upload expiry and orphan
// deletion. Filesystem callbacks execute before either lease is released.
type deviceSyncBlobMaintenanceStore struct {
	backend      deviceSyncBlobMaintenanceBackend
	bindings     *serviceauthority.BindingRegistry
	fences       devicesync.MutationFenceStore
	authorityNow func() time.Time
}

func newDeviceSyncBlobMaintenanceStore(
	backend deviceSyncBlobMaintenanceBackend,
	bindings *serviceauthority.BindingRegistry,
	fences devicesync.MutationFenceStore,
) (*deviceSyncBlobMaintenanceStore, error) {
	if backend == nil || bindings == nil || fences == nil {
		return nil, serviceauthority.ErrInvalid
	}
	return &deviceSyncBlobMaintenanceStore{
		backend:      backend,
		bindings:     bindings,
		fences:       fences,
		authorityNow: time.Now,
	}, nil
}

func (store *deviceSyncBlobMaintenanceStore) ExpireBlobUploads(
	ctx context.Context,
	nowMilliseconds, graceMilliseconds int64,
) ([]relay.BlobUploadExpiry, error) {
	if store == nil || ctx == nil ||
		!validDeviceSyncBlobMaintenanceTime(nowMilliseconds, graceMilliseconds) {
		return nil, serviceauthority.ErrInvalid
	}
	tenants, err := store.backend.ExpiredBlobUploadTenantCandidates(
		ctx,
		nowMilliseconds,
	)
	if err != nil {
		return nil, err
	}
	var expired []relay.BlobUploadExpiry
	var maintenanceErr error
	for _, tenantID := range tenants {
		remaining := relay.MaximumBlobUploadExpiryBatchSize - len(expired)
		if remaining == 0 {
			break
		}
		var tenantExpired []relay.BlobUploadExpiry
		err := store.withAuthorizedTenantMutation(
			ctx,
			tenantID,
			func() error {
				var err error
				tenantExpired, err = store.backend.ExpireBlobUploadsForTenant(
					ctx,
					tenantID,
					nowMilliseconds,
					graceMilliseconds,
					remaining,
				)
				return err
			},
		)
		// The backend may have committed a strict prefix before reporting a
		// later candidate failure. Count that durable work toward the global
		// bound even though the pass also reports the error.
		expired = append(expired, tenantExpired...)
		if err != nil {
			maintenanceErr = errors.Join(maintenanceErr, err)
			if errors.Is(err, context.Canceled) ||
				errors.Is(err, context.DeadlineExceeded) {
				break
			}
			continue
		}
	}
	return expired, maintenanceErr
}

func (store *deviceSyncBlobMaintenanceStore) DeleteBlobIfUnauthorized(
	ctx context.Context,
	candidate relay.BlobContentCandidate,
	nowMilliseconds, graceMilliseconds int64,
	remove func() error,
) (deleted bool, err error) {
	if store == nil || ctx == nil || candidate.Scope.TenantID == uuid.Nil ||
		candidate.Scope.DomainID == uuid.Nil ||
		relay.ValidateBlobID(candidate.BlobID) != nil ||
		!validDeviceSyncBlobMaintenanceTime(nowMilliseconds, graceMilliseconds) {
		return false, serviceauthority.ErrInvalid
	}
	err = store.withAuthorizedTenantMutation(
		ctx,
		candidate.Scope.TenantID,
		func() error {
			var delegateErr error
			deleted, delegateErr = store.backend.DeleteBlobIfUnauthorized(
				ctx,
				candidate,
				nowMilliseconds,
				graceMilliseconds,
				remove,
			)
			return delegateErr
		},
	)
	return deleted, err
}

func (store *deviceSyncBlobMaintenanceStore) DeleteBlobUploadIfUnauthorized(
	ctx context.Context,
	candidate relay.BlobUploadContentCandidate,
	nowMilliseconds, graceMilliseconds int64,
	remove func() error,
) (deleted bool, err error) {
	if store == nil || ctx == nil || candidate.Scope.TenantID == uuid.Nil ||
		candidate.Scope.DomainID == uuid.Nil || candidate.UploadID == uuid.Nil ||
		!validDeviceSyncBlobMaintenanceTime(nowMilliseconds, graceMilliseconds) {
		return false, serviceauthority.ErrInvalid
	}
	err = store.withAuthorizedTenantMutation(
		ctx,
		candidate.Scope.TenantID,
		func() error {
			var delegateErr error
			deleted, delegateErr = store.backend.DeleteBlobUploadIfUnauthorized(
				ctx,
				candidate,
				nowMilliseconds,
				graceMilliseconds,
				remove,
			)
			return delegateErr
		},
	)
	return deleted, err
}

func (store *deviceSyncBlobMaintenanceStore) withAuthorizedTenantMutation(
	ctx context.Context,
	tenantID uuid.UUID,
	mutate func() error,
) (err error) {
	if store == nil || store.bindings == nil || store.fences == nil ||
		store.authorityNow == nil || ctx == nil || tenantID == uuid.Nil ||
		mutate == nil {
		return serviceauthority.ErrInvalid
	}
	scope := serviceauthority.Scope{
		Kind:    serviceauthority.ScopeDeviceSync,
		ScopeID: tenantID,
	}
	processLease, err := store.bindings.AcquireMutationLease(ctx, scope)
	if err != nil {
		return fmt.Errorf("acquire Device Sync maintenance mutation lease: %w", err)
	}
	defer processLease.Release()

	// The maintenance cutoff may have been sampled before waiting for the
	// process lease. Authority is a separate decision and must be evaluated
	// from a fresh clock only after admission to the mutation boundary.
	authorityNow := store.authorityNow()
	authorization, err := store.bindings.AuthorizeInternalDeviceSyncMutationAt(
		scope,
		authorityNow,
	)
	if err != nil {
		return fmt.Errorf("authorize Device Sync maintenance mutation: %w", err)
	}
	durableLease, err := store.fences.AcquireDeviceSyncMutationFence(
		ctx,
		authorization,
	)
	if err != nil {
		return fmt.Errorf("acquire durable Device Sync maintenance fence: %w", err)
	}
	defer func() {
		releaseErr := durableLease.Release(context.WithoutCancel(ctx))
		if releaseErr != nil {
			err = errors.Join(
				err,
				fmt.Errorf("release durable Device Sync maintenance fence: %w", releaseErr),
			)
		}
	}()

	return mutate()
}

func validDeviceSyncBlobMaintenanceTime(
	nowMilliseconds,
	graceMilliseconds int64,
) bool {
	return nowMilliseconds >= 0 && graceMilliseconds >= 0 &&
		graceMilliseconds <= math.MaxInt64-nowMilliseconds
}
