package serverapp

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/devicesync"
	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

type deviceSyncMaintenanceBackend struct {
	tenants             []uuid.UUID
	fence               *deviceSyncMaintenanceFenceStore
	expiryCalls         []uuid.UUID
	expiryLimits        []int
	expiryCount         int
	expiryErrors        []error
	blobDeleteCalls     int
	uploadDeleteCalls   int
	aggregateExpiryCall bool
}

func (backend *deviceSyncMaintenanceBackend) ExpiredBlobUploadTenantCandidates(
	context.Context,
	int64,
) ([]uuid.UUID, error) {
	return append([]uuid.UUID(nil), backend.tenants...), nil
}

func (backend *deviceSyncMaintenanceBackend) ExpireBlobUploadsForTenant(
	_ context.Context,
	tenantID uuid.UUID,
	_, _ int64,
	limit int,
) ([]relay.BlobUploadExpiry, error) {
	if backend.fence.active.Load() != 1 {
		return nil, errors.New("expiry delegate ran outside durable fence")
	}
	backend.expiryCalls = append(backend.expiryCalls, tenantID)
	backend.expiryLimits = append(backend.expiryLimits, limit)
	callIndex := len(backend.expiryCalls) - 1
	count := backend.expiryCount
	if count == 0 {
		count = 1
	}
	if count > limit {
		count = limit
	}
	expired := make([]relay.BlobUploadExpiry, 0, count)
	for range count {
		expired = append(expired, relay.BlobUploadExpiry{
			Scope: relay.BlobScope{
				TenantID: tenantID,
				DomainID: uuid.New(),
			},
			UploadID: uuid.New(),
		})
	}
	if callIndex < len(backend.expiryErrors) {
		return expired, backend.expiryErrors[callIndex]
	}
	return expired, nil
}

func TestDeviceSyncBlobMaintenanceRetainsGlobalExpiryBatchBound(t *testing.T) {
	bindings, scope, deploymentID := deviceSyncMaintenanceRegistry(t)
	fences := &deviceSyncMaintenanceFenceStore{deploymentID: deploymentID}
	backend := &deviceSyncMaintenanceBackend{
		tenants:     []uuid.UUID{scope.ScopeID},
		fence:       fences,
		expiryCount: relay.MaximumBlobUploadExpiryBatchSize + 50,
	}
	store, err := newDeviceSyncBlobMaintenanceStore(backend, bindings, fences)
	if err != nil {
		t.Fatal(err)
	}
	store.authorityNow = func() time.Time { return time.UnixMilli(1_100) }

	expired, err := store.ExpireBlobUploads(context.Background(), 1_100, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(expired) != relay.MaximumBlobUploadExpiryBatchSize ||
		len(backend.expiryLimits) != 1 ||
		backend.expiryLimits[0] != relay.MaximumBlobUploadExpiryBatchSize {
		t.Fatalf(
			"expired=%d limits=%v",
			len(expired),
			backend.expiryLimits,
		)
	}
}

func TestDeviceSyncBlobMaintenanceCountsCommittedPrefixAfterError(t *testing.T) {
	bindings, scope, deploymentID := deviceSyncMaintenanceRegistry(t)
	fences := &deviceSyncMaintenanceFenceStore{deploymentID: deploymentID}
	injected := errors.New("later candidate failed after committed prefix")
	backend := &deviceSyncMaintenanceBackend{
		tenants:      []uuid.UUID{scope.ScopeID, scope.ScopeID},
		fence:        fences,
		expiryCount:  200,
		expiryErrors: []error{injected},
	}
	store, err := newDeviceSyncBlobMaintenanceStore(backend, bindings, fences)
	if err != nil {
		t.Fatal(err)
	}
	store.authorityNow = func() time.Time { return time.UnixMilli(1_100) }

	expired, err := store.ExpireBlobUploads(context.Background(), 1_100, 100)
	if !errors.Is(err, injected) {
		t.Fatalf("maintenance error=%v", err)
	}
	if len(expired) != relay.MaximumBlobUploadExpiryBatchSize ||
		len(backend.expiryLimits) != 2 ||
		backend.expiryLimits[0] != relay.MaximumBlobUploadExpiryBatchSize ||
		backend.expiryLimits[1] != 56 {
		t.Fatalf(
			"expired=%d limits=%v",
			len(expired),
			backend.expiryLimits,
		)
	}
}

func (backend *deviceSyncMaintenanceBackend) ExpireBlobUploads(
	context.Context,
	int64,
	int64,
) ([]relay.BlobUploadExpiry, error) {
	backend.aggregateExpiryCall = true
	return nil, errors.New("aggregate expiry delegate must not be used")
}

func (backend *deviceSyncMaintenanceBackend) DeleteBlobIfUnauthorized(
	_ context.Context,
	_ relay.BlobContentCandidate,
	_, _ int64,
	remove func() error,
) (bool, error) {
	if backend.fence.active.Load() != 1 {
		return false, errors.New("blob delegate ran outside durable fence")
	}
	backend.blobDeleteCalls++
	if remove == nil {
		return false, errors.New("missing blob removal callback")
	}
	return true, remove()
}

func (backend *deviceSyncMaintenanceBackend) DeleteBlobUploadIfUnauthorized(
	_ context.Context,
	_ relay.BlobUploadContentCandidate,
	_, _ int64,
	remove func() error,
) (bool, error) {
	if backend.fence.active.Load() != 1 {
		return false, errors.New("upload delegate ran outside durable fence")
	}
	backend.uploadDeleteCalls++
	if remove == nil {
		return false, errors.New("missing upload removal callback")
	}
	return true, remove()
}

type deviceSyncMaintenanceFenceStore struct {
	deploymentID uuid.UUID
	active       atomic.Int32
	acquisitions atomic.Int32
	mu           sync.Mutex
	authorities  []serviceauthority.MutationAuthorization
	acquireErr   error
	releaseErr   error
}

func (store *deviceSyncMaintenanceFenceStore) AcquireDeviceSyncMutationFence(
	_ context.Context,
	authorization serviceauthority.MutationAuthorization,
) (devicesync.MutationFenceLease, error) {
	if store.acquireErr != nil {
		return nil, store.acquireErr
	}
	if err := authorization.ValidateFor(
		serviceauthority.ScopeDeviceSync,
		store.deploymentID,
	); err != nil {
		return nil, err
	}
	if store.active.Add(1) != 1 {
		store.active.Add(-1)
		return nil, errors.New("overlapping fake durable fences")
	}
	store.acquisitions.Add(1)
	store.mu.Lock()
	store.authorities = append(store.authorities, authorization)
	store.mu.Unlock()
	return &deviceSyncMaintenanceFenceLease{store: store}, nil
}

type deviceSyncMaintenanceFenceLease struct {
	store *deviceSyncMaintenanceFenceStore
	once  sync.Once
}

func (lease *deviceSyncMaintenanceFenceLease) Release(context.Context) error {
	lease.once.Do(func() {
		lease.store.active.Add(-1)
	})
	return lease.store.releaseErr
}

func TestDeviceSyncBlobMaintenanceHoldsScopeAndDurableLeases(t *testing.T) {
	bindings, scope, deploymentID := deviceSyncMaintenanceRegistry(t)
	fences := &deviceSyncMaintenanceFenceStore{deploymentID: deploymentID}
	backend := &deviceSyncMaintenanceBackend{
		tenants: []uuid.UUID{scope.ScopeID},
		fence:   fences,
	}
	store, err := newDeviceSyncBlobMaintenanceStore(backend, bindings, fences)
	if err != nil {
		t.Fatal(err)
	}
	store.authorityNow = func() time.Time { return time.UnixMilli(1_100) }

	expired, err := store.ExpireBlobUploads(context.Background(), 1_100, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(expired) != 1 || expired[0].Scope.TenantID != scope.ScopeID ||
		len(backend.expiryCalls) != 1 || backend.expiryCalls[0] != scope.ScopeID ||
		backend.aggregateExpiryCall || fences.active.Load() != 0 {
		t.Fatalf(
			"unexpected expiry result=%+v backend=%+v active=%d",
			expired,
			backend,
			fences.active.Load(),
		)
	}

	callbackRan := false
	deleted, err := store.DeleteBlobIfUnauthorized(
		context.Background(),
		relay.BlobContentCandidate{
			Scope:  relay.BlobScope{TenantID: scope.ScopeID, DomainID: uuid.New()},
			BlobID: relay.BlobID([]byte("orphan")),
		},
		1_100,
		100,
		func() error {
			callbackRan = true
			if fences.active.Load() != 1 {
				t.Fatal("filesystem callback ran after durable lease release")
			}
			drainContext, cancel := context.WithTimeout(
				context.Background(),
				20*time.Millisecond,
			)
			defer cancel()
			if drain, err := bindings.AcquireMigrationDrain(
				drainContext,
				scope,
			); !errors.Is(err, context.DeadlineExceeded) {
				if drain != nil {
					drain.Release()
				}
				t.Fatalf("migration drain escaped active maintenance lease: %v", err)
			}
			return nil
		},
	)
	if err != nil || !deleted || !callbackRan || fences.active.Load() != 0 {
		t.Fatalf(
			"blob deletion deleted=%v callback=%v active=%d err=%v",
			deleted,
			callbackRan,
			fences.active.Load(),
			err,
		)
	}
	drain, err := bindings.AcquireMigrationDrain(context.Background(), scope)
	if err != nil {
		t.Fatalf("maintenance mutation lease was not released: %v", err)
	}
	drain.Release()

	uploadCallbackRan := false
	deleted, err = store.DeleteBlobUploadIfUnauthorized(
		context.Background(),
		relay.BlobUploadContentCandidate{
			Scope:    relay.BlobScope{TenantID: scope.ScopeID, DomainID: uuid.New()},
			UploadID: uuid.New(),
		},
		1_100,
		100,
		func() error {
			uploadCallbackRan = fences.active.Load() == 1
			return nil
		},
	)
	if err != nil || !deleted || !uploadCallbackRan || fences.active.Load() != 0 {
		t.Fatalf(
			"upload deletion deleted=%v callback=%v active=%d err=%v",
			deleted,
			uploadCallbackRan,
			fences.active.Load(),
			err,
		)
	}
	if fences.acquisitions.Load() != 3 || backend.blobDeleteCalls != 1 ||
		backend.uploadDeleteCalls != 1 {
		t.Fatalf(
			"unexpected calls fences=%d blobs=%d uploads=%d",
			fences.acquisitions.Load(),
			backend.blobDeleteCalls,
			backend.uploadDeleteCalls,
		)
	}
	identities, err := bindings.CurrentBindingIdentities(
		serviceauthority.ScopeDeviceSync,
	)
	if err != nil || len(identities) != 1 {
		t.Fatalf("current authority identities=%+v err=%v", identities, err)
	}
	fences.mu.Lock()
	authorities := append(
		[]serviceauthority.MutationAuthorization(nil),
		fences.authorities...,
	)
	fences.mu.Unlock()
	if len(authorities) != 3 {
		t.Fatalf("sealed maintenance authorities=%d", len(authorities))
	}
	for _, authorization := range authorities {
		if authorization.Scope() != scope ||
			authorization.AuthorityRevision() != identities[0].Revision ||
			authorization.AuthorityManifestDigest() != identities[0].Digest ||
			authorization.DeploymentID() != deploymentID ||
			authorization.AuthorizedAtMilliseconds() != 1_100 {
			t.Fatalf("wrong sealed maintenance authority: %+v", authorization)
		}
	}
}

func TestDeviceSyncBlobMaintenanceFailsClosedBeforeDelegate(t *testing.T) {
	bindings, scope, deploymentID := deviceSyncMaintenanceRegistry(t)
	fences := &deviceSyncMaintenanceFenceStore{deploymentID: deploymentID}
	backend := &deviceSyncMaintenanceBackend{fence: fences}
	store, err := newDeviceSyncBlobMaintenanceStore(backend, bindings, fences)
	if err != nil {
		t.Fatal(err)
	}

	unknownTenant := uuid.New()
	if _, err := store.DeleteBlobIfUnauthorized(
		context.Background(),
		relay.BlobContentCandidate{
			Scope:  relay.BlobScope{TenantID: unknownTenant, DomainID: uuid.New()},
			BlobID: relay.BlobID([]byte("unknown")),
		},
		1_100,
		100,
		func() error { return nil },
	); err == nil {
		t.Fatal("unbound tenant reached blob maintenance")
	}
	if backend.blobDeleteCalls != 0 || fences.acquisitions.Load() != 0 {
		t.Fatal("unbound tenant reached a mutation delegate or durable fence")
	}

	acquireFailure := errors.New("injected durable fence failure")
	fences.acquireErr = acquireFailure
	if _, err := store.DeleteBlobIfUnauthorized(
		context.Background(),
		relay.BlobContentCandidate{
			Scope:  relay.BlobScope{TenantID: scope.ScopeID, DomainID: uuid.New()},
			BlobID: relay.BlobID([]byte("blocked")),
		},
		1_100,
		100,
		func() error { return nil },
	); !errors.Is(err, acquireFailure) {
		t.Fatalf("durable acquisition error=%v", err)
	}
	if backend.blobDeleteCalls != 0 {
		t.Fatal("durable fence failure reached mutation delegate")
	}
}

func TestDeviceSyncBlobMaintenanceSamplesAuthorityTimeAfterLeaseAdmission(
	t *testing.T,
) {
	bindings, scope, deploymentID := finiteDeviceSyncMaintenanceRegistry(t)
	fences := &deviceSyncMaintenanceFenceStore{deploymentID: deploymentID}
	backend := &deviceSyncMaintenanceBackend{fence: fences}
	store, err := newDeviceSyncBlobMaintenanceStore(backend, bindings, fences)
	if err != nil {
		t.Fatal(err)
	}
	var authorityMilliseconds atomic.Int64
	authorityMilliseconds.Store(5_000)
	store.authorityNow = func() time.Time {
		return time.UnixMilli(authorityMilliseconds.Load())
	}

	drain, err := bindings.AcquireMigrationDrain(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		close(started)
		_, callErr := store.DeleteBlobIfUnauthorized(
			context.Background(),
			relay.BlobContentCandidate{
				Scope: relay.BlobScope{
					TenantID: scope.ScopeID,
					DomainID: uuid.New(),
				},
				BlobID: relay.BlobID([]byte("expired-authority")),
			},
			5_000,
			100,
			func() error { return nil },
		)
		result <- callErr
	}()
	<-started
	select {
	case err := <-result:
		drain.Release()
		t.Fatalf("maintenance escaped the held migration drain: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	// The signed Manifest is valid before, but not at, 10,000ms. Advancing
	// the authority clock while admission is blocked must fail closed.
	authorityMilliseconds.Store(10_000)
	drain.Release()
	if err := <-result; err == nil {
		t.Fatal("maintenance used the stale pre-admission cutoff as authority time")
	}
	if fences.acquisitions.Load() != 0 || backend.blobDeleteCalls != 0 {
		t.Fatalf(
			"expired authority reached fence=%d delegate=%d",
			fences.acquisitions.Load(),
			backend.blobDeleteCalls,
		)
	}
}

func TestDeviceSyncBlobMaintenanceReportsDurableReleaseFailure(t *testing.T) {
	bindings, scope, deploymentID := deviceSyncMaintenanceRegistry(t)
	releaseFailure := errors.New("injected durable release failure")
	fences := &deviceSyncMaintenanceFenceStore{
		deploymentID: deploymentID,
		releaseErr:   releaseFailure,
	}
	backend := &deviceSyncMaintenanceBackend{fence: fences}
	store, err := newDeviceSyncBlobMaintenanceStore(backend, bindings, fences)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.DeleteBlobUploadIfUnauthorized(
		context.Background(),
		relay.BlobUploadContentCandidate{
			Scope:    relay.BlobScope{TenantID: scope.ScopeID, DomainID: uuid.New()},
			UploadID: uuid.New(),
		},
		1_100,
		100,
		func() error { return nil },
	)
	if !errors.Is(err, releaseFailure) {
		t.Fatalf("release error=%v", err)
	}
	if fences.active.Load() != 0 || backend.uploadDeleteCalls != 1 {
		t.Fatalf(
			"release failure active=%d delegateCalls=%d",
			fences.active.Load(),
			backend.uploadDeleteCalls,
		)
	}
}

func deviceSyncMaintenanceRegistry(
	t *testing.T,
) (*serviceauthority.BindingRegistry, serviceauthority.Scope, uuid.UUID) {
	t.Helper()
	contents, err := os.ReadFile(
		"../serviceauthority/testdata/service-migration-portable-v2.json",
	)
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		RollbackEvidence struct {
			ActivationEvidence struct {
				Preparation struct {
					CurrentManifest serviceauthority.Manifest `json:"currentManifest"`
				} `json:"preparation"`
			} `json:"activationEvidence"`
		} `json:"rollbackEvidence"`
	}
	if err := json.Unmarshal(contents, &fixture); err != nil {
		t.Fatal(err)
	}
	manifest := fixture.RollbackEvidence.ActivationEvidence.Preparation.CurrentManifest
	return loadDeviceSyncMaintenanceRegistry(t, manifest, nil)
}

func finiteDeviceSyncMaintenanceRegistry(
	t *testing.T,
) (*serviceauthority.BindingRegistry, serviceauthority.Scope, uuid.UUID) {
	t.Helper()
	contents, err := os.ReadFile(
		"../serviceauthority/testdata/service-migration-portable-v2.json",
	)
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		RollbackEvidenceDigest string `json:"rollbackEvidenceDigest"`
		RollbackEvidence       struct {
			RollbackManifest serviceauthority.Manifest `json:"rollbackManifest"`
		} `json:"rollbackEvidence"`
	}
	if err := json.Unmarshal(contents, &fixture); err != nil {
		t.Fatal(err)
	}
	evidenceDigest := fixture.RollbackEvidenceDigest
	return loadDeviceSyncMaintenanceRegistry(
		t,
		fixture.RollbackEvidence.RollbackManifest,
		&evidenceDigest,
	)
}

func loadDeviceSyncMaintenanceRegistry(
	t *testing.T,
	manifest serviceauthority.Manifest,
	transitionEvidenceDigest *string,
) (*serviceauthority.BindingRegistry, serviceauthority.Scope, uuid.UUID) {
	t.Helper()
	payload, err := manifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := manifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	bindingFile, err := json.Marshal(serviceauthority.BindingFile{
		Version: serviceauthority.SchemaVersion,
		Bindings: []serviceauthority.BindingFileEntry{{
			Scope:                    payload.Scope,
			Revision:                 payload.Revision,
			Digest:                   digest,
			DeploymentID:             payload.ActiveDeployment.DeploymentID,
			Manifest:                 &manifest,
			TransitionEvidenceDigest: transitionEvidenceDigest,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "bindings.json")
	if err := os.WriteFile(path, bindingFile, 0o600); err != nil {
		t.Fatal(err)
	}
	registry, err := serviceauthority.LoadBindingRegistry(
		path,
		payload.ActiveDeployment.DeploymentID,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := registry.Close(); err != nil {
			t.Error(err)
		}
	})
	return registry, payload.Scope, payload.ActiveDeployment.DeploymentID
}
