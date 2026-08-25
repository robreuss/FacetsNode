package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

func TestDeviceSyncMutationFenceRejectsUnsealedOrWrongDeploymentBeforeDatabase(t *testing.T) {
	localDeploymentID := uuid.New()
	store := &RelayStore{deviceSyncLocalDeploymentID: localDeploymentID}
	if _, err := store.AcquireDeviceSyncMutationFence(
		context.Background(), serviceauthority.MutationAuthorization{},
	); !errors.Is(err, serviceauthority.ErrInvalid) {
		t.Fatalf("zero authorization error=%v", err)
	}

	scope := serviceauthority.Scope{
		Kind: serviceauthority.ScopeDeviceSync, ScopeID: uuid.New(),
	}
	wrongAuthorization := postgresMutationAuthorization(
		t, scope, uuid.New(), time.UnixMilli(4_000),
	)
	if _, err := store.AcquireDeviceSyncMutationFence(
		context.Background(), wrongAuthorization,
	); !errors.Is(err, serviceauthority.ErrInvalid) {
		t.Fatalf("wrong-deployment authorization error=%v", err)
	}
	wrongScopeAuthorization := postgresMutationAuthorization(
		t,
		serviceauthority.Scope{
			Kind: serviceauthority.ScopeSharedSpace, ScopeID: uuid.New(),
		},
		localDeploymentID,
		time.UnixMilli(4_000),
	)
	if _, err := store.AcquireDeviceSyncMutationFence(
		context.Background(), wrongScopeAuthorization,
	); !errors.Is(err, serviceauthority.ErrInvalid) {
		t.Fatalf("wrong-scope authorization error=%v", err)
	}

	validAuthorization := postgresMutationAuthorization(
		t, scope, localDeploymentID, time.UnixMilli(4_000),
	)
	if _, err := store.AcquireDeviceSyncMutationFence(
		context.Background(), validAuthorization,
	); err == nil || errors.Is(err, serviceauthority.ErrInvalid) {
		t.Fatalf("valid sealed authorization did not reach pool configuration: %v", err)
	}
}

func TestDeviceSyncFencePermitAdmissionIsBoundedAndCancellable(t *testing.T) {
	permits := make(chan struct{}, 1)
	if err := acquireDeviceSyncFencePermit(context.Background(), permits); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := acquireDeviceSyncFencePermit(ctx, permits); !errors.Is(
		err, context.Canceled,
	) {
		t.Fatalf("saturated permit admission error=%v", err)
	}
	if len(permits) != 1 {
		t.Fatalf("cancelled admission changed permit occupancy=%d", len(permits))
	}
	releaseDeviceSyncFencePermit(permits)
	if err := acquireDeviceSyncFencePermit(context.Background(), permits); err != nil {
		t.Fatalf("released permit was not reusable: %v", err)
	}
	releaseDeviceSyncFencePermit(permits)
}

func postgresMutationAuthorization(
	t *testing.T,
	scope serviceauthority.Scope,
	deploymentID uuid.UUID,
	now time.Time,
) serviceauthority.MutationAuthorization {
	t.Helper()
	digest := strings.Repeat("a", 64)
	registry := serviceauthority.NewBindingRegistry()
	if err := registry.Activate(scope, serviceauthority.CurrentBinding{
		Revision: 1, Digest: digest, DeploymentID: deploymentID,
	}); err != nil {
		t.Fatal(err)
	}
	authorization, err := registry.AuthorizeMutationAt(
		serviceauthority.RequestBinding{
			Scope: scope, AuthorityRevision: 1, AuthorityDigest: digest,
			DeploymentID: deploymentID, RouteID: uuid.New(),
			TrafficClass: serviceauthority.TrafficControl,
		},
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	return authorization
}
