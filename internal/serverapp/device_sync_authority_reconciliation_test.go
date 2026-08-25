package serverapp

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/devicesync"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

type reconciliationDeviceSyncStore struct {
	states                    []devicesync.DeviceSyncServiceAuthorityState
	activationError           error
	acknowledgeWithoutDurable bool
	activations               int
}

func (store *reconciliationDeviceSyncStore) ListDeviceSyncServiceAuthorityStates(
	context.Context,
) ([]devicesync.DeviceSyncServiceAuthorityState, error) {
	result := make([]devicesync.DeviceSyncServiceAuthorityState, len(store.states))
	copy(result, store.states)
	return result, nil
}

func (store *reconciliationDeviceSyncStore) ActivateBoundDeviceSyncScope(
	_ context.Context,
	principalID uuid.UUID,
	localDeploymentID uuid.UUID,
	revision uint64,
	digest string,
	_ int64,
) error {
	store.activations++
	if store.activationError != nil {
		return store.activationError
	}
	if store.acknowledgeWithoutDurable {
		return nil
	}
	for index := range store.states {
		state := &store.states[index]
		if state.Scope.ScopeID == principalID && state.Authority != nil &&
			state.Authority.LocalDeploymentID == localDeploymentID &&
			state.Authority.Revision == revision &&
			state.Authority.ManifestDigest == digest &&
			state.WriteState == devicesync.ServiceAuthorityStandby {
			state.WriteState = devicesync.ServiceAuthorityWritable
			return nil
		}
	}
	return errors.New("activation did not match fake durable authority")
}

func TestReconcileDeviceSyncServiceAuthorityAcceptsEmptyDeployment(t *testing.T) {
	store := &reconciliationDeviceSyncStore{}
	if err := reconcileDeviceSyncServiceAuthority(
		context.Background(),
		store,
		serviceauthority.NewBindingRegistry(),
		1_000,
	); err != nil {
		t.Fatal(err)
	}
	if store.activations != 0 {
		t.Fatal("empty deployment attempted an activation")
	}
}

func TestReconcileDeviceSyncServiceAuthorityRepairsExactStandby(t *testing.T) {
	state, binding := reconciliationStateAndBinding(
		uuid.MustParse("10000000-0000-0000-0000-000000000001"),
		uuid.MustParse("20000000-0000-0000-0000-000000000002"),
	)
	registry := registryWithReconciliationBindings(t, binding)
	store := &reconciliationDeviceSyncStore{states: []devicesync.DeviceSyncServiceAuthorityState{state}}

	if err := reconcileDeviceSyncServiceAuthority(
		context.Background(), store, registry, 1_000,
	); err != nil {
		t.Fatal(err)
	}
	if store.activations != 1 ||
		store.states[0].WriteState != devicesync.ServiceAuthorityWritable {
		t.Fatalf("standby was not durably repaired: %+v", store)
	}
}

func TestReconcileDeviceSyncServiceAuthorityAcceptsExactWritable(t *testing.T) {
	state, binding := reconciliationStateAndBinding(uuid.New(), uuid.New())
	state.WriteState = devicesync.ServiceAuthorityWritable
	registry := registryWithReconciliationBindings(t, binding)
	store := &reconciliationDeviceSyncStore{states: []devicesync.DeviceSyncServiceAuthorityState{state}}

	if err := reconcileDeviceSyncServiceAuthority(
		context.Background(), store, registry, 1_000,
	); err != nil {
		t.Fatal(err)
	}
	if store.activations != 0 {
		t.Fatalf("writable state was activated again: %d", store.activations)
	}
}

func TestReconcileDeviceSyncServiceAuthorityRejectsMissingAndConflictingRegistry(t *testing.T) {
	state, binding := reconciliationStateAndBinding(uuid.New(), uuid.New())
	tests := []struct {
		name     string
		registry *serviceauthority.BindingRegistry
		want     string
	}{
		{
			name:     "missing",
			registry: serviceauthority.NewBindingRegistry(),
			want:     "has no registry authority",
		},
		{
			name: "conflicting digest",
			registry: registryWithReconciliationBindings(t, serviceauthority.BindingIdentity{
				Scope: binding.Scope, Revision: binding.Revision,
				Digest: reconciliationDigest("b"), DeploymentID: binding.DeploymentID,
			}),
			want: "database and registry authority conflict",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &reconciliationDeviceSyncStore{
				states: []devicesync.DeviceSyncServiceAuthorityState{state},
			}
			err := reconcileDeviceSyncServiceAuthority(
				context.Background(), store, test.registry, 1_000,
			)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v; want %q", err, test.want)
			}
			if store.activations != 0 {
				t.Fatal("reconciliation mutated a mismatched scope")
			}
		})
	}
}

func TestReconcileDeviceSyncServiceAuthorityRejectsUnboundAndExtraScopes(t *testing.T) {
	state, binding := reconciliationStateAndBinding(uuid.New(), uuid.New())
	unbound := state
	unbound.Authority = nil
	tests := []struct {
		name     string
		states   []devicesync.DeviceSyncServiceAuthorityState
		bindings []serviceauthority.BindingIdentity
		want     string
	}{
		{
			name: "unbound standby", states: []devicesync.DeviceSyncServiceAuthorityState{unbound},
			bindings: []serviceauthority.BindingIdentity{binding}, want: "not authority-bound",
		},
		{
			name: "registry-only scope", bindings: []serviceauthority.BindingIdentity{binding},
			want: "has no durable enforcement row",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			registry := registryWithReconciliationBindings(t, test.bindings...)
			store := &reconciliationDeviceSyncStore{states: test.states}
			err := reconcileDeviceSyncServiceAuthority(
				context.Background(), store, registry, 1_000,
			)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v; want %q", err, test.want)
			}
		})
	}
}

func TestReconcileDeviceSyncServiceAuthorityRejectsIncompleteCrashRepair(t *testing.T) {
	state, binding := reconciliationStateAndBinding(uuid.New(), uuid.New())
	registry := registryWithReconciliationBindings(t, binding)
	tests := []struct {
		name  string
		store *reconciliationDeviceSyncStore
		want  string
	}{
		{
			name: "activation failure",
			store: &reconciliationDeviceSyncStore{
				states:          []devicesync.DeviceSyncServiceAuthorityState{state},
				activationError: errors.New("injected activation failure"),
			},
			want: "injected activation failure",
		},
		{
			name: "false durable acknowledgement",
			store: &reconciliationDeviceSyncStore{
				states:                    []devicesync.DeviceSyncServiceAuthorityState{state},
				acknowledgeWithoutDurable: true,
			},
			want: "did not reach exact writable readiness",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := reconcileDeviceSyncServiceAuthority(
				context.Background(), test.store, registry, 1_000,
			)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v; want %q", err, test.want)
			}
		})
	}
}

func TestReconcileDeviceSyncServiceAuthorityRejectsMigrationState(t *testing.T) {
	state, binding := reconciliationStateAndBinding(uuid.New(), uuid.New())
	state.WriteState = devicesync.ServiceAuthorityRetired
	registry := registryWithReconciliationBindings(t, binding)
	store := &reconciliationDeviceSyncStore{states: []devicesync.DeviceSyncServiceAuthorityState{state}}

	err := reconcileDeviceSyncServiceAuthority(
		context.Background(), store, registry, 1_000,
	)
	if err == nil || !strings.Contains(err.Error(), "explicit migration coordinator") {
		t.Fatalf("error=%v", err)
	}
}

func TestReconcileDeviceSyncServiceAuthorityDoesNotActivateLaterStandbyAuthority(t *testing.T) {
	state, binding := reconciliationStateAndBinding(uuid.New(), uuid.New())
	state.Authority.Revision = 2
	binding.Revision = 2
	registry := registryWithReconciliationBindings(t, binding)
	store := &reconciliationDeviceSyncStore{states: []devicesync.DeviceSyncServiceAuthorityState{state}}

	err := reconcileDeviceSyncServiceAuthority(
		context.Background(), store, registry, 1_000,
	)
	if err == nil || !strings.Contains(err.Error(), "explicit migration coordinator") {
		t.Fatalf("error=%v", err)
	}
	if store.activations != 0 {
		t.Fatal("later standby authority was made writable by initial repair")
	}
}

func reconciliationStateAndBinding(
	scopeID uuid.UUID,
	deploymentID uuid.UUID,
) (devicesync.DeviceSyncServiceAuthorityState, serviceauthority.BindingIdentity) {
	scope := serviceauthority.Scope{
		Kind: serviceauthority.ScopeDeviceSync, ScopeID: scopeID,
	}
	digest := reconciliationDigest("a")
	return devicesync.DeviceSyncServiceAuthorityState{
			Scope:      scope,
			WriteState: devicesync.ServiceAuthorityStandby,
			Authority: &devicesync.ServiceAuthorityIdentity{
				LocalDeploymentID: deploymentID, ActiveDeploymentID: deploymentID,
				Revision: 1, ManifestDigest: digest,
			},
		}, serviceauthority.BindingIdentity{
			Scope: scope, Revision: 1, Digest: digest, DeploymentID: deploymentID,
		}
}

func registryWithReconciliationBindings(
	t *testing.T,
	identities ...serviceauthority.BindingIdentity,
) *serviceauthority.BindingRegistry {
	t.Helper()
	registry := serviceauthority.NewBindingRegistry()
	for _, identity := range identities {
		binding := serviceauthority.CurrentBinding{
			Revision: identity.Revision, Digest: identity.Digest,
			DeploymentID:             identity.DeploymentID,
			TransitionEvidenceDigest: identity.TransitionEvidenceDigest,
		}
		if err := registry.Activate(identity.Scope, binding); err != nil {
			t.Fatal(err)
		}
	}
	return registry
}

func reconciliationDigest(character string) string {
	return strings.Repeat(character, 64)
}
