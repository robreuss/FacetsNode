package serviceauthority

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestScopeMutationGateDrainsAdmittedMutation(t *testing.T) {
	gate := NewScopeMutationGate()
	scope := mutationTestScope(ScopeDeviceSync)
	mutation, err := gate.AcquireMutation(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}

	drainAcquired := make(chan *ScopeLease, 1)
	drainError := make(chan error, 1)
	go func() {
		drain, err := gate.AcquireMigrationDrain(context.Background(), scope)
		if err != nil {
			drainError <- err
			return
		}
		drainAcquired <- drain
	}()

	select {
	case drain := <-drainAcquired:
		drain.Release()
		t.Fatal("exclusive drain passed an admitted mutation")
	case err := <-drainError:
		t.Fatal(err)
	case <-time.After(25 * time.Millisecond):
	}

	mutation.Release()
	select {
	case drain := <-drainAcquired:
		drain.Release()
	case err := <-drainError:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("exclusive drain did not acquire after mutation release")
	}
}

func TestQueuedMutationRejectsFenceStagedDuringDrain(t *testing.T) {
	registry := NewBindingRegistry()
	scope := mutationTestScope(ScopeSharedSpace)
	deploymentID := uuid.New()
	digest := mutationTestDigest("1")
	if err := registry.Activate(scope, CurrentBinding{
		Revision:     1,
		Digest:       digest,
		DeploymentID: deploymentID,
	}); err != nil {
		t.Fatal(err)
	}
	binding := RequestBinding{
		Scope:             scope,
		AuthorityRevision: 1,
		AuthorityDigest:   digest,
		DeploymentID:      deploymentID,
		RouteID:           uuid.New(),
		TrafficClass:      TrafficControl,
	}
	if err := registry.AuthorizeRequest(binding, RequestMutation); err != nil {
		t.Fatalf("provisional authorization failed: %v", err)
	}
	drain, err := registry.AcquireMigrationDrain(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}

	result := make(chan error, 1)
	go func() {
		lease, err := registry.AcquireMutationLease(context.Background(), scope)
		if err != nil {
			result <- err
			return
		}
		defer lease.Release()
		result <- registry.AuthorizeRequest(binding, RequestMutation)
	}()

	registry.mu.Lock()
	current := registry.bindings[scope]
	current.WriteFence = &MigrationWriteFence{}
	registry.bindings[scope] = current
	registry.mu.Unlock()
	drain.Release()

	select {
	case err := <-result:
		if err == nil {
			t.Fatal("mutation queued behind a drain ignored the newly staged fence")
		}
	case <-time.After(time.Second):
		t.Fatal("queued mutation did not resume after drain release")
	}
}

func TestScopeMutationGateCancellationAndScopeIsolation(t *testing.T) {
	gate := NewScopeMutationGate()
	blockedScope := mutationTestScope(ScopeDeviceSync)
	otherScope := mutationTestScope(ScopeDeviceSync)
	drain, err := gate.AcquireMigrationDrain(context.Background(), blockedScope)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := gate.AcquireMutation(ctx, blockedScope); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled mutation admission error=%v; want context.Canceled", err)
	}
	other, err := gate.AcquireMutation(context.Background(), otherScope)
	if err != nil {
		t.Fatalf("one scope's drain blocked a different scope: %v", err)
	}
	other.Release()
	drain.Release()

	mutation, err := gate.AcquireMutation(context.Background(), blockedScope)
	if err != nil {
		t.Fatalf("cancelled waiter leaked mutation-gate state: %v", err)
	}
	mutation.Release()
}

func TestCancelledDrainWaiterDoesNotBlockLaterMutation(t *testing.T) {
	gate := NewScopeMutationGate()
	scope := mutationTestScope(ScopeSharedSpace)
	active, err := gate.AcquireMutation(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	defer active.Release()

	ctx, cancel := context.WithCancel(context.Background())
	drainResult := make(chan error, 1)
	go func() {
		_, err := gate.AcquireMigrationDrain(ctx, scope)
		drainResult <- err
	}()
	state, err := gate.state(scope)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		state.mu.Lock()
		waiters := state.exclusiveWaiters
		state.mu.Unlock()
		if waiters == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("exclusive drain did not enter its wait state")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case err := <-drainResult:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled drain error=%v; want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled drain did not return")
	}

	admissionContext, stopAdmission := context.WithTimeout(context.Background(), time.Second)
	defer stopAdmission()
	later, err := gate.AcquireMutation(admissionContext, scope)
	if err != nil {
		t.Fatalf("cancelled drain waiter continued blocking mutations: %v", err)
	}
	later.Release()
}

func TestBindingRegistryDrainRejectsUnboundScope(t *testing.T) {
	registry := NewBindingRegistry()
	boundScope := mutationTestScope(ScopeDeviceSync)
	if err := registry.Activate(boundScope, CurrentBinding{
		Revision:     1,
		Digest:       mutationTestDigest("2"),
		DeploymentID: uuid.New(),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.AcquireMigrationDrain(
		context.Background(),
		mutationTestScope(ScopeDeviceSync),
	); err == nil {
		t.Fatal("migration drain accepted a scope with no current binding")
	}
}

func TestMutationAuthorizationIsSealedRegistryEvidence(t *testing.T) {
	registry := NewBindingRegistry()
	scope := mutationTestScope(ScopeDeviceSync)
	deploymentID := uuid.New()
	digest := mutationTestDigest("3")
	if err := registry.Activate(scope, CurrentBinding{
		Revision: 1, Digest: digest, DeploymentID: deploymentID,
	}); err != nil {
		t.Fatal(err)
	}
	binding := RequestBinding{
		Scope: scope, AuthorityRevision: 1, AuthorityDigest: digest,
		DeploymentID: deploymentID, RouteID: uuid.New(),
		TrafficClass: TrafficControl,
	}
	now := time.UnixMilli(4_000)
	authorization, err := registry.AuthorizeMutationAt(binding, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := authorization.ValidateFor(ScopeDeviceSync, deploymentID); err != nil {
		t.Fatal(err)
	}
	if authorization.Scope() != scope || authorization.AuthorityRevision() != 1 ||
		authorization.AuthorityManifestDigest() != digest ||
		authorization.DeploymentID() != deploymentID ||
		authorization.AuthorizedAtMilliseconds() != 4_000 {
		t.Fatalf("unexpected sealed authorization: %+v", authorization)
	}
	if (MutationAuthorization{}).ValidateFor(ScopeDeviceSync, deploymentID) == nil ||
		authorization.ValidateFor(ScopeSharedSpace, deploymentID) == nil ||
		authorization.ValidateFor(ScopeDeviceSync, uuid.New()) == nil {
		t.Fatal("sealed mutation authorization accepted the wrong boundary")
	}

	registry.mu.Lock()
	current := registry.bindings[scope]
	current.WriteFence = &MigrationWriteFence{}
	registry.bindings[scope] = current
	registry.mu.Unlock()
	if _, err := registry.AuthorizeMutationAt(binding, now); err == nil {
		t.Fatal("registry issued mutation authorization after a write fence")
	}
}

func TestInternalDeviceSyncMutationAuthorizationRequiresCurrentLocalAuthority(t *testing.T) {
	fixture := newBootstrapFixture(t)
	validUntil := int64(2_000)
	manifest := fixture.signedManifestUntil(t, fixture.policy, &validUntil)
	digest, err := manifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	registry := NewBindingRegistry()
	registry.expectedDeploymentID = fixture.descriptor.DeploymentID
	if err := registry.Activate(fixture.scope, CurrentBinding{
		Revision:     1,
		Digest:       digest,
		DeploymentID: fixture.descriptor.DeploymentID,
		Manifest:     &manifest,
	}); err != nil {
		t.Fatal(err)
	}

	authorization, err := registry.AuthorizeInternalDeviceSyncMutationAt(
		fixture.scope,
		time.UnixMilli(1_100),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := authorization.ValidateFor(
		ScopeDeviceSync,
		fixture.descriptor.DeploymentID,
	); err != nil {
		t.Fatal(err)
	}
	if authorization.Scope() != fixture.scope ||
		authorization.AuthorityRevision() != 1 ||
		authorization.AuthorityManifestDigest() != digest ||
		authorization.DeploymentID() != fixture.descriptor.DeploymentID ||
		authorization.AuthorizedAtMilliseconds() != 1_100 {
		t.Fatalf("unexpected internal authorization: %+v", authorization)
	}

	tests := []struct {
		name string
		now  int64
		edit func(*BindingRegistry)
	}{
		{
			name: "future manifest",
			now:  999,
		},
		{
			name: "expired manifest",
			now:  2_000,
		},
		{
			name: "negative time",
			now:  -1,
		},
		{
			name: "missing signed manifest",
			now:  1_100,
			edit: func(candidate *BindingRegistry) {
				current := candidate.bindings[fixture.scope]
				current.Manifest = nil
				candidate.bindings[fixture.scope] = current
			},
		},
		{
			name: "nonlocal deployment",
			now:  1_100,
			edit: func(candidate *BindingRegistry) {
				candidate.expectedDeploymentID = uuid.New()
			},
		},
		{
			name: "write fence",
			now:  1_100,
			edit: func(candidate *BindingRegistry) {
				current := candidate.bindings[fixture.scope]
				current.WriteFence = &MigrationWriteFence{}
				candidate.bindings[fixture.scope] = current
			},
		},
		{
			name: "poisoned custody",
			now:  1_100,
			edit: func(candidate *BindingRegistry) {
				candidate.poisoned = true
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := NewBindingRegistry()
			candidate.expectedDeploymentID = fixture.descriptor.DeploymentID
			candidate.bindings[fixture.scope] = registry.bindings[fixture.scope]
			if test.edit != nil {
				test.edit(candidate)
			}
			_, err := candidate.AuthorizeInternalDeviceSyncMutationAt(
				fixture.scope,
				time.UnixMilli(test.now),
			)
			if err == nil {
				t.Fatal("internal mutation authority was issued")
			}
			if test.name == "poisoned custody" &&
				!errors.Is(err, ErrBindingUnavailable) {
				t.Fatalf("poisoned error=%v; want ErrBindingUnavailable", err)
			}
		})
	}

	if _, err := NewBindingRegistry().AuthorizeInternalDeviceSyncMutationAt(
		fixture.scope,
		time.UnixMilli(1_100),
	); err == nil {
		t.Fatal("unscoped registry issued internal mutation authority")
	}
	if _, err := registry.AuthorizeInternalDeviceSyncMutationAt(
		Scope{Kind: ScopeDeviceSync, ScopeID: uuid.New()},
		time.UnixMilli(1_100),
	); err == nil {
		t.Fatal("missing scope issued internal mutation authority")
	}
	if _, err := registry.AuthorizeInternalDeviceSyncMutationAt(
		Scope{Kind: ScopeSharedSpace, ScopeID: fixture.scope.ScopeID},
		time.UnixMilli(1_100),
	); err == nil {
		t.Fatal("wrong service issued internal mutation authority")
	}
}

func mutationTestScope(kind ScopeKind) Scope {
	return Scope{Kind: kind, ScopeID: uuid.New()}
}

func mutationTestDigest(value string) string {
	digest := ""
	for len(digest) < 64 {
		digest += value
	}
	return digest[:64]
}
