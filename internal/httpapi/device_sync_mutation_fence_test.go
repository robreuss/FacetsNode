package httpapi

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/devicesync"
	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/rendezvous"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

type recordingDeviceSyncMutationFenceStore struct {
	authorization serviceauthority.MutationAuthorization
	acquireCount  int
	err           error
	lease         *recordingDeviceSyncMutationFenceLease
}

func (store *recordingDeviceSyncMutationFenceStore) AcquireDeviceSyncMutationFence(
	_ context.Context,
	authorization serviceauthority.MutationAuthorization,
) (devicesync.MutationFenceLease, error) {
	store.acquireCount++
	store.authorization = authorization
	if store.err != nil {
		return nil, store.err
	}
	if store.lease == nil {
		store.lease = &recordingDeviceSyncMutationFenceLease{}
	}
	return store.lease, nil
}

type recordingDeviceSyncMutationFenceLease struct {
	releaseCount int
}

type capacityOneDeviceSyncMutationFenceStore struct {
	deploymentID uuid.UUID
	permit       chan struct{}
	firstRelease chan struct{}
	releaseOnce  sync.Once
}

func (store *capacityOneDeviceSyncMutationFenceStore) AcquireDeviceSyncMutationFence(
	ctx context.Context,
	authorization serviceauthority.MutationAuthorization,
) (devicesync.MutationFenceLease, error) {
	if err := authorization.ValidateFor(
		serviceauthority.ScopeDeviceSync,
		store.deploymentID,
	); err != nil {
		return nil, err
	}
	select {
	case store.permit <- struct{}{}:
		return &capacityOneDeviceSyncMutationFenceLease{store: store}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type capacityOneDeviceSyncMutationFenceLease struct {
	store *capacityOneDeviceSyncMutationFenceStore
	once  sync.Once
}

func (lease *capacityOneDeviceSyncMutationFenceLease) Release(context.Context) error {
	lease.once.Do(func() {
		<-lease.store.permit
		lease.store.releaseOnce.Do(func() { close(lease.store.firstRelease) })
	})
	return nil
}

func (lease *recordingDeviceSyncMutationFenceLease) Release(context.Context) error {
	lease.releaseCount++
	return nil
}

func TestDeviceSyncCapabilityHandlerRejectsMissingDurableFence(t *testing.T) {
	deploymentID := uuid.New()
	seed := make([]byte, 32)
	seed[31] = 6
	signer, err := serviceauthority.NewDeploymentSigner(deploymentID, seed)
	if err != nil {
		t.Fatal(err)
	}
	server := New(
		rendezvous.NewMemoryStore(),
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	server.SetServiceAuthorityDeployment(
		signer,
		serviceauthority.NewBindingRegistry(),
		serviceauthority.ScopeDeviceSync,
	)
	defer func() {
		if recover() == nil {
			t.Fatal("Device Sync capability routes accepted no durable mutation fence")
		}
	}()
	_ = server.Handler()
}

func TestDeviceSyncMutationMiddlewareRequiresAndRetainsDurableFence(t *testing.T) {
	deploymentID := uuid.New()
	seed := make([]byte, 32)
	seed[31] = 7
	signer, err := serviceauthority.NewDeploymentSigner(deploymentID, seed)
	if err != nil {
		t.Fatal(err)
	}
	scope := serviceauthority.Scope{
		Kind: serviceauthority.ScopeDeviceSync, ScopeID: uuid.New(),
	}
	digest := strings.Repeat("a", 64)
	routeID := uuid.New()
	bindings := serviceauthority.NewBindingRegistry()
	if err := bindings.Activate(scope, serviceauthority.CurrentBinding{
		Revision: 1, Digest: digest, DeploymentID: deploymentID,
	}); err != nil {
		t.Fatal(err)
	}
	server := New(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	server.now = func() time.Time { return time.UnixMilli(4_000) }
	server.SetServiceAuthorityDeployment(
		signer, bindings, serviceauthority.ScopeDeviceSync,
	)
	fences := &recordingDeviceSyncMutationFenceStore{}
	server.deviceSyncMutationFenceStore = fences
	handlerEntered := false
	handler := server.serviceAuthorityBindingHandler(
		serviceauthority.TrafficControl,
		serviceauthority.RequestMutation,
		http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			handlerEntered = true
			if fences.acquireCount != 1 || fences.lease == nil ||
				fences.lease.releaseCount != 0 {
				t.Fatal("durable fence was not retained through the handler")
			}
			writer.WriteHeader(http.StatusNoContent)
		}),
	)
	request := httptest.NewRequest(http.MethodPost, "/", nil)
	request.SetPathValue("principalID", scope.ScopeID.String())
	setAuthorityHeaders(
		request.Header, scope, 1, digest, deploymentID, routeID,
		serviceauthority.TrafficControl,
	)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent || !handlerEntered ||
		fences.acquireCount != 1 || fences.lease.releaseCount != 1 {
		t.Fatalf(
			"status=%d entered=%v acquire=%d release=%d",
			recorder.Code, handlerEntered, fences.acquireCount,
			fences.lease.releaseCount,
		)
	}
	if err := fences.authorization.ValidateFor(
		serviceauthority.ScopeDeviceSync, deploymentID,
	); err != nil || fences.authorization.Scope() != scope ||
		fences.authorization.AuthorizedAtMilliseconds() != 4_000 {
		t.Fatalf("durable fence received invalid sealed authorization: %v", err)
	}
}

func TestDeviceSyncMutationMiddlewareFailsClosedBeforeHandler(t *testing.T) {
	for _, test := range []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{
			name: "durable fence", err: devicesync.ErrScopeWriteFenced,
			wantStatus: http.StatusConflict,
			wantCode:   "stale_or_invalid_service_authority",
		},
		{
			name: "database unavailable", err: errors.New("database unavailable"),
			wantStatus: http.StatusServiceUnavailable,
			wantCode:   "device_sync_authority_unavailable",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			deploymentID := uuid.New()
			seed := make([]byte, 32)
			seed[31] = 8
			signer, err := serviceauthority.NewDeploymentSigner(deploymentID, seed)
			if err != nil {
				t.Fatal(err)
			}
			scope := serviceauthority.Scope{
				Kind: serviceauthority.ScopeDeviceSync, ScopeID: uuid.New(),
			}
			digest := strings.Repeat("b", 64)
			bindings := serviceauthority.NewBindingRegistry()
			if err := bindings.Activate(scope, serviceauthority.CurrentBinding{
				Revision: 1, Digest: digest, DeploymentID: deploymentID,
			}); err != nil {
				t.Fatal(err)
			}
			server := New(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
			server.now = func() time.Time { return time.UnixMilli(4_000) }
			server.SetServiceAuthorityDeployment(
				signer, bindings, serviceauthority.ScopeDeviceSync,
			)
			fences := &recordingDeviceSyncMutationFenceStore{err: test.err}
			server.deviceSyncMutationFenceStore = fences
			handler := server.serviceAuthorityBindingHandler(
				serviceauthority.TrafficControl,
				serviceauthority.RequestMutation,
				http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					t.Fatal("rejected durable fence entered the mutation handler")
				}),
			)
			request := httptest.NewRequest(http.MethodPost, "/", nil)
			request.SetPathValue("principalID", scope.ScopeID.String())
			setAuthorityHeaders(
				request.Header, scope, 1, digest, deploymentID, uuid.New(),
				serviceauthority.TrafficControl,
			)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != test.wantStatus ||
				!strings.Contains(recorder.Body.String(), test.wantCode) {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestDeviceSyncWakeReleasesFenceDuringIdleWait(t *testing.T) {
	relayStore := relay.NewMemoryStore()
	domainInput := newRelayDomainProvisioningRequest(1_000, 51, 52)
	tenantInput := newRelayTenantProvisioningRequest(
		domainInput,
		relayTestToken(50),
	)
	tenant, domain, err := relayTenantAndDomainProvisioning(tenantInput)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := relayStore.ProvisionTenant(
		context.Background(), tenant, domain,
	); err != nil || result.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("provision relay tenant=%+v err=%v", result, err)
	}

	deploymentID := uuid.New()
	seed := make([]byte, 32)
	seed[31] = 9
	signer, err := serviceauthority.NewDeploymentSigner(deploymentID, seed)
	if err != nil {
		t.Fatal(err)
	}
	scope := serviceauthority.Scope{
		Kind: serviceauthority.ScopeDeviceSync, ScopeID: tenant.TenantID,
	}
	digest := strings.Repeat("c", 64)
	bindings := serviceauthority.NewBindingRegistry()
	if err := bindings.Activate(scope, serviceauthority.CurrentBinding{
		Revision: 1, Digest: digest, DeploymentID: deploymentID,
	}); err != nil {
		t.Fatal(err)
	}
	server := newRelayTestServer(t, relayStore, "")
	server.now = func() time.Time { return time.UnixMilli(1_100) }
	server.SetServiceAuthorityDeployment(
		signer, bindings, serviceauthority.ScopeDeviceSync,
	)
	fences := &capacityOneDeviceSyncMutationFenceStore{
		deploymentID: deploymentID,
		permit:       make(chan struct{}, 1),
		firstRelease: make(chan struct{}),
	}
	server.deviceSyncMutationFenceStore = fences
	handler := server.Handler()
	basePath := "/v1/relay/tenants/" + tenant.TenantID.String() +
		"/domains/" + domainInput.AdministrationCredential.DomainID.String() +
		"/messages"

	wakeRequest := httptest.NewRequest(
		http.MethodGet,
		basePath+"/wake?waitMilliseconds=5000",
		nil,
	)
	wakeRequest.Header.Set(
		"Authorization",
		"Bearer "+domainInput.MemberCredential.AuthorizationToken,
	)
	wakeRequest.Header.Set(
		"X-Facets-Member-ID",
		domainInput.MemberCredential.MemberID.String(),
	)
	setAuthorityHeaders(
		wakeRequest.Header, scope, 1, digest, deploymentID, uuid.New(),
		serviceauthority.TrafficMessage,
	)
	wakeResult := make(chan int, 1)
	go func() {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, wakeRequest)
		wakeResult <- recorder.Code
	}()
	select {
	case <-fences.firstRelease:
	case <-time.After(time.Second):
		t.Fatal("wake did not release its initial short mutation fence")
	}
	select {
	case status := <-wakeResult:
		t.Fatalf("wake returned before its idle wait with status %d", status)
	default:
	}

	fetchRequest := httptest.NewRequest(http.MethodGet, basePath, nil)
	fetchRequest.Header = wakeRequest.Header.Clone()
	fetchResult := make(chan int, 1)
	go func() {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, fetchRequest)
		fetchResult <- recorder.Code
	}()
	select {
	case status := <-fetchResult:
		if status != http.StatusOK {
			t.Fatalf("concurrent fetch status=%d", status)
		}
	case <-time.After(time.Second):
		t.Fatal("idle wake retained the only mutation-fence permit")
	}
	server.ReceiveRelayWake(
		domainInput.MemberCredential.TenantID,
		domainInput.MemberCredential.DomainID,
	)

	select {
	case status := <-wakeResult:
		if status != http.StatusNoContent {
			t.Fatalf("wake status=%d", status)
		}
	case <-time.After(time.Second):
		t.Fatal("wake did not finish after its configured wait")
	}
}
