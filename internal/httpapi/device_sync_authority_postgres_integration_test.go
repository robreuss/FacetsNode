package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/devicesync"
	postgresstore "github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/rendezvous"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
	"github.com/robreuss/FacetsNode/internal/testpostgres"
)

func TestPostgresDeviceSyncHTTPClaimCrashRepairRemainsMutationFenced(
	t *testing.T,
) {
	databaseURL := os.Getenv("FACETS_SERVER_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("FACETS_SERVER_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	databaseLock, err := testpostgres.AcquireDisposableDatabaseLock(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := databaseLock.Close(); err != nil {
			t.Errorf("release disposable PostgreSQL lock: %v", err)
		}
	})
	pool := openRelayWakePool(t, ctx, databaseURL)
	defer pool.Close()
	if err := postgresstore.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		TRUNCATE device_sync_account_admissions, relay_tenants CASCADE
	`); err != nil {
		t.Fatal(err)
	}

	const now = int64(1_100)
	deploymentID := uuid.MustParse("63000000-0000-0000-0000-000000000001")
	routeID := uuid.MustParse("62000000-0000-0000-0000-000000000001")
	seed := make([]byte, 32)
	seed[31] = 2
	signer, err := serviceauthority.NewDeploymentSigner(deploymentID, seed)
	if err != nil {
		t.Fatal(err)
	}
	store, err := postgresstore.NewDeviceSyncAuthorityBoundRelayStore(
		pool, deploymentID,
	)
	if err != nil {
		t.Fatal(err)
	}

	credential := devicesync.AdmissionCredential{
		AdmissionID: uuid.New(), Token: relayTestToken(241),
	}
	authorizationDigest, err := devicesync.AdmissionAuthorizationDigest(credential)
	if err != nil {
		t.Fatal(err)
	}
	admission := devicesync.AccountAdmission{
		Version: devicesync.SchemaVersion, RetryID: uuid.New(),
		AdmissionID:           credential.AdmissionID,
		AuthorizationDigest:   authorizationDigest,
		CreatedAtMilliseconds: now,
		ExpiresAtMilliseconds: now + devicesync.MinimumAdmissionLifetimeMilliseconds,
	}
	if _, err := store.CreateAccountAdmission(ctx, admission, now); err != nil {
		t.Fatal(err)
	}

	bindingPath := filepath.Join(t.TempDir(), "bindings.json")
	emptyBindings, err := json.Marshal(serviceauthority.BindingFile{
		Bindings: []serviceauthority.BindingFileEntry{},
		Version:  serviceauthority.SchemaVersion,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bindingPath, emptyBindings, 0o600); err != nil {
		t.Fatal(err)
	}
	bindings, err := serviceauthority.LoadBindingRegistry(bindingPath, deploymentID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bindings.Close() })

	server, err := NewWithRelay(
		rendezvous.NewMemoryStore(), store, nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)), "",
	)
	if err != nil {
		t.Fatal(err)
	}
	server.now = func() time.Time { return time.UnixMilli(now) }
	server.SetServiceAuthorityDeployment(
		signer, bindings, serviceauthority.ScopeDeviceSync,
	)
	server.SetDeviceSyncStore(store)
	handler := server.Handler()

	controlDomain := newRelayDomainProvisioningRequest(now, 242, 243)
	scope := serviceauthority.Scope{
		Kind:    serviceauthority.ScopeDeviceSync,
		ScopeID: controlDomain.AdministrationCredential.TenantID,
	}
	enrollment := testInitialServiceAuthorityEnrollment(
		t, signer, scope, routeID,
	)
	manifestDigest, err := enrollment.Manifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	claim := deviceSyncPrincipalClaimInput{
		Version: devicesync.SchemaVersion, RetryID: uuid.New(),
		PrincipalID:                scope.ScopeID,
		InitialDeviceID:            controlDomain.MemberCredential.MemberID,
		ServiceAuthorityEnrollment: &enrollment,
		TenantProvisioning: newRelayTenantProvisioningRequest(
			controlDomain, relayTestToken(244),
		),
	}
	claimPath := "/v1/device-sync/account-admissions/" +
		credential.AdmissionID.String() + "/claim"

	// First crash window: PostgreSQL commits the exact standby principal, then
	// registry persistence fails. The HTTP response must withhold success.
	if err := os.Remove(bindingPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(bindingPath, 0o700); err != nil {
		t.Fatal(err)
	}
	response := performRelayJSON(
		t, handler, http.MethodPost, claimPath, claim,
		credential.Token, uuid.Nil,
	)
	requireStatus(t, response, http.StatusServiceUnavailable)
	_ = response.Body.Close()
	requirePostgresDeviceSyncState(
		t, ctx, store, scope.ScopeID, postgresstore.DeviceSyncScopeStandby,
	)
	if err := os.Remove(bindingPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bindingPath, emptyBindings, 0o600); err != nil {
		t.Fatal(err)
	}

	// Second crash window: registry activation succeeds, but the exact database
	// standby->writable flip fails. A separately authorized mutation must still
	// stop at the durable fence before its capability handler runs.
	if _, err := pool.Exec(ctx, `
		CREATE OR REPLACE FUNCTION reject_device_sync_activation_for_test()
		RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF OLD.state='standby' AND NEW.state='writable' THEN
				RAISE EXCEPTION 'injected Device Sync activation failure';
			END IF;
			RETURN NEW;
		END;
		$$;
		CREATE TRIGGER reject_device_sync_activation_for_test
		BEFORE UPDATE ON device_sync_scope_enforcement
		FOR EACH ROW EXECUTE FUNCTION reject_device_sync_activation_for_test();
	`); err != nil {
		t.Fatal(err)
	}
	response = performRelayJSON(
		t, handler, http.MethodPost, claimPath, claim,
		credential.Token, uuid.Nil,
	)
	requireStatus(t, response, http.StatusServiceUnavailable)
	_ = response.Body.Close()
	requirePostgresDeviceSyncState(
		t, ctx, store, scope.ScopeID, postgresstore.DeviceSyncScopeStandby,
	)

	mutationPath := "/v1/device-sync/principals/" + scope.ScopeID.String() +
		"/devices/" + claim.InitialDeviceID.String() + "/revocation"
	mutationRequest := httptest.NewRequest(
		http.MethodPost, mutationPath, bytes.NewReader([]byte(`{}`)),
	)
	mutationRequest.Header.Set("Content-Type", "application/json")
	mutationRequest.Header.Set("Authorization", "Bearer "+
		controlDomain.AdministrationCredential.AuthorizationToken)
	setAuthorityHeaders(
		mutationRequest.Header, scope, 1, manifestDigest, deploymentID,
		routeID, serviceauthority.TrafficControl,
	)
	mutationResponse := httptest.NewRecorder()
	handler.ServeHTTP(mutationResponse, mutationRequest)
	if mutationResponse.Code != http.StatusConflict ||
		!bytes.Contains(
			mutationResponse.Body.Bytes(),
			[]byte("stale_or_invalid_service_authority"),
		) {
		t.Fatalf(
			"standby mutation status=%d body=%s",
			mutationResponse.Code, mutationResponse.Body.String(),
		)
	}

	if _, err := pool.Exec(ctx, `
		DROP TRIGGER reject_device_sync_activation_for_test
			ON device_sync_scope_enforcement;
		DROP FUNCTION reject_device_sync_activation_for_test();
	`); err != nil {
		t.Fatal(err)
	}
	response = performRelayJSON(
		t, handler, http.MethodPost, claimPath, claim,
		credential.Token, uuid.Nil,
	)
	requireStatus(t, response, http.StatusOK)
	_ = response.Body.Close()
	requirePostgresDeviceSyncState(
		t, ctx, store, scope.ScopeID, postgresstore.DeviceSyncScopeWritable,
	)
	if err := bindings.AuthorizeAt(serviceauthority.RequestBinding{
		Scope: scope, AuthorityRevision: 1, AuthorityDigest: manifestDigest,
		DeploymentID: deploymentID, RouteID: routeID,
		TrafficClass: serviceauthority.TrafficControl,
	}, time.UnixMilli(now)); err != nil {
		t.Fatalf("repaired registry binding is not authoritative: %v", err)
	}
}

func requirePostgresDeviceSyncState(
	t *testing.T,
	ctx context.Context,
	store *postgresstore.RelayStore,
	principalID uuid.UUID,
	want postgresstore.DeviceSyncScopeEnforcementState,
) {
	t.Helper()
	state, err := store.GetDeviceSyncScopeEnforcement(ctx, principalID)
	if err != nil {
		t.Fatal(err)
	}
	if state.State != want {
		t.Fatalf("Device Sync state=%q want=%q", state.State, want)
	}
}
