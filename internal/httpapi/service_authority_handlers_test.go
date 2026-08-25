package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/serviceauthority"
	"github.com/robreuss/FacetsNode/internal/testfixture"
)

func TestDeploymentProofAndCapabilityRoutesRequireCurrentAuthorityBinding(t *testing.T) {
	deploymentID := uuid.MustParse("63000000-0000-0000-0000-000000000001")
	scope := serviceauthority.Scope{
		Kind:    serviceauthority.ScopeDeviceSync,
		ScopeID: uuid.MustParse("61000000-0000-0000-0000-000000000001"),
	}
	routeID := uuid.MustParse("62000000-0000-0000-0000-000000000001")
	digest := repeatAuthorityHex("1")
	seed := make([]byte, 32)
	seed[31] = 2
	signer, err := serviceauthority.NewDeploymentSigner(deploymentID, seed)
	if err != nil {
		t.Fatal(err)
	}
	bindings := serviceauthority.NewBindingRegistry()
	if err := bindings.Activate(scope, testServiceAuthorityCurrentBinding(
		t, 1, digest, deploymentID,
	)); err != nil {
		t.Fatal(err)
	}
	server := New(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	server.now = func() time.Time { return time.UnixMilli(1_000) }
	server.SetServiceAuthorityDeployment(signer, bindings, serviceauthority.ScopeDeviceSync)
	handler := server.Handler()

	proofRequest := serviceauthority.ProofRequest{
		AuthorityManifestDigest: digest,
		AuthorityRevision:       1,
		Challenge:               base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		DeploymentID:            deploymentID,
		RouteID:                 routeID,
		Scope:                   scope,
		TrafficClass:            serviceauthority.TrafficControl,
		Version:                 serviceauthority.SchemaVersion,
	}
	body, err := json.Marshal(proofRequest)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/service-deployment/proof",
		bytes.NewReader(body),
	)
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("proof status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var proof serviceauthority.DeploymentProof
	if err := json.Unmarshal(recorder.Body.Bytes(), &proof); err != nil {
		t.Fatal(err)
	}
	var payload serviceauthority.ProofPayload
	if err := json.Unmarshal(proof.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Request != proofRequest || payload.IssuedAtMilliseconds != 1_000 {
		t.Fatalf("unexpected deployment proof: %+v", payload)
	}

	stale := proofRequest
	stale.AuthorityRevision = 2
	staleBody, _ := json.Marshal(stale)
	request = httptest.NewRequest(
		http.MethodPost,
		"/v1/service-deployment/proof",
		bytes.NewReader(staleBody),
	)
	request.Header.Set("Content-Type", "application/json")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("stale proof status=%d; want 409", recorder.Code)
	}

	capability := httptest.NewRequest(
		http.MethodPost,
		"/v1/pairing/routes",
		nil,
	)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, capability)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("unbound capability status=%d; want 409", recorder.Code)
	}
	setAuthorityHeaders(
		capability.Header,
		scope,
		1,
		digest,
		deploymentID,
		routeID,
		serviceauthority.TrafficControl,
	)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, capability)
	if recorder.Code == http.StatusConflict {
		t.Fatalf("current authority binding was rejected: %s", recorder.Body.String())
	}

	capability = httptest.NewRequest(http.MethodPost, "/v1/pairing/routes", nil)
	setAuthorityHeaders(
		capability.Header,
		scope,
		1,
		digest,
		deploymentID,
		routeID,
		serviceauthority.TrafficControl,
	)
	capability.Header.Set(serviceauthority.HeaderBulkResourceID, "smuggled-resource")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, capability)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("bulk metadata on control request status=%d; want 409", recorder.Code)
	}
}

func TestAuthorityBindingRejectsWrongServiceKindAndResourceScope(t *testing.T) {
	deploymentID := uuid.MustParse("63000000-0000-0000-0000-000000000001")
	principalID := uuid.MustParse("61000000-0000-0000-0000-000000000001")
	otherPrincipalID := uuid.MustParse("61000000-0000-0000-0000-000000000002")
	digest := repeatAuthorityHex("1")
	seed := make([]byte, 32)
	seed[31] = 2
	signer, err := serviceauthority.NewDeploymentSigner(deploymentID, seed)
	if err != nil {
		t.Fatal(err)
	}
	bindings := serviceauthority.NewBindingRegistry()
	scope := serviceauthority.Scope{Kind: serviceauthority.ScopeDeviceSync, ScopeID: principalID}
	if err := bindings.Activate(scope, testServiceAuthorityCurrentBinding(
		t, 1, digest, deploymentID,
	)); err != nil {
		t.Fatal(err)
	}
	server := New(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	server.SetServiceAuthorityDeployment(signer, bindings, serviceauthority.ScopeDeviceSync)
	next := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	})
	handler := server.serviceAuthorityBindingHandler(serviceauthority.TrafficControl, next)

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.SetPathValue("principalID", otherPrincipalID.String())
	setAuthorityHeaders(request.Header, scope, 1, digest, deploymentID, uuid.New(), serviceauthority.TrafficControl)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("cross-principal binding status=%d; want 409", recorder.Code)
	}

	wrongKind := serviceauthority.Scope{Kind: serviceauthority.ScopeSharedSpace, ScopeID: principalID}
	if err := bindings.Activate(wrongKind, testServiceAuthorityCurrentBinding(
		t, 1, digest, deploymentID,
	)); err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.SetPathValue("principalID", principalID.String())
	setAuthorityHeaders(request.Header, wrongKind, 1, digest, deploymentID, uuid.New(), serviceauthority.TrafficControl)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("cross-service binding status=%d; want 409", recorder.Code)
	}
}

func TestBulkAuthorityMiddlewareRequiresExactOperationGrant(t *testing.T) {
	fixture, err := testfixture.LoadBulkTransferGrantFixture()
	if err != nil {
		t.Fatal(err)
	}
	payload := fixture.Expected
	seed := make([]byte, 32)
	seed[31] = 2
	signer, err := serviceauthority.NewDeploymentSigner(payload.DeploymentID, seed)
	if err != nil {
		t.Fatal(err)
	}
	bindings := serviceauthority.NewBindingRegistry()
	if err := bindings.Activate(payload.Scope, testServiceAuthorityCurrentBinding(
		t,
		fixture.AuthorityRevision,
		payload.AuthorityManifestDigest,
		payload.DeploymentID,
	)); err != nil {
		t.Fatal(err)
	}
	server := New(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	server.now = func() time.Time { return time.UnixMilli(1_500) }
	server.SetServiceAuthorityDeployment(signer, bindings, serviceauthority.ScopeDeviceSync)

	perform := func(
		includeGrant bool,
		resourceID string,
		observedByteCount int64,
	) *httptest.ResponseRecorder {
		t.Helper()
		next := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if server.requireBulkOperation(
				writer,
				request,
				resourceID,
				serviceauthority.BulkUpload,
				observedByteCount,
			) {
				writer.WriteHeader(http.StatusNoContent)
			}
		})
		handler := server.serviceAuthorityBindingHandler(serviceauthority.TrafficBulk, next)
		request := httptest.NewRequest(http.MethodPost, "/", nil)
		setAuthorityHeaders(
			request.Header,
			payload.Scope,
			fixture.AuthorityRevision,
			payload.AuthorityManifestDigest,
			payload.DeploymentID,
			payload.RouteID,
			serviceauthority.TrafficBulk,
		)
		if includeGrant {
			request.Header.Set(serviceauthority.HeaderBulkTransferGrant, fixture.GrantHeader)
			request.Header.Set(serviceauthority.HeaderBulkResourceID, payload.ResourceID)
			request.Header.Set(serviceauthority.HeaderBulkDirection, string(payload.Direction))
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder
	}

	if recorder := perform(false, payload.ResourceID, payload.MaximumByteCount); recorder.Code != http.StatusConflict {
		t.Fatalf("grantless bulk request status=%d; want 409", recorder.Code)
	}
	if recorder := perform(true, payload.ResourceID, payload.MaximumByteCount); recorder.Code != http.StatusNoContent {
		t.Fatalf("exact bulk request status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if recorder := perform(true, "different-resource", payload.MaximumByteCount); recorder.Code != http.StatusConflict {
		t.Fatalf("resource substitution status=%d; want 409", recorder.Code)
	}
	if recorder := perform(true, payload.ResourceID, payload.MaximumByteCount+1); recorder.Code != http.StatusConflict {
		t.Fatalf("oversized transfer status=%d; want 409", recorder.Code)
	}
}

func setAuthorityHeaders(
	header http.Header,
	scope serviceauthority.Scope,
	revision uint64,
	digest string,
	deploymentID uuid.UUID,
	routeID uuid.UUID,
	trafficClass serviceauthority.TrafficClass,
) {
	header.Set(serviceauthority.HeaderScopeKind, string(scope.Kind))
	header.Set(serviceauthority.HeaderScopeID, scope.ScopeID.String())
	header.Set(serviceauthority.HeaderAuthorityRevision, strconv.FormatUint(revision, 10))
	header.Set(serviceauthority.HeaderAuthorityDigest, digest)
	header.Set(serviceauthority.HeaderDeploymentID, deploymentID.String())
	header.Set(serviceauthority.HeaderRouteID, routeID.String())
	header.Set(serviceauthority.HeaderTrafficClass, string(trafficClass))
}

func testServiceAuthorityCurrentBinding(
	t *testing.T,
	revision uint64,
	digest string,
	deploymentID uuid.UUID,
) serviceauthority.CurrentBinding {
	t.Helper()
	seed := make([]byte, 32)
	seed[31] = 1
	authority, err := serviceauthority.NewDeploymentSigner(
		uuid.MustParse("64000000-0000-0000-0000-000000000001"),
		seed,
	)
	if err != nil {
		t.Fatal(err)
	}
	return serviceauthority.CurrentBinding{
		Revision: revision, Digest: digest, DeploymentID: deploymentID,
		AuthoritySignerID:              authority.DeploymentID(),
		AuthorityPublicSigningKeyX963:  authority.PublicSigningKeyX963(),
		AuthoritySigningKeyFingerprint: authority.SigningKeyFingerprint(),
	}
}

func repeatAuthorityHex(value string) string {
	result := ""
	for len(result) < 64 {
		result += value
	}
	return result
}
