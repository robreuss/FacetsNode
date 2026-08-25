package computepool

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

func TestHTTPHandlerRequiresCurrentPoolAuthorityAndOperatorCredential(t *testing.T) {
	var fixture portableFixture
	decodeStrict(t, portableContractFixture, &fixture)
	store := NewMemoryStore()
	if err := store.CreatePool(context.Background(), fixture.Pool); err != nil {
		t.Fatal(err)
	}
	handler, binding, token := testHTTPHandler(t, store, fixture.Pool.PoolID)

	request := httptest.NewRequest(
		http.MethodGet,
		"/v1/compute-pools/"+fixture.Pool.PoolID.String()+"/status",
		nil,
	)
	request.Header.Set("Authorization", "Bearer "+token)
	setAuthorityHeaders(request, binding)
	recorder := httptest.NewRecorder()
	handler.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("authorized Compute Pool status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	stale := httptest.NewRequest(
		http.MethodGet,
		"/v1/compute-pools/"+fixture.Pool.PoolID.String()+"/status",
		nil,
	)
	stale.Header.Set("Authorization", "Bearer "+token)
	staleBinding := binding
	staleBinding.AuthorityRevision = 2
	setAuthorityHeaders(stale, staleBinding)
	recorder = httptest.NewRecorder()
	handler.Handler().ServeHTTP(recorder, stale)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("stale Compute Pool authority status=%d", recorder.Code)
	}

	unauthorized := httptest.NewRequest(
		http.MethodGet,
		"/v1/compute-pools/"+fixture.Pool.PoolID.String()+"/status",
		nil,
	)
	setAuthorityHeaders(unauthorized, binding)
	recorder = httptest.NewRecorder()
	handler.Handler().ServeHTTP(recorder, unauthorized)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("missing Compute Pool operator credential status=%d", recorder.Code)
	}
}

func TestHTTPHandlerProducesDeploymentProofOnlyForCurrentComputePoolScope(t *testing.T) {
	poolID := uuid.MustParse("71000000-0000-0000-0000-000000000001")
	handler, binding, _ := testHTTPHandler(t, NewMemoryStore(), poolID)
	challenge := make([]byte, 32)
	requestBody := serviceauthority.ProofRequest{
		AuthorityManifestDigest: binding.AuthorityDigest,
		AuthorityRevision:       binding.AuthorityRevision,
		Challenge:               base64.RawURLEncoding.EncodeToString(challenge),
		DeploymentID:            binding.DeploymentID,
		RouteID:                 binding.RouteID,
		Scope:                   binding.Scope,
		TrafficClass:            serviceauthority.TrafficControl,
		Version:                 serviceauthority.SchemaVersion,
	}
	encoded, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/service-deployment/proof",
		bytes.NewReader(encoded),
	)
	recorder := httptest.NewRecorder()
	handler.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("Compute Pool deployment proof status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var proof serviceauthority.DeploymentProof
	if err := json.Unmarshal(recorder.Body.Bytes(), &proof); err != nil {
		t.Fatal(err)
	}
	var payload serviceauthority.ProofPayload
	if err := json.Unmarshal(proof.Payload, &payload); err != nil || payload.Request != requestBody {
		t.Fatalf("Compute Pool deployment proof payload=%+v error=%v", payload, err)
	}

	requestBody.Scope.Kind = serviceauthority.ScopeSharedSpace
	encoded, _ = json.Marshal(requestBody)
	request = httptest.NewRequest(
		http.MethodPost,
		"/v1/service-deployment/proof",
		bytes.NewReader(encoded),
	)
	recorder = httptest.NewRecorder()
	handler.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("Shared Space scope received Compute Pool proof status=%d", recorder.Code)
	}
}

func testHTTPHandler(
	t *testing.T,
	store Store,
	poolID uuid.UUID,
) (*HTTPHandler, serviceauthority.RequestBinding, string) {
	t.Helper()
	deploymentID := uuid.MustParse("88000000-0000-0000-0000-000000000001")
	seed := make([]byte, 32)
	seed[31] = 2
	signer, err := serviceauthority.NewDeploymentSigner(deploymentID, seed)
	if err != nil {
		t.Fatal(err)
	}
	binding := serviceauthority.RequestBinding{
		Scope: serviceauthority.Scope{
			Kind: serviceauthority.ScopeComputePool, ScopeID: poolID,
		},
		AuthorityRevision: 1, AuthorityDigest: repeatHex("1"),
		DeploymentID: deploymentID,
		RouteID:      uuid.MustParse("89000000-0000-0000-0000-000000000001"),
		TrafficClass: serviceauthority.TrafficControl,
	}
	bindings := serviceauthority.NewBindingRegistry()
	authoritySeed := make([]byte, 32)
	authoritySeed[31] = 1
	authority, err := serviceauthority.NewDeploymentSigner(
		uuid.MustParse("8a000000-0000-0000-0000-000000000001"),
		authoritySeed,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := bindings.Activate(binding.Scope, serviceauthority.CurrentBinding{
		Revision: binding.AuthorityRevision, Digest: binding.AuthorityDigest,
		DeploymentID:                   deploymentID,
		AuthoritySignerID:              authority.DeploymentID(),
		AuthorityPublicSigningKeyX963:  authority.PublicSigningKeyX963(),
		AuthoritySigningKeyFingerprint: authority.SigningKeyFingerprint(),
	}); err != nil {
		t.Fatal(err)
	}
	tokenBytes := bytes.Repeat([]byte{0x61}, 32)
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	handler, err := NewHTTPHandler(store, signer, bindings, token)
	if err != nil {
		t.Fatal(err)
	}
	handler.now = func() time.Time { return time.UnixMilli(1_000) }
	return handler, binding, token
}

func setAuthorityHeaders(request *http.Request, binding serviceauthority.RequestBinding) {
	request.Header.Set(serviceauthority.HeaderScopeKind, string(binding.Scope.Kind))
	request.Header.Set(serviceauthority.HeaderScopeID, binding.Scope.ScopeID.String())
	request.Header.Set(serviceauthority.HeaderAuthorityRevision, "1")
	if binding.AuthorityRevision != 1 {
		request.Header.Set(
			serviceauthority.HeaderAuthorityRevision,
			"2",
		)
	}
	request.Header.Set(serviceauthority.HeaderAuthorityDigest, binding.AuthorityDigest)
	request.Header.Set(serviceauthority.HeaderDeploymentID, binding.DeploymentID.String())
	request.Header.Set(serviceauthority.HeaderRouteID, binding.RouteID.String())
	request.Header.Set(serviceauthority.HeaderTrafficClass, string(binding.TrafficClass))
}

func repeatHex(value string) string {
	result := ""
	for len(result) < 64 {
		result += value
	}
	return result
}
