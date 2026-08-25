package httpapi

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/rendezvous"
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

func TestBootstrapDeploymentProofRequiresSignedOfferButNoActiveBinding(t *testing.T) {
	deploymentID := uuid.MustParse("63000000-0000-0000-0000-000000000001")
	routeID := uuid.MustParse("62000000-0000-0000-0000-000000000001")
	scope := serviceauthority.Scope{
		Kind:    serviceauthority.ScopeDeviceSync,
		ScopeID: uuid.MustParse("61000000-0000-0000-0000-000000000001"),
	}
	seed := make([]byte, 32)
	seed[31] = 2
	signer, err := serviceauthority.NewDeploymentSigner(deploymentID, seed)
	if err != nil {
		t.Fatal(err)
	}
	offer := testBootstrapDeploymentOffer(t, signer, routeID)
	digest, err := offer.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	proofRequest := serviceauthority.BootstrapProofRequest{
		Challenge:             base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		DeploymentID:          deploymentID,
		DeploymentOfferDigest: digest,
		RouteID:               routeID,
		Scope:                 scope,
		TrafficClass:          serviceauthority.TrafficControl,
		Version:               serviceauthority.SchemaVersion,
	}
	body, err := json.Marshal(bootstrapDeploymentProofInput{
		DeploymentOffer: offer,
		Request:         proofRequest,
	})
	if err != nil {
		t.Fatal(err)
	}
	server := New(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	server.now = func() time.Time { return time.UnixMilli(1_100) }
	server.SetServiceAuthorityDeployment(
		signer,
		serviceauthority.NewBindingRegistry(),
		serviceauthority.ScopeDeviceSync,
	)
	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/service-deployment/bootstrap-proof",
		bytes.NewReader(body),
	)
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("bootstrap proof status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var proof serviceauthority.BootstrapProof
	if err := json.Unmarshal(recorder.Body.Bytes(), &proof); err != nil {
		t.Fatal(err)
	}
	var payload serviceauthority.BootstrapProofPayload
	if err := json.Unmarshal(proof.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Request != proofRequest || payload.IssuedAtMilliseconds != 1_100 {
		t.Fatalf("unexpected bootstrap deployment proof: %+v", payload)
	}

	proofRequest.DeploymentOfferDigest = repeatAuthorityHex("f")
	body, _ = json.Marshal(bootstrapDeploymentProofInput{
		DeploymentOffer: offer,
		Request:         proofRequest,
	})
	request = httptest.NewRequest(
		http.MethodPost,
		"/v1/service-deployment/bootstrap-proof",
		bytes.NewReader(body),
	)
	request.Header.Set("Content-Type", "application/json")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("wrong-offer bootstrap proof status=%d; want 400", recorder.Code)
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

func TestDeploymentIssuesBearerAuthorizedGrantBeforeBulkUpload(t *testing.T) {
	blobRoot := t.TempDir()
	blobStore, err := relay.NewFileBlobContentStore(blobRoot)
	if err != nil {
		t.Fatal(err)
	}
	uploadStore, err := relay.NewFileBlobUploadContentStore(blobRoot, blobStore)
	if err != nil {
		t.Fatal(err)
	}
	operatorToken := relayTestToken(201)
	server, err := NewWithRelay(
		rendezvous.NewMemoryStore(),
		relay.NewMemoryStore(),
		blobStore,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		operatorToken,
		uploadStore,
	)
	if err != nil {
		t.Fatal(err)
	}
	server.now = func() time.Time { return time.UnixMilli(1_500) }
	authority := provisionRelayTestAuthority(
		t, server.Handler(), operatorToken, 1_500, 202, 203,
	)
	deploymentID := uuid.MustParse("63000000-0000-0000-0000-000000000001")
	routeID := uuid.MustParse("62000000-0000-0000-0000-000000000001")
	digest := repeatAuthorityHex("1")
	seed := make([]byte, 32)
	seed[31] = 2
	signer, err := serviceauthority.NewDeploymentSigner(deploymentID, seed)
	if err != nil {
		t.Fatal(err)
	}
	scope := serviceauthority.Scope{
		Kind:    serviceauthority.ScopeDeviceSync,
		ScopeID: authority.Domain.TenantID,
	}
	bindings := serviceauthority.NewBindingRegistry()
	if err := bindings.Activate(scope, serviceauthority.CurrentBinding{
		Revision: 1, Digest: digest, DeploymentID: deploymentID,
	}); err != nil {
		t.Fatal(err)
	}
	server.SetServiceAuthorityDeployment(
		signer, bindings, serviceauthority.ScopeDeviceSync,
	)
	handler := server.Handler()
	uploadID := uuid.New()
	grantRequest := serviceauthority.BulkGrantRequest{
		Direction:         serviceauthority.BulkUpload,
		RequiredByteCount: 12,
		ResourceID:        uploadID.String(),
		RouteID:           routeID,
		Version:           serviceauthority.SchemaVersion,
	}
	body, err := json.Marshal(grantRequest)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/relay/tenants/"+authority.Domain.TenantID.String()+
			"/domains/"+authority.Domain.DomainID.String()+
			"/bulk-transfer-grants",
		bytes.NewReader(body),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+authority.MemberCredential.AuthorizationToken)
	request.Header.Set("X-Facets-Member-ID", authority.Member.MemberID.String())
	setAuthorityHeaders(
		request.Header, scope, 1, digest, deploymentID, routeID,
		serviceauthority.TrafficControl,
	)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("grant status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var grant serviceauthority.BulkTransferGrant
	if err := json.NewDecoder(recorder.Body).Decode(&grant); err != nil {
		t.Fatal(err)
	}
	grantHeaderData, err := json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}
	grantHeader := base64.RawURLEncoding.EncodeToString(grantHeaderData)
	_, grantPayload, err := serviceauthority.ParseBulkTransferGrantHeader(grantHeader)
	if err != nil {
		t.Fatal(err)
	}
	if grant.Signature.SignerID != deploymentID ||
		grantPayload.ResourceID != uploadID.String() ||
		grantPayload.MaximumByteCount != 12 ||
		grantPayload.ExpiresAtMilliseconds != 301_500 {
		t.Fatalf("unexpected deployment grant: grant=%+v payload=%+v", grant, grantPayload)
	}

	blobBytes := []byte("cipher-bytes")
	upload := relay.BlobUploadRequest{
		RetryID: uuid.New(), UploadID: uploadID, RelayBlobID: relay.BlobID(blobBytes),
		ByteCount: int64(len(blobBytes)), CreatedAtMilliseconds: 1_500,
	}
	uploadBody, err := json.Marshal(upload)
	if err != nil {
		t.Fatal(err)
	}
	uploadRequest := httptest.NewRequest(
		http.MethodPost,
		"/v1/relay/tenants/"+authority.Domain.TenantID.String()+
			"/domains/"+authority.Domain.DomainID.String()+"/blob-uploads",
		bytes.NewReader(uploadBody),
	)
	uploadRequest.Header.Set("Content-Type", "application/json")
	uploadRequest.Header.Set("Authorization", "Bearer "+authority.MemberCredential.AuthorizationToken)
	uploadRequest.Header.Set("X-Facets-Member-ID", authority.Member.MemberID.String())
	uploadRequest.Header.Set(serviceauthority.HeaderBulkTransferGrant, grantHeader)
	uploadRequest.Header.Set(serviceauthority.HeaderBulkResourceID, uploadID.String())
	uploadRequest.Header.Set(serviceauthority.HeaderBulkDirection, string(serviceauthority.BulkUpload))
	setAuthorityHeaders(
		uploadRequest.Header, scope, 1, digest, deploymentID, routeID,
		serviceauthority.TrafficBulk,
	)
	uploadRecorder := httptest.NewRecorder()
	handler.ServeHTTP(uploadRecorder, uploadRequest)
	if uploadRecorder.Code != http.StatusCreated {
		t.Fatalf("authorized upload status=%d body=%s", uploadRecorder.Code, uploadRecorder.Body.String())
	}

	missingGrant := uploadRequest.Clone(uploadRequest.Context())
	missingGrant.Body = io.NopCloser(bytes.NewReader(uploadBody))
	missingGrant.Header = uploadRequest.Header.Clone()
	missingGrant.Header.Del(serviceauthority.HeaderBulkTransferGrant)
	missingRecorder := httptest.NewRecorder()
	handler.ServeHTTP(missingRecorder, missingGrant)
	if missingRecorder.Code != http.StatusConflict {
		t.Fatalf("grantless upload status=%d; want 409", missingRecorder.Code)
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
	return serviceauthority.CurrentBinding{
		Revision: revision, Digest: digest, DeploymentID: deploymentID,
	}
}

func repeatAuthorityHex(value string) string {
	result := ""
	for len(result) < 64 {
		result += value
	}
	return result
}

func testBootstrapDeploymentOffer(
	t *testing.T,
	signer *serviceauthority.DeploymentSigner,
	routeID uuid.UUID,
) serviceauthority.DeploymentOffer {
	t.Helper()
	pin := repeatAuthorityHex("1")
	route := serviceauthority.TransportRoute{
		Endpoint:     "https://facets-box.local:8443",
		Kind:         serviceauthority.RouteDirectHTTPS,
		NetworkScope: serviceauthority.NetworkTrustedLAN,
		RouteID:      routeID,
		ServerAuthentication: serviceauthority.ServerAuthentication{
			Kind: "pinned_spki_sha256", PinnedSPKISHA256: &pin,
		},
	}
	descriptor := serviceauthority.DeploymentDescriptor{
		CreatedAtMilliseconds: 900,
		DeploymentID:          signer.DeploymentID(),
		PublicSigningKeyX963:  signer.PublicSigningKeyX963(),
		Routes:                []serviceauthority.TransportRoute{route},
		SigningKeyFingerprint: signer.SigningKeyFingerprint(),
		Version:               serviceauthority.SchemaVersion,
	}
	policy := serviceauthority.TransportPolicy{
		BulkRouteIDs:    []uuid.UUID{routeID},
		ControlRouteIDs: []uuid.UUID{routeID},
		MessageRouteIDs: []uuid.UUID{routeID},
		Version:         serviceauthority.SchemaVersion,
	}
	offer, err := signer.SignDeploymentOffer(serviceauthority.DeploymentOfferPayload{
		Deployment:            descriptor,
		ExpiresAtMilliseconds: 2_000,
		IssuedAtMilliseconds:  1_000,
		TransportPolicy:       policy,
		Version:               serviceauthority.SchemaVersion,
	})
	if err != nil {
		t.Fatal(err)
	}
	return offer
}

func testInitialServiceAuthorityEnrollment(
	t *testing.T,
	signer *serviceauthority.DeploymentSigner,
	scope serviceauthority.Scope,
	routeID uuid.UUID,
) serviceauthority.InitialEnrollment {
	t.Helper()
	offer := testBootstrapDeploymentOffer(t, signer, routeID)
	offerPayload, err := offer.VerifiedPayload(nil)
	if err != nil {
		t.Fatal(err)
	}
	authorityScalar := make([]byte, 32)
	authorityScalar[31] = 1
	d := new(big.Int).SetBytes(authorityScalar)
	x, y := elliptic.P256().ScalarBaseMult(authorityScalar)
	key := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y},
		D:         d,
	}
	authorityID := uuid.MustParse("64000000-0000-0000-0000-000000000001")
	public := elliptic.Marshal(elliptic.P256(), x, y)
	fingerprint := sha256.Sum256(public)
	manifestPayload := serviceauthority.ManifestPayload{
		ActiveDeployment:      offerPayload.Deployment,
		IssuedAtMilliseconds:  1_000,
		PreparedDeployments:   []serviceauthority.DeploymentDescriptor{},
		Revision:              1,
		Scope:                 scope,
		Transition:            "initial_activation",
		TransportPolicy:       offerPayload.TransportPolicy,
		ValidFromMilliseconds: 1_000,
		Version:               serviceauthority.SchemaVersion,
	}
	encoded, err := json.Marshal(manifestPayload)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(append(
		[]byte("Facets service authority manifest v1\x00"),
		encoded...,
	))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if s.Cmp(new(big.Int).Rsh(new(big.Int).Set(elliptic.P256().Params().N), 1)) > 0 {
		s.Sub(elliptic.P256().Params().N, s)
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	manifest := serviceauthority.Manifest{
		Payload: encoded,
		Signature: serviceauthority.Signature{
			Algorithm:             "ES256",
			PublicSigningKeyX963:  base64.RawURLEncoding.EncodeToString(public),
			Signature:             base64.RawURLEncoding.EncodeToString(raw),
			SignerID:              authorityID,
			SigningKeyFingerprint: hex.EncodeToString(fingerprint[:]),
		},
	}
	return serviceauthority.InitialEnrollment{
		Anchor: serviceauthority.TrustAnchor{
			PublicSigningKeyX963:  base64.RawURLEncoding.EncodeToString(public),
			Scope:                 scope,
			SignerID:              authorityID,
			SigningKeyFingerprint: hex.EncodeToString(fingerprint[:]),
			Version:               serviceauthority.SchemaVersion,
		},
		DeploymentOffer: offer,
		Manifest:        manifest,
		Version:         serviceauthority.SchemaVersion,
	}
}
