package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/rendezvous"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
	"github.com/robreuss/FacetsNode/internal/traffic"
)

func TestRegisteredRoutesUseFixedTrafficSurfaces(t *testing.T) {
	blobs, err := relay.NewFileBlobContentStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewWithRelay(
		rendezvous.NewMemoryStore(), relay.NewMemoryStore(), blobs,
		slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), relayTestToken(11),
	)
	if err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, 32)
	seed[31] = 8
	signer, err := serviceauthority.NewDeploymentSigner(uuid.New(), seed)
	if err != nil {
		t.Fatal(err)
	}
	server.SetServiceAuthorityDeployment(signer, serviceauthority.NewBindingRegistry(), serviceauthority.ScopeDeviceSync)
	setUnboundDeviceSyncMutationFenceForTesting(server)
	handler := server.Handler()
	tenantID, domainID := uuid.New(), uuid.New()
	requests := []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: "/livez"},
		{method: http.MethodPost, path: "/v1/relay/tenants"},
		{method: http.MethodPost, path: "/v1/pairing/routes"},
		{method: http.MethodPost, path: "/v1/service-deployment/proof"},
		{method: http.MethodPost, path: "/v1/service-deployment/bootstrap-proof"},
		{method: http.MethodPost, path: "/v1/relay/tenants/" + tenantID.String() + "/domains/" + domainID.String() + "/bulk-transfer-grants"},
		{method: http.MethodGet, path: "/v1/relay/tenants/" + tenantID.String() + "/domains/" + domainID.String() + "/messages"},
		{method: http.MethodGet, path: "/v1/relay/tenants/" + tenantID.String() + "/domains/" + domainID.String() + "/blobs/" + relay.BlobID([]byte("blob"))},
		{method: http.MethodPost, path: "/v1/relay/tenants/" + tenantID.String() + "/domains/" + domainID.String() + "/checkpoint-fences"},
	}
	for _, item := range requests {
		req := httptest.NewRequest(item.method, item.path, nil)
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}
	expected := map[traffic.Surface]uint64{
		traffic.SurfaceRendezvous:      1,
		traffic.SurfaceRelayMessage:    1,
		traffic.SurfaceStorage:         1,
		traffic.SurfaceCheckpointAdmin: 1,
		traffic.SurfaceManagement:      2,
		traffic.SurfaceDeploymentProof: 2,
		traffic.SurfaceBulkGrant:       1,
	}
	for surface, count := range expected {
		if got := server.metrics.requests[surface].Load(); got != count {
			t.Fatalf("surface %s requests=%d expected=%d", surface.Name(), got, count)
		}
	}
	if serviceAuthorityTrafficClass(traffic.SurfaceBulkGrant) != serviceauthority.TrafficControl {
		t.Fatal("bulk grants must retain authenticated control-route authorization")
	}
}

func TestTrafficRateLimitRefillsAndExactRetryCanResume(t *testing.T) {
	server := newTrafficTestServer(t, traffic.SurfaceRelayMessage, traffic.Limit{
		RequestsPerMinute: 60, Burst: 1,
		ConnectionRequestsPerMinute: 600, ConnectionBurst: 10,
		Concurrency: 2,
	})
	now := time.Unix(1_000, 0)
	server.now = func() time.Time { return now }
	handler := server.trafficHandler(traffic.SurfaceRelayMessage, func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	})
	request := func() *http.Response {
		req := httptest.NewRequest(http.MethodPut, "/message", nil)
		req.RemoteAddr = "192.0.2.10:4000"
		req.Header.Set("Authorization", "Bearer exact-retry-secret")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		return recorder.Result()
	}
	if response := request(); response.StatusCode != http.StatusNoContent {
		t.Fatalf("initial status=%d", response.StatusCode)
	}
	limited := request()
	if limited.StatusCode != http.StatusTooManyRequests || limited.Header.Get("Retry-After") != "1" {
		t.Fatalf("limited status=%d retry=%q", limited.StatusCode, limited.Header.Get("Retry-After"))
	}
	if _, err := strconv.Atoi(limited.Header.Get("Retry-After")); err != nil {
		t.Fatalf("Retry-After is not an integer: %v", err)
	}
	if got := server.metrics.rejections[traffic.SurfaceRelayMessage][rejectionIdentityRateLimit].Load(); got != 1 {
		t.Fatalf("identity rate rejection metric=%d", got)
	}
	now = now.Add(time.Second)
	if response := request(); response.StatusCode != http.StatusNoContent {
		t.Fatalf("retry after refill status=%d", response.StatusCode)
	}
}

// Characterizes why interactive management admission must not also be the
// anonymous per-request deployment-proof budget for a bulk transfer. The
// production retry policy sleeps for Retry-After; the fake clock keeps this
// reproduction deterministic and does not require a live service.
func TestManagementBudgetCannotServeBulkDeploymentProofWorkload(t *testing.T) {
	server := newTrafficTestServer(t, traffic.SurfaceManagement, traffic.DefaultLimits()[traffic.SurfaceManagement])
	now := time.Unix(1_000, 0)
	server.now = func() time.Time { return now }
	handler := server.trafficHandler(traffic.SurfaceManagement, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	const requests = 256 * 8 // four upload operations, two proofs per operation
	accepted, rejected, slept := 0, 0, 0
	for accepted < requests {
		req := httptest.NewRequest(http.MethodPost, "/v1/service-deployment/proof", nil)
		req.Pattern = "POST /v1/service-deployment/proof"
		req.RemoteAddr = "192.0.2.10:50000" // observed peer, e.g. an ingress proxy
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("198.51.100.%d", accepted%2+1))
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		now = now.Add(2 * time.Millisecond)
		if recorder.Code == http.StatusNoContent {
			accepted++
			continue
		}
		if recorder.Code != http.StatusTooManyRequests {
			t.Fatalf("unexpected status %d", recorder.Code)
		}
		seconds, err := strconv.Atoi(recorder.Header().Get("Retry-After"))
		if err != nil || seconds < 1 || seconds > 60 {
			t.Fatalf("invalid backoff %q", recorder.Header().Get("Retry-After"))
		}
		rejected++
		slept += seconds
		now = now.Add(time.Duration(seconds) * time.Second)
	}
	if slept < 350 || rejected == 0 {
		t.Fatalf("missing reproduced bottleneck: accepted=%d rejected=%d sleep=%ds", accepted, rejected, slept)
	}
	t.Logf("proofRequests=%d http429=%d retrySleepSeconds=%d network=none", accepted, rejected, slept)
}

func TestDeploymentProofRoutesHaveIndependentAdmission(t *testing.T) {
	server := newTrafficTestServer(t, traffic.SurfaceManagement, traffic.Limit{
		RequestsPerMinute: 1, Burst: 1, ConnectionRequestsPerMinute: 1, ConnectionBurst: 1, Concurrency: 1,
	})
	seed := make([]byte, 32)
	seed[31] = 6
	signer, err := serviceauthority.NewDeploymentSigner(uuid.New(), seed)
	if err != nil {
		t.Fatal(err)
	}
	server.SetServiceAuthorityDeployment(signer, serviceauthority.NewBindingRegistry(), serviceauthority.ScopeDeviceSync)
	handler := server.Handler()
	for _, path := range []string{"/v1/service-deployment/proof", "/v1/service-deployment/bootstrap-proof"} {
		for range 2 {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}")))
			// Admission is independent; request validation still runs and rejects
			// malformed proof requests instead of producing trusted proofs.
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("proof route %s status=%d", path, recorder.Code)
			}
		}
	}
	if got := server.metrics.requests[traffic.SurfaceDeploymentProof].Load(); got != 4 {
		t.Fatalf("deployment proof requests=%d", got)
	}
	if got := server.metrics.requests[traffic.SurfaceManagement].Load(); got != 0 {
		t.Fatalf("proof requests charged to management=%d", got)
	}
}

func TestDeploymentProofBudgetServesBoundedTwoClientBulkWorkload(t *testing.T) {
	server := newTrafficTestServer(t, traffic.SurfaceDeploymentProof, traffic.DefaultLimits()[traffic.SurfaceDeploymentProof])
	now := time.Unix(1_000, 0)
	server.now = func() time.Time { return now }
	proof := server.trafficHandler(traffic.SurfaceDeploymentProof, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	management := server.trafficHandler(traffic.SurfaceManagement, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	request := func(handler http.Handler, path string) int {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		req.Pattern = "POST " + path
		req.RemoteAddr = "192.0.2.10:50000"
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		return recorder.Code
	}
	// Eight slots, three upload operations each, with fresh grant and dispatch
	// proofs: 48 proofs per bounded batch. 240ms/batch is 200 proofs/second.
	for batch := 0; batch < 256; batch++ {
		for range 2 * 4 * 3 * 2 {
			if status := request(proof, "/v1/service-deployment/proof"); status != http.StatusNoContent {
				t.Fatalf("bounded batch=%d status=%d", batch, status)
			}
		}
		if batch%10 == 0 && request(management, "/v1/administration") != http.StatusNoContent {
			t.Fatal("bulk proofs exhausted interactive administration")
		}
		now = now.Add(240 * time.Millisecond)
	}
	// A client cannot exceed the retained burst indefinitely, even when it
	// invents proxy identity headers. The observed peer controls admission.
	for attempt := 0; attempt <= traffic.DefaultLimits()[traffic.SurfaceDeploymentProof].Burst; attempt++ {
		status := request(proof, "/v1/service-deployment/proof")
		if status == http.StatusTooManyRequests {
			now = now.Add(time.Second)
			if request(proof, "/v1/service-deployment/proof") != http.StatusNoContent {
				t.Fatal("proof admission did not recover after bounded backoff")
			}
			if request(management, "/v1/administration") != http.StatusNoContent {
				t.Fatal("exhausted proof budget affected administration")
			}
			return
		}
		if status != http.StatusNoContent {
			t.Fatalf("unexpected proof status=%d", status)
		}
	}
	t.Fatal("proof flood was not bounded")
}

func TestDeploymentProofSigningConcurrencyRemainsBounded(t *testing.T) {
	limit := traffic.DefaultLimits()[traffic.SurfaceDeploymentProof]
	server := newTrafficTestServer(t, traffic.SurfaceDeploymentProof, limit)
	entered := make(chan struct{}, limit.Concurrency)
	release := make(chan struct{})
	done := make(chan struct{}, limit.Concurrency)
	handler := server.trafficHandler(traffic.SurfaceDeploymentProof, func(w http.ResponseWriter, _ *http.Request) {
		entered <- struct{}{}
		<-release
		w.WriteHeader(http.StatusNoContent)
	})
	for range limit.Concurrency {
		go func() {
			handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/proof", nil))
			done <- struct{}{}
		}()
	}
	defer func() {
		close(release)
		for range limit.Concurrency {
			<-done
		}
	}()
	for range limit.Concurrency {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("proof concurrency capacity did not fill")
		}
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/proof", nil))
	if recorder.Code != http.StatusTooManyRequests || recorder.Header().Get("Retry-After") == "" {
		t.Fatalf("unbounded proof concurrency: status=%d", recorder.Code)
	}
}

func TestCompleteTwoClientBulkProtocolFitsSeparateBoundedBudgets(t *testing.T) {
	server := newTrafficTestServer(t, traffic.SurfaceBulkGrant, traffic.DefaultLimits()[traffic.SurfaceBulkGrant])
	now := time.Unix(1_000, 0)
	server.now = func() time.Time { return now }
	handlers := map[traffic.Surface]http.Handler{}
	for _, surface := range traffic.Surfaces() {
		handlers[surface] = server.trafficHandler(surface, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	}
	request := func(surface traffic.Surface, credential string, sequence int) {
		req := httptest.NewRequest(http.MethodPost, "/protocol", nil)
		req.Pattern = "POST /protocol"
		req.RemoteAddr = "192.0.2.10:50000"
		if credential != "" {
			req.Header.Set("Authorization", "Bearer "+credential)
		}
		recorder := httptest.NewRecorder()
		handlers[surface].ServeHTTP(recorder, req)
		if recorder.Code != http.StatusNoContent {
			t.Fatalf("surface=%s sequence=%d status=%d", surface.Name(), sequence, recorder.Code)
		}
	}
	// A/B have four slots each. Each 240ms batch has 24 actual operations,
	// 24 grants and 48 proofs. Reuse each member credential deliberately:
	// capacity must not depend on inventing identities for each request.
	for batch := 0; batch < 300; batch++ {
		for client := 0; client < 2; client++ {
			credential := fmt.Sprintf("member-%d", client)
			for range 4 * 3 {
				request(traffic.SurfaceDeploymentProof, "", batch)
				request(traffic.SurfaceBulkGrant, credential, batch)
				request(traffic.SurfaceDeploymentProof, "", batch)
				request(traffic.SurfaceStorage, credential, batch)
			}
		}
		if batch%10 == 0 {
			request(traffic.SurfaceManagement, "admin", batch)
			request(traffic.SurfaceCheckpointAdmin, "checkpoint-admin", batch)
		}
		now = now.Add(240 * time.Millisecond)
	}
}

func TestTrafficPairingRoutesRemainIndependentBehindOneConnectionAddress(t *testing.T) {
	server := newTrafficTestServer(t, traffic.SurfaceRendezvous, traffic.Limit{
		RequestsPerMinute: 1, Burst: 1,
		ConnectionRequestsPerMinute: 600, ConnectionBurst: 10,
		Concurrency: 2,
	})
	handler := server.trafficHandler(traffic.SurfaceRendezvous, func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	})
	firstRoute, secondRoute := uuid.New(), uuid.New()
	request := func(routeID uuid.UUID) int {
		req := httptest.NewRequest(http.MethodGet, "/v1/pairing/routes/"+routeID.String()+"/messages", nil)
		req.Pattern = "GET /v1/pairing/routes/{routeID}/messages"
		req.SetPathValue("routeID", routeID.String())
		req.RemoteAddr = "10.0.0.8:51000"
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		return recorder.Code
	}
	if status := request(firstRoute); status != http.StatusNoContent {
		t.Fatalf("first route status=%d", status)
	}
	if status := request(secondRoute); status != http.StatusNoContent {
		t.Fatalf("second route shared the first route limit: status=%d", status)
	}
	if status := request(firstRoute); status != http.StatusTooManyRequests {
		t.Fatalf("first route identity limit status=%d", status)
	}
}

func TestTrafficConnectionBucketBoundsRandomCredentialChurn(t *testing.T) {
	server := newTrafficTestServer(t, traffic.SurfaceCheckpointAdmin, traffic.Limit{
		RequestsPerMinute: 600, Burst: 10,
		ConnectionRequestsPerMinute: 1, ConnectionBurst: 2,
		Concurrency: 2,
	})
	handler := server.trafficHandler(traffic.SurfaceCheckpointAdmin, func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	})
	for index := 0; index < 3; index++ {
		req := httptest.NewRequest(http.MethodPost, "/admin", nil)
		req.RemoteAddr = "198.51.100.9:6000"
		req.Header.Set("Authorization", fmt.Sprintf("Bearer random-%d", index))
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		expected := http.StatusNoContent
		if index == 2 {
			expected = http.StatusTooManyRequests
		}
		if recorder.Code != expected {
			t.Fatalf("request %d status=%d expected=%d", index, recorder.Code, expected)
		}
	}
	if got := server.metrics.rejections[traffic.SurfaceCheckpointAdmin][rejectionConnectionRateLimit].Load(); got != 1 {
		t.Fatalf("connection rate rejection metric=%d", got)
	}
}

func TestTrafficKeysIgnoreForwardedAddressAndRetainOnlyDigests(t *testing.T) {
	first := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	first.RemoteAddr = "[::ffff:192.0.2.4]:1234"
	first.Header.Set("X-Forwarded-For", "203.0.113.1")
	second := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	second.RemoteAddr = "192.0.2.4:9999"
	second.Header.Set("X-Forwarded-For", "203.0.113.200")
	if requestTrafficConnectionKey(first, traffic.SurfaceManagement, false) !=
		requestTrafficConnectionKey(second, traffic.SurfaceManagement, false) {
		t.Fatal("trusted connection key depended on port or forwarded address")
	}
	secret := "credential-material-that-must-not-be-retained"
	first.Header.Set("Authorization", "Bearer "+secret)
	key := requestTrafficIdentityKey(first, traffic.SurfaceManagement, false)
	if bytes.Contains(key[:], []byte(secret)) || key == (traffic.Key{}) {
		t.Fatal("traffic identity key retained raw credential material")
	}
}

func TestAuthenticatedOnionIngressUsesPrivacySafeKeysAndStripsMarker(t *testing.T) {
	server := New(nil, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	token := bytes.Repeat([]byte{0x63}, 32)
	if err := server.SetOnionIngressToken(token); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/pairing/routes/example/messages", nil)
	request.Pattern = "GET /v1/pairing/routes/{routeID}/messages"
	request.RemoteAddr = "172.30.0.2:1234"
	request.Header.Set(headerIngressTransport, ingressTransportOnion)
	request.Header.Set(headerOnionIngressToken, base64.RawURLEncoding.EncodeToString(token))
	if !server.consumeOnionIngressMarker(request) {
		t.Fatal("valid onion ingress marker rejected")
	}
	if request.Header.Get(headerIngressTransport) != "" ||
		request.Header.Get(headerOnionIngressToken) != "" {
		t.Fatal("private onion ingress headers reached the application handler")
	}
	first := requestTrafficConnectionKey(request, traffic.SurfaceRendezvous, true)
	request.RemoteAddr = "198.51.100.40:9000"
	second := requestTrafficConnectionKey(request, traffic.SurfaceRendezvous, true)
	if first != second {
		t.Fatal("onion connection bucket retained a connection address")
	}
	if first == requestTrafficConnectionKey(request, traffic.SurfaceStorage, true) {
		t.Fatal("onion connection budget was not isolated by traffic surface")
	}
}

func TestSpoofedOnionMarkerDoesNotChangeDirectTrafficIdentity(t *testing.T) {
	server := New(nil, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	token := bytes.Repeat([]byte{0x63}, 32)
	if err := server.SetOnionIngressToken(token); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/pairing/routes", nil)
	request.RemoteAddr = "192.0.2.9:5000"
	request.Header.Set(headerIngressTransport, ingressTransportOnion)
	request.Header.Set(
		headerOnionIngressToken,
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x64}, 32)),
	)
	if server.consumeOnionIngressMarker(request) {
		t.Fatal("spoofed onion ingress marker accepted")
	}
	if request.Header.Get(headerIngressTransport) != "" ||
		request.Header.Get(headerOnionIngressToken) != "" {
		t.Fatal("spoofed private ingress headers were not stripped")
	}
}

func TestTrafficConcurrencyReleasesAfterCancellationAndPanic(t *testing.T) {
	server := newTrafficTestServer(t, traffic.SurfaceStorage, traffic.Limit{
		RequestsPerMinute: 600, Burst: 20,
		ConnectionRequestsPerMinute: 600, ConnectionBurst: 20,
		Concurrency: 1,
	})
	started := make(chan struct{})
	blocked := server.trafficHandler(traffic.SurfaceStorage, func(_ http.ResponseWriter, request *http.Request) {
		close(started)
		<-request.Context().Done()
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		req := httptest.NewRequest(http.MethodGet, "/blob", nil).WithContext(ctx)
		req.RemoteAddr = "192.0.2.20:1"
		req.Header.Set("Authorization", "Bearer cancellation")
		blocked.ServeHTTP(httptest.NewRecorder(), req)
	}()
	<-started
	rejected := httptest.NewRecorder()
	rejectedRequest := httptest.NewRequest(http.MethodGet, "/blob", nil)
	rejectedRequest.RemoteAddr = "192.0.2.21:1"
	rejectedRequest.Header.Set("Authorization", "Bearer concurrent")
	blocked.ServeHTTP(rejected, rejectedRequest)
	if rejected.Code != http.StatusTooManyRequests || rejected.Header().Get("Retry-After") != "1" {
		t.Fatalf("concurrency rejection status=%d retry=%q", rejected.Code, rejected.Header().Get("Retry-After"))
	}
	if got := server.metrics.rejections[traffic.SurfaceStorage][rejectionConcurrencyLimit].Load(); got != 1 {
		t.Fatalf("concurrency rejection metric=%d", got)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("canceled handler did not release")
	}

	panicking := server.trafficHandler(traffic.SurfaceStorage, func(http.ResponseWriter, *http.Request) {
		panic("expected panic")
	})
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("handler panic did not propagate")
			}
		}()
		req := httptest.NewRequest(http.MethodGet, "/blob", nil)
		req.RemoteAddr = "192.0.2.22:1"
		req.Header.Set("Authorization", "Bearer panic")
		panicking.ServeHTTP(httptest.NewRecorder(), req)
	}()
	normal := server.trafficHandler(traffic.SurfaceStorage, func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	})
	req := httptest.NewRequest(http.MethodGet, "/blob", nil)
	req.RemoteAddr = "192.0.2.23:1"
	req.Header.Set("Authorization", "Bearer after-panic")
	recorder := httptest.NewRecorder()
	normal.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("panic leaked concurrency permit: status=%d", recorder.Code)
	}
	if got := server.metrics.rejections[traffic.SurfaceStorage][rejectionInternal].Load(); got != 1 {
		t.Fatalf("panic rejection metric=%d", got)
	}
}

func TestTrafficLogsDoNotContainCredentialAddressOrDigest(t *testing.T) {
	var logs bytes.Buffer
	server := New(nil, slog.New(slog.NewJSONHandler(&logs, nil)))
	limits := traffic.DefaultLimits()
	limits[traffic.SurfaceManagement] = traffic.Limit{
		RequestsPerMinute: 1, Burst: 1,
		ConnectionRequestsPerMinute: 1, ConnectionBurst: 1,
		Concurrency: 1,
	}
	if err := server.SetTrafficLimits(limits); err != nil {
		t.Fatal(err)
	}
	handler := server.securityHeaders(server.requestLog(server.trafficHandler(
		traffic.SurfaceManagement,
		func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusNoContent) },
	)))
	secret := "private-rate-limit-secret"
	address := "192.0.2.99"
	var digest = sha256.Sum256([]byte("facets-server-traffic-credential-v1\x00" + secret))
	for range 2 {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		req.Pattern = "GET /metrics"
		req.RemoteAddr = address + ":1234"
		req.Header.Set("Authorization", "Bearer "+secret)
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}
	for _, protected := range []string{secret, address, fmt.Sprintf("%x", digest)} {
		if strings.Contains(logs.String(), protected) {
			t.Fatalf("traffic log contained protected key material %q: %s", protected, logs.String())
		}
	}
}

func newTrafficTestServer(
	t *testing.T,
	surface traffic.Surface,
	limit traffic.Limit,
) *Server {
	t.Helper()
	server := New(nil, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	limits := traffic.DefaultLimits()
	limits[surface] = limit
	if err := server.SetTrafficLimits(limits); err != nil {
		t.Fatal(err)
	}
	return server
}
