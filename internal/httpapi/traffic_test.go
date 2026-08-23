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
	handler := server.Handler()
	tenantID, domainID := uuid.New(), uuid.New()
	requests := []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: "/livez"},
		{method: http.MethodPost, path: "/v1/relay/tenants"},
		{method: http.MethodPost, path: "/v1/pairing/routes"},
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
	}
	for surface, count := range expected {
		if got := server.metrics.requests[surface].Load(); got != count {
			t.Fatalf("surface %s requests=%d expected=%d", surface.Name(), got, count)
		}
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
