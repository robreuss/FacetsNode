package serverapp

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/robreuss/FacetsNode/internal/config"
)

func TestStorageCapacityAuthorityHealthIsCoarseAndPrivateRoutesAreForwarded(t *testing.T) {
	private := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/readiness/query" {
			t.Fatal("wrong private route")
		}
		writer.WriteHeader(http.StatusTeapot)
	})
	handler := storageCapacityAuthorityHealthHandler(nil, private)
	for path, status := range map[string]int{
		"/livez":              http.StatusOK,
		"/readyz":             http.StatusServiceUnavailable,
		"/v1/readiness/query": http.StatusTeapot,
	} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != status {
			t.Fatalf("%s status=%d", path, response.Code)
		}
		if path == "/readyz" && response.Body.String() != "{\"status\":\"unavailable\"}\n" {
			t.Fatalf("detailed readiness leaked: %s", response.Body.String())
		}
	}
}

func TestStorageCapacityAuthorityHTTPServerUsesTightPrivateTimeouts(t *testing.T) {
	server := newStorageCapacityAuthorityHTTPServer(config.Config{ListenAddress: "127.0.0.1:9000"}, http.NotFoundHandler())
	if server.Addr != "127.0.0.1:9000" || server.ReadHeaderTimeout != 5*time.Second ||
		server.ReadTimeout != 15*time.Second || server.WriteTimeout != 15*time.Second ||
		server.IdleTimeout != 30*time.Second || server.MaxHeaderBytes != 8*1024 {
		t.Fatalf("unexpected server policy: %+v", server)
	}
}
