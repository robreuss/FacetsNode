package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/relay"
)

func TestFacetsBoxManifestPublishesDeviceSyncServiceFromOneURL(t *testing.T) {
	server := newDeviceSyncTestServer(t, relay.NewMemoryStore(), relayTestToken(241), 1_000)
	server.serviceIdentity = "facets-device-sync-server"
	server.publicURL = "https://box.example/facetsbox/devicesync"
	server.boxID = uuid.MustParse("11111111-1111-4111-8111-111111111111")
	server.SetFacetsBoxServiceEndpoints(map[string]string{
		"device-sync":   server.publicURL,
		"shared-spaces": "https://box.example/facetsbox/shared-spaces",
	})

	request := httptest.NewRequest(http.MethodGet, "/.well-known/facets-box", nil)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var manifest facetsBoxManifest
	if err := json.Unmarshal(response.Body.Bytes(), &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Version != 1 || manifest.BoxID != server.boxID ||
		len(manifest.Services) != 2 ||
		manifest.Services[0].Kind != "device-sync" ||
		manifest.Services[0].Endpoint != server.publicURL ||
		manifest.Services[1].Kind != "shared-spaces" {
		t.Fatalf("unexpected manifest: %+v", manifest)
	}
}
