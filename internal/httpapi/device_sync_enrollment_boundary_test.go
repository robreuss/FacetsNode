package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

func TestDeviceSyncGenericEnrollmentCannotBypassSponsorChecks(t *testing.T) {
	server := &Server{serviceAuthorityScopeKind: serviceauthority.ScopeDeviceSync}
	for name, handler := range map[string]http.HandlerFunc{
		"register member":  server.handleCreateRelayMember,
		"create admission": server.handleCreateRelayAdmission,
		"claim admission":  server.handleClaimRelayAdmission,
	} {
		t.Run(name, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler(response, httptest.NewRequest(http.MethodPost, "/", nil))
			if response.Code < 400 || !strings.Contains(response.Body.String(), "device_sync_wrong_scope") {
				t.Fatalf("generic enrollment reached a store: %d %s", response.Code, response.Body.String())
			}
		})
	}
	for _, kind := range []serviceauthority.ScopeKind{"", serviceauthority.ScopeSharedSpace} {
		if (&Server{serviceAuthorityScopeKind: kind}).rejectGenericDeviceSyncEnrollment(httptest.NewRecorder()) {
			t.Fatal("unrelated service enrollment disabled")
		}
	}
}
