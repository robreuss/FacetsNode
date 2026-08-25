package httpapi

import (
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

func TestServiceAuthorityPathScopeUsesProductPrincipal(t *testing.T) {
	principalID := uuid.New()
	spaceID := uuid.New()
	request := httptest.NewRequest("POST", "/", nil)
	request.SetPathValue("principalID", principalID.String())
	request.SetPathValue("spaceID", spaceID.String())

	if err := requestScopeMatchesBinding(request, serviceauthority.Scope{
		Kind: serviceauthority.ScopeDeviceSync, ScopeID: principalID,
	}); err != nil {
		t.Fatalf("Device Sync nested Space was not bound to its principal: %v", err)
	}

	request.SetPathValue("principalID", uuid.NewString())
	if err := requestScopeMatchesBinding(request, serviceauthority.Scope{
		Kind: serviceauthority.ScopeDeviceSync, ScopeID: principalID,
	}); err == nil {
		t.Fatal("Device Sync accepted another principal")
	}
}

func TestServiceAuthorityPathScopeUsesSharedSpaceForControlAndRelay(t *testing.T) {
	spaceID := uuid.New()
	control := httptest.NewRequest("GET", "/", nil)
	control.SetPathValue("spaceID", spaceID.String())
	if err := requestScopeMatchesBinding(control, serviceauthority.Scope{
		Kind: serviceauthority.ScopeSharedSpace, ScopeID: spaceID,
	}); err != nil {
		t.Fatalf("Shared Space control path rejected: %v", err)
	}

	relay := httptest.NewRequest("GET", "/", nil)
	relay.SetPathValue("tenantID", spaceID.String())
	if err := requestScopeMatchesBinding(relay, serviceauthority.Scope{
		Kind: serviceauthority.ScopeSharedSpace, ScopeID: spaceID,
	}); err != nil {
		t.Fatalf("Shared Space relay tenant rejected: %v", err)
	}

	relay.SetPathValue("tenantID", uuid.NewString())
	if err := requestScopeMatchesBinding(relay, serviceauthority.Scope{
		Kind: serviceauthority.ScopeSharedSpace, ScopeID: spaceID,
	}); err == nil {
		t.Fatal("Shared Space accepted another relay tenant")
	}
}
