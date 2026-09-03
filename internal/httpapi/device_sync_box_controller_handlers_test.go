package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/devicesync"
	"github.com/robreuss/FacetsNode/internal/relay"
)

func TestBoxControllerAuthorityIsPrivateAndNarrow(t *testing.T) {
	server := newDeviceSyncTestServer(t, relay.NewMemoryStore(), relayTestToken(242), 1_000)
	token := make([]byte, 32)
	for index := range token {
		token[index] = byte(index + 1)
	}
	issueCount := 0
	server.SetDeviceSyncBoxControllerAuthority(token, func(_ context.Context, _ time.Duration, _ time.Time) (devicesync.IssuedAccountBootstrap, error) {
		issueCount++
		return devicesync.IssuedAccountBootstrap{Bootstrap: devicesync.AccountBootstrap{Version: devicesync.SchemaVersion, AdmissionID: uuid.New()}}, nil
	})
	handler := server.Handler()

	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodPost, "/internal/box-controller/device-sync/account-admissions", nil))
	if unauthorized.Code != http.StatusNotFound {
		t.Fatalf("unauthorized status %d", unauthorized.Code)
	}

	authorizedRequest := httptest.NewRequest(http.MethodPost, "/internal/box-controller/device-sync/account-admissions", nil)
	authorizedRequest.Header.Set("Authorization", "Bearer "+base64.RawURLEncoding.EncodeToString(token))
	authorized := httptest.NewRecorder()
	handler.ServeHTTP(authorized, authorizedRequest)
	if authorized.Code != http.StatusCreated || issueCount != 1 {
		t.Fatalf("authorized status=%d issues=%d body=%s", authorized.Code, issueCount, authorized.Body.String())
	}
	var response struct {
		Bootstrap json.RawMessage `json:"bootstrap"`
	}
	if err := json.Unmarshal(authorized.Body.Bytes(), &response); err != nil || len(response.Bootstrap) == 0 {
		t.Fatalf("bootstrap response invalid: %v", err)
	}

	groupsRequest := httptest.NewRequest(http.MethodGet, "/internal/box-controller/device-sync/groups", nil)
	groupsRequest.Header.Set("Authorization", "Bearer "+base64.RawURLEncoding.EncodeToString(token))
	groups := httptest.NewRecorder()
	handler.ServeHTTP(groups, groupsRequest)
	if groups.Code != http.StatusOK || groups.Body.String() != "{\"groups\":[]}\n" {
		t.Fatalf("groups status=%d body=%s", groups.Code, groups.Body.String())
	}
}
