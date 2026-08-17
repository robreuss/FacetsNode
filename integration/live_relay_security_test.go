package integration_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/relay"
)

// TestLiveRelayDelegationAndDurableWakeFallback crosses the HTTP and real
// PostgreSQL boundaries. The message is published before the wake request, so
// no process-local signal can wake the subscriber; the endpoint must discover
// the durable message through its authoritative cursor check.
func TestLiveRelayDelegationAndDurableWakeFallback(t *testing.T) {
	baseURL := strings.TrimRight(os.Getenv("FACETS_NODE_TEST_BASE_URL"), "/")
	operatorToken := os.Getenv("FACETS_NODE_TEST_OPERATOR_TOKEN")
	if baseURL == "" || operatorToken == "" {
		t.Skip("FACETS_NODE_TEST_BASE_URL and FACETS_NODE_TEST_OPERATOR_TOKEN are required")
	}
	client := &http.Client{Timeout: 15 * time.Second}
	parent := provisionLiveRelayDomain(t, client, baseURL, operatorToken)
	parentPath := fmt.Sprintf(
		"%s/v1/relay/tenants/%s/domains/%s",
		baseURL,
		parent.Domain.TenantID,
		parent.Domain.DomainID,
	)

	childRequest := newLiveRelayDomainProvisioningRequest(time.Now().UnixMilli())
	childRequest.AdministrationCredential.TenantID = parent.Domain.TenantID
	childRequest.AdministrationCredential.AuthorizationToken = encodedBytes(33)
	childRequest.MemberCredential.TenantID = parent.Domain.TenantID
	childRequest.MemberCredential.AuthorizationToken = encodedBytes(65)
	delegatedURL := parentPath + "/delegated-domains"
	delegated := requestRelayJSON(
		t,
		client,
		http.MethodPost,
		delegatedURL,
		childRequest,
		parent.AdministrationCredential.AuthorizationToken,
		uuid.Nil,
	)
	requireStatus(t, delegated, http.StatusCreated)
	var child liveRelayDomain
	if err := json.NewDecoder(delegated.Body).Decode(&child); err != nil {
		t.Fatal(err)
	}
	_ = delegated.Body.Close()
	if child.Domain.TenantID != parent.Domain.TenantID ||
		child.Domain.DomainID != childRequest.AdministrationCredential.DomainID {
		t.Fatalf("delegated domain scope=%s/%s", child.Domain.TenantID, child.Domain.DomainID)
	}
	requireStatusAndClose(t, requestRelayJSON(
		t,
		client,
		http.MethodPost,
		delegatedURL,
		childRequest,
		parent.AdministrationCredential.AuthorizationToken,
		uuid.Nil,
	), http.StatusOK)

	childPath := fmt.Sprintf(
		"%s/v1/relay/tenants/%s/domains/%s",
		baseURL,
		child.Domain.TenantID,
		child.Domain.DomainID,
	)
	recipient := admitLiveRelayRecipient(t, client, childPath, child, 97, 129)
	publisher := relay.Credential{
		TenantID: child.Domain.TenantID,
		DomainID: child.Domain.DomainID,
		MemberID: child.Member.MemberID,
		Token:    child.MemberCredential.AuthorizationToken,
	}
	envelope := liveRelayEnvelope(child, 1, time.Now().UnixMilli()-1_000)
	requireLiveRelayPublish(
		t, client, childPath, publisher, envelope, http.StatusCreated,
	)

	wake := requestRelayJSON(
		t,
		client,
		http.MethodGet,
		childPath+"/messages/wake?waitMilliseconds=1000",
		nil,
		recipient.Credential.Token,
		recipient.Credential.MemberID,
	)
	requireStatus(t, wake, http.StatusOK)
	var wakeResult struct {
		Changed bool `json:"changed"`
	}
	if err := json.NewDecoder(wake.Body).Decode(&wakeResult); err != nil {
		t.Fatal(err)
	}
	_ = wake.Body.Close()
	if !wakeResult.Changed {
		t.Fatal("durable wake fallback did not report the pre-existing message")
	}
}
