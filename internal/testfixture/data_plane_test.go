package testfixture_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/relay"
)

const dataPlaneFixtureSHA256 = "d81b42bc95b1e7adda3ef2ff6c5dbaa471512787481c9fe8b42a563e4b07293f"

func TestReplicaRelayDataPlaneFixtureIsExactFrozenSwiftContract(t *testing.T) {
	path := filepath.Join("replica-relay-data-plane-portable-v1.json")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(contents)
	if actual := hex.EncodeToString(digest[:]); actual != dataPlaneFixtureSHA256 {
		t.Fatalf("fixture SHA-256=%s; want %s", actual, dataPlaneFixtureSHA256)
	}
	var fixture struct {
		Format                            string                                  `json:"format"`
		TenantCredential                  tenantCredential                        `json:"tenantCredential"`
		ExpectedTenantAuthorizationDigest string                                  `json:"expectedTenantAuthorizationDigest"`
		TenantProvisioningResponse        relay.TenantProvisioningResult          `json:"tenantProvisioningResponse"`
		AdmissionCreateResponse           relay.SubscriptionAdmissionCreateResult `json:"admissionCreateResponse"`
		AdmissionClaimResponse            relay.SubscriptionAdmissionClaimResult  `json:"admissionClaimResponse"`
		Subscription                      relay.Subscription                      `json:"subscription"`
		SubscriptionCreateRequest         relay.SubscriptionCreateRequest         `json:"subscriptionCreateRequest"`
		SubscriptionCreateResponse        relay.SubscriptionCreateResponse        `json:"subscriptionCreateResponse"`
		SubscriptionStatusChangeRequest   relay.SubscriptionStatusChangeRequest   `json:"subscriptionStatusChangeRequest"`
		SubscriptionStatusChangeResponse  relay.SubscriptionStatusChangeResponse  `json:"subscriptionStatusChangeResponse"`
		DomainStatus                      relay.DomainStatus                      `json:"domainStatus"`
		TenantStatus                      relay.TenantStatus                      `json:"tenantStatus"`
	}
	if err := json.Unmarshal(contents, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Format != "facets.replica-relay-data-plane-fixture.v1" {
		t.Fatalf("format=%q", fixture.Format)
	}
	tenantID, err := uuid.Parse(fixture.TenantCredential.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	actualTenantDigest, err := relay.TenantAuthorizationDigest(relay.TenantCredential{
		TenantID: tenantID,
		Token:    fixture.TenantCredential.AuthorizationToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	if actualTenantDigest != fixture.ExpectedTenantAuthorizationDigest ||
		actualTenantDigest != fixture.TenantProvisioningResponse.TenantProvisioningAuthorizationDigest {
		t.Fatalf("tenant digest=%s expected=%s", actualTenantDigest, fixture.ExpectedTenantAuthorizationDigest)
	}
	for name, validate := range map[string]func() error{
		"subscription":                 fixture.Subscription.Validate,
		"subscription create request":  fixture.SubscriptionCreateRequest.Validate,
		"subscription create response": fixture.SubscriptionCreateResponse.Subscription.Validate,
		"subscription status request":  fixture.SubscriptionStatusChangeRequest.Validate,
		"subscription status response": fixture.SubscriptionStatusChangeResponse.Subscription.Validate,
		"admission":                    fixture.AdmissionCreateResponse.Admission.Admission.Validate,
		"member":                       fixture.AdmissionClaimResponse.Member.MemberRegistration.Validate,
	} {
		if err := validate(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if fixture.DomainStatus.ReservedBlobCount != 2 ||
		fixture.DomainStatus.ReservedBlobByteCount != 12_288 ||
		fixture.TenantStatus.ReservedBlobCount != 3 ||
		fixture.TenantStatus.ReservedBlobByteCount != 16_384 {
		t.Fatalf("reserved upload quota fields did not decode")
	}
	lockContents, err := os.ReadFile("replica-relay-data-plane-contract.lock.json")
	if err != nil {
		t.Fatal(err)
	}
	var lock struct {
		Format                     string `json:"format"`
		FixtureSHA256              string `json:"fixtureSHA256"`
		RelayEnvelopeSchemaVersion int    `json:"relayEnvelopeSchemaVersion"`
	}
	if err := json.Unmarshal(lockContents, &lock); err != nil {
		t.Fatal(err)
	}
	if lock.Format != "facets.replica-relay-data-plane-contract-lock.v1" ||
		lock.FixtureSHA256 != dataPlaneFixtureSHA256 ||
		lock.RelayEnvelopeSchemaVersion != relay.SchemaVersion {
		t.Fatalf("contract lock does not bind fixture and Envelope V1: %+v", lock)
	}
}

type tenantCredential struct {
	TenantID           string `json:"tenantID"`
	AuthorizationToken string `json:"authorizationToken"`
}
