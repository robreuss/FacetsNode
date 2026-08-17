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

const dataPlaneFixtureSHA256 = "15ed50e43d159f41b750d5f2a48afc20135d4c64be0f83266b577df22c802537"

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
		CheckpointFenceRequest            relay.CheckpointFenceRequest            `json:"checkpointFenceRequest"`
		CheckpointFenceResponse           relay.CheckpointFenceResponse           `json:"checkpointFenceResponse"`
		CheckpointFenceState              relay.CheckpointFenceState              `json:"checkpointFenceState"`
		CheckpointFenceAbortRequest       relay.CheckpointFenceAbortRequest       `json:"checkpointFenceAbortRequest"`
		CheckpointFenceAbortResponse      relay.CheckpointFenceAbortResponse      `json:"checkpointFenceAbortResponse"`
		CheckpointCandidate               relay.CheckpointCandidate               `json:"checkpointCandidate"`
		ActivationRequest                 relay.CheckpointActivationRequest       `json:"activationRequest"`
		CheckpointStageResponse           relay.CheckpointStageResponse           `json:"checkpointStageResponse"`
		CheckpointActivationResponse      relay.CheckpointActivationResponse      `json:"checkpointActivationResponse"`
		DryRunResponse                    relay.CheckpointDryRunResponse          `json:"dryRunResponse"`
		CollectionRequest                 relay.CheckpointCollectionRequest       `json:"collectionRequest"`
		CollectionResponse                relay.CheckpointCollectionResponse      `json:"collectionResponse"`
		DomainStatus                      relay.DomainStatus                      `json:"domainStatus"`
		TenantStatus                      relay.TenantStatus                      `json:"tenantStatus"`
		UploadRequest                     relay.BlobUploadRequest                 `json:"uploadRequest"`
		UploadCreateResponse              relay.BlobUploadCreateResponse          `json:"uploadCreateResponse"`
		UploadChunkRequest                relay.BlobUploadChunkRequest            `json:"uploadChunkRequest"`
		UploadStatus                      relay.BlobUploadStatus                  `json:"uploadStatus"`
		FullUnfinalizedUploadStatus       relay.BlobUploadStatus                  `json:"fullUnfinalizedUploadStatus"`
		ZeroByteUnfinalizedUploadStatus   relay.BlobUploadStatus                  `json:"zeroByteUnfinalizedUploadStatus"`
		UploadFinalizationRequest         relay.BlobUploadFinalizationRequest     `json:"uploadFinalizationRequest"`
		UploadFinalizationResponse        relay.BlobUploadFinalizationResponse    `json:"uploadFinalizationResponse"`
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
		"checkpoint fence request":     fixture.CheckpointFenceRequest.Validate,
		"checkpoint fence state":       fixture.CheckpointFenceState.Validate,
		"checkpoint fence abort":       fixture.CheckpointFenceAbortRequest.Validate,
		"checkpoint candidate":         fixture.CheckpointCandidate.Validate,
		"checkpoint activation":        fixture.ActivationRequest.Validate,
		"checkpoint collection":        fixture.CollectionRequest.Validate,
		"admission":                    fixture.AdmissionCreateResponse.Admission.Admission.Validate,
		"member":                       fixture.AdmissionClaimResponse.Member.MemberRegistration.Validate,
		"upload request":               fixture.UploadRequest.Validate,
		"upload chunk":                 fixture.UploadChunkRequest.Validate,
		"upload status":                fixture.UploadStatus.Validate,
		"full unfinalized upload":      fixture.FullUnfinalizedUploadStatus.Validate,
		"zero byte unfinalized upload": fixture.ZeroByteUnfinalizedUploadStatus.Validate,
		"upload finalization":          fixture.UploadFinalizationRequest.Validate,
	} {
		if err := validate(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if fixture.UploadCreateResponse.RetryID != fixture.UploadRequest.RetryID ||
		fixture.UploadCreateResponse.Status.UploadID != fixture.UploadRequest.UploadID ||
		fixture.UploadFinalizationResponse.RetryID != fixture.UploadFinalizationRequest.RetryID ||
		fixture.UploadFinalizationResponse.UploadID != fixture.UploadFinalizationRequest.UploadID ||
		fixture.UploadFinalizationResponse.RelayBlobID != fixture.UploadFinalizationRequest.RelayBlobID ||
		fixture.UploadFinalizationResponse.ByteCount != fixture.UploadFinalizationRequest.ByteCount {
		t.Fatal("upload fixture responses are not bound to their exact requests")
	}
	if fixture.CheckpointStageResponse.CheckpointID != fixture.CheckpointCandidate.CheckpointID ||
		fixture.CheckpointCandidate.FenceID != fixture.CheckpointFenceRequest.FenceID ||
		fixture.CheckpointFenceResponse.FenceID != fixture.CheckpointFenceRequest.FenceID ||
		fixture.CheckpointFenceAbortResponse.FenceID != fixture.CheckpointFenceAbortRequest.FenceID ||
		fixture.CheckpointActivationResponse.CheckpointID != fixture.CheckpointCandidate.CheckpointID ||
		fixture.DryRunResponse.CheckpointID != fixture.CheckpointCandidate.CheckpointID ||
		fixture.CollectionResponse.PlanDigest != fixture.CollectionRequest.PlanDigest {
		t.Fatal("checkpoint fixture operations are not bound to one exact checkpoint plan")
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
