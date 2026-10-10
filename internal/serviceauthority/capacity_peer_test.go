package serviceauthority

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/storagecapacity"
)

type capacityPeerFixture struct {
	signer   *DeploymentSigner
	identity CapacityPeerIdentity
	request  CapacityPeerRequest
	body     []byte
	now      time.Time
}

func newCapacityPeerFixture(t *testing.T, kind storagecapacity.ServiceKind, operation CapacityPeerOperation) capacityPeerFixture {
	t.Helper()
	deploymentID := uuid.New()
	seed := make([]byte, 32)
	seed[31] = 7
	signer, err := NewDeploymentSigner(deploymentID, seed)
	if err != nil {
		t.Fatal(err)
	}
	service := storagecapacity.ServiceBinding{Kind: kind, InstanceID: deploymentID}
	identity := CapacityPeerIdentity{Service: service, PublicSigningKeyX963: signer.PublicSigningKeyX963(), SigningKeyFingerprint: signer.SigningKeyFingerprint(), Version: SchemaVersion}
	body := []byte(`{"protocolVersion":1,"opaque":"request"}`)
	request, err := NewCapacityPeerRequest(operation, uuid.New(), uuid.New(), body)
	if err != nil {
		t.Fatal(err)
	}
	return capacityPeerFixture{signer: signer, identity: identity, request: request, body: body, now: time.UnixMilli(10_000)}
}

func (fixture capacityPeerFixture) sign(t *testing.T) CapacityPeerProof {
	t.Helper()
	proof, err := fixture.signer.SignCapacityPeerRequestAt(fixture.identity.Service, fixture.request, fixture.body, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func TestCapacityPeerAuthenticatesEveryContentBlindServiceKind(t *testing.T) {
	kinds := []storagecapacity.ServiceKind{
		storagecapacity.ServiceJobCustody,
		storagecapacity.ServiceBackupCustody,
		storagecapacity.ServiceDeviceSync,
		storagecapacity.ServiceSharedSpaces,
		storagecapacity.ServiceComputePool,
	}
	operations := []CapacityPeerOperation{CapacityReserve, CapacityRecheck, CapacityDecide, CapacityRead, CapacityReadiness}
	for _, kind := range kinds {
		for _, operation := range operations {
			t.Run(string(kind)+"/"+string(operation), func(t *testing.T) {
				fixture := newCapacityPeerFixture(t, kind, operation)
				verified, err := VerifyCapacityPeerRequestAt(fixture.identity, fixture.sign(t), fixture.request, fixture.body, fixture.now)
				if err != nil || verified.Service() != fixture.identity.Service || verified.Request() != fixture.request {
					t.Fatalf("verify: %v", err)
				}
				if _, err := json.Marshal(verified); err == nil {
					t.Fatal("verified identity became a serializable bearer")
				}
				if strings.Contains(fmt.Sprintf("%#v", verified), fixture.identity.Service.InstanceID.String()) {
					t.Fatal("service identity leaked through defensive formatting")
				}
			})
		}
	}
}

func TestCapacityPeerRejectsRequestBodyServiceAndKeySubstitution(t *testing.T) {
	fixture := newCapacityPeerFixture(t, storagecapacity.ServiceJobCustody, CapacityReserve)
	proof := fixture.sign(t)
	for _, field := range []string{"body", "length", "digest", "operation", "operationID", "pool", "version"} {
		t.Run(field, func(t *testing.T) {
			request := fixture.request
			body := fixture.body
			switch field {
			case "body":
				body = bytes.Repeat([]byte{'x'}, len(body))
			case "length":
				request.BodyByteCount++
			case "digest":
				request.BodySHA256 = strings.Repeat("1", 64)
			case "operation":
				request.Operation = CapacityDecide
			case "operationID":
				request.OperationID = uuid.New()
			case "pool":
				request.PoolID = uuid.New()
			case "version":
				request.Version++
			}
			if _, err := VerifyCapacityPeerRequestAt(fixture.identity, proof, request, body, fixture.now); err == nil {
				t.Fatal("substitution accepted")
			}
		})
	}

	otherService := fixture.identity
	otherService.Service.InstanceID = uuid.New()
	if _, err := VerifyCapacityPeerRequestAt(otherService, proof, fixture.request, fixture.body, fixture.now); err == nil {
		t.Fatal("service instance substitution accepted")
	}
	otherService = fixture.identity
	otherService.Service.Kind = storagecapacity.ServiceBackupCustody
	if _, err := VerifyCapacityPeerRequestAt(otherService, proof, fixture.request, fixture.body, fixture.now); err == nil {
		t.Fatal("service kind substitution accepted")
	}

	seed := make([]byte, 32)
	seed[31] = 8
	otherSigner, err := NewDeploymentSigner(fixture.identity.Service.InstanceID, seed)
	if err != nil {
		t.Fatal(err)
	}
	otherIdentity := fixture.identity
	otherIdentity.PublicSigningKeyX963 = otherSigner.PublicSigningKeyX963()
	otherIdentity.SigningKeyFingerprint = otherSigner.SigningKeyFingerprint()
	if _, err := VerifyCapacityPeerRequestAt(otherIdentity, proof, fixture.request, fixture.body, fixture.now); err == nil {
		t.Fatal("unprovisioned key accepted under matching deployment UUID")
	}
}

func TestCapacityPeerProofIsShortLivedAndSignerIsExactDeployment(t *testing.T) {
	fixture := newCapacityPeerFixture(t, storagecapacity.ServiceBackupCustody, CapacityDecide)
	proof := fixture.sign(t)
	if _, err := VerifyCapacityPeerRequestAt(fixture.identity, proof, fixture.request, fixture.body, fixture.now.Add(-time.Millisecond)); err == nil {
		t.Fatal("proof accepted before issue")
	}
	if _, err := VerifyCapacityPeerRequestAt(fixture.identity, proof, fixture.request, fixture.body, fixture.now.Add(CapacityPeerProofLifetime)); err == nil {
		t.Fatal("expired proof accepted")
	}
	service := fixture.identity.Service
	service.InstanceID = uuid.New()
	if _, err := fixture.signer.SignCapacityPeerRequestAt(service, fixture.request, fixture.body, fixture.now); err == nil {
		t.Fatal("signer signed for a different service instance")
	}
	if _, err := fixture.signer.SignCapacityPeerRequestAt(fixture.identity.Service, fixture.request, append([]byte(nil), fixture.body[:len(fixture.body)-1]...), fixture.now); err == nil {
		t.Fatal("signer accepted mismatched body")
	}
	if _, err := fixture.signer.SignCapacityPeerRequestAt(fixture.identity.Service, fixture.request, fixture.body, time.UnixMilli(1<<63-1)); err == nil {
		t.Fatal("proof expiration overflow accepted")
	}
	for _, operation := range []CapacityPeerOperation{"", "owner_readiness", "delete", "admin", "worker"} {
		request := fixture.request
		request.Operation = operation
		if _, err := fixture.signer.SignCapacityPeerRequestAt(fixture.identity.Service, request, fixture.body, fixture.now); err == nil {
			t.Fatal("unsupported operation signed")
		}
	}
}

func TestCapacityPeerRejectsNonCanonicalOrOversizeProofsAndBodies(t *testing.T) {
	fixture := newCapacityPeerFixture(t, storagecapacity.ServiceSharedSpaces, CapacityReadiness)
	proof := fixture.sign(t)
	proof.Payload = append(proof.Payload, ' ')
	if _, err := VerifyCapacityPeerRequestAt(fixture.identity, proof, fixture.request, fixture.body, fixture.now); err == nil {
		t.Fatal("noncanonical proof accepted")
	}
	tooLarge := make([]byte, MaximumCapacityPeerBodyBytes+1)
	if _, err := NewCapacityPeerRequest(CapacityReserve, uuid.New(), uuid.New(), tooLarge); err == nil {
		t.Fatal("oversize body accepted")
	}
	identity := fixture.identity
	identity.PublicSigningKeyX963 += "A"
	if identity.Validate() == nil {
		t.Fatal("noncanonical key accepted")
	}
}
