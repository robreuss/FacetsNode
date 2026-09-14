package serviceauthority

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/objectcustodywire"
)

type custodyPeerFixture struct {
	bootstrap        bootstrapFixture
	sender, receiver *BindingRegistry
	binding          RequestBinding
	request          CustodyPeerRequest
	body             []byte
	now              time.Time
}

func newCustodyPeerFixture(t *testing.T, kind ScopeKind, operation CustodyPeerOperation) custodyPeerFixture {
	t.Helper()
	f := newBootstrapFixture(t)
	f.scope.Kind, f.anchor.Scope.Kind = kind, kind
	manifest := f.signedManifest(t, f.policy)
	digest, err := manifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	newRegistry := func() *BindingRegistry {
		path := filepath.Join(t.TempDir(), "bindings.json")
		data, err := json.Marshal(BindingFile{Bindings: []BindingFileEntry{{DeploymentID: f.descriptor.DeploymentID, Digest: digest, Manifest: &manifest, Revision: 1, Scope: f.scope}}, Version: SchemaVersion})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		registry, err := LoadBindingRegistry(path, f.descriptor.DeploymentID)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = registry.Close() })
		return registry
	}
	body := []byte("opaque-request-fixture")
	hash := sha256.Sum256(body)
	request := CustodyPeerRequest{BodyByteCount: int64(len(body)), BodySHA256: hex.EncodeToString(hash[:]),
		Challenge: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), Operation: operation, OperationID: uuid.New(),
		Target: CustodyPeerTarget{BindingID: uuid.New(), ContentEpoch: 7, ContentScopeID: uuid.New(), LedgerID: uuid.New(), PoolID: uuid.New()}, Version: 1}
	return custodyPeerFixture{bootstrap: f, sender: newRegistry(), receiver: newRegistry(),
		binding: RequestBinding{Scope: f.scope, AuthorityRevision: 1, AuthorityDigest: digest, DeploymentID: f.descriptor.DeploymentID, RouteID: f.route.RouteID, TrafficClass: operation.trafficClass()},
		request: request, body: body, now: time.UnixMilli(1100)}
}

func (f custodyPeerFixture) sign(t *testing.T) CustodyPeerProof {
	t.Helper()
	proof, err := f.sender.SignCustodyPeerRequestAt(f.bootstrap.deploymentSigner, f.binding, f.request, f.body, f.now)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func TestCustodyPeerBoundRoundtripForOnlySyncAndBackupOperations(t *testing.T) {
	for _, kind := range []ScopeKind{ScopeDeviceSync, ScopeBackupCustody} {
		for _, operation := range []CustodyPeerOperation{CustodyReserveObject, CustodyPutObject, CustodyReadObject, CustodyBeginPublication, CustodyAddPins, CustodyPreparePublication, CustodyConfirmPublication, CustodyAcquireLease, CustodyRenewLease, CustodyCloseLease, CustodyRetirePublication} {
			t.Run(string(kind)+"/"+string(operation), func(t *testing.T) {
				f := newCustodyPeerFixture(t, kind, operation)
				proof := f.sign(t)
				verified, err := f.receiver.VerifyCustodyPeerRequestAt(proof, f.request, f.body, f.now)
				if err != nil || verified.Source() != f.binding || verified.Request() != f.request {
					t.Fatalf("bound roundtrip: %v", err)
				}
				if _, err := json.Marshal(verified); err == nil {
					t.Fatal("verification result became a serializable bearer")
				}
				if strings.Contains(fmt.Sprintf("%#v", verified), f.request.Challenge) {
					t.Fatal("challenge leaked in result formatting")
				}
				// This primitive alone does not consume/expire the challenge.
				// The receiver's durable adapter must supply that independent gate.
				if _, err := f.receiver.VerifyCustodyPeerRequestAt(proof, f.request, f.body, f.now); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestCustodyPeerRejectsEveryRequestAndBodySubstitution(t *testing.T) {
	f := newCustodyPeerFixture(t, ScopeDeviceSync, CustodyPutObject)
	proof := f.sign(t)
	for _, field := range []string{"body", "length", "challenge", "operation", "operationID", "binding", "epoch", "scope", "ledger", "pool", "version"} {
		t.Run(field, func(t *testing.T) {
			changed := f.request
			body := f.body
			switch field {
			case "body":
				body = bytes.Repeat([]byte{'X'}, len(f.body))
				h := sha256.Sum256(body)
				changed.BodySHA256 = hex.EncodeToString(h[:])
			case "length":
				changed.BodyByteCount++
			case "challenge":
				changed.Challenge = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32))
			case "operation":
				changed.Operation = CustodyReadObject
			case "operationID":
				changed.OperationID = uuid.New()
			case "binding":
				changed.Target.BindingID = uuid.New()
			case "epoch":
				changed.Target.ContentEpoch++
			case "scope":
				changed.Target.ContentScopeID = uuid.New()
			case "ledger":
				changed.Target.LedgerID = uuid.New()
			case "pool":
				changed.Target.PoolID = uuid.New()
			case "version":
				changed.Version++
			}
			if _, err := f.receiver.VerifyCustodyPeerRequestAt(proof, changed, body, f.now); err == nil {
				t.Fatal("request substitution accepted")
			}
		})
	}
	wrongBody := bytes.Repeat([]byte{'Y'}, len(f.body))
	if _, err := f.sender.SignCustodyPeerRequestAt(f.bootstrap.deploymentSigner, f.binding, f.request, wrongBody, f.now); err == nil {
		t.Fatal("signed body with wrong commitment")
	}
	if _, err := f.receiver.VerifyCustodyPeerRequestAt(proof, f.request, wrongBody, f.now); err == nil {
		t.Fatal("received body with wrong commitment")
	}
}

func TestCustodyPeerRejectsUnknownServicesOperationsAndUnpinnedKeys(t *testing.T) {
	for _, kind := range []ScopeKind{ScopeSharedSpace, ScopeComputePool} {
		f := newCustodyPeerFixture(t, kind, CustodyPutObject)
		if _, err := f.sender.SignCustodyPeerRequestAt(f.bootstrap.deploymentSigner, f.binding, f.request, f.body, f.now); err == nil {
			t.Fatal("unsupported service signed")
		}
		encoded, _ := json.Marshal(CustodyPeerPayload{Request: f.request, Source: custodyPeerSource(f.binding), Version: 1})
		signature, _ := f.bootstrap.deploymentSigner.signRecord(custodyPeerSignatureDomain, encoded)
		if _, err := f.receiver.VerifyCustodyPeerRequestAt(CustodyPeerProof{Payload: encoded, Signature: signature}, f.request, f.body, f.now); err == nil {
			t.Fatal("otherwise valid unsupported peer service accepted")
		}
	}
	f := newCustodyPeerFixture(t, ScopeDeviceSync, CustodyPutObject)
	for _, operation := range []CustodyPeerOperation{"", "register_binding", "delete_object", "box_admin", "worker"} {
		request := f.request
		request.Operation = operation
		if _, err := f.sender.SignCustodyPeerRequestAt(f.bootstrap.deploymentSigner, f.binding, request, f.body, f.now); err == nil {
			t.Fatal("unsupported operation signed")
		}
	}
	seed := make([]byte, 32)
	seed[31] = 3
	otherSigner, err := NewDeploymentSigner(f.binding.DeploymentID, seed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.sender.SignCustodyPeerRequestAt(otherSigner, f.binding, f.request, f.body, f.now); err == nil {
		t.Fatal("wrong key signed under matching deployment UUID")
	}
	proof := f.sign(t)
	proof.Signature, err = otherSigner.signRecord(custodyPeerSignatureDomain, proof.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.receiver.VerifyCustodyPeerRequestAt(proof, f.request, f.body, f.now); err == nil {
		t.Fatal("self-supplied key became a trust anchor")
	}
}

func TestCustodyPeerRequiresPersistentSignedCurrentAuthority(t *testing.T) {
	f := newCustodyPeerFixture(t, ScopeBackupCustody, CustodyConfirmPublication)
	proof := f.sign(t)
	for _, withManifest := range []bool{false, true} {
		registry := NewBindingRegistry()
		current := CurrentBinding{Revision: 1, Digest: f.binding.AuthorityDigest, DeploymentID: f.binding.DeploymentID}
		if withManifest {
			manifest := f.bootstrap.signedManifest(t, f.bootstrap.policy)
			current.Manifest = &manifest
			current.Digest, _ = manifest.ReferenceDigest()
		}
		if err := registry.Activate(f.binding.Scope, current); err != nil {
			t.Fatal(err)
		}
		if _, err := registry.VerifyCustodyPeerRequestAt(proof, f.request, f.body, f.now); err == nil {
			t.Fatal("nonpersistent fixture registry authorized peer")
		}
	}
	for _, field := range []string{"revision", "digest", "deployment", "route", "class", "scope"} {
		t.Run(field, func(t *testing.T) {
			binding := f.binding
			switch field {
			case "revision":
				binding.AuthorityRevision++
			case "digest":
				binding.AuthorityDigest = strings.Repeat("2", 64)
			case "deployment":
				binding.DeploymentID = uuid.New()
			case "route":
				binding.RouteID = uuid.New()
			case "class":
				binding.TrafficClass = TrafficBulk
			case "scope":
				binding.Scope.ScopeID = uuid.New()
			}
			if _, err := f.sender.SignCustodyPeerRequestAt(f.bootstrap.deploymentSigner, binding, f.request, f.body, f.now); err == nil {
				t.Fatal("unbound source signed")
			}
			payload := CustodyPeerPayload{Request: f.request, Source: custodyPeerSource(binding), Version: 1}
			encoded, _ := json.Marshal(payload)
			signature, err := f.bootstrap.deploymentSigner.signRecord(custodyPeerSignatureDomain, encoded)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.receiver.VerifyCustodyPeerRequestAt(CustodyPeerProof{Payload: encoded, Signature: signature}, f.request, f.body, f.now); err == nil {
				t.Fatal("unbound signed source accepted")
			}
		})
	}
	if err := f.receiver.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.receiver.VerifyCustodyPeerRequestAt(proof, f.request, f.body, f.now); err == nil {
		t.Fatal("closed registry accepted proof")
	}
}

func TestCustodyPeerRejectsDomainAndCanonicalEncodingConfusion(t *testing.T) {
	f := newCustodyPeerFixture(t, ScopeDeviceSync, CustodyReserveObject)
	proof := f.sign(t)
	for _, domain := range []string{deploymentProofSignatureDomain, bulkGrantSignatureDomain, bootstrapProofSignatureDomain, "Facets service authority manifest v1\x00"} {
		changed := proof
		changed.Signature, _ = f.bootstrap.deploymentSigner.signRecord(domain, changed.Payload)
		if _, err := f.receiver.VerifyCustodyPeerRequestAt(changed, f.request, f.body, f.now); err == nil {
			t.Fatal("another signature domain accepted")
		}
	}
	for _, change := range []func([]byte) []byte{
		func(b []byte) []byte { return append(b, '\n') },
		func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"version":1}`), []byte(`"version":1,"unknown":true}`), 1)
		},
		func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"version":1}`), []byte(`"version":1,"version":1}`), 1)
		},
		func(b []byte) []byte { return append(b, []byte(`{}`)...) },
	} {
		changed := proof
		changed.Payload = change(append([]byte(nil), proof.Payload...))
		changed.Signature, _ = f.bootstrap.deploymentSigner.signRecord(custodyPeerSignatureDomain, changed.Payload)
		if _, err := f.receiver.VerifyCustodyPeerRequestAt(changed, f.request, f.body, f.now); err == nil {
			t.Fatal("noncanonical signed payload accepted")
		}
	}
	changed := proof
	changed.Signature = highSSignature(t, proof.Signature)
	if _, err := f.receiver.VerifyCustodyPeerRequestAt(changed, f.request, f.body, f.now); err == nil {
		t.Fatal("malleable high-S signature accepted")
	}
}

func TestCustodyPeerBodyAndProofBounds(t *testing.T) {
	f := newCustodyPeerFixture(t, ScopeDeviceSync, CustodyPutObject)
	for _, size := range []int{0, objectcustodywire.MaximumPlaintextBytes + objectcustodywire.WireOverhead} {
		body := make([]byte, size)
		hash := sha256.Sum256(body)
		request := f.request
		request.BodyByteCount, request.BodySHA256 = int64(size), hex.EncodeToString(hash[:])
		proof, err := f.sender.SignCustodyPeerRequestAt(f.bootstrap.deploymentSigner, f.binding, request, body, f.now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.receiver.VerifyCustodyPeerRequestAt(proof, request, body, f.now); err != nil {
			t.Fatal(err)
		}
		request.BodyByteCount = objectcustodywire.MaximumPlaintextBytes + objectcustodywire.WireOverhead + 1
		if request.Validate() == nil {
			t.Fatal("oversize object request")
		}
	}
	f.request.Operation = CustodyReserveObject
	f.request.BodyByteCount = MaximumCustodyPeerControlBodyBytes + 1
	if f.request.Validate() == nil {
		t.Fatal("oversize control request")
	}
	f = newCustodyPeerFixture(t, ScopeDeviceSync, CustodyPutObject)
	proof := f.sign(t)
	for _, field := range []string{"payload", "publicKey", "signature", "challenge", "digest"} {
		changed, request := proof, f.request
		switch field {
		case "payload":
			changed.Payload = make([]byte, MaximumCustodyPeerPayloadBytes+1)
		case "publicKey":
			changed.Signature.PublicSigningKeyX963 = strings.Repeat("A", 100000)
		case "signature":
			changed.Signature.Signature = strings.Repeat("A", 100000)
		case "challenge":
			request.Challenge = strings.Repeat("A", 100000)
		case "digest":
			request.BodySHA256 = strings.Repeat("a", 100000)
		}
		if _, err := f.receiver.VerifyCustodyPeerRequestAt(changed, request, f.body, f.now); err == nil {
			t.Fatal("oversize field accepted")
		}
	}
}

func TestCustodyPeerManifestExpiryAndWriteFenceFailClosed(t *testing.T) {
	f := newCustodyPeerFixture(t, ScopeDeviceSync, CustodyRetirePublication)
	proof := f.sign(t)
	until := int64(1500)
	manifest := f.bootstrap.signedManifestUntil(t, f.bootstrap.policy, &until)
	digest, _ := manifest.ReferenceDigest()
	f.receiver.mu.Lock()
	current := f.receiver.bindings[f.binding.Scope]
	current.Manifest, current.Digest = &manifest, digest
	f.receiver.bindings[f.binding.Scope] = current
	f.receiver.mu.Unlock()
	if _, err := f.receiver.VerifyCustodyPeerRequestAt(proof, f.request, f.body, f.now); err == nil {
		t.Fatal("old authority digest accepted after registry change")
	}
	f.sender.mu.Lock()
	f.sender.bindings[f.binding.Scope] = current
	f.sender.mu.Unlock()
	f.binding.AuthorityDigest = digest
	proof = f.sign(t)
	if _, err := f.receiver.VerifyCustodyPeerRequestAt(proof, f.request, f.body, time.UnixMilli(until)); err == nil {
		t.Fatal("expired manifest accepted")
	}
	f.receiver.mu.Lock()
	current.WriteFence = &MigrationWriteFence{}
	f.receiver.bindings[f.binding.Scope] = current
	f.receiver.mu.Unlock()
	if _, err := f.receiver.VerifyCustodyPeerRequestAt(proof, f.request, f.body, f.now); err == nil {
		t.Fatal("fenced mutation accepted")
	}
}

func TestCustodyPeerCanonicalPayloadIndependentFixture(t *testing.T) {
	// Independent literal and shasum-256 fixture. UInt64.max must remain exact,
	// not be routed through floating point or a platform-specific JSON encoder.
	const fixture = `{"request":{"bodyByteCount":0,"bodySHA256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","operation":"read_object","operationID":"01000000-0000-0000-0000-000000000005","target":{"bindingID":"01000000-0000-0000-0000-000000000001","contentEpoch":18446744073709551615,"contentScopeID":"01000000-0000-0000-0000-000000000002","ledgerID":"01000000-0000-0000-0000-000000000003","poolID":"01000000-0000-0000-0000-000000000004"},"version":1},"source":{"authorityManifestDigest":"1111111111111111111111111111111111111111111111111111111111111111","authorityRevision":7,"deploymentID":"01000000-0000-0000-0000-000000000006","routeID":"01000000-0000-0000-0000-000000000007","scope":{"kind":"device_sync","scopeID":"01000000-0000-0000-0000-000000000008"},"trafficClass":"bulk"},"version":1}`
	var payload CustodyPeerPayload
	if err := json.Unmarshal([]byte(fixture), &payload); err != nil {
		t.Fatal(err)
	}
	if !payload.Request.MatchesBody(nil) || payload.Request.Target.ContentEpoch != ^uint64(0) {
		t.Fatal("fixture lost exact request identity")
	}
	encoded, err := json.Marshal(payload)
	if err != nil || string(encoded) != fixture {
		t.Fatal("canonical field order or integer representation changed")
	}
	hash := sha256.Sum256(encoded)
	if hex.EncodeToString(hash[:]) != "a9e6b7adf06f13e057e92aead253a0c45e294475644b3ae775419ee4380f9aa7" {
		t.Fatal("independent canonical payload digest changed")
	}
}
