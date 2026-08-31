package serviceauthority

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestDeploymentProofUsesCanonicalPayloadAndIndependentKey(t *testing.T) {
	deploymentID := uuid.MustParse("63000000-0000-0000-0000-000000000001")
	seed := make([]byte, 32)
	seed[31] = 2
	signer, err := NewDeploymentSigner(deploymentID, seed)
	if err != nil {
		t.Fatal(err)
	}
	request := testProofRequest(deploymentID)
	proof, err := signer.SignProof(request, time.UnixMilli(1_000))
	if err != nil {
		t.Fatal(err)
	}
	var payload ProofPayload
	if err := json.Unmarshal(proof.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	canonical, err := json.Marshal(payload)
	if err != nil || string(canonical) != string(proof.Payload) {
		t.Fatalf("deployment proof payload is not canonical: %v", err)
	}
	if payload.Request != request || payload.IssuedAtMilliseconds != 1_000 ||
		payload.ExpiresAtMilliseconds != 301_000 {
		t.Fatalf("unexpected proof payload: %+v", payload)
	}
	publicBytes, err := base64.RawURLEncoding.Strict().DecodeString(
		proof.Signature.PublicSigningKeyX963,
	)
	if err != nil {
		t.Fatal(err)
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), publicBytes)
	rawSignature, err := base64.RawURLEncoding.Strict().DecodeString(
		proof.Signature.Signature,
	)
	if err != nil || len(rawSignature) != 64 {
		t.Fatalf("invalid raw signature: %v", err)
	}
	digest := sha256.Sum256(append(
		[]byte(deploymentProofSignatureDomain),
		proof.Payload...,
	))
	if !ecdsa.Verify(
		&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y},
		digest[:],
		new(big.Int).SetBytes(rawSignature[:32]),
		new(big.Int).SetBytes(rawSignature[32:]),
	) {
		t.Fatal("deployment proof signature failed")
	}
	fingerprint := sha256.Sum256(publicBytes)
	if proof.Signature.SignerID != deploymentID ||
		proof.Signature.SigningKeyFingerprint != hex.EncodeToString(fingerprint[:]) {
		t.Fatal("deployment proof identity mismatch")
	}
}

func TestComputePoolIsAnIndependentPortableServiceScope(t *testing.T) {
	scope := Scope{
		Kind:    ScopeComputePool,
		ScopeID: uuid.MustParse("61000000-0000-0000-0000-000000000003"),
	}
	if err := scope.Validate(); err != nil {
		t.Fatalf("compute Pool scope rejected: %v", err)
	}
	encoded, err := json.Marshal(scope)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"kind":"compute_pool","scopeID":"61000000-0000-0000-0000-000000000003"}`
	if string(encoded) != want {
		t.Fatalf("compute Pool scope=%s; want %s", encoded, want)
	}
}

func TestBackupCustodyIsAnAccountScopedPortableServiceScope(t *testing.T) {
	scope := Scope{Kind: ScopeBackupCustody, ScopeID: uuid.MustParse("10000000-0000-0000-0000-000000000004")}
	if err := scope.Validate(); err != nil {
		t.Fatalf("validate Backup scope: %v", err)
	}
	encoded, err := json.Marshal(scope)
	if err != nil {
		t.Fatalf("encode Backup scope: %v", err)
	}
	if string(encoded) != `{"kind":"backup_custody","scopeID":"10000000-0000-0000-0000-000000000004"}` {
		t.Fatalf("unexpected Backup scope: %s", encoded)
	}
}

func TestBackupCustodyReceiptsRequireExactHistoricalDeploymentAndPointInTimeRetention(t *testing.T) {
	fixture := newBootstrapFixture(t)
	accountID := uuid.MustParse("20000000-0000-4000-8000-000000000001")
	scope := Scope{Kind: ScopeBackupCustody, ScopeID: accountID}
	anchor := fixture.anchor
	anchor.Scope = scope
	validUntil := int64(5_000)
	manifestPayload := ManifestPayload{
		ActiveDeployment: fixture.descriptor, IssuedAtMilliseconds: 1_000,
		PreparedDeployments: []DeploymentDescriptor{}, Revision: 1, Scope: scope,
		Transition: TransitionInitialActivation, TransportPolicy: fixture.policy,
		ValidFromMilliseconds: 1_000, ValidUntilMilliseconds: &validUntil,
		Version: SchemaVersion,
	}
	manifestBytes, err := json.Marshal(manifestPayload)
	if err != nil {
		t.Fatal(err)
	}
	manifest := Manifest{Payload: manifestBytes, Signature: signTestAuthorityRecord(
		t, fixture.authorityKey, fixture.authorityID,
		"Facets service authority manifest v1\x00", manifestBytes,
	)}
	manifestDigest, err := manifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	generation := BackupCustodyGenerationRecord{
		AccountID:   accountID,
		BackupSetID: uuid.MustParse("10000000-0000-4000-8000-000000000001"),
		Generation:  1, OuterByteCount: 2_522,
		OuterDigest: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32)),
		TargetID:    uuid.MustParse("30000000-0000-4000-8000-000000000001"),
		UploadID:    uuid.MustParse("40000000-0000-4000-8000-000000000001"), Version: 1,
	}
	authority := BackupCustodyAuthorityContext{
		AuthorityManifestDigest: manifestDigest, AuthorityRevision: 1,
		DeploymentID: fixture.descriptor.DeploymentID, Scope: scope,
	}
	payload := BackupCustodyReceiptPayload{
		Authority:    authority,
		CredentialID: uuid.MustParse("50000000-0000-4000-8000-000000000001"),
		Generation:   generation, IssuedAtMilliseconds: 2_000,
		Kind:      BackupCustodyCommittedKind,
		ReceiptID: uuid.MustParse("80000000-0000-4000-8000-000000000001"),
		RequestID: uuid.MustParse("70000000-0000-4000-8000-000000000001"),
		Version:   1,
	}
	deploymentSigner := fixtureDeploymentSigner(t, fixture.descriptor)
	receipt, err := deploymentSigner.SignBackupCustodyReceipt(payload)
	if err != nil {
		t.Fatal(err)
	}
	if authorized, err := receipt.Authorize(anchor, manifest); err != nil || !reflect.DeepEqual(authorized, payload) {
		t.Fatalf("historical receipt rejected: %v", err)
	}
	wrongDomainSignature, err := deploymentSigner.signRecord(
		BackupRetentionReceiptSignatureDomain,
		receipt.Payload,
	)
	if err != nil {
		t.Fatal(err)
	}
	wrongDomainReceipt := BackupCustodyReceipt{
		Payload: receipt.Payload, Signature: wrongDomainSignature,
	}
	if _, err := wrongDomainReceipt.VerifiedPayload(); err == nil {
		t.Fatal("custody payload accepted a retention receipt signature domain")
	}

	retention, err := NewBackupRetentionReceiptPayload(
		uuid.New(), authority, uuid.New(), payload.CredentialID, receipt,
		anchor, manifest, 2_500, 2_500,
	)
	if err != nil {
		t.Fatal(err)
	}
	retentionReceipt, err := deploymentSigner.SignBackupCustodyReceipt(retention)
	if err != nil {
		t.Fatal(err)
	}
	if verified, err := retentionReceipt.Authorize(anchor, manifest); err != nil ||
		verified.RetainedThroughMilliseconds == nil || *verified.RetainedThroughMilliseconds != 2_500 {
		t.Fatalf("point-in-time retention receipt rejected: %v", err)
	}
	custodyReference, _ := receipt.ReferenceDigest()
	retentionReference, _ := retentionReceipt.ReferenceDigest()
	if custodyReference == retentionReference {
		t.Fatal("custody and retention receipt reference domains collided")
	}
	if _, err := NewBackupRetentionReceiptPayload(
		uuid.New(), authority, uuid.New(), payload.CredentialID, receipt,
		anchor, manifest, 2_501, 2_500,
	); err == nil {
		t.Fatal("future retention promise accepted")
	}
	if _, err := NewBackupRetentionReceiptPayload(
		uuid.New(), authority, uuid.New(), payload.CredentialID, receipt,
		anchor, manifest, 2_499, 2_500,
	); err == nil {
		t.Fatal("past retention value accepted as current proof")
	}

	wrongAnchor := anchor
	wrongAnchor.Scope.ScopeID = uuid.New()
	if _, err := receipt.Authorize(wrongAnchor, manifest); err == nil {
		t.Fatal("wrong account authority accepted")
	}
	if _, err := NewBackupRetentionReceiptPayload(
		uuid.New(), authority, uuid.New(), payload.CredentialID, receipt,
		wrongAnchor, manifest, 2_500, 2_500,
	); err == nil {
		t.Fatal("retention proof referenced custody without exact historical authorization")
	}
	attackerSeed := make([]byte, 32)
	attackerSeed[31] = 15
	attacker, err := NewDeploymentSigner(fixture.descriptor.DeploymentID, attackerSeed)
	if err != nil {
		t.Fatal(err)
	}
	attackerReceipt, err := attacker.SignBackupCustodyReceipt(payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := attackerReceipt.Authorize(anchor, manifest); err == nil {
		t.Fatal("wrong deployment signing key authorized")
	}
	expiredPayload := manifestPayload
	expiry := int64(1_500)
	expiredPayload.ValidUntilMilliseconds = &expiry
	expiredBytes, _ := json.Marshal(expiredPayload)
	expiredManifest := Manifest{Payload: expiredBytes, Signature: signTestAuthorityRecord(
		t, fixture.authorityKey, fixture.authorityID,
		"Facets service authority manifest v1\x00", expiredBytes,
	)}
	if _, err := receipt.Authorize(anchor, expiredManifest); err == nil {
		t.Fatal("expired historical authority accepted")
	}

	highS := receipt
	raw, err := base64.RawURLEncoding.Strict().DecodeString(highS.Signature.Signature)
	if err != nil {
		t.Fatal(err)
	}
	s := new(big.Int).SetBytes(raw[32:])
	s.Sub(elliptic.P256().Params().N, s).FillBytes(raw[32:])
	highS.Signature.Signature = base64.RawURLEncoding.EncodeToString(raw)
	if _, err := highS.VerifiedPayload(); err == nil {
		t.Fatal("high-S receipt accepted")
	}
	encoded, _ := receipt.CanonicalJSON()
	if _, err := DecodeBackupCustodyReceipt(append(encoded, '\n')); err == nil {
		t.Fatal("noncanonical receipt accepted")
	}
}

func TestDeploymentSignerLoadsOnlyOwnerProtectedCanonicalKeyFile(t *testing.T) {
	deploymentID := uuid.MustParse("63000000-0000-0000-0000-000000000001")
	seed := make([]byte, 32)
	seed[31] = 2
	path := filepath.Join(t.TempDir(), "deployment-signing-key")
	encoded := base64.RawURLEncoding.EncodeToString(seed) + "\n"
	if err := os.WriteFile(path, []byte(encoded), 0o600); err != nil {
		t.Fatal(err)
	}
	signer, err := LoadDeploymentSigner(deploymentID, path)
	if err != nil || signer.DeploymentID() != deploymentID {
		t.Fatalf("protected key rejected: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDeploymentSigner(deploymentID, path); err == nil {
		t.Fatal("group/world-readable deployment key accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	symlinkPath := filepath.Join(t.TempDir(), "deployment-signing-key-link")
	if err := os.Symlink(path, symlinkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDeploymentSigner(deploymentID, symlinkPath); err == nil {
		t.Fatal("deployment key symlink accepted")
	}
}

func TestBindingRegistryRejectsRollbackEquivocationAndStaleHeaders(t *testing.T) {
	registry := NewBindingRegistry()
	scope := Scope{
		Kind:    ScopeDeviceSync,
		ScopeID: uuid.MustParse("61000000-0000-0000-0000-000000000001"),
	}
	deploymentID := uuid.MustParse("63000000-0000-0000-0000-000000000001")
	digestOne := string(make([]byte, 0)) + repeatHex("1")
	digestTwo := repeatHex("2")
	if err := registry.Activate(scope, testCurrentBinding(
		t, 1, digestOne, deploymentID,
	)); err != nil {
		t.Fatal(err)
	}
	if err := registry.Activate(scope, testCurrentBinding(
		t, 1, digestTwo, deploymentID,
	)); err == nil {
		t.Fatal("accepted equivocation")
	}
	if err := registry.Activate(scope, testCurrentBinding(
		t, 2, digestTwo, deploymentID,
	)); err != nil {
		t.Fatal(err)
	}
	if err := registry.Activate(scope, testCurrentBinding(
		t, 1, digestOne, deploymentID,
	)); err == nil {
		t.Fatal("accepted rollback")
	}
	if err := registry.Activate(scope, testCurrentBinding(
		t, 4, repeatHex("4"), deploymentID,
	)); err == nil {
		t.Fatal("accepted authority revision gap")
	}
	header := make(http.Header)
	header.Set(HeaderScopeKind, string(scope.Kind))
	header.Set(HeaderScopeID, scope.ScopeID.String())
	header.Set(HeaderAuthorityRevision, "2")
	header.Set(HeaderAuthorityDigest, digestTwo)
	header.Set(HeaderDeploymentID, deploymentID.String())
	header.Set(HeaderRouteID, uuid.NewString())
	header.Set(HeaderTrafficClass, string(TrafficMessage))
	binding, err := ParseRequestBinding(header, deploymentID, TrafficMessage)
	if err != nil || registry.Authorize(binding) != nil {
		t.Fatalf("current binding rejected: parse=%v", err)
	}
	header.Set(HeaderAuthorityRevision, "1")
	binding, err = ParseRequestBinding(header, deploymentID, TrafficMessage)
	if err != nil {
		t.Fatal(err)
	}
	if registry.Authorize(binding) == nil {
		t.Fatal("stale binding accepted")
	}
	header.Set(HeaderAuthorityRevision, "2")
	header.Add(HeaderAuthorityRevision, "2")
	if _, err := ParseRequestBinding(header, deploymentID, TrafficMessage); err == nil {
		t.Fatal("duplicate authority header accepted")
	}
}

func TestBindingRegistryLoadsStrictDeploymentScopedState(t *testing.T) {
	fixture := newBootstrapFixture(t)
	messageRoute := fixture.route
	messageRoute.Endpoint = "https://facets-box.local:9443"
	messageRoute.RouteID = uuid.MustParse("62000000-0000-0000-0000-000000000002")
	fixture.descriptor.Routes = []TransportRoute{fixture.route, messageRoute}
	fixture.policy.MessageRouteIDs = []uuid.UUID{messageRoute.RouteID}
	deploymentID := fixture.descriptor.DeploymentID
	scopeID := fixture.scope.ScopeID
	manifest := fixture.signedManifest(t, fixture.policy)
	digest, err := manifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "bindings.json")
	data, err := json.Marshal(BindingFile{
		Bindings: []BindingFileEntry{{
			DeploymentID: deploymentID,
			Digest:       digest,
			Manifest:     &manifest,
			Revision:     1,
			Scope: Scope{
				Kind: ScopeDeviceSync, ScopeID: scopeID,
			},
		}},
		Version: SchemaVersion,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	registry, err := LoadBindingRegistry(path, deploymentID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.Close() })
	controlBinding := RequestBinding{
		Scope:             Scope{Kind: ScopeDeviceSync, ScopeID: scopeID},
		AuthorityRevision: 1,
		AuthorityDigest:   digest,
		DeploymentID:      deploymentID,
		RouteID:           fixture.route.RouteID,
		TrafficClass:      TrafficControl,
	}
	if err := registry.Authorize(controlBinding); err != nil {
		t.Fatal(err)
	}
	messageBinding := controlBinding
	messageBinding.RouteID = messageRoute.RouteID
	messageBinding.TrafficClass = TrafficMessage
	if err := registry.Authorize(messageBinding); err != nil {
		t.Fatalf("listed message route rejected: %v", err)
	}
	unlisted := controlBinding
	unlisted.RouteID = uuid.New()
	if err := registry.Authorize(unlisted); err == nil {
		t.Fatal("unlisted route authorized")
	}
	wrongTrafficClass := controlBinding
	wrongTrafficClass.TrafficClass = TrafficMessage
	if err := registry.Authorize(wrongTrafficClass); err == nil {
		t.Fatal("control-only route authorized for message traffic")
	}
	if _, err := LoadBindingRegistry(path, deploymentID); err == nil {
		t.Fatal("binding file admitted a second live process owner")
	}
	if err := registry.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBindingRegistry(path, uuid.New()); err == nil {
		t.Fatal("binding file accepted for another deployment")
	}
	if err := os.Chmod(path, 0o622); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBindingRegistry(path, deploymentID); err == nil {
		t.Fatal("group/world-writable binding file accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	symlinkPath := filepath.Join(t.TempDir(), "bindings-link.json")
	if err := os.Symlink(path, symlinkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBindingRegistry(symlinkPath, deploymentID); err == nil {
		t.Fatal("binding file symlink accepted")
	}
}

func TestBindingRegistryPersistsFirstActivationAndReloadsIt(t *testing.T) {
	fixture := newBootstrapFixture(t)
	deploymentID := fixture.descriptor.DeploymentID
	scope := fixture.scope
	path := filepath.Join(t.TempDir(), "bindings.json")
	empty, err := json.Marshal(BindingFile{Bindings: []BindingFileEntry{}, Version: SchemaVersion})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, empty, 0o600); err != nil {
		t.Fatal(err)
	}
	registry, err := LoadBindingRegistry(path, deploymentID)
	if err != nil {
		t.Fatalf("empty initial registry rejected: %v", err)
	}
	t.Cleanup(func() { _ = registry.Close() })
	manifest := fixture.signedManifest(t, fixture.policy)
	digest, err := manifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	binding := CurrentBinding{
		Revision: 1, Digest: digest, DeploymentID: deploymentID, Manifest: &manifest,
	}
	if err := registry.Activate(scope, binding); err != nil {
		t.Fatalf("first activation failed: %v", err)
	}
	if err := registry.Close(); err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadBindingRegistry(path, deploymentID)
	if err != nil {
		t.Fatalf("persisted registry rejected: %v", err)
	}
	t.Cleanup(func() { _ = reloaded.Close() })
	if err := reloaded.Authorize(RequestBinding{
		Scope:             scope,
		AuthorityRevision: binding.Revision,
		AuthorityDigest:   binding.Digest,
		DeploymentID:      binding.DeploymentID,
		RouteID:           fixture.route.RouteID,
		TrafficClass:      TrafficControl,
	}); err != nil {
		t.Fatalf("reloaded activation not authoritative: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("persisted bindings are not owner-only: %o", info.Mode().Perm())
	}
}

func TestBindingRegistryRejectsPersistedDigestWithoutSignedManifest(t *testing.T) {
	fixture := newBootstrapFixture(t)
	path := filepath.Join(t.TempDir(), "bindings.json")
	data, err := json.Marshal(BindingFile{
		Bindings: []BindingFileEntry{{
			DeploymentID: fixture.descriptor.DeploymentID,
			Digest:       repeatHex("1"),
			Revision:     1,
			Scope:        fixture.scope,
		}},
		Version: SchemaVersion,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBindingRegistry(path, fixture.descriptor.DeploymentID); err == nil {
		t.Fatal("persisted authority digest accepted without its signed manifest")
	}
}

func testProofRequest(deploymentID uuid.UUID) ProofRequest {
	return ProofRequest{
		AuthorityManifestDigest: repeatHex("1"),
		AuthorityRevision:       1,
		Challenge:               base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		DeploymentID:            deploymentID,
		RouteID:                 uuid.MustParse("62000000-0000-0000-0000-000000000001"),
		Scope: Scope{
			Kind:    ScopeDeviceSync,
			ScopeID: uuid.MustParse("61000000-0000-0000-0000-000000000001"),
		},
		TrafficClass: TrafficMessage,
		Version:      SchemaVersion,
	}
}

func testCurrentBinding(
	t *testing.T,
	revision uint64,
	digest string,
	deploymentID uuid.UUID,
) CurrentBinding {
	t.Helper()
	return CurrentBinding{
		Revision: revision, Digest: digest, DeploymentID: deploymentID,
	}
}

func repeatHex(value string) string {
	result := ""
	for len(result) < 64 {
		result += value
	}
	return result
}
