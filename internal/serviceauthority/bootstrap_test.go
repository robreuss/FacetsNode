package serviceauthority

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestDeploymentOfferAndInitialEnrollmentKeepAuthorityKeysSeparate(t *testing.T) {
	fixture := newBootstrapFixture(t)
	offer, err := fixture.deploymentSigner.SignDeploymentOffer(fixture.offerPayload)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := offer.ReferenceDigest()
	if err != nil || len(digest) != 64 {
		t.Fatalf("offer digest=%q err=%v", digest, err)
	}
	manifest := fixture.signedManifest(t, fixture.policy)
	enrollment := InitialEnrollment{
		Anchor:          fixture.anchor,
		DeploymentOffer: offer,
		Manifest:        manifest,
		Version:         SchemaVersion,
	}
	payload, err := enrollment.Validate(fixture.scope, 1_100)
	if err != nil {
		t.Fatal(err)
	}
	if payload.Revision != 1 || manifest.Signature.SignerID == offer.Signature.SignerID {
		t.Fatal("client and deployment authorities were conflated")
	}

	if _, err := enrollment.Validate(fixture.scope, 2_000); err == nil {
		t.Fatal("expired deployment offer accepted")
	}
	if _, err := enrollment.ValidateForAdmissionClaim(fixture.scope); err != nil {
		t.Fatalf("structurally valid committed admission retry rejected: %v", err)
	}
}

func TestInitialEnrollmentAdmissionRetryAuthenticatesExpiredFiniteManifest(t *testing.T) {
	fixture := newBootstrapFixture(t)
	offer, err := fixture.deploymentSigner.SignDeploymentOffer(fixture.offerPayload)
	if err != nil {
		t.Fatal(err)
	}
	validUntil := int64(1_500)
	enrollment := InitialEnrollment{
		Anchor:          fixture.anchor,
		DeploymentOffer: offer,
		Manifest:        fixture.signedManifestUntil(t, fixture.policy, &validUntil),
		Version:         SchemaVersion,
	}
	if _, err := enrollment.Validate(fixture.scope, 1_100); err != nil {
		t.Fatalf("current finite Manifest rejected: %v", err)
	}
	if _, err := enrollment.Validate(fixture.scope, 2_100); err == nil {
		t.Fatal("expired offer and finite Manifest accepted as a fresh enrollment")
	}
	if _, err := enrollment.ValidateForAdmissionClaim(fixture.scope); err != nil {
		t.Fatalf("expired finite Manifest lost structural authenticity: %v", err)
	}
}

func TestInitialEnrollmentRejectsPolicyNotAuthenticatedByOffer(t *testing.T) {
	fixture := newBootstrapFixture(t)
	offer, err := fixture.deploymentSigner.SignDeploymentOffer(fixture.offerPayload)
	if err != nil {
		t.Fatal(err)
	}
	changed := fixture.policy
	changed.AllowsPublicDirectBulkTransfer = true
	enrollment := InitialEnrollment{
		Anchor:          fixture.anchor,
		DeploymentOffer: offer,
		Manifest:        fixture.signedManifest(t, changed),
		Version:         SchemaVersion,
	}
	if _, err := enrollment.Validate(fixture.scope, 1_100); err == nil {
		t.Fatal("manifest policy not present in the signed deployment offer was accepted")
	}
	if _, err := enrollment.ValidateForAdmissionClaim(fixture.scope); err == nil {
		t.Fatal("structural retry accepted policy not authenticated by the offer")
	}
}

func TestInitialBindingPreservesExactServiceScopeAcrossKinds(t *testing.T) {
	fixture := newBootstrapFixture(t)
	fixture.scope = Scope{
		Kind:    ScopeSharedSpace,
		ScopeID: uuid.MustParse("65000000-0000-0000-0000-000000000001"),
	}
	fixture.anchor.Scope = fixture.scope
	offer, err := fixture.deploymentSigner.SignDeploymentOffer(fixture.offerPayload)
	if err != nil {
		t.Fatal(err)
	}
	enrollment := InitialEnrollment{
		Anchor:          fixture.anchor,
		DeploymentOffer: offer,
		Manifest:        fixture.signedManifest(t, fixture.policy),
		Version:         SchemaVersion,
	}
	binding, err := NewInitialBinding(
		enrollment, fixture.deploymentSigner, fixture.scope, 1_100,
	)
	if err != nil || binding.Validate() != nil || binding.Scope() != fixture.scope ||
		binding.RequireFreshClaimAt(1_100) != nil {
		t.Fatalf("Shared Space initial binding=%+v err=%v", binding, err)
	}
	wrongScope := fixture.scope
	wrongScope.Kind = ScopeDeviceSync
	if _, err := NewInitialBinding(
		enrollment, fixture.deploymentSigner, wrongScope, 1_100,
	); err == nil {
		t.Fatal("Shared Space enrollment accepted as Device Sync authority")
	}
}

func TestBootstrapProofBindsOfferScopeRouteAndLiveDeploymentKey(t *testing.T) {
	fixture := newBootstrapFixture(t)
	offer, err := fixture.deploymentSigner.SignDeploymentOffer(fixture.offerPayload)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := offer.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	request := BootstrapProofRequest{
		Challenge: base64.RawURLEncoding.EncodeToString(
			make([]byte, 32),
		),
		DeploymentID:          fixture.descriptor.DeploymentID,
		DeploymentOfferDigest: digest,
		RouteID:               fixture.route.RouteID,
		Scope:                 fixture.scope,
		TrafficClass:          TrafficControl,
		Version:               SchemaVersion,
	}
	proof, err := fixture.deploymentSigner.SignBootstrapProof(
		request,
		offer,
		time.UnixMilli(1_100),
	)
	if err != nil {
		t.Fatal(err)
	}
	var payload BootstrapProofPayload
	if err := verifyCanonicalRecord(
		proof.Payload,
		proof.Signature,
		bootstrapProofSignatureDomain,
		&payload,
	); err != nil {
		t.Fatal(err)
	}
	if payload.Request != request || payload.IssuedAtMilliseconds != 1_100 ||
		payload.ExpiresAtMilliseconds != 301_100 {
		t.Fatalf("unexpected bootstrap proof payload: %+v", payload)
	}
	request.DeploymentOfferDigest = repeatHex("f")
	if _, err := fixture.deploymentSigner.SignBootstrapProof(
		request,
		offer,
		time.UnixMilli(1_100),
	); err == nil {
		t.Fatal("bootstrap proof signed for another offer digest")
	}
}

func TestSwiftCompatibleBootstrapPortableFixture(t *testing.T) {
	data, err := os.ReadFile(
		filepath.Join("testdata", "service-bootstrap-portable-v1.json"),
	)
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Format               string                `json:"format"`
		Offer                DeploymentOffer       `json:"offer"`
		OfferReferenceDigest string                `json:"offerReferenceDigest"`
		Proof                BootstrapProof        `json:"proof"`
		Request              BootstrapProofRequest `json:"request"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(&struct{}{}); err == nil {
		t.Fatal("portable fixture contains trailing JSON")
	}
	if fixture.Format != "facets.service-bootstrap-fixture.v1" {
		t.Fatalf("format=%q", fixture.Format)
	}
	var offerPayload DeploymentOfferPayload
	if err := json.Unmarshal(fixture.Offer.Payload, &offerPayload); err != nil {
		t.Fatalf("offer payload decode: %v", err)
	}
	canonicalOffer, err := json.Marshal(offerPayload)
	if err != nil || !bytes.Equal(canonicalOffer, fixture.Offer.Payload) {
		t.Fatalf("offer payload is not canonical: %v", err)
	}
	publicBytes, err := canonicalP256PublicKey(
		fixture.Offer.Signature.PublicSigningKeyX963,
	)
	if err != nil {
		t.Fatalf("offer public key: %v", err)
	}
	rawSignature, err := base64.RawURLEncoding.Strict().DecodeString(
		fixture.Offer.Signature.Signature,
	)
	if err != nil || len(rawSignature) != 64 {
		t.Fatalf("offer signature encoding: bytes=%d err=%v", len(rawSignature), err)
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), publicBytes)
	signed := append([]byte(deploymentOfferSignatureDomain), fixture.Offer.Payload...)
	signedDigest := sha256.Sum256(signed)
	if x == nil || y == nil || !ecdsa.Verify(
		&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y},
		signedDigest[:],
		new(big.Int).SetBytes(rawSignature[:32]),
		new(big.Int).SetBytes(rawSignature[32:]),
	) {
		t.Fatal("offer signature verification failed")
	}
	if err := offerPayload.Validate(nil); err != nil {
		t.Fatalf("offer payload semantics: %v", err)
	}
	digest, err := fixture.Offer.ReferenceDigest()
	if err != nil || digest != fixture.OfferReferenceDigest {
		t.Fatalf("offer digest=%q err=%v", digest, err)
	}
	if err := fixture.Request.Validate(
		fixture.Offer,
		fixture.Request.DeploymentID,
	); err != nil {
		t.Fatal(err)
	}
	var payload BootstrapProofPayload
	if err := verifyCanonicalRecord(
		fixture.Proof.Payload,
		fixture.Proof.Signature,
		bootstrapProofSignatureDomain,
		&payload,
	); err != nil {
		t.Fatal(err)
	}
	if payload.Request != fixture.Request ||
		payload.IssuedAtMilliseconds != 1_100 ||
		payload.ExpiresAtMilliseconds != 301_100 {
		t.Fatalf("unexpected portable bootstrap proof: %+v", payload)
	}
}

func TestDeploymentOfferTemplateLoadsProtectedExactSignerPolicy(t *testing.T) {
	fixture := newBootstrapFixture(t)
	template := DeploymentOfferTemplate{
		Deployment:      fixture.descriptor,
		TransportPolicy: fixture.policy,
		Version:         SchemaVersion,
	}
	encoded, err := json.Marshal(template)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "deployment-route-policy.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadDeploymentOfferTemplate(path, fixture.deploymentSigner)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.ContainsControlEndpoint(fixture.route.Endpoint) {
		t.Fatal("loaded template lost its control route")
	}
	offer, err := loaded.SignOffer(
		fixture.deploymentSigner,
		time.UnixMilli(1_000),
		time.UnixMilli(2_000),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := offer.VerifiedPayload(nil); err != nil {
		t.Fatalf("signed template offer rejected: %v", err)
	}
	if err := os.Chmod(path, 0o622); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDeploymentOfferTemplate(path, fixture.deploymentSigner); err == nil {
		t.Fatal("group/world-writable deployment route policy accepted")
	}
}

type bootstrapFixture struct {
	scope            Scope
	route            TransportRoute
	descriptor       DeploymentDescriptor
	policy           TransportPolicy
	offerPayload     DeploymentOfferPayload
	deploymentSigner *DeploymentSigner
	authorityKey     *ecdsa.PrivateKey
	authorityID      uuid.UUID
	anchor           TrustAnchor
}

func newBootstrapFixture(t *testing.T) bootstrapFixture {
	t.Helper()
	deploymentID := uuid.MustParse("63000000-0000-0000-0000-000000000001")
	deploymentSeed := make([]byte, 32)
	deploymentSeed[31] = 2
	signer, err := NewDeploymentSigner(deploymentID, deploymentSeed)
	if err != nil {
		t.Fatal(err)
	}
	pin := repeatHex("1")
	route := TransportRoute{
		Endpoint:     "https://facets-box.local:8443",
		Kind:         RouteDirectHTTPS,
		NetworkScope: NetworkTrustedLAN,
		RouteID:      uuid.MustParse("62000000-0000-0000-0000-000000000001"),
		ServerAuthentication: ServerAuthentication{
			Kind: "pinned_spki_sha256", PinnedSPKISHA256: &pin,
		},
	}
	descriptor := DeploymentDescriptor{
		CreatedAtMilliseconds: 900,
		DeploymentID:          deploymentID,
		PublicSigningKeyX963:  signer.PublicSigningKeyX963(),
		Routes:                []TransportRoute{route},
		SigningKeyFingerprint: signer.SigningKeyFingerprint(),
		Version:               SchemaVersion,
	}
	policy := TransportPolicy{
		AllowsPublicDirectBulkTransfer: false,
		BulkRouteIDs:                   []uuid.UUID{route.RouteID},
		ControlRouteIDs:                []uuid.UUID{route.RouteID},
		MessageRouteIDs:                []uuid.UUID{route.RouteID},
		Version:                        SchemaVersion,
	}
	authorityScalar := make([]byte, 32)
	authorityScalar[31] = 1
	authorityKey := testPrivateKey(t, authorityScalar)
	authorityID := uuid.MustParse("64000000-0000-0000-0000-000000000001")
	public := elliptic.Marshal(
		elliptic.P256(),
		authorityKey.PublicKey.X,
		authorityKey.PublicKey.Y,
	)
	scope := Scope{
		Kind: ScopeDeviceSync,
		ScopeID: uuid.MustParse(
			"61000000-0000-0000-0000-000000000001",
		),
	}
	return bootstrapFixture{
		scope:            scope,
		route:            route,
		descriptor:       descriptor,
		policy:           policy,
		deploymentSigner: signer,
		authorityKey:     authorityKey,
		authorityID:      authorityID,
		anchor: TrustAnchor{
			PublicSigningKeyX963:  base64.RawURLEncoding.EncodeToString(public),
			Scope:                 scope,
			SignerID:              authorityID,
			SigningKeyFingerprint: hex.EncodeToString(sha256Bytes(public)),
			Version:               SchemaVersion,
		},
		offerPayload: DeploymentOfferPayload{
			Deployment:            descriptor,
			ExpiresAtMilliseconds: 2_000,
			IssuedAtMilliseconds:  1_000,
			TransportPolicy:       policy,
			Version:               SchemaVersion,
		},
	}
}

func (fixture bootstrapFixture) signedManifest(
	t *testing.T,
	policy TransportPolicy,
) Manifest {
	return fixture.signedManifestUntil(t, policy, nil)
}

func (fixture bootstrapFixture) signedManifestUntil(
	t *testing.T,
	policy TransportPolicy,
	validUntil *int64,
) Manifest {
	t.Helper()
	payload := ManifestPayload{
		ActiveDeployment:       fixture.descriptor,
		IssuedAtMilliseconds:   1_000,
		PreparedDeployments:    []DeploymentDescriptor{},
		Revision:               1,
		Scope:                  fixture.scope,
		Transition:             "initial_activation",
		TransportPolicy:        policy,
		ValidFromMilliseconds:  1_000,
		ValidUntilMilliseconds: validUntil,
		Version:                SchemaVersion,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	signature := signTestAuthorityRecord(
		t,
		fixture.authorityKey,
		fixture.authorityID,
		"Facets service authority manifest v1\x00",
		encoded,
	)
	return Manifest{Payload: encoded, Signature: signature}
}

func signTestAuthorityRecord(
	t *testing.T,
	key *ecdsa.PrivateKey,
	signerID uuid.UUID,
	domain string,
	payload []byte,
) Signature {
	t.Helper()
	digest := sha256.Sum256(append([]byte(domain), payload...))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if s.Cmp(new(big.Int).Rsh(new(big.Int).Set(elliptic.P256().Params().N), 1)) > 0 {
		s.Sub(elliptic.P256().Params().N, s)
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	public := elliptic.Marshal(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y)
	return Signature{
		Algorithm:             "ES256",
		PublicSigningKeyX963:  base64.RawURLEncoding.EncodeToString(public),
		Signature:             base64.RawURLEncoding.EncodeToString(raw),
		SignerID:              signerID,
		SigningKeyFingerprint: hex.EncodeToString(sha256Bytes(public)),
	}
}

func testPrivateKey(t *testing.T, scalar []byte) *ecdsa.PrivateKey {
	t.Helper()
	d := new(big.Int).SetBytes(scalar)
	x, y := elliptic.P256().ScalarBaseMult(scalar)
	if d.Sign() <= 0 || x == nil || y == nil {
		t.Fatal("invalid test private key")
	}
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y},
		D:         d,
	}
}
