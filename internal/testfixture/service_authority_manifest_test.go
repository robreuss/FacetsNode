package testfixture_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"testing"
)

const (
	manifestSignatureDomain = "Facets service authority manifest v1\x00"
	manifestReferenceDomain = "Facets service authority manifest reference v1\x00"
)

//go:embed service-authority-manifest-portable-v1.json
var serviceAuthorityFixture []byte

//go:embed service-deployment-proof-go-v1.json
var serviceDeploymentProofFixture []byte

type portableServiceAuthorityFixture struct {
	Manifest        []byte `json:"manifest"`
	ReferenceDigest string `json:"referenceDigest"`
}

type portableDeploymentProofFixture struct {
	Proof struct {
		Payload   []byte            `json:"payload"`
		Signature portableSignature `json:"signature"`
	} `json:"proof"`
	Request json.RawMessage `json:"request"`
}

type portableManifest struct {
	Payload   []byte            `json:"payload"`
	Signature portableSignature `json:"signature"`
}

type portableSignature struct {
	Algorithm             string `json:"algorithm"`
	PublicSigningKeyX963  string `json:"publicSigningKeyX963"`
	Signature             string `json:"signature"`
	SignerID              string `json:"signerID"`
	SigningKeyFingerprint string `json:"signingKeyFingerprint"`
}

type portableManifestPayload struct {
	ActiveDeployment          portableDeployment   `json:"activeDeployment"`
	IssuedAtMilliseconds      int64                `json:"issuedAtMilliseconds"`
	PredecessorManifestDigest *string              `json:"predecessorManifestDigest,omitempty"`
	PreparedDeployments       []portableDeployment `json:"preparedDeployments"`
	Revision                  int64                `json:"revision"`
	Scope                     portableScope        `json:"scope"`
	Transition                string               `json:"transition"`
	TransportPolicy           portablePolicy       `json:"transportPolicy"`
	ValidFromMilliseconds     int64                `json:"validFromMilliseconds"`
	ValidUntilMilliseconds    *int64               `json:"validUntilMilliseconds,omitempty"`
	Version                   int                  `json:"version"`
}

type portableScope struct {
	Kind    string `json:"kind"`
	ScopeID string `json:"scopeID"`
}

type portableDeployment struct {
	CreatedAtMilliseconds int64           `json:"createdAtMilliseconds"`
	DeploymentID          string          `json:"deploymentID"`
	PublicSigningKeyX963  string          `json:"publicSigningKeyX963"`
	Routes                []portableRoute `json:"routes"`
	SigningKeyFingerprint string          `json:"signingKeyFingerprint"`
	Version               int             `json:"version"`
}

type portableRoute struct {
	Endpoint             string                       `json:"endpoint"`
	Kind                 string                       `json:"kind"`
	NetworkScope         string                       `json:"networkScope"`
	OnionPortability     *string                      `json:"onionPortability,omitempty"`
	OnionServiceID       *string                      `json:"onionServiceID,omitempty"`
	RouteID              string                       `json:"routeID"`
	ServerAuthentication portableServerAuthentication `json:"serverAuthentication"`
}

type portableServerAuthentication struct {
	Kind             string  `json:"kind"`
	PinnedSPKISHA256 *string `json:"pinnedSPKISHA256,omitempty"`
}

type portablePolicy struct {
	AllowsPublicDirectBulkTransfer bool     `json:"allowsPublicDirectBulkTransfer"`
	BulkRouteIDs                   []string `json:"bulkRouteIDs"`
	ControlRouteIDs                []string `json:"controlRouteIDs"`
	MessageRouteIDs                []string `json:"messageRouteIDs"`
	Version                        int      `json:"version"`
}

func TestServiceAuthorityManifestPortableFixture(t *testing.T) {
	var fixture portableServiceAuthorityFixture
	decodeStrict(t, serviceAuthorityFixture, &fixture)

	var manifest portableManifest
	decodeStrict(t, fixture.Manifest, &manifest)
	var payload portableManifestPayload
	decodeStrict(t, manifest.Payload, &payload)

	if payload.Version != 1 || payload.Revision != 1 || payload.Transition != "initial_activation" {
		t.Fatalf("unexpected authority manifest version/revision/transition: %+v", payload)
	}
	if payload.Scope.Kind != "device_sync" || payload.Scope.ScopeID == "" {
		t.Fatalf("unexpected service scope: %+v", payload.Scope)
	}
	if payload.PredecessorManifestDigest != nil || len(payload.PreparedDeployments) != 0 {
		t.Fatal("initial manifest must not have a predecessor or prepared deployment")
	}
	if payload.TransportPolicy.AllowsPublicDirectBulkTransfer {
		t.Fatal("portable private policy unexpectedly authorizes public direct bulk transfer")
	}
	assertIndependentOnionAuthentication(t, payload.ActiveDeployment.Routes)
	assertCanonicalJSON(t, manifest.Payload)
	assertManifestSignature(t, manifest)
	assertReferenceDigest(t, fixture, manifest)

	if bytes.Contains(fixture.Manifest, []byte("authorizationToken")) ||
		bytes.Contains(fixture.Manifest, []byte("contentKey")) ||
		bytes.Contains(fixture.Manifest, []byte("onionPrivate")) {
		t.Fatal("portable authority fixture contains secret or content-key material")
	}
}

func TestGoDeploymentProofPortableFixture(t *testing.T) {
	var fixture portableDeploymentProofFixture
	decodeStrict(t, serviceDeploymentProofFixture, &fixture)
	var payload struct {
		ExpiresAtMilliseconds int64           `json:"expiresAtMilliseconds"`
		IssuedAtMilliseconds  int64           `json:"issuedAtMilliseconds"`
		Request               json.RawMessage `json:"request"`
		Version               int             `json:"version"`
	}
	decodeStrict(t, fixture.Proof.Payload, &payload)
	if payload.Version != 1 || payload.IssuedAtMilliseconds != 1_000 ||
		payload.ExpiresAtMilliseconds != 301_000 ||
		!bytes.Equal(payload.Request, fixture.Request) {
		t.Fatalf("unexpected portable deployment proof: %+v", payload)
	}
	var request struct {
		Scope portableScope `json:"scope"`
	}
	if err := json.Unmarshal(fixture.Request, &request); err != nil {
		t.Fatal(err)
	}
	if request.Scope.Kind != "compute_pool" ||
		request.Scope.ScopeID != "61000000-0000-0000-0000-000000000003" {
		t.Fatalf("unexpected portable compute Pool scope: %+v", request.Scope)
	}
	assertCanonicalJSON(t, fixture.Proof.Payload)
	assertRawP256Signature(
		t,
		fixture.Proof.Signature,
		"Facets server deployment proof v1\x00",
		fixture.Proof.Payload,
	)
}

func assertIndependentOnionAuthentication(t *testing.T, routes []portableRoute) {
	t.Helper()
	for _, route := range routes {
		if route.Kind != "tor_onion" {
			continue
		}
		if route.NetworkScope != "tor_network" || route.OnionServiceID == nil ||
			route.OnionPortability == nil || *route.OnionPortability != "dedicated_portable" ||
			route.ServerAuthentication.Kind != "pinned_spki_sha256" ||
			route.ServerAuthentication.PinnedSPKISHA256 == nil {
			t.Fatalf("onion route lacks independent authenticated deployment binding: %+v", route)
		}
		return
	}
	t.Fatal("portable authority fixture has no onion route")
}

func assertManifestSignature(t *testing.T, manifest portableManifest) {
	t.Helper()
	if manifest.Signature.Algorithm != "ES256" {
		t.Fatalf("signature algorithm=%q", manifest.Signature.Algorithm)
	}
	assertRawP256Signature(
		t,
		manifest.Signature,
		manifestSignatureDomain,
		manifest.Payload,
	)
}

func assertRawP256Signature(
	t *testing.T,
	signature portableSignature,
	domain string,
	payload []byte,
) {
	t.Helper()
	if signature.Algorithm != "ES256" {
		t.Fatalf("signature algorithm=%q", signature.Algorithm)
	}
	publicBytes := decodeBase64URL(t, signature.PublicSigningKeyX963)
	x, y := elliptic.Unmarshal(elliptic.P256(), publicBytes)
	if x == nil || y == nil {
		t.Fatal("invalid X9.63 P-256 authority public key")
	}
	fingerprint := sha256.Sum256(publicBytes)
	if hex.EncodeToString(fingerprint[:]) != signature.SigningKeyFingerprint {
		t.Fatal("authority signing-key fingerprint mismatch")
	}
	rawSignature := decodeBase64URL(t, signature.Signature)
	if len(rawSignature) != 64 {
		t.Fatalf("raw ES256 signature length=%d; want 64", len(rawSignature))
	}
	signed := append([]byte(domain), payload...)
	digest := sha256.Sum256(signed)
	key := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	r := new(big.Int).SetBytes(rawSignature[:32])
	s := new(big.Int).SetBytes(rawSignature[32:])
	if !ecdsa.Verify(key, digest[:], r, s) {
		t.Fatal("Go rejected Swift service-authority signature")
	}
}

func assertReferenceDigest(
	t *testing.T,
	fixture portableServiceAuthorityFixture,
	manifest portableManifest,
) {
	t.Helper()
	canonicalSignature, err := json.Marshal(manifest.Signature)
	if err != nil {
		t.Fatal(err)
	}
	input := append([]byte(manifestReferenceDomain), manifest.Payload...)
	input = append(input, canonicalSignature...)
	digest := sha256.Sum256(input)
	if actual := hex.EncodeToString(digest[:]); actual != fixture.ReferenceDigest {
		t.Fatalf("manifest reference digest=%s; want %s", actual, fixture.ReferenceDigest)
	}
}

func assertCanonicalJSON(t *testing.T, input []byte) {
	t.Helper()
	var value any
	decodeStrict(t, input, &value)
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, input) {
		t.Fatal("Swift authority payload is not canonical sorted-key JSON")
	}
}

func decodeStrict(t *testing.T, input []byte, target any) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		t.Fatal(err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		t.Fatalf("unexpected trailing JSON value: %v", err)
	}
}

func decodeBase64URL(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		t.Fatalf("invalid canonical base64url value: %v", err)
	}
	return decoded
}
