package testfixture_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"strconv"
	"strings"
	"testing"
)

const (
	jobCapsuleManifestDigestDomain     = "facets.job-capsule.manifest-canonical.v1"
	jobCapsuleManifestSignatureDomain  = "facets.job-capsule.manifest-signature-payload.v1"
	jobCapsuleManifestSignatureProfile = "facets.p256-sha256.utf8-digest-v1"
)

//go:embed job-capsule-manifest-signature-portable-v1.json
var jobCapsuleManifestSignatureFixture []byte

type portableJobCapsuleManifestSignatureVector struct {
	CanonicalManifestDigest string `json:"canonicalManifestDigest"`
	CanonicalManifestJSON   string `json:"canonicalManifestJSON"`
	ProtocolVersion         int    `json:"protocolVersion"`
	PublicKeyX963Base64URL  string `json:"publicKeyX963Base64URL"`
	SignatureProfileID      string `json:"signatureProfileID"`
	SignatureRawBase64URL   string `json:"signatureRawBase64URL"`
	SignerID                string `json:"signerID"`
	SigningKeyID            string `json:"signingKeyID"`
	SigningKeyRevision      uint64 `json:"signingKeyRevision"`
	SigningPayloadDigest    string `json:"signingPayloadDigest"`
	SyntheticTestOnly       bool   `json:"syntheticTestOnly"`
}

func TestJobCapsuleManifestSignaturePortableKnownAnswer(t *testing.T) {
	vector := loadJobCapsuleManifestSignatureVector(t)
	if vector.ProtocolVersion != 1 || !vector.SyntheticTestOnly || vector.SignatureProfileID != jobCapsuleManifestSignatureProfile {
		t.Fatalf("unexpected portable Job Capsule signature profile: %+v", vector)
	}

	manifest := assertCanonicalJobCapsuleManifest(t, vector)
	manifestDigest := jobCapsulePortableDigest(
		jobCapsuleManifestDigestDomain,
		vector.CanonicalManifestJSON,
	)
	if manifestDigest != vector.CanonicalManifestDigest {
		t.Fatalf("canonical manifest digest mismatch: got %s want %s", manifestDigest, vector.CanonicalManifestDigest)
	}
	payloadDigest := jobCapsuleManifestPayloadDigest(vector, manifestDigest)
	if payloadDigest != vector.SigningPayloadDigest {
		t.Fatalf("signing payload digest mismatch: got %s want %s", payloadDigest, vector.SigningPayloadDigest)
	}

	assertManifestSigner(t, manifest, vector)
	publicKey := decodeJobCapsulePublicKey(t, vector.PublicKeyX963Base64URL)
	signature := decodeRawJobCapsuleSignature(t, vector.SignatureRawBase64URL)
	if !verifyJobCapsuleManifestSignature(publicKey, signature, payloadDigest) {
		t.Fatal("Go rejected Swift Job Capsule manifest signature")
	}
}

func TestJobCapsuleManifestSignatureRejectsBoundInputMutations(t *testing.T) {
	vector := loadJobCapsuleManifestSignatureVector(t)
	publicKey := decodeJobCapsulePublicKey(t, vector.PublicKeyX963Base64URL)
	signature := decodeRawJobCapsuleSignature(t, vector.SignatureRawBase64URL)

	changedSignature := append([]byte(nil), signature...)
	changedSignature[len(changedSignature)-1] ^= 0xff
	if verifyJobCapsuleManifestSignature(publicKey, changedSignature, vector.SigningPayloadDigest) {
		t.Fatal("changed manifest signature verified")
	}

	changedManifest := strings.Replace(
		vector.CanonicalManifestJSON,
		`"cancellationFence":6`,
		`"cancellationFence":7`,
		1,
	)
	if changedManifest == vector.CanonicalManifestJSON {
		t.Fatal("fixture manifest mutation did not apply")
	}
	changedManifestDigest := jobCapsulePortableDigest(
		jobCapsuleManifestDigestDomain,
		changedManifest,
	)
	changedPayloadDigest := jobCapsuleManifestPayloadDigest(
		vector,
		changedManifestDigest,
	)
	if verifyJobCapsuleManifestSignature(publicKey, signature, changedPayloadDigest) {
		t.Fatal("changed canonical manifest verified")
	}

	changedSigner := vector
	changedSigner.SignerID = "job-capsule.other-source"
	changedSignerDigest := jobCapsuleManifestPayloadDigest(
		changedSigner,
		vector.CanonicalManifestDigest,
	)
	if verifyJobCapsuleManifestSignature(publicKey, signature, changedSignerDigest) {
		t.Fatal("changed manifest signer verified")
	}
}

func loadJobCapsuleManifestSignatureVector(t *testing.T) portableJobCapsuleManifestSignatureVector {
	t.Helper()
	var vector portableJobCapsuleManifestSignatureVector
	decodeStrict(t, jobCapsuleManifestSignatureFixture, &vector)
	return vector
}

func assertCanonicalJobCapsuleManifest(
	t *testing.T,
	vector portableJobCapsuleManifestSignatureVector,
) map[string]any {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(vector.CanonicalManifestJSON))
	decoder.UseNumber()
	var manifest map[string]any
	if err := decoder.Decode(&manifest); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatalf("manifest has trailing JSON: %v", err)
	}
	canonical, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonical, []byte(vector.CanonicalManifestJSON)) {
		t.Fatalf("manifest is not canonical sorted-key JSON\n got=%s\nwant=%s", canonical, vector.CanonicalManifestJSON)
	}
	return manifest
}

func assertManifestSigner(
	t *testing.T,
	manifest map[string]any,
	vector portableJobCapsuleManifestSignatureVector,
) {
	t.Helper()
	signer, ok := manifest["sourceManifestSigner"].(map[string]any)
	if !ok || signer["signerID"] != vector.SignerID || signer["signingKeyID"] != vector.SigningKeyID || signer["signatureProfileID"] != vector.SignatureProfileID || signer["signingKeyRevision"] != json.Number(strconv.FormatUint(vector.SigningKeyRevision, 10)) {
		t.Fatalf("manifest signer does not match portable trust binding: %#v", signer)
	}
}

func jobCapsuleManifestPayloadDigest(
	vector portableJobCapsuleManifestSignatureVector,
	manifestDigest string,
) string {
	return jobCapsulePortableDigest(
		jobCapsuleManifestSignatureDomain,
		strconv.Itoa(vector.ProtocolVersion),
		vector.SignerID,
		vector.SigningKeyID,
		strconv.FormatUint(vector.SigningKeyRevision, 10),
		vector.SignatureProfileID,
		manifestDigest,
	)
}

func jobCapsulePortableDigest(domain string, components ...string) string {
	hasher := sha256.New()
	for _, component := range append([]string{domain}, components...) {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len([]byte(component))))
		_, _ = hasher.Write(length[:])
		_, _ = hasher.Write([]byte(component))
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func decodeJobCapsulePublicKey(t *testing.T, encoded string) *ecdsa.PublicKey {
	t.Helper()
	bytes := decodeRawJobCapsuleBase64URL(t, encoded, 65)
	x, y := elliptic.Unmarshal(elliptic.P256(), bytes)
	if x == nil || y == nil {
		t.Fatal("invalid P-256 public key")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
}

func decodeRawJobCapsuleSignature(t *testing.T, encoded string) []byte {
	t.Helper()
	return decodeRawJobCapsuleBase64URL(t, encoded, 64)
}

func decodeRawJobCapsuleBase64URL(t *testing.T, encoded string, expectedBytes int) []byte {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != expectedBytes || base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		t.Fatalf("noncanonical base64url length=%d err=%v", len(decoded), err)
	}
	return decoded
}

func verifyJobCapsuleManifestSignature(
	publicKey *ecdsa.PublicKey,
	signature []byte,
	payloadDigest string,
) bool {
	if len(signature) != 64 {
		return false
	}
	digest := sha256.Sum256([]byte(payloadDigest))
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	return ecdsa.Verify(publicKey, digest[:], r, s)
}
