package testfixture_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/robreuss/FacetsNode/internal/testfixture"
)

const secureRosterFixtureSHA256 = "0a6a21ca7bb79821137bd9a039fe6c17a082c19be3fbf40eb4daadb55098a172"

func TestSecureSharedSpaceRosterFixtureIsExactPortableAuthorityContract(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("shared-space-secure-roster-attestation-portable-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(contents)
	if actual := hex.EncodeToString(digest[:]); actual != secureRosterFixtureSHA256 {
		t.Fatalf("fixture SHA-256=%s; want %s", actual, secureRosterFixtureSHA256)
	}

	fixture, err := testfixture.LoadSecureRosterFixture()
	if err != nil {
		t.Fatal(err)
	}
	if fixture.Format != "facets.shared-space-secure-roster-attestation-fixture.v1" {
		t.Fatalf("format=%q", fixture.Format)
	}
	if err := fixture.Initial.Validate(); err != nil {
		t.Fatalf("initial: %v", err)
	}
	if err := fixture.Successor.ValidateSuccessor(
		fixture.Initial,
		fixture.Successor.Participants,
		fixture.Successor.CurrentKeyEpoch,
	); err != nil {
		t.Fatalf("successor: %v", err)
	}
	initialDigest, err := fixture.Initial.Digest()
	if err != nil {
		t.Fatal(err)
	}
	successorDigest, err := fixture.Successor.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if initialDigest != fixture.ExpectedInitialDigest || successorDigest != fixture.ExpectedSuccessorDigest {
		t.Fatalf("authority digests initial=%s successor=%s", initialDigest, successorDigest)
	}
	initialPayload, err := fixture.Initial.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	successorPayload, err := fixture.Successor.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	if base64.RawURLEncoding.EncodeToString(initialPayload) != fixture.ExpectedInitialSigningPayloadBase64 ||
		base64.RawURLEncoding.EncodeToString(successorPayload) != fixture.ExpectedSuccessorSigningPayloadBase64 {
		t.Fatal("Secure roster signing payload differs from portable fixture")
	}
}
