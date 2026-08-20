package testfixture_test

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/testfixture"
)

const deviceSyncJoinRequestFixtureSHA256 = "24be9e30766d891588556f7154cfe2ebb0ca3566e2e3ee91eb0b9e71bdd9b26c"

func TestDeviceSyncJoinRequestFixtureIsExactPortableWireContract(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("device-sync-join-request-portable-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(contents)
	if actual := hex.EncodeToString(digest[:]); actual != deviceSyncJoinRequestFixtureSHA256 {
		t.Fatalf("fixture SHA-256=%s; want %s", actual, deviceSyncJoinRequestFixtureSHA256)
	}

	fixture, err := testfixture.LoadDeviceSyncJoinRequestFixture()
	if err != nil {
		t.Fatal(err)
	}
	if fixture.Format != "facets.device-sync-join-request-fixture.v1" {
		t.Fatalf("format=%q", fixture.Format)
	}
	request, err := fixture.Request.JoinRequest()
	if err != nil {
		t.Fatal(err)
	}
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	if fixture.SponsorPresentation.Version != request.Version ||
		fixture.SponsorPresentation.RequestID == uuid.Nil ||
		fixture.SponsorPresentation.CandidateDeviceID == uuid.Nil ||
		fixture.SponsorPresentation.CandidateBootstrapPublicKey == "" ||
		fixture.SponsorPresentation.ExpiresAtMilliseconds < 0 {
		t.Fatal("sponsor presentation is invalid")
	}
	if fixture.SponsorPresentation.RequestID != request.RequestID ||
		fixture.SponsorPresentation.CandidateDeviceID != request.CandidateDeviceID ||
		fixture.SponsorPresentation.CandidateBootstrapPublicKey != request.CandidateBootstrapPublicKey {
		t.Fatal("sponsor presentation does not bind the candidate request")
	}
	if err := fixture.Bootstrap.Validate(); err != nil {
		t.Fatal(err)
	}
	if fixture.Bootstrap.RequestID != request.RequestID ||
		fixture.Bootstrap.ExpiresAtMilliseconds > request.ExpiresAtMilliseconds {
		t.Fatal("bootstrap does not bind the candidate request lifetime")
	}
	if fixture.CreateResult.RequestID != request.RequestID ||
		fixture.CreateResult.ExpiresAtMilliseconds != request.ExpiresAtMilliseconds {
		t.Fatal("create result does not bind the candidate request")
	}
}
