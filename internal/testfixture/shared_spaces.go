package testfixture

import (
	_ "embed"
	"encoding/json"

	"github.com/robreuss/FacetsNode/internal/sharedspaces"
)

//go:embed shared-space-secure-roster-attestation-portable-v1.json
var secureRosterFixture []byte

// SecureRosterFixture is a portable, signed authority transition. It fixes
// both the canonical signing bytes and the predecessor digest used by Secure
// Shared Space clients, irrespective of transport implementation.
type SecureRosterFixture struct {
	Format                                string                               `json:"format"`
	Warning                               string                               `json:"warning"`
	Initial                               sharedspaces.SecureRosterAttestation `json:"initial"`
	Successor                             sharedspaces.SecureRosterAttestation `json:"successor"`
	ExpectedInitialDigest                 string                               `json:"expectedInitialDigest"`
	ExpectedSuccessorDigest               string                               `json:"expectedSuccessorDigest"`
	ExpectedInitialSigningPayloadBase64   string                               `json:"expectedInitialSigningPayloadBase64"`
	ExpectedSuccessorSigningPayloadBase64 string                               `json:"expectedSuccessorSigningPayloadBase64"`
}

func LoadSecureRosterFixture() (SecureRosterFixture, error) {
	var fixture SecureRosterFixture
	err := json.Unmarshal(secureRosterFixture, &fixture)
	return fixture, err
}
