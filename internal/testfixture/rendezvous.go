package testfixture

import (
	_ "embed"
	"encoding/json"

	"github.com/robreuss/FacetsNode/internal/rendezvous"
)

//go:embed principal-pairing-rendezvous-portable-v1.json
var rendezvousFixture []byte

type Access struct {
	RouteID                  string          `json:"routeID"`
	Role                     rendezvous.Role `json:"role"`
	EncryptionKeyMaterial    string          `json:"encryptionKeyMaterial"`
	RouterAuthorizationToken string          `json:"routerAuthorizationToken"`
}

type Expected struct {
	EnvelopeReferenceDigest string `json:"envelopeReferenceDigest"`
}

type Rendezvous struct {
	Format          string                  `json:"format"`
	Warning         string                  `json:"warning"`
	Registration    rendezvous.Registration `json:"registration"`
	Envelope        rendezvous.Envelope     `json:"envelope"`
	SponsorAccess   Access                  `json:"sponsorAccess"`
	CandidateAccess Access                  `json:"candidateAccess"`
	Expected        Expected                `json:"expected"`
}

func LoadRendezvous() (Rendezvous, error) {
	var fixture Rendezvous
	err := json.Unmarshal(rendezvousFixture, &fixture)
	return fixture, err
}
