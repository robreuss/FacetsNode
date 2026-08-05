package testfixture

import (
	_ "embed"
	"encoding/json"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/relay"
)

//go:embed replica-relay-carrier-portable-v1.json
var relayFixture []byte

type RelayAccess struct {
	Version                  int       `json:"version"`
	TenantID                 uuid.UUID `json:"tenantID"`
	DomainID                 uuid.UUID `json:"domainID"`
	MemberID                 uuid.UUID `json:"memberID"`
	KeyEpoch                 uint64    `json:"keyEpoch"`
	EncryptionKeyMaterial    string    `json:"encryptionKeyMaterial"`
	RouterAuthorizationToken string    `json:"routerAuthorizationToken"`
}

func (a RelayAccess) Credential() relay.Credential {
	return relay.Credential{
		TenantID: a.TenantID,
		DomainID: a.DomainID,
		MemberID: a.MemberID,
		Token:    a.RouterAuthorizationToken,
	}
}

type RelayCarrier struct {
	Format                          string                   `json:"format"`
	Warning                         string                   `json:"warning"`
	PublisherAccess                 RelayAccess              `json:"publisherAccess"`
	RecipientAccess                 RelayAccess              `json:"recipientAccess"`
	PublisherRegistration           relay.MemberRegistration `json:"publisherRegistration"`
	Envelope                        relay.Envelope           `json:"envelope"`
	ExpectedEnvelopeReferenceDigest string                   `json:"expectedEnvelopeReferenceDigest"`
}

func LoadRelayCarrier() (RelayCarrier, error) {
	var fixture RelayCarrier
	err := json.Unmarshal(relayFixture, &fixture)
	return fixture, err
}
