package testfixture

import (
	_ "embed"
	"encoding/json"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/relay"
)

//go:embed relay-member-admission-portable-v1.json
var admissionFixture []byte

type RelayAdmissionCredential struct {
	TenantID           uuid.UUID `json:"tenantID"`
	DomainID           uuid.UUID `json:"domainID"`
	AdmissionID        uuid.UUID `json:"admissionID"`
	AuthorizationToken string    `json:"authorizationToken"`
}

func (c RelayAdmissionCredential) Credential() relay.AdmissionCredential {
	return relay.AdmissionCredential{
		TenantID:    c.TenantID,
		DomainID:    c.DomainID,
		AdmissionID: c.AdmissionID,
		Token:       c.AuthorizationToken,
	}
}

type RelayMemberCredential struct {
	TenantID           uuid.UUID `json:"tenantID"`
	DomainID           uuid.UUID `json:"domainID"`
	MemberID           uuid.UUID `json:"memberID"`
	AuthorizationToken string    `json:"authorizationToken"`
}

func (c RelayMemberCredential) Credential() relay.Credential {
	return relay.Credential{
		TenantID: c.TenantID,
		DomainID: c.DomainID,
		MemberID: c.MemberID,
		Token:    c.AuthorizationToken,
	}
}

type RelayAdmissionCreateRequest struct {
	AdmissionID           uuid.UUID          `json:"admissionID"`
	AuthorizationDigest   string             `json:"authorizationDigest"`
	Capabilities          []relay.Capability `json:"capabilities"`
	ExpiresAtMilliseconds int64              `json:"expiresAtMilliseconds"`
}

type RelayMemberAdmissionFixture struct {
	Format                               string                      `json:"format"`
	Warning                              string                      `json:"warning"`
	AdmissionCredential                  RelayAdmissionCredential    `json:"admissionCredential"`
	ExpectedAdmissionAuthorizationDigest string                      `json:"expectedAdmissionAuthorizationDigest"`
	MemberCredential                     RelayMemberCredential       `json:"memberCredential"`
	ExpectedMemberAuthorizationDigest    string                      `json:"expectedMemberAuthorizationDigest"`
	CreateRequest                        RelayAdmissionCreateRequest `json:"createRequest"`
	ClaimRequest                         relay.MemberAdmissionClaim  `json:"claimRequest"`
}

func LoadRelayMemberAdmission() (RelayMemberAdmissionFixture, error) {
	var fixture RelayMemberAdmissionFixture
	err := json.Unmarshal(admissionFixture, &fixture)
	return fixture, err
}
