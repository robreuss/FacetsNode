package testfixture

import (
	_ "embed"
	"encoding/json"

	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

//go:embed bulk-transfer-grant-portable-v1.json
var bulkTransferGrantFixture []byte

type BulkTransferGrantFixture struct {
	Format            string                            `json:"format"`
	Warning           string                            `json:"warning"`
	AuthorityRevision uint64                            `json:"authorityRevision"`
	GrantHeader       string                            `json:"grantHeader"`
	Expected          serviceauthority.BulkGrantPayload `json:"expected"`
}

func LoadBulkTransferGrantFixture() (BulkTransferGrantFixture, error) {
	var fixture BulkTransferGrantFixture
	err := json.Unmarshal(bulkTransferGrantFixture, &fixture)
	return fixture, err
}
