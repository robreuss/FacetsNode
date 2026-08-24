package computepool

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

//go:embed compute-pool-contracts-portable-v2.json
var portableContractFixture []byte

type portableFixture struct {
	Binding           SpaceBinding       `json:"binding"`
	Offerings         []Offering         `json:"offerings"`
	Pool              Pool               `json:"pool"`
	PoolAuthority     AuthorityReference `json:"poolAuthority"`
	Version           int                `json:"version"`
	WorkerCards       []WorkerCard       `json:"workerCards"`
	WorkerEnrollments []WorkerEnrollment `json:"workerEnrollments"`
}

func TestPortableComputePoolContractsMatchSwiftFixture(t *testing.T) {
	var fixture portableFixture
	decodeStrict(t, portableContractFixture, &fixture)
	if fixture.Version != SchemaVersion || fixture.Pool.Validate() != nil ||
		fixture.PoolAuthority.Validate() != nil || fixture.Binding.Validate() != nil ||
		len(fixture.WorkerEnrollments) != 3 || len(fixture.WorkerCards) != 3 ||
		len(fixture.Offerings) != 3 {
		t.Fatalf("portable Compute Pool fixture failed validation: %+v", fixture)
	}
	for index := range fixture.WorkerEnrollments {
		enrollment := fixture.WorkerEnrollments[index]
		card := fixture.WorkerCards[index]
		offering := fixture.Offerings[index]
		cardDigest, err := card.Digest()
		if enrollment.Validate() != nil || card.Validate() != nil || offering.Validate() != nil ||
			enrollment.PoolID != fixture.Pool.PoolID || card.PoolID != fixture.Pool.PoolID ||
			offering.PoolID != fixture.Pool.PoolID || card.WorkerEnrollmentID != enrollment.EnrollmentID ||
			offering.WorkerEnrollmentID != enrollment.EnrollmentID || offering.WorkerCardID != card.WorkerCardID ||
			offering.WorkerCardRevision != card.Revision || err != nil || offering.WorkerCardDigest != cardDigest {
			t.Fatalf("portable Worker/Card/offering %d failed validation", index)
		}
	}
	if fixture.Pool.PoolID != fixture.PoolAuthority.PoolID ||
		fixture.Binding.PoolAuthority != fixture.PoolAuthority ||
		fixture.Binding.SpaceID == fixture.Pool.PoolID ||
		fixture.WorkerEnrollments[0].WorkerOwnerAuthorityID == fixture.Pool.OwnerAuthorityID {
		t.Fatal("portable fixture collapsed Pool, Space, Worker, or owner authority")
	}
	var generic any
	if err := json.Unmarshal(portableContractFixture, &generic); err != nil {
		t.Fatal(err)
	}
	canonical, err := json.Marshal(generic)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonical, bytes.TrimSpace(portableContractFixture)) {
		t.Fatal("portable Compute Pool fixture is not canonical sorted-key JSON")
	}
}

func TestContractsRejectSpaceOwnedPoolAndImplicitWorkerConsent(t *testing.T) {
	var fixture portableFixture
	decodeStrict(t, portableContractFixture, &fixture)

	wrongAuthority := fixture.PoolAuthority
	wrongAuthority.TrustAnchor.Scope.ScopeID = uuid.New()
	if err := wrongAuthority.Validate(); !errorsIsInvalid(err) {
		t.Fatalf("cross-Pool authority reference accepted: %v", err)
	}

	unenrolled := fixture.WorkerEnrollments[0]
	unenrolled.ConsentRevision = 0
	if err := unenrolled.Validate(); !errorsIsInvalid(err) {
		t.Fatalf("Worker without consent revision accepted: %v", err)
	}

	implicitEligibility := fixture.Binding
	implicitEligibility.EligiblePrincipalIDs = nil
	implicitEligibility.EligibleRoleIdentifiers = nil
	if err := implicitEligibility.Validate(); !errorsIsInvalid(err) {
		t.Fatalf("binding with implicit eligibility accepted: %v", err)
	}
}

func TestSchemaV1AndFreeFormHandlingFieldsAreRejected(t *testing.T) {
	var generic map[string]any
	if err := json.Unmarshal(portableContractFixture, &generic); err != nil {
		t.Fatal(err)
	}
	generic["version"] = float64(1)
	encoded, _ := json.Marshal(generic)
	var fixture portableFixture
	decodeStrict(t, encoded, &fixture)
	if fixture.Version == SchemaVersion {
		t.Fatal("schema v1 fixture accepted")
	}

	offering := map[string]any{}
	encodedOffering, _ := json.Marshal(genericFixtureOffering(t, 0))
	if err := json.Unmarshal(encodedOffering, &offering); err != nil {
		t.Fatal(err)
	}
	offering["retentionDeclaration"] = "provider-retention-v1"
	mutated, _ := json.Marshal(offering)
	decoder := json.NewDecoder(bytes.NewReader(mutated))
	decoder.DisallowUnknownFields()
	var decoded Offering
	if err := decoder.Decode(&decoded); err == nil {
		t.Fatal("free-form v1 handling field accepted")
	}
}

func genericFixtureOffering(t *testing.T, index int) any {
	t.Helper()
	var fixture map[string]any
	if err := json.Unmarshal(portableContractFixture, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture["offerings"].([]any)[index]
}

func decodeStrict(t *testing.T, input []byte, target any) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		t.Fatal(err)
	}
}

func errorsIsInvalid(err error) bool {
	return err == ErrInvalid
}
