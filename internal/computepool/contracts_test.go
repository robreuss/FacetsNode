package computepool

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

//go:embed compute-pool-contracts-portable-v1.json
var portableContractFixture []byte

type portableFixture struct {
	Binding          SpaceBinding       `json:"binding"`
	Offering         Offering           `json:"offering"`
	Pool             Pool               `json:"pool"`
	PoolAuthority    AuthorityReference `json:"poolAuthority"`
	Version          int                `json:"version"`
	WorkerEnrollment WorkerEnrollment   `json:"workerEnrollment"`
}

func TestPortableComputePoolContractsMatchSwiftFixture(t *testing.T) {
	var fixture portableFixture
	decodeStrict(t, portableContractFixture, &fixture)
	if fixture.Version != SchemaVersion || fixture.Pool.Validate() != nil ||
		fixture.PoolAuthority.Validate() != nil || fixture.WorkerEnrollment.Validate() != nil ||
		fixture.Offering.Validate() != nil || fixture.Binding.Validate() != nil {
		t.Fatalf("portable Compute Pool fixture failed validation: %+v", fixture)
	}
	if fixture.Pool.PoolID != fixture.PoolAuthority.PoolID ||
		fixture.WorkerEnrollment.PoolID != fixture.Pool.PoolID ||
		fixture.Offering.WorkerEnrollmentID != fixture.WorkerEnrollment.EnrollmentID ||
		fixture.Binding.PoolAuthority != fixture.PoolAuthority ||
		fixture.Binding.SpaceID == fixture.Pool.PoolID ||
		fixture.WorkerEnrollment.WorkerOwnerAuthorityID == fixture.Pool.OwnerAuthorityID {
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

	unenrolled := fixture.WorkerEnrollment
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
