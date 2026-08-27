package protocol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

type portableReplicaStateFixture struct {
	Format                      string           `json:"format"`
	Warning                     string           `json:"warning"`
	Root                        ReplicaStateRoot `json:"root"`
	ExpectedRootDigest          string           `json:"expectedRootDigest"`
	SuccessorRoot               ReplicaStateRoot `json:"successorRoot"`
	ExpectedSuccessorRootDigest string           `json:"expectedSuccessorRootDigest"`
}

func TestPortableReplicaStateRoots(t *testing.T) {
	fixture := loadPortableReplicaStateFixture(t)
	if err := fixture.Root.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := fixture.SuccessorRoot.ValidateSuccessor(fixture.Root); err != nil {
		t.Fatal(err)
	}
	rootDigest, err := fixture.Root.ReferenceDigest()
	if err != nil || rootDigest != fixture.ExpectedRootDigest {
		t.Fatalf("root digest=%s error=%v", rootDigest, err)
	}
	successorDigest, err := fixture.SuccessorRoot.ReferenceDigest()
	if err != nil || successorDigest != fixture.ExpectedSuccessorRootDigest {
		t.Fatalf("successor digest=%s error=%v", successorDigest, err)
	}
	if fixture.Root.Pieces[0].PieceID != fixture.SuccessorRoot.Pieces[0].PieceID {
		t.Fatal("successor did not structurally share the unchanged piece")
	}
}

func TestReplicaStateRejectsGraphAndSuccessorTampering(t *testing.T) {
	fixture := loadPortableReplicaStateFixture(t)
	missing := fixture.Root
	missing.Pieces = slices.Clone(missing.Pieces)
	missing.Pieces[1].DependencyPieceIDs = []string{
		"b_CxO9i2h4yCpjK_EH0jKbroC_ydlvUkXByT_x7gO6I",
	}
	if err := missing.Validate(); err == nil {
		t.Fatal("missing dependency accepted")
	}

	cycle := fixture.Root
	cycle.Pieces = slices.Clone(cycle.Pieces)
	cycle.Pieces[0].DependencyPieceIDs = []string{cycle.Pieces[1].PieceID}
	if err := cycle.Validate(); err == nil {
		t.Fatal("piece cycle accepted")
	}

	rollback := fixture.SuccessorRoot
	rollback.CoveredClock.Counters = map[string]uint64{"device-a": 11, "device-b": 10}
	if err := rollback.ValidateSuccessor(fixture.Root); err == nil {
		t.Fatal("causal rollback accepted")
	}

	fork := fixture.SuccessorRoot
	fork.PredecessorRootDigest = &fixture.ExpectedSuccessorRootDigest
	if err := fork.ValidateSuccessor(fixture.Root); err == nil {
		t.Fatal("conflicting predecessor accepted")
	}
}

func loadPortableReplicaStateFixture(t *testing.T) portableReplicaStateFixture {
	t.Helper()
	path := filepath.Join("..", "testfixture", "replica-state-root-portable-v1.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixture portableReplicaStateFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}
