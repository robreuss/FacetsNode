package protocol

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
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

func TestReplicaStateAllowsRevisionZeroAndIgnoresSenderCaptureTime(t *testing.T) {
	fixture := loadPortableReplicaStateFixture(t)
	emptyRevision := fixture.Root
	emptyRevision.CapturedCoreRevision = 0
	if err := emptyRevision.Validate(); err != nil {
		t.Fatalf("revision zero rejected: %v", err)
	}

	digest, err := fixture.Root.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	sameRevisionSuccessor := fixture.Root
	sameRevisionSuccessor.PredecessorRootDigest = &digest
	sameRevisionSuccessor.CapturedAtMilliseconds = 0
	if err := sameRevisionSuccessor.ValidateSuccessor(fixture.Root); err != nil {
		t.Fatalf("valid same-revision successor rejected: %v", err)
	}

	substituted := sameRevisionSuccessor
	substituted.Pieces = slices.Clone(fixture.SuccessorRoot.Pieces)
	if err := substituted.ValidateSuccessor(fixture.Root); err == nil {
		t.Fatal("same-revision piece substitution accepted")
	}
}

func TestReplicaStateEnforcesPortableResourceCeilings(t *testing.T) {
	fixture := loadPortableReplicaStateFixture(t)
	first := fixture.Root.Pieces[0]

	tooManyPieces := fixture.Root
	tooManyPieces.Pieces = make(
		[]ReplicaStatePieceDescriptor,
		ReplicaStateMaximumPieceCount+1,
	)
	for index := range tooManyPieces.Pieces {
		tooManyPieces.Pieces[index] = first
	}
	if err := tooManyPieces.Validate(); err == nil {
		t.Fatal("piece ceiling not enforced")
	}

	tooManyDependencies := first
	tooManyDependencies.DependencyPieceIDs = make(
		[]string,
		ReplicaStateMaximumDependenciesPerPiece+1,
	)
	for index := range tooManyDependencies.DependencyPieceIDs {
		tooManyDependencies.DependencyPieceIDs[index] = fixture.Root.Pieces[1].PieceID
	}
	if err := tooManyDependencies.Validate(); err == nil {
		t.Fatal("per-piece dependency ceiling not enforced")
	}

	tooManyBlobReferences := first
	tooManyBlobReferences.RequiredBlobReferences = make(
		[]ReplicaStateBlobReference,
		ReplicaStateMaximumBlobReferencesPerPiece+1,
	)
	for index := range tooManyBlobReferences.RequiredBlobReferences {
		tooManyBlobReferences.RequiredBlobReferences[index] = first.RequiredBlobReferences[0]
	}
	if err := tooManyBlobReferences.Validate(); err == nil {
		t.Fatal("per-piece blob-reference ceiling not enforced")
	}

	tooManyClockEntries := fixture.Root
	tooManyClockEntries.CoveredClock.Counters = make(
		map[string]uint64,
		ReplicaStateMaximumClockEntryCount+1,
	)
	for index := 0; index <= ReplicaStateMaximumClockEntryCount; index++ {
		tooManyClockEntries.CoveredClock.Counters[fmt.Sprintf("replica-%d", index)] = 1
	}
	if err := tooManyClockEntries.Validate(); err == nil {
		t.Fatal("clock-entry ceiling not enforced")
	}

	oversizedIdentifier := strings.Repeat(
		"é",
		ReplicaStateMaximumIdentifierByteCount/2+1,
	)
	oversizedDomain := fixture.Root
	oversizedDomain.DomainID = oversizedIdentifier
	if err := oversizedDomain.Validate(); err == nil {
		t.Fatal("domain identifier byte ceiling not enforced")
	}
	oversizedClockID := fixture.Root
	oversizedClockID.CoveredClock.Counters = map[string]uint64{oversizedIdentifier: 1}
	if err := oversizedClockID.Validate(); err == nil {
		t.Fatal("clock identifier byte ceiling not enforced")
	}

	pieceIDs := make([]string, ReplicaStateMaximumDependenciesPerPiece+1)
	for index := range pieceIDs {
		digest := sha256.Sum256([]byte(fmt.Sprintf("bounded-piece-%d", index)))
		pieceIDs[index] = base64.RawURLEncoding.EncodeToString(digest[:])
	}
	sort.Strings(pieceIDs)
	denseGraph := make([]ReplicaStatePieceDescriptor, len(pieceIDs))
	for pieceIndex, pieceID := range pieceIDs {
		dependencies := make([]string, 0, ReplicaStateMaximumDependenciesPerPiece)
		for _, candidate := range pieceIDs {
			if candidate != pieceID {
				dependencies = append(dependencies, candidate)
			}
		}
		denseGraph[pieceIndex] = ReplicaStatePieceDescriptor{
			PieceID:            pieceID,
			ByteCount:          1,
			DependencyPieceIDs: dependencies,
		}
	}
	denseRoot := fixture.Root
	denseRoot.Pieces = denseGraph
	if err := denseRoot.Validate(); err == nil {
		t.Fatal("total dependency-edge ceiling not enforced")
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
