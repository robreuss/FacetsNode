package protocol

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
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

type portableCompleteSpaceCoverageFixture struct {
	Format   string               `json:"format"`
	Warning  string               `json:"warning"`
	Coverage ReplicaStateCoverage `json:"coverage"`
}

type portableHostileJSONFixture struct {
	Format  string `json:"format"`
	Warning string `json:"warning"`
	Cases   []struct {
		Name          string `json:"name"`
		Accepted      bool   `json:"accepted"`
		JSONBase64URL string `json:"jsonBase64URL"`
	} `json:"cases"`
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

func TestCanonicalReplicaStateRootJSONRejectsAlternateAndHostileEncodings(t *testing.T) {
	fixture := loadPortableHostileJSONFixture(t)
	if fixture.Format != "facets.replica-state-hostile-json.v1" || len(fixture.Cases) != 11 {
		t.Fatalf("unexpected hostile fixture shape: %s cases=%d", fixture.Format, len(fixture.Cases))
	}
	for _, testCase := range fixture.Cases {
		bytes, err := base64.RawURLEncoding.Strict().DecodeString(testCase.JSONBase64URL)
		if err != nil {
			t.Fatalf("decode %s: %v", testCase.Name, err)
		}
		root, decodeErr := DecodeCanonicalReplicaStateRoot(bytes)
		if testCase.Accepted {
			if decodeErr != nil {
				t.Fatalf("rejected %s: %v", testCase.Name, decodeErr)
			}
			canonical, err := root.CanonicalJSON()
			if err != nil || !reflect.DeepEqual(canonical, bytes) {
				t.Fatalf("canonical mismatch %s: %v", testCase.Name, err)
			}
			normalized := root
			normalized.Coverage.Sidecars = nil
			normalized.Pieces = slices.Clone(root.Pieces)
			normalized.Pieces[0].DependencyPieceIDs = nil
			canonical, err = normalized.CanonicalJSON()
			if err != nil || !reflect.DeepEqual(canonical, bytes) {
				t.Fatalf("nil collection normalization mismatch %s: %v", testCase.Name, err)
			}
		} else if decodeErr == nil {
			t.Fatalf("hostile fixture %s accepted", testCase.Name)
		}
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

func TestReplicaStateLocalRevisionAndCaptureTimeDoNotGovernSuccessors(t *testing.T) {
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
	sameRevisionSuccessor.CheckpointID = fixture.SuccessorRoot.CheckpointID
	sameRevisionSuccessor.PredecessorRootDigest = &digest
	sameRevisionSuccessor.CapturedAtMilliseconds = 0
	if err := sameRevisionSuccessor.ValidateSuccessor(fixture.Root); err != nil {
		t.Fatalf("valid same-revision successor rejected: %v", err)
	}

	substituted := sameRevisionSuccessor
	substituted.CapturedCoreRevision = fixture.Root.CapturedCoreRevision + 1
	substituted.Pieces = slices.Clone(fixture.SuccessorRoot.Pieces)
	if err := substituted.ValidateSuccessor(fixture.Root); err == nil {
		t.Fatal("same-clock piece substitution accepted")
	}

	maximumLocalRevision := fixture.Root
	maximumLocalRevision.CapturedCoreRevision = ^uint64(0)
	maximumDigest, err := maximumLocalRevision.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	causallyAdvancedLowerRevision := fixture.SuccessorRoot
	causallyAdvancedLowerRevision.CapturedCoreRevision = 1
	causallyAdvancedLowerRevision.PredecessorRootDigest = &maximumDigest
	if err := causallyAdvancedLowerRevision.ValidateSuccessor(maximumLocalRevision); err != nil {
		t.Fatalf("causally advanced lower local revision rejected: %v", err)
	}
}

func TestReplicaStateCoveragePromotesOnceToCompleteSpace(t *testing.T) {
	fixture := loadPortableReplicaStateFixture(t)
	completeFixture := loadPortableCompleteSpaceCoverageFixture(t)
	references := make([]ReplicaStateBlobReference, 0, len(completeFixture.Coverage.Sidecars))
	for _, sidecar := range completeFixture.Coverage.Sidecars {
		references = append(references, ReplicaStateBlobReference{
			BlobID:    sidecar.Digest,
			ByteCount: sidecar.ByteCount,
		})
	}
	sort.Slice(references, func(left, right int) bool {
		return references[left].BlobID < references[right].BlobID
	})
	predecessorDigest, err := fixture.Root.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	checkpointID := fixture.SuccessorRoot.CheckpointID
	itemCount, ok := completeFixture.Coverage.canonicalItemCount()
	if !ok {
		t.Fatal("complete fixture item count overflow")
	}
	promoted := ReplicaStateRoot{
		Version:               fixture.Root.Version,
		DomainID:              fixture.Root.DomainID,
		KeyEpoch:              fixture.Root.KeyEpoch,
		CapturedCoreRevision:  fixture.Root.CapturedCoreRevision,
		CheckpointID:          checkpointID,
		PredecessorRootDigest: &predecessorDigest,
		CoveredClock:          fixture.Root.CoveredClock,
		Coverage:              completeFixture.Coverage,
		Pieces: []ReplicaStatePieceDescriptor{{
			PieceID:                "0G_PuACy792gbilqXy7FJbgb8EGYDlLasljwluqgA5s",
			ByteCount:              512,
			RequiredBlobReferences: references,
			ItemCount:              itemCount,
		}},
		CapturedAtMilliseconds: fixture.Root.CapturedAtMilliseconds + 1,
	}
	if err := promoted.ValidateSuccessor(fixture.Root); err != nil {
		t.Fatalf("canonical-to-complete promotion rejected: %v", err)
	}

	downgradeID := *fixture.SuccessorRoot.CheckpointID
	downgradeID[15] ^= 1
	promotedDigest, err := promoted.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	downgrade := ReplicaStateRoot{
		Version:                promoted.Version,
		DomainID:               promoted.DomainID,
		KeyEpoch:               promoted.KeyEpoch,
		CapturedCoreRevision:   promoted.CapturedCoreRevision + 1,
		CheckpointID:           &downgradeID,
		PredecessorRootDigest:  &promotedDigest,
		CoveredClock:           promoted.CoveredClock,
		Coverage:               fixture.Root.Coverage,
		Pieces:                 fixture.Root.Pieces,
		CapturedAtMilliseconds: promoted.CapturedAtMilliseconds + 1,
	}
	if err := downgrade.ValidateSuccessor(promoted); err == nil {
		t.Fatal("complete-to-canonical downgrade accepted")
	}
}

func TestReplicaStateBindsCheckpointIdentity(t *testing.T) {
	fixture := loadPortableReplicaStateFixture(t)
	if fixture.Root.CheckpointID != nil || fixture.SuccessorRoot.CheckpointID == nil {
		t.Fatal("fixture checkpoint identity shape is invalid")
	}

	omitted := fixture.SuccessorRoot
	omitted.CheckpointID = nil
	if err := omitted.Validate(); err == nil {
		t.Fatal("successor without checkpoint identity accepted")
	}

	substituted := fixture.SuccessorRoot
	replacementID := *fixture.SuccessorRoot.CheckpointID
	replacementID[15] ^= 1
	substituted.CheckpointID = &replacementID
	digest, err := substituted.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	if digest == fixture.ExpectedSuccessorRootDigest {
		t.Fatal("checkpoint substitution did not change root digest")
	}

	reused := fixture.SuccessorRoot
	reused.CapturedCoreRevision++
	reused.PredecessorRootDigest = &fixture.ExpectedSuccessorRootDigest
	reused.CapturedAtMilliseconds++
	if err := reused.ValidateSuccessor(fixture.SuccessorRoot); err == nil {
		t.Fatal("successor checkpoint identity reuse accepted")
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

func TestReplicaStateCoverageIsExplicitCanonicalAndNonSubstitutable(t *testing.T) {
	fixture := loadPortableReplicaStateFixture(t)
	if fixture.Root.Coverage.Profile != ReplicaStateCanonicalCoreCoverageProfile {
		t.Fatal("fixture did not declare canonical-core coverage")
	}
	count, ok := fixture.Root.Coverage.canonicalItemCount()
	if !ok || count != 150 {
		t.Fatalf("canonical item count=%d valid=%v", count, ok)
	}

	mismatched := fixture.Root
	mismatched.Coverage.CanonicalModelTypes = slices.Clone(
		fixture.Root.Coverage.CanonicalModelTypes,
	)
	mismatched.Coverage.CanonicalModelTypes[0].ItemCount = 149
	if err := mismatched.Validate(); err == nil {
		t.Fatal("coverage/item inventory mismatch accepted")
	}

	noncanonical := fixture.Root
	noncanonical.Coverage.CanonicalModelTypes = []ReplicaStateModelTypeCoverage{
		{ModelTypeRaw: 5, ItemCount: 50},
		{ModelTypeRaw: 4, ItemCount: 100},
	}
	if err := noncanonical.Validate(); err == nil {
		t.Fatal("noncanonical model-type coverage accepted")
	}

	incompleteCompleteClaim := fixture.Root
	incompleteCompleteClaim.Coverage.Profile = ReplicaStateCompleteSpaceCoverageProfile
	incompleteCompleteClaim.Coverage.ExcludedDurableScopes = []string{}
	if err := incompleteCompleteClaim.Validate(); err == nil {
		t.Fatal("incomplete complete-space coverage accepted")
	}

	digest, err := fixture.Root.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	substituted := fixture.Root
	substituted.Coverage.CanonicalModelTypes = []ReplicaStateModelTypeCoverage{
		{ModelTypeRaw: 3, ItemCount: 50},
		{ModelTypeRaw: 4, ItemCount: 100},
	}
	substitutedDigest, err := substituted.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	if substitutedDigest == digest {
		t.Fatal("coverage substitution did not change root digest")
	}
	substituted.PredecessorRootDigest = &digest
	if err := substituted.ValidateSuccessor(fixture.Root); err == nil {
		t.Fatal("same-revision coverage substitution accepted")
	}
}

func TestReplicaStateCompleteSpaceInventoryIsPortableAndContentAddressed(t *testing.T) {
	fixture := loadPortableCompleteSpaceCoverageFixture(t)
	if err := fixture.Coverage.Validate(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fixture.Coverage.CoveredSemanticScopes, replicaStateCompleteSpaceScopes) {
		t.Fatal("complete-space semantic scope mismatch")
	}
	if len(fixture.Coverage.Sidecars) != len(replicaStateCompleteSpaceSidecarKinds) {
		t.Fatal("complete-space sidecar count mismatch")
	}
	references := make([]ReplicaStateBlobReference, 0, len(fixture.Coverage.Sidecars))
	for index, sidecar := range fixture.Coverage.Sidecars {
		if sidecar.Kind != replicaStateCompleteSpaceSidecarKinds[index] {
			t.Fatalf("sidecar kind %d=%s", index, sidecar.Kind)
		}
		references = append(references, ReplicaStateBlobReference{
			BlobID: sidecar.Digest, ByteCount: sidecar.ByteCount,
		})
	}
	sort.Slice(references, func(i, j int) bool { return references[i].BlobID < references[j].BlobID })
	root := ReplicaStateRoot{
		Version:              ReplicaStateVersion,
		DomainID:             "portable-complete-space",
		KeyEpoch:             1,
		CapturedCoreRevision: 7,
		CoveredClock:         ReplicaStateCausalClock{Counters: map[string]uint64{"fixture-device": 1}},
		Coverage:             fixture.Coverage,
		Pieces: []ReplicaStatePieceDescriptor{{
			PieceID:                "0G_PuACy792gbilqXy7FJbgb8EGYDlLasljwluqgA5s",
			ByteCount:              512,
			RequiredBlobReferences: references,
			ItemCount:              5,
		}},
		CapturedAtMilliseconds: 1,
	}
	if err := root.Validate(); err != nil {
		t.Fatal(err)
	}

	missing := root
	missing.Pieces = slices.Clone(root.Pieces)
	missing.Pieces[0].RequiredBlobReferences = slices.Clone(references[:len(references)-1])
	if err := missing.Validate(); err == nil {
		t.Fatal("complete-space root accepted a missing sidecar blob")
	}

	reordered := fixture.Coverage
	reordered.Sidecars = slices.Clone(fixture.Coverage.Sidecars)
	slices.Reverse(reordered.Sidecars)
	if err := reordered.Validate(); err == nil {
		t.Fatal("complete-space coverage accepted reordered sidecars")
	}

	excluded := fixture.Coverage
	excluded.ExcludedDurableScopes = []string{"facets.document-library"}
	if err := excluded.Validate(); err == nil {
		t.Fatal("complete-space coverage accepted a durable exclusion")
	}
}

func loadPortableReplicaStateFixture(t *testing.T) portableReplicaStateFixture {
	t.Helper()
	path := filepath.Join("..", "testfixture", "replica-state-root-portable-v2.json")
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

func loadPortableCompleteSpaceCoverageFixture(t *testing.T) portableCompleteSpaceCoverageFixture {
	t.Helper()
	path := filepath.Join("..", "testfixture", "replica-complete-space-coverage-portable-v1.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixture portableCompleteSpaceCoverageFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func loadPortableHostileJSONFixture(t *testing.T) portableHostileJSONFixture {
	t.Helper()
	path := filepath.Join("..", "testfixture", "replica-state-hostile-json-v1.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixture portableHostileJSONFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}
