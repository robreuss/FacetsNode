package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
)

const (
	ReplicaStateVersion                         = 1
	ReplicaStateMaximumPieceCount               = 4_096
	ReplicaStateMaximumTotalDependencyEdgeCount = 65_536
	ReplicaStateMaximumDependenciesPerPiece     = 256
	ReplicaStateMaximumBlobReferencesPerPiece   = 4_096
	ReplicaStateMaximumClockEntryCount          = 4_096
	ReplicaStateMaximumIdentifierByteCount      = 1_024
)

var (
	ErrInvalidReplicaState          = errors.New("invalid replica state root")
	ErrInvalidReplicaStatePiece     = errors.New("invalid replica state piece")
	ErrReplicaStateDependency       = errors.New("invalid replica state piece dependency")
	ErrReplicaStateBlobCollision    = errors.New("replica state blob identity collision")
	ErrReplicaStatePredecessor      = errors.New("replica state predecessor digest mismatch")
	ErrInvalidReplicaStateSuccessor = errors.New("invalid replica state successor")
)

var replicaStateRootDigestDomain = []byte("Facets replica state root v1\x00")

// ReplicaStateBlobReference names exact source bytes inside the encrypted
// client root. FacetsNode's relay does not decode this structure.
type ReplicaStateBlobReference struct {
	BlobID    string `json:"blobID"`
	ByteCount int64  `json:"byteCount"`
}

type ReplicaStatePieceDescriptor struct {
	PieceID                string                      `json:"pieceID"`
	ByteCount              int64                       `json:"byteCount"`
	DependencyPieceIDs     []string                    `json:"dependencyPieceIDs"`
	RequiredBlobReferences []ReplicaStateBlobReference `json:"requiredBlobReferences"`
	ItemCount              uint64                      `json:"itemCount"`
}

func (piece ReplicaStatePieceDescriptor) Validate() error {
	if len(piece.DependencyPieceIDs) > ReplicaStateMaximumDependenciesPerPiece ||
		len(piece.RequiredBlobReferences) > ReplicaStateMaximumBlobReferencesPerPiece ||
		!isReplicaStateDigest(piece.PieceID) || piece.ByteCount <= 0 ||
		!canonicalDigestStrings(piece.DependencyPieceIDs) {
		return fmt.Errorf("%w: %s", ErrInvalidReplicaStatePiece, piece.PieceID)
	}
	for _, dependency := range piece.DependencyPieceIDs {
		if dependency == piece.PieceID {
			return fmt.Errorf("%w: self dependency %s", ErrReplicaStateDependency, piece.PieceID)
		}
	}
	previous := ""
	seen := make(map[string]int64, len(piece.RequiredBlobReferences))
	for _, reference := range piece.RequiredBlobReferences {
		if !isReplicaStateDigest(reference.BlobID) || reference.ByteCount < 0 ||
			(previous != "" && previous >= reference.BlobID) {
			return fmt.Errorf("%w: %s", ErrInvalidReplicaStatePiece, piece.PieceID)
		}
		if count, exists := seen[reference.BlobID]; exists && count != reference.ByteCount {
			return fmt.Errorf("%w: %s", ErrReplicaStateBlobCollision, reference.BlobID)
		}
		seen[reference.BlobID] = reference.ByteCount
		previous = reference.BlobID
	}
	return nil
}

type ReplicaStateCausalClock struct {
	Counters map[string]uint64 `json:"counters"`
}

type ReplicaStateRoot struct {
	Version                int                           `json:"version"`
	DomainID               string                        `json:"domainID"`
	KeyEpoch               uint64                        `json:"keyEpoch"`
	CapturedCoreRevision   uint64                        `json:"capturedCoreRevision"`
	PredecessorRootDigest  *string                       `json:"predecessorRootDigest,omitempty"`
	CoveredClock           ReplicaStateCausalClock       `json:"coveredClock"`
	PredecessorMessageIDs  []uuid.UUID                   `json:"predecessorMessageIDs"`
	Pieces                 []ReplicaStatePieceDescriptor `json:"pieces"`
	CapturedAtMilliseconds int64                         `json:"capturedAtMilliseconds"`
}

func (root ReplicaStateRoot) Validate() error {
	if root.Version != ReplicaStateVersion || root.DomainID == "" ||
		root.DomainID != strings.TrimSpace(root.DomainID) ||
		len(root.DomainID) > ReplicaStateMaximumIdentifierByteCount ||
		root.KeyEpoch == 0 || root.CapturedAtMilliseconds < 0 || len(root.Pieces) == 0 ||
		len(root.Pieces) > ReplicaStateMaximumPieceCount ||
		len(root.CoveredClock.Counters) > ReplicaStateMaximumClockEntryCount {
		return ErrInvalidReplicaState
	}
	if root.PredecessorRootDigest != nil && !isReplicaStateDigest(*root.PredecessorRootDigest) {
		return ErrInvalidReplicaState
	}
	for replicaID, sequence := range root.CoveredClock.Counters {
		if replicaID == "" || replicaID != strings.TrimSpace(replicaID) ||
			len(replicaID) > ReplicaStateMaximumIdentifierByteCount || sequence == 0 {
			return ErrInvalidReplicaState
		}
	}
	for index, messageID := range root.PredecessorMessageIDs {
		if messageID == uuid.Nil || (index > 0 &&
			strings.ToLower(root.PredecessorMessageIDs[index-1].String()) >=
				strings.ToLower(messageID.String())) {
			return ErrInvalidReplicaState
		}
	}

	pieceByID := make(map[string]ReplicaStatePieceDescriptor, len(root.Pieces))
	blobByteCounts := make(map[string]int64)
	previousPieceID := ""
	totalDependencyEdgeCount := 0
	for _, piece := range root.Pieces {
		if len(piece.DependencyPieceIDs) >
			ReplicaStateMaximumTotalDependencyEdgeCount-totalDependencyEdgeCount {
			return ErrInvalidReplicaState
		}
		totalDependencyEdgeCount += len(piece.DependencyPieceIDs)
		if err := piece.Validate(); err != nil {
			return err
		}
		if previousPieceID != "" && previousPieceID >= piece.PieceID {
			return ErrInvalidReplicaState
		}
		if _, exists := pieceByID[piece.PieceID]; exists {
			return fmt.Errorf("%w: duplicate %s", ErrInvalidReplicaStatePiece, piece.PieceID)
		}
		pieceByID[piece.PieceID] = piece
		previousPieceID = piece.PieceID
		for _, reference := range piece.RequiredBlobReferences {
			if count, exists := blobByteCounts[reference.BlobID]; exists && count != reference.ByteCount {
				return fmt.Errorf("%w: %s", ErrReplicaStateBlobCollision, reference.BlobID)
			}
			blobByteCounts[reference.BlobID] = reference.ByteCount
		}
	}
	for _, piece := range root.Pieces {
		for _, dependency := range piece.DependencyPieceIDs {
			if _, exists := pieceByID[dependency]; !exists {
				return fmt.Errorf("%w: %s requires %s", ErrReplicaStateDependency, piece.PieceID, dependency)
			}
		}
	}
	dependencyCounts := make(map[string]int, len(root.Pieces))
	dependents := make(map[string][]string, len(root.Pieces))
	ready := make([]string, 0, len(root.Pieces))
	for _, piece := range root.Pieces {
		dependencyCounts[piece.PieceID] = len(piece.DependencyPieceIDs)
		if len(piece.DependencyPieceIDs) == 0 {
			ready = append(ready, piece.PieceID)
		}
		for _, dependency := range piece.DependencyPieceIDs {
			dependents[dependency] = append(dependents[dependency], piece.PieceID)
		}
	}
	completedCount := 0
	for readyIndex := 0; readyIndex < len(ready); readyIndex++ {
		pieceID := ready[readyIndex]
		completedCount++
		for _, dependent := range dependents[pieceID] {
			dependencyCounts[dependent]--
			if dependencyCounts[dependent] == 0 {
				ready = append(ready, dependent)
			}
		}
	}
	if completedCount != len(pieceByID) {
		for _, piece := range root.Pieces {
			if dependencyCounts[piece.PieceID] > 0 {
				return fmt.Errorf("%w: cycle at %s", ErrReplicaStateDependency, piece.PieceID)
			}
		}
		return ErrReplicaStateDependency
	}
	return nil
}

func (root ReplicaStateRoot) ReferenceDigest() (string, error) {
	if err := root.Validate(); err != nil {
		return "", err
	}
	var data bytes.Buffer
	data.Write(replicaStateRootDigestDomain)
	writeReplicaStateUint64(&data, uint64(root.Version))
	writeReplicaStateString(&data, root.DomainID)
	writeReplicaStateUint64(&data, root.KeyEpoch)
	writeReplicaStateUint64(&data, root.CapturedCoreRevision)
	if root.PredecessorRootDigest == nil {
		data.WriteByte(0)
	} else {
		data.WriteByte(1)
		digest, _ := base64.RawURLEncoding.Strict().DecodeString(*root.PredecessorRootDigest)
		data.Write(digest)
	}
	clockIDs := make([]string, 0, len(root.CoveredClock.Counters))
	for replicaID := range root.CoveredClock.Counters {
		clockIDs = append(clockIDs, replicaID)
	}
	sort.Strings(clockIDs)
	writeReplicaStateUint64(&data, uint64(len(clockIDs)))
	for _, replicaID := range clockIDs {
		writeReplicaStateString(&data, replicaID)
		writeReplicaStateUint64(&data, root.CoveredClock.Counters[replicaID])
	}
	writeReplicaStateUint64(&data, uint64(len(root.PredecessorMessageIDs)))
	for _, messageID := range root.PredecessorMessageIDs {
		data.Write(messageID[:])
	}
	writeReplicaStateUint64(&data, uint64(len(root.Pieces)))
	for _, piece := range root.Pieces {
		digest, _ := base64.RawURLEncoding.Strict().DecodeString(piece.PieceID)
		data.Write(digest)
		writeReplicaStateUint64(&data, uint64(piece.ByteCount))
		writeReplicaStateUint64(&data, uint64(len(piece.DependencyPieceIDs)))
		for _, dependency := range piece.DependencyPieceIDs {
			digest, _ = base64.RawURLEncoding.Strict().DecodeString(dependency)
			data.Write(digest)
		}
		writeReplicaStateUint64(&data, uint64(len(piece.RequiredBlobReferences)))
		for _, reference := range piece.RequiredBlobReferences {
			digest, _ = base64.RawURLEncoding.Strict().DecodeString(reference.BlobID)
			data.Write(digest)
			writeReplicaStateUint64(&data, uint64(reference.ByteCount))
		}
		writeReplicaStateUint64(&data, piece.ItemCount)
	}
	writeReplicaStateUint64(&data, uint64(root.CapturedAtMilliseconds))
	digest := sha256.Sum256(data.Bytes())
	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func (root ReplicaStateRoot) ValidateSuccessor(predecessor ReplicaStateRoot) error {
	if err := predecessor.Validate(); err != nil {
		return err
	}
	if err := root.Validate(); err != nil {
		return err
	}
	digest, _ := predecessor.ReferenceDigest()
	if root.PredecessorRootDigest == nil || *root.PredecessorRootDigest != digest {
		return ErrReplicaStatePredecessor
	}
	if root.DomainID != predecessor.DomainID || root.KeyEpoch < predecessor.KeyEpoch ||
		root.CapturedCoreRevision < predecessor.CapturedCoreRevision {
		return ErrInvalidReplicaStateSuccessor
	}
	if root.CapturedCoreRevision == predecessor.CapturedCoreRevision &&
		!replicaStatePieceInventoriesEqual(root.Pieces, predecessor.Pieces) {
		return ErrInvalidReplicaStateSuccessor
	}
	for replicaID, previousSequence := range predecessor.CoveredClock.Counters {
		if root.CoveredClock.Counters[replicaID] < previousSequence {
			return ErrInvalidReplicaStateSuccessor
		}
	}
	return nil
}

func replicaStatePieceInventoriesEqual(
	left []ReplicaStatePieceDescriptor,
	right []ReplicaStatePieceDescriptor,
) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].PieceID != right[index].PieceID ||
			left[index].ByteCount != right[index].ByteCount ||
			left[index].ItemCount != right[index].ItemCount ||
			len(left[index].DependencyPieceIDs) != len(right[index].DependencyPieceIDs) ||
			len(left[index].RequiredBlobReferences) != len(right[index].RequiredBlobReferences) {
			return false
		}
		for dependencyIndex := range left[index].DependencyPieceIDs {
			if left[index].DependencyPieceIDs[dependencyIndex] !=
				right[index].DependencyPieceIDs[dependencyIndex] {
				return false
			}
		}
		for blobIndex := range left[index].RequiredBlobReferences {
			if left[index].RequiredBlobReferences[blobIndex] !=
				right[index].RequiredBlobReferences[blobIndex] {
				return false
			}
		}
	}
	return true
}

func (root *ReplicaStateRoot) UnmarshalJSON(data []byte) error {
	type rawRoot ReplicaStateRoot
	var decoded rawRoot
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	candidate := ReplicaStateRoot(decoded)
	if err := candidate.Validate(); err != nil {
		return err
	}
	*root = candidate
	return nil
}

func isReplicaStateDigest(value string) bool {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(decoded) == sha256.Size &&
		base64.RawURLEncoding.EncodeToString(decoded) == value
}

func canonicalDigestStrings(values []string) bool {
	for index, value := range values {
		if !isReplicaStateDigest(value) || (index > 0 && values[index-1] >= value) {
			return false
		}
	}
	return true
}

func writeReplicaStateUint64(data *bytes.Buffer, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	data.Write(encoded[:])
}

func writeReplicaStateString(data *bytes.Buffer, value string) {
	writeReplicaStateUint64(data, uint64(len(value)))
	data.WriteString(value)
}
