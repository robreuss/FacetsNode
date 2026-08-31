package backupcustody

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"math"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

// OuterWireSummary is the only plaintext the custody engine learns from a
// Backup: its routing-independent generation coordinates and exact opaque-byte
// commitment. No encrypted catalog or recovery chunk is decoded.
type OuterWireSummary struct {
	BackupSetID            uuid.UUID
	Generation             uint64
	PredecessorOuterDigest *string
	OuterDigest            string
	OuterByteCount         uint64
}

// ValidateOuterStream parses the fixed-memory outer framing while hashing the
// exact accepted bytes. maximumByteCount is service policy, not a portable
// protocol claim. The function consumes exactly one record through EOF.
func ValidateOuterStream(reader io.Reader, maximumByteCount uint64) (OuterWireSummary, error) {
	if reader == nil || maximumByteCount == 0 || maximumByteCount > math.MaxInt64 {
		return OuterWireSummary{}, serviceauthority.ErrInvalid
	}
	counted := &boundedHashReader{reader: reader, maximum: maximumByteCount, digest: sha256.New()}
	magic := make([]byte, len(outerMagic))
	if _, err := io.ReadFull(counted, magic); err != nil || string(magic) != outerMagic {
		return OuterWireSummary{}, serviceauthority.ErrInvalid
	}
	var headerLengthBytes [4]byte
	if _, err := io.ReadFull(counted, headerLengthBytes[:]); err != nil {
		return OuterWireSummary{}, serviceauthority.ErrInvalid
	}
	headerLength := binary.BigEndian.Uint32(headerLengthBytes[:])
	if headerLength == 0 || headerLength > maximumHeaderBytes {
		return OuterWireSummary{}, serviceauthority.ErrInvalid
	}
	headerBytes := make([]byte, int(headerLength))
	if _, err := io.ReadFull(counted, headerBytes); err != nil {
		return OuterWireSummary{}, serviceauthority.ErrInvalid
	}
	header, err := decodeOuterHeader(headerBytes)
	if err != nil {
		return OuterWireSummary{}, err
	}

	expectedRecovery := uint64(0)
	seenCatalog, seenRecovery := false, false
	previousRecoveryLength := uint32(0)
	for {
		var sectionHeader [13]byte
		if _, err := io.ReadFull(counted, sectionHeader[:]); err != nil {
			return OuterWireSummary{}, serviceauthority.ErrInvalid
		}
		kind := sectionHeader[0]
		index := binary.BigEndian.Uint64(sectionHeader[1:9])
		length := binary.BigEndian.Uint32(sectionHeader[9:13])
		maximum := uint32(0)
		switch kind {
		case 1:
			maximum = maximumCatalogBytes + aesGCMOverhead
		case 2:
			maximum = recoveryChunkBytes + aesGCMOverhead
		case 3:
			maximum = maximumFinalizationBytes + aesGCMOverhead
		default:
			return OuterWireSummary{}, serviceauthority.ErrInvalid
		}
		if length < aesGCMOverhead+1 || length > maximum {
			return OuterWireSummary{}, serviceauthority.ErrInvalid
		}
		if _, err := io.CopyN(io.Discard, counted, int64(length)); err != nil {
			return OuterWireSummary{}, serviceauthority.ErrInvalid
		}
		switch kind {
		case 1:
			if seenCatalog || seenRecovery || index != 0 {
				return OuterWireSummary{}, serviceauthority.ErrInvalid
			}
			seenCatalog = true
		case 2:
			if !seenCatalog || index != expectedRecovery ||
				(seenRecovery && previousRecoveryLength != recoveryChunkBytes+aesGCMOverhead) ||
				expectedRecovery == ^uint64(0) {
				return OuterWireSummary{}, serviceauthority.ErrInvalid
			}
			expectedRecovery++
			seenRecovery = true
			previousRecoveryLength = length
		case 3:
			if !seenCatalog || !seenRecovery || index != expectedRecovery {
				return OuterWireSummary{}, serviceauthority.ErrInvalid
			}
			var trailing [1]byte
			if count, readErr := counted.Read(trailing[:]); count != 0 || !errors.Is(readErr, io.EOF) {
				return OuterWireSummary{}, serviceauthority.ErrInvalid
			}
			return OuterWireSummary{
				BackupSetID: header.BackupSetID, Generation: header.Generation,
				PredecessorOuterDigest: cloneString(header.PredecessorOuterDigest),
				OuterDigest:            base64.RawURLEncoding.EncodeToString(counted.digest.Sum(nil)),
				OuterByteCount:         counted.count,
			}, nil
		}
	}
}

func decodeOuterHeader(encoded []byte) (backupOuterHeader, error) {
	var header backupOuterHeader
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&header) != nil {
		return header, serviceauthority.ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return header, serviceauthority.ErrInvalid
	}
	canonical, err := json.Marshal(header)
	if err != nil || !bytes.Equal(canonical, encoded) || header.Version != Version ||
		header.BackupSetID == uuid.Nil || header.Generation == 0 || header.Generation > math.MaxInt64 ||
		(header.Generation == 1) != (header.PredecessorOuterDigest == nil) ||
		(header.PredecessorOuterDigest != nil && !validBase64URLDigest(*header.PredecessorOuterDigest)) ||
		!slotBucket(len(header.RecipientSlots)) {
		return header, serviceauthority.ErrInvalid
	}
	seen := make(map[string]struct{}, len(header.RecipientSlots))
	for index, slot := range header.RecipientSlots {
		if len(slot.EphemeralPublicKey) != 32 || len(slot.SealedContentKey) != 60 {
			return header, serviceauthority.ErrInvalid
		}
		key := string(slot.EphemeralPublicKey)
		if _, exists := seen[key]; exists || (index > 0 && compareSlots(header.RecipientSlots[index-1], slot) >= 0) {
			return header, serviceauthority.ErrInvalid
		}
		seen[key] = struct{}{}
	}
	return header, nil
}

type boundedHashReader struct {
	reader  io.Reader
	maximum uint64
	count   uint64
	digest  hash.Hash
}

func (reader *boundedHashReader) Read(output []byte) (int, error) {
	if len(output) == 0 {
		return 0, nil
	}
	if reader.count >= reader.maximum {
		var probe [1]byte
		count, err := reader.reader.Read(probe[:])
		if count > 0 {
			return 0, serviceauthority.ErrInvalid
		}
		if err == nil {
			return 0, io.ErrNoProgress
		}
		return 0, err
	}
	remaining := reader.maximum - reader.count
	if uint64(len(output)) > remaining {
		output = output[:remaining]
	}
	count, err := reader.reader.Read(output)
	if count == 0 && err == nil {
		return 0, io.ErrNoProgress
	}
	if uint64(count) > remaining {
		return 0, serviceauthority.ErrInvalid
	}
	if count > 0 {
		_, _ = reader.digest.Write(output[:count])
		reader.count += uint64(count)
	}
	return count, err
}

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
