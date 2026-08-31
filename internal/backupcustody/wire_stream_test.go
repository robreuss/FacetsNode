package backupcustody

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math"
	"testing"

	"github.com/google/uuid"
)

func TestValidateOuterStreamMatchesInMemoryContract(t *testing.T) {
	setID := uuid.New()
	wire := testOuterWire(t, setID, 1, nil, 10)
	summary, err := ValidateOuterStream(bytes.NewReader(wire), uint64(len(wire)))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(wire)
	if summary.BackupSetID != setID || summary.Generation != 1 || summary.PredecessorOuterDigest != nil ||
		summary.OuterByteCount != uint64(len(wire)) ||
		summary.OuterDigest != base64.RawURLEncoding.EncodeToString(digest[:]) {
		t.Fatalf("summary=%+v", summary)
	}
}

func TestValidateOuterStreamRejectsTruncationTrailingAndCapOverflow(t *testing.T) {
	wire := testOuterWire(t, uuid.New(), 1, nil, 10)
	for name, candidate := range map[string][]byte{
		"truncated": wire[:len(wire)-1],
		"trailing":  append(append([]byte(nil), wire...), 0),
	} {
		if _, err := ValidateOuterStream(bytes.NewReader(candidate), uint64(len(candidate))); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if _, err := ValidateOuterStream(bytes.NewReader(wire), uint64(len(wire)-1)); err == nil {
		t.Fatal("over-cap record accepted")
	}
	if _, err := ValidateOuterStream(bytes.NewReader(wire), math.MaxInt64+1); err == nil {
		t.Fatal("unrepresentable cap accepted")
	}
	if _, err := ValidateOuterStream(bytes.NewReader(wire), math.MaxUint64); err == nil {
		t.Fatal("maximum uint64 cap accepted")
	}
	if _, err := ValidateOuterStream(bytes.NewReader(wire), uint64(len(wire))); err != nil {
		t.Fatalf("exact cap rejected: %v", err)
	}
}

func TestValidateOuterStreamHandlesFragmentationAndPropagatesReadFailure(t *testing.T) {
	wire := testOuterWire(t, uuid.New(), 1, nil, 10)
	fragmented := &fragmentedReader{reader: bytes.NewReader(wire), maximum: 3}
	if _, err := ValidateOuterStream(fragmented, uint64(len(wire))); err != nil {
		t.Fatalf("fragmented stream rejected: %v", err)
	}
	if fragmented.largestRequest > 32*1024 {
		t.Fatalf("unbounded read request=%d", fragmented.largestRequest)
	}
	failure := errors.New("injected transport failure")
	reader := io.MultiReader(bytes.NewReader(wire[:len(wire)-5]), errorReader{failure})
	if _, err := ValidateOuterStream(reader, uint64(len(wire))); err == nil {
		t.Fatal("injected read failure accepted")
	}
	if _, err := ValidateOuterStream(zeroProgressReader{}, uint64(len(wire))); err == nil {
		t.Fatal("zero-progress reader accepted")
	}
}

func TestValidateOuterStreamRejectsHostileSectionGrammar(t *testing.T) {
	setID := uuid.New()
	valid := testOuterWire(t, setID, 1, nil, 10)
	headerEnd := outerHeaderEnd(t, valid)
	cases := map[string][]byte{
		"missing catalog": outerWireWithSections(t, setID,
			wireSection{kind: 2, index: 0, length: aesGCMOverhead + 10},
			wireSection{kind: 3, index: 1, length: aesGCMOverhead + 1}),
		"missing recovery": outerWireWithSections(t, setID,
			wireSection{kind: 1, index: 0, length: aesGCMOverhead + 1},
			wireSection{kind: 3, index: 0, length: aesGCMOverhead + 1}),
		"noncontiguous recovery": outerWireWithSections(t, setID,
			wireSection{kind: 1, index: 0, length: aesGCMOverhead + 1},
			wireSection{kind: 2, index: 1, length: aesGCMOverhead + 10},
			wireSection{kind: 3, index: 2, length: aesGCMOverhead + 1}),
		"maximum recovery index": outerWireWithSections(t, setID,
			wireSection{kind: 1, index: 0, length: aesGCMOverhead + 1},
			wireSection{kind: 2, index: math.MaxUint64, length: aesGCMOverhead + 10},
			wireSection{kind: 3, index: 0, length: aesGCMOverhead + 1}),
		"short nonterminal recovery": outerWireWithSections(t, setID,
			wireSection{kind: 1, index: 0, length: aesGCMOverhead + 1},
			wireSection{kind: 2, index: 0, length: aesGCMOverhead + 10},
			wireSection{kind: 2, index: 1, length: aesGCMOverhead + 10},
			wireSection{kind: 3, index: 2, length: aesGCMOverhead + 1}),
	}
	hugeFrame := append([]byte(nil), valid...)
	binary.BigEndian.PutUint32(hugeFrame[headerEnd+9:headerEnd+13], maximumCatalogBytes+aesGCMOverhead+1)
	cases["oversized frame"] = hugeFrame
	for name, candidate := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ValidateOuterStream(bytes.NewReader(candidate), uint64(len(candidate))); err == nil {
				t.Fatal("hostile grammar accepted")
			}
		})
	}
}

func testOuterWire(t *testing.T, setID uuid.UUID, generation uint64, predecessor *string, recoveryBytes int) []byte {
	t.Helper()
	header := backupOuterHeader{
		BackupSetID: setID, Generation: generation, PredecessorOuterDigest: predecessor, Version: Version,
		RecipientSlots: []backupRecipientSlot{{EphemeralPublicKey: bytes.Repeat([]byte{1}, 32), SealedContentKey: bytes.Repeat([]byte{2}, 60)}},
	}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	result := append([]byte(outerMagic), 0, 0, 0, 0)
	binary.BigEndian.PutUint32(result[len(outerMagic):], uint32(len(headerBytes)))
	result = append(result, headerBytes...)
	result = appendSection(result, 1, 0, bytes.Repeat([]byte{3}, aesGCMOverhead+1))
	result = appendSection(result, 2, 0, bytes.Repeat([]byte{4}, aesGCMOverhead+recoveryBytes))
	result = appendSection(result, 3, 1, bytes.Repeat([]byte{5}, aesGCMOverhead+1))
	return result
}

func appendSection(destination []byte, kind byte, index uint64, body []byte) []byte {
	var header [13]byte
	header[0] = kind
	binary.BigEndian.PutUint64(header[1:9], index)
	binary.BigEndian.PutUint32(header[9:13], uint32(len(body)))
	destination = append(destination, header[:]...)
	return append(destination, body...)
}

type wireSection struct {
	kind   byte
	index  uint64
	length uint32
}

func outerWireWithSections(t *testing.T, setID uuid.UUID, sections ...wireSection) []byte {
	t.Helper()
	header := backupOuterHeader{
		BackupSetID: setID, Generation: 1, Version: Version,
		RecipientSlots: []backupRecipientSlot{{
			EphemeralPublicKey: bytes.Repeat([]byte{1}, 32),
			SealedContentKey:   bytes.Repeat([]byte{2}, 60),
		}},
	}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	result := append([]byte(outerMagic), 0, 0, 0, 0)
	binary.BigEndian.PutUint32(result[len(outerMagic):], uint32(len(headerBytes)))
	result = append(result, headerBytes...)
	for _, section := range sections {
		result = appendSection(result, section.kind, section.index, bytes.Repeat([]byte{section.kind}, int(section.length)))
	}
	return result
}

func outerHeaderEnd(t *testing.T, wire []byte) int {
	t.Helper()
	lengthOffset := len(outerMagic)
	if len(wire) < lengthOffset+4 {
		t.Fatal("short test wire")
	}
	return lengthOffset + 4 + int(binary.BigEndian.Uint32(wire[lengthOffset:lengthOffset+4]))
}

type fragmentedReader struct {
	reader         io.Reader
	maximum        int
	largestRequest int
}

func (reader *fragmentedReader) Read(output []byte) (int, error) {
	if len(output) > reader.largestRequest {
		reader.largestRequest = len(output)
	}
	if len(output) > reader.maximum {
		output = output[:reader.maximum]
	}
	return reader.reader.Read(output)
}

type errorReader struct{ err error }

func (reader errorReader) Read([]byte) (int, error) { return 0, reader.err }

type zeroProgressReader struct{}

func (zeroProgressReader) Read([]byte) (int, error) { return 0, nil }
