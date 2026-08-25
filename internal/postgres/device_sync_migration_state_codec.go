package postgres

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	deviceSyncMigrationArtifactVersion = uint16(1)
	// Relay message envelopes are capped at 16 MiB of ciphertext. A 32 MiB
	// encoded-scalar ceiling leaves room for base64 expansion while preventing a
	// signed malformed length from becoming an unbounded allocation request.
	deviceSyncMigrationMaximumScalarLength  = uint64(32 * 1024 * 1024)
	deviceSyncMigrationMaximumArrayElements = uint64(4_096)
)

var (
	deviceSyncMigrationStateMagic       = []byte("FACETS-DS-STATE\x00")
	deviceSyncMigrationBlobMagic        = []byte("FACETS-DS-BLOBS\x00")
	deviceSyncMigrationCommitmentDomain = []byte(
		"Facets Device Sync migration logical state commitment v1\x00",
	)
)

// DeviceSyncMigrationDigest is an ordinary SHA-256 digest. Its authenticity
// comes from the signed migration snapshot that will carry it, not from the
// digest itself.
type DeviceSyncMigrationDigest [sha256.Size]byte

func (digest DeviceSyncMigrationDigest) String() string {
	return hex.EncodeToString(digest[:])
}

// DeviceSyncMigrationArtifactDigests binds the two independently transferable
// streams into one domain-separated logical-state commitment.
type DeviceSyncMigrationArtifactDigests struct {
	StateArtifactSHA256    DeviceSyncMigrationDigest
	StateArtifactByteCount int64
	BlobInventorySHA256    DeviceSyncMigrationDigest
	BlobInventoryByteCount int64
	StateCommitment        DeviceSyncMigrationDigest
}

// DeviceSyncMigrationBlobInventoryEntry describes one opaque blob that a
// future transfer coordinator must copy and verify against its relay blob ID.
type DeviceSyncMigrationBlobInventoryEntry struct {
	DomainID  uuid.UUID
	BlobID    string
	ByteCount int64
}

// DeviceSyncMigrationStateCommitment binds exact artifact transfer digests.
func DeviceSyncMigrationStateCommitment(
	stateArtifactSHA256 DeviceSyncMigrationDigest,
	blobInventorySHA256 DeviceSyncMigrationDigest,
) DeviceSyncMigrationDigest {
	hasher := sha256.New()
	_, _ = hasher.Write(deviceSyncMigrationCommitmentDomain)
	_, _ = hasher.Write(stateArtifactSHA256[:])
	_, _ = hasher.Write(blobInventorySHA256[:])
	var result DeviceSyncMigrationDigest
	copy(result[:], hasher.Sum(nil))
	return result
}

type deviceSyncMigrationScalar struct {
	kind       deviceSyncMigrationScalarKind
	isNull     bool
	uuidValue  uuid.UUID
	textValue  string
	intValue   int64
	boolValue  bool
	arrayValue []string
	bytesValue []byte
}

func (value deviceSyncMigrationScalar) clone() deviceSyncMigrationScalar {
	cloned := value
	cloned.arrayValue = append([]string(nil), value.arrayValue...)
	cloned.bytesValue = append([]byte(nil), value.bytesValue...)
	return cloned
}

type deviceSyncMigrationArtifactWriter struct {
	destination  io.Writer
	byteCounter  *deviceSyncMigrationCountingWriter
	bodyHash     hash.Hash
	transferHash hash.Hash
	bodyWriter   io.Writer
	outerWriter  io.Writer
}

type deviceSyncMigrationCountingWriter struct {
	destination io.Writer
	byteCount   int64
}

func (writer *deviceSyncMigrationCountingWriter) Write(value []byte) (int, error) {
	written, err := writer.destination.Write(value)
	if written > 0 {
		if int64(written) > math.MaxInt64-writer.byteCount {
			return written, errors.New("Device Sync migration artifact byte count overflow")
		}
		writer.byteCount += int64(written)
	}
	return written, err
}

func newDeviceSyncMigrationArtifactWriter(
	destination io.Writer,
) *deviceSyncMigrationArtifactWriter {
	bodyHash := sha256.New()
	transferHash := sha256.New()
	byteCounter := &deviceSyncMigrationCountingWriter{destination: destination}
	outer := io.MultiWriter(byteCounter, transferHash)
	return &deviceSyncMigrationArtifactWriter{
		destination:  destination,
		byteCounter:  byteCounter,
		bodyHash:     bodyHash,
		transferHash: transferHash,
		bodyWriter:   io.MultiWriter(outer, bodyHash),
		outerWriter:  outer,
	}
}

func (writer *deviceSyncMigrationArtifactWriter) byteCount() int64 {
	return writer.byteCounter.byteCount
}

func (writer *deviceSyncMigrationArtifactWriter) finish() (
	DeviceSyncMigrationDigest,
	error,
) {
	if _, err := writer.outerWriter.Write(writer.bodyHash.Sum(nil)); err != nil {
		return DeviceSyncMigrationDigest{}, err
	}
	var digest DeviceSyncMigrationDigest
	copy(digest[:], writer.transferHash.Sum(nil))
	return digest, nil
}

func writeMigrationBytes(writer io.Writer, value []byte) error {
	_, err := writer.Write(value)
	return err
}

func writeMigrationUint16(writer io.Writer, value uint16) error {
	var encoded [2]byte
	binary.BigEndian.PutUint16(encoded[:], value)
	return writeMigrationBytes(writer, encoded[:])
}

func writeMigrationUint32(writer io.Writer, value uint32) error {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	return writeMigrationBytes(writer, encoded[:])
}

func writeMigrationUint64(writer io.Writer, value uint64) error {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return writeMigrationBytes(writer, encoded[:])
}

func writeMigrationString(writer io.Writer, value string) error {
	if err := writeMigrationUint64(writer, uint64(len(value))); err != nil {
		return err
	}
	return writeMigrationBytes(writer, []byte(value))
}

func writeDeviceSyncMigrationStateHeader(
	writer io.Writer,
	principalID uuid.UUID,
) error {
	if err := writeMigrationBytes(writer, deviceSyncMigrationStateMagic); err != nil {
		return err
	}
	if err := writeMigrationUint16(writer, deviceSyncMigrationArtifactVersion); err != nil {
		return err
	}
	if err := writeMigrationBytes(writer, principalID[:]); err != nil {
		return err
	}
	return writeMigrationUint32(writer, uint32(len(deviceSyncMigrationTableSpecs)))
}

func writeDeviceSyncMigrationSectionHeader(
	writer io.Writer,
	spec deviceSyncMigrationTableSpec,
	rowCount uint64,
) error {
	if err := writeMigrationString(writer, spec.name); err != nil {
		return err
	}
	if len(spec.columns) > math.MaxUint16 || len(spec.keyColumnIndexes) > math.MaxUint16 {
		return errors.New("Device Sync migration schema exceeds canonical limits")
	}
	if err := writeMigrationUint16(writer, uint16(len(spec.columns))); err != nil {
		return err
	}
	for _, column := range spec.columns {
		if err := writeMigrationString(writer, column.name); err != nil {
			return err
		}
		if err := writeMigrationBytes(writer, []byte{byte(column.kind)}); err != nil {
			return err
		}
		if err := writeMigrationString(writer, column.databaseType); err != nil {
			return err
		}
		nullable := byte(0)
		if column.nullable {
			nullable = 1
		}
		if err := writeMigrationBytes(writer, []byte{nullable}); err != nil {
			return err
		}
	}
	if err := writeMigrationUint16(writer, uint16(len(spec.keyColumnIndexes))); err != nil {
		return err
	}
	for _, index := range spec.keyColumnIndexes {
		if err := writeMigrationUint16(writer, uint16(index)); err != nil {
			return err
		}
	}
	multiplicity := byte(0)
	if spec.allowMultiplicity {
		multiplicity = 1
	}
	if err := writeMigrationBytes(writer, []byte{multiplicity}); err != nil {
		return err
	}
	return writeMigrationUint64(writer, rowCount)
}

func writeDeviceSyncMigrationRow(
	writer io.Writer,
	spec deviceSyncMigrationTableSpec,
	occurrence uint64,
	values []deviceSyncMigrationScalar,
) error {
	if len(values) != len(spec.columns) {
		return fmt.Errorf("Device Sync migration %s row has %d values, expected %d",
			spec.name, len(values), len(spec.columns))
	}
	if err := writeMigrationUint64(writer, occurrence); err != nil {
		return err
	}
	for index, value := range values {
		column := spec.columns[index]
		if value.isNull {
			if !column.nullable {
				return fmt.Errorf("Device Sync migration %s.%s is unexpectedly null",
					spec.name, column.name)
			}
			if err := writeMigrationBytes(writer, []byte{byte(deviceSyncMigrationScalarNull)}); err != nil {
				return err
			}
			continue
		}
		if value.kind != column.kind {
			return fmt.Errorf("Device Sync migration %s.%s has scalar kind %d, expected %d",
				spec.name, column.name, value.kind, column.kind)
		}
		if err := writeMigrationBytes(writer, []byte{byte(value.kind)}); err != nil {
			return err
		}
		switch value.kind {
		case deviceSyncMigrationScalarUUID:
			if err := writeMigrationBytes(writer, value.uuidValue[:]); err != nil {
				return err
			}
		case deviceSyncMigrationScalarText, deviceSyncMigrationScalarCanonicalJSON:
			if err := writeMigrationString(writer, value.textValue); err != nil {
				return err
			}
		case deviceSyncMigrationScalarInt:
			if err := writeMigrationUint64(writer, uint64(value.intValue)); err != nil {
				return err
			}
		case deviceSyncMigrationScalarBool:
			encoded := byte(0)
			if value.boolValue {
				encoded = 1
			}
			if err := writeMigrationBytes(writer, []byte{encoded}); err != nil {
				return err
			}
		case deviceSyncMigrationScalarTextArray:
			if err := writeMigrationUint64(writer, uint64(len(value.arrayValue))); err != nil {
				return err
			}
			for _, item := range value.arrayValue {
				if err := writeMigrationString(writer, item); err != nil {
					return err
				}
			}
		case deviceSyncMigrationScalarBytes:
			if err := writeMigrationUint64(writer, uint64(len(value.bytesValue))); err != nil {
				return err
			}
			if err := writeMigrationBytes(writer, value.bytesValue); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported Device Sync migration scalar kind %d", value.kind)
		}
	}
	return nil
}

type deviceSyncMigrationArtifactReader struct {
	source       io.Reader
	bodyReader   io.Reader
	transferHash hash.Hash
	bodyHash     hash.Hash
}

func newDeviceSyncMigrationArtifactReader(source io.Reader) *deviceSyncMigrationArtifactReader {
	transferHash := sha256.New()
	bodyHash := sha256.New()
	outer := io.TeeReader(source, transferHash)
	return &deviceSyncMigrationArtifactReader{
		source:       outer,
		bodyReader:   io.TeeReader(outer, bodyHash),
		transferHash: transferHash,
		bodyHash:     bodyHash,
	}
}

func (reader *deviceSyncMigrationArtifactReader) finish(
	expected DeviceSyncMigrationDigest,
) error {
	var storedBodyDigest [sha256.Size]byte
	if _, err := io.ReadFull(reader.source, storedBodyDigest[:]); err != nil {
		return fmt.Errorf("read Device Sync migration artifact checksum: %w", err)
	}
	if !bytes.Equal(storedBodyDigest[:], reader.bodyHash.Sum(nil)) {
		return errors.New("Device Sync migration artifact body checksum does not match")
	}
	var trailing [1]byte
	readCount, err := io.ReadFull(reader.source, trailing[:])
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read Device Sync migration artifact trailer: %w", err)
	}
	if readCount != 0 {
		return errors.New("Device Sync migration artifact has trailing bytes")
	}
	var actual DeviceSyncMigrationDigest
	copy(actual[:], reader.transferHash.Sum(nil))
	if actual != expected {
		return fmt.Errorf("Device Sync migration artifact SHA-256 %s does not match expected %s",
			actual, expected)
	}
	return nil
}

func readMigrationBytes(reader io.Reader, length uint64) ([]byte, error) {
	if length > deviceSyncMigrationMaximumScalarLength {
		return nil, fmt.Errorf("Device Sync migration scalar length %d exceeds limit", length)
	}
	value, err := io.ReadAll(io.LimitReader(reader, int64(length)))
	if err != nil {
		return nil, err
	}
	if uint64(len(value)) != length {
		return nil, io.ErrUnexpectedEOF
	}
	return value, nil
}

func readMigrationUint16(reader io.Reader) (uint16, error) {
	var encoded [2]byte
	_, err := io.ReadFull(reader, encoded[:])
	return binary.BigEndian.Uint16(encoded[:]), err
}

func readMigrationUint32(reader io.Reader) (uint32, error) {
	var encoded [4]byte
	_, err := io.ReadFull(reader, encoded[:])
	return binary.BigEndian.Uint32(encoded[:]), err
}

func readMigrationUint64(reader io.Reader) (uint64, error) {
	var encoded [8]byte
	_, err := io.ReadFull(reader, encoded[:])
	return binary.BigEndian.Uint64(encoded[:]), err
}

func readMigrationString(reader io.Reader) (string, error) {
	length, err := readMigrationUint64(reader)
	if err != nil {
		return "", err
	}
	value, err := readMigrationBytes(reader, length)
	if err != nil {
		return "", err
	}
	if !utf8.Valid(value) {
		return "", errors.New("Device Sync migration string is invalid UTF-8")
	}
	return string(value), nil
}

func readDeviceSyncMigrationScalar(
	reader io.Reader,
	column deviceSyncMigrationColumnSpec,
) (deviceSyncMigrationScalar, error) {
	var tag [1]byte
	if _, err := io.ReadFull(reader, tag[:]); err != nil {
		return deviceSyncMigrationScalar{}, err
	}
	kind := deviceSyncMigrationScalarKind(tag[0])
	if kind == deviceSyncMigrationScalarNull {
		if !column.nullable {
			return deviceSyncMigrationScalar{}, fmt.Errorf("non-nullable column %s is null", column.name)
		}
		return deviceSyncMigrationScalar{kind: column.kind, isNull: true}, nil
	}
	if kind != column.kind {
		return deviceSyncMigrationScalar{}, fmt.Errorf("column %s scalar kind %d, expected %d",
			column.name, kind, column.kind)
	}
	value := deviceSyncMigrationScalar{kind: kind}
	switch kind {
	case deviceSyncMigrationScalarUUID:
		if _, err := io.ReadFull(reader, value.uuidValue[:]); err != nil {
			return deviceSyncMigrationScalar{}, err
		}
	case deviceSyncMigrationScalarText, deviceSyncMigrationScalarCanonicalJSON:
		textValue, err := readMigrationString(reader)
		if err != nil {
			return deviceSyncMigrationScalar{}, err
		}
		value.textValue = textValue
		if kind == deviceSyncMigrationScalarCanonicalJSON {
			canonical, err := canonicalizeDeviceSyncMigrationJSON([]byte(textValue))
			if err != nil {
				return deviceSyncMigrationScalar{}, fmt.Errorf("column %s JSON: %w", column.name, err)
			}
			if canonical != textValue {
				return deviceSyncMigrationScalar{}, fmt.Errorf("column %s JSON is not canonical", column.name)
			}
		}
	case deviceSyncMigrationScalarInt:
		encoded, err := readMigrationUint64(reader)
		if err != nil {
			return deviceSyncMigrationScalar{}, err
		}
		value.intValue = int64(encoded)
	case deviceSyncMigrationScalarBool:
		var encoded [1]byte
		if _, err := io.ReadFull(reader, encoded[:]); err != nil {
			return deviceSyncMigrationScalar{}, err
		}
		if encoded[0] > 1 {
			return deviceSyncMigrationScalar{}, errors.New("non-canonical Device Sync migration boolean")
		}
		value.boolValue = encoded[0] == 1
	case deviceSyncMigrationScalarTextArray:
		count, err := readMigrationUint64(reader)
		if err != nil {
			return deviceSyncMigrationScalar{}, err
		}
		if count > deviceSyncMigrationMaximumArrayElements {
			return deviceSyncMigrationScalar{}, fmt.Errorf("column %s array count %d exceeds limit", column.name, count)
		}
		value.arrayValue = make([]string, int(count))
		for index := range value.arrayValue {
			value.arrayValue[index], err = readMigrationString(reader)
			if err != nil {
				return deviceSyncMigrationScalar{}, err
			}
		}
	case deviceSyncMigrationScalarBytes:
		length, err := readMigrationUint64(reader)
		if err != nil {
			return deviceSyncMigrationScalar{}, err
		}
		value.bytesValue, err = readMigrationBytes(reader, length)
		if err != nil {
			return deviceSyncMigrationScalar{}, err
		}
	default:
		return deviceSyncMigrationScalar{}, fmt.Errorf("unsupported scalar kind %d", kind)
	}
	return value, nil
}

func canonicalizeDeviceSyncMigrationJSON(input []byte) (string, error) {
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return "", err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return "", errors.New("JSON contains more than one value")
		}
		return "", err
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(canonical), nil
}

func compareDeviceSyncMigrationScalars(
	left deviceSyncMigrationScalar,
	right deviceSyncMigrationScalar,
) int {
	if left.isNull || right.isNull {
		if left.isNull && right.isNull {
			return 0
		}
		if left.isNull {
			return -1
		}
		return 1
	}
	switch left.kind {
	case deviceSyncMigrationScalarUUID:
		return bytes.Compare(left.uuidValue[:], right.uuidValue[:])
	case deviceSyncMigrationScalarText, deviceSyncMigrationScalarCanonicalJSON:
		return strings.Compare(left.textValue, right.textValue)
	case deviceSyncMigrationScalarInt:
		if left.intValue < right.intValue {
			return -1
		}
		if left.intValue > right.intValue {
			return 1
		}
		return 0
	case deviceSyncMigrationScalarBool:
		if left.boolValue == right.boolValue {
			return 0
		}
		if !left.boolValue {
			return -1
		}
		return 1
	case deviceSyncMigrationScalarTextArray:
		minimum := len(left.arrayValue)
		if len(right.arrayValue) < minimum {
			minimum = len(right.arrayValue)
		}
		for index := 0; index < minimum; index++ {
			if comparison := strings.Compare(left.arrayValue[index], right.arrayValue[index]); comparison != 0 {
				return comparison
			}
		}
		if len(left.arrayValue) < len(right.arrayValue) {
			return -1
		}
		if len(left.arrayValue) > len(right.arrayValue) {
			return 1
		}
		return 0
	case deviceSyncMigrationScalarBytes:
		return bytes.Compare(left.bytesValue, right.bytesValue)
	default:
		return 0
	}
}

func compareDeviceSyncMigrationRows(
	spec deviceSyncMigrationTableSpec,
	left []deviceSyncMigrationScalar,
	right []deviceSyncMigrationScalar,
) int {
	for _, columnIndex := range spec.keyColumnIndexes {
		if comparison := compareDeviceSyncMigrationScalars(left[columnIndex], right[columnIndex]); comparison != 0 {
			return comparison
		}
	}
	return 0
}

func cloneDeviceSyncMigrationRow(values []deviceSyncMigrationScalar) []deviceSyncMigrationScalar {
	result := make([]deviceSyncMigrationScalar, len(values))
	for index, value := range values {
		result[index] = value.clone()
	}
	return result
}
