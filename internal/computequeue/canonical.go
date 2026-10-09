// Package computequeue contains the portable Compute Queue v1 contracts.
//
// It deliberately contains no persistence, scheduling, transport, admission,
// or execution implementation. Those layers consume records only after this
// package has validated their canonical bytes and semantic invariants.
package computequeue

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	ProtocolVersion         = 1
	MaximumDocumentBytes    = 16 * 1024 * 1024
	MaximumDepth            = 64
	MaximumContainerEntries = 250_000
	MaximumNodeCount        = 1_000_000

	maximumCustodyDocumentBytes    = 64 * 1024
	maximumCustodyDepth            = 8
	maximumCustodyContainerEntries = 32
	maximumCustodyNodeCount        = 128
)

var (
	ErrNonCanonical  = errors.New("compute queue: non-canonical JSON")
	ErrInvalidRecord = errors.New("compute queue: invalid record")
)

type FailureClass string

const (
	FailureDuplicateValue             FailureClass = "duplicateValue"
	FailureInvalidIdentifier          FailureClass = "invalidIdentifier"
	FailureInvalidDigest              FailureClass = "invalidDigest"
	FailureInvalidField               FailureClass = "invalidField"
	FailureNonCanonicalEncoding       FailureClass = "nonCanonicalEncoding"
	FailureUnsupportedProtocolVersion FailureClass = "unsupportedProtocolVersion"
)

type ContractError struct {
	Class FailureClass
	Field string
	Cause error
}

func (err *ContractError) Error() string {
	if err.Field == "" {
		return string(err.Class)
	}
	return string(err.Class) + ": " + err.Field
}

func (err *ContractError) Unwrap() error { return err.Cause }

func FailureClassOf(err error) FailureClass {
	var contractError *ContractError
	if errors.As(err, &contractError) {
		return contractError.Class
	}
	if errors.Is(err, ErrNonCanonical) {
		return FailureNonCanonicalEncoding
	}
	return FailureInvalidField
}

// Validatable is implemented by every typed v1 contract.
type Validatable interface {
	Validate() error
}

// DecodeCanonical is the source-ledger codec. It rejects duplicate keys,
// alternate spellings, unbounded trees and any bytes that do not exactly
// match the portable Swift/Go representation. Unknown fields are detected by
// the mandatory typed re-encode comparison, matching Swift's classification.
func DecodeCanonical[T Validatable](data []byte) (T, error) {
	return decodeCanonicalWithBounds[T](data, jsonBounds{
		maximumDocumentBytes:    MaximumDocumentBytes,
		maximumDepth:            MaximumDepth,
		maximumContainerEntries: MaximumContainerEntries,
		maximumNodeCount:        MaximumNodeCount,
	})
}

// EncodeCanonical is the source-ledger codec. Source-only records must never
// be passed to the custody codec below.
func EncodeCanonical[T Validatable](value T) ([]byte, error) {
	if err := value.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRecord, err)
	}
	canonical, err := canonicalizeWithBounds(encoded, sourceJSONBounds())
	if err != nil {
		return nil, err
	}
	return canonical, nil
}

// EncodeCustodyCanonical intentionally accepts only the one CP1 Box-visible
// contract. The concrete parameter preserves the same source/custody boundary
// as Swift.
func EncodeCustodyCanonical(value SignedReceiptEnvelope) ([]byte, error) {
	if err := value.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRecord, err)
	}
	return canonicalizeWithBounds(encoded, jsonBounds{
		maximumDocumentBytes:    maximumCustodyDocumentBytes,
		maximumDepth:            maximumCustodyDepth,
		maximumContainerEntries: maximumCustodyContainerEntries,
		maximumNodeCount:        maximumCustodyNodeCount,
	})
}

// DecodeCustodyCanonical uses the smaller bounded parser appropriate for the
// content-free signed receipt envelope visible to Job Custody.
func DecodeCustodyCanonical(data []byte) (SignedReceiptEnvelope, error) {
	return decodeCanonicalWithBounds[SignedReceiptEnvelope](data, jsonBounds{
		maximumDocumentBytes:    maximumCustodyDocumentBytes,
		maximumDepth:            maximumCustodyDepth,
		maximumContainerEntries: maximumCustodyContainerEntries,
		maximumNodeCount:        maximumCustodyNodeCount,
	})
}

func sourceJSONBounds() jsonBounds {
	return jsonBounds{
		maximumDocumentBytes:    MaximumDocumentBytes,
		maximumDepth:            MaximumDepth,
		maximumContainerEntries: MaximumContainerEntries,
		maximumNodeCount:        MaximumNodeCount,
	}
}

func decodeCanonicalWithBounds[T Validatable](data []byte, bounds jsonBounds) (T, error) {
	var zero T
	canonical, err := canonicalizeWithBounds(data, bounds)
	if err != nil {
		return zero, err
	}
	if !bytes.Equal(canonical, data) {
		return zero, ErrNonCanonical
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value T
	if err := decoder.Decode(&value); err != nil {
		return zero, fmt.Errorf("%w: %v", ErrInvalidRecord, err)
	}
	if err := value.Validate(); err != nil {
		return zero, err
	}
	encoded, err := EncodeCanonical(value)
	if err != nil {
		return zero, err
	}
	if !bytes.Equal(encoded, data) {
		return zero, ErrNonCanonical
	}
	return value, nil
}

type jsonBounds struct {
	maximumDocumentBytes    int
	maximumDepth            int
	maximumContainerEntries int
	maximumNodeCount        int
}

type canonicalKind uint8

const (
	canonicalObject canonicalKind = iota
	canonicalArray
	canonicalString
	canonicalInteger
	canonicalBoolean
	canonicalNull
)

type canonicalEntry struct {
	key   string
	value canonicalValue
}

type canonicalValue struct {
	kind    canonicalKind
	object  []canonicalEntry
	array   []canonicalValue
	text    string
	boolean bool
}

func canonicalize(data []byte) ([]byte, error) {
	return canonicalizeWithBounds(data, sourceJSONBounds())
}

func canonicalizeWithBounds(data []byte, bounds jsonBounds) ([]byte, error) {
	if len(data) == 0 || len(data) > bounds.maximumDocumentBytes || !utf8.Valid(data) {
		return nil, fmt.Errorf("%w: documentBytes", ErrInvalidRecord)
	}
	parser := canonicalParser{data: data, bounds: bounds}
	value, err := parser.parse()
	if err != nil {
		return nil, err
	}
	var output bytes.Buffer
	output.Grow(len(data))
	value.write(&output)
	if output.Len() > bounds.maximumDocumentBytes {
		return nil, fmt.Errorf("%w: documentBytes", ErrInvalidRecord)
	}
	return output.Bytes(), nil
}

func (value canonicalValue) write(output *bytes.Buffer) {
	switch value.kind {
	case canonicalObject:
		entries := append([]canonicalEntry(nil), value.object...)
		sortCanonicalEntries(entries)
		output.WriteByte('{')
		for index, entry := range entries {
			if index > 0 {
				output.WriteByte(',')
			}
			writeCanonicalString(output, entry.key)
			output.WriteByte(':')
			entry.value.write(output)
		}
		output.WriteByte('}')
	case canonicalArray:
		output.WriteByte('[')
		for index, child := range value.array {
			if index > 0 {
				output.WriteByte(',')
			}
			child.write(output)
		}
		output.WriteByte(']')
	case canonicalString:
		writeCanonicalString(output, value.text)
	case canonicalInteger:
		output.WriteString(value.text)
	case canonicalBoolean:
		if value.boolean {
			output.WriteString("true")
		} else {
			output.WriteString("false")
		}
	case canonicalNull:
		output.WriteString("null")
	}
}

func sortCanonicalEntries(entries []canonicalEntry) {
	// UTF-8 byte ordering is the portable contract. Go's byte comparison is
	// exactly the ordering Swift implements with utf8.lexicographicallyPrecedes.
	sort.Slice(entries, func(left, right int) bool {
		return bytes.Compare([]byte(entries[left].key), []byte(entries[right].key)) < 0
	})
}

func writeCanonicalString(output *bytes.Buffer, value string) {
	output.WriteByte('"')
	for _, current := range value {
		switch current {
		case '"', '\\':
			output.WriteByte('\\')
			output.WriteRune(current)
		case '\b':
			output.WriteString(`\b`)
		case '\f':
			output.WriteString(`\f`)
		case '\n':
			output.WriteString(`\n`)
		case '\r':
			output.WriteString(`\r`)
		case '\t':
			output.WriteString(`\t`)
		case '\u2028':
			output.WriteString(`\u2028`)
		case '\u2029':
			output.WriteString(`\u2029`)
		default:
			if current < 0x20 {
				output.WriteString(`\u00`)
				output.WriteString(fmt.Sprintf("%02x", current))
			} else {
				output.WriteRune(current)
			}
		}
	}
	output.WriteByte('"')
}

type canonicalParser struct {
	data      []byte
	index     int
	nodeCount int
	bounds    jsonBounds
}

func (parser *canonicalParser) parse() (canonicalValue, error) {
	parser.skipWhitespace()
	value, err := parser.parseValue(0)
	if err != nil {
		return canonicalValue{}, err
	}
	parser.skipWhitespace()
	if parser.index != len(parser.data) {
		return canonicalValue{}, ErrNonCanonical
	}
	return value, nil
}

func (parser *canonicalParser) parseValue(depth int) (canonicalValue, error) {
	if depth > parser.bounds.maximumDepth || parser.index >= len(parser.data) {
		return canonicalValue{}, ErrNonCanonical
	}
	parser.nodeCount++
	if parser.nodeCount > parser.bounds.maximumNodeCount {
		return canonicalValue{}, fmt.Errorf("%w: jsonNodeCount", ErrInvalidRecord)
	}
	switch parser.data[parser.index] {
	case '{':
		return parser.parseObject(depth)
	case '[':
		return parser.parseArray(depth)
	case '"':
		text, err := parser.parseString()
		return canonicalValue{kind: canonicalString, text: text}, err
	case 't':
		if err := parser.consumeLiteral("true"); err != nil {
			return canonicalValue{}, err
		}
		return canonicalValue{kind: canonicalBoolean, boolean: true}, nil
	case 'f':
		if err := parser.consumeLiteral("false"); err != nil {
			return canonicalValue{}, err
		}
		return canonicalValue{kind: canonicalBoolean}, nil
	case 'n':
		if err := parser.consumeLiteral("null"); err != nil {
			return canonicalValue{}, err
		}
		return canonicalValue{kind: canonicalNull}, nil
	case '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		integer, err := parser.parseInteger()
		return canonicalValue{kind: canonicalInteger, text: integer}, err
	default:
		return canonicalValue{}, ErrNonCanonical
	}
}

func (parser *canonicalParser) parseObject(depth int) (canonicalValue, error) {
	parser.index++
	parser.skipWhitespace()
	if parser.consumeByte('}') {
		return canonicalValue{kind: canonicalObject}, nil
	}
	entries := make([]canonicalEntry, 0)
	keys := make(map[string]struct{})
	for {
		if len(entries) >= parser.bounds.maximumContainerEntries || parser.index >= len(parser.data) || parser.data[parser.index] != '"' {
			return canonicalValue{}, fmt.Errorf("%w: jsonContainerEntries", ErrInvalidRecord)
		}
		key, err := parser.parseString()
		if err != nil {
			return canonicalValue{}, err
		}
		if _, exists := keys[key]; exists {
			return canonicalValue{}, duplicateValue("jsonKey")
		}
		keys[key] = struct{}{}
		parser.skipWhitespace()
		if !parser.consumeByte(':') {
			return canonicalValue{}, ErrNonCanonical
		}
		parser.skipWhitespace()
		child, err := parser.parseValue(depth + 1)
		if err != nil {
			return canonicalValue{}, err
		}
		entries = append(entries, canonicalEntry{key: key, value: child})
		parser.skipWhitespace()
		if parser.consumeByte('}') {
			return canonicalValue{kind: canonicalObject, object: entries}, nil
		}
		if !parser.consumeByte(',') {
			return canonicalValue{}, ErrNonCanonical
		}
		parser.skipWhitespace()
	}
}

func (parser *canonicalParser) parseArray(depth int) (canonicalValue, error) {
	parser.index++
	parser.skipWhitespace()
	if parser.consumeByte(']') {
		return canonicalValue{kind: canonicalArray}, nil
	}
	values := make([]canonicalValue, 0)
	for {
		if len(values) >= parser.bounds.maximumContainerEntries {
			return canonicalValue{}, fmt.Errorf("%w: jsonContainerEntries", ErrInvalidRecord)
		}
		child, err := parser.parseValue(depth + 1)
		if err != nil {
			return canonicalValue{}, err
		}
		values = append(values, child)
		parser.skipWhitespace()
		if parser.consumeByte(']') {
			return canonicalValue{kind: canonicalArray, array: values}, nil
		}
		if !parser.consumeByte(',') {
			return canonicalValue{}, ErrNonCanonical
		}
		parser.skipWhitespace()
	}
}

func (parser *canonicalParser) parseString() (string, error) {
	if !parser.consumeByte('"') {
		return "", ErrNonCanonical
	}
	var output []rune
	for parser.index < len(parser.data) {
		current := parser.data[parser.index]
		parser.index++
		switch current {
		case '"':
			return string(output), nil
		case '\\':
			if parser.index >= len(parser.data) {
				return "", ErrNonCanonical
			}
			escaped := parser.data[parser.index]
			parser.index++
			switch escaped {
			case '"', '\\', '/':
				output = append(output, rune(escaped))
			case 'b':
				output = append(output, '\b')
			case 'f':
				output = append(output, '\f')
			case 'n':
				output = append(output, '\n')
			case 'r':
				output = append(output, '\r')
			case 't':
				output = append(output, '\t')
			case 'u':
				first, err := parser.parseHexQuad()
				if err != nil {
					return "", err
				}
				if utf16.IsSurrogate(first) {
					if first < 0xd800 || first > 0xdbff || parser.index+2 > len(parser.data) || parser.data[parser.index] != '\\' || parser.data[parser.index+1] != 'u' {
						return "", ErrNonCanonical
					}
					parser.index += 2
					second, err := parser.parseHexQuad()
					if err != nil || second < 0xdc00 || second > 0xdfff {
						return "", ErrNonCanonical
					}
					output = append(output, utf16.DecodeRune(first, second))
				} else {
					output = append(output, first)
				}
			default:
				return "", ErrNonCanonical
			}
		default:
			if current < 0x20 {
				return "", ErrNonCanonical
			}
			parser.index--
			r, width := utf8.DecodeRune(parser.data[parser.index:])
			if r == utf8.RuneError && width == 1 {
				return "", ErrNonCanonical
			}
			output = append(output, r)
			parser.index += width
		}
	}
	return "", ErrNonCanonical
}

func (parser *canonicalParser) parseHexQuad() (rune, error) {
	if parser.index+4 > len(parser.data) {
		return 0, ErrNonCanonical
	}
	value, err := strconv.ParseUint(string(parser.data[parser.index:parser.index+4]), 16, 16)
	if err != nil {
		return 0, ErrNonCanonical
	}
	parser.index += 4
	return rune(value), nil
}

func (parser *canonicalParser) parseInteger() (string, error) {
	start := parser.index
	negative := parser.consumeByte('-')
	if negative {
		if parser.index == len(parser.data) {
			return "", ErrNonCanonical
		}
	}
	if parser.index >= len(parser.data) {
		return "", ErrNonCanonical
	}
	if parser.data[parser.index] == '0' {
		if negative {
			return "", ErrNonCanonical
		}
		parser.index++
		if parser.index < len(parser.data) && parser.data[parser.index] >= '0' && parser.data[parser.index] <= '9' {
			return "", ErrNonCanonical
		}
	} else {
		if parser.data[parser.index] < '1' || parser.data[parser.index] > '9' {
			return "", ErrNonCanonical
		}
		for parser.index < len(parser.data) && parser.data[parser.index] >= '0' && parser.data[parser.index] <= '9' {
			parser.index++
		}
	}
	if parser.index < len(parser.data) && !isJSONDelimiter(parser.data[parser.index]) {
		return "", ErrNonCanonical
	}
	return string(parser.data[start:parser.index]), nil
}

func (parser *canonicalParser) consumeLiteral(value string) error {
	if parser.index+len(value) > len(parser.data) || string(parser.data[parser.index:parser.index+len(value)]) != value {
		return ErrNonCanonical
	}
	parser.index += len(value)
	if parser.index < len(parser.data) && !isJSONDelimiter(parser.data[parser.index]) {
		return ErrNonCanonical
	}
	return nil
}

func (parser *canonicalParser) consumeByte(value byte) bool {
	if parser.index >= len(parser.data) || parser.data[parser.index] != value {
		return false
	}
	parser.index++
	return true
}

func (parser *canonicalParser) skipWhitespace() {
	for parser.index < len(parser.data) {
		switch parser.data[parser.index] {
		case ' ', '\t', '\n', '\r':
			parser.index++
		default:
			return
		}
	}
}

func isJSONDelimiter(value byte) bool {
	switch value {
	case ',', ']', '}', ' ', '\t', '\n', '\r':
		return true
	default:
		return false
	}
}
