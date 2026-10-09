package computequeue

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type canonicalProbe struct {
	ProtocolVersion int    `json:"protocolVersion"`
	Text            string `json:"text"`
}

func (probe canonicalProbe) Validate() error {
	return requireProtocol(probe.ProtocolVersion)
}

func TestCanonicalJSONRoundTripsExactPortableBytes(t *testing.T) {
	wire := []byte(`{"protocolVersion":1,"text":"<&>/\u0001\u2028\u2029"}`)
	decoded, err := DecodeCanonical[canonicalProbe](wire)
	if err != nil {
		t.Fatalf("decode canonical probe: %v", err)
	}
	if decoded.Text != "<&>/\x01\u2028\u2029" {
		t.Fatalf("decoded text = %q", decoded.Text)
	}
	encoded, err := EncodeCanonical(decoded)
	if err != nil {
		t.Fatalf("encode canonical probe: %v", err)
	}
	if !bytes.Equal(encoded, wire) {
		t.Fatalf("round trip\n got %s\nwant %s", encoded, wire)
	}
}

func TestCanonicalJSONRejectsHostileOrAlternateRepresentations(t *testing.T) {
	valid := `{"protocolVersion":1,"text":"ok"}`
	testCases := map[string]string{
		"trailing newline":            valid + "\n",
		"leading whitespace":          " " + valid,
		"unsorted keys":               `{"text":"ok","protocolVersion":1}`,
		"duplicate key":               `{"protocolVersion":1,"protocolVersion":1,"text":"ok"}`,
		"unknown canonical field":     `{"aaa":1,"protocolVersion":1,"text":"ok"}`,
		"floating point":              `{"protocolVersion":1,"text":"ok","z":1.0}`,
		"exponent":                    `{"protocolVersion":1,"text":"ok","z":1e0}`,
		"negative zero":               `{"protocolVersion":1,"text":"ok","z":-0}`,
		"escaped slash":               `{"protocolVersion":1,"text":"a\/b"}`,
		"nonminimal unicode":          `{"protocolVersion":1,"text":"\u006f\u006b"}`,
		"literal line separator":      "{\"protocolVersion\":1,\"text\":\"\u2028\"}",
		"literal paragraph separator": "{\"protocolVersion\":1,\"text\":\"\u2029\"}",
		"unnecessary unicode escape":  `{"protocolVersion":1,"text":"\u202a"}`,
		"unsupported protocol":        `{"protocolVersion":2,"text":"ok"}`,
	}
	for name, wire := range testCases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeCanonical[canonicalProbe]([]byte(wire)); err == nil {
				t.Fatalf("accepted %s", wire)
			}
		})
	}
}

func TestCanonicalJSONBoundsDocumentAndDepth(t *testing.T) {
	oversized := bytes.Repeat([]byte{' '}, MaximumDocumentBytes+1)
	if _, err := canonicalize(oversized); err == nil {
		t.Fatal("accepted oversized document")
	}

	deep := strings.Repeat("[", MaximumDepth+2) + "0" +
		strings.Repeat("]", MaximumDepth+2)
	if _, err := canonicalize([]byte(deep)); err == nil {
		t.Fatal("accepted over-depth document")
	}

	invalidUTF8 := []byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}
	if _, err := canonicalize(invalidUTF8); err == nil {
		t.Fatal("accepted invalid UTF-8")
	}
}

func TestCanonicalJSONSortsLargeReverseOrderedObject(t *testing.T) {
	const entryCount = 4_096
	var wire strings.Builder
	wire.WriteByte('{')
	for index := entryCount - 1; index >= 0; index-- {
		if index != entryCount-1 {
			wire.WriteByte(',')
		}
		wire.WriteString(strconv.Quote("key-" + fmt.Sprintf("%06d", index)))
		wire.WriteString(":0")
	}
	wire.WriteByte('}')
	canonical, err := canonicalize([]byte(wire.String()))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(canonical, []byte(`{"key-000000":0,"key-000001":0`)) ||
		!bytes.HasSuffix(canonical, []byte(`"key-004095":0}`)) {
		t.Fatal("large reverse-ordered object was not sorted canonically")
	}
}

func TestCanonicalJSONReportsNonCanonicalSeparately(t *testing.T) {
	_, err := DecodeCanonical[canonicalProbe]([]byte(`{"text":"ok","protocolVersion":1}`))
	if !errors.Is(err, ErrNonCanonical) {
		t.Fatalf("error = %v, want ErrNonCanonical", err)
	}
}

func TestCanonicalJSONRejectsNullForRequiredArrays(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "compute-queue-immediate-occurrence-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.TrimSuffix(data, []byte{'\n'})
	mutated := bytes.Replace(data, []byte(`"receiptIDs":[]`), []byte(`"receiptIDs":null`), 1)
	if bytes.Equal(mutated, data) {
		t.Fatal("fixture did not contain an empty required receiptIDs array")
	}
	if _, err := DecodeCanonical[scheduleOccurrenceFixture](mutated); err == nil {
		t.Fatal("accepted null for a required receiptIDs array")
	}

	if err := (RetryPolicy{}).Validate(); err == nil {
		t.Fatal("accepted nil required retry-policy arrays")
	}
	if err := (RetryPolicy{BackoffMillisecondsByRetry: []uint64{}, RetryableErrorCodes: []ErrorCode{}}).Validate(); err != nil {
		t.Fatalf("rejected present empty retry-policy arrays: %v", err)
	}
}

func TestFacetsObjectIDMatchesSwiftURLComponentsSchemeAcceptance(t *testing.T) {
	identifier := FacetsObjectID{ProviderRootURI: "x:%", Kind: "text", SourceID: "source"}
	if err := identifier.Validate(); err != nil {
		t.Fatalf("Swift-compatible provider root was rejected: %v", err)
	}
	identifier.ProviderRootURI = "1x:value"
	if err := identifier.Validate(); err == nil {
		t.Fatal("provider root with an invalid URI scheme was accepted")
	}
}

func TestFacetsObjectIDRejectsInvalidUTF8BeforeCanonicalEncoding(t *testing.T) {
	testCases := map[string]FacetsObjectID{
		"provider root": {
			ProviderRootURI: string([]byte{'x', ':', 0xff}),
			Kind:            "text",
			SourceID:        "source",
		},
		"source ID": {
			ProviderRootURI: "x:value",
			Kind:            "text",
			SourceID:        string([]byte{'s', 0xff}),
		},
	}
	for name, identifier := range testCases {
		t.Run(name, func(t *testing.T) {
			if err := identifier.Validate(); err == nil {
				t.Fatal("accepted invalid UTF-8")
			}
			if _, err := EncodeCanonical(identifier); err == nil {
				t.Fatal("canonical encoding replaced invalid UTF-8 instead of rejecting it")
			}
		})
	}
}

func TestLengthPrefixedDigestMatchesSwiftFixtureConstant(t *testing.T) {
	got := SHA256Digest("fixture.definition", "release-position-v1")
	want := Digest("478dfeb7ac5de34f920798e3477238309d5e42f2c221d13966841a584379d98b")
	if got != want {
		t.Fatalf("digest = %s, want %s", got, want)
	}
}
