package objectcustodywire

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func fixture(t *testing.T) map[string]string {
	t.Helper()
	data, err := os.ReadFile("testdata/immutable-object-wire-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]string
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func unhex(t *testing.T, value string) []byte {
	t.Helper()
	result, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestExactSwiftFixtureAndStandardAEAD(t *testing.T) {
	f := fixture(t)
	wire := unhex(t, f["wireHex"])
	r, err := Inspect(wire)
	if err != nil {
		t.Fatal(err)
	}
	if r.CiphertextID != f["ciphertextID"] || r.Header.ContentEpoch != 7 || r.Header.PlaintextBytes != 34 {
		t.Fatalf("unexpected public fixture reference: %#v", r)
	}
	header, err := r.Header.Encode()
	if err != nil || !bytes.Equal(header, unhex(t, f["headerHex"])) {
		t.Fatal("header mismatch", err)
	}
	aad := append([]byte(AuthenticationDomain), header...)
	if !bytes.Equal(aad, unhex(t, f["associatedDataHex"])) {
		t.Fatal("AAD mismatch")
	}
	// Public fixture key is used only in tests. Production Node code does not
	// import AES, decrypt an object, or accept an object key.
	block, err := aes.NewCipher(unhex(t, f["keyHex"]))
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	sealed := gcm.Seal(nil, unhex(t, f["nonceHex"]), unhex(t, f["plaintextHex"]), aad)
	if !bytes.Equal(sealed, unhex(t, f["ciphertextAndTagHex"])) {
		t.Fatal("ciphertext/tag mismatch")
	}
	opened, err := gcm.Open(nil, wire[54:66], wire[66:], aad)
	if err != nil || !bytes.Equal(opened, unhex(t, f["plaintextHex"])) {
		t.Fatal("open mismatch", err)
	}
	if err := Verify(wire, r); err != nil {
		t.Fatal(err)
	}
}

func TestEveryByteBoundToReference(t *testing.T) {
	wire := unhex(t, fixture(t)["wireHex"])
	r, err := Inspect(wire)
	if err != nil {
		t.Fatal(err)
	}
	for offset := range wire {
		changed := bytes.Clone(wire)
		changed[offset] ^= 1
		if err := Verify(changed, r); err == nil {
			t.Fatalf("accepted changed byte %d", offset)
		}
	}
}

func TestTruncationTrailingAndOversize(t *testing.T) {
	wire := unhex(t, fixture(t)["wireHex"])
	for count := 0; count < len(wire); count++ {
		if _, err := Inspect(wire[:count]); err == nil {
			t.Fatalf("accepted prefix %d", count)
		}
	}
	if _, err := Inspect(append(bytes.Clone(wire), 0)); err == nil {
		t.Fatal("accepted trailing data")
	}
	if _, err := Inspect(make([]byte, WireOverhead+MaximumPlaintextBytes+1)); err == nil {
		t.Fatal("accepted oversize")
	}
}

func TestInvalidHeaderFieldsFailClosed(t *testing.T) {
	wire := unhex(t, fixture(t)["wireHex"])
	for _, offset := range []int{0, 1, 2, 3, 44, 45, 46} {
		changed := bytes.Clone(wire)
		changed[offset] ^= 0x80
		if _, err := Inspect(changed); err == nil {
			t.Fatalf("accepted malformed field %d", offset)
		}
	}
	for _, pair := range [][2]int{{4, 20}, {20, 28}, {28, 44}} {
		changed := bytes.Clone(wire)
		clear(changed[pair[0]:pair[1]])
		if _, err := Inspect(changed); err == nil {
			t.Fatal("accepted zero identity/epoch")
		}
	}
	changed := bytes.Clone(wire)
	binary.BigEndian.PutUint64(changed[46:54], ^uint64(0))
	if _, err := Inspect(changed); err == nil {
		t.Fatal("accepted overflow length")
	}
}

func TestEmptyAndMaximumOpaqueRecords(t *testing.T) {
	for _, count := range []uint64{0, MaximumPlaintextBytes} {
		h := Header{ScopeID: uuid.New(), ContentEpoch: ^uint64(0), IncarnationID: uuid.New(), PlaintextBytes: count}
		header, err := h.Encode()
		if err != nil {
			t.Fatal(err)
		}
		wire := append(header, make([]byte, int(count)+28)...)
		r, err := Inspect(wire)
		if err != nil || r.Header != h {
			t.Fatal("opaque bounds failed", err)
		}
		// Zero-filled opaque bytes are structurally legal but NOT authenticated.
		// This test deliberately does not claim an Inspect result can decrypt.
	}
}

func TestWrongReferenceScopeEpochAndIdentity(t *testing.T) {
	wire := unhex(t, fixture(t)["wireHex"])
	r, _ := Inspect(wire)
	for _, mutate := range []func(*Reference){
		func(r *Reference) { r.Header.ScopeID = uuid.New() },
		func(r *Reference) { r.Header.ContentEpoch++ },
		func(r *Reference) { r.Header.IncarnationID = uuid.New() },
		func(r *Reference) { r.Header.PlaintextBytes++ },
		func(r *Reference) { r.CiphertextID = strings.Repeat("0", 64) },
	} {
		changed := r
		mutate(&changed)
		if err := Verify(wire, changed); err == nil {
			t.Fatal("accepted wrong reference")
		}
	}
	for _, id := range []string{"", strings.Repeat("a", 63), strings.Repeat("G", 64), strings.ToUpper(r.CiphertextID)} {
		changed := r
		changed.CiphertextID = id
		if err := changed.Validate(); err == nil {
			t.Fatal("accepted malformed digest")
		}
	}
}

func FuzzInspectNeverPanicsOrAcceptsInconsistentLength(f *testing.F) {
	data, err := os.ReadFile("testdata/immutable-object-wire-v1.json")
	if err != nil {
		f.Fatal(err)
	}
	var fixture map[string]string
	if err := json.Unmarshal(data, &fixture); err != nil {
		f.Fatal(err)
	}
	wire, _ := hex.DecodeString(fixture["wireHex"])
	f.Add(wire)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, wire []byte) {
		r, err := Inspect(wire)
		if err != nil {
			return
		}
		if r.Validate() != nil || len(wire) != WireOverhead+int(r.Header.PlaintextBytes) {
			t.Fatal("inconsistent inspected record")
		}
		header, err := r.Header.Encode()
		if err != nil || !bytes.Equal(header, wire[:HeaderBytes]) || Verify(wire, r) != nil {
			t.Fatal("noncanonical inspected record")
		}
	})
}
