package testfixture_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"golang.org/x/crypto/hkdf"
)

const (
	jobCapsuleChunkKeyDomain = "net.simplyformed.facets.job-capsule.chunk-key.v1\x00"
	jobCapsuleChunkAADDomain = "net.simplyformed.facets.job-capsule.chunk-aad.v1\x00"
)

//go:embed job-capsule-chunk-cryptography-portable-v1.json
var jobCapsuleChunkFixture []byte

type portableJobCapsuleChunkVector struct {
	BindingSHA256           string `json:"bindingSHA256"`
	ContentKeyHex           string `json:"contentKeyHex"`
	CryptographicProfile    string `json:"cryptographicProfile"`
	DerivedChunkKeyHex      string `json:"derivedChunkKeyHex"`
	HeaderCanonicalJSON     string `json:"headerCanonicalJSON"`
	NonceHex                string `json:"nonceHex"`
	PlaintextUTF8           string `json:"plaintextUTF8"`
	ProtocolVersion         int    `json:"protocolVersion"`
	SealedCombinedBase64URL string `json:"sealedCombinedBase64URL"`
	SyntheticTestOnly       bool   `json:"syntheticTestOnly"`
}

type portableJobCapsuleChunkHeader struct {
	ChunkCount         int64  `json:"chunkCount"`
	ChunkIndex         int64  `json:"chunkIndex"`
	PayloadID          string `json:"payloadID"`
	PlaintextByteCount int64  `json:"plaintextByteCount"`
	ProtocolVersion    int    `json:"protocolVersion"`
}

func TestJobCapsuleChunkPortableKnownAnswer(t *testing.T) {
	var vector portableJobCapsuleChunkVector
	decodeStrict(t, jobCapsuleChunkFixture, &vector)
	if vector.ProtocolVersion != 1 || !vector.SyntheticTestOnly || vector.CryptographicProfile != "HKDF-SHA256+A256GCM" {
		t.Fatalf("unexpected portable Job Capsule profile: %+v", vector)
	}

	contentKey := decodeHex(t, vector.ContentKeyHex, 32)
	_ = decodeHex(t, vector.BindingSHA256, sha256.Size)
	binding := []byte(vector.BindingSHA256)
	nonce := decodeHex(t, vector.NonceHex, 12)
	expectedDerivedKey := decodeHex(t, vector.DerivedChunkKeyHex, 32)
	header := []byte(vector.HeaderCanonicalJSON)
	assertCanonicalChunkHeader(t, header, int64(len(vector.PlaintextUTF8)))
	derivedKey := deriveJobCapsuleChunkKey(t, contentKey, binding, header)
	if !bytes.Equal(derivedKey, expectedDerivedKey) {
		t.Fatalf("derived key mismatch: got %x want %x", derivedKey, expectedDerivedKey)
	}

	combined, err := base64.RawURLEncoding.DecodeString(vector.SealedCombinedBase64URL)
	if err != nil || base64.RawURLEncoding.EncodeToString(combined) != vector.SealedCombinedBase64URL {
		t.Fatalf("noncanonical sealed bytes: %v", err)
	}
	if len(combined) < len(nonce)+16 || !bytes.Equal(combined[:len(nonce)], nonce) {
		t.Fatal("combined value does not contain the exact fixture nonce")
	}
	plaintext := []byte(vector.PlaintextUTF8)
	if opened := openJobCapsuleChunk(t, derivedKey, binding, header, combined); !bytes.Equal(opened, plaintext) {
		t.Fatalf("plaintext mismatch: got %q want %q", opened, plaintext)
	}
	if sealed := sealJobCapsuleChunk(t, derivedKey, binding, header, nonce, plaintext); !bytes.Equal(sealed, combined) {
		t.Fatalf("sealed bytes mismatch: got %x want %x", sealed, combined)
	}
}

func TestJobCapsuleChunkPortableVectorRejectsAuthenticatedMutations(t *testing.T) {
	var vector portableJobCapsuleChunkVector
	decodeStrict(t, jobCapsuleChunkFixture, &vector)
	contentKey := decodeHex(t, vector.ContentKeyHex, 32)
	_ = decodeHex(t, vector.BindingSHA256, sha256.Size)
	binding := []byte(vector.BindingSHA256)
	header := []byte(vector.HeaderCanonicalJSON)
	combined, err := base64.RawURLEncoding.DecodeString(vector.SealedCombinedBase64URL)
	if err != nil {
		t.Fatal(err)
	}
	derivedKey := deriveJobCapsuleChunkKey(t, contentKey, binding, header)

	changedCiphertext := append([]byte(nil), combined...)
	changedCiphertext[len(changedCiphertext)-1] ^= 0xff
	if _, err := openJobCapsuleChunkRaw(derivedKey, binding, header, changedCiphertext); err == nil {
		t.Fatal("changed ciphertext authenticated")
	}
	changedHeader := append([]byte(nil), header...)
	changedHeader[len(changedHeader)-1] ^= 0x01
	if _, err := openJobCapsuleChunkRaw(derivedKey, binding, changedHeader, combined); err == nil {
		t.Fatal("changed header authenticated")
	}
	changedBinding := append([]byte(nil), binding...)
	changedBinding[0] ^= 0x01
	changedBindingKey := deriveJobCapsuleChunkKey(
		t,
		contentKey,
		changedBinding,
		header,
	)
	if _, err := openJobCapsuleChunkRaw(changedBindingKey, changedBinding, header, combined); err == nil {
		t.Fatal("changed binding authenticated")
	}
}

func assertCanonicalChunkHeader(t *testing.T, encoded []byte, expectedPlaintextBytes int64) {
	t.Helper()
	var header portableJobCapsuleChunkHeader
	decodeStrict(t, encoded, &header)
	if header.ProtocolVersion != 1 || header.ChunkCount != 3 || header.ChunkIndex != 1 || header.PlaintextByteCount != expectedPlaintextBytes || header.PayloadID != "56565656-5656-4656-8656-565656565656" {
		t.Fatalf("unexpected chunk header: %+v", header)
	}
	canonical, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonical, encoded) {
		t.Fatalf("noncanonical chunk header: got %s want %s", encoded, canonical)
	}
}

func deriveJobCapsuleChunkKey(t *testing.T, contentKey, binding, header []byte) []byte {
	t.Helper()
	salt := sha256.Sum256(binding)
	info := concatenate([]byte(jobCapsuleChunkKeyDomain), binding, header)
	derived := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, contentKey, salt[:], info), derived); err != nil {
		t.Fatal(err)
	}
	return derived
}

func sealJobCapsuleChunk(t *testing.T, key, binding, header, nonce, plaintext []byte) []byte {
	t.Helper()
	gcm := newJobCapsuleGCM(t, key)
	aad := concatenate([]byte(jobCapsuleChunkAADDomain), binding, header)
	return append(append([]byte(nil), nonce...), gcm.Seal(nil, nonce, plaintext, aad)...)
}

func openJobCapsuleChunk(t *testing.T, key, binding, header, combined []byte) []byte {
	t.Helper()
	plaintext, err := openJobCapsuleChunkRaw(key, binding, header, combined)
	if err != nil {
		t.Fatal(err)
	}
	return plaintext
}

func openJobCapsuleChunkRaw(key, binding, header, combined []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(combined) < gcm.NonceSize()+gcm.Overhead() {
		return nil, errors.New("invalid sealed chunk length")
	}
	nonce := combined[:gcm.NonceSize()]
	aad := concatenate([]byte(jobCapsuleChunkAADDomain), binding, header)
	return gcm.Open(nil, nonce, combined[gcm.NonceSize():], aad)
}

func newJobCapsuleGCM(t *testing.T, key []byte) cipher.AEAD {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return gcm
}

func decodeHex(t *testing.T, value string, expectedBytes int) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != expectedBytes || hex.EncodeToString(decoded) != value {
		t.Fatalf("noncanonical hex value length=%d err=%v", len(decoded), err)
	}
	return decoded
}

func concatenate(values ...[]byte) []byte {
	var result []byte
	for _, value := range values {
		result = append(result, value...)
	}
	return result
}
