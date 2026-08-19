package keycustody_test

import (
	"bytes"
	"testing"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/keycustody"
)

func TestManagedContentKeyRoundTripIsScopeBound(t *testing.T) {
	master := bytes.Repeat([]byte{0x42}, keycustody.ContentKeySize)
	custodian, err := keycustody.NewManagedContentKeys(master)
	if err != nil {
		t.Fatal(err)
	}
	spaceID := uuid.New()
	plaintext, wrapped, err := custodian.Generate(spaceID, 7)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := custodian.Unwrap(spaceID, 7, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recovered, plaintext) || len(recovered) != keycustody.ContentKeySize {
		t.Fatalf("managed content key did not round-trip")
	}
	if _, err := custodian.Unwrap(uuid.New(), 7, wrapped); err == nil {
		t.Fatal("expected another Space scope to reject the wrapped key")
	}
	if _, err := custodian.Unwrap(spaceID, 8, wrapped); err == nil {
		t.Fatal("expected another key epoch to reject the wrapped key")
	}
}

func TestManagedContentKeyRejectsWrongMasterAndTampering(t *testing.T) {
	spaceID := uuid.New()
	first, err := keycustody.NewManagedContentKeys(bytes.Repeat([]byte{0x11}, keycustody.ContentKeySize))
	if err != nil {
		t.Fatal(err)
	}
	second, err := keycustody.NewManagedContentKeys(bytes.Repeat([]byte{0x22}, keycustody.ContentKeySize))
	if err != nil {
		t.Fatal(err)
	}
	_, wrapped, err := first.Generate(spaceID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.Unwrap(spaceID, 1, wrapped); err == nil {
		t.Fatal("expected the wrong deployment key to fail authentication")
	}
	tampered := append([]byte(nil), wrapped...)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := first.Unwrap(spaceID, 1, tampered); err == nil {
		t.Fatal("expected tampered wrapped key to fail authentication")
	}
}

func TestManagedContentKeyConfigurationAndRandomness(t *testing.T) {
	if _, err := keycustody.NewManagedContentKeys(make([]byte, keycustody.ContentKeySize-1)); err == nil {
		t.Fatal("expected an invalid master-key length to be rejected")
	}
	custodian, err := keycustody.NewManagedContentKeys(make([]byte, keycustody.ContentKeySize))
	if err != nil {
		t.Fatal(err)
	}
	spaceID := uuid.New()
	firstPlaintext, firstWrapped, err := custodian.Generate(spaceID, 1)
	if err != nil {
		t.Fatal(err)
	}
	secondPlaintext, secondWrapped, err := custodian.Generate(spaceID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(firstPlaintext, secondPlaintext) || bytes.Equal(firstWrapped, secondWrapped) {
		t.Fatal("managed content keys and custody ciphertext must be independently randomized")
	}
}
