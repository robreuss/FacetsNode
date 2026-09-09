package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
)

func TestControllerIdentityRetentionRejectsMismatchedDatabaseAndKey(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	root := t.TempDir()
	keyPath := filepath.Join(root, "key")
	record := filepath.Join(root, "identity.json")
	_ = os.WriteFile(keyPath, []byte(base64.RawURLEncoding.EncodeToString(key)), 0600)
	if _, e := readControllerKey(keyPath); e != nil {
		t.Fatal(e)
	}
	id := uuid.NewString()
	if _, e := retainControllerIdentity(record, id, key); e != nil {
		t.Fatal(e)
	}
	if _, e := retainControllerIdentity(record, id, key); e != nil {
		t.Fatal(e)
	}
	if _, e := retainControllerIdentity(record, uuid.NewString(), key); e == nil {
		t.Fatal("accepted replacement database identity")
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	if _, e := retainControllerIdentity(record, id, other); e == nil {
		t.Fatal("accepted replacement signing identity")
	}
	key[40] ^= 1
	_ = os.WriteFile(keyPath, []byte(base64.RawURLEncoding.EncodeToString(key)), 0600)
	if _, e := readControllerKey(keyPath); e == nil {
		t.Fatal("accepted malformed private key")
	}
}
