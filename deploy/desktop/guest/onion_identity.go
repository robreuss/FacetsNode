package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha3"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Kept outside the Tor-owned volume. Fingerprints detect replacement of an
// expanded private key even when a stale hostname/public-key file remains.
// They are continuity evidence, not proof against a compromised guest root.
type onionIdentity struct {
	Onion      string `json:"onion"`
	PublicHash string `json:"publicHash"`
	SecretHash string `json:"secretHash"`
}

func boundedIdentityFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit {
		return nil, errors.New("identity file unavailable")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("identity file unavailable")
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("identity file changed while opening")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, errors.New("identity file unreadable")
	}
	return b, nil
}

func readOnionIdentity(root string) (onionIdentity, error) {
	var out onionIdentity
	host, err := boundedIdentityFile(filepath.Join(root, "hostname"), 63)
	if err != nil {
		return out, err
	}
	pub, err := boundedIdentityFile(filepath.Join(root, "hs_ed25519_public_key"), 64)
	if err != nil {
		return out, err
	}
	secret, err := boundedIdentityFile(filepath.Join(root, "hs_ed25519_secret_key"), 96)
	if err != nil {
		return out, err
	}
	if len(pub) != 64 || len(secret) != 96 ||
		!bytes.Equal(pub[:32], []byte("== ed25519v1-public: type0 ==\x00\x00\x00")) ||
		!bytes.Equal(secret[:32], []byte("== ed25519v1-secret: type0 ==\x00\x00\x00")) {
		return out, errors.New("invalid onion key encoding")
	}
	// https://spec.torproject.org/rend-spec/encoding-onion-addresses.html
	input := append([]byte(".onion checksum"), pub[32:]...)
	checksum := sha3.Sum256(append(input, 3))
	address := append(append(append([]byte{}, pub[32:]...), checksum[:2]...), 3)
	out.Onion = strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(address)) + ".onion"
	if string(host) != out.Onion && string(host) != out.Onion+"\n" {
		return out, errors.New("onion hostname does not match public key")
	}
	publicSum, secretSum := sha256.Sum256(pub), sha256.Sum256(secret)
	out.PublicHash, out.SecretHash = hex.EncodeToString(publicSum[:]), hex.EncodeToString(secretSum[:])
	return out, nil
}

func retainOnionIdentity(path string, current onionIdentity, allowCreate bool) error {
	if b, err := boundedIdentityFile(path, 1024); err == nil {
		var retained onionIdentity
		if json.Unmarshal(b, &retained) != nil || retained != current {
			return errors.New("retained onion identity changed")
		}
		return nil
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) || !allowCreate {
		return errors.New("retained onion evidence unavailable")
	}
	return writeJSONFile(path, current)
}
