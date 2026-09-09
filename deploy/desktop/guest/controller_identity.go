package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"

	"github.com/google/uuid"
)

type controllerIdentity struct {
	BoxID     string `json:"boxID"`
	PublicKey string `json:"publicKey"`
}

func readControllerKey(path string) (ed25519.PrivateKey, error) {
	b, e := boundedIdentityFile(path, 256)
	if e != nil {
		return nil, e
	}
	key, e := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(b)))
	if e != nil || len(key) != ed25519.PrivateKeySize || !ed25519.NewKeyFromSeed(key[:ed25519.SeedSize]).Equal(ed25519.PrivateKey(key)) {
		return nil, errors.New("invalid retained controller identity")
	}
	return ed25519.PrivateKey(key), nil
}

func retainControllerIdentity(path, boxID string, key ed25519.PrivateKey) (controllerIdentity, error) {
	var previous controllerIdentity
	id, e := uuid.Parse(boxID)
	if e != nil || id == uuid.Nil || len(key) != ed25519.PrivateKeySize {
		return previous, errors.New("invalid controller identity evidence")
	}
	current := controllerIdentity{BoxID: boxID, PublicKey: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))}
	if b, e := os.ReadFile(path); e == nil {
		if json.Unmarshal(b, &previous) != nil || previous != current {
			return previous, errors.New("controller identity changed")
		}
	} else if os.IsNotExist(e) {
		if e = writeJSONFile(path, current); e != nil {
			return previous, e
		}
	} else {
		return previous, e
	}
	return current, nil
}
