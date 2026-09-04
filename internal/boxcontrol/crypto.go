package boxcontrol

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"

	"github.com/google/uuid"
	"golang.org/x/crypto/chacha20poly1305"
)

type SealedConnectionResult struct {
	Version         int    `json:"version"`
	ServerPublicKey string `json:"serverPublicKey"`
	Nonce           string `json:"nonce"`
	Ciphertext      string `json:"ciphertext"`
}

type ConnectionResultPayload struct {
	Version    int                  `json:"version"`
	BoxID      uuid.UUID            `json:"boxID"`
	GrantToken string               `json:"grantToken"`
	Profile    AuthenticatedProfile `json:"profile"`
}

func sealConnectionResult(
	requestID uuid.UUID,
	clientPublicKey [32]byte,
	payload ConnectionResultPayload,
	random io.Reader,
) ([]byte, error) {
	if random == nil {
		random = rand.Reader
	}
	curve := ecdh.X25519()
	clientKey, err := curve.NewPublicKey(clientPublicKey[:])
	if err != nil {
		return nil, errors.New("client handoff key is invalid")
	}
	serverKey, err := curve.GenerateKey(random)
	if err != nil {
		return nil, err
	}
	shared, err := serverKey.ECDH(clientKey)
	if err != nil {
		return nil, err
	}
	context := append([]byte("facets-box-app-handoff-v1\x00"), requestID[:]...)
	material := append(context, shared...)
	key := sha256.Sum256(material)
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(random, nonce); err != nil {
		return nil, err
	}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	if len(plaintext) > 768*1024 {
		return nil, errors.New("connection handoff is too large")
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, context)
	return json.Marshal(SealedConnectionResult{
		Version:         SchemaVersion,
		ServerPublicKey: base64.RawURLEncoding.EncodeToString(serverKey.PublicKey().Bytes()),
		Nonce:           base64.RawURLEncoding.EncodeToString(nonce),
		Ciphertext:      base64.RawURLEncoding.EncodeToString(ciphertext),
	})
}

func signPublicManifest(privateKey ed25519.PrivateKey, payload PublicManifestPayload) (SignedPublicManifest, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedPublicManifest{}, errors.New("Box identity key is invalid")
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return SignedPublicManifest{}, err
	}
	signature := ed25519.Sign(privateKey, encoded)
	return SignedPublicManifest{
		Payload:   base64.RawURLEncoding.EncodeToString(encoded),
		Signature: base64.RawURLEncoding.EncodeToString(signature),
	}, nil
}
