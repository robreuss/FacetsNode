package keycustody

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

const (
	ContentKeySize = 32
	wrappedVersion = byte(1)
)

// ManagedContentKeys encrypts service-owned Shared Space content keys under a
// deployment key. The Space and epoch are authenticated as associated data so
// a stored key cannot be replayed into another authority scope.
type ManagedContentKeys struct {
	aead cipher.AEAD
}

func NewManagedContentKeys(masterKey []byte) (*ManagedContentKeys, error) {
	if len(masterKey) != ContentKeySize {
		return nil, fmt.Errorf("managed content-key encryption key must be %d bytes", ContentKeySize)
	}
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("initialize managed content-key encryption: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize managed content-key custody: %w", err)
	}
	return &ManagedContentKeys{aead: aead}, nil
}

func NewEphemeralManagedContentKeys() (*ManagedContentKeys, error) {
	masterKey := make([]byte, ContentKeySize)
	if _, err := rand.Read(masterKey); err != nil {
		return nil, fmt.Errorf("generate ephemeral managed content-key encryption key: %w", err)
	}
	return NewManagedContentKeys(masterKey)
}

func (c *ManagedContentKeys) Generate(spaceID uuid.UUID, keyEpoch uint64) (plaintext, wrapped []byte, err error) {
	plaintext = make([]byte, ContentKeySize)
	if _, err := rand.Read(plaintext); err != nil {
		return nil, nil, fmt.Errorf("generate managed content key: %w", err)
	}
	wrapped, err = c.Wrap(spaceID, keyEpoch, plaintext)
	if err != nil {
		return nil, nil, err
	}
	return plaintext, wrapped, nil
}

func (c *ManagedContentKeys) Wrap(spaceID uuid.UUID, keyEpoch uint64, plaintext []byte) ([]byte, error) {
	if c == nil || c.aead == nil {
		return nil, errors.New("managed content-key custody is not configured")
	}
	if spaceID == uuid.Nil || keyEpoch == 0 || len(plaintext) != ContentKeySize {
		return nil, errors.New("managed content-key scope or material is invalid")
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate managed content-key nonce: %w", err)
	}
	result := make([]byte, 1, 1+len(nonce)+len(plaintext)+c.aead.Overhead())
	result[0] = wrappedVersion
	result = append(result, nonce...)
	result = c.aead.Seal(result, nonce, plaintext, managedContentKeyAAD(spaceID, keyEpoch))
	return result, nil
}

func (c *ManagedContentKeys) Unwrap(spaceID uuid.UUID, keyEpoch uint64, wrapped []byte) ([]byte, error) {
	if c == nil || c.aead == nil {
		return nil, errors.New("managed content-key custody is not configured")
	}
	minimumSize := 1 + c.aead.NonceSize() + ContentKeySize + c.aead.Overhead()
	if spaceID == uuid.Nil || keyEpoch == 0 || len(wrapped) != minimumSize || wrapped[0] != wrappedVersion {
		return nil, errors.New("wrapped managed content key is invalid")
	}
	nonce := wrapped[1 : 1+c.aead.NonceSize()]
	plaintext, err := c.aead.Open(nil, nonce, wrapped[1+c.aead.NonceSize():], managedContentKeyAAD(spaceID, keyEpoch))
	if err != nil || len(plaintext) != ContentKeySize {
		return nil, errors.New("wrapped managed content key could not be authenticated")
	}
	return plaintext, nil
}

func managedContentKeyAAD(spaceID uuid.UUID, keyEpoch uint64) []byte {
	aad := make([]byte, 1+len(spaceID)+8)
	aad[0] = wrappedVersion
	copy(aad[1:], spaceID[:])
	binary.BigEndian.PutUint64(aad[1+len(spaceID):], keyEpoch)
	return aad
}
