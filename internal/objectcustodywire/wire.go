// Package objectcustodywire validates bounded, opaque immutable ciphertext.
// It provides no decryption, service authorization, scope linking, persistence,
// publication receipt, capacity accounting or deletion authority.
package objectcustodywire

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"

	"github.com/google/uuid"
)

const (
	HeaderBytes           = 54
	WireOverhead          = HeaderBytes + 12 + 16
	MaximumPlaintextBytes = 4 * 1024 * 1024
	AuthenticationDomain  = "Facets immutable object custody v1\x00"
)

var (
	ErrHeader    = errors.New("invalid immutable object header")
	ErrWire      = errors.New("invalid immutable object wire")
	ErrReference = errors.New("invalid immutable object reference")
	magic        = []byte{0x46, 0x43, 0x4f, 0x01}
)

type Header struct {
	ScopeID        uuid.UUID
	ContentEpoch   uint64
	IncarnationID  uuid.UUID
	PlaintextBytes uint64
}

func (h Header) Validate() error {
	if h.ScopeID == uuid.Nil || h.IncarnationID == uuid.Nil || h.ContentEpoch == 0 ||
		h.PlaintextBytes > MaximumPlaintextBytes {
		return ErrHeader
	}
	return nil
}

func (h Header) Encode() ([]byte, error) {
	if err := h.Validate(); err != nil {
		return nil, err
	}
	result := make([]byte, HeaderBytes)
	copy(result[:4], magic)
	copy(result[4:20], h.ScopeID[:])
	binary.BigEndian.PutUint64(result[20:28], h.ContentEpoch)
	copy(result[28:44], h.IncarnationID[:])
	binary.BigEndian.PutUint16(result[44:46], 1)
	binary.BigEndian.PutUint64(result[46:54], h.PlaintextBytes)
	return result, nil
}

type Reference struct {
	Header       Header
	CiphertextID string
}

func (r Reference) Validate() error {
	if err := r.Header.Validate(); err != nil {
		return err
	}
	id, err := hex.DecodeString(r.CiphertextID)
	if err != nil || len(id) != sha256.Size || hex.EncodeToString(id) != r.CiphertextID {
		return ErrReference
	}
	return nil
}

// Inspect verifies structure and computes a digest, not authenticity or access.
// Never treat a successfully inspected wire as a grant or a complete FEF root.
func Inspect(wire []byte) (Reference, error) {
	if len(wire) < WireOverhead || len(wire) > WireOverhead+MaximumPlaintextBytes {
		return Reference{}, ErrWire
	}
	if !bytes.Equal(wire[:4], magic) || binary.BigEndian.Uint16(wire[44:46]) != 1 {
		return Reference{}, ErrHeader
	}
	h := Header{ContentEpoch: binary.BigEndian.Uint64(wire[20:28]),
		PlaintextBytes: binary.BigEndian.Uint64(wire[46:54])}
	copy(h.ScopeID[:], wire[4:20])
	copy(h.IncarnationID[:], wire[28:44])
	if err := h.Validate(); err != nil {
		return Reference{}, err
	}
	// The bound above and validated h avoid integer conversion/addition overflow.
	if len(wire) != WireOverhead+int(h.PlaintextBytes) {
		return Reference{}, ErrWire
	}
	digest := sha256.Sum256(wire)
	return Reference{Header: h, CiphertextID: hex.EncodeToString(digest[:])}, nil
}

// Verify compares against a reference already authorized by its service. This
// low-level routine must not infer that authorization from client headers.
func Verify(wire []byte, expected Reference) error {
	if err := expected.Validate(); err != nil {
		return err
	}
	actual, err := Inspect(wire)
	if err != nil {
		return err
	}
	if actual != expected {
		return ErrReference
	}
	return nil
}
