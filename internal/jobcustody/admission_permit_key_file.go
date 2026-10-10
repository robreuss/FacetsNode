//go:build unix

package jobcustody

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/google/uuid"
)

const (
	AdmissionPermitKeyFileVersion = 1
	MaximumAdmissionAuthorities   = 64
	MaximumAdmissionPermitKeyFile = 128 * 1024
)

type AdmissionPermitKeyFileEntry struct {
	AuthorityID uuid.UUID `json:"authorityID"`
	PublicKey   string    `json:"publicKey"`
}

type AdmissionPermitKeyFile struct {
	Authorities []AdmissionPermitKeyFileEntry `json:"authorities"`
	Version     int                           `json:"version"`
}

// LoadAdmissionPermitVerifier reads the immutable Box control-plane trust
// file. The request cannot add, replace, or alias an authority key.
func LoadAdmissionPermitVerifier(path string) (*AdmissionPermitVerifier, error) {
	data, err := readAdmissionPermitKeyFile(path)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var value AdmissionPermitKeyFile
	if decoder.Decode(&value) != nil {
		return nil, ErrAdmissionPermitAuthentication
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) ||
		value.Version != AdmissionPermitKeyFileVersion || len(value.Authorities) == 0 ||
		len(value.Authorities) > MaximumAdmissionAuthorities {
		return nil, ErrAdmissionPermitAuthentication
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(data, append(canonical, '\n')) {
		return nil, ErrAdmissionPermitAuthentication
	}
	trusted := make([]AdmissionPermitVerificationKey, 0, len(value.Authorities))
	for _, entry := range value.Authorities {
		publicKey, err := base64.RawURLEncoding.Strict().DecodeString(entry.PublicKey)
		if err != nil || len(publicKey) != ed25519.PublicKeySize ||
			base64.RawURLEncoding.EncodeToString(publicKey) != entry.PublicKey {
			return nil, ErrAdmissionPermitAuthentication
		}
		key, err := NewAdmissionPermitVerificationKey(entry.AuthorityID, ed25519.PublicKey(publicKey))
		if err != nil {
			return nil, err
		}
		trusted = append(trusted, key)
	}
	return NewAdmissionPermitVerifier(trusted)
}

func readAdmissionPermitKeyFile(path string) ([]byte, error) {
	if path == "" {
		return nil, ErrAdmissionPermitAuthentication
	}
	resolved, err := filepath.Abs(path)
	if err != nil {
		return nil, ErrAdmissionPermitAuthentication
	}
	resolved = filepath.Clean(resolved)
	pathInfo, err := os.Lstat(resolved)
	if err != nil || !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 ||
		pathInfo.Mode().Perm()&0o022 != 0 || pathInfo.Size() <= 0 ||
		pathInfo.Size() > MaximumAdmissionPermitKeyFile {
		return nil, ErrAdmissionPermitAuthentication
	}
	file, err := os.Open(resolved)
	if err != nil {
		return nil, ErrAdmissionPermitAuthentication
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || openedInfo.Mode().Perm()&0o022 != 0 ||
		openedInfo.Size() <= 0 || openedInfo.Size() > MaximumAdmissionPermitKeyFile ||
		!os.SameFile(pathInfo, openedInfo) {
		return nil, ErrAdmissionPermitAuthentication
	}
	data, err := io.ReadAll(io.LimitReader(file, MaximumAdmissionPermitKeyFile+1))
	if err != nil || len(data) == 0 || len(data) > MaximumAdmissionPermitKeyFile {
		return nil, ErrAdmissionPermitAuthentication
	}
	return data, nil
}
