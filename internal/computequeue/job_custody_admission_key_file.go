//go:build unix

package computequeue

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

const (
	JobCustodyAdmissionKeyFileVersion = 1
	MaximumJobCustodyAdmissionKeys    = 64
	MaximumJobCustodyAdmissionKeyFile = 128 * 1024
)

type JobCustodyAdmissionKeyFileEntry struct {
	PublicKeyX963 string               `json:"publicKeyX963"`
	Signer        ReceiptSignerBinding `json:"signer"`
}

type JobCustodyAdmissionKeyFile struct {
	Keys    []JobCustodyAdmissionKeyFileEntry `json:"keys"`
	Version int                               `json:"version"`
}

// LoadJobCustodyP256AdmissionVerifier reads the immutable, owner-provisioned
// public-key trust file used by Job Custody. The file is configuration, not an
// enrollment endpoint: it rejects symlinks, non-regular files, group/other
// writable files, ambiguous JSON, duplicate signer bindings, and reuse of one
// public key under multiple signer identities.
func LoadJobCustodyP256AdmissionVerifier(
	path string,
) (*JobCustodyP256AdmissionVerifier, error) {
	data, err := readJobCustodyAdmissionKeyFile(path)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var value JobCustodyAdmissionKeyFile
	if err := decoder.Decode(&value); err != nil {
		return nil, ErrJobCustodyAdmissionAuthentication
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) ||
		value.Version != JobCustodyAdmissionKeyFileVersion || len(value.Keys) == 0 ||
		len(value.Keys) > MaximumJobCustodyAdmissionKeys {
		return nil, ErrJobCustodyAdmissionAuthentication
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(data, append(canonical, '\n')) {
		return nil, ErrJobCustodyAdmissionAuthentication
	}
	trusted := make([]JobCustodyP256AdmissionVerificationKey, 0, len(value.Keys))
	seenPublicKeys := make(map[[sha256.Size]byte]struct{}, len(value.Keys))
	for _, entry := range value.Keys {
		publicKey, err := base64.RawURLEncoding.Strict().DecodeString(entry.PublicKeyX963)
		if err != nil || base64.RawURLEncoding.EncodeToString(publicKey) != entry.PublicKeyX963 {
			return nil, ErrJobCustodyAdmissionAuthentication
		}
		fingerprint := sha256.Sum256(publicKey)
		if _, duplicate := seenPublicKeys[fingerprint]; duplicate {
			return nil, ErrJobCustodyAdmissionAuthentication
		}
		key, err := NewJobCustodyP256AdmissionVerificationKey(entry.Signer, publicKey)
		if err != nil {
			return nil, err
		}
		seenPublicKeys[fingerprint] = struct{}{}
		trusted = append(trusted, key)
	}
	return NewJobCustodyP256AdmissionVerifier(trusted)
}

func readJobCustodyAdmissionKeyFile(path string) ([]byte, error) {
	if path == "" {
		return nil, ErrJobCustodyAdmissionAuthentication
	}
	resolved, err := filepath.Abs(path)
	if err != nil {
		return nil, ErrJobCustodyAdmissionAuthentication
	}
	resolved = filepath.Clean(resolved)
	pathInfo, err := os.Lstat(resolved)
	if err != nil || !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 ||
		pathInfo.Mode().Perm()&0o022 != 0 || pathInfo.Size() <= 0 ||
		pathInfo.Size() > MaximumJobCustodyAdmissionKeyFile {
		return nil, ErrJobCustodyAdmissionAuthentication
	}
	file, err := os.Open(resolved)
	if err != nil {
		return nil, ErrJobCustodyAdmissionAuthentication
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || openedInfo.Mode().Perm()&0o022 != 0 ||
		openedInfo.Size() <= 0 || openedInfo.Size() > MaximumJobCustodyAdmissionKeyFile ||
		!os.SameFile(pathInfo, openedInfo) {
		return nil, ErrJobCustodyAdmissionAuthentication
	}
	data, err := io.ReadAll(io.LimitReader(file, MaximumJobCustodyAdmissionKeyFile+1))
	if err != nil || len(data) == 0 || len(data) > MaximumJobCustodyAdmissionKeyFile {
		return nil, ErrJobCustodyAdmissionAuthentication
	}
	return data, nil
}
