//go:build unix

package storageauthority

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

const MaximumCapacityPeerRegistryBytes = 128 * 1024

type CapacityPeerRegistryFile struct {
	Identities []serviceauthority.CapacityPeerIdentity `json:"identities"`
	Version    int                                     `json:"version"`
}

// LoadCapacityPeerRegistry reads the owner-provisioned, public-key-only peer
// allowlist. It rejects symlinks, non-regular files, ambiguous JSON, and files
// writable by group/other. The registry has no network mutation route.
func LoadCapacityPeerRegistry(path string) (*CapacityPeerRegistry, error) {
	if path == "" {
		return nil, ErrInvalid
	}
	resolved, err := filepath.Abs(path)
	if err != nil {
		return nil, ErrInvalid
	}
	resolved = filepath.Clean(resolved)
	pathInfo, err := os.Lstat(resolved)
	if err != nil || !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 || pathInfo.Mode().Perm()&0o022 != 0 ||
		pathInfo.Size() <= 0 || pathInfo.Size() > MaximumCapacityPeerRegistryBytes {
		return nil, ErrInvalid
	}
	file, err := os.Open(resolved)
	if err != nil {
		return nil, ErrInvalid
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || openedInfo.Mode().Perm()&0o022 != 0 ||
		openedInfo.Size() <= 0 || openedInfo.Size() > MaximumCapacityPeerRegistryBytes ||
		!os.SameFile(pathInfo, openedInfo) {
		return nil, ErrInvalid
	}
	data, err := io.ReadAll(io.LimitReader(file, MaximumCapacityPeerRegistryBytes+1))
	if err != nil || len(data) == 0 || len(data) > MaximumCapacityPeerRegistryBytes {
		return nil, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var value CapacityPeerRegistryFile
	if err := decoder.Decode(&value); err != nil {
		return nil, ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) || value.Version != serviceauthority.SchemaVersion {
		return nil, ErrInvalid
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(data, append(canonical, '\n')) {
		return nil, ErrInvalid
	}
	return NewCapacityPeerRegistry(value.Identities)
}
