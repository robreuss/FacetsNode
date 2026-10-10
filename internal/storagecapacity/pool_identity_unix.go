//go:build linux || darwin

package storagecapacity

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

const (
	PoolIdentityVersion  = 1
	PoolIdentityFileName = ".facets-storage-capacity-pool-v1"
	maximumIdentityBytes = 256
)

var (
	ErrPoolIdentityUnavailable = errors.New("storage pool identity is unavailable")
	ErrPoolIdentityConflict    = errors.New("storage pool identity conflicts with the configured pool")
)

// PhysicalPoolIdentity is the durable, content-blind identity of one physical
// admission pool. It is not a service, path, filesystem, or semantic-resource
// identity.
type PhysicalPoolIdentity struct {
	Version int       `json:"version"`
	PoolID  uuid.UUID `json:"poolID"`
}

func (value PhysicalPoolIdentity) Validate() error {
	if value.Version != PoolIdentityVersion || value.PoolID == uuid.Nil {
		return ErrPoolIdentityUnavailable
	}
	return nil
}

// CreatePhysicalPoolIdentity performs explicit one-time initialization. An
// exact retry is idempotent; a different configured pool never replaces the
// existing marker.
func CreatePhysicalPoolIdentity(root string, poolID uuid.UUID) (PhysicalPoolIdentity, error) {
	requested := PhysicalPoolIdentity{Version: PoolIdentityVersion, PoolID: poolID}
	if requested.Validate() != nil {
		return PhysicalPoolIdentity{}, ErrPoolIdentityUnavailable
	}
	directory, err := openIdentityRoot(root)
	if err != nil {
		return PhysicalPoolIdentity{}, err
	}
	defer unix.Close(directory)
	if unix.Flock(directory, unix.LOCK_EX) != nil {
		return PhysicalPoolIdentity{}, ErrPoolIdentityUnavailable
	}
	defer unix.Flock(directory, unix.LOCK_UN)
	encoded, err := json.Marshal(requested)
	if err != nil || len(encoded) == 0 || len(encoded) > maximumIdentityBytes {
		return PhysicalPoolIdentity{}, ErrPoolIdentityUnavailable
	}
	fd, err := unix.Openat(directory, PoolIdentityFileName,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if errors.Is(err, unix.EEXIST) {
		existing, loadErr := loadPhysicalPoolIdentityAt(directory)
		if loadErr != nil {
			return PhysicalPoolIdentity{}, loadErr
		}
		if existing != requested {
			return PhysicalPoolIdentity{}, ErrPoolIdentityConflict
		}
		return existing, nil
	}
	if err != nil {
		return PhysicalPoolIdentity{}, ErrPoolIdentityUnavailable
	}
	created := os.NewFile(uintptr(fd), PoolIdentityFileName)
	if created == nil {
		_ = unix.Close(fd)
		return PhysicalPoolIdentity{}, ErrPoolIdentityUnavailable
	}
	writeErr := writeIdentity(created, encoded)
	closeErr := created.Close()
	if writeErr != nil || closeErr != nil || unix.Fsync(directory) != nil {
		return PhysicalPoolIdentity{}, ErrPoolIdentityUnavailable
	}
	return requested, nil
}

func LoadPhysicalPoolIdentity(root string) (PhysicalPoolIdentity, error) {
	directory, err := openIdentityRoot(root)
	if err != nil {
		return PhysicalPoolIdentity{}, err
	}
	defer unix.Close(directory)
	if unix.Flock(directory, unix.LOCK_SH) != nil {
		return PhysicalPoolIdentity{}, ErrPoolIdentityUnavailable
	}
	defer unix.Flock(directory, unix.LOCK_UN)
	return loadPhysicalPoolIdentityAt(directory)
}

func openIdentityRoot(root string) (int, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == string(filepath.Separator) {
		return -1, ErrPoolIdentityUnavailable
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, ErrPoolIdentityUnavailable
	}
	var status unix.Stat_t
	if unix.Fstat(fd, &status) != nil || status.Mode&unix.S_IFMT != unix.S_IFDIR {
		unix.Close(fd)
		return -1, ErrPoolIdentityUnavailable
	}
	return fd, nil
}

func loadPhysicalPoolIdentityAt(directory int) (PhysicalPoolIdentity, error) {
	fd, err := unix.Openat(directory, PoolIdentityFileName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return PhysicalPoolIdentity{}, ErrPoolIdentityUnavailable
	}
	file := os.NewFile(uintptr(fd), PoolIdentityFileName)
	if file == nil {
		_ = unix.Close(fd)
		return PhysicalPoolIdentity{}, ErrPoolIdentityUnavailable
	}
	defer file.Close()
	var status unix.Stat_t
	if unix.Fstat(fd, &status) != nil || status.Mode&unix.S_IFMT != unix.S_IFREG ||
		status.Mode&0o777 != 0o600 || status.Nlink != 1 || status.Size <= 0 || status.Size > maximumIdentityBytes {
		return PhysicalPoolIdentity{}, ErrPoolIdentityUnavailable
	}
	encoded, err := io.ReadAll(io.LimitReader(file, maximumIdentityBytes+1))
	if err != nil || len(encoded) == 0 || len(encoded) > maximumIdentityBytes {
		return PhysicalPoolIdentity{}, ErrPoolIdentityUnavailable
	}
	var value PhysicalPoolIdentity
	if json.Unmarshal(encoded, &value) != nil || value.Validate() != nil {
		return PhysicalPoolIdentity{}, ErrPoolIdentityUnavailable
	}
	canonical, marshalErr := json.Marshal(value)
	if marshalErr != nil || !bytes.Equal(encoded, canonical) {
		return PhysicalPoolIdentity{}, ErrPoolIdentityUnavailable
	}
	return value, nil
}

func writeIdentity(file *os.File, encoded []byte) error {
	for len(encoded) > 0 {
		written, err := file.Write(encoded)
		if err != nil || written <= 0 {
			return ErrPoolIdentityUnavailable
		}
		encoded = encoded[written:]
	}
	if file.Sync() != nil {
		return ErrPoolIdentityUnavailable
	}
	return nil
}
