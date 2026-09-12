//go:build linux || darwin

package storagecapacity

import (
	"context"
	"math"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type FileSystemProvider struct{ root string }

func NewFileSystemProvider(root string) (*FileSystemProvider, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, ErrUnavailable
	}
	provider := &FileSystemProvider{root: root}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrUnavailable
	}
	// Do not make service startup/read/cleanup depend on a successful capacity
	// probe. Each write admission probes and fails closed independently.
	return provider, nil
}

func (p *FileSystemProvider) Snapshot(ctx context.Context) (Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	info, err := os.Lstat(p.root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return Snapshot{}, ErrUnavailable
	}
	var status unix.Statfs_t
	if err := unix.Statfs(p.root, &status); err != nil {
		return Snapshot{}, ErrUnavailable
	}
	blockSize := int64(status.Bsize)
	if blockSize <= 0 || status.Blocks == 0 || status.Bavail > status.Blocks ||
		uint64(status.Blocks) > uint64(math.MaxInt64/blockSize) {
		return Snapshot{}, ErrUnavailable
	}
	snapshot := Snapshot{TotalBytes: int64(status.Blocks) * blockSize, AvailableBytes: int64(status.Bavail) * blockSize}
	if _, err := snapshot.OperatingReserve(); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}
