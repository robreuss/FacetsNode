//go:build !linux && !darwin

package storagecapacity

import "context"

type FileSystemProvider struct{}

func NewFileSystemProvider(string) (*FileSystemProvider, error) { return nil, ErrUnavailable }
func (*FileSystemProvider) Snapshot(context.Context) (Snapshot, error) {
	return Snapshot{}, ErrUnavailable
}
