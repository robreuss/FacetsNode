// Package jobcustody implements content-blind custody for protected Job
// Capsules. It must not receive plaintext Job inputs, prompts, results, Space
// identifiers, object identifiers, or caller-selected filesystem paths.
package jobcustody

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/robreuss/FacetsNode/internal/computequeue"
)

var (
	ErrInvalid     = errors.New("invalid job custody operation")
	ErrConflict    = errors.New("conflicting job custody operation")
	ErrMissing     = errors.New("job custody object not found")
	ErrUnavailable = errors.New("job custody storage unavailable")
)

// ContentStore has one exclusive process owner. Staging and object names are
// derived only from validated opaque capsule IDs.
type ContentStore struct {
	mu                                               sync.Mutex
	parentPath, rootPath, rootName                   string
	parent, root, staging, objects                   *os.Root
	parentDir, rootDir, stagingDir, objectsDir, lock *os.File
	closed                                           bool
}

func OpenContentStore(path string) (_ *ContentStore, result error) {
	abs, err := filepath.Abs(path)
	if err != nil || filepath.Base(abs) == "." || filepath.Dir(abs) == abs {
		return nil, ErrInvalid
	}
	parentPath := filepath.Dir(abs)
	parentInfo, err := os.Lstat(parentPath)
	if err != nil || !privateDirectory(parentInfo) {
		return nil, ErrInvalid
	}
	parentPath, err = filepath.EvalSymlinks(parentPath)
	if err != nil {
		return nil, ErrInvalid
	}
	store := &ContentStore{parentPath: parentPath, rootName: filepath.Base(abs)}
	store.rootPath = filepath.Join(parentPath, store.rootName)
	defer func() {
		if result != nil {
			_ = store.closeHandles()
		}
	}()
	store.parent, err = os.OpenRoot(parentPath)
	if err != nil {
		return nil, ErrUnavailable
	}
	store.parentDir, err = store.parent.Open(".")
	if err != nil || !sameInfo(store.parentDir, parentInfo) {
		return nil, ErrInvalid
	}
	if err := ensureDirectory(store.parent, store.parentDir, store.rootName); err != nil {
		return nil, err
	}
	store.root, store.rootDir, err = openDirectory(store.parent, store.rootName)
	if err != nil {
		return nil, err
	}
	if err := ensureDirectory(store.root, store.rootDir, "staging"); err != nil {
		return nil, err
	}
	if err := ensureDirectory(store.root, store.rootDir, "objects"); err != nil {
		return nil, err
	}
	store.staging, store.stagingDir, err = openDirectory(store.root, "staging")
	if err != nil {
		return nil, err
	}
	store.objects, store.objectsDir, err = openDirectory(store.root, "objects")
	if err != nil {
		return nil, err
	}
	store.lock, err = store.root.OpenFile(
		".process.lock",
		os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK,
		0o600,
	)
	if err != nil || syscall.Flock(int(store.lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return nil, ErrUnavailable
	}
	if !stableFile(store.root, ".process.lock", store.lock, 1, 0o600) ||
		store.lock.Sync() != nil || store.rootDir.Sync() != nil || store.validate() != nil {
		return nil, ErrInvalid
	}
	return store, nil
}

func (store *ContentStore) Prepare(capsuleID computequeue.JobCapsuleID) error {
	if store == nil {
		return ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	name, err := capsuleName(capsuleID)
	if err != nil || store == nil || store.validate() != nil {
		return ErrInvalid
	}
	if _, err := store.objects.Lstat(name); err == nil {
		return ErrConflict
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrUnavailable
	}
	file, err := store.staging.OpenFile(
		name,
		os.O_CREATE|os.O_EXCL|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK,
		0o600,
	)
	if errors.Is(err, os.ErrExist) {
		file, err = openRegular(store.staging, name, 1, 0o600)
		if err == nil {
			defer file.Close()
			info, statErr := file.Stat()
			if statErr == nil && info.Size() == 0 && file.Sync() == nil {
				return nil
			}
		}
		return ErrConflict
	}
	if err != nil {
		return ErrUnavailable
	}
	if !stableFile(store.staging, name, file, 1, 0o600) || file.Sync() != nil {
		_ = file.Close()
		return ErrInvalid
	}
	if err := file.Close(); err != nil || store.stagingDir.Sync() != nil {
		return ErrUnavailable
	}
	return nil
}

// ReconcileAndAppend truncates only an uncommitted tail beyond the ledger's
// exact committed offset, then appends and fsyncs one bounded protected chunk.
func (store *ContentStore) ReconcileAndAppend(
	capsuleID computequeue.JobCapsuleID,
	descriptor computequeue.JobCapsuleProtectedObjectDescriptor,
	committedOffset int64,
	chunk []byte,
) (int64, error) {
	if store == nil {
		return 0, ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	name, err := capsuleName(capsuleID)
	if err != nil || descriptor.Validate() != nil || committedOffset < 0 ||
		len(chunk) == 0 || int64(len(chunk)) > descriptor.ChunkByteCount ||
		committedOffset > descriptor.ByteCount || int64(len(chunk)) > descriptor.ByteCount-committedOffset ||
		store == nil || store.validate() != nil {
		return 0, ErrInvalid
	}
	file, err := openRegular(store.staging, name, 1, 0o600)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() < committedOffset || info.Size() > descriptor.ByteCount {
		return 0, ErrInvalid
	}
	if info.Size() > committedOffset {
		if file.Truncate(committedOffset) != nil || file.Sync() != nil {
			return 0, ErrUnavailable
		}
	}
	if store.validate() != nil || !stableFile(store.staging, name, file, 1, 0o600) {
		return 0, ErrInvalid
	}
	if _, err := file.Seek(committedOffset, io.SeekStart); err != nil {
		return 0, ErrUnavailable
	}
	written, err := file.Write(chunk)
	if err != nil || written != len(chunk) || file.Sync() != nil {
		return 0, ErrUnavailable
	}
	return committedOffset + int64(len(chunk)), nil
}

func (store *ContentStore) VerifyRange(
	capsuleID computequeue.JobCapsuleID,
	offset int64,
	length int64,
	expectedSHA256 computequeue.Digest,
) error {
	if store == nil {
		return ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	name, err := capsuleName(capsuleID)
	if err != nil || offset < 0 || length <= 0 || offset > math.MaxInt64-length ||
		expectedSHA256.Validate() != nil || store == nil || store.validate() != nil {
		return ErrInvalid
	}
	file, err := store.openStagingOrObject(name)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || offset+length > info.Size() {
		return ErrInvalid
	}
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return ErrUnavailable
	}
	hash := sha256.New()
	if copied, err := io.CopyN(hash, file, length); err != nil || copied != length ||
		fmt.Sprintf("%x", hash.Sum(nil)) != string(expectedSHA256) {
		return ErrInvalid
	}
	return nil
}

// Finalize verifies the exact complete protected object, publishes it through
// a non-overwriting hard link, and removes the writable staging alias.
func (store *ContentStore) Finalize(
	capsuleID computequeue.JobCapsuleID,
	descriptor computequeue.JobCapsuleProtectedObjectDescriptor,
) (string, error) {
	if store == nil {
		return "", ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	name, err := capsuleName(capsuleID)
	if err != nil || descriptor.Validate() != nil || store == nil || store.validate() != nil {
		return "", ErrInvalid
	}
	if _, err := store.objects.Lstat(name); err == nil {
		if err := store.finish(name, descriptor); err != nil {
			return "", err
		}
		return filepath.Join("objects", name), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", ErrUnavailable
	}
	file, err := openRegular(store.staging, name, 1, 0o600, 0o400)
	if err != nil {
		return "", err
	}
	if err := verifyComplete(file, descriptor); err != nil {
		_ = file.Close()
		return "", err
	}
	if file.Chmod(0o400) != nil || file.Sync() != nil ||
		!stableFile(store.staging, name, file, 1, 0o400) {
		_ = file.Close()
		return "", ErrUnavailable
	}
	if err := file.Close(); err != nil {
		return "", ErrUnavailable
	}
	if err := store.root.Link(filepath.Join("staging", name), filepath.Join("objects", name)); err != nil {
		return "", ErrUnavailable
	}
	if err := store.finish(name, descriptor); err != nil {
		return "", err
	}
	return filepath.Join("objects", name), nil
}

func (store *ContentStore) OpenObject(
	capsuleID computequeue.JobCapsuleID,
	descriptor computequeue.JobCapsuleProtectedObjectDescriptor,
) (*os.File, error) {
	if store == nil {
		return nil, ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	name, err := capsuleName(capsuleID)
	if err != nil || descriptor.Validate() != nil || store == nil || store.validate() != nil {
		return nil, ErrInvalid
	}
	file, err := openRegular(store.objects, name, 1, 0o400)
	if err != nil {
		return nil, err
	}
	if err := verifyComplete(file, descriptor); err != nil ||
		store.validate() != nil || !stableFile(store.objects, name, file, 1, 0o400) {
		_ = file.Close()
		if err != nil {
			return nil, err
		}
		return nil, ErrInvalid
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return nil, ErrUnavailable
	}
	return file, nil
}

func (store *ContentStore) finish(
	name string,
	descriptor computequeue.JobCapsuleProtectedObjectDescriptor,
) error {
	file, err := openRegular(store.objects, name, 2, 0o400)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := verifyComplete(file, descriptor); err != nil || file.Sync() != nil || store.objectsDir.Sync() != nil {
		if err != nil {
			return err
		}
		return ErrUnavailable
	}
	held, err := file.Stat()
	if err != nil {
		return ErrInvalid
	}
	if staged, stageErr := store.staging.Lstat(name); stageErr == nil {
		if !privateFile(staged, 2, 0o400) || !os.SameFile(staged, held) || linkCount(held) != 2 {
			return ErrConflict
		}
		if store.staging.Remove(name) != nil || store.stagingDir.Sync() != nil {
			return ErrUnavailable
		}
	} else if !errors.Is(stageErr, os.ErrNotExist) {
		return ErrUnavailable
	}
	if store.validate() != nil || !stableFile(store.objects, name, file, 1, 0o400) {
		return ErrInvalid
	}
	return nil
}

func (store *ContentStore) openStagingOrObject(name string) (*os.File, error) {
	if file, err := openRegular(store.staging, name, 1, 0o600, 0o400); err == nil {
		return file, nil
	} else if !errors.Is(err, ErrMissing) {
		return nil, err
	}
	return openRegular(store.objects, name, 1, 0o400)
}

func verifyComplete(
	file *os.File,
	descriptor computequeue.JobCapsuleProtectedObjectDescriptor,
) error {
	info, err := file.Stat()
	if err != nil || info.Size() != descriptor.ByteCount {
		return ErrInvalid
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return ErrUnavailable
	}
	hash := sha256.New()
	if copied, err := io.CopyN(hash, file, descriptor.ByteCount); err != nil || copied != descriptor.ByteCount ||
		fmt.Sprintf("%x", hash.Sum(nil)) != string(descriptor.SHA256) {
		return ErrInvalid
	}
	return nil
}

func capsuleName(value computequeue.JobCapsuleID) (string, error) {
	if err := value.Validate(); err != nil {
		return "", ErrInvalid
	}
	return string(value), nil
}

func (store *ContentStore) validate() error {
	if store == nil || store.closed || store.parent == nil || store.root == nil ||
		store.staging == nil || store.objects == nil || store.lock == nil {
		return ErrUnavailable
	}
	for _, pair := range []struct {
		root *os.Root
		name string
		file *os.File
	}{
		{store.parent, ".", store.parentDir},
		{store.parent, store.rootName, store.rootDir},
		{store.root, ".", store.rootDir},
		{store.root, "staging", store.stagingDir},
		{store.root, "objects", store.objectsDir},
	} {
		info, err := pair.root.Lstat(pair.name)
		if err != nil || !privateDirectory(info) || !sameInfo(pair.file, info) {
			return ErrInvalid
		}
	}
	for _, pair := range []struct {
		path string
		file *os.File
	}{{store.parentPath, store.parentDir}, {store.rootPath, store.rootDir}} {
		info, err := os.Lstat(pair.path)
		if err != nil || !privateDirectory(info) || !sameInfo(pair.file, info) {
			return ErrInvalid
		}
	}
	if !stableFile(store.root, ".process.lock", store.lock, 1, 0o600) {
		return ErrInvalid
	}
	return nil
}

func (store *ContentStore) Close() error {
	if store == nil {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return nil
	}
	store.closed = true
	if store.lock != nil {
		_ = syscall.Flock(int(store.lock.Fd()), syscall.LOCK_UN)
	}
	return store.closeHandles()
}

func (store *ContentStore) closeHandles() error {
	var failures []error
	for _, file := range []*os.File{store.lock, store.objectsDir, store.stagingDir, store.rootDir, store.parentDir} {
		if file != nil && file.Close() != nil {
			failures = append(failures, ErrUnavailable)
		}
	}
	for _, root := range []*os.Root{store.objects, store.staging, store.root, store.parent} {
		if root != nil && root.Close() != nil {
			failures = append(failures, ErrUnavailable)
		}
	}
	return errors.Join(failures...)
}

func ensureDirectory(root *os.Root, parent *os.File, name string) error {
	if err := root.Mkdir(name, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return ErrUnavailable
	}
	info, err := root.Lstat(name)
	if err != nil || !privateDirectory(info) {
		return ErrInvalid
	}
	if parent.Sync() != nil {
		return ErrUnavailable
	}
	return nil
}

func openDirectory(parent *os.Root, name string) (*os.Root, *os.File, error) {
	info, err := parent.Lstat(name)
	if err != nil || !privateDirectory(info) {
		return nil, nil, ErrInvalid
	}
	root, err := parent.OpenRoot(name)
	if err != nil {
		return nil, nil, ErrUnavailable
	}
	directory, err := root.Open(".")
	if err != nil || !sameInfo(directory, info) {
		if directory != nil {
			_ = directory.Close()
		}
		_ = root.Close()
		return nil, nil, ErrInvalid
	}
	return root, directory, nil
}

func openRegular(root *os.Root, name string, maximumLinks uint64, permissions ...os.FileMode) (*os.File, error) {
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrMissing
	}
	if err != nil || !privateFile(info, maximumLinks, permissions...) {
		return nil, ErrInvalid
	}
	flags := os.O_RDONLY
	if info.Mode().Perm() == 0o600 {
		flags = os.O_RDWR
	}
	file, err := root.OpenFile(name, flags|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	if !sameInfo(file, info) || !stableFile(root, name, file, maximumLinks, permissions...) {
		_ = file.Close()
		return nil, ErrInvalid
	}
	return file, nil
}

func privateDirectory(info os.FileInfo) bool {
	return info != nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 &&
		info.Mode().Perm() == 0o700 && owned(info)
}

func privateFile(info os.FileInfo, maximumLinks uint64, permissions ...os.FileMode) bool {
	if info == nil || !info.Mode().IsRegular() || !owned(info) ||
		linkCount(info) < 1 || linkCount(info) > maximumLinks {
		return false
	}
	for _, permission := range permissions {
		if info.Mode().Perm() == permission {
			return true
		}
	}
	return false
}

func owned(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && uint64(stat.Uid) == uint64(os.Geteuid())
}

func linkCount(info os.FileInfo) uint64 {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return uint64(stat.Nlink)
}

func sameInfo(file *os.File, info os.FileInfo) bool {
	if file == nil || info == nil {
		return false
	}
	held, err := file.Stat()
	return err == nil && os.SameFile(held, info)
}

func stableFile(
	root *os.Root,
	name string,
	file *os.File,
	maximumLinks uint64,
	permissions ...os.FileMode,
) bool {
	if root == nil || file == nil {
		return false
	}
	info, err := root.Lstat(name)
	held, heldErr := file.Stat()
	return err == nil && heldErr == nil &&
		privateFile(info, maximumLinks, permissions...) &&
		privateFile(held, maximumLinks, permissions...) && os.SameFile(info, held)
}
