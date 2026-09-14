// Package objectcustodyfiles provides isolated opaque-byte filesystem custody.
// It is not wired to a service. Callers must independently authorize references
// and hold durable shared-pool capacity reservations before production use.
// No API here grants access, pins objects, collects or deletes retained objects.
package objectcustodyfiles

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/robreuss/FacetsNode/internal/objectcustodywire"
)

var (
	ErrInvalid     = errors.New("invalid immutable ciphertext custody")
	ErrUnavailable = errors.New("immutable ciphertext custody unavailable")
	ErrMissing     = errors.New("immutable ciphertext is not retained")
)

const blockBytes = 64 * 1024

type boundary uint8

const (
	afterStageCreate boundary = iota
	afterStageWrite
	afterStageSync
	afterObjectLink
	afterObjectSync
	afterStageRemove
	afterStagingSync
)

// Store has one exclusive process owner. Its returned byte slices are bounded,
// detached snapshots, never raw paths or writable descriptors into custody.
type Store struct {
	mu                                               sync.Mutex
	parentPath, rootPath, rootName                   string
	parent, root, staging, objects                   *os.Root
	parentDir, rootDir, stagingDir, objectsDir, lock *os.File
	closed                                           bool
	fault                                            func(boundary) error // fixed, content-free fault points; tests only
}

// Open requires a private existing parent. It creates only its own immediate
// private root/children, never changes permissions on preexisting directories.
func Open(path string) (_ *Store, result error) {
	abs, err := filepath.Abs(path)
	if err != nil || filepath.Base(abs) == "." || filepath.Dir(abs) == abs {
		return nil, ErrInvalid
	}
	parentPath := filepath.Dir(abs)
	parentInfo, err := os.Lstat(parentPath)
	if err != nil || !privateDirectory(parentInfo) {
		return nil, ErrInvalid
	}
	// Resolve benign ancestor aliases (including macOS /var) once, then retain
	// and compare the canonical ambient identities throughout this open store.
	parentPath, err = filepath.EvalSymlinks(parentPath)
	if err != nil {
		return nil, ErrInvalid
	}
	s := &Store{parentPath: parentPath, rootName: filepath.Base(abs)}
	s.rootPath = filepath.Join(parentPath, s.rootName)
	defer func() {
		if result != nil {
			s.closeHandles()
		}
	}()
	s.parent, err = os.OpenRoot(parentPath)
	if err != nil {
		return nil, ErrUnavailable
	}
	s.parentDir, err = s.parent.Open(".")
	if err != nil || !sameInfo(s.parentDir, parentInfo) {
		return nil, ErrInvalid
	}
	if err = ensureDirectory(s.parent, s.parentDir, s.rootName); err != nil {
		return nil, err
	}
	s.root, s.rootDir, err = openDirectory(s.parent, s.rootName)
	if err != nil {
		return nil, err
	}
	s.lock, err = s.root.OpenFile(".process.lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, ErrUnavailable
	}
	if !stableFile(s.root, ".process.lock", s.lock, 1, 0o600) {
		return nil, ErrInvalid
	}
	if syscall.Flock(int(s.lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return nil, ErrUnavailable
	}
	for _, name := range []string{"staging", "objects"} {
		if err = ensureDirectory(s.root, s.rootDir, name); err != nil {
			return nil, err
		}
	}
	s.staging, s.stagingDir, err = openDirectory(s.root, "staging")
	if err != nil {
		return nil, err
	}
	s.objects, s.objectsDir, err = openDirectory(s.root, "objects")
	if err != nil {
		return nil, err
	}
	if s.lock.Sync() != nil || s.rootDir.Sync() != nil || s.validate() != nil {
		return nil, ErrUnavailable
	}
	return s, nil
}

// Put verifies an exact bounded wire and durably publishes it without replacing
// an existing incarnation. Its success is byte custody, not a service receipt.
// The production integration must reserve capacity before calling this method.
func (s *Store) Put(expected objectcustodywire.Reference, wire []byte) error {
	if s == nil || objectcustodywire.Verify(wire, expected) != nil {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validate(); err != nil {
		return err
	}
	id := expected.CiphertextID
	if _, err := s.objects.Lstat(id); err == nil {
		return s.finish(expected)
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrUnavailable
	}
	file, err := s.openStage(id)
	if err != nil {
		return err
	}
	defer file.Close()
	if err = s.checkpoint(afterStageCreate); err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil || info.Size() < 0 || info.Size() > int64(len(wire)) {
		return ErrInvalid
	}
	// A partial prior write is resumable only when every retained byte belongs
	// to this exact retry. Corruption is never silently repaired or overwritten.
	buffer := make([]byte, blockBytes)
	for offset := 0; offset < int(info.Size()); {
		count := min(len(buffer), int(info.Size())-offset)
		if _, err = io.ReadFull(file, buffer[:count]); err != nil || !bytes.Equal(buffer[:count], wire[offset:offset+count]) {
			return ErrInvalid
		}
		offset += count
	}
	if info.Size() < int64(len(wire)) && info.Mode().Perm() != 0o600 {
		return ErrInvalid
	}
	for offset := int(info.Size()); offset < len(wire); {
		if s.validate() != nil || !stableFile(s.staging, id, file, 1, 0o600) {
			return ErrInvalid
		}
		end := min(offset+blockBytes, len(wire))
		written, writeErr := file.Write(wire[offset:end])
		if writeErr != nil || written != end-offset {
			return ErrUnavailable
		}
		offset = end
		if err = s.checkpoint(afterStageWrite); err != nil {
			return err
		}
	}
	if file.Chmod(0o400) != nil || file.Sync() != nil {
		return ErrUnavailable
	}
	if s.validate() != nil || !stableFile(s.staging, id, file, 1, 0o400) {
		return ErrInvalid
	}
	if err = verifyFile(file, expected); err != nil {
		return err
	}
	if err = s.checkpoint(afterStageSync); err != nil {
		return err
	}
	if s.validate() != nil || !stableFile(s.staging, id, file, 1, 0o400) {
		return ErrInvalid
	}
	// Link is non-overwriting. The alias stays inside this owner's descriptor-
	// anchored root; it never joins the existing Sync/Backup private directories.
	if err = s.root.Link(filepath.Join("staging", id), filepath.Join("objects", id)); err != nil {
		return ErrUnavailable
	}
	if err = s.checkpoint(afterObjectLink); err != nil {
		return err
	}
	return s.finish(expected)
}

// Read returns a fully commitment-verified bounded snapshot. This does not
// authenticate AEAD or the service authority that supplied expected.
func (s *Store) Read(expected objectcustodywire.Reference) ([]byte, error) {
	if s == nil || expected.Validate() != nil {
		return nil, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readLocked(expected)
}

func (s *Store) readLocked(expected objectcustodywire.Reference) ([]byte, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	file, err := openRegular(s.objects, expected.CiphertextID, 2, 0o400)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	count := int64(objectcustodywire.WireOverhead) + int64(expected.Header.PlaintextBytes)
	info, err := file.Stat()
	if err != nil || info.Size() != count {
		return nil, ErrInvalid
	}
	data, err := io.ReadAll(io.LimitReader(file, count+1))
	if err != nil || objectcustodywire.Verify(data, expected) != nil {
		return nil, ErrInvalid
	}
	if s.validate() != nil || !stableFile(s.objects, expected.CiphertextID, file, 2, 0o400) {
		return nil, ErrInvalid
	}
	if err = s.validateAlias(expected.CiphertextID, file); err != nil {
		return nil, err
	}
	return data, nil
}

func (s *Store) finish(expected objectcustodywire.Reference) error {
	id := expected.CiphertextID
	if _, err := s.readLocked(expected); err != nil {
		return err
	}
	file, err := openRegular(s.objects, id, 2, 0o400)
	if err != nil {
		return err
	}
	defer file.Close()
	if file.Sync() != nil || s.objectsDir.Sync() != nil {
		return ErrUnavailable
	}
	if err = s.checkpoint(afterObjectSync); err != nil {
		return err
	}
	if s.validate() != nil || s.validateAlias(id, file) != nil {
		return ErrInvalid
	}
	if stage, stageErr := s.staging.Lstat(id); stageErr == nil {
		held, heldErr := file.Stat()
		if heldErr != nil || !os.SameFile(stage, held) {
			return ErrInvalid
		}
		if s.staging.Remove(id) != nil {
			return ErrUnavailable
		}
	} else if !errors.Is(stageErr, os.ErrNotExist) {
		return ErrUnavailable
	}
	if err = s.checkpoint(afterStageRemove); err != nil {
		return err
	}
	if s.stagingDir.Sync() != nil {
		return ErrUnavailable
	}
	if err = s.checkpoint(afterStagingSync); err != nil {
		return err
	}
	if s.validate() != nil || !stableFile(s.objects, id, file, 1, 0o400) {
		return ErrInvalid
	}
	return nil
}

func (s *Store) openStage(id string) (*os.File, error) {
	file, err := s.staging.OpenFile(id, os.O_CREATE|os.O_EXCL|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
	if errors.Is(err, os.ErrExist) {
		return openRegular(s.staging, id, 1, 0o600, 0o400)
	}
	if err != nil {
		return nil, ErrUnavailable
	}
	if !stableFile(s.staging, id, file, 1, 0o600) || file.Sync() != nil || s.stagingDir.Sync() != nil {
		file.Close()
		return nil, ErrInvalid
	}
	return file, nil
}

func (s *Store) validateAlias(id string, object *os.File) error {
	held, err := object.Stat()
	if err != nil {
		return ErrInvalid
	}
	stage, err := s.staging.Lstat(id)
	if errors.Is(err, os.ErrNotExist) {
		if linkCount(held) != 1 {
			return ErrInvalid
		}
		return nil
	}
	if err != nil || !privateFile(stage, 2, 0o400) || !os.SameFile(stage, held) || linkCount(held) != 2 {
		return ErrInvalid
	}
	return nil
}

func (s *Store) checkpoint(point boundary) error {
	if s.fault != nil {
		return s.fault(point)
	}
	return nil
}

func verifyFile(file *os.File, expected objectcustodywire.Reference) error {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return ErrUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(objectcustodywire.WireOverhead+objectcustodywire.MaximumPlaintextBytes+1)))
	if err != nil || objectcustodywire.Verify(data, expected) != nil {
		return ErrInvalid
	}
	return nil
}

func openRegular(root *os.Root, name string, maxLinks uint64, permissions ...os.FileMode) (*os.File, error) {
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrMissing
	}
	if err != nil || !privateFile(info, maxLinks, permissions...) {
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
	if !sameInfo(file, info) || !stableFile(root, name, file, maxLinks, permissions...) {
		file.Close()
		return nil, ErrInvalid
	}
	return file, nil
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
			directory.Close()
		}
		root.Close()
		return nil, nil, ErrInvalid
	}
	return root, directory, nil
}

func (s *Store) validate() error {
	if s.closed || s.parent == nil || s.root == nil || s.staging == nil || s.objects == nil || s.lock == nil {
		return ErrUnavailable
	}
	for _, pair := range []struct {
		root *os.Root
		name string
		file *os.File
	}{
		{s.parent, ".", s.parentDir}, {s.parent, s.rootName, s.rootDir},
		{s.root, ".", s.rootDir}, {s.root, "staging", s.stagingDir}, {s.root, "objects", s.objectsDir},
	} {
		info, err := pair.root.Lstat(pair.name)
		if err != nil || !privateDirectory(info) || !sameInfo(pair.file, info) {
			return ErrInvalid
		}
	}
	for _, pair := range []struct {
		path string
		file *os.File
	}{{s.parentPath, s.parentDir}, {s.rootPath, s.rootDir}} {
		info, err := os.Lstat(pair.path)
		if err != nil || !privateDirectory(info) || !sameInfo(pair.file, info) {
			return ErrInvalid
		}
	}
	if !stableFile(s.root, ".process.lock", s.lock, 1, 0o600) {
		return ErrInvalid
	}
	return nil
}

func privateDirectory(info os.FileInfo) bool {
	return info != nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm() == 0o700 && owned(info)
}

func privateFile(info os.FileInfo, maximumLinks uint64, permissions ...os.FileMode) bool {
	if info == nil || !info.Mode().IsRegular() || !owned(info) || linkCount(info) < 1 || linkCount(info) > maximumLinks {
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

func stableFile(root *os.Root, name string, file *os.File, maximumLinks uint64, permissions ...os.FileMode) bool {
	if root == nil || file == nil {
		return false
	}
	info, err := root.Lstat(name)
	held, heldErr := file.Stat()
	return err == nil && heldErr == nil && privateFile(info, maximumLinks, permissions...) && privateFile(held, maximumLinks, permissions...) && os.SameFile(info, held)
}

func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.closeHandles()
}

func (s *Store) closeHandles() error {
	var failures []error
	for _, file := range []*os.File{s.lock, s.objectsDir, s.stagingDir, s.rootDir, s.parentDir} {
		if file != nil {
			if err := file.Close(); err != nil {
				failures = append(failures, ErrUnavailable)
			}
		}
	}
	for _, root := range []*os.Root{s.objects, s.staging, s.root, s.parent} {
		if root != nil {
			if err := root.Close(); err != nil {
				failures = append(failures, ErrUnavailable)
			}
		}
	}
	return errors.Join(failures...)
}
