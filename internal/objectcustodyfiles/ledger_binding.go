package objectcustodyfiles

import (
	"bytes"
	"errors"
	"io"
	"os"
	"syscall"

	"github.com/google/uuid"
)

const ledgerMarker = ".ledger-binding"
const ledgerPending = ".ledger-binding.pending"

// BindLedger is explicit first-time provisioning, not ordinary open. A root
// containing any object/staging bytes cannot acquire a missing identity. The
// caller has already durably recorded these exact IDs in a bootstrap database.
func (s *Store) BindLedger(poolID, ledgerID uuid.UUID) error {
	if s == nil || poolID == uuid.Nil || ledgerID == uuid.Nil {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validate(); err != nil {
		return err
	}
	expected := ledgerBindingBytes(poolID, ledgerID)
	if _, err := s.root.Lstat(ledgerMarker); err == nil {
		return s.verifyLedgerBinding(expected, true)
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrUnavailable
	}
	for _, directory := range []*os.Root{s.objects, s.staging} {
		file, err := directory.Open(".")
		if err != nil {
			return ErrUnavailable
		}
		entries, readErr := file.Readdirnames(1)
		_ = file.Close()
		if len(entries) != 0 || (readErr != nil && !errors.Is(readErr, io.EOF)) {
			return ErrInvalid
		}
	}
	file, err := s.root.OpenFile(ledgerPending, os.O_CREATE|os.O_EXCL|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
	if errors.Is(err, os.ErrExist) {
		file, err = openRegular(s.root, ledgerPending, 1, 0o600, 0o400)
	}
	if err != nil {
		return ErrInvalid
	}
	defer file.Close()
	if !stableFile(s.root, ledgerPending, file, 1, 0o600, 0o400) {
		return ErrInvalid
	}
	info, err := file.Stat()
	if err != nil || info.Size() < 0 || info.Size() > int64(len(expected)) {
		return ErrInvalid
	}
	prefix, err := io.ReadAll(io.LimitReader(file, int64(len(expected)+1)))
	if err != nil || len(prefix) > len(expected) || !bytes.Equal(prefix, expected[:len(prefix)]) {
		return ErrInvalid
	}
	if len(prefix) < len(expected) {
		if info.Mode().Perm() != 0o600 {
			return ErrInvalid
		}
		written, writeErr := file.Write(expected[len(prefix):])
		if writeErr != nil || written != len(expected)-len(prefix) {
			return ErrUnavailable
		}
	}
	if file.Chmod(0o400) != nil || file.Sync() != nil {
		return ErrUnavailable
	}
	if s.validate() != nil || !stableFile(s.root, ledgerPending, file, 1, 0o400) {
		return ErrInvalid
	}
	if s.root.Link(ledgerPending, ledgerMarker) != nil {
		return ErrUnavailable
	}
	return s.verifyLedgerBinding(expected, true)
}

// CheckLedger is read-only and fails closed if the marker is missing, corrupt,
// replaced, or belongs to another ledger. It does not silently rebind a root.
func (s *Store) CheckLedger(poolID, ledgerID uuid.UUID) error {
	if s == nil || poolID == uuid.Nil || ledgerID == uuid.Nil {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validate(); err != nil {
		return err
	}
	return s.verifyLedgerBinding(ledgerBindingBytes(poolID, ledgerID), false)
}

func ledgerBindingBytes(poolID, ledgerID uuid.UUID) []byte {
	result := []byte{0x46, 0x4c, 0x42, 0x01}
	result = append(result, poolID[:]...)
	return append(result, ledgerID[:]...)
}

func (s *Store) verifyLedgerBinding(expected []byte, reconcile bool) error {
	file, err := openRegular(s.root, ledgerMarker, 2, 0o400)
	if err != nil {
		return err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, int64(len(expected)+1)))
	if err != nil || !bytes.Equal(data, expected) {
		return ErrInvalid
	}
	marker, err := file.Stat()
	if err != nil {
		return ErrInvalid
	}
	pending, pendingErr := s.root.Lstat(ledgerPending)
	if pendingErr == nil {
		if !privateFile(pending, 2, 0o400) || !os.SameFile(marker, pending) || linkCount(marker) != 2 {
			return ErrInvalid
		}
	} else if !errors.Is(pendingErr, os.ErrNotExist) || linkCount(marker) != 1 {
		return ErrInvalid
	}
	if reconcile {
		if file.Sync() != nil || s.rootDir.Sync() != nil {
			return ErrUnavailable
		}
		if pendingErr == nil && s.root.Remove(ledgerPending) != nil {
			return ErrUnavailable
		}
		if s.rootDir.Sync() != nil {
			return ErrUnavailable
		}
	}
	if s.validate() != nil || !stableFile(s.root, ledgerMarker, file, 2, 0o400) {
		return ErrInvalid
	}
	return nil
}
