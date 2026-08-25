//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package serviceauthority

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

type bindingProcessLock struct {
	file *os.File
}

func acquireBindingProcessLock(bindingPath string) (*bindingProcessLock, error) {
	lockPath := bindingPath + ".process.lock"
	if err := validatePrivateBindingLockDirectory(filepath.Dir(lockPath)); err != nil {
		return nil, err
	}
	if pathInfo, err := os.Lstat(lockPath); err == nil {
		if !pathInfo.Mode().IsRegular() || pathInfo.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("unsafe service authority process lock")
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspect service authority process lock: %w", err)
	}
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open service authority process lock: %w", err)
	}
	pathInfo, pathErr := os.Lstat(lockPath)
	openedInfo, openedErr := file.Stat()
	if pathErr != nil || openedErr != nil || !pathInfo.Mode().IsRegular() ||
		!openedInfo.Mode().IsRegular() || pathInfo.Mode().Perm()&0o077 != 0 ||
		openedInfo.Mode().Perm()&0o077 != 0 || !os.SameFile(pathInfo, openedInfo) {
		_ = file.Close()
		return nil, fmt.Errorf("unsafe service authority process lock")
	}
	if err := syscall.Flock(
		int(file.Fd()),
		syscall.LOCK_EX|syscall.LOCK_NB,
	); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("service authority binding file is already in use: %w", err)
	}
	return &bindingProcessLock{file: file}, nil
}

func validatePrivateBindingLockDirectory(directoryPath string) error {
	pathInfo, err := os.Lstat(directoryPath)
	if err != nil || !pathInfo.IsDir() || pathInfo.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("service authority binding directory is not owner-controlled")
	}
	directory, err := os.Open(directoryPath)
	if err != nil {
		return fmt.Errorf("open service authority binding directory: %w", err)
	}
	defer directory.Close()
	openedInfo, err := directory.Stat()
	if err != nil || !openedInfo.IsDir() || openedInfo.Mode().Perm()&0o022 != 0 ||
		!os.SameFile(pathInfo, openedInfo) {
		return fmt.Errorf("service authority binding directory is not owner-controlled")
	}
	return nil
}

func (lock *bindingProcessLock) release() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	file := lock.file
	lock.file = nil
	unlockErr := syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	closeErr := file.Close()
	if unlockErr != nil {
		return fmt.Errorf("unlock service authority binding file: %w", unlockErr)
	}
	return closeErr
}
