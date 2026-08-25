//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package serviceauthority

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const bindingProcessLockChildPathEnvironment = "FACETS_TEST_BINDING_PROCESS_LOCK_CHILD_PATH"

func TestBindingProcessLockExcludesAnotherProcess(t *testing.T) {
	if bindingPath := os.Getenv(bindingProcessLockChildPathEnvironment); bindingPath != "" {
		lock, err := acquireBindingProcessLock(bindingPath)
		if err == nil {
			_ = lock.release()
			t.Fatal("child process acquired an already-held binding lock")
		}
		return
	}

	bindingPath := filepath.Join(t.TempDir(), "bindings.json")
	lock, err := acquireBindingProcessLock(bindingPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lock.release() })
	command := exec.Command(
		os.Args[0],
		"-test.run=^TestBindingProcessLockExcludesAnotherProcess$",
	)
	command.Env = append(
		os.Environ(),
		bindingProcessLockChildPathEnvironment+"="+bindingPath,
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("child process lock check failed: %v\n%s", err, output)
	}
}

func TestBindingProcessLockRejectsUnsafeFilesystemObjects(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		directory := t.TempDir()
		target := filepath.Join(directory, "target")
		if err := os.WriteFile(target, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		bindingPath := filepath.Join(directory, "bindings.json")
		if err := os.Symlink(target, bindingPath+".process.lock"); err != nil {
			t.Fatal(err)
		}
		if lock, err := acquireBindingProcessLock(bindingPath); err == nil {
			_ = lock.release()
			t.Fatal("symlink process lock accepted")
		}
	})

	t.Run("nonregular", func(t *testing.T) {
		directory := t.TempDir()
		bindingPath := filepath.Join(directory, "bindings.json")
		if err := os.Mkdir(bindingPath+".process.lock", 0o700); err != nil {
			t.Fatal(err)
		}
		if lock, err := acquireBindingProcessLock(bindingPath); err == nil {
			_ = lock.release()
			t.Fatal("nonregular process lock accepted")
		}
	})

	t.Run("permissive lock", func(t *testing.T) {
		directory := t.TempDir()
		bindingPath := filepath.Join(directory, "bindings.json")
		lockPath := bindingPath + ".process.lock"
		if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(lockPath, 0o644); err != nil {
			t.Fatal(err)
		}
		if lock, err := acquireBindingProcessLock(bindingPath); err == nil {
			_ = lock.release()
			t.Fatal("group/world-accessible process lock accepted")
		}
	})

	t.Run("writable directory", func(t *testing.T) {
		root := t.TempDir()
		directory := filepath.Join(root, "authority")
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, 0o777); err != nil {
			t.Fatal(err)
		}
		bindingPath := filepath.Join(directory, "bindings.json")
		if lock, err := acquireBindingProcessLock(bindingPath); err == nil {
			_ = lock.release()
			t.Fatal("process lock accepted from a group/world-writable directory")
		}
	})
}
