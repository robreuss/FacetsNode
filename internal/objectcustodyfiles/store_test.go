package objectcustodyfiles

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/objectcustodywire"
)

// The file layer validates opaque structure/digest, not AEAD. Crypto validity
// is exercised by the separate Swift/Go wire fixture and client cipher suites.
func fixture(size int) (objectcustodywire.Reference, []byte) {
	header := objectcustodywire.Header{ScopeID: uuid.MustParse("669a154c-395b-4754-9447-1c3749509ae1"), ContentEpoch: 7,
		IncarnationID: uuid.MustParse("61f7c054-9aef-450d-8b90-237c7c8941cd"), PlaintextBytes: uint64(size)}
	wire, _ := header.Encode()
	for index := 0; index < size+28; index++ {
		wire = append(wire, byte(index%251))
	}
	reference, err := objectcustodywire.Inspect(wire)
	if err != nil {
		panic(err)
	}
	return reference, wire
}

func temporaryStore(t *testing.T) (*Store, string) {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "custody")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, path
}

func assertContents(t *testing.T, store *Store, reference objectcustodywire.Reference, wire []byte) {
	t.Helper()
	actual, err := store.Read(reference)
	if err != nil || !bytes.Equal(actual, wire) {
		t.Fatalf("retained wire mismatch: %v", err)
	}
	if len(actual) > objectcustodywire.MaximumPlaintextBytes+objectcustodywire.WireOverhead {
		t.Fatal("unbounded read")
	}
}

func TestPublishReopenExactRetryWithoutNewInode(t *testing.T) {
	for _, size := range []int{0, 1, 3*blockBytes + 17, objectcustodywire.MaximumPlaintextBytes} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			store, path := temporaryStore(t)
			reference, wire := fixture(size)
			if err := store.Put(reference, wire); err != nil {
				t.Fatal(err)
			}
			assertContents(t, store, reference, wire)
			first, err := os.Stat(filepath.Join(path, "objects", reference.CiphertextID))
			if err != nil || first.Mode().Perm() != 0o400 || linkCount(first) != 1 {
				t.Fatal("unsafe final file")
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			store, err = Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			for range 3 {
				if err := store.Put(reference, wire); err != nil {
					t.Fatal(err)
				}
			}
			assertContents(t, store, reference, wire)
			after, _ := os.Stat(filepath.Join(path, "objects", reference.CiphertextID))
			if !os.SameFile(first, after) || linkCount(after) != 1 {
				t.Fatal("retry added/replaced payload")
			}
			staging, err := os.ReadDir(filepath.Join(path, "staging"))
			if err != nil || len(staging) != 0 {
				t.Fatal("temporary alias remains")
			}
			// The returned snapshot cannot mutate retained ciphertext.
			copy, _ := store.Read(reference)
			copy[len(copy)-1] ^= 1
			assertContents(t, store, reference, wire)
		})
	}
}

func TestConcurrentExactAndDifferentWriters(t *testing.T) {
	store, path := temporaryStore(t)
	var group sync.WaitGroup
	failures := make(chan error, 32)
	for index := range 32 {
		group.Add(1)
		go func() {
			defer group.Done()
			reference, wire := fixture((index%4)*blockBytes + 13)
			if err := store.Put(reference, wire); err != nil {
				failures <- err
				return
			}
			actual, err := store.Read(reference)
			if err != nil {
				failures <- err
			} else if !bytes.Equal(actual, wire) {
				failures <- ErrInvalid
			}
		}()
	}
	group.Wait()
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	objects, err := os.ReadDir(filepath.Join(path, "objects"))
	if err != nil || len(objects) != 4 {
		t.Fatalf("physical objects=%d err=%v", len(objects), err)
	}
}

func TestExactRetryAtEveryDurabilityBoundary(t *testing.T) {
	for point := afterStageCreate; point <= afterStagingSync; point++ {
		t.Run(strconv.Itoa(int(point)), func(t *testing.T) {
			store, path := temporaryStore(t)
			reference, wire := fixture(3*blockBytes + 17)
			injected := errors.New("injected custody boundary failure")
			store.fault = func(current boundary) error {
				if current == point {
					return injected
				}
				return nil
			}
			if err := store.Put(reference, wire); !errors.Is(err, injected) {
				t.Fatalf("expected injected failure: %v", err)
			}
			_ = store.Close()
			store, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			if err := store.Put(reference, wire); err != nil {
				t.Fatal(err)
			}
			assertContents(t, store, reference, wire)
		})
	}
}

func TestAbruptProcessRecoveryHelper(t *testing.T) {
	if os.Getenv("FACETS_OBJECT_FILES_CRASH_HELPER") != "1" {
		return
	}
	point, err := strconv.Atoi(os.Getenv("FACETS_OBJECT_FILES_CRASH_POINT"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(os.Getenv("FACETS_OBJECT_FILES_CRASH_ROOT"))
	if err != nil {
		t.Fatal(err)
	}
	store.fault = func(current boundary) error {
		if int(current) == point {
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
		}
		return nil
	}
	reference, wire := fixture(3*blockBytes + 17)
	_ = store.Put(reference, wire)
	t.Fatal("process did not terminate at requested boundary")
}

func TestSIGKILLReleasesOwnerAndReconcilesEveryBoundary(t *testing.T) {
	for point := afterStageCreate; point <= afterStagingSync; point++ {
		t.Run(strconv.Itoa(int(point)), func(t *testing.T) {
			parent := t.TempDir()
			if err := os.Chmod(parent, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(parent, "custody")
			command := exec.Command(os.Args[0], "-test.run=^TestAbruptProcessRecoveryHelper$")
			command.Env = append(os.Environ(), "FACETS_OBJECT_FILES_CRASH_HELPER=1", "FACETS_OBJECT_FILES_CRASH_ROOT="+path,
				"FACETS_OBJECT_FILES_CRASH_POINT="+strconv.Itoa(int(point)))
			err := command.Run()
			var failure *exec.ExitError
			if !errors.As(err, &failure) || failure.ProcessState.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
				t.Fatalf("expected SIGKILL: %v", err)
			}
			store, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			reference, wire := fixture(3*blockBytes + 17)
			if err := store.Put(reference, wire); err != nil {
				t.Fatal(err)
			}
			assertContents(t, store, reference, wire)
		})
	}
}

func TestRejectInvalidReferencesAndWireBeforeEffects(t *testing.T) {
	store, path := temporaryStore(t)
	reference, wire := fixture(128)
	for _, edit := range []func(*objectcustodywire.Reference){
		func(r *objectcustodywire.Reference) { r.Header.ScopeID = uuid.New() },
		func(r *objectcustodywire.Reference) { r.Header.ContentEpoch++ },
		func(r *objectcustodywire.Reference) { r.Header.IncarnationID = uuid.New() },
		func(r *objectcustodywire.Reference) { r.Header.PlaintextBytes++ },
		func(r *objectcustodywire.Reference) { r.CiphertextID = "../escape" },
		func(r *objectcustodywire.Reference) { r.Header.ContentEpoch = 0 },
	} {
		other := reference
		edit(&other)
		if store.Put(other, wire) == nil {
			t.Fatal("wrong reference accepted")
		}
		if _, err := store.Read(other); err == nil {
			t.Fatal("wrong reference readable")
		}
	}
	for _, invalid := range [][]byte{nil, wire[:len(wire)-1], append(bytes.Clone(wire), 0), bytes.Repeat([]byte{0}, objectcustodywire.MaximumPlaintextBytes+objectcustodywire.WireOverhead+1)} {
		if store.Put(reference, invalid) == nil {
			t.Fatal("invalid wire accepted")
		}
	}
	for _, child := range []string{"staging", "objects"} {
		entries, err := os.ReadDir(filepath.Join(path, child))
		if err != nil || len(entries) != 0 {
			t.Fatal("invalid input had filesystem effects")
		}
	}
	if _, err := store.Read(reference); !errors.Is(err, ErrMissing) {
		t.Fatalf("missing result: %v", err)
	}
}

func TestCorruptPartialAndFinalBytesFailWithoutRepair(t *testing.T) {
	for _, child := range []string{"staging", "objects"} {
		t.Run(child, func(t *testing.T) {
			store, path := temporaryStore(t)
			reference, wire := fixture(128)
			corrupt := bytes.Clone(wire)
			corrupt[20] ^= 1
			mode := os.FileMode(0o400)
			if child == "staging" {
				corrupt = corrupt[:70]
				mode = 0o600
			}
			name := filepath.Join(path, child, reference.CiphertextID)
			if err := os.WriteFile(name, corrupt, mode); err != nil {
				t.Fatal(err)
			}
			if store.Put(reference, wire) == nil {
				t.Fatal("corruption overwritten")
			}
			after, _ := os.ReadFile(name)
			if !bytes.Equal(corrupt, after) {
				t.Fatal("corrupt evidence changed")
			}
		})
	}
}

func TestTamperedPublishedObjectFailsReadAndRetry(t *testing.T) {
	store, path := temporaryStore(t)
	reference, wire := fixture(128)
	if err := store.Put(reference, wire); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(path, "objects", reference.CiphertextID)
	if err := os.Chmod(name, 0o600); err != nil {
		t.Fatal(err)
	}
	corrupt := bytes.Clone(wire)
	corrupt[len(corrupt)-1] ^= 1
	if err := os.WriteFile(name, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(name, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read(reference); err == nil {
		t.Fatal("tampered ciphertext served")
	}
	if store.Put(reference, wire) == nil {
		t.Fatal("tampered ciphertext silently repaired")
	}
}

func TestFileSubstitutionsCannotModifyOutside(t *testing.T) {
	for _, child := range []string{"staging", "objects"} {
		for _, kind := range []string{"symlink", "hardlink", "directory", "fifo", "public"} {
			t.Run(child+"/"+kind, func(t *testing.T) {
				store, path := temporaryStore(t)
				reference, wire := fixture(128)
				outside := filepath.Join(t.TempDir(), "outside")
				if err := os.WriteFile(outside, wire, 0o400); err != nil {
					t.Fatal(err)
				}
				name := filepath.Join(path, child, reference.CiphertextID)
				var err error
				switch kind {
				case "symlink":
					err = os.Symlink(outside, name)
				case "hardlink":
					err = os.Link(outside, name)
				case "directory":
					err = os.Mkdir(name, 0o700)
				case "fifo":
					err = syscall.Mkfifo(name, 0o600)
				case "public":
					err = os.WriteFile(name, wire, 0o644)
				}
				if err != nil {
					t.Fatal(err)
				}
				if store.Put(reference, wire) == nil {
					t.Fatal("unsafe file accepted")
				}
				if child == "objects" {
					if _, err := store.Read(reference); err == nil {
						t.Fatal("unsafe file read")
					}
				}
				after, err := os.ReadFile(outside)
				if err != nil || !bytes.Equal(after, wire) {
					t.Fatal("outside file modified")
				}
			})
		}
	}
}

func TestRejectReplacedDirectoriesAndLock(t *testing.T) {
	for _, child := range []string{"parent", "root", "staging", "objects", ".process.lock"} {
		t.Run(child, func(t *testing.T) {
			store, path := temporaryStore(t)
			reference, wire := fixture(128)
			if err := store.Put(reference, wire); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(path, child)
			if child == "parent" {
				target = filepath.Dir(path)
			} else if child == "root" {
				target = path
			}
			moved := target + "-old"
			if err := os.Rename(target, moved); err != nil {
				t.Fatal(err)
			}
			// Test only: restore the renamed t.TempDir parent after the store is
			// closed so the test harness can reclaim both exact fixture roots.
			if child == "parent" {
				defer func() { store.Close(); _ = os.Remove(target); _ = os.Rename(moved, target) }()
			}
			if child == ".process.lock" {
				if err := os.WriteFile(target, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Mkdir(target, 0o700); err != nil {
				t.Fatal(err)
			}
			if store.Put(reference, wire) == nil {
				t.Fatal("directory/lock replacement accepted")
			}
			if _, err := store.Read(reference); err == nil {
				t.Fatal("directory/lock replacement read")
			}
		})
	}
}

func TestProcessOwnershipPermissionsAndClose(t *testing.T) {
	store, path := temporaryStore(t)
	if duplicate, err := Open(path); err == nil {
		duplicate.Close()
		t.Fatal("duplicate owner")
	}
	reference, wire := fixture(128)
	if err := os.Chmod(filepath.Join(path, "objects"), 0o755); err != nil {
		t.Fatal(err)
	}
	if store.Put(reference, wire) == nil {
		t.Fatal("unsafe changed directory accepted")
	}
	if err := os.Chmod(filepath.Join(path, "objects"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if store.Put(reference, wire) == nil {
		t.Fatal("closed store write")
	}
	if _, err := store.Read(reference); err == nil {
		t.Fatal("closed store read")
	}
	other, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	other.Close()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	if other, err := Open(filepath.Join(parent, "unsafe")); err == nil {
		other.Close()
		t.Fatal("unsafe parent")
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(parent, "linked")
	if err := os.Symlink(filepath.Dir(path), linked); err != nil {
		t.Fatal(err)
	}
	if other, err := Open(filepath.Join(linked, "unsafe")); err == nil {
		other.Close()
		t.Fatal("symlink parent")
	}
}

func TestValidPrefixRecoveryAndInvalidStageLengths(t *testing.T) {
	for _, count := range []int{0, 1, blockBytes - 1, blockBytes, 2*blockBytes + 3} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			store, path := temporaryStore(t)
			reference, wire := fixture(2*blockBytes + 3)
			name := filepath.Join(path, "staging", reference.CiphertextID)
			if err := os.WriteFile(name, wire[:count], 0o600); err != nil {
				t.Fatal(err)
			}
			if err := store.Put(reference, wire); err != nil {
				t.Fatal(err)
			}
			assertContents(t, store, reference, wire)
		})
	}
	for _, kind := range []string{"extra", "short-readonly", "full-readonly"} {
		t.Run(kind, func(t *testing.T) {
			store, path := temporaryStore(t)
			reference, wire := fixture(128)
			staged := bytes.Clone(wire)
			mode := os.FileMode(0o400)
			if kind == "extra" {
				staged = append(staged, 0)
				mode = 0o600
			}
			if kind == "short-readonly" {
				staged = staged[:10]
			}
			if err := os.WriteFile(filepath.Join(path, "staging", reference.CiphertextID), staged, mode); err != nil {
				t.Fatal(err)
			}
			err := store.Put(reference, wire)
			if kind == "full-readonly" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("invalid staged length accepted")
			}
		})
	}
}

func TestReplacementAtPublicationBoundaryFailsClosed(t *testing.T) {
	for _, target := range []string{"staging", "objects", "stage-file", "existing-object"} {
		t.Run(target, func(t *testing.T) {
			store, path := temporaryStore(t)
			reference, wire := fixture(128)
			store.fault = func(point boundary) error {
				if point != afterStageSync {
					return nil
				}
				switch target {
				case "staging", "objects":
					name := filepath.Join(path, target)
					if err := os.Rename(name, name+"-held"); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(name, 0o700); err != nil {
						t.Fatal(err)
					}
				case "stage-file":
					name := filepath.Join(path, "staging", reference.CiphertextID)
					if err := os.Rename(name, name+"-held"); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(name, wire, 0o400); err != nil {
						t.Fatal(err)
					}
				case "existing-object":
					if err := os.WriteFile(filepath.Join(path, "objects", reference.CiphertextID), []byte("preserve"), 0o400); err != nil {
						t.Fatal(err)
					}
				}
				return nil
			}
			if store.Put(reference, wire) == nil {
				t.Fatal("publication substitution accepted")
			}
			if target == "existing-object" {
				retained, _ := os.ReadFile(filepath.Join(path, "objects", reference.CiphertextID))
				if !bytes.Equal(retained, []byte("preserve")) {
					t.Fatal("preexisting object overwritten")
				}
			} else if objects, _ := os.ReadDir(filepath.Join(path, "objects")); len(objects) != 0 {
				t.Fatal("object published after substitution")
			}
		})
	}
}

func TestExistingObjectRejectsUnrelatedStagingAndForeignAlias(t *testing.T) {
	for _, kind := range []string{"separate-stage", "foreign-alias", "truncated", "extra"} {
		t.Run(kind, func(t *testing.T) {
			store, path := temporaryStore(t)
			reference, wire := fixture(128)
			if err := store.Put(reference, wire); err != nil {
				t.Fatal(err)
			}
			final := filepath.Join(path, "objects", reference.CiphertextID)
			switch kind {
			case "separate-stage":
				if err := os.WriteFile(filepath.Join(path, "staging", reference.CiphertextID), wire, 0o400); err != nil {
					t.Fatal(err)
				}
			case "foreign-alias":
				if err := os.Link(final, filepath.Join(t.TempDir(), "foreign")); err != nil {
					t.Fatal(err)
				}
			default:
				if err := os.Chmod(final, 0o600); err != nil {
					t.Fatal(err)
				}
				content := append(bytes.Clone(wire), 0)
				if kind == "truncated" {
					content = content[:3]
				}
				if err := os.WriteFile(final, content, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(final, 0o400); err != nil {
					t.Fatal(err)
				}
			}
			if store.Put(reference, wire) == nil {
				t.Fatal("invalid final/alias accepted")
			}
			if _, err := store.Read(reference); err == nil {
				t.Fatal("invalid final/alias read")
			}
		})
	}
}
