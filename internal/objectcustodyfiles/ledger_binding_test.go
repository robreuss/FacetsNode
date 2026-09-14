package objectcustodyfiles

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/google/uuid"
)

func TestLedgerBindingExactReopenAndConflict(t *testing.T) {
	store, path := temporaryStore(t)
	poolID, ledgerID := uuid.New(), uuid.New()
	if store.CheckLedger(poolID, ledgerID) == nil {
		t.Fatal("missing identity accepted")
	}
	if err := store.BindLedger(poolID, ledgerID); err != nil {
		t.Fatal(err)
	}
	if err := store.CheckLedger(poolID, ledgerID); err != nil {
		t.Fatal(err)
	}
	if err := store.BindLedger(poolID, ledgerID); err != nil {
		t.Fatal(err)
	}
	if store.BindLedger(poolID, uuid.New()) == nil || store.BindLedger(uuid.New(), ledgerID) == nil {
		t.Fatal("different ledger adopted root")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err = store.CheckLedger(poolID, ledgerID); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(path, ledgerMarker))
	if err != nil || len(data) != 36 || !bytes.Equal(data, ledgerBindingBytes(poolID, ledgerID)) {
		t.Fatal("durable exact binding")
	}
}

func TestLedgerBindingResumesOnlyExactPartialBootstrap(t *testing.T) {
	for _, size := range []int{0, 1, 16, 35, 36} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			store, path := temporaryStore(t)
			poolID, ledgerID := uuid.New(), uuid.New()
			data := ledgerBindingBytes(poolID, ledgerID)
			if err := os.WriteFile(filepath.Join(path, ledgerPending), data[:size], 0o600); err != nil {
				t.Fatal(err)
			}
			if err := store.BindLedger(poolID, ledgerID); err != nil {
				t.Fatal(err)
			}
			if err := store.CheckLedger(poolID, ledgerID); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(filepath.Join(path, ledgerPending)); !os.IsNotExist(err) {
				t.Fatal("pending marker alias remains")
			}
		})
	}
	store, path := temporaryStore(t)
	poolID, ledgerID := uuid.New(), uuid.New()
	if err := os.WriteFile(filepath.Join(path, ledgerPending), []byte("invalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if store.BindLedger(poolID, ledgerID) == nil {
		t.Fatal("corrupt partial marker replaced")
	}
}

func TestLedgerBindingRejectsPopulatedRootMissingMarkerAndForeignAliases(t *testing.T) {
	store, _ := temporaryStore(t)
	reference, wire := fixture(0)
	if err := store.Put(reference, wire); err != nil {
		t.Fatal(err)
	}
	if store.BindLedger(uuid.New(), uuid.New()) == nil {
		t.Fatal("populated unbound root adopted")
	}
	for _, kind := range []string{"symlink", "hardlink", "corrupt", "missing"} {
		t.Run(kind, func(t *testing.T) {
			store, path := temporaryStore(t)
			poolID, ledgerID := uuid.New(), uuid.New()
			if err := store.BindLedger(poolID, ledgerID); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(path, ledgerMarker)
			switch kind {
			case "hardlink":
				if err := os.Link(marker, filepath.Join(t.TempDir(), "foreign")); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Remove(marker); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.Chmod(marker, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(marker, []byte("invalid"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(marker, 0o400); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(marker, marker+"-held"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(marker+"-held", marker); err != nil {
					t.Fatal(err)
				}
			}
			if store.CheckLedger(poolID, ledgerID) == nil {
				t.Fatal("invalid marker accepted")
			}
		})
	}
}
