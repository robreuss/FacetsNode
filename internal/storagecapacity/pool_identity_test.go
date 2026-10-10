//go:build linux || darwin

package storagecapacity

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/uuid"
)

func TestPhysicalPoolIdentityCreationLoadAndCollision(t *testing.T) {
	root := t.TempDir()
	poolID := uuid.New()
	created, err := CreatePhysicalPoolIdentity(root, poolID)
	if err != nil || created.PoolID != poolID || created.Version != PoolIdentityVersion {
		t.Fatalf("created=%+v err=%v", created, err)
	}
	info, err := os.Lstat(filepath.Join(root, PoolIdentityFileName))
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("marker=%+v err=%v", info, err)
	}
	loaded, err := LoadPhysicalPoolIdentity(root)
	if err != nil || loaded != created {
		t.Fatalf("loaded=%+v err=%v", loaded, err)
	}
	retry, err := CreatePhysicalPoolIdentity(root, poolID)
	if err != nil || retry != created {
		t.Fatalf("retry=%+v err=%v", retry, err)
	}
	if _, err = CreatePhysicalPoolIdentity(root, uuid.New()); !errors.Is(err, ErrPoolIdentityConflict) {
		t.Fatalf("replacement identity accepted: %v", err)
	}
}

func TestPhysicalPoolIdentityRejectsMissingMalformedAndSymlinkedState(t *testing.T) {
	root := t.TempDir()
	if _, err := LoadPhysicalPoolIdentity(root); !errors.Is(err, ErrPoolIdentityUnavailable) {
		t.Fatalf("missing marker: %v", err)
	}
	if _, err := CreatePhysicalPoolIdentity("/", uuid.New()); !errors.Is(err, ErrPoolIdentityUnavailable) {
		t.Fatalf("filesystem root accepted: %v", err)
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	rootLink := filepath.Join(t.TempDir(), "root-link")
	if err := os.Symlink(target, rootLink); err != nil {
		t.Fatal(err)
	}
	if _, err := CreatePhysicalPoolIdentity(rootLink, uuid.New()); !errors.Is(err, ErrPoolIdentityUnavailable) {
		t.Fatalf("symlinked root accepted: %v", err)
	}

	markerTarget := filepath.Join(t.TempDir(), "marker")
	if err := os.WriteFile(markerTarget, []byte(`{"version":1,"poolID":"`+uuid.NewString()+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(markerTarget, filepath.Join(root, PoolIdentityFileName)); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPhysicalPoolIdentity(root); !errors.Is(err, ErrPoolIdentityUnavailable) {
		t.Fatalf("symlinked marker accepted: %v", err)
	}

	if err := os.Remove(filepath.Join(root, PoolIdentityFileName)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, PoolIdentityFileName), []byte(`{"version":1,"poolID":"`+uuid.NewString()+`","extra":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPhysicalPoolIdentity(root); !errors.Is(err, ErrPoolIdentityUnavailable) {
		t.Fatalf("non-canonical marker accepted: %v", err)
	}
}

func TestConcurrentPhysicalPoolIdentityCreationCannotSubstitutePool(t *testing.T) {
	root := t.TempDir()
	identities := []uuid.UUID{uuid.New(), uuid.New()}
	errorsChannel := make(chan error, 2)
	var group sync.WaitGroup
	for _, poolID := range identities {
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := CreatePhysicalPoolIdentity(root, poolID)
			errorsChannel <- err
		}()
	}
	group.Wait()
	close(errorsChannel)
	var accepted, conflicted int
	for err := range errorsChannel {
		if err == nil {
			accepted++
		} else if errors.Is(err, ErrPoolIdentityConflict) {
			conflicted++
		} else {
			t.Fatalf("unexpected identity error: %v", err)
		}
	}
	if accepted != 1 || conflicted != 1 {
		t.Fatalf("accepted=%d conflicted=%d", accepted, conflicted)
	}
	loaded, err := LoadPhysicalPoolIdentity(root)
	if err != nil || (loaded.PoolID != identities[0] && loaded.PoolID != identities[1]) {
		t.Fatalf("loaded=%+v err=%v", loaded, err)
	}
}
