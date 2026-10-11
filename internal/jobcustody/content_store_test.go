package jobcustody

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/robreuss/FacetsNode/internal/computequeue"
)

func TestContentStoreReconcilesAppendAndPublishesExactProtectedObject(t *testing.T) {
	store, root := temporaryContentStore(t)
	capsuleID := computequeue.JobCapsuleID("11111111-1111-4111-8111-111111111111")
	contents := []byte("opaque-protected-job-capsule")
	descriptor := protectedDescriptor(t, contents, 7)
	if err := store.Prepare(capsuleID); err != nil {
		t.Fatal(err)
	}

	next, err := store.ReconcileAndAppend(capsuleID, descriptor, 0, contents[:7])
	if err != nil || next != 7 {
		t.Fatalf("first append next=%d err=%v", next, err)
	}
	// Simulate a lost ledger commit after the prior fsync. The exact retry owns
	// offset zero and truncates the uncommitted tail before re-appending it.
	next, err = store.ReconcileAndAppend(capsuleID, descriptor, 0, contents[:7])
	if err != nil || next != 7 {
		t.Fatalf("reconciled append next=%d err=%v", next, err)
	}
	for offset := next; offset < int64(len(contents)); {
		end := min(offset+descriptor.ChunkByteCount, int64(len(contents)))
		offset, err = store.ReconcileAndAppend(capsuleID, descriptor, offset, contents[offset:end])
		if err != nil {
			t.Fatal(err)
		}
	}

	path, err := store.Finalize(capsuleID, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	first, err := os.Stat(filepath.Join(root, path))
	if err != nil || first.Mode().Perm() != 0o400 || linkCount(first) != 1 {
		t.Fatalf("unsafe immutable object: %v", err)
	}
	if retry, err := store.Finalize(capsuleID, descriptor); err != nil || retry != path {
		t.Fatalf("finalize retry path=%q err=%v", retry, err)
	}
	after, err := os.Stat(filepath.Join(root, path))
	if err != nil || !os.SameFile(first, after) {
		t.Fatal("exact retry replaced the retained object")
	}
	if _, err := os.Lstat(filepath.Join(root, "staging", string(capsuleID))); !os.IsNotExist(err) {
		t.Fatalf("writable staging alias remains: %v", err)
	}
	file, err := store.OpenObject(capsuleID, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	actual, readErr := io.ReadAll(file)
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(actual, contents) {
		t.Fatalf("retained bytes=%q read=%v close=%v", actual, readErr, closeErr)
	}
}

func TestContentStoreVerifiesRangesAndRejectsTampering(t *testing.T) {
	store, root := temporaryContentStore(t)
	capsuleID := computequeue.JobCapsuleID("22222222-2222-4222-8222-222222222222")
	contents := []byte("0123456789abcdefghijklmnopqrstuvwxyz")
	descriptor := protectedDescriptor(t, contents, int64(len(contents)))
	if err := store.Prepare(capsuleID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReconcileAndAppend(capsuleID, descriptor, 0, contents); err != nil {
		t.Fatal(err)
	}
	rangeDigest := sha256.Sum256(contents[7:19])
	if err := store.VerifyRange(
		capsuleID,
		7,
		12,
		computequeue.Digest(fmt.Sprintf("%x", rangeDigest[:])),
	); err != nil {
		t.Fatal(err)
	}
	wrongDigest := computequeue.SHA256Digest("wrong-range", "value")
	if err := store.VerifyRange(capsuleID, 7, 12, wrongDigest); err == nil {
		t.Fatal("accepted a mismatched protected-byte range")
	}
	path, err := store.Finalize(capsuleID, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	absolute := filepath.Join(root, path)
	if err := os.Chmod(absolute, 0o600); err != nil {
		t.Fatal(err)
	}
	corrupt := bytes.Clone(contents)
	corrupt[0] ^= 0xff
	if err := os.WriteFile(absolute, corrupt, 0o600); err != nil || os.Chmod(absolute, 0o400) != nil {
		t.Fatal(err)
	}
	if _, err := store.OpenObject(capsuleID, descriptor); err == nil {
		t.Fatal("accepted a tampered immutable object")
	}
}

func TestContentStoreDeletesOnlyExactFinalizedObjectAndConvergesAfterUnlink(t *testing.T) {
	store, _ := temporaryContentStore(t)
	capsuleID := computequeue.JobCapsuleID("29292929-2929-4929-8929-292929292929")
	contents := []byte("opaque-result-ready-for-custody-release")
	descriptor := protectedDescriptor(t, contents, 11)
	if err := store.Prepare(capsuleID); err != nil {
		t.Fatal(err)
	}
	for offset := int64(0); offset < int64(len(contents)); {
		end := min(offset+descriptor.ChunkByteCount, int64(len(contents)))
		next, err := store.ReconcileAndAppend(capsuleID, descriptor, offset, contents[offset:end])
		if err != nil {
			t.Fatal(err)
		}
		offset = next
	}
	if _, err := store.Finalize(capsuleID, descriptor); err != nil {
		t.Fatal(err)
	}
	wrongDescriptor := descriptor
	wrongDescriptor.SHA256 = computequeue.SHA256Digest("content-store-delete-test", "wrong")
	if err := store.DeleteObject(capsuleID, wrongDescriptor); err == nil {
		t.Fatal("deleted a finalized object under a substituted descriptor")
	}
	if file, err := store.OpenObject(capsuleID, descriptor); err != nil {
		t.Fatalf("descriptor rejection removed the retained object: %v", err)
	} else if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteObject(capsuleID, descriptor); err != nil {
		t.Fatal(err)
	}
	if _, err := store.OpenObject(capsuleID, descriptor); !errors.Is(err, ErrMissing) {
		t.Fatalf("released object remained readable: %v", err)
	}
	if err := store.DeleteObject(capsuleID, descriptor); err != nil {
		t.Fatalf("release replay did not converge after unlink: %v", err)
	}
}

func TestContentStoreDeletesPartialAndInterruptedStagingExactly(t *testing.T) {
	store, root := temporaryContentStore(t)
	partialID := computequeue.JobCapsuleID("2a2a2a2a-2a2a-4a2a-8a2a-2a2a2a2a2a2a")
	contents := []byte("opaque-partial-staging-object")
	descriptor := protectedDescriptor(t, contents, 7)
	if err := store.Prepare(partialID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReconcileAndAppend(partialID, descriptor, 0, contents[:7]); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteStaging(partialID, descriptor, 6); err == nil {
		t.Fatal("deleted partial staging under a substituted committed offset")
	}
	if err := store.DeleteStaging(partialID, descriptor, 7); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteStaging(partialID, descriptor, 7); err != nil {
		t.Fatalf("partial staging deletion did not converge: %v", err)
	}
	if err := store.Prepare(partialID); err != nil {
		t.Fatalf("partial staging namespace remained occupied: %v", err)
	}

	interruptedID := computequeue.JobCapsuleID("2b2b2b2b-2b2b-4b2b-8b2b-2b2b2b2b2b2b")
	if err := store.Prepare(interruptedID); err != nil {
		t.Fatal(err)
	}
	for offset := int64(0); offset < int64(len(contents)); {
		end := min(offset+descriptor.ChunkByteCount, int64(len(contents)))
		next, err := store.ReconcileAndAppend(interruptedID, descriptor, offset, contents[offset:end])
		if err != nil {
			t.Fatal(err)
		}
		offset = next
	}
	stage := filepath.Join(root, "staging", string(interruptedID))
	object := filepath.Join(root, "objects", string(interruptedID))
	if err := os.Chmod(stage, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(stage, object); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteStaging(interruptedID, descriptor, int64(len(contents))); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{stage, object} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("interrupted publication alias remains at %s: %v", path, err)
		}
	}
	if err := store.DeleteStaging(interruptedID, descriptor, int64(len(contents))); err != nil {
		t.Fatalf("interrupted staging deletion did not converge: %v", err)
	}
}

func TestContentStoreRecoversPublicationAliasAndRejectsForeignAlias(t *testing.T) {
	store, root := temporaryContentStore(t)
	capsuleID := computequeue.JobCapsuleID("33333333-3333-4333-8333-333333333333")
	contents := []byte("publication-recovery")
	descriptor := protectedDescriptor(t, contents, int64(len(contents)))
	if err := store.Prepare(capsuleID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReconcileAndAppend(capsuleID, descriptor, 0, contents); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(root, "staging", string(capsuleID))
	object := filepath.Join(root, "objects", string(capsuleID))
	if err := os.Chmod(stage, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(stage, object); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Finalize(capsuleID, descriptor); err != nil {
		t.Fatalf("exact interrupted publication did not converge: %v", err)
	}
	if _, err := os.Lstat(stage); !os.IsNotExist(err) {
		t.Fatal("reconciled staging alias remains")
	}

	chmodOnlyID := computequeue.JobCapsuleID("34343434-3434-4434-8434-343434343434")
	chmodOnly := []byte("publication-before-link-recovery")
	chmodOnlyDescriptor := protectedDescriptor(t, chmodOnly, int64(len(chmodOnly)))
	if err := store.Prepare(chmodOnlyID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReconcileAndAppend(chmodOnlyID, chmodOnlyDescriptor, 0, chmodOnly); err != nil {
		t.Fatal(err)
	}
	chmodOnlyStage := filepath.Join(root, "staging", string(chmodOnlyID))
	if err := os.Chmod(chmodOnlyStage, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Finalize(chmodOnlyID, chmodOnlyDescriptor); err != nil {
		t.Fatalf("publication after a durable chmod did not converge: %v", err)
	}

	otherID := computequeue.JobCapsuleID("44444444-4444-4444-8444-444444444444")
	other := []byte("foreign-object")
	otherDescriptor := protectedDescriptor(t, other, int64(len(other)))
	if err := store.Prepare(otherID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReconcileAndAppend(otherID, otherDescriptor, 0, other); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(t.TempDir(), "foreign")
	if err := os.WriteFile(foreign, other, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(foreign, filepath.Join(root, "objects", string(otherID))); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Finalize(otherID, otherDescriptor); err == nil {
		t.Fatal("accepted a foreign immutable alias")
	}
}

func TestContentStoreRejectsUnsafeRootsSymlinksAndReplacement(t *testing.T) {
	unsafeParent := t.TempDir()
	if err := os.Chmod(unsafeParent, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenContentStore(filepath.Join(unsafeParent, "custody")); err == nil {
		t.Fatal("accepted a non-private parent")
	}

	store, root := temporaryContentStore(t)
	if _, err := OpenContentStore(root); err == nil {
		t.Fatal("second process owner acquired the same custody root")
	}
	capsuleID := computequeue.JobCapsuleID("55555555-5555-4555-8555-555555555555")
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("unchanged"), 0o600); err != nil ||
		os.Symlink(outside, filepath.Join(root, "staging", string(capsuleID))) != nil {
		t.Fatal(err)
	}
	if _, err := store.ReconcileAndAppend(capsuleID, protectedDescriptor(t, []byte("x"), 1), 0, []byte("x")); err == nil {
		t.Fatal("accepted a symlink staging object")
	}
	if value, _ := os.ReadFile(outside); !bytes.Equal(value, []byte("unchanged")) {
		t.Fatal("modified a symlink target")
	}

	moved := root + "-moved"
	if err := os.Rename(root, moved); err != nil || os.Mkdir(root, 0o700) != nil {
		t.Fatal(err)
	}
	if err := store.Prepare(computequeue.JobCapsuleID("66666666-6666-4666-8666-666666666666")); err == nil {
		t.Fatal("ambient custody root replacement was not detected")
	}
}

func TestContentStoreReadinessTracksExclusiveCustodyLifetime(t *testing.T) {
	store, _ := temporaryContentStore(t)
	if err := store.Readiness(); err != nil {
		t.Fatalf("open store not ready: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Readiness(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("closed store readiness=%v", err)
	}
}

func TestContentStoreSerializesConcurrentCapsuleWrites(t *testing.T) {
	store, _ := temporaryContentStore(t)
	var group sync.WaitGroup
	failures := make(chan error, 16)
	for index := range 16 {
		id := computequeue.JobCapsuleID(fmt.Sprintf("%08d-7777-4777-8777-777777777777", index+1))
		contents := []byte(fmt.Sprintf("opaque-%d", index))
		descriptor := protectedDescriptor(t, contents, int64(len(contents)))
		group.Add(1)
		go func(
			id computequeue.JobCapsuleID,
			contents []byte,
			descriptor computequeue.JobCapsuleProtectedObjectDescriptor,
		) {
			defer group.Done()
			if err := store.Prepare(id); err != nil {
				failures <- err
				return
			}
			if _, err := store.ReconcileAndAppend(id, descriptor, 0, contents); err != nil {
				failures <- err
				return
			}
			if _, err := store.Finalize(id, descriptor); err != nil {
				failures <- err
			}
		}(id, contents, descriptor)
	}
	group.Wait()
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
}

func temporaryContentStore(t *testing.T) (*ContentStore, string) {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(parent, "job-custody")
	store, err := OpenContentStore(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, root
}

func protectedDescriptor(
	t *testing.T,
	contents []byte,
	chunkBytes int64,
) computequeue.JobCapsuleProtectedObjectDescriptor {
	t.Helper()
	digest := sha256.Sum256(contents)
	descriptor, err := computequeue.NewJobCapsuleProtectedObjectDescriptor(
		int64(len(contents)),
		computequeue.Digest(fmt.Sprintf("%x", digest[:])),
		chunkBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	return descriptor
}
