package backupcustody

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

func TestContentStoreReconcilesTailAndPublishesExactObject(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(parent, "custody")
	store, err := OpenContentStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := OpenContentStore(root); err == nil {
		t.Fatal("second process/store lock acquired")
	}
	uploadID := uuid.New()
	if err := store.PrepareUpload(uploadID); err != nil {
		t.Fatal(err)
	}
	if next, err := store.ReconcileAndAppend(uploadID, 0, []byte("first"), 100, 100); err != nil || next != 5 {
		t.Fatalf("first append next=%d err=%v", next, err)
	}
	// Simulate a database failure after fsync. The exact retry truncates the
	// uncommitted tail before replacing it with the committed next chunk.
	if next, err := store.ReconcileAndAppend(uploadID, 0, []byte("second"), 100, 100); err != nil || next != 6 {
		t.Fatalf("reconciled append next=%d err=%v", next, err)
	}
	record := serviceauthority.BackupCustodyGenerationRecord{
		Version: Version, AccountID: uuid.New(), TargetID: uuid.New(), BackupSetID: uuid.New(),
		Generation: 1, UploadID: uploadID, OuterByteCount: 6,
		OuterDigest: "FjZ6rLZ6SgF8jairlWgsyzkIY3gPcRTdoKDgxVZEx8Q",
	}
	path, err := store.Publish(record)
	if err != nil {
		t.Fatal(err)
	}
	if retry, err := store.Publish(record); err != nil || retry != path {
		t.Fatalf("publish retry path=%q err=%v", retry, err)
	}
	if _, err := os.Lstat(filepath.Join(root, stagingPath(uploadID))); !os.IsNotExist(err) {
		t.Fatalf("writable staging alias remains: %v", err)
	}
	bytesOnDisk, err := os.ReadFile(filepath.Join(root, path))
	if err != nil || !bytes.Equal(bytesOnDisk, []byte("second")) {
		t.Fatalf("object=%q err=%v", bytesOnDisk, err)
	}
}

func TestContentStoreRejectsSymlinkStagingAndShortCommittedFile(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(parent, "custody")
	store, err := OpenContentStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	uploadID := uuid.New()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, stagingPath(uploadID))); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReconcileAndAppend(uploadID, 0, []byte("x"), 1, 1); err == nil {
		t.Fatal("symlink staging accepted")
	}
	if outsideBytes, _ := os.ReadFile(outside); !bytes.Equal(outsideBytes, []byte("secret")) {
		t.Fatal("symlink target was modified")
	}
}

func TestContentStoreDetectsRootReplacementAndUnsafeParents(t *testing.T) {
	unsafeParent := t.TempDir()
	if err := os.Chmod(unsafeParent, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenContentStore(filepath.Join(unsafeParent, "custody")); err == nil {
		t.Fatal("group/world-readable parent accepted")
	}

	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	realParent := filepath.Join(parent, "real")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	linkedParent := filepath.Join(parent, "linked")
	if err := os.Symlink(realParent, linkedParent); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenContentStore(filepath.Join(linkedParent, "custody")); err == nil {
		t.Fatal("symlink parent accepted")
	}

	root := filepath.Join(parent, "custody")
	store, err := OpenContentStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	moved := filepath.Join(parent, "custody-moved")
	if err := os.Rename(root, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := store.PrepareUpload(uuid.New()); err == nil {
		t.Fatal("ambient custody-root replacement was not detected")
	}
}

func TestContentStoreRejectsTamperedImmutableObjectAndReconcilesPublishedOrphan(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(parent, "custody")
	store, err := OpenContentStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	uploadID := uuid.New()
	accountID, targetID, setID := uuid.New(), uuid.New(), uuid.New()
	contents := []byte("opaque-backup-generation")
	if err := store.PrepareUpload(uploadID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReconcileAndAppend(uploadID, 0, contents, uint64(len(contents)), uint64(len(contents))); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(contents)
	record := serviceauthority.BackupCustodyGenerationRecord{
		Version: Version, AccountID: accountID, TargetID: targetID, BackupSetID: setID,
		Generation: 1, UploadID: uploadID, OuterByteCount: uint64(len(contents)),
		OuterDigest: base64.RawURLEncoding.EncodeToString(digest[:]),
	}
	object, err := store.Publish(record)
	if err != nil {
		t.Fatal(err)
	}
	upload := UploadRecord{
		AccountID: accountID, TargetID: targetID, BackupSetID: setID, UploadID: uploadID,
		Request: PublishRequest{Version: Version, RequestID: uuid.New(), Generation: 1,
			RequestedAtMilliseconds: 1_000,
			Credential: TargetCredentialReference{Version: Version, AccountID: accountID, TargetID: targetID,
				BackupSetID: setID, CredentialID: uuid.New(), Capabilities: []Capability{Publish},
				ExpiresAtMilliseconds: 2_000, RequestNonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}},
	}
	if err := store.EnsureStaging(upload, uint64(len(contents)), uint64(len(contents))); err != nil {
		t.Fatalf("published orphan did not converge: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, stagingPath(uploadID))); !os.IsNotExist(err) {
		t.Fatalf("orphan reconciliation recreated staging: %v", err)
	}
	objectPath := filepath.Join(root, object)
	if err := os.Chmod(objectPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(objectPath, bytes.Repeat([]byte{9}, len(contents)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.OpenObject(record, object); err == nil {
		t.Fatal("tampered immutable object accepted")
	}
}

func TestContentStoreRangeUsesHeldExactObjectAndDetectsPathSubstitution(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(parent, "custody")
	store, err := OpenContentStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	contents := []byte("0123456789abcdefghijklmnopqrstuvwxyz")
	uploadID := uuid.New()
	if err := store.PrepareUpload(uploadID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReconcileAndAppend(uploadID, 0, contents, uint64(len(contents)), uint64(len(contents))); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(contents)
	record := serviceauthority.BackupCustodyGenerationRecord{
		Version: Version, AccountID: uuid.New(), TargetID: uuid.New(), BackupSetID: uuid.New(),
		Generation: 1, UploadID: uploadID, OuterByteCount: uint64(len(contents)),
		OuterDigest: base64.RawURLEncoding.EncodeToString(digest[:]),
	}
	path, err := store.Publish(record)
	if err != nil {
		t.Fatal(err)
	}
	rangeReader, count, err := store.OpenObjectRange(record, path, 10, 9)
	if err != nil || count != 9 {
		t.Fatalf("range count=%d err=%v", count, err)
	}
	rangeBytes, err := io.ReadAll(rangeReader)
	if err != nil || !bytes.Equal(rangeBytes, contents[10:19]) || rangeReader.Close() != nil {
		t.Fatalf("range=%q err=%v", rangeBytes, err)
	}
	tailReader, count, err := store.OpenObjectRange(record, path, uint64(len(contents)-3), 10)
	if err != nil || count != 3 {
		t.Fatalf("tail count=%d err=%v", count, err)
	}
	if tail, err := io.ReadAll(tailReader); err != nil || !bytes.Equal(tail, contents[len(contents)-3:]) {
		t.Fatalf("tail=%q err=%v", tail, err)
	}
	if err := tailReader.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.OpenObjectRange(record, path, 0, MaximumRangeByteCount+1); err == nil {
		t.Fatal("oversized range accepted")
	}

	held, _, err := store.OpenObjectRange(record, path, 4, 8)
	if err != nil {
		t.Fatal(err)
	}
	absolute := filepath.Join(root, path)
	moved := absolute + ".moved"
	if err := os.Rename(absolute, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(absolute, bytes.Repeat([]byte{'x'}, len(contents)), 0o400); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 8)
	if _, err := io.ReadFull(held, buffer); err != nil || !bytes.Equal(buffer, contents[4:12]) {
		t.Fatalf("held bytes=%q err=%v", buffer, err)
	}
	probe := make([]byte, 1)
	if _, err := held.Read(probe); !errors.Is(err, serviceauthority.ErrInvalid) {
		t.Fatalf("path substitution not detected: %v", err)
	}
	if err := held.Close(); !errors.Is(err, serviceauthority.ErrInvalid) {
		t.Fatalf("close did not retain substitution error: %v", err)
	}
}
