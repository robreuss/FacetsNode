package relay_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/relay"
)

func TestFileBlobContentStoreCommitsContentAddressedBytesAtomically(t *testing.T) {
	store, err := relay.NewFileBlobContentStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	scope := relay.BlobScope{TenantID: uuid.New(), DomainID: uuid.New()}
	content := []byte("independently encrypted relay blob")
	blobID := relay.BlobID(content)
	result, err := store.Put(
		ctx,
		scope,
		blobID,
		bytes.NewReader(content),
		int64(len(content)),
	)
	if err != nil || !result.Created || result.ByteCount != int64(len(content)) {
		t.Fatalf("first put=%+v err=%v", result, err)
	}
	retry, err := store.Put(
		ctx,
		scope,
		blobID,
		bytes.NewReader(content),
		int64(len(content)),
	)
	if err != nil || retry.Created || retry.ByteCount != int64(len(content)) {
		t.Fatalf("retry=%+v err=%v", retry, err)
	}
	stored, err := store.Open(ctx, scope, blobID)
	if err != nil {
		t.Fatal(err)
	}
	defer stored.Reader.Close()
	actual, err := io.ReadAll(stored.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, content) || stored.ByteCount != int64(len(content)) {
		t.Fatalf("stored bytes=%q count=%d", actual, stored.ByteCount)
	}

	otherScope := relay.BlobScope{TenantID: scope.TenantID, DomainID: uuid.New()}
	if _, err := store.Open(ctx, otherScope, blobID); err == nil {
		t.Fatalf("blob crossed domain scope")
	}
}

func TestFileBlobUploadStoreRepairsCrashTailAndPublishesAfterRestart(t *testing.T) {
	root := t.TempDir()
	blobs, err := relay.NewFileBlobContentStore(root)
	if err != nil {
		t.Fatal(err)
	}
	uploads, err := relay.NewFileBlobUploadContentStore(root, blobs)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	scope := relay.BlobScope{TenantID: uuid.New(), DomainID: uuid.New()}
	uploadID := uuid.New()
	content := []byte("restart-safe contiguous opaque bytes")
	first := content[:12]
	firstDigest := sha256.Sum256(first)
	if err := uploads.Initialize(ctx, scope, uploadID, 0); err != nil {
		t.Fatal(err)
	}
	if err := uploads.Append(ctx, scope, relay.BlobUploadChunkRequest{
		UploadID: uploadID, Offset: 0, ByteCount: int64(len(first)), ChunkSHA256: hex.EncodeToString(firstDigest[:]),
	}, bytes.NewReader(first)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, ".uploads", scope.TenantID.String(), scope.DomainID.String(), uploadID.String())
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("uncommitted-crash-tail")); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	restarted, err := relay.NewFileBlobUploadContentStore(root, blobs)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Initialize(ctx, scope, uploadID, int64(len(first))); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Size() != int64(len(first)) {
		t.Fatalf("repaired size=%v err=%v", info, err)
	}
	second := content[len(first):]
	secondDigest := sha256.Sum256(second)
	if err := restarted.Append(ctx, scope, relay.BlobUploadChunkRequest{
		UploadID: uploadID, Offset: int64(len(first)), ByteCount: int64(len(second)), ChunkSHA256: hex.EncodeToString(secondDigest[:]),
	}, bytes.NewReader(second)); err != nil {
		t.Fatal(err)
	}
	result, err := restarted.Publish(ctx, scope, uploadID, relay.BlobID(content), int64(len(content)))
	if err != nil || !result.Created {
		t.Fatalf("publish=%+v err=%v", result, err)
	}
	stored, err := blobs.Open(ctx, scope, relay.BlobID(content))
	if err != nil {
		t.Fatal(err)
	}
	defer stored.Reader.Close()
	actual, _ := io.ReadAll(stored.Reader)
	if !bytes.Equal(actual, content) {
		t.Fatalf("stored=%q", actual)
	}
}

func TestFileBlobUploadStoreRejectsChunkHashWithoutAdvancingAndSupportsZeroBytes(t *testing.T) {
	root := t.TempDir()
	blobs, _ := relay.NewFileBlobContentStore(root)
	uploads, _ := relay.NewFileBlobUploadContentStore(root, blobs)
	ctx := context.Background()
	scope := relay.BlobScope{TenantID: uuid.New(), DomainID: uuid.New()}
	uploadID := uuid.New()
	if err := uploads.Initialize(ctx, scope, uploadID, 0); err != nil {
		t.Fatal(err)
	}
	if err := uploads.Append(ctx, scope, relay.BlobUploadChunkRequest{
		UploadID: uploadID, Offset: 0, ByteCount: 3, ChunkSHA256: hex.EncodeToString(make([]byte, 32)),
	}, bytes.NewReader([]byte("bad"))); !relay.ErrorHasCode(err, relay.CodeInvalidBlobUpload) {
		t.Fatalf("hash mismatch err=%v", err)
	}
	path := filepath.Join(root, ".uploads", scope.TenantID.String(), scope.DomainID.String(), uploadID.String())
	info, err := os.Stat(path)
	if err != nil || info.Size() != 0 {
		t.Fatalf("failed chunk size=%v err=%v", info, err)
	}
	emptyID := relay.BlobID(nil)
	result, err := uploads.Publish(ctx, scope, uploadID, emptyID, 0)
	if err != nil || !result.Created || result.ByteCount != 0 {
		t.Fatalf("zero publish=%+v err=%v", result, err)
	}
}

func TestFileBlobContentStoreRejectsDigestLengthAndCancellation(t *testing.T) {
	store, err := relay.NewFileBlobContentStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	scope := relay.BlobScope{TenantID: uuid.New(), DomainID: uuid.New()}
	content := []byte("relay blob")
	if _, err := store.Put(
		context.Background(),
		scope,
		relay.BlobID([]byte("different")),
		bytes.NewReader(content),
		int64(len(content)),
	); !relay.ErrorHasCode(err, relay.CodeInvalidBlob) {
		t.Fatalf("digest mismatch err=%v", err)
	}
	if _, err := store.Put(
		context.Background(),
		scope,
		relay.BlobID(content),
		bytes.NewReader(content),
		int64(len(content)-1),
	); !relay.ErrorHasCode(err, relay.CodeInvalidBlob) {
		t.Fatalf("length mismatch err=%v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Put(
		canceled,
		scope,
		relay.BlobID(content),
		bytes.NewReader(content),
		int64(len(content)),
	); err == nil {
		t.Fatalf("canceled upload succeeded")
	}
}
