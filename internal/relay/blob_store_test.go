package relay_test

import (
	"bytes"
	"context"
	"io"
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
