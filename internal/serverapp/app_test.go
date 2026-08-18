package serverapp

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/relay"
)

type maintenanceAuthority struct {
	blobs   map[string]bool
	uploads map[uuid.UUID]bool
	expired bool
}

func (s *maintenanceAuthority) ExpireBlobUploads(context.Context, int64, int64) ([]relay.BlobUploadExpiry, error) {
	s.expired = true
	return nil, nil
}

func (s *maintenanceAuthority) DeleteBlobIfUnauthorized(_ context.Context, candidate relay.BlobFileCandidate, _, _ int64, remove func() error) (bool, error) {
	if s.blobs[candidate.BlobID] {
		return false, nil
	}
	return true, remove()
}

func (s *maintenanceAuthority) DeleteBlobUploadIfUnauthorized(_ context.Context, candidate relay.BlobUploadFileCandidate, _, _ int64, remove func() error) (bool, error) {
	if s.uploads[candidate.UploadID] {
		return false, nil
	}
	return true, remove()
}

func TestReconcileBlobFilesRechecksAuthorityBeforeDeletion(t *testing.T) {
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
	protectedBytes, orphanBytes := []byte("republished"), []byte("orphan")
	protectedID, orphanID := relay.BlobID(protectedBytes), relay.BlobID(orphanBytes)
	for id, content := range map[string][]byte{protectedID: protectedBytes, orphanID: orphanBytes} {
		if _, err := blobs.Put(ctx, scope, id, bytes.NewReader(content), int64(len(content))); err != nil {
			t.Fatal(err)
		}
	}
	protectedUpload, orphanUpload := uuid.New(), uuid.New()
	if err := uploads.Initialize(ctx, scope, protectedUpload, 0); err != nil {
		t.Fatal(err)
	}
	if err := uploads.Initialize(ctx, scope, orphanUpload, 0); err != nil {
		t.Fatal(err)
	}
	authority := &maintenanceAuthority{blobs: map[string]bool{protectedID: true}, uploads: map[uuid.UUID]bool{protectedUpload: true}}
	if err := reconcileBlobFiles(ctx, authority, blobs, uploads, time.Now().Add(2*time.Hour).UnixMilli(), time.Hour.Milliseconds()); err != nil {
		t.Fatal(err)
	}
	if !authority.expired {
		t.Fatal("expiry pass was not run")
	}
	protected, err := blobs.Open(ctx, scope, protectedID)
	if err != nil {
		t.Fatalf("authoritative blob deleted: %v", err)
	}
	_ = protected.Reader.Close()
	if _, err := blobs.Open(ctx, scope, orphanID); err == nil {
		t.Fatal("orphan blob was retained")
	}
	uploadPath := func(id uuid.UUID) string {
		return filepath.Join(root, ".uploads", scope.TenantID.String(), scope.DomainID.String(), id.String())
	}
	if _, err := os.Stat(uploadPath(protectedUpload)); err != nil {
		t.Fatalf("active upload deleted: %v", err)
	}
	if _, err := os.Stat(uploadPath(orphanUpload)); !os.IsNotExist(err) {
		t.Fatalf("orphan upload retained err=%v", err)
	}
}
