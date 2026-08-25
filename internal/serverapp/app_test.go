package serverapp

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/relay"
)

type maintenanceAuthority struct {
	blobs        map[string]bool
	uploads      map[uuid.UUID]bool
	expired      bool
	expiryErr    error
	blobErrors   map[string]error
	uploadErrors map[uuid.UUID]error
}

// memoryBlobMaintenanceStore intentionally has no filesystem representation.
// It protects the adapter boundary used by hosted object storage: serverapp
// decides whether a candidate is still authorized, while the backend owns how
// it is listed and removed.
type memoryBlobMaintenanceStore struct {
	candidates []relay.BlobContentCandidate
	deleted    []string
}

func (s *memoryBlobMaintenanceStore) BlobCandidates(context.Context) ([]relay.BlobContentCandidate, error) {
	return append([]relay.BlobContentCandidate(nil), s.candidates...), nil
}

func (s *memoryBlobMaintenanceStore) DeleteBlob(_ context.Context, _ relay.BlobScope, blobID string) error {
	s.deleted = append(s.deleted, blobID)
	return nil
}

type memoryBlobUploadMaintenanceStore struct {
	candidates []relay.BlobUploadContentCandidate
	deleted    []uuid.UUID
}

func (s *memoryBlobUploadMaintenanceStore) UploadCandidates(context.Context) ([]relay.BlobUploadContentCandidate, error) {
	return append([]relay.BlobUploadContentCandidate(nil), s.candidates...), nil
}

func (s *memoryBlobUploadMaintenanceStore) DeleteUpload(_ context.Context, _ relay.BlobScope, uploadID uuid.UUID) error {
	s.deleted = append(s.deleted, uploadID)
	return nil
}

func (s *maintenanceAuthority) ExpireBlobUploads(context.Context, int64, int64) ([]relay.BlobUploadExpiry, error) {
	s.expired = true
	return nil, s.expiryErr
}

func (s *maintenanceAuthority) DeleteBlobIfUnauthorized(_ context.Context, candidate relay.BlobContentCandidate, _, _ int64, remove func() error) (bool, error) {
	if err := s.blobErrors[candidate.BlobID]; err != nil {
		return false, err
	}
	if s.blobs[candidate.BlobID] {
		return false, nil
	}
	return true, remove()
}

func (s *maintenanceAuthority) DeleteBlobUploadIfUnauthorized(_ context.Context, candidate relay.BlobUploadContentCandidate, _, _ int64, remove func() error) (bool, error) {
	if err := s.uploadErrors[candidate.UploadID]; err != nil {
		return false, err
	}
	if s.uploads[candidate.UploadID] {
		return false, nil
	}
	return true, remove()
}

func TestReconcileBlobFilesContinuesAfterScopeFailure(t *testing.T) {
	ctx := context.Background()
	scope := relay.BlobScope{TenantID: uuid.New(), DomainID: uuid.New()}
	blockedBlob := relay.BlobID([]byte("blocked"))
	writableBlob := relay.BlobID([]byte("writable"))
	blockedUpload := uuid.New()
	writableUpload := uuid.New()
	blobs := &memoryBlobMaintenanceStore{candidates: []relay.BlobContentCandidate{
		{Scope: scope, BlobID: blockedBlob, ModifiedMilliseconds: 1},
		{Scope: scope, BlobID: writableBlob, ModifiedMilliseconds: 1},
	}}
	uploads := &memoryBlobUploadMaintenanceStore{
		candidates: []relay.BlobUploadContentCandidate{
			{Scope: scope, UploadID: blockedUpload, ModifiedMilliseconds: 1},
			{Scope: scope, UploadID: writableUpload, ModifiedMilliseconds: 1},
		},
	}
	expiryFailure := errors.New("expiry scope is fenced")
	blobFailure := errors.New("blob scope is fenced")
	uploadFailure := errors.New("upload scope is fenced")
	authority := &maintenanceAuthority{
		blobs:      map[string]bool{},
		uploads:    map[uuid.UUID]bool{},
		expiryErr:  expiryFailure,
		blobErrors: map[string]error{blockedBlob: blobFailure},
		uploadErrors: map[uuid.UUID]error{
			blockedUpload: uploadFailure,
		},
	}
	err := reconcileBlobFiles(ctx, authority, blobs, uploads, 9_999, 100)
	if !errors.Is(err, expiryFailure) || !errors.Is(err, blobFailure) ||
		!errors.Is(err, uploadFailure) {
		t.Fatalf("maintenance error=%v", err)
	}
	if len(blobs.deleted) != 1 || blobs.deleted[0] != writableBlob {
		t.Fatalf("later writable blob was starved: %v", blobs.deleted)
	}
	if len(uploads.deleted) != 1 || uploads.deleted[0] != writableUpload {
		t.Fatalf("later writable upload was starved: %v", uploads.deleted)
	}
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

func TestReconcileBlobFilesUsesBackendNeutralMaintenanceStores(t *testing.T) {
	ctx := context.Background()
	scope := relay.BlobScope{TenantID: uuid.New(), DomainID: uuid.New()}
	orphanBlob := relay.BlobID([]byte("hosted-orphan"))
	orphanUpload := uuid.New()
	blobs := &memoryBlobMaintenanceStore{candidates: []relay.BlobContentCandidate{{
		Scope: scope, BlobID: orphanBlob, ModifiedMilliseconds: 1,
	}}}
	uploads := &memoryBlobUploadMaintenanceStore{candidates: []relay.BlobUploadContentCandidate{{
		Scope: scope, UploadID: orphanUpload, ModifiedMilliseconds: 1,
	}}}
	authority := &maintenanceAuthority{blobs: map[string]bool{}, uploads: map[uuid.UUID]bool{}}
	if err := reconcileBlobFiles(ctx, authority, blobs, uploads, 9_999, 100); err != nil {
		t.Fatal(err)
	}
	if len(blobs.deleted) != 1 || blobs.deleted[0] != orphanBlob {
		t.Fatalf("expected orphan blob deletion, got %v", blobs.deleted)
	}
	if len(uploads.deleted) != 1 || uploads.deleted[0] != orphanUpload {
		t.Fatalf("expected orphan upload deletion, got %v", uploads.deleted)
	}
}
