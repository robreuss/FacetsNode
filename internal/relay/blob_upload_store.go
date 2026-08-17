package relay

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/google/uuid"
)

type BlobUploadContentStore interface {
	Initialize(context.Context, BlobScope, uuid.UUID, int64) error
	Append(context.Context, BlobScope, BlobUploadChunkRequest, io.Reader) error
	Publish(context.Context, BlobScope, uuid.UUID, string, int64) (BlobContentResult, error)
	Delete(context.Context, BlobScope, uuid.UUID) error
}

type FileBlobUploadContentStore struct {
	root  string
	blobs BlobContentStore
}

func NewFileBlobUploadContentStore(root string, blobs BlobContentStore) (*FileBlobUploadContentStore, error) {
	if root == "" || !filepath.IsAbs(root) || blobs == nil {
		return nil, fmt.Errorf("blob upload root must be absolute and final store is required")
	}
	root = filepath.Clean(root)
	if err := os.MkdirAll(filepath.Join(root, ".uploads"), 0o700); err != nil {
		return nil, fmt.Errorf("create blob upload directory: %w", err)
	}
	return &FileBlobUploadContentStore{root: root, blobs: blobs}, nil
}

func (s *FileBlobUploadContentStore) Initialize(
	ctx context.Context, scope BlobScope, uploadID uuid.UUID, committedOffset int64,
) error {
	if err := validateUploadContentScope(ctx, scope, uploadID); err != nil {
		return err
	}
	if committedOffset < 0 || committedOffset > MaximumBlobByteCount {
		return protocolError(CodeInvalidBlobUpload, "durable upload offset is invalid")
	}
	path := s.uploadPath(scope, uploadID)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create upload scope directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open staged upload: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat staged upload: %w", err)
	}
	if info.Size() < committedOffset {
		return fmt.Errorf("staged upload is shorter than its durable offset")
	}
	if info.Size() != committedOffset {
		if err := file.Truncate(committedOffset); err != nil {
			return fmt.Errorf("repair staged upload tail: %w", err)
		}
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync staged upload: %w", err)
	}
	return syncDirectory(filepath.Dir(path))
}

func (s *FileBlobUploadContentStore) Append(
	ctx context.Context, scope BlobScope, request BlobUploadChunkRequest, source io.Reader,
) error {
	if err := validateUploadContentScope(ctx, scope, request.UploadID); err != nil {
		return err
	}
	if err := request.Validate(); err != nil {
		return err
	}
	path := s.uploadPath(scope, request.UploadID)
	file, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open staged upload: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat staged upload: %w", err)
	}
	if info.Size() < request.Offset {
		return fmt.Errorf("staged upload is shorter than its durable offset")
	}
	if err := file.Truncate(request.Offset); err != nil {
		return fmt.Errorf("truncate staged upload to durable offset: %w", err)
	}
	if _, err := file.Seek(request.Offset, io.SeekStart); err != nil {
		return fmt.Errorf("seek staged upload: %w", err)
	}
	hash := sha256.New()
	limited := &io.LimitedReader{R: &contextReader{ctx: ctx, reader: source}, N: request.ByteCount + 1}
	written, copyErr := io.Copy(io.MultiWriter(file, hash), limited)
	if copyErr != nil || written != request.ByteCount ||
		hex.EncodeToString(hash.Sum(nil)) != request.ChunkSHA256 {
		_ = file.Truncate(request.Offset)
		_ = file.Sync()
		if copyErr != nil {
			return fmt.Errorf("append staged upload: %w", copyErr)
		}
		return protocolError(CodeInvalidBlobUpload, "chunk length or SHA-256 does not match")
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync staged upload: %w", err)
	}
	return nil
}

func (s *FileBlobUploadContentStore) Publish(
	ctx context.Context, scope BlobScope, uploadID uuid.UUID, blobID string, byteCount int64,
) (BlobContentResult, error) {
	if err := validateUploadContentScope(ctx, scope, uploadID); err != nil {
		return BlobContentResult{}, err
	}
	file, err := os.Open(s.uploadPath(scope, uploadID))
	if err != nil {
		return BlobContentResult{}, fmt.Errorf("open staged upload for publication: %w", err)
	}
	defer file.Close()
	return s.blobs.Put(ctx, scope, blobID, file, byteCount)
}

func (s *FileBlobUploadContentStore) Delete(
	ctx context.Context, scope BlobScope, uploadID uuid.UUID,
) error {
	if err := validateUploadContentScope(ctx, scope, uploadID); err != nil {
		return err
	}
	err := os.Remove(s.uploadPath(scope, uploadID))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete staged upload: %w", err)
	}
	return nil
}

func (s *FileBlobUploadContentStore) DeleteUpload(ctx context.Context, scope BlobScope, uploadID uuid.UUID) error {
	return s.Delete(ctx, scope, uploadID)
}

func (s *FileBlobUploadContentStore) UploadCandidates(ctx context.Context) ([]BlobUploadFileCandidate, error) {
	base := filepath.Join(s.root, ".uploads")
	var result []BlobUploadFileCandidate
	err := filepath.WalkDir(base, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(base, path)
		if err != nil {
			return err
		}
		segments := splitCleanPath(relative)
		if len(segments) != 3 {
			return nil
		}
		tenantID, tenantErr := uuid.Parse(segments[0])
		domainID, domainErr := uuid.Parse(segments[1])
		uploadID, uploadErr := uuid.Parse(segments[2])
		if tenantErr != nil || domainErr != nil || uploadErr != nil {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		result = append(result, BlobUploadFileCandidate{Scope: BlobScope{TenantID: tenantID, DomainID: domainID}, UploadID: uploadID, ModifiedMilliseconds: info.ModTime().UnixMilli()})
		return nil
	})
	return result, err
}

func (s *FileBlobUploadContentStore) uploadPath(scope BlobScope, uploadID uuid.UUID) string {
	return filepath.Join(s.root, ".uploads", scope.TenantID.String(), scope.DomainID.String(), uploadID.String())
}

func validateUploadContentScope(ctx context.Context, scope BlobScope, uploadID uuid.UUID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := scope.validate(); err != nil {
		return err
	}
	if uploadID == uuid.Nil {
		return protocolError(CodeInvalidBlobUpload, "blob upload ID is invalid")
	}
	return nil
}
