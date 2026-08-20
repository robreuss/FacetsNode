package relay

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/google/uuid"
)

type BlobScope struct {
	TenantID uuid.UUID
	DomainID uuid.UUID
}

func (s BlobScope) validate() error {
	if s.TenantID == uuid.Nil || s.DomainID == uuid.Nil {
		return protocolError(CodeWrongScope, "blob scope is invalid")
	}
	return nil
}

type BlobContentResult struct {
	Created   bool
	ByteCount int64
}

type BlobContent struct {
	Reader    io.ReadSeekCloser
	ByteCount int64
}

type BlobContentStore interface {
	Put(
		ctx context.Context,
		scope BlobScope,
		blobID string,
		source io.Reader,
		expectedByteCount int64,
	) (BlobContentResult, error)
	Open(
		ctx context.Context,
		scope BlobScope,
		blobID string,
	) (BlobContent, error)
}

// BlobContentMaintenanceStore is deliberately separate from BlobContentStore.
// Hosted object storage needs the same authority-checked reclamation lifecycle
// as local volumes, but does not need to expose filesystem paths to serverapp.
type BlobContentMaintenanceStore interface {
	BlobCandidates(context.Context) ([]BlobContentCandidate, error)
	DeleteBlob(context.Context, BlobScope, string) error
}

type BlobContentCandidate struct {
	Scope                BlobScope
	BlobID               string
	ModifiedMilliseconds int64
}

type BlobUploadContentCandidate struct {
	Scope                BlobScope
	UploadID             uuid.UUID
	ModifiedMilliseconds int64
}

type FileBlobContentStore struct {
	root string
}

func NewFileBlobContentStore(root string) (*FileBlobContentStore, error) {
	if root == "" || !filepath.IsAbs(root) {
		return nil, fmt.Errorf("blob root must be an absolute path")
	}
	root = filepath.Clean(root)
	if err := os.MkdirAll(filepath.Join(root, ".staging"), 0o700); err != nil {
		return nil, fmt.Errorf("create blob staging directory: %w", err)
	}
	return &FileBlobContentStore{root: root}, nil
}

func (s *FileBlobContentStore) Put(
	ctx context.Context,
	scope BlobScope,
	blobID string,
	source io.Reader,
	expectedByteCount int64,
) (BlobContentResult, error) {
	if err := scope.validate(); err != nil {
		return BlobContentResult{}, err
	}
	if err := ValidateBlobID(blobID); err != nil {
		return BlobContentResult{}, err
	}
	if expectedByteCount < 0 || expectedByteCount > MaximumBlobByteCount {
		return BlobContentResult{}, protocolError(CodeInvalidBlob, "blob byte count is invalid")
	}
	staged, err := os.CreateTemp(filepath.Join(s.root, ".staging"), "upload-*")
	if err != nil {
		return BlobContentResult{}, fmt.Errorf("create staged blob: %w", err)
	}
	stagedPath := staged.Name()
	defer func() { _ = os.Remove(stagedPath) }()
	hash := sha256.New()
	limited := &io.LimitedReader{
		R: &contextReader{ctx: ctx, reader: source},
		N: expectedByteCount + 1,
	}
	written, copyErr := io.Copy(io.MultiWriter(staged, hash), limited)
	if copyErr != nil {
		_ = staged.Close()
		return BlobContentResult{}, fmt.Errorf("stage blob content: %w", copyErr)
	}
	if written != expectedByteCount {
		_ = staged.Close()
		return BlobContentResult{}, protocolError(CodeInvalidBlob, "blob length differs from Content-Length")
	}
	actualID := base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
	if actualID != blobID {
		_ = staged.Close()
		return BlobContentResult{}, protocolError(CodeInvalidBlob, "blob content digest differs from its identifier")
	}
	if err := staged.Sync(); err != nil {
		_ = staged.Close()
		return BlobContentResult{}, fmt.Errorf("sync staged blob: %w", err)
	}
	if err := staged.Close(); err != nil {
		return BlobContentResult{}, fmt.Errorf("close staged blob: %w", err)
	}
	domainDirectory := s.domainDirectory(scope)
	if err := os.MkdirAll(domainDirectory, 0o700); err != nil {
		return BlobContentResult{}, fmt.Errorf("create blob domain directory: %w", err)
	}
	destination := filepath.Join(domainDirectory, blobID)
	if err := os.Link(stagedPath, destination); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return BlobContentResult{}, fmt.Errorf("commit blob content: %w", err)
		}
		if err := verifyBlobFile(destination, blobID, expectedByteCount); err != nil {
			return BlobContentResult{}, err
		}
		return BlobContentResult{Created: false, ByteCount: expectedByteCount}, nil
	}
	if err := syncDirectory(domainDirectory); err != nil {
		return BlobContentResult{}, err
	}
	return BlobContentResult{Created: true, ByteCount: expectedByteCount}, nil
}

func (s *FileBlobContentStore) Open(
	ctx context.Context,
	scope BlobScope,
	blobID string,
) (BlobContent, error) {
	if err := scope.validate(); err != nil {
		return BlobContent{}, err
	}
	if err := ValidateBlobID(blobID); err != nil {
		return BlobContent{}, err
	}
	if err := ctx.Err(); err != nil {
		return BlobContent{}, err
	}
	file, err := os.Open(filepath.Join(s.domainDirectory(scope), blobID))
	if err != nil {
		return BlobContent{}, fmt.Errorf("open blob content: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return BlobContent{}, fmt.Errorf("stat blob content: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > MaximumBlobByteCount {
		_ = file.Close()
		return BlobContent{}, fmt.Errorf("stored blob content has invalid file metadata")
	}
	return BlobContent{Reader: file, ByteCount: info.Size()}, nil
}

func (s *FileBlobContentStore) domainDirectory(scope BlobScope) string {
	return filepath.Join(s.root, scope.TenantID.String(), scope.DomainID.String())
}

func (s *FileBlobContentStore) DeleteBlob(ctx context.Context, scope BlobScope, blobID string) error {
	if err := scope.validate(); err != nil {
		return err
	}
	if err := ValidateBlobID(blobID); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	err := os.Remove(filepath.Join(s.domainDirectory(scope), blobID))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete blob content: %w", err)
	}
	return nil
}

func (s *FileBlobContentStore) BlobCandidates(ctx context.Context) ([]BlobContentCandidate, error) {
	var result []BlobContentCandidate
	err := filepath.WalkDir(s.root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() {
			if path != s.root && (entry.Name() == ".staging" || entry.Name() == ".uploads") {
				return filepath.SkipDir
			}
			return nil
		}
		relative, err := filepath.Rel(s.root, path)
		if err != nil {
			return err
		}
		segments := splitCleanPath(relative)
		if len(segments) != 3 {
			return nil
		}
		tenantID, tenantErr := uuid.Parse(segments[0])
		domainID, domainErr := uuid.Parse(segments[1])
		if tenantErr != nil || domainErr != nil || ValidateBlobID(segments[2]) != nil {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		result = append(result, BlobContentCandidate{Scope: BlobScope{TenantID: tenantID, DomainID: domainID}, BlobID: segments[2], ModifiedMilliseconds: info.ModTime().UnixMilli()})
		return nil
	})
	return result, err
}

func splitCleanPath(path string) []string {
	var parts []string
	for path != "." && path != string(filepath.Separator) && path != "" {
		dir, file := filepath.Split(path)
		if file != "" {
			parts = append([]string{file}, parts...)
		}
		path = filepath.Clean(dir)
	}
	return parts
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
}

func verifyBlobFile(path, blobID string, expectedByteCount int64) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open existing blob content: %w", err)
	}
	defer file.Close()
	hash := sha256.New()
	written, err := io.Copy(hash, file)
	if err != nil {
		return fmt.Errorf("verify existing blob content: %w", err)
	}
	actualID := base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
	if written != expectedByteCount || actualID != blobID {
		return fmt.Errorf("existing blob content failed integrity verification")
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open blob directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync blob directory: %w", err)
	}
	return nil
}
