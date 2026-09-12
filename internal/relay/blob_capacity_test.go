package relay_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/storagecapacity"
)

type blobTestCapacity struct {
	probes      int
	failAfter   int
	unavailable bool
}

func (p *blobTestCapacity) Snapshot(context.Context) (storagecapacity.Snapshot, error) {
	p.probes++
	if p.unavailable {
		return storagecapacity.Snapshot{}, storagecapacity.ErrUnavailable
	}
	free := int64(4 << 30)
	if p.failAfter > 0 && p.probes > p.failAfter {
		free = storagecapacity.MinimumOperatingReserve
	}
	return storagecapacity.Snapshot{TotalBytes: 10 << 30, AvailableBytes: free}, nil
}

func TestBlobStoragePressureRetainsCommittedPrefixAndRecoversWithoutReplacement(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	blobs, err := relay.NewFileBlobContentStore(root)
	if err != nil {
		t.Fatal(err)
	}
	uploads, err := relay.NewFileBlobUploadContentStore(root, blobs)
	if err != nil {
		t.Fatal(err)
	}
	capacity := &blobTestCapacity{}
	if err := blobs.SetSharedCapacityProvider(capacity); err != nil {
		t.Fatal(err)
	}
	if err := uploads.SetSharedCapacityProvider(capacity); err != nil {
		t.Fatal(err)
	}
	scope := relay.BlobScope{TenantID: uuid.New(), DomainID: uuid.New()}
	uploadID := uuid.New()
	content := bytes.Repeat([]byte{7}, 2*storagecapacity.MaximumWriteBoundary)
	chunk := func(offset int64, data []byte) relay.BlobUploadChunkRequest {
		digest := sha256.Sum256(data)
		return relay.BlobUploadChunkRequest{UploadID: uploadID, Offset: offset,
			ByteCount: int64(len(data)), ChunkSHA256: hex.EncodeToString(digest[:])}
	}
	if err := uploads.Initialize(ctx, scope, uploadID, 0); err != nil {
		t.Fatal(err)
	}
	if err := uploads.Append(ctx, scope, chunk(0, content[:16]), bytes.NewReader(content[:16])); err != nil {
		t.Fatal(err)
	}
	capacity.failAfter = capacity.probes + 1
	if err := uploads.Append(ctx, scope, chunk(16, content[16:]), bytes.NewReader(content[16:])); !errors.Is(err, storagecapacity.ErrPressure) {
		t.Fatalf("append=%v", err)
	}
	path := filepath.Join(root, ".uploads", scope.TenantID.String(), scope.DomainID.String(), uploadID.String())
	info, err := os.Stat(path)
	if err != nil || info.Size() != 16 {
		t.Fatalf("committed prefix=%v err=%v", info, err)
	}
	capacity.failAfter = 0
	if err := uploads.Append(ctx, scope, chunk(16, content[16:]), bytes.NewReader(content[16:])); err != nil {
		t.Fatal(err)
	}
	capacity.failAfter = capacity.probes + 1
	if _, err := uploads.Publish(ctx, scope, uploadID, relay.BlobID(content), int64(len(content))); !errors.Is(err, storagecapacity.ErrPressure) {
		t.Fatalf("publish=%v", err)
	}
	info, err = os.Stat(path)
	if err != nil || info.Size() != int64(len(content)) {
		t.Fatalf("staging lost=%v %v", info, err)
	}
	if _, err := blobs.Open(ctx, scope, relay.BlobID(content)); err == nil {
		t.Fatal("partial publication became visible")
	}
	staged, err := os.ReadDir(filepath.Join(root, ".staging"))
	if err != nil || len(staged) != 0 {
		t.Fatalf("failed temporary publication was retained: %v %v", staged, err)
	}
	capacity.failAfter = 0
	if _, err := uploads.Publish(ctx, scope, uploadID, relay.BlobID(content), int64(len(content))); err != nil {
		t.Fatal(err)
	}
	capacity.unavailable = true
	stored, err := blobs.Open(ctx, scope, relay.BlobID(content))
	if err != nil {
		t.Fatalf("capacity probe blocked reads: %v", err)
	}
	actual, err := io.ReadAll(stored.Reader)
	_ = stored.Reader.Close()
	if err != nil || !bytes.Equal(actual, content) {
		t.Fatal("content changed after recovery", err)
	}
	if err := uploads.Delete(ctx, scope, uploadID); err != nil {
		t.Fatalf("capacity probe blocked cleanup: %v", err)
	}
}
