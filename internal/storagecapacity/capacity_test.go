package storagecapacity

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestOperatingReserveAndAdmissionBoundaries(t *testing.T) {
	for _, item := range []struct{ total, want int64 }{
		{10 << 30, 2 << 30}, {40 << 30, 4 << 30}, {(40 << 30) + 1, (4 << 30) + 1}, {1 << 30, 2 << 30},
	} {
		snapshot := Snapshot{TotalBytes: item.total, AvailableBytes: item.total}
		reserve, err := snapshot.OperatingReserve()
		if err != nil || reserve != item.want {
			t.Fatalf("reserve=%d err=%v want=%d", reserve, err, item.want)
		}
	}
	snapshot := Snapshot{TotalBytes: 10 << 30, AvailableBytes: (2 << 30) + 100}
	if err := Check(snapshot, 60, 40); err != nil {
		t.Fatal(err)
	}
	if err := Check(snapshot, 60, 41); !errors.Is(err, ErrPressure) {
		t.Fatalf("over-reservation=%v", err)
	}
	if err := Check(Snapshot{TotalBytes: 1 << 30, AvailableBytes: 1 << 30}, 0, 0); !errors.Is(err, ErrPressure) {
		t.Fatalf("undersized filesystem=%v", err)
	}
}

func TestUnknownAndOverflowCapacityFailClosed(t *testing.T) {
	for _, snapshot := range []Snapshot{{}, {TotalBytes: -1}, {TotalBytes: 1, AvailableBytes: 2}, {TotalBytes: 1, AvailableBytes: -1}} {
		if err := Check(snapshot, 0, 0); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("invalid snapshot=%v", err)
		}
	}
	valid := Snapshot{TotalBytes: math.MaxInt64, AvailableBytes: math.MaxInt64}
	if err := Check(valid, math.MaxInt64, math.MaxInt64); !errors.Is(err, ErrPressure) {
		t.Fatalf("overflow admission=%v", err)
	}
	if err := Check(valid, -1, 0); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("negative reservation=%v", err)
	}
}

func TestUploadReservationsIncludePublicationCopyAndMetadataWithoutDoubleChargingStaging(t *testing.T) {
	before, err := UploadReservation(1_000, 0, 0)
	if err != nil || before != 2_000+UploadMetadataAllowance {
		t.Fatalf("initial=%d err=%v", before, err)
	}
	after, err := UploadReservation(1_000, 400, 1)
	if err != nil || after != before-400+ChunkMetadataAllowance {
		t.Fatalf("staged=%d err=%v", after, err)
	}
	finalizing, err := UploadReservation(1_000, 1_000, 2)
	if err != nil || finalizing != 1_000+UploadMetadataAllowance+2*ChunkMetadataAllowance {
		t.Fatalf("publication=%d err=%v", finalizing, err)
	}
	for _, input := range [][3]int64{{-1, 0, 0}, {1, 2, 0}, {1, -1, 0}, {1, 0, -1}, {math.MaxInt64, 0, 0}, {1, 0, math.MaxInt64}} {
		if _, err := UploadReservation(input[0], input[1], input[2]); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("invalid reservation=%v", err)
		}
	}
}

func TestFileSystemProbeAndUnavailablePath(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("filesystem probe is not supported on this server platform")
	}
	root := t.TempDir()
	provider, err := NewFileSystemProvider(root)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := provider.Snapshot(context.Background())
	if err != nil || snapshot.TotalBytes <= 0 || snapshot.AvailableBytes < 0 {
		t.Fatalf("snapshot=%+v err=%v", snapshot, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := provider.Snapshot(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled probe=%v", err)
	}
	if _, err := NewFileSystemProvider(filepath.Join(root, "missing")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing root=%v", err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileSystemProvider(alias); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("symlink root=%v", err)
	}
}
