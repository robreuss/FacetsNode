package storagecapacity

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
)

type sequenceCapacity struct {
	snapshots []Snapshot
	err       error
	calls     int
}

func (p *sequenceCapacity) Snapshot(context.Context) (Snapshot, error) {
	p.calls++
	if p.err != nil {
		return Snapshot{}, p.err
	}
	if len(p.snapshots) == 0 {
		return Snapshot{}, ErrUnavailable
	}
	result := p.snapshots[0]
	if len(p.snapshots) > 1 {
		p.snapshots = p.snapshots[1:]
	}
	return result, nil
}

func TestWriteRechecksCapacityBeforeEachBoundedPart(t *testing.T) {
	provider := &sequenceCapacity{snapshots: []Snapshot{
		{TotalBytes: 10 << 30, AvailableBytes: 4 << 30},
		{TotalBytes: 10 << 30, AvailableBytes: MinimumOperatingReserve},
	}}
	var target bytes.Buffer
	writer := CheckedWriter{Context: context.Background(), Destination: &target, Capacity: provider}
	count, err := writer.Write(make([]byte, 2*MaximumWriteBoundary))
	if count != MaximumWriteBoundary || target.Len() != count || !errors.Is(err, ErrPressure) || provider.calls != 2 {
		t.Fatalf("write=%d stored=%d probes=%d err=%v", count, target.Len(), provider.calls, err)
	}
	// Resuming after capacity recovery needs no new writer or reservation.
	provider.snapshots = []Snapshot{{TotalBytes: 10 << 30, AvailableBytes: 4 << 30}}
	count, err = writer.Write(make([]byte, MaximumWriteBoundary))
	if err != nil || count != MaximumWriteBoundary || target.Len() != 2*MaximumWriteBoundary {
		t.Fatal(count, err)
	}
}

func TestWriteFailsClosedOnUnknownCapacityAndCancellation(t *testing.T) {
	for _, provider := range []Provider{nil, &sequenceCapacity{err: ErrUnavailable}, &sequenceCapacity{snapshots: []Snapshot{{}}}} {
		var target bytes.Buffer
		count, err := (CheckedWriter{context.Background(), &target, provider}).Write([]byte("data"))
		if count != 0 || target.Len() != 0 || !errors.Is(err, ErrUnavailable) {
			t.Fatal(count, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	provider := &sequenceCapacity{}
	count, err := (CheckedWriter{ctx, io.Discard, provider}).Write([]byte("data"))
	if count != 0 || provider.calls != 0 || !errors.Is(err, context.Canceled) {
		t.Fatal(count, err)
	}
}

type shortWriter struct{}

func (shortWriter) Write(data []byte) (int, error) { return len(data) - 1, nil }

func TestWritePreservesShortWriteFailure(t *testing.T) {
	provider := &sequenceCapacity{snapshots: []Snapshot{{TotalBytes: 10 << 30, AvailableBytes: 4 << 30}}}
	count, err := (CheckedWriter{context.Background(), shortWriter{}, provider}).Write([]byte("data"))
	if count != 3 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(count, err)
	}
}
