// Package storagecapacity defines the private physical-capacity boundary used
// by storage admission. It does not assign per-Space quotas or infer capacity
// from finalized blob metadata. Reservation ownership lives in the durable
// service store and must be serialized across every instance sharing a pool.
package storagecapacity

import (
	"context"
	"errors"
	"math"
)

var (
	ErrUnavailable = errors.New("storage capacity is unavailable")
	ErrPressure    = errors.New("storage operating reserve would be exceeded")
)

type Snapshot struct {
	TotalBytes     int64
	AvailableBytes int64
}

type Provider interface {
	Snapshot(context.Context) (Snapshot, error)
}

const (
	MinimumOperatingReserve = int64(2 << 30)
	// Conservative allowances for upload/session/finalization rows and their
	// indexes/WAL. Per-chunk growth is charged as chunks are admitted, not just
	// as finalized bytes. Publication temporarily holds a second full copy.
	UploadMetadataAllowance   = int64(64 << 10)
	ChunkMetadataAllowance    = int64(8 << 10)
	MutationMetadataAllowance = int64(16 << 10)
)

func (s Snapshot) OperatingReserve() (int64, error) {
	if s.TotalBytes <= 0 || s.AvailableBytes < 0 || s.AvailableBytes > s.TotalBytes {
		return 0, ErrUnavailable
	}
	reserve := s.TotalBytes / 10
	if s.TotalBytes%10 != 0 {
		reserve++
	}
	return max(MinimumOperatingReserve, reserve), nil
}

// Check must run while the durable pool's admission lock is held. Outstanding
// is promised but not yet physically consumed storage, including publication
// copies and metadata growth. Physical free bytes already exclude staged data.
func Check(s Snapshot, outstanding, additional int64) error {
	reserve, err := s.OperatingReserve()
	if err != nil || outstanding < 0 || additional < 0 {
		return ErrUnavailable
	}
	if s.AvailableBytes < reserve || outstanding > s.AvailableBytes-reserve ||
		additional > s.AvailableBytes-reserve-outstanding {
		return ErrPressure
	}
	return nil
}

// UploadReservation accounts for the remaining staging bytes, a full temporary
// publication copy, and conservative metadata headroom. Committed staging is
// subtracted exactly once because the physical probe already sees it. Rows
// retain this reservation across crashes; finalization/expiry release it in
// the same transaction as their durable state change.
func UploadReservation(byteCount, committedOffset, chunkCount int64) (int64, error) {
	if byteCount < 0 || committedOffset < 0 || committedOffset > byteCount || chunkCount < 0 ||
		byteCount > (math.MaxInt64-UploadMetadataAllowance)/2 {
		return 0, ErrUnavailable
	}
	base := 2*byteCount - committedOffset + UploadMetadataAllowance
	if chunkCount > (math.MaxInt64-base)/ChunkMetadataAllowance {
		return 0, ErrUnavailable
	}
	return base + chunkCount*ChunkMetadataAllowance, nil
}
