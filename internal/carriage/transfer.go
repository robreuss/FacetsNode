package carriage

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type Code string
type Phase string

const (
	InvalidDescriptor    Code = "CAR-DESCRIPTOR"
	InvalidFrame         Code = "CAR-FRAME"
	Capacity             Code = "CAR-CAPACITY"
	InvalidProgress      Code = "CAR-PROGRESS"
	SourceChanged        Code = "CAR-SOURCE"
	TransportInterrupted Code = "CAR-IO"

	DescriptorPhase Phase = "descriptor"
	FramePhase      Phase = "frame"
	SourceReadPhase Phase = "sourceRead"
	ProgressPhase   Phase = "confirmedProgress"
	AppendPhase     Phase = "append"
	CommitPhase     Phase = "commit"
)

// Failure contains only a stable code and phase, never transferred content.
type Failure struct {
	Code  Code
	Phase Phase
	Cause error
}

func (f Failure) Error() string { return fmt.Sprintf("%s at %s", f.Code, f.Phase) }
func (f Failure) Unwrap() error { return f.Cause }

func (f Failure) RecoveryGuidance() string {
	switch f.Code {
	case InvalidDescriptor, InvalidFrame:
		return "Retry with a supported, intact transfer object."
	case Capacity:
		return "Reduce the transfer section size or use bounded chunks."
	case InvalidProgress:
		return "Reconcile the receiver's confirmed offset before retrying."
	case TransportInterrupted:
		return "Retry using the same transfer identity; progress resumes from the receiver's confirmed offset."
	default:
		return "Recreate the transfer from an unchanged immutable source."
	}
}

// ObjectDescriptor describes already-protected bytes, not semantic identity,
// authorization, encryption, or a durable application receipt.
type ObjectDescriptor struct {
	ByteCount uint64
	SHA256    [32]byte
}

func Describe(data []byte) ObjectDescriptor {
	return ObjectDescriptor{ByteCount: uint64(len(data)), SHA256: sha256.Sum256(data)}
}

// Source may return a short positive read. A zero read before ByteCount is an
// error. Adapter implementations must hold the descriptor's source immutable.
type Source interface {
	Descriptor() ObjectDescriptor
	ReadAt(ctx context.Context, offset uint64, maximumBytes int) ([]byte, error)
}

// BytesSource owns a private immutable copy for fixtures and small objects.
// File and network adapters can implement Source with bounded storage.
type BytesSource struct {
	bytes      []byte
	descriptor ObjectDescriptor
}

func NewBytesSource(data []byte) BytesSource {
	owned := append([]byte(nil), data...)
	return BytesSource{bytes: owned, descriptor: Describe(owned)}
}

func (s BytesSource) Descriptor() ObjectDescriptor { return s.descriptor }

func (s BytesSource) ReadAt(ctx context.Context, offset uint64,
	maximumBytes int) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if maximumBytes < 1 || offset > uint64(len(s.bytes)) {
		return nil, Failure{Code: SourceChanged, Phase: SourceReadPhase}
	}
	start := int(offset)
	count := maximumBytes
	if remaining := len(s.bytes) - start; count > remaining {
		count = remaining
	}
	end := start + count
	return append([]byte(nil), s.bytes[start:end]...), nil
}

// Sink reports only durable contiguous offsets scoped to the same retry ID
// and descriptor. Commit verifies the whole digest. Abort is explicit: an
// interrupted transfer must remain resumable unless service policy says stop.
type Sink interface {
	ConfirmedOffset(ctx context.Context, transferID uuid.UUID, object ObjectDescriptor) (uint64, error)
	Append(ctx context.Context, transferID uuid.UUID, object ObjectDescriptor,
		offset uint64, data []byte, chunkSHA256 [32]byte) (uint64, error)
	Commit(ctx context.Context, transferID uuid.UUID, object ObjectDescriptor) error
	Abort(ctx context.Context, transferID uuid.UUID) error
}

type TracePhase string

const (
	TraceConfirmed TracePhase = "confirmedProgress"
	TraceRead      TracePhase = "sourceRead"
	TraceAppend    TracePhase = "append"
	TraceReconcile TracePhase = "reconcile"
	TraceCommit    TracePhase = "commit"
)

type Event struct {
	Phase     TracePhase
	Elapsed   time.Duration
	ByteCount int
}

type Driver struct {
	ChunkBytes int
	Trace      func(Event)
}

func NewDriver(chunkBytes int, trace func(Event)) (Driver, error) {
	if chunkBytes < 1 || chunkBytes > MaximumPayloadBytes {
		return Driver{}, Failure{Code: Capacity, Phase: SourceReadPhase}
	}
	return Driver{ChunkBytes: chunkBytes, Trace: trace}, nil
}

// Transfer allows one in-flight chunk. Only receiver-confirmed progress can
// advance its offset; a lost append response is reconciled through status.
func (d Driver) Transfer(ctx context.Context, source Source, sink Sink,
	transferID uuid.UUID) (uint64, error) {
	if d.ChunkBytes < 1 || d.ChunkBytes > MaximumPayloadBytes || transferID == uuid.Nil {
		return 0, Failure{Code: InvalidDescriptor, Phase: DescriptorPhase}
	}
	object := source.Descriptor()
	started := time.Now()
	offset, err := sink.ConfirmedOffset(ctx, transferID, object)
	d.record(TraceConfirmed, started, 0)
	if err != nil {
		return 0, present(err, ProgressPhase)
	}
	if offset > object.ByteCount {
		return 0, Failure{Code: InvalidProgress, Phase: ProgressPhase}
	}
	for offset < object.ByteCount {
		if err := ctx.Err(); err != nil {
			return offset, err
		}
		requested := uint64(d.ChunkBytes)
		if remaining := object.ByteCount - offset; remaining < requested {
			requested = remaining
		}
		started = time.Now()
		chunk, err := source.ReadAt(ctx, offset, int(requested))
		d.record(TraceRead, started, len(chunk))
		if err != nil {
			return offset, present(err, SourceReadPhase)
		}
		if len(chunk) == 0 || uint64(len(chunk)) > requested {
			return offset, Failure{Code: SourceChanged, Phase: SourceReadPhase}
		}
		if err := ctx.Err(); err != nil {
			return offset, err
		}
		end := offset + uint64(len(chunk))
		started = time.Now()
		confirmed, appendErr := sink.Append(ctx, transferID, object, offset,
			chunk, sha256.Sum256(chunk))
		if appendErr != nil {
			if err := ctx.Err(); err != nil {
				return offset, err
			}
			reconcileStarted := time.Now()
			confirmed, err = sink.ConfirmedOffset(ctx, transferID, object)
			d.record(TraceReconcile, reconcileStarted, 0)
			if err != nil {
				return offset, present(err, ProgressPhase)
			}
			if confirmed > object.ByteCount {
				return offset, Failure{Code: InvalidProgress, Phase: ProgressPhase}
			}
			if confirmed < end {
				return offset, present(appendErr, AppendPhase)
			}
		}
		d.record(TraceAppend, started, len(chunk))
		if confirmed < end || confirmed > object.ByteCount {
			return offset, Failure{Code: InvalidProgress, Phase: AppendPhase}
		}
		offset = confirmed
	}
	if err := ctx.Err(); err != nil {
		return offset, err
	}
	started = time.Now()
	err = sink.Commit(ctx, transferID, object)
	d.record(TraceCommit, started, 0)
	if err != nil {
		return offset, present(err, CommitPhase)
	}
	return offset, nil
}

func (d Driver) record(phase TracePhase, started time.Time, bytes int) {
	if d.Trace != nil {
		d.Trace(Event{Phase: phase, Elapsed: time.Since(started), ByteCount: bytes})
	}
}

// IsFailure avoids exposing an adapter's underlying error or content.
func IsFailure(err error, code Code) bool {
	var failure Failure
	return errors.As(err, &failure) && failure.Code == code
}

func present(err error, phase Phase) error {
	var failure Failure
	if errors.As(err, &failure) || errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return Failure{Code: TransportInterrupted, Phase: phase, Cause: err}
}
