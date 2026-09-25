package carriage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestPublishedFrameVector(t *testing.T) {
	frame := Frame{SectionKind: 1, Header: []byte{1, 2, 3}, Payload: []byte{0, 1, 2, 255}}
	wire, err := frame.Encode()
	if err != nil {
		t.Fatal(err)
	}
	const expected = "4643415201010000000000030000000000000004010203000102ff"
	if hex.EncodeToString(wire) != expected {
		t.Fatalf("frame mismatch: %x", wire)
	}
	decoded, err := DecodeFrame(wire)
	if err != nil || decoded.SectionKind != frame.SectionKind ||
		!bytes.Equal(decoded.Header, frame.Header) || !bytes.Equal(decoded.Payload, frame.Payload) {
		t.Fatalf("frame round trip: %+v %v", decoded, err)
	}
	badFlags := bytes.Clone(wire)
	badFlags[7] = 1
	badLength := bytes.Clone(wire)
	badLength[19] = 255
	excessiveHeader := bytes.Clone(wire)
	excessiveHeader[10], excessiveHeader[11] = 0x40, 0x01
	if _, err := DecodeFrame(excessiveHeader); !IsFailure(err, Capacity) {
		t.Fatalf("oversized frame header did not report capacity: %v", err)
	}
	for _, invalid := range [][]byte{badFlags, badLength, append(bytes.Clone(wire), 0), wire[:len(wire)-1]} {
		if _, err := DecodeFrame(invalid); err == nil {
			t.Fatalf("malformed frame accepted: %x", invalid)
		}
	}
}

func TestResponseLossAndInterruptionResume(t *testing.T) {
	data := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	source := NewBytesSource(data)
	var events []Event
	driver, err := NewDriver(4, func(event Event) { events = append(events, event) })
	if err != nil {
		t.Fatal(err)
	}
	t.Run("lost acknowledgment", func(t *testing.T) {
		sink := &fixtureSink{lostAck: true}
		transferred, err := driver.Transfer(context.Background(), source, sink, uuid.New())
		if err != nil || transferred != uint64(len(data)) ||
			!sink.committed || !bytes.Equal(sink.data, data) {
			t.Fatalf("lost response did not reconcile: offset=%d error=%v", transferred, err)
		}
		if len(sink.offsets) != 3 || sink.offsets[0] != 0 ||
			sink.offsets[1] != 4 || sink.offsets[2] != 8 {
			t.Fatalf("unexpected append offsets: %v", sink.offsets)
		}
		var sawReconcile, sawCommit bool
		var readBytes int
		for _, event := range events {
			sawReconcile = sawReconcile || event.Phase == TraceReconcile
			sawCommit = sawCommit || event.Phase == TraceCommit
			if event.Phase == TraceRead {
				readBytes += event.ByteCount
			}
		}
		if !sawReconcile || !sawCommit || readBytes != len(data) {
			t.Fatalf("missing payload-free phase trace: %+v", events)
		}
	})
	t.Run("interrupted then resumed", func(t *testing.T) {
		sink := &fixtureSink{interruptAt: 4}
		transferID := uuid.New()
		if _, err := driver.Transfer(context.Background(), source, sink, transferID); !errors.Is(err, errInterrupted) || !IsFailure(err, TransportInterrupted) {
			t.Fatalf("expected interruption, got %v", err)
		}
		if !bytes.Equal(sink.data, data[:4]) || sink.committed {
			t.Fatal("interrupted transfer changed custody incorrectly")
		}
		transferred, err := driver.Transfer(context.Background(), source, sink, transferID)
		if err != nil || transferred != uint64(len(data)) ||
			!sink.committed || !bytes.Equal(sink.data, data) {
			t.Fatalf("resume failed: offset=%d error=%v", transferred, err)
		}
	})
}

func TestChangedSourceCannotCommit(t *testing.T) {
	data := []byte{1, 2, 3}
	source := fixtureSource{data: data, descriptor: Describe(data), changed: true}
	sink := &fixtureSink{}
	driver, err := NewDriver(2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := driver.Transfer(context.Background(), source, sink, uuid.New()); !IsFailure(err, SourceChanged) || sink.committed {
		t.Fatalf("changed source committed: %v", err)
	}
}

func TestLostCommitResponseRetriesWithoutAppendingAgain(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5}
	source := NewBytesSource(data)
	sink := &fixtureSink{lostCommitAck: true}
	driver, err := NewDriver(2, nil)
	if err != nil {
		t.Fatal(err)
	}
	transferID := uuid.New()
	if _, err := driver.Transfer(context.Background(), source, sink, transferID); !IsFailure(err, TransportInterrupted) {
		t.Fatalf("expected lost commit response, got %v", err)
	}
	if !sink.committed || !bytes.Equal(sink.data, data) || len(sink.offsets) != 3 {
		t.Fatalf("commit custody was not retained: %+v", sink)
	}
	transferred, err := driver.Transfer(context.Background(), source, sink, transferID)
	if err != nil || transferred != uint64(len(data)) || len(sink.offsets) != 3 {
		t.Fatalf("idempotent commit retry failed: offset=%d error=%v offsets=%v", transferred, err, sink.offsets)
	}
}

func TestCancellationAndEmptyObject(t *testing.T) {
	driver, err := NewDriver(2, nil)
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	sink := &fixtureSink{}
	if _, err := driver.Transfer(cancelled, NewBytesSource([]byte{1, 2, 3}),
		sink, uuid.New()); !errors.Is(err, context.Canceled) || sink.committed || len(sink.data) != 0 {
		t.Fatalf("cancellation incorrectly committed: %v", err)
	}
	emptySink := &fixtureSink{}
	transferred, err := driver.Transfer(context.Background(), NewBytesSource(nil), emptySink, uuid.New())
	if err != nil || transferred != 0 || !emptySink.committed {
		t.Fatalf("empty object did not commit: offset=%d error=%v", transferred, err)
	}
}

var errInterrupted = errors.New("fixture interruption")

type fixtureSource struct {
	data       []byte
	descriptor ObjectDescriptor
	changed    bool
}

func (s fixtureSource) Descriptor() ObjectDescriptor { return s.descriptor }

func (s fixtureSource) ReadAt(_ context.Context, offset uint64, maximumBytes int) ([]byte, error) {
	end := int(offset) + maximumBytes
	if end > len(s.data) {
		end = len(s.data)
	}
	chunk := bytes.Clone(s.data[int(offset):end])
	if s.changed {
		for i := range chunk {
			chunk[i] = 9
		}
	}
	return chunk, nil
}

type fixtureSink struct {
	transferID    uuid.UUID
	descriptor    ObjectDescriptor
	data          []byte
	offsets       []uint64
	committed     bool
	lostAck       bool
	lostCommitAck bool
	interruptAt   uint64
	interrupted   bool
}

func (s *fixtureSink) bind(id uuid.UUID, object ObjectDescriptor) error {
	if s.transferID != uuid.Nil && (s.transferID != id || s.descriptor != object) {
		return Failure{Code: InvalidDescriptor, Phase: DescriptorPhase}
	}
	s.transferID, s.descriptor = id, object
	return nil
}

func (s *fixtureSink) ConfirmedOffset(_ context.Context, id uuid.UUID,
	object ObjectDescriptor) (uint64, error) {
	if err := s.bind(id, object); err != nil {
		return 0, err
	}
	return uint64(len(s.data)), nil
}

func (s *fixtureSink) Append(_ context.Context, id uuid.UUID,
	object ObjectDescriptor, offset uint64, chunk []byte,
	chunkDigest [32]byte) (uint64, error) {
	if err := s.bind(id, object); err != nil {
		return 0, err
	}
	if offset != uint64(len(s.data)) || sha256.Sum256(chunk) != chunkDigest {
		return 0, Failure{Code: InvalidProgress, Phase: AppendPhase}
	}
	if s.interruptAt != 0 && !s.interrupted && offset == s.interruptAt {
		s.interrupted = true
		return 0, errInterrupted
	}
	s.offsets = append(s.offsets, offset)
	s.data = append(s.data, chunk...)
	if s.lostAck {
		s.lostAck = false
		return 0, errInterrupted
	}
	return uint64(len(s.data)), nil
}

func (s *fixtureSink) Commit(_ context.Context, id uuid.UUID,
	object ObjectDescriptor) error {
	if err := s.bind(id, object); err != nil {
		return err
	}
	if uint64(len(s.data)) != object.ByteCount || sha256.Sum256(s.data) != object.SHA256 {
		return Failure{Code: SourceChanged, Phase: CommitPhase}
	}
	s.committed = true
	if s.lostCommitAck {
		s.lostCommitAck = false
		return errInterrupted
	}
	return nil
}

func (s *fixtureSink) Abort(_ context.Context, id uuid.UUID) error {
	if s.transferID != id {
		return Failure{Code: InvalidDescriptor, Phase: DescriptorPhase}
	}
	s.data, s.committed = nil, false
	return nil
}
