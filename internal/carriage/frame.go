package carriage

import "encoding/binary"

// Frame v1 is FCAR, version, section kind, zero flags, big-endian header and
// payload lengths, then opaque bytes. Authentication belongs to the service
// profile; this package does not interpret or decrypt either section.
const (
	FixedHeaderBytes    = 20
	MaximumHeaderBytes  = 16 * 1024
	MaximumPayloadBytes = 8 * 1024 * 1024
)

type Frame struct {
	SectionKind byte
	Header      []byte
	Payload     []byte
}

func (f Frame) Encode() ([]byte, error) {
	if f.SectionKind == 0 {
		return nil, Failure{Code: InvalidFrame, Phase: FramePhase}
	}
	if len(f.Header) > MaximumHeaderBytes || len(f.Payload) > MaximumPayloadBytes {
		return nil, Failure{Code: Capacity, Phase: FramePhase}
	}
	wire := make([]byte, FixedHeaderBytes+len(f.Header)+len(f.Payload))
	copy(wire[:4], "FCAR")
	wire[4], wire[5] = 1, f.SectionKind
	binary.BigEndian.PutUint32(wire[8:12], uint32(len(f.Header)))
	binary.BigEndian.PutUint64(wire[12:20], uint64(len(f.Payload)))
	copy(wire[20:], f.Header)
	copy(wire[20+len(f.Header):], f.Payload)
	return wire, nil
}

func DecodeFrame(wire []byte) (Frame, error) {
	if len(wire) < FixedHeaderBytes || string(wire[:4]) != "FCAR" ||
		wire[4] != 1 || wire[5] == 0 || wire[6] != 0 || wire[7] != 0 {
		return Frame{}, Failure{Code: InvalidFrame, Phase: FramePhase}
	}
	headerCount := binary.BigEndian.Uint32(wire[8:12])
	payloadCount := binary.BigEndian.Uint64(wire[12:20])
	if headerCount > MaximumHeaderBytes || payloadCount > MaximumPayloadBytes {
		return Frame{}, Failure{Code: Capacity, Phase: FramePhase}
	}
	expected := FixedHeaderBytes + int(headerCount) + int(payloadCount)
	if len(wire) != expected {
		return Frame{}, Failure{Code: InvalidFrame, Phase: FramePhase}
	}
	header := append([]byte(nil), wire[20:20+int(headerCount)]...)
	payload := append([]byte(nil), wire[20+int(headerCount):]...)
	return Frame{SectionKind: wire[5], Header: header, Payload: payload}, nil
}
