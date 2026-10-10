package testfixture_test

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/robreuss/FacetsNode/internal/carriage"
)

//go:embed job-capsule-opaque-carriage-portable-v1.json
var jobCapsuleOpaqueCarriageFixture []byte

type portableJobCapsuleOpaqueCarriageVector struct {
	InputByteCount             int    `json:"inputByteCount"`
	InputCarriageSectionKinds  []int  `json:"inputCarriageSectionKinds"`
	InputSHA256                string `json:"inputSHA256"`
	ProtectedInputBase64URL    string `json:"protectedInputBase64URL"`
	ProtectedResultBase64URL   string `json:"protectedResultBase64URL"`
	ProtocolVersion            int    `json:"protocolVersion"`
	ResultByteCount            int    `json:"resultByteCount"`
	ResultCarriageSectionKinds []int  `json:"resultCarriageSectionKinds"`
	ResultSHA256               string `json:"resultSHA256"`
	SyntheticTestOnly          bool   `json:"syntheticTestOnly"`
}

func TestJobCapsuleOpaqueCarriagePortableKnownAnswer(t *testing.T) {
	vector := loadJobCapsuleOpaqueCarriageVector(t)
	if vector.ProtocolVersion != 1 || !vector.SyntheticTestOnly {
		t.Fatalf("unexpected opaque Job Capsule profile: %+v", vector)
	}
	input := decodeOpaqueCarriageBase64URL(t, vector.ProtectedInputBase64URL)
	result := decodeOpaqueCarriageBase64URL(t, vector.ProtectedResultBase64URL)
	assertOpaqueCarriageObject(
		t,
		input,
		vector.InputByteCount,
		vector.InputSHA256,
		vector.InputCarriageSectionKinds,
	)
	assertOpaqueCarriageObject(
		t,
		result,
		vector.ResultByteCount,
		vector.ResultSHA256,
		vector.ResultCarriageSectionKinds,
	)

	for _, forbidden := range []string{
		"PROMPT-SENTINEL-2d9033d7 classify confidential project language",
		"model-secret-clef-job-capsule-sentinel",
		"/SecretSpace/private/message-export.json",
		"41414141-4141-4141-8141-414141414141",
		"42424242-4242-4242-8242-424242424242",
		"RESULT-SENTINEL-validated-memberships",
	} {
		if bytes.Contains(input, []byte(forbidden)) || bytes.Contains(result, []byte(forbidden)) {
			t.Fatalf("opaque Job Capsule exposed semantic fixture value %q", forbidden)
		}
	}
}

func TestJobCapsuleOpaqueCarriageRejectsTruncationReorderAndDuplication(t *testing.T) {
	vector := loadJobCapsuleOpaqueCarriageVector(t)
	input := decodeOpaqueCarriageBase64URL(t, vector.ProtectedInputBase64URL)
	_, rawFrames, err := decodeOpaqueCarriageSequence(input)
	if err != nil || len(rawFrames) != 2 {
		t.Fatalf("fixture sequence: frames=%d err=%v", len(rawFrames), err)
	}
	if _, _, err := decodeOpaqueCarriageSequence(input[:len(input)-1]); err == nil {
		t.Fatal("truncated opaque carriage sequence decoded")
	}
	reordered := append(append([]byte(nil), rawFrames[1]...), rawFrames[0]...)
	if profileMatchesOpaqueCarriage(reordered, vector.InputCarriageSectionKinds) {
		t.Fatal("reordered opaque carriage sequence matched the profile")
	}
	duplicated := append(append([]byte(nil), input...), input...)
	if profileMatchesOpaqueCarriage(duplicated, vector.InputCarriageSectionKinds) {
		t.Fatal("duplicated opaque carriage sequence matched the profile")
	}
}

func loadJobCapsuleOpaqueCarriageVector(t *testing.T) portableJobCapsuleOpaqueCarriageVector {
	t.Helper()
	var vector portableJobCapsuleOpaqueCarriageVector
	decodeStrict(t, jobCapsuleOpaqueCarriageFixture, &vector)
	return vector
}

func assertOpaqueCarriageObject(
	t *testing.T,
	wire []byte,
	expectedByteCount int,
	expectedSHA256 string,
	expectedKinds []int,
) {
	t.Helper()
	if len(wire) != expectedByteCount {
		t.Fatalf("opaque byte count=%d want=%d", len(wire), expectedByteCount)
	}
	digest := sha256.Sum256(wire)
	if hex.EncodeToString(digest[:]) != expectedSHA256 {
		t.Fatalf("opaque digest=%x want=%s", digest, expectedSHA256)
	}
	if !profileMatchesOpaqueCarriage(wire, expectedKinds) {
		t.Fatalf("opaque carriage profile mismatch: want=%v", expectedKinds)
	}
}

func profileMatchesOpaqueCarriage(wire []byte, expectedKinds []int) bool {
	frames, _, err := decodeOpaqueCarriageSequence(wire)
	if err != nil || len(frames) != len(expectedKinds) {
		return false
	}
	for index, frame := range frames {
		if int(frame.SectionKind) != expectedKinds[index] {
			return false
		}
	}
	return true
}

func decodeOpaqueCarriageSequence(wire []byte) ([]carriage.Frame, [][]byte, error) {
	var frames []carriage.Frame
	var rawFrames [][]byte
	for len(wire) > 0 {
		if len(wire) < carriage.FixedHeaderBytes {
			return nil, nil, errors.New("truncated carriage header")
		}
		headerCount := uint64(binary.BigEndian.Uint32(wire[8:12]))
		payloadCount := binary.BigEndian.Uint64(wire[12:20])
		if headerCount > carriage.MaximumHeaderBytes || payloadCount > carriage.MaximumPayloadBytes {
			return nil, nil, errors.New("oversized carriage frame")
		}
		frameCount := uint64(carriage.FixedHeaderBytes) + headerCount + payloadCount
		if frameCount > uint64(len(wire)) || frameCount > uint64(^uint(0)>>1) {
			return nil, nil, errors.New("invalid carriage frame length")
		}
		raw := append([]byte(nil), wire[:int(frameCount)]...)
		frame, err := carriage.DecodeFrame(raw)
		if err != nil {
			return nil, nil, err
		}
		frames = append(frames, frame)
		rawFrames = append(rawFrames, raw)
		wire = wire[int(frameCount):]
	}
	if len(frames) == 0 {
		return nil, nil, errors.New("empty carriage sequence")
	}
	return frames, rawFrames, nil
}

func decodeOpaqueCarriageBase64URL(t *testing.T, encoded string) []byte {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		t.Fatalf("noncanonical opaque carriage base64url: %v", err)
	}
	return decoded
}
