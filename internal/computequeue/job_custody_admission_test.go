package computequeue

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	jobCustodyFixtureProtectedDigest = "cede6fcef87bd4e9acc3b8b9507763af537e8e8b4c57c29aaf4d94326f5dfc8a"
	jobCustodyFixtureIdempotencyKey  = "0ed0b476cd8c857cdd3e526bff0a370bf0daa859481f30bb026c017d51e626a4"
	jobCustodyFixtureHeaderDigest    = "d12fb9f23048a86c7b727c9266a1d4e8ed28c5a430392050648cc7a0439e80b7"
	jobCustodyFixtureCanonicalDigest = "94de854c77adefd8ac4bbd4003cc4d2b6c5e371d4879408889475e7a61c171fa"
	jobCustodyFixturePayloadDigest   = "897f8c9a4d1c3773f42a48855945a839e2cb48334ef91b1e084ad4980c52bb0b"
)

type expectedJobCustodyVerifier struct {
	want Digest
}

func (verifier expectedJobCustodyVerifier) VerifySignature(
	_ SignatureValue,
	payloadDigest Digest,
	_ ReceiptSignerBinding,
) error {
	if payloadDigest != verifier.want {
		return errors.New("unexpected admission payload digest")
	}
	return nil
}

type rejectingJobCustodyVerifier struct{}

func (rejectingJobCustodyVerifier) VerifySignature(
	SignatureValue,
	Digest,
	ReceiptSignerBinding,
) error {
	return errors.New("signature rejected")
}

func TestJobCustodyAdmissionPortableFixture(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "job-custody-admission-portable-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 2 || data[len(data)-1] != '\n' || data[len(data)-2] == '\n' {
		t.Fatal("fixture must have exactly one trailing LF")
	}
	canonical := data[:len(data)-1]
	envelope, err := DecodeJobCustodyAdmissionCanonical(canonical)
	if err != nil {
		t.Fatal(err)
	}
	reencoded, err := EncodeJobCustodyAdmissionCanonical(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reencoded, canonical) {
		t.Fatal("Go round trip changed the portable admission fixture")
	}

	if got := envelope.Header.ProtectedObject.Digest(); got != jobCustodyFixtureProtectedDigest {
		t.Fatalf("protected-object digest = %s", got)
	}
	if got := envelope.Header.IdempotencyKey; got != jobCustodyFixtureIdempotencyKey {
		t.Fatalf("idempotency key = %s", got)
	}
	if got := envelope.Header.Digest(); got != jobCustodyFixtureHeaderDigest {
		t.Fatalf("header digest = %s", got)
	}
	if got := envelope.CanonicalHeaderDigest; got != jobCustodyFixtureCanonicalDigest {
		t.Fatalf("canonical header digest = %s", got)
	}

	signer := fixtureJobCustodySigner()
	payload, err := envelope.SignaturePayloadDigest(signer)
	if err != nil {
		t.Fatal(err)
	}
	if payload != jobCustodyFixturePayloadDigest {
		t.Fatalf("signature payload digest = %s", payload)
	}
	expectation, err := NewJobCustodyAdmissionExpectation(envelope.Header, 1_800_000_000_001)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := acceptVerifiedJobCustodyAdmission(
		envelope,
		expectation,
		signer,
		expectedJobCustodyVerifier{want: payload},
	)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Header() != envelope.Header || verified.ExpectedSigner() != signer {
		t.Fatal("verified admission did not retain the authenticated snapshot")
	}
}

func TestJobCustodyAdmissionRejectsTamperingAndSubstitution(t *testing.T) {
	envelope := fixtureJobCustodyEnvelope(t)
	signer := fixtureJobCustodySigner()
	expectation, err := NewJobCustodyAdmissionExpectation(envelope.Header, envelope.Header.NotBeforeAt)
	if err != nil {
		t.Fatal(err)
	}

	tampered := envelope
	tampered.Header.RetentionUntil++
	if _, err := EncodeJobCustodyAdmissionCanonical(tampered); err == nil {
		t.Fatal("accepted a header mutation with stale admission digests")
	}

	wrongHeader := envelope.Header
	wrongHeader.RouteRecipientWorkerID = "44444444-4444-4444-8444-444444444444"
	wrongHeader.IdempotencyKey = wrongHeader.MakeIdempotencyKey()
	wrongExpectation, err := NewJobCustodyAdmissionExpectation(wrongHeader, wrongHeader.NotBeforeAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acceptVerifiedJobCustodyAdmission(
		envelope,
		wrongExpectation,
		signer,
		expectedJobCustodyVerifier{want: jobCustodyFixturePayloadDigest},
	); err == nil {
		t.Fatal("accepted a valid envelope for a substituted route")
	}

	wrongSigner := signer
	wrongSigner.SigningKeyRevision++
	if _, err := acceptVerifiedJobCustodyAdmission(
		envelope,
		expectation,
		wrongSigner,
		expectedJobCustodyVerifier{want: jobCustodyFixturePayloadDigest},
	); err == nil {
		t.Fatal("accepted signer substitution")
	}
	if _, err := acceptVerifiedJobCustodyAdmission(
		envelope,
		expectation,
		signer,
		rejectingJobCustodyVerifier{},
	); err == nil {
		t.Fatal("accepted a rejected signature")
	}
	if _, err := acceptVerifiedJobCustodyAdmission(envelope, expectation, signer, nil); err == nil {
		t.Fatal("accepted admission without a verifier")
	}
}

func TestJobCustodyAdmissionTimingAndGeometryFailClosed(t *testing.T) {
	envelope := fixtureJobCustodyEnvelope(t)
	for name, acceptedAt := range map[string]Timestamp{
		"before":  envelope.Header.NotBeforeAt - 1,
		"expires": envelope.Header.ExpiresAt,
		"after":   envelope.Header.ExpiresAt + 1,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewJobCustodyAdmissionExpectation(envelope.Header, acceptedAt); err == nil {
				t.Fatal("accepted admission outside its half-open validity window")
			}
		})
	}
	if _, err := NewJobCustodyAdmissionExpectation(envelope.Header, envelope.Header.ExpiresAt-1); err != nil {
		t.Fatalf("rejected final valid millisecond: %v", err)
	}

	descriptor := envelope.Header.ProtectedObject
	descriptor.ChunkCount++
	if err := descriptor.Validate(); err == nil {
		t.Fatal("accepted inconsistent chunk geometry")
	}
	descriptor = envelope.Header.ProtectedObject
	descriptor.ChunkByteCount = MaximumJobCustodyChunkBytes + 1
	if err := descriptor.Validate(); err == nil {
		t.Fatal("accepted an oversized chunk")
	}
}

func TestJobCustodyAdmissionCanonicalDecoderIsBoundedAndExact(t *testing.T) {
	canonical, err := EncodeJobCustodyAdmissionCanonical(fixtureJobCustodyEnvelope(t))
	if err != nil {
		t.Fatal(err)
	}
	noncanonical := append([]byte(" \n"), canonical...)
	if _, err := DecodeJobCustodyAdmissionCanonical(noncanonical); !errors.Is(err, ErrNonCanonical) {
		t.Fatalf("noncanonical admission error = %v", err)
	}
	withUnknown := bytes.Replace(
		canonical,
		[]byte(`{"canonicalHeaderDigest"`),
		[]byte(`{"additionalMetadata":"must-not-cross-custody","canonicalHeaderDigest"`),
		1,
	)
	if _, err := DecodeJobCustodyAdmissionCanonical(withUnknown); !errors.Is(err, ErrNonCanonical) {
		t.Fatalf("unknown-field admission error = %v", err)
	}
	oversized := []byte(`{"padding":"` + strings.Repeat("a", maximumCustodyDocumentBytes) + `"}`)
	if _, err := DecodeJobCustodyAdmissionCanonical(oversized); err == nil {
		t.Fatal("accepted an oversized custody document")
	}
}

func fixtureJobCustodyEnvelope(t *testing.T) JobCustodySignedAdmissionEnvelope {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "job-custody-admission-portable-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := DecodeJobCustodyAdmissionCanonical(data[:len(data)-1])
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func fixtureJobCustodySigner() ReceiptSignerBinding {
	return ReceiptSignerBinding{
		SignerID:           "source.device.fixture",
		SigningKeyID:       "source.key.fixture",
		SigningKeyRevision: 7,
		SignatureProfileID: "p256-sha256-raw-v1",
	}
}
