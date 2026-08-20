package protocol

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"testing"

	"github.com/google/uuid"
)

func TestPayloadKindsAreFrozen(t *testing.T) {
	want := []PayloadKind{
		"fef_checkpoint", "fef_mutation_batch", "control_message", "blob_manifest",
		"delivery_receipt", "correction_receipt", "ai_job_request", "ai_job_result",
	}
	if !slices.Equal(PayloadKinds, want) {
		t.Fatalf("payload kinds = %v, want %v", PayloadKinds, want)
	}
}

func TestTransportEnvelopeNormalizesDependenciesAndBlobs(t *testing.T) {
	messageID := uuid.MustParse("10000000-0000-4000-8000-000000000009")
	first := uuid.MustParse("10000000-0000-4000-8000-000000000001")
	second := uuid.MustParse("10000000-0000-4000-8000-000000000002")
	envelope, err := NewTransportEnvelope(
		PayloadFEFMutationBatch,
		messageID,
		1710000000009,
		" application/json ",
		[]byte(`{"ok":true}`),
		[]uuid.UUID{second, first},
		[]BlobReference{
			{BlobID: "z", SHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", ByteCount: 2, ContentType: "application/octet-stream"},
			{BlobID: "a", SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ByteCount: 1, ContentType: "application/octet-stream"},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.PayloadContentType != "application/json" || envelope.DependencyMessageIDs[0] != first || envelope.BlobReferences[0].BlobID != "a" {
		t.Fatalf("envelope was not normalized: %+v", envelope)
	}
	if envelope.PayloadSHA256 != "4062edaf750fb8074e7e83e0c9028c94e32468a8b6f1614774328ef045150f93" {
		t.Fatalf("unexpected digest: %s", envelope.PayloadSHA256)
	}
	if _, err := envelope.CanonicalJSON(); err != nil {
		t.Fatal(err)
	}
}

func TestPortableTransportFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/facets-server-transport-portable-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	if digest := fmt.Sprintf("%x", sha256.Sum256(data)); digest != "1102b3f64c007b9bbf66c9eb74cb87b6b512e84241419df8827f7149b4e3ea26" {
		t.Fatalf("portable fixture digest = %s", digest)
	}
	var fixture struct {
		Format    string              `json:"format"`
		Envelopes []TransportEnvelope `json:"envelopes"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Format != "facets.server-transport-fixture.v1" || len(fixture.Envelopes) != len(PayloadKinds) {
		t.Fatalf("unexpected fixture header: %q %d", fixture.Format, len(fixture.Envelopes))
	}
	for index, envelope := range fixture.Envelopes {
		if envelope.Kind != PayloadKinds[index] {
			t.Fatalf("envelope %d kind = %q, want %q", index, envelope.Kind, PayloadKinds[index])
		}
		if _, err := envelope.PayloadBytes(); err != nil {
			t.Fatalf("envelope %d: %v", index, err)
		}
		encoded, err := envelope.CanonicalJSON()
		if err != nil {
			t.Fatal(err)
		}
		var roundTrip TransportEnvelope
		if err := json.Unmarshal(encoded, &roundTrip); err != nil || roundTrip.MessageID != envelope.MessageID {
			t.Fatalf("envelope %d round trip: %v", index, err)
		}
	}
}

func TestTransportEnvelopeRejectsTampering(t *testing.T) {
	data, err := os.ReadFile("testdata/facets-server-transport-portable-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Envelopes []json.RawMessage `json:"envelopes"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(fixture.Envelopes[0], &object); err != nil {
		t.Fatal(err)
	}
	object["payloadSHA256"] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	tampered, _ := json.Marshal(object)
	var envelope TransportEnvelope
	if err := json.Unmarshal(tampered, &envelope); !errors.Is(err, ErrPayloadDigest) {
		t.Fatalf("tampered envelope error = %v", err)
	}
}

func TestReceiptVocabulary(t *testing.T) {
	messageID := uuid.MustParse("10000000-0000-4000-8000-000000000001")
	delivery, err := NewDeliveryReceipt(messageID, " device-1 ", DeliveryCanonicalApplied, 1710000000010)
	if err != nil || delivery.RecipientID != "device-1" {
		t.Fatalf("delivery receipt: %+v %v", delivery, err)
	}
	correction, err := NewCorrectionReceipt(messageID, "device-1", CorrectionMissingDependency, []string{"object-b", "object-a"}, 1710000000011)
	if err != nil || !slices.Equal(correction.MissingDependencyIDs, []string{"object-a", "object-b"}) {
		t.Fatalf("correction receipt: %+v %v", correction, err)
	}
	if _, err := NewCorrectionReceipt(messageID, "device-1", CorrectionConflict, []string{"object-a"}, 1710000000011); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("unexpected correction validation error: %v", err)
	}
}

func TestPortableCorrectionFixtureOrdersCompleteBundle(t *testing.T) {
	data, err := os.ReadFile("testdata/facets-server-correction-portable-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	if digest := fmt.Sprintf("%x", sha256.Sum256(data)); digest != "9588e7ba7bdd1012ed48578a89f729a540a43241dcdf7e33aa056a5876b13cc9" {
		t.Fatalf("portable correction fixture digest = %s", digest)
	}
	var fixture struct {
		Format                    string              `json:"format"`
		CorrectionReceipt         CorrectionReceipt   `json:"correctionReceipt"`
		CorrectedEnvelopes        []TransportEnvelope `json:"correctedEnvelopes"`
		ExpectedOrderedMessageIDs []uuid.UUID         `json:"expectedOrderedMessageIDs"`
		CanonicalAppliedReceipt   DeliveryReceipt     `json:"canonicalAppliedReceipt"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Format != "facets.server-correction-fixture.v1" {
		t.Fatalf("unexpected fixture format: %q", fixture.Format)
	}
	ordered, err := CorrectedBundle(fixture.CorrectionReceipt, fixture.CorrectedEnvelopes)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]uuid.UUID, len(ordered))
	for index, envelope := range ordered {
		got[index] = envelope.MessageID
	}
	if !slices.Equal(got, fixture.ExpectedOrderedMessageIDs) {
		t.Fatalf("corrected bundle order = %v, want %v", got, fixture.ExpectedOrderedMessageIDs)
	}
	if fixture.CanonicalAppliedReceipt.Stage != DeliveryCanonicalApplied ||
		fixture.CanonicalAppliedReceipt.ReferencedMessageID != fixture.CorrectionReceipt.ReferencedMessageID {
		t.Fatalf("unexpected canonical receipt: %+v", fixture.CanonicalAppliedReceipt)
	}
}

func TestCorrectedBundleRejectsIncompleteAndCyclicBundles(t *testing.T) {
	parentID := uuid.MustParse("10000000-0000-4000-8000-000000000001")
	childID := uuid.MustParse("10000000-0000-4000-8000-000000000002")
	child, err := NewTransportEnvelope(
		PayloadFEFMutationBatch,
		childID,
		1,
		"application/json",
		[]byte("child"),
		[]uuid.UUID{parentID},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := NewCorrectionReceipt(childID, "device-b", CorrectionMissingDependency, []string{parentID.String()}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CorrectedBundle(receipt, []TransportEnvelope{child}); !errors.Is(err, ErrCorrectionDependencyMissing) {
		t.Fatalf("incomplete correction error = %v", err)
	}

	parent, err := NewTransportEnvelope(
		PayloadFEFCheckpoint,
		parentID,
		0,
		"application/json",
		[]byte("parent"),
		[]uuid.UUID{childID},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CorrectedBundle(receipt, []TransportEnvelope{parent, child}); !errors.Is(err, ErrCorrectionDependencyCycle) {
		t.Fatalf("cyclic correction error = %v", err)
	}
}
