package protocol

import (
	"encoding/json"
	"errors"
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
