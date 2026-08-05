package relay_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/testfixture"
)

func TestSwiftCarrierFixtureFreezesOpaqueGoContract(t *testing.T) {
	fixture, err := testfixture.LoadRelayCarrier()
	if err != nil {
		t.Fatal(err)
	}
	if fixture.Format != "facets.replica-relay-carrier-fixture.v1" ||
		!strings.HasPrefix(fixture.Warning, "TEST FIXTURE ONLY.") {
		t.Fatalf("unexpected fixture metadata")
	}
	if err := fixture.Envelope.Validate(); err != nil {
		t.Fatal(err)
	}
	digest, err := fixture.Envelope.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	if digest != fixture.ExpectedEnvelopeReferenceDigest {
		t.Fatalf("reference digest=%s; want %s", digest, fixture.ExpectedEnvelopeReferenceDigest)
	}
	if err := fixture.PublisherRegistration.Authorize(
		fixture.PublisherAccess.Credential(),
		relay.CapabilityPublishMessage,
		1_500,
	); err != nil {
		t.Fatal(err)
	}
	carrier, err := json.Marshal(struct {
		Registration relay.MemberRegistration `json:"registration"`
		Envelope     relay.Envelope           `json:"envelope"`
	}{fixture.PublisherRegistration, fixture.Envelope})
	if err != nil {
		t.Fatal(err)
	}
	for _, protected := range []string{
		fixture.PublisherAccess.RouterAuthorizationToken,
		fixture.PublisherAccess.EncryptionKeyMaterial,
		"private-replica-identity-sentinel",
		"senderPrincipalID",
		"payloadKind",
	} {
		if strings.Contains(string(carrier), protected) {
			t.Fatalf("carrier contains protected material %q", protected)
		}
	}
}

func TestCursorEncodingIsOpaqueCanonicalAndStrict(t *testing.T) {
	for _, sequence := range []uint64{0, 1, 42, uint64(1<<63 - 1)} {
		cursor := relay.EncodeCursor(sequence)
		decoded, err := relay.DecodeCursor(cursor)
		if err != nil || decoded != sequence {
			t.Fatalf("cursor round trip sequence=%d decoded=%d err=%v", sequence, decoded, err)
		}
	}
	for _, invalid := range []string{
		"AQ",
		"AAAAAAAAAAE=",
		"not-a-cursor",
		relay.EncodeCursor(^uint64(0)),
	} {
		if _, err := relay.DecodeCursor(invalid); !relay.ErrorHasCode(err, relay.CodeInvalidCursor) {
			t.Fatalf("cursor %q err=%v; want invalid cursor", invalid, err)
		}
	}
}
