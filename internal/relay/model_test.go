package relay_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
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

func TestMemberAdmissionFreezesScopeCapabilitiesAndLifetime(t *testing.T) {
	tenantID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	domainID := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	admissionID := uuid.MustParse("33333333-3333-4333-8333-333333333333")
	credential := relay.AdmissionCredential{
		TenantID:    tenantID,
		DomainID:    domainID,
		AdmissionID: admissionID,
		Token:       modelTestToken(32),
	}
	digest, err := relay.AdmissionAuthorizationDigest(credential)
	if err != nil {
		t.Fatal(err)
	}
	memberExpiry := int64(700_000)
	admission := relay.MemberAdmission{
		Version:                     relay.SchemaVersion,
		TenantID:                    tenantID,
		DomainID:                    domainID,
		AdmissionID:                 admissionID,
		AuthorizationDigest:         digest,
		Capabilities:                []relay.Capability{relay.CapabilityFetchMessage},
		CreatedAtMilliseconds:       1_000,
		ExpiresAtMilliseconds:       10_000,
		MemberExpiresAtMilliseconds: &memberExpiry,
	}
	if err := admission.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := admission.VerifyCredential(credential); err != nil {
		t.Fatal(err)
	}
	if err := admission.RequireActive(9_999); err != nil {
		t.Fatal(err)
	}
	if err := admission.RequireActive(10_000); !relay.ErrorHasCode(
		err,
		relay.CodeAdmissionExpired,
	) {
		t.Fatalf("expiry err=%v", err)
	}
	wrong := credential
	wrong.Token = modelTestToken(64)
	if err := admission.VerifyCredential(wrong); !relay.ErrorHasCode(
		err,
		relay.CodeUnauthorized,
	) {
		t.Fatalf("wrong credential err=%v", err)
	}

	tooLong := admission
	tooLong.ExpiresAtMilliseconds = admission.CreatedAtMilliseconds +
		relay.MaximumAdmissionLifetimeMilliseconds + 1
	if err := tooLong.Validate(); !relay.ErrorHasCode(
		err,
		relay.CodeInvalidAdmission,
	) {
		t.Fatalf("overlong admission err=%v", err)
	}
	unsorted := admission
	unsorted.Capabilities = []relay.Capability{
		relay.CapabilityPublishMessage,
		relay.CapabilityFetchMessage,
	}
	if err := unsorted.Validate(); !relay.ErrorHasCode(
		err,
		relay.CodeInvalidAdmission,
	) {
		t.Fatalf("unsorted capabilities err=%v", err)
	}
	uppercaseDigest := admission
	uppercaseDigest.AuthorizationDigest = strings.ToUpper(digest)
	if err := uppercaseDigest.Validate(); !relay.ErrorHasCode(
		err,
		relay.CodeInvalidAdmission,
	) {
		t.Fatalf("non-canonical digest err=%v", err)
	}
}

func TestPortableMemberAdmissionFixtureFreezesClientGeneratedDigests(t *testing.T) {
	fixture, err := testfixture.LoadRelayMemberAdmission()
	if err != nil {
		t.Fatal(err)
	}
	if fixture.Format != "facets.relay-member-admission-fixture.v1" ||
		!strings.HasPrefix(fixture.Warning, "TEST FIXTURE ONLY.") {
		t.Fatal("unexpected admission fixture metadata")
	}
	admissionDigest, err := relay.AdmissionAuthorizationDigest(
		fixture.AdmissionCredential.Credential(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if admissionDigest != fixture.ExpectedAdmissionAuthorizationDigest {
		t.Fatalf("admission digest=%s", admissionDigest)
	}
	memberDigest, err := relay.AuthorizationDigest(
		fixture.MemberCredential.Credential(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if memberDigest != fixture.ExpectedMemberAuthorizationDigest {
		t.Fatalf("member digest=%s", memberDigest)
	}
	if fixture.CreateRequest.AdmissionID !=
		fixture.AdmissionCredential.AdmissionID ||
		fixture.CreateRequest.AuthorizationDigest != admissionDigest ||
		fixture.ClaimRequest.MemberID != fixture.MemberCredential.MemberID ||
		fixture.ClaimRequest.AuthorizationDigest != memberDigest {
		t.Fatal("fixture requests are not bound to the generated credentials")
	}
}

func modelTestToken(seed byte) string {
	value := make([]byte, 32)
	for index := range value {
		value[index] = seed + byte(index)
	}
	return base64.RawURLEncoding.EncodeToString(value)
}
