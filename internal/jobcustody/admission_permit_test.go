package jobcustody

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/computequeue"
)

func TestAdmissionPermitDerivesSignerAndRouteFromBoxAuthority(t *testing.T) {
	fixture := newAdmissionPermitFixture(t)
	authorization, err := fixture.verifier.Verify(
		fixture.permit,
		fixture.admission.envelopeBytes,
		fixture.issuedAt+1,
	)
	if err != nil {
		t.Fatal(err)
	}
	if authorization.Header() != fixture.admission.header ||
		authorization.ExpectedSigner() != fixture.admission.signer ||
		authorization.PermitDigest().Validate() != nil {
		t.Fatalf("unexpected authorization: %#v", authorization)
	}
	if _, err := json.Marshal(authorization); err == nil {
		t.Fatal("verified authorization became a wire contract")
	}
	formatted := fmt.Sprintf("%v %#v", authorization, authorization)
	for _, forbidden := range []string{
		string(fixture.admission.header.CapsuleID),
		string(fixture.admission.signer.SignerID),
		string(fixture.payload.RequesterAuthorityDigest),
	} {
		if strings.Contains(formatted, forbidden) {
			t.Fatalf("authorization diagnostics exposed authority: %s", formatted)
		}
	}
}

func TestAdmissionPermitRejectsSubstitutionExpiryAndNoncanonicalPayload(t *testing.T) {
	fixture := newAdmissionPermitFixture(t)
	otherAdmission := newStagingFixture(t, []byte("different-opaque-capsule"), 7)
	tests := []struct {
		name     string
		permit   SignedAdmissionPermit
		envelope []byte
		now      computequeue.Timestamp
	}{
		{
			name: "different envelope", permit: fixture.permit,
			envelope: otherAdmission.envelopeBytes, now: fixture.issuedAt + 1,
		},
		{
			name: "expired", permit: fixture.permit,
			envelope: fixture.admission.envelopeBytes, now: fixture.payload.ExpiresAt,
		},
		{
			name: "changed signature",
			permit: func() SignedAdmissionPermit {
				value := fixture.permit
				raw, err := base64.RawURLEncoding.DecodeString(string(value.Signature))
				if err != nil {
					t.Fatal(err)
				}
				raw[0] ^= 0x01
				value.Signature = computequeue.SignatureValue(base64.RawURLEncoding.EncodeToString(raw))
				return value
			}(),
			envelope: fixture.admission.envelopeBytes, now: fixture.issuedAt + 1,
		},
		{
			name: "noncanonical payload",
			permit: func() SignedAdmissionPermit {
				value := fixture.permit
				value.Payload = append(bytes.Clone(value.Payload), '\n')
				value.Signature = computequeue.SignatureValue(
					base64URLSignature(fixture.privateKey, value.Payload),
				)
				return value
			}(),
			envelope: fixture.admission.envelopeBytes, now: fixture.issuedAt + 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := fixture.verifier.Verify(test.permit, test.envelope, test.now); err == nil {
				t.Fatal("invalid permit was accepted")
			}
		})
	}
}

func TestAdmissionPermitRejectsControllerSignedRouteMismatch(t *testing.T) {
	fixture := newAdmissionPermitFixture(t)
	tampered := fixture.payload
	tampered.RouteRecipientWorkerID = "44444444-4444-4444-8444-444444444444"
	permit, err := fixture.signer.Sign(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.verifier.Verify(
		permit,
		fixture.admission.envelopeBytes,
		fixture.issuedAt+1,
	); err == nil {
		t.Fatal("controller-signed permit for a substituted Worker was accepted")
	}

	tampered = fixture.payload
	tampered.RouteRecipientKeyFingerprint = computequeue.SHA256Digest(
		"job-custody-permit-tests",
		"other-recipient-key",
	)
	permit, err = fixture.signer.Sign(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.verifier.Verify(
		permit,
		fixture.admission.envelopeBytes,
		fixture.issuedAt+1,
	); err == nil {
		t.Fatal("controller-signed permit for a substituted recipient key was accepted")
	}
}

func TestAdmissionPermitTrustRejectsIdentityAndKeyAliases(t *testing.T) {
	fixture := newAdmissionPermitFixture(t)
	publicKey := fixture.privateKey.Public().(ed25519.PublicKey)
	alias, err := NewAdmissionPermitVerificationKey(uuid.New(), publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewAdmissionPermitVerifier([]AdmissionPermitVerificationKey{
		fixture.verificationKey,
		alias,
	}); err == nil {
		t.Fatal("one Box authority key was accepted under two identities")
	}
	if _, err := NewAdmissionPermitVerifier([]AdmissionPermitVerificationKey{
		fixture.verificationKey,
		fixture.verificationKey,
	}); err == nil {
		t.Fatal("duplicate Box authority identity was accepted")
	}

	_, unrelatedPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	unrelatedKey, err := NewAdmissionPermitVerificationKey(
		fixture.authorityID,
		unrelatedPrivateKey.Public().(ed25519.PublicKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	unrelatedVerifier, err := NewAdmissionPermitVerifier(
		[]AdmissionPermitVerificationKey{unrelatedKey},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unrelatedVerifier.Verify(
		fixture.permit,
		fixture.admission.envelopeBytes,
		fixture.issuedAt+1,
	); err == nil {
		t.Fatal("permit signed by an unpinned Box authority key was accepted")
	}
}

type admissionPermitFixture struct {
	admission       stagingFixture
	authorityID     uuid.UUID
	issuedAt        computequeue.Timestamp
	payload         AdmissionPermitPayload
	permit          SignedAdmissionPermit
	privateKey      ed25519.PrivateKey
	signer          *AdmissionPermitSigner
	verificationKey AdmissionPermitVerificationKey
	verifier        *AdmissionPermitVerifier
}

func newAdmissionPermitFixture(t *testing.T) admissionPermitFixture {
	t.Helper()
	admission := newStagingFixture(t, []byte("opaque-job-capsule"), 8)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authorityID := uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	signer, err := NewAdmissionPermitSigner(authorityID, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	issuedAt := computequeue.Timestamp(1_800_000_000_010)
	payload, err := NewAdmissionPermitPayload(
		authorityID,
		uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
		computequeue.SHA256Digest("job-custody-permit-tests", "requester-authority"),
		computequeue.SHA256Digest("job-custody-permit-tests", "worker-access-grant"),
		computequeue.SHA256Digest("job-custody-permit-tests", "worker-capabilities"),
		admission.signer,
		admission.envelopeBytes,
		issuedAt,
		issuedAt+60_000,
	)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	verificationKey, err := NewAdmissionPermitVerificationKey(authorityID, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewAdmissionPermitVerifier(
		[]AdmissionPermitVerificationKey{verificationKey},
	)
	if err != nil {
		t.Fatal(err)
	}
	return admissionPermitFixture{
		admission: admission, authorityID: authorityID, issuedAt: issuedAt,
		payload: payload, permit: permit, privateKey: privateKey, signer: signer,
		verificationKey: verificationKey, verifier: verifier,
	}
}

func base64URLSignature(privateKey ed25519.PrivateKey, payload []byte) string {
	signature := ed25519.Sign(privateKey, admissionPermitSigningBytes(payload))
	return base64.RawURLEncoding.EncodeToString(signature)
}
