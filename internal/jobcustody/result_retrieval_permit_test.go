package jobcustody

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/computequeue"
)

func TestResultRetrievalPermitAuthenticatesExactSourceAndInputCapsule(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authorityID := uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	signer, err := NewResultRetrievalPermitSigner(authorityID, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	payload := resultRetrievalPermitPayloadFixture(authorityID)
	permit, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	key, err := NewAdmissionPermitVerificationKey(authorityID, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewAdmissionPermitVerifier([]AdmissionPermitVerificationKey{key})
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := verifier.VerifyResultRetrieval(permit, payload.IssuedAt+1)
	if err != nil || authorization.Payload() != payload || authorization.PermitDigest().Validate() != nil {
		t.Fatalf("authorization=%+v err=%v", authorization, err)
	}
	if _, err := authorization.MarshalJSON(); err == nil ||
		authorization.String() != "verified-job-custody-result-retrieval-authorization(redacted)" {
		t.Fatal("verified retrieval authorization became serializable or disclosed itself")
	}
}

func TestResultRetrievalPermitRejectsSubstitutionExpiryAndWrongIdentity(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authorityID := uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	payload := resultRetrievalPermitPayloadFixture(authorityID)
	signer, _ := NewResultRetrievalPermitSigner(authorityID, privateKey)
	permit, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := NewAdmissionPermitVerificationKey(authorityID, publicKey)
	verifier, _ := NewAdmissionPermitVerifier([]AdmissionPermitVerificationKey{key})

	changedPayload := payload
	changedPayload.InputCapsuleID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	changedPermit, _ := signer.Sign(changedPayload)
	changedPermit.Signature = permit.Signature

	otherPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	wrongKey, _ := NewAdmissionPermitVerificationKey(authorityID, otherPublic)
	wrongVerifier, _ := NewAdmissionPermitVerifier([]AdmissionPermitVerificationKey{wrongKey})

	for _, test := range []struct {
		name     string
		verifier *AdmissionPermitVerifier
		permit   SignedResultRetrievalPermit
		now      computequeue.Timestamp
	}{
		{name: "changed payload", verifier: verifier, permit: changedPermit, now: payload.IssuedAt + 1},
		{name: "expired", verifier: verifier, permit: permit, now: payload.ExpiresAt},
		{name: "wrong identity", verifier: wrongVerifier, permit: permit, now: payload.IssuedAt + 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := test.verifier.VerifyResultRetrieval(test.permit, test.now); err == nil {
				t.Fatal("accepted substituted or expired result retrieval permit")
			}
		})
	}
}

func resultRetrievalPermitPayloadFixture(authorityID uuid.UUID) ResultRetrievalPermitPayload {
	return ResultRetrievalPermitPayload{
		AdmissionPermitDigest: computequeue.SHA256Digest("result-retrieval-test", "admission-permit"),
		AuthorityID:           authorityID, ExpiresAt: 1_800_000_060_000,
		InputCapsuleID: "11111111-1111-4111-8111-111111111111",
		IssuedAt:       1_800_000_000_000,
		PermitID:       uuid.MustParse("22222222-2222-4222-8222-222222222222"),
		RequesterAuthorityDigest: computequeue.SHA256Digest(
			"result-retrieval-test", "requester-authority",
		),
		Version: ResultRetrievalPermitVersion,
	}
}
