package jobcustody

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/computequeue"
)

func TestResultMutationPermitAuthenticatesExactSourceResultAndAction(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authorityID := uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	signer, err := NewResultMutationPermitSigner(authorityID, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	payload := resultMutationPermitPayloadFixture(authorityID, ResultMutationAcknowledgeDelivery)
	permit, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := NewAdmissionPermitVerificationKey(authorityID, publicKey)
	verifier, _ := NewAdmissionPermitVerifier([]AdmissionPermitVerificationKey{key})
	authorization, err := verifier.VerifyResultMutation(permit, payload.IssuedAt+1)
	if err != nil || authorization.Payload() != payload || authorization.PermitDigest().Validate() != nil {
		t.Fatalf("authorization=%+v err=%v", authorization, err)
	}
	if _, err := authorization.MarshalJSON(); err == nil ||
		authorization.String() != "verified-job-custody-result-mutation-authorization(redacted)" {
		t.Fatal("verified result mutation authorization became serializable or disclosed itself")
	}
}

func TestResultMutationPermitRejectsActionResultReceiptAndSignerSubstitution(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	authorityID := uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	payload := resultMutationPermitPayloadFixture(authorityID, ResultMutationReleaseCustody)
	signer, _ := NewResultMutationPermitSigner(authorityID, privateKey)
	permit, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := NewAdmissionPermitVerificationKey(authorityID, publicKey)
	verifier, _ := NewAdmissionPermitVerifier([]AdmissionPermitVerificationKey{key})

	changedPayload := payload
	changedPayload.SourceTransitionReceiptDigest = computequeue.SHA256Digest("result-mutation-test", "changed")
	changedPermit, _ := signer.Sign(changedPayload)
	changedPermit.Signature = permit.Signature
	otherPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	wrongKey, _ := NewAdmissionPermitVerificationKey(authorityID, otherPublic)
	wrongVerifier, _ := NewAdmissionPermitVerifier([]AdmissionPermitVerificationKey{wrongKey})

	for _, test := range []struct {
		name     string
		verifier *AdmissionPermitVerifier
		permit   SignedResultMutationPermit
		now      computequeue.Timestamp
	}{
		{name: "changed receipt", verifier: verifier, permit: changedPermit, now: payload.IssuedAt + 1},
		{name: "expired", verifier: verifier, permit: permit, now: payload.ExpiresAt},
		{name: "wrong identity", verifier: wrongVerifier, permit: permit, now: payload.IssuedAt + 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := test.verifier.VerifyResultMutation(test.permit, test.now); err == nil {
				t.Fatal("accepted substituted or expired result mutation permit")
			}
		})
	}
}

func resultMutationPermitPayloadFixture(
	authorityID uuid.UUID,
	action ResultMutationAction,
) ResultMutationPermitPayload {
	return ResultMutationPermitPayload{
		Action:                action,
		AdmissionPermitDigest: computequeue.SHA256Digest("result-mutation-test", "admission-permit"),
		AuthorityID:           authorityID, ExpiresAt: 1_800_000_060_000,
		InputCapsuleID: "11111111-1111-4111-8111-111111111111",
		IssuedAt:       1_800_000_000_000,
		PermitID:       uuid.MustParse("22222222-2222-4222-8222-222222222222"),
		RequesterAuthorityDigest: computequeue.SHA256Digest(
			"result-mutation-test", "requester-authority",
		),
		ResultCapsuleID: "33333333-3333-4333-8333-333333333333",
		ResultCustodyReceiptDigest: computequeue.SHA256Digest(
			"result-mutation-test", "custody-receipt",
		),
		ResultSetDigest: computequeue.SHA256Digest("result-mutation-test", "result-set"),
		SourceTransitionReceiptDigest: computequeue.SHA256Digest(
			"result-mutation-test", "source-receipt", string(action),
		),
		Version: ResultMutationPermitVersion,
	}
}
