package jobcustody

import (
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

func TestWorkerResultPermitAuthenticatesExactClaimAndProtectedResult(t *testing.T) {
	authorityID := uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := workerResultPermitPayloadFixture(t, authorityID)
	signer, err := NewWorkerResultPermitSigner(authorityID, privateKey)
	if err != nil {
		t.Fatal(err)
	}
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
	authorization, err := verifier.VerifyWorkerResult(permit, payload.IssuedAt+1)
	if err != nil {
		t.Fatal(err)
	}
	if authorization.Payload() != payload || authorization.PermitDigest().Validate() != nil {
		t.Fatalf("authorization=%+v", authorization)
	}
	if _, err := json.Marshal(authorization); err == nil {
		t.Fatal("verified Worker result authorization became a wire contract")
	}
	formatted := fmt.Sprintf("%v %#v", authorization, authorization)
	for _, forbidden := range []string{payload.Result.ClaimID.String(), string(payload.Result.ResultCapsuleID)} {
		if strings.Contains(formatted, forbidden) {
			t.Fatalf("authorization diagnostics exposed result authority: %s", formatted)
		}
	}
}

func TestWorkerResultPermitRejectsSubstitutionExpiryAndWrongIdentity(t *testing.T) {
	authorityID := uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := workerResultPermitPayloadFixture(t, authorityID)
	signer, _ := NewWorkerResultPermitSigner(authorityID, privateKey)
	permit, _ := signer.Sign(payload)
	key, _ := NewAdmissionPermitVerificationKey(authorityID, publicKey)
	verifier, _ := NewAdmissionPermitVerifier([]AdmissionPermitVerificationKey{key})

	tests := []struct {
		name   string
		permit SignedWorkerResultPermit
		now    computequeue.Timestamp
	}{
		{name: "expired", permit: permit, now: payload.ExpiresAt},
		{name: "changed result", permit: func() SignedWorkerResultPermit {
			value := permit
			changed := payload
			changed.Result.ResultSetDigest = computequeue.SHA256Digest("changed", "result")
			changed.Result.IdempotencyKey = changed.Result.MakeIdempotencyKey()
			value.Payload, _ = computequeue.EncodeCanonical(changed)
			return value
		}(), now: payload.IssuedAt + 1},
		{name: "changed signature", permit: func() SignedWorkerResultPermit {
			value := permit
			raw, _ := base64.RawURLEncoding.DecodeString(string(value.Signature))
			raw[0] ^= 1
			value.Signature = computequeue.SignatureValue(base64.RawURLEncoding.EncodeToString(raw))
			return value
		}(), now: payload.IssuedAt + 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := verifier.VerifyWorkerResult(test.permit, test.now); err == nil {
				t.Fatal("invalid Worker result permit verified")
			}
		})
	}
}

func workerResultPermitPayloadFixture(t *testing.T, authorityID uuid.UUID) WorkerResultPermitPayload {
	t.Helper()
	descriptor, err := computequeue.NewJobCapsuleProtectedObjectDescriptor(
		4096, computequeue.SHA256Digest("worker-result", "protected"), 1024,
	)
	if err != nil {
		t.Fatal(err)
	}
	header, err := NewWorkerResultHeader(
		"11111111-1111-4111-8111-111111111111",
		uuid.MustParse("22222222-2222-4222-8222-222222222222"),
		"33333333-3333-4333-8333-333333333333",
		"44444444-4444-4444-8444-444444444444",
		descriptor,
		computequeue.SHA256Digest("worker-result", "result-set"),
		computequeue.SHA256Digest("worker-result", "execution-receipt"),
		1_800_000_200_000,
	)
	if err != nil {
		t.Fatal(err)
	}
	return WorkerResultPermitPayload{
		AuthorityID: authorityID, ExpiresAt: 1_800_000_060_000,
		IssuedAt:                     1_800_000_000_000,
		PermitID:                     uuid.MustParse("55555555-5555-4555-8555-555555555555"),
		Result:                       header,
		RouteRecipientKeyFingerprint: computequeue.SHA256Digest("worker-result", "recipient-key"),
		RouteRecipientWorkerID:       "66666666-6666-4666-8666-666666666666",
		Version:                      WorkerResultPermitVersion,
		WorkerCapabilitiesDigest:     computequeue.SHA256Digest("worker-result", "capabilities"),
		WorkerOwnerAuthorityDigest:   computequeue.SHA256Digest("worker-result", "owner"),
	}
}
