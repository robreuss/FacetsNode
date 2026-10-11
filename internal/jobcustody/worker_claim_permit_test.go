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

func TestWorkerClaimPermitAuthenticatesExactWorkerRoute(t *testing.T) {
	authorityID := uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := workerClaimPermitPayloadFixture(authorityID)
	signer, err := NewWorkerClaimPermitSigner(authorityID, privateKey)
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
	authorization, err := verifier.VerifyWorkerClaim(permit, payload.IssuedAt+1)
	if err != nil {
		t.Fatal(err)
	}
	if authorization.Payload() != payload || authorization.PermitDigest().Validate() != nil {
		t.Fatalf("authorization=%+v", authorization)
	}
	if _, err := json.Marshal(authorization); err == nil {
		t.Fatal("verified Worker authorization became a wire contract")
	}
	formatted := fmt.Sprintf("%v %#v", authorization, authorization)
	for _, forbidden := range []string{payload.ClaimID.String(), string(payload.RouteRecipientWorkerID)} {
		if strings.Contains(formatted, forbidden) {
			t.Fatalf("authorization diagnostics exposed route authority: %s", formatted)
		}
	}
}

func TestWorkerClaimPermitRejectsSubstitutionExpiryAndWrongAuthority(t *testing.T) {
	authorityID := uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := workerClaimPermitPayloadFixture(authorityID)
	signer, _ := NewWorkerClaimPermitSigner(authorityID, privateKey)
	permit, _ := signer.Sign(payload)
	key, _ := NewAdmissionPermitVerificationKey(authorityID, publicKey)
	verifier, _ := NewAdmissionPermitVerifier([]AdmissionPermitVerificationKey{key})

	tests := []struct {
		name   string
		permit SignedWorkerClaimPermit
		now    computequeue.Timestamp
	}{
		{name: "expired", permit: permit, now: payload.ExpiresAt},
		{name: "changed payload", permit: func() SignedWorkerClaimPermit {
			value := permit
			changed := payload
			changed.ClaimID = uuid.New()
			value.Payload, _ = computequeue.EncodeCanonical(changed)
			return value
		}(), now: payload.IssuedAt + 1},
		{name: "changed signature", permit: func() SignedWorkerClaimPermit {
			value := permit
			raw, _ := base64.RawURLEncoding.DecodeString(string(value.Signature))
			raw[0] ^= 1
			value.Signature = computequeue.SignatureValue(base64.RawURLEncoding.EncodeToString(raw))
			return value
		}(), now: payload.IssuedAt + 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := verifier.VerifyWorkerClaim(test.permit, test.now); err == nil {
				t.Fatal("invalid Worker claim permit verified")
			}
		})
	}
}

func workerClaimPermitPayloadFixture(authorityID uuid.UUID) WorkerClaimPermitPayload {
	return WorkerClaimPermitPayload{
		AuthorityID:                  authorityID,
		ClaimID:                      uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
		ExpiresAt:                    1_800_000_060_000,
		IssuedAt:                     1_800_000_000_000,
		PermitID:                     uuid.MustParse("cccccccc-cccc-4ccc-8ccc-cccccccccccc"),
		RouteRecipientKeyFingerprint: computequeue.SHA256Digest("worker-claim", "recipient-key"),
		RouteRecipientWorkerID:       "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
		Version:                      WorkerClaimPermitVersion,
		WorkerCapabilitiesDigest:     computequeue.SHA256Digest("worker-claim", "capabilities"),
		WorkerOwnerAuthorityDigest:   computequeue.SHA256Digest("worker-claim", "owner"),
	}
}
