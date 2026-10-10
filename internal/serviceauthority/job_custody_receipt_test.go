package serviceauthority

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

func TestJobCustodyReceiptBindsExactProtectedObjectAndDeployment(t *testing.T) {
	deploymentID := uuid.MustParse("8b000000-0000-0000-0000-000000000001")
	seed := bytes.Repeat([]byte{0}, 32)
	seed[31] = 7
	signer, err := NewDeploymentSigner(deploymentID, seed)
	if err != nil {
		t.Fatal(err)
	}
	payload := fixtureJobCustodyReceiptPayload(deploymentID)
	receipt, err := signer.SignJobCustodyReceipt(payload)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := receipt.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeJobCustodyReceipt(encoded)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := fixtureDeploymentDescriptor(t, signer)
	verified, err := decoded.Authorize(descriptor)
	if err != nil || verified != payload {
		t.Fatalf("authorized payload=%+v err=%v", verified, err)
	}
	firstReference, err := decoded.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	secondReference, err := receipt.ReferenceDigest()
	if err != nil || firstReference != secondReference {
		t.Fatalf("reference mismatch %q %q err=%v", firstReference, secondReference, err)
	}
}

func TestJobCustodyReceiptRejectsMutationAndSignerSubstitution(t *testing.T) {
	deploymentID := uuid.MustParse("8b000000-0000-0000-0000-000000000001")
	seed := bytes.Repeat([]byte{0}, 32)
	seed[31] = 7
	signer, err := NewDeploymentSigner(deploymentID, seed)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := signer.SignJobCustodyReceipt(fixtureJobCustodyReceiptPayload(deploymentID))
	if err != nil {
		t.Fatal(err)
	}
	mutated := receipt
	var payload JobCustodyReceiptPayload
	if err := json.Unmarshal(mutated.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	payload.ProtectedObjectByteCount++
	mutated.Payload, _ = json.Marshal(payload)
	if _, err := mutated.VerifiedPayload(); err == nil {
		t.Fatal("mutated protected byte count retained a valid receipt")
	}

	attackerSeed := bytes.Repeat([]byte{0}, 32)
	attackerSeed[31] = 9
	attacker, err := NewDeploymentSigner(uuid.MustParse("8b000000-0000-0000-0000-000000000009"), attackerSeed)
	if err != nil {
		t.Fatal(err)
	}
	attackerPayload := fixtureJobCustodyReceiptPayload(attacker.DeploymentID())
	attackerReceipt, err := attacker.SignJobCustodyReceipt(attackerPayload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := attackerReceipt.Authorize(fixtureDeploymentDescriptor(t, signer)); err == nil {
		t.Fatal("different Job Custody deployment authorized receipt")
	}
}

func fixtureJobCustodyReceiptPayload(deploymentID uuid.UUID) JobCustodyReceiptPayload {
	return JobCustodyReceiptPayload{
		AdmissionEnvelopeDigest:         jobCustodyReceiptTestDigest("admission-envelope"),
		AdmissionIdempotencyKey:         jobCustodyReceiptTestDigest("admission-idempotency"),
		AdmissionPermitDigest:           jobCustodyReceiptTestDigest("admission-permit"),
		AssignmentID:                    uuid.MustParse("22222222-2222-4222-8222-222222222222"),
		CapsuleID:                       uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		CommittedAtMilliseconds:         1_800_000_000_100,
		DeploymentID:                    deploymentID,
		Kind:                            JobCustodyCommittedReceiptKind,
		ProtectedObjectByteCount:        4096,
		ProtectedObjectDescriptorDigest: jobCustodyReceiptTestDigest("protected-descriptor"),
		ProtectedObjectSHA256:           jobCustodyReceiptTestDigest("protected-object"),
		RetentionUntilMilliseconds:      1_800_000_200_000,
		Version:                         JobCustodyReceiptVersion,
	}
}

func fixtureDeploymentDescriptor(t *testing.T, signer *DeploymentSigner) DeploymentDescriptor {
	t.Helper()
	descriptor := DeploymentDescriptor{
		CreatedAtMilliseconds: 1_700_000_000_000,
		DeploymentID:          signer.DeploymentID(),
		PublicSigningKeyX963:  signer.PublicSigningKeyX963(),
		Routes: []TransportRoute{{
			Endpoint: "https://job-custody.example", Kind: RouteDirectHTTPS,
			NetworkScope:         NetworkPublic,
			RouteID:              uuid.MustParse("8b000000-0000-0000-0000-000000000002"),
			ServerAuthentication: ServerAuthentication{Kind: "web_pki"},
		}},
		SigningKeyFingerprint: signer.SigningKeyFingerprint(),
		Version:               SchemaVersion,
	}
	if err := descriptor.Validate(); err != nil {
		t.Fatal(err)
	}
	return descriptor
}

func jobCustodyReceiptTestDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}
