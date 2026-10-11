package serviceauthority

import (
	"bytes"
	"testing"

	"github.com/google/uuid"
)

func TestJobCustodyResultReceiptBindsExactProtectedResultAndDeployment(t *testing.T) {
	deploymentID := uuid.MustParse("8b000000-0000-0000-0000-000000000001")
	seed := bytes.Repeat([]byte{0}, 32)
	seed[31] = 7
	signer, err := NewDeploymentSigner(deploymentID, seed)
	if err != nil {
		t.Fatal(err)
	}
	payload := fixtureJobCustodyResultReceiptPayload(deploymentID)
	receipt, err := signer.SignJobCustodyResultReceipt(payload)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := receipt.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeJobCustodyResultReceipt(encoded)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := decoded.Authorize(fixtureDeploymentDescriptor(t, signer))
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

func TestJobCustodyResultReceiptRejectsMutationAndSignerSubstitution(t *testing.T) {
	deploymentID := uuid.MustParse("8b000000-0000-0000-0000-000000000001")
	seed := bytes.Repeat([]byte{0}, 32)
	seed[31] = 7
	signer, err := NewDeploymentSigner(deploymentID, seed)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := signer.SignJobCustodyResultReceipt(fixtureJobCustodyResultReceiptPayload(deploymentID))
	if err != nil {
		t.Fatal(err)
	}
	mutated := receipt
	mutated.Payload = bytes.Replace(mutated.Payload, []byte(`"protectedObjectByteCount":4096`), []byte(`"protectedObjectByteCount":4097`), 1)
	if _, err := mutated.VerifiedPayload(); err == nil {
		t.Fatal("mutated result byte count retained a valid receipt")
	}

	attackerSeed := bytes.Repeat([]byte{0}, 32)
	attackerSeed[31] = 9
	attacker, err := NewDeploymentSigner(uuid.MustParse("8b000000-0000-0000-0000-000000000009"), attackerSeed)
	if err != nil {
		t.Fatal(err)
	}
	attackerReceipt, err := attacker.SignJobCustodyResultReceipt(
		fixtureJobCustodyResultReceiptPayload(attacker.DeploymentID()),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := attackerReceipt.Authorize(fixtureDeploymentDescriptor(t, signer)); err == nil {
		t.Fatal("different Job Custody deployment authorized result receipt")
	}
}

func fixtureJobCustodyResultReceiptPayload(deploymentID uuid.UUID) JobCustodyResultReceiptPayload {
	return JobCustodyResultReceiptPayload{
		AssignmentID:                    uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		ClaimID:                         uuid.MustParse("22222222-2222-4222-8222-222222222222"),
		ClaimPermitDigest:               jobCustodyReceiptTestDigest("claim-permit"),
		CommittedAtMilliseconds:         1_800_000_000_100,
		DeploymentID:                    deploymentID,
		InputCapsuleID:                  uuid.MustParse("33333333-3333-4333-8333-333333333333"),
		Kind:                            JobCustodyResultReceiptKind,
		ProtectedObjectByteCount:        4096,
		ProtectedObjectDescriptorDigest: jobCustodyReceiptTestDigest("result-descriptor"),
		ProtectedObjectSHA256:           jobCustodyReceiptTestDigest("result-protected-object"),
		ResultCapsuleID:                 uuid.MustParse("44444444-4444-4444-8444-444444444444"),
		ResultIdempotencyKey:            jobCustodyReceiptTestDigest("result-idempotency"),
		ResultPermitDigest:              jobCustodyReceiptTestDigest("result-permit"),
		ResultSetDigest:                 jobCustodyReceiptTestDigest("result-set"),
		RetentionUntilMilliseconds:      1_800_000_200_000,
		Version:                         JobCustodyResultReceiptVersion,
		WorkerExecutionReceiptDigest:    jobCustodyReceiptTestDigest("worker-execution-receipt"),
	}
}
