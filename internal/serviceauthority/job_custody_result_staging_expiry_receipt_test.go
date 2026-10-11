package serviceauthority

import (
	"bytes"
	"testing"

	"github.com/google/uuid"
)

func TestJobCustodyResultStagingExpiryReceiptBindsPartialCustodyAndDeployment(t *testing.T) {
	deploymentID := uuid.MustParse("9d000000-0000-0000-0000-000000000001")
	seed := bytes.Repeat([]byte{0}, 32)
	seed[31] = 14
	signer, err := NewDeploymentSigner(deploymentID, seed)
	if err != nil {
		t.Fatal(err)
	}
	payload := fixtureJobCustodyResultStagingExpiryReceiptPayload(deploymentID)
	receipt, err := signer.SignJobCustodyResultStagingExpiryReceipt(payload)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := receipt.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeJobCustodyResultStagingExpiryReceipt(encoded)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := decoded.Authorize(fixtureDeploymentDescriptor(t, signer))
	if err != nil || verified != payload {
		t.Fatalf("authorized payload=%+v error=%v", verified, err)
	}
}

func TestJobCustodyResultStagingExpiryReceiptRejectsMutationAndInvalidProgress(t *testing.T) {
	deploymentID := uuid.MustParse("9d000000-0000-0000-0000-000000000001")
	seed := bytes.Repeat([]byte{0}, 32)
	seed[31] = 14
	signer, _ := NewDeploymentSigner(deploymentID, seed)
	payload := fixtureJobCustodyResultStagingExpiryReceiptPayload(deploymentID)
	receipt, err := signer.SignJobCustodyResultStagingExpiryReceipt(payload)
	if err != nil {
		t.Fatal(err)
	}
	mutated := receipt
	mutated.Payload = bytes.Replace(mutated.Payload,
		[]byte(`"committedBytes":1024`), []byte(`"committedBytes":1025`), 1)
	if _, err := mutated.VerifiedPayload(); err == nil {
		t.Fatal("mutated committed bytes retained a valid receipt")
	}
	invalid := payload
	invalid.CommittedBytes = invalid.ProtectedObjectByteCount + 1
	if _, err := signer.SignJobCustodyResultStagingExpiryReceipt(invalid); err == nil {
		t.Fatal("staging progress beyond the protected object was accepted")
	}
}

func fixtureJobCustodyResultStagingExpiryReceiptPayload(
	deploymentID uuid.UUID,
) JobCustodyResultStagingExpiryReceiptPayload {
	return JobCustodyResultStagingExpiryReceiptPayload{
		AssignmentID:                 uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		CommittedBytes:               1024,
		DeploymentID:                 deploymentID,
		ExpiredAtMilliseconds:        1_800_000_000_400,
		InputCapsuleID:               uuid.MustParse("33333333-3333-4333-8333-333333333333"),
		Kind:                         JobCustodyResultStagingExpiryReceiptKind,
		ProtectedObjectByteCount:     4096,
		ProtectedObjectSHA256:        jobCustodyReceiptTestDigest("protected-result"),
		ResultCapsuleID:              uuid.MustParse("44444444-4444-4444-8444-444444444444"),
		ResultPermitDigest:           jobCustodyReceiptTestDigest("result-permit"),
		ResultSetDigest:              jobCustodyReceiptTestDigest("result-set"),
		RetentionUntilMilliseconds:   1_800_000_000_300,
		Version:                      JobCustodyResultStagingExpiryReceiptVersion,
		WorkerExecutionReceiptDigest: jobCustodyReceiptTestDigest("worker-execution"),
	}
}
