package serviceauthority

import (
	"bytes"
	"testing"

	"github.com/google/uuid"
)

func TestJobCustodyExpiryReceiptsBindRetainedAndPartialInputCustody(t *testing.T) {
	deploymentID := uuid.MustParse("9e000000-0000-0000-0000-000000000001")
	seed := bytes.Repeat([]byte{0}, 32)
	seed[31] = 15
	signer, err := NewDeploymentSigner(deploymentID, seed)
	if err != nil {
		t.Fatal(err)
	}
	retainedPayload := fixtureJobCustodyExpiryReceiptPayload(deploymentID)
	retained, err := signer.SignJobCustodyExpiryReceipt(retainedPayload)
	if err != nil {
		t.Fatal(err)
	}
	encodedRetained, err := retained.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	decodedRetained, err := DecodeJobCustodyExpiryReceipt(encodedRetained)
	if err != nil {
		t.Fatal(err)
	}
	if authorized, err := decodedRetained.Authorize(fixtureDeploymentDescriptor(t, signer)); err != nil || authorized != retainedPayload {
		t.Fatalf("authorized retained expiry=%+v error=%v", authorized, err)
	}

	stagingPayload := fixtureJobCustodyStagingExpiryReceiptPayload(deploymentID)
	staging, err := signer.SignJobCustodyStagingExpiryReceipt(stagingPayload)
	if err != nil {
		t.Fatal(err)
	}
	encodedStaging, err := staging.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	decodedStaging, err := DecodeJobCustodyStagingExpiryReceipt(encodedStaging)
	if err != nil {
		t.Fatal(err)
	}
	if authorized, err := decodedStaging.Authorize(fixtureDeploymentDescriptor(t, signer)); err != nil || authorized != stagingPayload {
		t.Fatalf("authorized staging expiry=%+v error=%v", authorized, err)
	}
}

func TestJobCustodyExpiryReceiptsRejectMutationAndInvalidProgress(t *testing.T) {
	deploymentID := uuid.MustParse("9e000000-0000-0000-0000-000000000001")
	seed := bytes.Repeat([]byte{0}, 32)
	seed[31] = 15
	signer, _ := NewDeploymentSigner(deploymentID, seed)
	retained, err := signer.SignJobCustodyExpiryReceipt(
		fixtureJobCustodyExpiryReceiptPayload(deploymentID),
	)
	if err != nil {
		t.Fatal(err)
	}
	mutated := retained
	mutated.Payload = bytes.Replace(mutated.Payload,
		[]byte(`"expiredAtMilliseconds":1800000000400`),
		[]byte(`"expiredAtMilliseconds":1800000000401`), 1)
	if _, err := mutated.VerifiedPayload(); err == nil {
		t.Fatal("mutated retained expiry retained a valid signature")
	}
	invalid := fixtureJobCustodyStagingExpiryReceiptPayload(deploymentID)
	invalid.CommittedBytes = invalid.ProtectedObjectByteCount + 1
	if _, err := signer.SignJobCustodyStagingExpiryReceipt(invalid); err == nil {
		t.Fatal("staging progress beyond the protected input was accepted")
	}
}

func fixtureJobCustodyExpiryReceiptPayload(
	deploymentID uuid.UUID,
) JobCustodyExpiryReceiptPayload {
	return JobCustodyExpiryReceiptPayload{
		AdmissionEnvelopeDigest:    jobCustodyReceiptTestDigest("input-envelope"),
		AdmissionPermitDigest:      jobCustodyReceiptTestDigest("input-permit"),
		AssignmentID:               uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		CapsuleID:                  uuid.MustParse("22222222-2222-4222-8222-222222222222"),
		CustodyReceiptDigest:       jobCustodyReceiptTestDigest("input-custody-receipt"),
		DeploymentID:               deploymentID,
		ExpiredAtMilliseconds:      1_800_000_000_400,
		Kind:                       JobCustodyExpiryReceiptKind,
		RetentionUntilMilliseconds: 1_800_000_000_300,
		Version:                    JobCustodyExpiryReceiptVersion,
	}
}

func fixtureJobCustodyStagingExpiryReceiptPayload(
	deploymentID uuid.UUID,
) JobCustodyStagingExpiryReceiptPayload {
	return JobCustodyStagingExpiryReceiptPayload{
		AdmissionEnvelopeDigest:    jobCustodyReceiptTestDigest("input-envelope"),
		AdmissionPermitDigest:      jobCustodyReceiptTestDigest("input-permit"),
		AssignmentID:               uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		CapsuleID:                  uuid.MustParse("22222222-2222-4222-8222-222222222222"),
		CommittedBytes:             1024,
		DeploymentID:               deploymentID,
		ExpiredAtMilliseconds:      1_800_000_000_400,
		Kind:                       JobCustodyStagingExpiryReceiptKind,
		ProtectedObjectByteCount:   4096,
		ProtectedObjectSHA256:      jobCustodyReceiptTestDigest("protected-input"),
		RetentionUntilMilliseconds: 1_800_000_000_300,
		Version:                    JobCustodyStagingExpiryReceiptVersion,
	}
}
