package serviceauthority

import (
	"bytes"
	"testing"

	"github.com/google/uuid"
)

func TestJobCustodyResultReleaseReceiptBindsExactCleanupAndDeployment(t *testing.T) {
	deploymentID := uuid.MustParse("9b000000-0000-0000-0000-000000000001")
	seed := bytes.Repeat([]byte{0}, 32)
	seed[31] = 11
	signer, err := NewDeploymentSigner(deploymentID, seed)
	if err != nil {
		t.Fatal(err)
	}
	payload := fixtureJobCustodyResultReleaseReceiptPayload(deploymentID)
	receipt, err := signer.SignJobCustodyResultReleaseReceipt(payload)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := receipt.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeJobCustodyResultReleaseReceipt(encoded)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := decoded.Authorize(fixtureDeploymentDescriptor(t, signer))
	if err != nil || verified != payload {
		t.Fatalf("authorized payload=%+v err=%v", verified, err)
	}
	if first, err := decoded.ReferenceDigest(); err != nil {
		t.Fatal(err)
	} else if second, err := receipt.ReferenceDigest(); err != nil || first != second {
		t.Fatalf("reference mismatch %q %q err=%v", first, second, err)
	}
}

func TestJobCustodyResultReleaseReceiptRejectsMutationAndSignerSubstitution(t *testing.T) {
	deploymentID := uuid.MustParse("9b000000-0000-0000-0000-000000000001")
	seed := bytes.Repeat([]byte{0}, 32)
	seed[31] = 11
	signer, _ := NewDeploymentSigner(deploymentID, seed)
	receipt, err := signer.SignJobCustodyResultReleaseReceipt(
		fixtureJobCustodyResultReleaseReceiptPayload(deploymentID),
	)
	if err != nil {
		t.Fatal(err)
	}
	mutated := receipt
	mutated.Payload = bytes.Replace(
		mutated.Payload,
		[]byte(`"releasedAtMilliseconds":1800000000300`),
		[]byte(`"releasedAtMilliseconds":1800000000301`), 1,
	)
	if _, err := mutated.VerifiedPayload(); err == nil {
		t.Fatal("mutated release time retained a valid receipt")
	}
	attackerSeed := bytes.Repeat([]byte{0}, 32)
	attackerSeed[31] = 12
	attacker, _ := NewDeploymentSigner(
		uuid.MustParse("9b000000-0000-0000-0000-000000000009"), attackerSeed,
	)
	attackerReceipt, err := attacker.SignJobCustodyResultReleaseReceipt(
		fixtureJobCustodyResultReleaseReceiptPayload(attacker.DeploymentID()),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := attackerReceipt.Authorize(fixtureDeploymentDescriptor(t, signer)); err == nil {
		t.Fatal("different Job Custody deployment authorized release receipt")
	}
}

func fixtureJobCustodyResultReleaseReceiptPayload(
	deploymentID uuid.UUID,
) JobCustodyResultReleaseReceiptPayload {
	return JobCustodyResultReleaseReceiptPayload{
		AssignmentID:                 uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		CustodyReceiptDigest:         jobCustodyReceiptTestDigest("custody-receipt"),
		DeliveryAcknowledgedAtMillis: 1_800_000_000_200,
		DeploymentID:                 deploymentID,
		InputCapsuleID:               uuid.MustParse("33333333-3333-4333-8333-333333333333"),
		Kind:                         JobCustodyResultReleaseReceiptKind,
		ReleasedAtMilliseconds:       1_800_000_000_300,
		ResultCapsuleID:              uuid.MustParse("44444444-4444-4444-8444-444444444444"),
		ResultSetDigest:              jobCustodyReceiptTestDigest("result-set"),
		SourceDeliveryReceiptDigest:  jobCustodyReceiptTestDigest("source-delivery"),
		SourceReleaseReceiptDigest:   jobCustodyReceiptTestDigest("source-release"),
		Version:                      JobCustodyResultReleaseReceiptVersion,
	}
}
