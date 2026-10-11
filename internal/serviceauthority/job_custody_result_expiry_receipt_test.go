package serviceauthority

import (
	"bytes"
	"testing"

	"github.com/google/uuid"
)

func TestJobCustodyResultExpiryReceiptBindsRetentionAndOptionalDelivery(t *testing.T) {
	deploymentID := uuid.MustParse("9c000000-0000-0000-0000-000000000001")
	seed := bytes.Repeat([]byte{0}, 32)
	seed[31] = 13
	signer, err := NewDeploymentSigner(deploymentID, seed)
	if err != nil {
		t.Fatal(err)
	}
	payload := fixtureJobCustodyResultExpiryReceiptPayload(deploymentID)
	receipt, err := signer.SignJobCustodyResultExpiryReceipt(payload)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := receipt.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeJobCustodyResultExpiryReceipt(encoded)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := decoded.Authorize(fixtureDeploymentDescriptor(t, signer))
	if err != nil || verified != payload {
		t.Fatalf("authorized payload=%+v err=%v", verified, err)
	}
	undelivered := payload
	undelivered.DeliveryAcknowledgedAtMillis = 0
	undelivered.SourceDeliveryReceiptDigest = ""
	if _, err := signer.SignJobCustodyResultExpiryReceipt(undelivered); err != nil {
		t.Fatalf("undelivered expiry rejected: %v", err)
	}
}

func TestJobCustodyResultExpiryReceiptRejectsMutationAndPartialDelivery(t *testing.T) {
	deploymentID := uuid.MustParse("9c000000-0000-0000-0000-000000000001")
	seed := bytes.Repeat([]byte{0}, 32)
	seed[31] = 13
	signer, _ := NewDeploymentSigner(deploymentID, seed)
	payload := fixtureJobCustodyResultExpiryReceiptPayload(deploymentID)
	receipt, err := signer.SignJobCustodyResultExpiryReceipt(payload)
	if err != nil {
		t.Fatal(err)
	}
	mutated := receipt
	mutated.Payload = bytes.Replace(mutated.Payload,
		[]byte(`"expiredAtMilliseconds":1800000000400`),
		[]byte(`"expiredAtMilliseconds":1800000000401`), 1)
	if _, err := mutated.VerifiedPayload(); err == nil {
		t.Fatal("mutated expiry time retained a valid receipt")
	}
	partial := payload
	partial.SourceDeliveryReceiptDigest = ""
	if _, err := signer.SignJobCustodyResultExpiryReceipt(partial); err == nil {
		t.Fatal("partial source delivery evidence was accepted")
	}
}

func fixtureJobCustodyResultExpiryReceiptPayload(
	deploymentID uuid.UUID,
) JobCustodyResultExpiryReceiptPayload {
	return JobCustodyResultExpiryReceiptPayload{
		AssignmentID:                 uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		CustodyReceiptDigest:         jobCustodyReceiptTestDigest("custody-receipt"),
		DeliveryAcknowledgedAtMillis: 1_800_000_000_200,
		DeploymentID:                 deploymentID,
		ExpiredAtMilliseconds:        1_800_000_000_400,
		InputCapsuleID:               uuid.MustParse("33333333-3333-4333-8333-333333333333"),
		Kind:                         JobCustodyResultExpiryReceiptKind,
		ResultCapsuleID:              uuid.MustParse("44444444-4444-4444-8444-444444444444"),
		ResultSetDigest:              jobCustodyReceiptTestDigest("result-set"),
		RetentionUntilMilliseconds:   1_800_000_000_300,
		SourceDeliveryReceiptDigest:  jobCustodyReceiptTestDigest("source-delivery"),
		Version:                      JobCustodyResultExpiryReceiptVersion,
	}
}
