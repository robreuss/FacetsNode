package serviceauthority

import (
	"testing"

	"github.com/google/uuid"
)

func TestMigrationCancellationAcceptanceBindsDeploymentAndExactEvidence(t *testing.T) {
	fixture := decodeMigrationPortableFixture(t)
	evidence := fixture.CancellationEvidence
	cancellation, err := evidence.CancellationManifest.VerifiedPayload()
	if err != nil || cancellation.Migration == nil {
		t.Fatalf("cancellation=%+v err=%v", cancellation, err)
	}
	signer := fixtureDeploymentSigner(t, cancellation.ActiveDeployment)
	digest, err := evidence.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	payload := MigrationCancellationAcceptancePayload{
		AcceptedAtMilliseconds:     cancellation.ValidFromMilliseconds,
		CancellationEvidenceDigest: digest,
		LocalDeploymentID:          signer.DeploymentID(),
		MigrationID:                cancellation.Migration.MigrationID,
		Scope:                      cancellation.Scope,
		Version:                    SchemaVersion,
	}
	acceptance, err := signer.SignMigrationCancellationAcceptance(payload)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := acceptance.VerifiedPayload()
	if err != nil || verified != payload {
		t.Fatalf("verified=%+v err=%v", verified, err)
	}
	tampered := acceptance
	tampered.Payload = append([]byte(nil), acceptance.Payload...)
	tampered.Payload[0] ^= 0x01
	if _, err := tampered.VerifiedPayload(); err == nil {
		t.Fatal("tampered cancellation acceptance was verified")
	}
	wrong := payload
	wrong.LocalDeploymentID = uuid.New()
	if _, err := signer.SignMigrationCancellationAcceptance(wrong); err == nil {
		t.Fatal("signer accepted another local deployment")
	}
}
