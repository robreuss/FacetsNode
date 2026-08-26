package serviceauthority

import (
	"testing"

	"github.com/google/uuid"
)

func TestMigrationRetirementAcceptanceBindsDeploymentAndExactEvidence(t *testing.T) {
	fixture := decodeMigrationPortableFixture(t)
	evidence := fixture.RetirementEvidence
	retirement, err := evidence.RetirementManifest.VerifiedPayload()
	if err != nil || retirement.Migration == nil {
		t.Fatalf("retirement=%+v err=%v", retirement, err)
	}
	digest, err := evidence.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	signer := fixtureDeploymentSigner(t, retirement.ActiveDeployment)
	payload := MigrationRetirementAcceptancePayload{
		AcceptedAtMilliseconds:   retirement.ValidFromMilliseconds,
		LocalDeploymentID:        signer.DeploymentID(),
		MigrationID:              retirement.Migration.MigrationID,
		RetirementEvidenceDigest: digest,
		Scope:                    retirement.Scope,
		Version:                  SchemaVersion,
	}
	acceptance, err := signer.SignMigrationRetirementAcceptance(payload)
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
		t.Fatal("tampered retirement acceptance was verified")
	}
	wrong := payload
	wrong.LocalDeploymentID = uuid.New()
	if _, err := signer.SignMigrationRetirementAcceptance(wrong); err == nil {
		t.Fatal("signer accepted another local deployment")
	}
}
