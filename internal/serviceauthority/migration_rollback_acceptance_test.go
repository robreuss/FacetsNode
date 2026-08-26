package serviceauthority

import "testing"

func TestMigrationRollbackAcceptanceBindsDeploymentAndExactEvidence(t *testing.T) {
	fixture := decodeMigrationPortableFixture(t)
	rollback, err := fixture.RollbackEvidence.RollbackManifest.VerifiedPayload()
	if err != nil || rollback.Migration == nil {
		t.Fatalf("rollback=%+v err=%v", rollback, err)
	}
	signer := fixtureDeploymentSigner(t, rollback.ActiveDeployment)
	payload := MigrationRollbackAcceptancePayload{
		AcceptedAtMilliseconds: rollback.ValidFromMilliseconds,
		LocalDeploymentID:      rollback.ActiveDeployment.DeploymentID,
		MigrationID:            rollback.Migration.MigrationID,
		RollbackEvidenceDigest: fixture.RollbackEvidenceDigest,
		Scope:                  rollback.Scope,
		Version:                SchemaVersion,
	}
	acceptance, err := signer.SignMigrationRollbackAcceptance(payload)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := acceptance.VerifiedPayload()
	if err != nil || verified != payload {
		t.Fatalf("verified=%+v err=%v", verified, err)
	}

	wrong := payload
	wrong.LocalDeploymentID = rollback.Migration.TargetDeploymentID
	if _, err := signer.SignMigrationRollbackAcceptance(wrong); err == nil {
		t.Fatal("rollback acceptance signed for another deployment")
	}
}
