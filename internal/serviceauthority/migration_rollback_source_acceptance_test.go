package serviceauthority

import (
	"testing"

	"github.com/google/uuid"
)

func TestMigrationRollbackSourceAcceptanceBindsOperationAndDeployment(t *testing.T) {
	fixture := decodeMigrationPortableFixture(t)
	activation, err := fixture.RollbackEvidence.ActivationEvidence.
		ActivationManifest.VerifiedPayload()
	if err != nil || activation.Migration == nil {
		t.Fatalf("activation=%+v err=%v", activation, err)
	}
	digest, err := fixture.RollbackEvidence.ActivationEvidence.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	signer := fixtureDeploymentSigner(t, activation.ActiveDeployment)
	payload := MigrationRollbackSourceAcceptancePayload{
		AcceptedAtMilliseconds:   activation.ValidFromMilliseconds,
		ActivationEvidenceDigest: digest,
		BlobInventoryArtifactID:  uuid.MustParse("81000000-0000-0000-0000-000000000004"),
		ExportWriteFenceID:       uuid.MustParse("81000000-0000-0000-0000-000000000001"),
		LocalDeploymentID:        activation.ActiveDeployment.DeploymentID,
		MigrationID:              activation.Migration.MigrationID,
		Scope:                    activation.Scope,
		ServiceStateArtifactID:   uuid.MustParse("81000000-0000-0000-0000-000000000003"),
		SnapshotID:               uuid.MustParse("81000000-0000-0000-0000-000000000002"),
		Version:                  SchemaVersion,
	}
	acceptance, err := signer.SignMigrationRollbackSourceAcceptance(payload)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := acceptance.VerifiedPayload()
	if err != nil || verified != payload {
		t.Fatalf("verified=%+v err=%v", verified, err)
	}

	wrongDeployment := payload
	wrongDeployment.LocalDeploymentID = activation.Migration.SourceDeploymentID
	if _, err := signer.SignMigrationRollbackSourceAcceptance(
		wrongDeployment,
	); err == nil {
		t.Fatal("rollback source operation signed for another deployment")
	}
	invalidArtifacts := payload
	invalidArtifacts.BlobInventoryArtifactID = invalidArtifacts.ServiceStateArtifactID
	if _, err := signer.SignMigrationRollbackSourceAcceptance(
		invalidArtifacts,
	); err == nil {
		t.Fatal("rollback source operation accepted conflicting artifact identities")
	}

	acceptanceDigest, err := acceptance.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	snapshotDigest, err := fixture.RollbackEvidence.TargetSnapshot.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	snapshotPayload, err := fixture.RollbackEvidence.TargetSnapshot.VerifiedPayload(nil)
	if err != nil {
		t.Fatal(err)
	}
	preparedPayload := MigrationRollbackSourcePreparedPayload{
		AcceptanceReferenceDigest: acceptanceDigest,
		LocalDeploymentID:         payload.LocalDeploymentID,
		MigrationID:               payload.MigrationID,
		Scope:                     payload.Scope,
		SnapshotID:                payload.SnapshotID,
		SnapshotReferenceDigest:   snapshotDigest,
		StateCommitmentDigest:     snapshotPayload.StateCommitmentDigest,
		Version:                   SchemaVersion,
	}
	prepared, err := signer.SignMigrationRollbackSourcePrepared(preparedPayload)
	if err != nil {
		t.Fatal(err)
	}
	verifiedPrepared, err := prepared.VerifiedPayload()
	if err != nil || verifiedPrepared != preparedPayload {
		t.Fatalf("verified prepared=%+v err=%v", verifiedPrepared, err)
	}
	wrongPrepared := preparedPayload
	wrongPrepared.LocalDeploymentID = activation.Migration.SourceDeploymentID
	if _, err := signer.SignMigrationRollbackSourcePrepared(wrongPrepared); err == nil {
		t.Fatal("rollback source prepared evidence signed for another deployment")
	}
}
