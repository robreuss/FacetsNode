package serviceauthority

import (
	"testing"

	"github.com/google/uuid"
)

func TestMigrationActivationAcceptanceBindsLocalDeploymentAndExactEvidence(t *testing.T) {
	fixture := decodeMigrationPortableFixture(t)
	evidence := fixture.RollbackEvidence.ActivationEvidence
	activation, err := evidence.ActivationManifest.VerifiedPayload()
	if err != nil || activation.Migration == nil {
		t.Fatalf("activation=%+v err=%v", activation, err)
	}
	digest, err := evidence.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	snapshotDigest, err := evidence.Snapshot.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	signer := fixtureDeploymentSigner(t, activation.ActiveDeployment)
	record, err := signer.SignMigrationActivationAcceptance(
		MigrationActivationAcceptancePayload{
			AcceptedAtMilliseconds:   3_200,
			ActivationEvidenceDigest: digest,
			LocalDeploymentID:        signer.DeploymentID(),
			MigrationID:              activation.Migration.MigrationID,
			Scope:                    activation.Scope,
			SnapshotReferenceDigest:  snapshotDigest,
			Version:                  SchemaVersion,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := record.VerifiedPayload()
	if err != nil || payload.LocalDeploymentID != signer.DeploymentID() ||
		payload.ActivationEvidenceDigest != fixture.ActivationEvidenceDigest {
		t.Fatalf("acceptance=%+v err=%v", payload, err)
	}
	tampered := record
	tampered.Payload = append([]byte(nil), record.Payload...)
	tampered.Payload[len(tampered.Payload)-1] ^= 0x01
	if _, err := tampered.VerifiedPayload(); err == nil {
		t.Fatal("tampered activation acceptance was verified")
	}
	wrong := payload
	wrong.LocalDeploymentID = uuid.New()
	if _, err := signer.SignMigrationActivationAcceptance(wrong); err == nil {
		t.Fatal("signer accepted another local deployment identity")
	}
}
