package serviceauthority

import (
	"bytes"
	"testing"

	"github.com/google/uuid"
)

func TestMigrationPreparationReferenceDigestMatchesPortableFixture(t *testing.T) {
	fixture := decodeMigrationPortableFixture(t)
	preparation := fixture.RollbackEvidence.ActivationEvidence.Preparation

	digest, err := preparation.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	if digest != fixture.PreparationEvidenceDigest {
		t.Fatalf("preparation digest=%s, want %s", digest, fixture.PreparationEvidenceDigest)
	}

	tampered := preparation
	tampered.TargetOffer.Payload = append([]byte(nil), preparation.TargetOffer.Payload...)
	tampered.TargetOffer.Payload[len(tampered.TargetOffer.Payload)-1] ^= 0x01
	tamperedDigest, err := tampered.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	if tamperedDigest == digest {
		t.Fatal("changed preparation evidence retained its reference digest")
	}
}

func TestMigrationSnapshotValidatesExactPreparedTransfer(t *testing.T) {
	fixture := decodeMigrationPortableFixture(t)
	activation := fixture.RollbackEvidence.ActivationEvidence

	validated, err := activation.Snapshot.ValidatePreparedTransfer(
		activation.Preparation,
		fixture.AuthorityAnchor,
		3_200,
	)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := activation.Preparation.PreparationManifest.VerifiedPayload()
	if err != nil || prepared.Migration == nil {
		t.Fatal("fixture preparation is invalid")
	}
	target, err := activation.Preparation.TargetOffer.VerifiedPayload(nil)
	if err != nil {
		t.Fatal(err)
	}
	targetDeployment, err := target.DeploymentOffer.VerifiedPayload(nil)
	if err != nil {
		t.Fatal(err)
	}
	expectedSnapshot, err := activation.Snapshot.VerifiedPayload(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !migrationEqual(&validated.Migration, prepared.Migration) ||
		!canonicalEqual(validated.PreparationManifest, prepared) ||
		!canonicalEqual(validated.TargetOffer, target) ||
		!canonicalEqual(validated.TargetDeploymentOffer, targetDeployment) ||
		!canonicalEqual(validated.Snapshot, expectedSnapshot) {
		t.Fatal("validated transfer facts differ from the signed preparation or snapshot")
	}
}

func TestMigrationSnapshotPreparedTransferRejectsTamperWrongAnchorTargetAndExpiry(t *testing.T) {
	fixture := decodeMigrationPortableFixture(t)
	activation := fixture.RollbackEvidence.ActivationEvidence

	t.Run("tampered snapshot", func(t *testing.T) {
		tampered := activation.Snapshot
		tampered.Payload = append([]byte(nil), tampered.Payload...)
		tampered.Payload[len(tampered.Payload)-1] ^= 0x01
		if _, err := tampered.ValidatePreparedTransfer(
			activation.Preparation,
			fixture.AuthorityAnchor,
			3_200,
		); err == nil {
			t.Fatal("tampered snapshot was accepted")
		}
	})

	t.Run("tampered preparation", func(t *testing.T) {
		tampered := activation.Preparation
		tampered.TargetOffer.Payload = append(
			[]byte(nil),
			tampered.TargetOffer.Payload...,
		)
		tampered.TargetOffer.Payload[len(tampered.TargetOffer.Payload)-1] ^= 0x01
		if _, err := activation.Snapshot.ValidatePreparedTransfer(
			tampered,
			fixture.AuthorityAnchor,
			3_200,
		); err == nil {
			t.Fatal("tampered preparation was accepted")
		}
	})

	t.Run("wrong authority anchor", func(t *testing.T) {
		wrongAnchor := fixture.AuthorityAnchor
		wrongAnchor.SignerID = uuid.New()
		if _, err := activation.Snapshot.ValidatePreparedTransfer(
			activation.Preparation,
			wrongAnchor,
			3_200,
		); err == nil {
			t.Fatal("snapshot was accepted under another authority anchor")
		}
	})

	t.Run("wrong offered target", func(t *testing.T) {
		payload, err := activation.Snapshot.VerifiedPayload(nil)
		if err != nil {
			t.Fatal(err)
		}
		payload.ImportingDeploymentID = uuid.New()
		encoded, err := canonicalJSON(payload)
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := activation.Preparation.PreparationManifest.VerifiedPayload()
		if err != nil {
			t.Fatal(err)
		}
		sourceSigner := fixtureDeploymentSigner(t, prepared.ActiveDeployment)
		signature, err := sourceSigner.signRecord(migrationSnapshotSignatureDomain, encoded)
		if err != nil {
			t.Fatal(err)
		}
		wrongTarget := MigrationSnapshot{Payload: encoded, Signature: signature}
		if bytes.Equal(wrongTarget.Payload, activation.Snapshot.Payload) {
			t.Fatal("wrong-target test did not change the snapshot payload")
		}
		if _, err := wrongTarget.ValidatePreparedTransfer(
			activation.Preparation,
			fixture.AuthorityAnchor,
			3_200,
		); err == nil {
			t.Fatal("validly source-signed snapshot for another target was accepted")
		}
	})

	t.Run("expired snapshot", func(t *testing.T) {
		if _, err := activation.Snapshot.ValidatePreparedTransfer(
			activation.Preparation,
			fixture.AuthorityAnchor,
			10_000,
		); err == nil {
			t.Fatal("snapshot was accepted at its half-open expiry boundary")
		}
	})
}
