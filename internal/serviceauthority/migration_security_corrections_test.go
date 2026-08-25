package serviceauthority

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestCanonicalES256RejectsHighSAndNonCanonicalBase64URL(t *testing.T) {
	fixture := newBootstrapFixture(t)
	manifest := fixture.signedManifest(t, fixture.policy)
	if _, err := manifest.VerifiedPayload(); err != nil {
		t.Fatal(err)
	}

	highS := manifest
	highS.Signature = highSSignature(t, manifest.Signature)
	if _, err := highS.VerifiedPayload(); err == nil {
		t.Fatal("high-S authority signature accepted")
	}
	if _, err := highS.ReferenceDigest(); err == nil {
		t.Fatal("high-S authority signature received a reference digest")
	}

	nonCanonical := manifest
	nonCanonical.Signature.Signature = equivalentNonCanonicalBase64URL(
		t,
		manifest.Signature.Signature,
	)
	if _, err := nonCanonical.VerifiedPayload(); err == nil {
		t.Fatal("noncanonical base64url authority signature accepted")
	}
}

func TestBulkGrantRejectsHighSES256(t *testing.T) {
	deploymentID := uuid.New()
	seed := make([]byte, 32)
	seed[31] = 9
	signer, err := NewDeploymentSigner(deploymentID, seed)
	if err != nil {
		t.Fatal(err)
	}
	payload := BulkGrantPayload{
		AuthorityManifestDigest: strings.Repeat("a", 64),
		DeploymentID:            deploymentID,
		Direction:               BulkUpload,
		ExpiresAtMilliseconds:   2_000,
		GrantID:                 uuid.New(),
		MaximumByteCount:        1,
		NotBeforeMilliseconds:   1_000,
		ResourceID:              "canonical-es256-test",
		RouteID:                 uuid.New(),
		Scope:                   Scope{Kind: ScopeDeviceSync, ScopeID: uuid.New()},
		Version:                 SchemaVersion,
	}
	grant, err := signer.SignBulkTransferGrant(payload)
	if err != nil || verifyBulkTransferGrant(grant, payload, signer) != nil {
		t.Fatalf("canonical bulk grant rejected: %v", err)
	}
	grant.Signature = highSSignature(t, grant.Signature)
	if verifyBulkTransferGrant(grant, payload, signer) == nil {
		t.Fatal("high-S bulk grant accepted")
	}
}

func TestMigrationTransitionsRejectPolicySmugglingAndUnsafeRollbackTiming(t *testing.T) {
	fixture := decodeMigrationPortableFixture(t)
	activation := fixture.RollbackEvidence.ActivationEvidence
	current, err := activation.Preparation.CurrentManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := activation.Preparation.PreparationManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateManifestTransition(current, prepared); err != nil {
		t.Fatalf("portable preparation is not a valid transition: %v", err)
	}

	smuggledPreparation := prepared
	smuggledPreparation.TransportPolicy.AllowsPublicDirectBulkTransfer =
		!prepared.TransportPolicy.AllowsPublicDirectBulkTransfer
	if err := validateManifestTransition(current, smuggledPreparation); err == nil {
		t.Fatal("migration preparation changed transport policy")
	}

	activated, err := activation.ActivationManifest.VerifiedPayload()
	if err != nil || activated.Migration == nil ||
		activated.Migration.RollbackUntilMilliseconds == nil {
		t.Fatalf("invalid activation fixture: payload=%+v err=%v", activated, err)
	}
	deadline := *activated.Migration.RollbackUntilMilliseconds
	shortValidity := activated
	endsEarly := deadline - 1
	shortValidity.ValidUntilMilliseconds = &endsEarly
	if err := validateManifestTransition(prepared, shortValidity); err == nil {
		t.Fatal("activation expiring before rollback deadline accepted")
	}

	retirement := activated
	retirement.Transition = TransitionMigrationRetirement
	retirement.PreparedDeployments = []DeploymentDescriptor{}
	retirement.ValidFromMilliseconds = deadline - 1
	retirement.ValidUntilMilliseconds = nil
	if err := validateManifestTransition(activated, retirement); err == nil {
		t.Fatal("migration retired before rollback deadline")
	}
	retirement.ValidFromMilliseconds = deadline
	if err := validateManifestTransition(activated, retirement); err != nil {
		t.Fatalf("retirement at rollback deadline rejected: %v", err)
	}
	retirement.TransportPolicy.AllowsPublicDirectBulkTransfer =
		!activated.TransportPolicy.AllowsPublicDirectBulkTransfer
	if err := validateManifestTransition(activated, retirement); err == nil {
		t.Fatal("migration retirement changed transport policy")
	}
}

func TestMigrationSnapshotRequiresCurrentCanonicalServiceState(t *testing.T) {
	fixture := decodeMigrationPortableFixture(t)
	activation := fixture.RollbackEvidence.ActivationEvidence
	payload, err := activation.Snapshot.VerifiedPayload(nil)
	if err != nil {
		t.Fatal(err)
	}

	withoutState := payload
	withoutState.Artifacts = []MigrationArtifactDescriptor{{
		ArtifactID:     payload.Artifacts[0].ArtifactID,
		ByteCount:      1,
		Kind:           ArtifactBlobInventory,
		TransferDigest: strings.Repeat("a", 64),
	}}
	if withoutState.Validate(nil) == nil {
		t.Fatal("snapshot without service state accepted")
	}

	duplicateKind := payload
	duplicate := payload.Artifacts[0]
	duplicate.ArtifactID[15] ^= 1
	duplicateKind.Artifacts = append(duplicateKind.Artifacts, duplicate)
	if duplicateKind.Validate(nil) == nil {
		t.Fatal("snapshot with duplicate semantic artifact kind accepted")
	}

	prepared, err := activation.Preparation.PreparationManifest.VerifiedPayload()
	if err != nil || prepared.Migration == nil {
		t.Fatal(err)
	}
	target, err := activation.Preparation.TargetOffer.VerifiedPayload(nil)
	if err != nil {
		t.Fatal(err)
	}
	targetOffer, err := target.DeploymentOffer.VerifiedPayload(nil)
	if err != nil {
		t.Fatal(err)
	}
	stalePayload := payload
	stalePayload.CapturedAtMilliseconds = prepared.ValidFromMilliseconds - 1
	stalePayload.ExpiresAtMilliseconds = prepared.ValidFromMilliseconds + 1_000
	encoded, err := canonicalJSON(stalePayload)
	if err != nil {
		t.Fatal(err)
	}
	sourceSigner := fixtureDeploymentSigner(t, prepared.ActiveDeployment)
	signature, err := sourceSigner.signRecord(migrationSnapshotSignatureDomain, encoded)
	if err != nil {
		t.Fatal(err)
	}
	stale := MigrationSnapshot{Payload: encoded, Signature: signature}
	if _, err := stale.validateTransfer(
		activation.Preparation.PreparationManifest,
		prepared,
		*prepared.Migration,
		prepared.ActiveDeployment,
		targetOffer.Deployment,
		prepared.ValidFromMilliseconds,
	); err == nil {
		t.Fatal("snapshot captured before preparation authority became valid")
	}
}

func TestMigrationTransferSurvivesOnlyPredecessorManifestExpiry(t *testing.T) {
	fixture := decodeMigrationPortableFixture(t)
	preparation := fixture.RollbackEvidence.ActivationEvidence.Preparation
	current, err := preparation.CurrentManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	validUntil := int64(3_000)
	current.ValidUntilMilliseconds = &validUntil
	currentManifest := signedAuthorityManifest(
		t,
		current,
		fixtureAuthorityPrivateKey(t, fixture.AuthorityAnchor),
		fixture.AuthorityAnchor,
	)
	currentDigest, err := currentManifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}

	target, err := preparation.TargetOffer.VerifiedPayload(nil)
	if err != nil {
		t.Fatal(err)
	}
	target.SourceManifestDigest = currentDigest
	offered, err := target.DeploymentOffer.VerifiedPayload(nil)
	if err != nil {
		t.Fatal(err)
	}
	targetOffer, err := fixtureDeploymentSigner(
		t,
		offered.Deployment,
	).SignMigrationTargetOffer(target)
	if err != nil {
		t.Fatal(err)
	}
	targetDigest, err := targetOffer.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}

	prepared, err := preparation.PreparationManifest.VerifiedPayload()
	if err != nil || prepared.Migration == nil {
		t.Fatal(err)
	}
	prepared.PredecessorManifestDigest = &currentDigest
	migration := *prepared.Migration
	migration.TargetMigrationOfferDigest = targetDigest
	prepared.Migration = &migration
	preparedManifest := signedAuthorityManifest(
		t,
		prepared,
		fixtureAuthorityPrivateKey(t, fixture.AuthorityAnchor),
		fixture.AuthorityAnchor,
	)
	bounded := MigrationPreparation{
		CurrentManifest:     currentManifest,
		PreparationManifest: preparedManifest,
		TargetOffer:         targetOffer,
	}

	if _, _, err := bounded.Validate(fixture.AuthorityAnchor, 3_500); err == nil {
		t.Fatal("ordinary preparation validation accepted an expired predecessor")
	}
	if _, _, err := bounded.validateForTransfer(
		fixture.AuthorityAnchor,
		3_500,
	); err != nil {
		t.Fatalf("transfer validation rejected a live preparation after only its predecessor expired: %v", err)
	}

	preparedDigest, err := preparedManifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	fixtureActivation := fixture.RollbackEvidence.ActivationEvidence
	snapshotPayload, err := fixtureActivation.Snapshot.VerifiedPayload(nil)
	if err != nil {
		t.Fatal(err)
	}
	snapshotPayload.AuthorityManifestDigest = preparedDigest
	snapshotEncoded, err := canonicalJSON(snapshotPayload)
	if err != nil {
		t.Fatal(err)
	}
	sourceSigner := fixtureDeploymentSigner(t, prepared.ActiveDeployment)
	snapshotSignature, err := sourceSigner.signRecord(
		migrationSnapshotSignatureDomain,
		snapshotEncoded,
	)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := MigrationSnapshot{Payload: snapshotEncoded, Signature: snapshotSignature}
	snapshotDigest, err := snapshot.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	readinessPayload, err := fixtureActivation.Readiness.VerifiedPayload(nil)
	if err != nil {
		t.Fatal(err)
	}
	readinessPayload.AuthorityManifestDigest = preparedDigest
	readinessPayload.SnapshotReferenceDigest = snapshotDigest
	readiness, err := fixtureDeploymentSigner(t, offered.Deployment).
		SignMigrationReadiness(readinessPayload)
	if err != nil {
		t.Fatal(err)
	}
	activationPayload, err := fixtureActivation.ActivationManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	activationPayload.Migration = &migration
	activationPayload.PredecessorManifestDigest = &preparedDigest
	activationPrerequisiteDigest, err := (MigrationActivationPrerequisites{
		Preparation: bounded,
		Readiness:   readiness,
		Snapshot:    snapshot,
	}).ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	activationPayload.MigrationPrerequisiteEvidenceDigest = &activationPrerequisiteDigest
	activationManifest := signedAuthorityManifest(
		t,
		activationPayload,
		fixtureAuthorityPrivateKey(t, fixture.AuthorityAnchor),
		fixture.AuthorityAnchor,
	)
	boundedActivation := MigrationActivationEvidence{
		ActivationManifest: activationManifest,
		Preparation:        bounded,
		Readiness:          readiness,
		Snapshot:           snapshot,
	}
	if _, err := boundedActivation.Validate(fixture.AuthorityAnchor, 3_500); err != nil {
		t.Fatalf("activation rejected after only its predecessor expired: %v", err)
	}

	expiredPreparationPayload := prepared
	preparationValidUntil := int64(3_400)
	expiredPreparationPayload.ValidUntilMilliseconds = &preparationValidUntil
	expiredPreparation := bounded
	expiredPreparation.PreparationManifest = signedAuthorityManifest(
		t,
		expiredPreparationPayload,
		fixtureAuthorityPrivateKey(t, fixture.AuthorityAnchor),
		fixture.AuthorityAnchor,
	)
	if _, _, err := expiredPreparation.validateForTransfer(
		fixture.AuthorityAnchor,
		3_500,
	); err == nil {
		t.Fatal("transfer accepted an expired preparation manifest")
	}
	if _, _, err := bounded.validateForTransfer(
		fixture.AuthorityAnchor,
		target.ExpiresAtMilliseconds,
	); err == nil {
		t.Fatal("transfer accepted an expired target offer")
	}
}

func TestMigrationCancellationRequiresExactPreparedAuthority(t *testing.T) {
	fixture := decodeMigrationPortableFixture(t)
	preparation := fixture.RollbackEvidence.ActivationEvidence.Preparation
	prepared, err := preparation.PreparationManifest.VerifiedPayload()
	if err != nil || prepared.Migration == nil {
		t.Fatal(err)
	}
	predecessorDigest, err := preparation.PreparationManifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	cancelledPayload := ManifestPayload{
		ActiveDeployment:          prepared.ActiveDeployment,
		IssuedAtMilliseconds:      prepared.ValidFromMilliseconds + 500,
		Migration:                 prepared.Migration,
		PredecessorManifestDigest: &predecessorDigest,
		PreparedDeployments:       []DeploymentDescriptor{},
		Revision:                  prepared.Revision + 1,
		Scope:                     prepared.Scope,
		Transition:                TransitionMigrationCancellation,
		TransportPolicy:           prepared.TransportPolicy,
		ValidFromMilliseconds:     prepared.ValidFromMilliseconds + 500,
		Version:                   SchemaVersion,
	}
	cancellation := signedAuthorityManifest(
		t,
		cancelledPayload,
		fixtureAuthorityPrivateKey(t, fixture.AuthorityAnchor),
		fixture.AuthorityAnchor,
	)
	evidence := MigrationCancellationEvidence{
		CancellationManifest: cancellation,
		Preparation:          preparation,
	}
	if payload, err := evidence.Validate(
		fixture.AuthorityAnchor,
		cancelledPayload.ValidFromMilliseconds,
	); err != nil || payload.Transition != TransitionMigrationCancellation {
		t.Fatalf("valid cancellation rejected: payload=%+v err=%v", payload, err)
	}

	smuggled := cancelledPayload
	smuggled.TransportPolicy.AllowsPublicDirectBulkTransfer =
		!cancelledPayload.TransportPolicy.AllowsPublicDirectBulkTransfer
	evidence.CancellationManifest = signedAuthorityManifest(
		t,
		smuggled,
		fixtureAuthorityPrivateKey(t, fixture.AuthorityAnchor),
		fixture.AuthorityAnchor,
	)
	if _, err := evidence.Validate(
		fixture.AuthorityAnchor,
		cancelledPayload.ValidFromMilliseconds,
	); err == nil {
		t.Fatal("policy-smuggling cancellation accepted")
	}
}

func TestCustodyOpenRejectsStructurallyValidUnsignedReplacement(t *testing.T) {
	fixture := decodeMigrationPortableFixture(t)
	activation := fixture.RollbackEvidence.ActivationEvidence
	privateKey, err := canonicalBase64URL(fixture.TargetCustodyPrivateKeyRawRepresentation)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := fixture.CustodyEnvelope.Open(
		privateKey,
		activation.Preparation,
		activation.Snapshot,
		fixture.AuthorityAnchor,
		3_200,
	)
	if err != nil {
		t.Fatalf("fixture custody envelope rejected: %v", err)
	}
	expected, err := canonicalBase64URL(fixture.CustodyPlaintext)
	if err != nil || !bytes.Equal(plaintext, expected) {
		t.Fatal("custody plaintext changed")
	}

	forged := fixture.CustodyEnvelope
	sealed, err := canonicalBase64URL(forged.SealedPayload)
	if err != nil {
		t.Fatal(err)
	}
	sealed[len(sealed)-1] ^= 1
	forged.SealedPayload = encodeBase64URL(sealed)
	if forged.Validate() != nil {
		t.Fatal("forged envelope is not structurally valid")
	}
	if _, err := forged.Open(
		privateKey,
		activation.Preparation,
		activation.Snapshot,
		fixture.AuthorityAnchor,
		3_200,
	); err == nil {
		t.Fatal("custody envelope absent from source-signed snapshot accepted")
	}
}

func TestMigrationEvidenceDigestUsesDedicatedBound(t *testing.T) {
	evidence := struct {
		Value string `json:"value"`
	}{Value: strings.Repeat("x", 300_000)}
	if _, err := canonicalJSON(evidence); err == nil {
		t.Fatal("oversized signed record admitted")
	}
	if _, err := migrationEvidenceDigest("test\x00", evidence); err != nil {
		t.Fatalf("bounded nested migration evidence rejected: %v", err)
	}
	evidence.Value = strings.Repeat("x", maximumMigrationEvidenceByteCount)
	if _, err := migrationEvidenceDigest("test\x00", evidence); err == nil {
		t.Fatal("migration evidence exceeded dedicated encoding bound")
	}
}

func highSSignature(t *testing.T, signature Signature) Signature {
	t.Helper()
	raw, err := base64.RawURLEncoding.Strict().DecodeString(signature.Signature)
	if err != nil || len(raw) != 64 {
		t.Fatal("invalid test signature")
	}
	s := new(big.Int).SetBytes(raw[32:])
	s.Sub(elliptic.P256().Params().N, s)
	s.FillBytes(raw[32:])
	signature.Signature = base64.RawURLEncoding.EncodeToString(raw)
	return signature
}

func equivalentNonCanonicalBase64URL(t *testing.T, value string) string {
	t.Helper()
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	if value == "" {
		t.Fatal("empty base64url test value")
	}
	last := strings.IndexByte(alphabet, value[len(value)-1])
	if last < 0 || last%4 != 0 || last+1 >= len(alphabet) {
		t.Fatalf("unexpected canonical final base64url character %q", value[len(value)-1])
	}
	variant := value[:len(value)-1] + string(alphabet[last+1])
	canonicalBytes, canonicalErr := base64.RawURLEncoding.DecodeString(value)
	variantBytes, variantErr := base64.RawURLEncoding.DecodeString(variant)
	if canonicalErr != nil || variantErr != nil || !bytes.Equal(canonicalBytes, variantBytes) {
		t.Fatal("test variant did not preserve decoded signature bytes")
	}
	return variant
}

func fixtureAuthorityPrivateKey(t *testing.T, anchor TrustAnchor) *ecdsa.PrivateKey {
	t.Helper()
	for scalar := byte(1); scalar <= 16; scalar++ {
		seed := make([]byte, 32)
		seed[31] = scalar
		key := testPrivateKey(t, seed)
		public := elliptic.Marshal(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y)
		if base64.RawURLEncoding.EncodeToString(public) == anchor.PublicSigningKeyX963 {
			return key
		}
	}
	t.Fatal("portable fixture authority key is outside deterministic test range")
	return nil
}

func signedAuthorityManifest(
	t *testing.T,
	payload ManifestPayload,
	key *ecdsa.PrivateKey,
	anchor TrustAnchor,
) Manifest {
	t.Helper()
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return Manifest{
		Payload: encoded,
		Signature: signTestAuthorityRecord(
			t,
			key,
			anchor.SignerID,
			"Facets service authority manifest v1\x00",
			encoded,
		),
	}
}
