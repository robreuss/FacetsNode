package serviceauthority

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
)

//go:embed testdata/service-migration-portable-v1.json
var serviceMigrationPortableFixture []byte

type migrationPortableFixture struct {
	ActivationManifestDigest                 string                    `json:"activationManifestDigest"`
	AuthorityAnchor                          TrustAnchor               `json:"authorityAnchor"`
	CustodyEnvelope                          MigrationCustodyEnvelope  `json:"custodyEnvelope"`
	CustodyPlaintext                         string                    `json:"custodyPlaintext"`
	PreparationManifestDigest                string                    `json:"preparationManifestDigest"`
	RollbackEvidence                         MigrationRollbackEvidence `json:"rollbackEvidence"`
	RollbackManifestDigest                   string                    `json:"rollbackManifestDigest"`
	TargetCustodyPrivateKeyRawRepresentation string                    `json:"targetCustodyPrivateKeyRawRepresentation"`
	TargetOfferDigest                        string                    `json:"targetOfferDigest"`
	Version                                  int                       `json:"version"`
}

func TestSwiftMigrationPortableFixtureValidatesInGo(t *testing.T) {
	fixture := decodeMigrationPortableFixture(t)
	if fixture.Version != SchemaVersion || fixture.AuthorityAnchor.Validate() != nil {
		t.Fatal("invalid portable fixture header or authority anchor")
	}

	activation, err := fixture.RollbackEvidence.ActivationEvidence.Validate(
		fixture.AuthorityAnchor,
		3_200,
	)
	if err != nil || activation.Transition != TransitionMigrationActivation {
		t.Fatalf("Swift activation evidence rejected: payload=%+v err=%v", activation, err)
	}
	activationDigest, err := fixture.RollbackEvidence.ActivationEvidence.
		ActivationManifest.ReferenceDigest()
	if err != nil || activationDigest != fixture.ActivationManifestDigest {
		t.Fatalf("activation digest=%s err=%v", activationDigest, err)
	}
	preparationDigest, err := fixture.RollbackEvidence.ActivationEvidence.
		Preparation.PreparationManifest.ReferenceDigest()
	if err != nil || preparationDigest != fixture.PreparationManifestDigest {
		t.Fatalf("preparation digest=%s err=%v", preparationDigest, err)
	}
	targetDigest, err := fixture.RollbackEvidence.ActivationEvidence.
		Preparation.TargetOffer.ReferenceDigest()
	if err != nil || targetDigest != fixture.TargetOfferDigest {
		t.Fatalf("target offer digest=%s err=%v", targetDigest, err)
	}

	rolledBack, err := fixture.RollbackEvidence.Validate(fixture.AuthorityAnchor, 4_000)
	if err != nil || rolledBack.Transition != TransitionMigrationRollback {
		t.Fatalf("Swift rollback evidence rejected: payload=%+v err=%v", rolledBack, err)
	}
	rollbackDigest, err := fixture.RollbackEvidence.RollbackManifest.ReferenceDigest()
	if err != nil || rollbackDigest != fixture.RollbackManifestDigest {
		t.Fatalf("rollback digest=%s err=%v", rollbackDigest, err)
	}

	preparation, _, err := fixture.RollbackEvidence.ActivationEvidence.
		Preparation.Validate(fixture.AuthorityAnchor, 3_200)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := canonicalBase64URL(fixture.TargetCustodyPrivateKeyRawRepresentation)
	if err != nil {
		t.Fatal(err)
	}
	expectedPlaintext, err := canonicalBase64URL(fixture.CustodyPlaintext)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := fixture.CustodyEnvelope.Open(
		privateKey,
		preparation,
		fixture.RollbackEvidence.ActivationEvidence.Preparation.TargetOffer,
	)
	if err != nil || !bytes.Equal(plaintext, expectedPlaintext) {
		t.Fatalf("Swift custody envelope rejected or changed: plaintext=%q err=%v", plaintext, err)
	}
}

func TestMigrationFixtureRejectsTamperingExpiryAndBareSuccessors(t *testing.T) {
	fixture := decodeMigrationPortableFixture(t)
	activation := fixture.RollbackEvidence.ActivationEvidence
	if _, err := activation.Validate(fixture.AuthorityAnchor, 5_000); err == nil {
		t.Fatal("expired activation readiness accepted")
	}
	if _, err := fixture.RollbackEvidence.Validate(fixture.AuthorityAnchor, 10_000); err == nil {
		t.Fatal("rollback accepted at its strict deadline")
	}

	tampered := fixture.CustodyEnvelope
	sealed, err := canonicalBase64URL(tampered.SealedPayload)
	if err != nil {
		t.Fatal(err)
	}
	sealed[len(sealed)-1] ^= 0x01
	tampered.SealedPayload = encodeBase64URL(sealed)
	preparation, _, err := activation.Preparation.Validate(fixture.AuthorityAnchor, 3_200)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := canonicalBase64URL(fixture.TargetCustodyPrivateKeyRawRepresentation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tampered.Open(
		privateKey,
		preparation,
		activation.Preparation.TargetOffer,
	); err == nil {
		t.Fatal("tampered custody ciphertext accepted")
	}

	manifest := activation.ActivationManifest
	manifest.Payload = append([]byte(nil), manifest.Payload...)
	manifest.Payload[len(manifest.Payload)-1] ^= 0x01
	if _, err := manifest.VerifiedPayload(); err == nil {
		t.Fatal("tampered activation manifest accepted")
	}

	// A signed successor alone is not migration evidence. The generic manifest
	// validator can validate its chain shape, but only the evidence validator
	// establishes the fenced snapshot and target readiness prerequisites.
	if payload, err := activation.ActivationManifest.ValidateSuccessor(
		activation.Preparation.PreparationManifest,
	); err != nil || payload.Transition != TransitionMigrationActivation {
		t.Fatalf("fixture chain unexpectedly invalid: payload=%+v err=%v", payload, err)
	}
}

func TestMigrationContractsRejectMalformedCollectionsAndCustodyKeys(t *testing.T) {
	fixture := decodeMigrationPortableFixture(t)
	snapshot, err := fixture.RollbackEvidence.ActivationEvidence.Snapshot.VerifiedPayload(nil)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := snapshot
	duplicate.Artifacts = append(duplicate.Artifacts, duplicate.Artifacts[0])
	if duplicate.Validate(nil) == nil {
		t.Fatal("duplicate or unsorted migration artifacts accepted")
	}

	target, err := fixture.RollbackEvidence.ActivationEvidence.Preparation.
		TargetOffer.VerifiedPayload(nil)
	if err != nil {
		t.Fatal(err)
	}
	target.CustodyAgreementKeyFingerprint = target.DeploymentOffer.Signature.SigningKeyFingerprint
	if target.Validate(nil) == nil {
		t.Fatal("deployment signing key accepted as custody agreement key")
	}
	manifest, err := fixture.RollbackEvidence.ActivationEvidence.Preparation.
		CurrentManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	manifest.Transition = "unknown_transition"
	if manifest.Validate(nil) == nil {
		t.Fatal("unknown service-authority transition accepted")
	}

	envelope := fixture.CustodyEnvelope
	envelope.Metadata.Kind = ArtifactServiceStateSnapshot
	if envelope.Validate() == nil {
		t.Fatal("bulk service state accepted in small custody envelope")
	}
}

func TestBindingRegistriesPersistFencesAndRequireEvidenceSpecificCutover(t *testing.T) {
	fixture := decodeMigrationPortableFixture(t)
	activation := fixture.RollbackEvidence.ActivationEvidence
	currentPayload, err := activation.Preparation.CurrentManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	currentDigest, err := activation.Preparation.CurrentManifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	sourceID := currentPayload.ActiveDeployment.DeploymentID
	targetPayload, err := activation.Preparation.TargetOffer.VerifiedPayload(nil)
	if err != nil {
		t.Fatal(err)
	}
	targetOffer, err := targetPayload.DeploymentOffer.VerifiedPayload(nil)
	if err != nil {
		t.Fatal(err)
	}
	targetID := targetOffer.Deployment.DeploymentID

	source, sourcePath := newMigrationRegistry(t, sourceID)
	target, targetPath := newMigrationRegistry(t, targetID)
	initialManifest := activation.Preparation.CurrentManifest
	if err := source.Activate(currentPayload.Scope, CurrentBinding{
		Revision: currentPayload.Revision, Digest: currentDigest,
		DeploymentID: sourceID, Manifest: &initialManifest,
	}); err != nil {
		t.Fatalf("source initial activation failed: %v", err)
	}
	if err := target.Activate(currentPayload.Scope, CurrentBinding{
		Revision: currentPayload.Revision, Digest: currentDigest,
		DeploymentID: sourceID, Manifest: &initialManifest,
	}); err == nil {
		t.Fatal("standby accepted an initial manifest that did not name it")
	}

	if err := source.ApplyMigrationPreparation(
		activation.Preparation, fixture.AuthorityAnchor, 2_200,
	); err != nil {
		t.Fatalf("source preparation failed: %v", err)
	}
	if err := target.ApplyMigrationPreparation(
		activation.Preparation, fixture.AuthorityAnchor, 2_200,
	); err != nil {
		t.Fatalf("target preparation failed: %v", err)
	}
	if err := target.ApplyMigrationPreparation(
		activation.Preparation, fixture.AuthorityAnchor, 2_200,
	); err != nil {
		t.Fatalf("exact target preparation retry failed: %v", err)
	}
	if err := target.ApplyMigrationPreparation(
		activation.Preparation, fixture.AuthorityAnchor, 20_000,
	); err != nil {
		t.Fatalf("exact target preparation retry failed after offer expiry: %v", err)
	}

	preparedPayload, err := activation.Preparation.PreparationManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	preparedDigest, err := activation.Preparation.PreparationManifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	sourceRequest := requestForAuthority(
		preparedPayload.Scope, preparedPayload.Revision, preparedDigest, sourceID,
	)
	if err := source.AuthorizeRequest(sourceRequest, http.MethodPost); err != nil {
		t.Fatalf("source write rejected before fence: %v", err)
	}
	forwardSnapshot, err := activation.Snapshot.VerifiedPayload(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := source.StageMigrationWriteFence(
		activation.Preparation.PreparationManifest,
		forwardSnapshot,
		fixture.AuthorityAnchor,
		3_000,
	); err != nil {
		t.Fatalf("source fence staging failed: %v", err)
	}
	if err := source.StageMigrationWriteFence(
		activation.Preparation.PreparationManifest,
		forwardSnapshot,
		fixture.AuthorityAnchor,
		3_000,
	); err != nil {
		t.Fatalf("exact source fence staging retry failed: %v", err)
	}
	if err := source.AuthorizeRequest(sourceRequest, http.MethodGet); err != nil {
		t.Fatalf("source read rejected after fence: %v", err)
	}
	if err := source.AuthorizeRequest(sourceRequest, http.MethodPost); err == nil {
		t.Fatal("source write accepted after durable fence")
	}
	reloadedPendingSource, err := LoadBindingRegistry(sourcePath, sourceID)
	if err != nil {
		t.Fatalf("staged unsigned fence did not survive restart: %v", err)
	}
	if err := reloadedPendingSource.AuthorizeRequest(sourceRequest, http.MethodPost); err == nil {
		t.Fatal("reloaded staged fence accepted a write")
	}
	source = reloadedPendingSource
	if err := source.StageMigrationWriteFence(
		activation.Preparation.PreparationManifest,
		forwardSnapshot,
		fixture.AuthorityAnchor,
		10_000,
	); err != nil {
		t.Fatalf("exact staged fence retry failed after snapshot expiry: %v", err)
	}
	if err := source.ConfirmMigrationWriteFenceSnapshot(
		preparedPayload.Scope,
		activation.Snapshot,
	); err != nil {
		t.Fatalf("source signed snapshot confirmation failed: %v", err)
	}
	if err := target.ApplyMigrationActivation(
		activation, fixture.AuthorityAnchor, 3_200,
	); err != nil {
		t.Fatalf("target activation failed: %v", err)
	}
	if err := source.ApplyMigrationActivation(
		activation, fixture.AuthorityAnchor, 3_200,
	); err != nil {
		t.Fatalf("source activation failed: %v", err)
	}
	if err := target.ApplyMigrationActivation(
		activation, fixture.AuthorityAnchor, 3_200,
	); err != nil {
		t.Fatalf("exact target activation retry failed: %v", err)
	}
	if err := target.ApplyMigrationActivation(
		activation, fixture.AuthorityAnchor, 6_000,
	); err != nil {
		t.Fatalf("exact target activation retry failed after evidence expiry: %v", err)
	}
	tamperedActivation := activation
	tamperedActivation.Readiness.Payload = append(
		[]byte(nil),
		tamperedActivation.Readiness.Payload...,
	)
	tamperedActivation.Readiness.Payload[len(tamperedActivation.Readiness.Payload)-1] ^= 0x01
	if err := target.ApplyMigrationActivation(
		tamperedActivation, fixture.AuthorityAnchor, 3_200,
	); err == nil {
		t.Fatal("changed activation evidence accepted as an exact retry")
	}
	if err := source.ApplyServiceAuthoritySuccessor(
		activation.Preparation.PreparationManifest,
		activation.ActivationManifest,
		fixture.AuthorityAnchor,
		3_200,
	); err == nil {
		t.Fatal("bare activation accepted through generic successor path")
	}
	if err := source.Activate(preparedPayload.Scope, source.bindings[preparedPayload.Scope]); err == nil {
		t.Fatal("migration manifest accepted through initial activation path")
	}

	activatedPayload, err := activation.ActivationManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	activatedDigest, err := activation.ActivationManifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	targetRequest := requestForAuthority(
		activatedPayload.Scope, activatedPayload.Revision, activatedDigest, targetID,
	)
	if err := target.AuthorizeRequest(targetRequest, http.MethodPost); err != nil {
		t.Fatalf("target write rejected after activation: %v", err)
	}
	reverseSnapshot, err := fixture.RollbackEvidence.TargetSnapshot.VerifiedPayload(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := target.StageMigrationWriteFence(
		activation.ActivationManifest,
		reverseSnapshot,
		fixture.AuthorityAnchor,
		4_000,
	); err != nil {
		t.Fatalf("target reverse fence staging failed: %v", err)
	}
	if err := target.ConfirmMigrationWriteFenceSnapshot(
		activatedPayload.Scope,
		fixture.RollbackEvidence.TargetSnapshot,
	); err != nil {
		t.Fatalf("target reverse snapshot confirmation failed: %v", err)
	}
	if err := target.AuthorizeRequest(targetRequest, http.MethodPost); err == nil {
		t.Fatal("target write accepted after reverse fence")
	}

	if err := source.ApplyMigrationRollback(
		fixture.RollbackEvidence, fixture.AuthorityAnchor, 4_000,
	); err != nil {
		t.Fatalf("source rollback failed: %v", err)
	}
	if err := target.ApplyMigrationRollback(
		fixture.RollbackEvidence, fixture.AuthorityAnchor, 4_000,
	); err != nil {
		t.Fatalf("target rollback failed: %v", err)
	}
	if err := target.ApplyMigrationRollback(
		fixture.RollbackEvidence, fixture.AuthorityAnchor, 10_000,
	); err != nil {
		t.Fatalf("exact target rollback retry failed at rollback deadline: %v", err)
	}
	rolledBackPayload, err := fixture.RollbackEvidence.RollbackManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	rolledBackDigest, err := fixture.RollbackEvidence.RollbackManifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	rolledBackRequest := requestForAuthority(
		rolledBackPayload.Scope, rolledBackPayload.Revision, rolledBackDigest, sourceID,
	)
	if err := source.AuthorizeRequest(rolledBackRequest, http.MethodPost); err != nil {
		t.Fatalf("source did not clear its forward fence at validated rollback: %v", err)
	}
	if err := target.AuthorizeRequest(targetRequest, http.MethodGet); err == nil {
		t.Fatal("retired target authorized stale active binding after rollback")
	}

	reloadedSource, err := LoadBindingRegistry(sourcePath, sourceID)
	if err != nil || reloadedSource.AuthorizeRequest(rolledBackRequest, http.MethodPost) != nil {
		t.Fatalf("reloaded source lost rollback activation: registry=%v err=%v", reloadedSource, err)
	}
	reloadedTarget, err := LoadBindingRegistry(targetPath, targetID)
	if err != nil {
		t.Fatalf("reloaded target fence rejected: %v", err)
	}
	if reloadedTarget.bindings[rolledBackPayload.Scope].WriteFence == nil {
		t.Fatal("reloaded target lost its durable reverse fence")
	}
}

func TestNodeSignsOnlyPreviouslyStagedMigrationSnapshots(t *testing.T) {
	fixture := decodeMigrationPortableFixture(t)
	preparation := fixture.RollbackEvidence.ActivationEvidence.Preparation
	current, err := preparation.CurrentManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	currentDigest, err := preparation.CurrentManifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	registry, _ := newMigrationRegistry(t, current.ActiveDeployment.DeploymentID)
	initial := preparation.CurrentManifest
	if err := registry.Activate(current.Scope, CurrentBinding{
		Revision: current.Revision, Digest: currentDigest,
		DeploymentID: current.ActiveDeployment.DeploymentID, Manifest: &initial,
	}); err != nil {
		t.Fatal(err)
	}
	if err := registry.ApplyMigrationPreparation(preparation, fixture.AuthorityAnchor, 2_200); err != nil {
		t.Fatal(err)
	}
	signer := fixtureDeploymentSigner(t, current.ActiveDeployment)
	if _, err := registry.SignStagedMigrationSnapshot(current.Scope, signer); err == nil {
		t.Fatal("deployment signed a snapshot before a durable fence was staged")
	}
	payload, err := fixture.RollbackEvidence.ActivationEvidence.Snapshot.VerifiedPayload(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.StageMigrationWriteFence(
		preparation.PreparationManifest,
		payload,
		fixture.AuthorityAnchor,
		3_000,
	); err != nil {
		t.Fatal(err)
	}
	snapshot, err := registry.SignStagedMigrationSnapshot(current.Scope, signer)
	if err != nil {
		t.Fatalf("staged snapshot signing failed: %v", err)
	}
	verified, err := snapshot.VerifiedPayload(nil)
	if err != nil || !canonicalEqual(verified, payload) {
		t.Fatalf("Node signed a different snapshot payload: verified=%+v err=%v", verified, err)
	}
	if _, err := registry.SignStagedMigrationSnapshot(current.Scope, signer); err == nil {
		t.Fatal("already signed fence produced a second conflicting snapshot")
	}
}

func decodeMigrationPortableFixture(t *testing.T) migrationPortableFixture {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(serviceMigrationPortableFixture))
	decoder.DisallowUnknownFields()
	var fixture migrationPortableFixture
	if err := decoder.Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatalf("unexpected trailing fixture JSON: %v", err)
	}
	return fixture
}

func newMigrationRegistry(t *testing.T, deploymentID uuid.UUID) (*BindingRegistry, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bindings.json")
	if err := os.WriteFile(path, []byte(`{"bindings":[],"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	registry, err := LoadBindingRegistry(path, deploymentID)
	if err != nil {
		t.Fatal(err)
	}
	return registry, path
}

func requestForAuthority(
	scope Scope,
	revision uint64,
	digest string,
	deploymentID uuid.UUID,
) RequestBinding {
	return RequestBinding{
		Scope: scope, AuthorityRevision: revision, AuthorityDigest: digest,
		DeploymentID: deploymentID, RouteID: uuid.New(), TrafficClass: TrafficControl,
	}
}

func fixtureDeploymentSigner(
	t *testing.T,
	deployment DeploymentDescriptor,
) *DeploymentSigner {
	t.Helper()
	for scalar := byte(1); scalar <= 16; scalar++ {
		seed := make([]byte, 32)
		seed[31] = scalar
		signer, err := NewDeploymentSigner(deployment.DeploymentID, seed)
		if err == nil && signer.PublicSigningKeyX963() == deployment.PublicSigningKeyX963 {
			return signer
		}
	}
	t.Fatal("portable fixture deployment key is outside the deterministic test range")
	return nil
}

func encodeBase64URL(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}
