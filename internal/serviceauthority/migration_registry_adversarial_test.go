package serviceauthority

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestStagedSnapshotRejectsWrongDeploymentKeyWithoutPoisoningFence(t *testing.T) {
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

	seed := make([]byte, 32)
	seed[31] = 31
	wrongSigner, err := NewDeploymentSigner(current.ActiveDeployment.DeploymentID, seed)
	if err != nil {
		t.Fatal(err)
	}
	if wrongSigner.SigningKeyFingerprint() == current.ActiveDeployment.SigningKeyFingerprint {
		t.Fatal("wrong-key test accidentally selected the deployment key")
	}
	if _, err := registry.SignStagedMigrationSnapshotAt(current.Scope, wrongSigner, 3_000); err == nil {
		t.Fatal("registry signed a staged snapshot with another key using the same deployment ID")
	}

	staged := registry.bindings[current.Scope].WriteFence
	signature, err := wrongSigner.signRecord(migrationSnapshotSignatureDomain, staged.SnapshotPayload)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.ConfirmMigrationWriteFenceSnapshotAt(current.Scope, MigrationSnapshot{
		Payload: append([]byte(nil), staged.SnapshotPayload...), Signature: signature,
	}, 3_000); err == nil {
		t.Fatal("registry confirmed an externally signed snapshot from another deployment key")
	}
	if registry.bindings[current.Scope].WriteFence.Snapshot != nil {
		t.Fatal("wrong-key confirmation poisoned the staged fence")
	}

	legitimate := fixtureDeploymentSigner(t, current.ActiveDeployment)
	if _, err := registry.SignStagedMigrationSnapshotAt(current.Scope, legitimate, 3_000); err != nil {
		t.Fatalf("legitimate signer could not recover after wrong-key attempts: %v", err)
	}
}

func TestMigrationCancellationClearsOnlySourceFenceAndStalesTarget(t *testing.T) {
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
	prepared, err := preparation.PreparationManifest.VerifiedPayload()
	if err != nil || prepared.Migration == nil {
		t.Fatal(err)
	}
	targetOffer, err := preparation.TargetOffer.VerifiedPayload(nil)
	if err != nil {
		t.Fatal(err)
	}
	target, err := targetOffer.DeploymentOffer.VerifiedPayload(nil)
	if err != nil {
		t.Fatal(err)
	}

	source, sourcePath := newMigrationRegistry(t, current.ActiveDeployment.DeploymentID)
	targetRegistry, targetPath := newMigrationRegistry(t, target.Deployment.DeploymentID)
	initial := preparation.CurrentManifest
	if err := source.Activate(current.Scope, CurrentBinding{
		Revision: current.Revision, Digest: currentDigest,
		DeploymentID: current.ActiveDeployment.DeploymentID, Manifest: &initial,
	}); err != nil {
		t.Fatal(err)
	}
	for name, registry := range map[string]*BindingRegistry{
		"source": source, "target": targetRegistry,
	} {
		if err := registry.ApplyMigrationPreparation(
			preparation,
			fixture.AuthorityAnchor,
			2_200,
		); err != nil {
			t.Fatalf("%s preparation failed: %v", name, err)
		}
	}
	forward, err := fixture.RollbackEvidence.ActivationEvidence.Snapshot.VerifiedPayload(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := source.StageMigrationWriteFence(
		preparation.PreparationManifest,
		forward,
		fixture.AuthorityAnchor,
		3_000,
	); err != nil {
		t.Fatal(err)
	}

	predecessorDigest, err := preparation.PreparationManifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	cancelledPayload := ManifestPayload{
		ActiveDeployment:          prepared.ActiveDeployment,
		IssuedAtMilliseconds:      3_000,
		Migration:                 prepared.Migration,
		PredecessorManifestDigest: &predecessorDigest,
		PreparedDeployments:       []DeploymentDescriptor{},
		Revision:                  prepared.Revision + 1,
		Scope:                     prepared.Scope,
		Transition:                TransitionMigrationCancellation,
		TransportPolicy:           prepared.TransportPolicy,
		ValidFromMilliseconds:     3_000,
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
	for name, registry := range map[string]*BindingRegistry{
		"source": source, "target": targetRegistry,
	} {
		if err := registry.ApplyMigrationCancellation(
			evidence,
			fixture.AuthorityAnchor,
			3_000,
		); err != nil {
			t.Fatalf("%s cancellation failed: %v", name, err)
		}
		if err := registry.ApplyMigrationCancellation(
			evidence,
			fixture.AuthorityAnchor,
			20_000,
		); err != nil {
			t.Fatalf("%s exact cancellation retry failed: %v", name, err)
		}
	}

	cancellationDigest, err := cancellation.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	sourceRequest := requestForAuthority(
		cancelledPayload.Scope,
		cancelledPayload.Revision,
		cancellationDigest,
		current.ActiveDeployment.DeploymentID,
		cancellation,
	)
	if err := source.AuthorizeRequestAt(
		sourceRequest,
		RequestMutation,
		time.UnixMilli(3_000),
	); err != nil {
		t.Fatalf("cancelled source did not resume writes: %v", err)
	}
	if source.bindings[current.Scope].WriteFence != nil {
		t.Fatal("cancelled source retained its forward fence")
	}
	targetRequest := requestForAuthority(
		cancelledPayload.Scope,
		cancelledPayload.Revision,
		cancellationDigest,
		target.Deployment.DeploymentID,
		cancellation,
	)
	if err := targetRegistry.AuthorizeRequestAt(
		targetRequest,
		RequestMutation,
		time.UnixMilli(3_000),
	); err == nil {
		t.Fatal("cancelled target became serving")
	}

	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	if err := targetRegistry.Close(); err != nil {
		t.Fatal(err)
	}
	reloadedSource, err := LoadBindingRegistry(sourcePath, current.ActiveDeployment.DeploymentID)
	if err != nil {
		t.Fatalf("source cancellation did not survive restart: %v", err)
	}
	t.Cleanup(func() { _ = reloadedSource.Close() })
	if err := reloadedSource.AuthorizeRequestAt(
		sourceRequest,
		RequestMutation,
		time.UnixMilli(3_000),
	); err != nil {
		t.Fatalf("source cancellation did not survive restart: %v", err)
	}
	reloadedTarget, err := LoadBindingRegistry(targetPath, target.Deployment.DeploymentID)
	if err != nil {
		t.Fatalf("target cancellation did not survive restart: %v", err)
	}
	t.Cleanup(func() { _ = reloadedTarget.Close() })
	if err := reloadedTarget.AuthorizeRequestAt(
		targetRequest,
		RequestMutation,
		time.UnixMilli(3_000),
	); err == nil {
		t.Fatal("reloaded cancelled target became serving")
	}
	if err := source.ApplyServiceAuthoritySuccessor(
		preparation.PreparationManifest,
		cancellation,
		fixture.AuthorityAnchor,
		3_000,
	); err == nil {
		t.Fatal("bare cancellation passed through the generic successor path")
	}
}

func TestRetirementClearsTargetReverseFenceAndPreservesSourceFence(t *testing.T) {
	fixture := decodeMigrationPortableFixture(t)
	activation := fixture.RollbackEvidence.ActivationEvidence
	prepared, err := activation.Preparation.PreparationManifest.VerifiedPayload()
	if err != nil || prepared.Migration == nil ||
		prepared.Migration.RollbackUntilMilliseconds == nil {
		t.Fatal(err)
	}
	current, err := activation.Preparation.CurrentManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	currentDigest, err := activation.Preparation.CurrentManifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	activated, err := activation.ActivationManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	targetID := activated.ActiveDeployment.DeploymentID
	sourceID := current.ActiveDeployment.DeploymentID
	target, targetPath := newMigrationRegistry(t, targetID)
	if err := target.ApplyMigrationPreparation(
		activation.Preparation,
		fixture.AuthorityAnchor,
		2_200,
	); err != nil {
		t.Fatal(err)
	}
	if err := target.ApplyMigrationActivation(
		activation,
		fixture.AuthorityAnchor,
		3_200,
	); err != nil {
		t.Fatal(err)
	}
	reverse, err := fixture.RollbackEvidence.TargetSnapshot.VerifiedPayload(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := target.StageMigrationWriteFence(
		activation.ActivationManifest,
		reverse,
		fixture.AuthorityAnchor,
		4_000,
	); err != nil {
		t.Fatal(err)
	}
	if err := target.ConfirmMigrationWriteFenceSnapshotAt(
		activated.Scope,
		fixture.RollbackEvidence.TargetSnapshot,
		4_000,
	); err != nil {
		t.Fatal(err)
	}

	activationDigest, err := activation.ActivationManifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	retirementPayload := ManifestPayload{
		ActiveDeployment:          activated.ActiveDeployment,
		IssuedAtMilliseconds:      *activated.Migration.RollbackUntilMilliseconds,
		Migration:                 activated.Migration,
		PredecessorManifestDigest: &activationDigest,
		PreparedDeployments:       []DeploymentDescriptor{},
		Revision:                  activated.Revision + 1,
		Scope:                     activated.Scope,
		Transition:                TransitionMigrationRetirement,
		TransportPolicy:           activated.TransportPolicy,
		ValidFromMilliseconds:     *activated.Migration.RollbackUntilMilliseconds,
		Version:                   SchemaVersion,
	}
	retirement := signedAuthorityManifest(
		t,
		retirementPayload,
		fixtureAuthorityPrivateKey(t, fixture.AuthorityAnchor),
		fixture.AuthorityAnchor,
	)
	deadline := *activated.Migration.RollbackUntilMilliseconds
	if err := target.ApplyServiceAuthoritySuccessor(
		activation.ActivationManifest,
		retirement,
		fixture.AuthorityAnchor,
		deadline,
	); err != nil {
		t.Fatalf("target retirement failed: %v", err)
	}
	if target.bindings[activated.Scope].WriteFence != nil {
		t.Fatal("retired target retained its abandoned reverse fence")
	}
	retirementDigest, err := retirement.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	targetRequest := requestForAuthority(
		activated.Scope,
		retirementPayload.Revision,
		retirementDigest,
		targetID,
		retirement,
	)
	if err := target.AuthorizeRequestAt(
		targetRequest,
		RequestMutation,
		time.UnixMilli(deadline),
	); err != nil {
		t.Fatalf("retired target did not resume writes: %v", err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	reloadedTarget, err := LoadBindingRegistry(targetPath, targetID)
	if err != nil {
		t.Fatalf("target retirement did not survive restart: %v", err)
	}
	t.Cleanup(func() { _ = reloadedTarget.Close() })
	if err := reloadedTarget.AuthorizeRequestAt(
		targetRequest,
		RequestMutation,
		time.UnixMilli(deadline),
	); err != nil {
		t.Fatalf("target retirement did not survive restart: %v", err)
	}

	source, _ := newMigrationRegistry(t, sourceID)
	initial := activation.Preparation.CurrentManifest
	if err := source.Activate(current.Scope, CurrentBinding{
		Revision: current.Revision, Digest: currentDigest,
		DeploymentID: sourceID, Manifest: &initial,
	}); err != nil {
		t.Fatal(err)
	}
	if err := source.ApplyMigrationPreparation(
		activation.Preparation,
		fixture.AuthorityAnchor,
		2_200,
	); err != nil {
		t.Fatal(err)
	}
	forward, err := activation.Snapshot.VerifiedPayload(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := source.StageMigrationWriteFence(
		activation.Preparation.PreparationManifest,
		forward,
		fixture.AuthorityAnchor,
		3_000,
	); err != nil {
		t.Fatal(err)
	}
	if err := source.ConfirmMigrationWriteFenceSnapshotAt(
		activated.Scope,
		activation.Snapshot,
		3_000,
	); err != nil {
		t.Fatal(err)
	}
	if err := source.ApplyMigrationActivation(
		activation,
		fixture.AuthorityAnchor,
		3_200,
	); err != nil {
		t.Fatal(err)
	}
	if err := source.ApplyServiceAuthoritySuccessor(
		activation.ActivationManifest,
		retirement,
		fixture.AuthorityAnchor,
		deadline,
	); err != nil {
		t.Fatalf("source retirement failed: %v", err)
	}
	if source.bindings[activated.Scope].WriteFence == nil {
		t.Fatal("retired source lost its durable forward fence")
	}
}

func TestBindingAuthorizationRejectsExpiredManifestAtStrictBoundary(t *testing.T) {
	fixture := newBootstrapFixture(t)
	payload := ManifestPayload{
		ActiveDeployment:      fixture.descriptor,
		IssuedAtMilliseconds:  1_000,
		PreparedDeployments:   []DeploymentDescriptor{},
		Revision:              1,
		Scope:                 fixture.scope,
		Transition:            TransitionInitialActivation,
		TransportPolicy:       fixture.policy,
		ValidFromMilliseconds: 1_000,
		Version:               SchemaVersion,
	}
	validUntil := int64(2_000)
	payload.ValidUntilMilliseconds = &validUntil
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	manifest := Manifest{Payload: encoded, Signature: signTestAuthorityRecord(
		t,
		fixture.authorityKey,
		fixture.authorityID,
		"Facets service authority manifest v1\x00",
		encoded,
	)}
	digest, err := manifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	registry := NewBindingRegistry()
	if err := registry.Activate(fixture.scope, CurrentBinding{
		Revision: 1, Digest: digest, DeploymentID: fixture.descriptor.DeploymentID,
		Manifest: &manifest,
	}); err != nil {
		t.Fatal(err)
	}
	binding := requestForAuthority(
		fixture.scope, 1, digest, fixture.descriptor.DeploymentID, manifest,
	)
	if err := registry.AuthorizeRequestAt(
		binding,
		RequestMutation,
		time.UnixMilli(1_999),
	); err != nil {
		t.Fatalf("current manifest was rejected before expiry: %v", err)
	}
	if err := registry.AuthorizeAt(binding, time.UnixMilli(2_000)); err == nil {
		t.Fatal("expired manifest authorized a request at its strict deadline")
	}
	if err := registry.AuthorizeRequestAt(
		binding,
		RequestRead,
		time.UnixMilli(2_000),
	); err == nil {
		t.Fatal("expired manifest authorized a read at its strict deadline")
	}
}

func TestAmbiguousBindingPersistencePoisonsRegistryFailClosed(t *testing.T) {
	fixture := newBootstrapFixture(t)
	manifest := fixture.signedManifest(t, fixture.policy)
	digest, err := manifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "bindings.json")
	if err := os.WriteFile(path, []byte(`{"bindings":[],"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	registry, err := LoadBindingRegistry(path, fixture.descriptor.DeploymentID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.Close() })
	registry.persist = func(string, uuid.UUID, map[Scope]CurrentBinding) error {
		return fmt.Errorf("%w: injected post-rename directory fsync failure", errBindingPersistenceAmbiguous)
	}
	if err := registry.Activate(fixture.scope, CurrentBinding{
		Revision: 1, Digest: digest, DeploymentID: fixture.descriptor.DeploymentID,
		Manifest: &manifest,
	}); !errors.Is(err, errBindingPersistenceAmbiguous) {
		t.Fatalf("ambiguous persistence error was not returned: %v", err)
	}
	if !registry.poisoned {
		t.Fatal("registry did not retain its fail-closed poison state")
	}
	if err := registry.AuthorizeAt(
		requestForAuthority(
			fixture.scope, 1, digest, fixture.descriptor.DeploymentID, manifest,
		),
		time.UnixMilli(1_500),
	); err == nil {
		t.Fatal("poisoned registry authorized a request")
	}
}

func TestPersistenceNeverWritesAFileLargerThanLoaderAccepts(t *testing.T) {
	fixture := newBootstrapFixture(t)
	bindings := make(map[Scope]CurrentBinding)
	for len(bindings) < 800 {
		scope := Scope{Kind: ScopeDeviceSync, ScopeID: uuid.New()}
		payload := ManifestPayload{
			ActiveDeployment:      fixture.descriptor,
			IssuedAtMilliseconds:  1_000,
			PreparedDeployments:   []DeploymentDescriptor{},
			Revision:              1,
			Scope:                 scope,
			Transition:            TransitionInitialActivation,
			TransportPolicy:       fixture.policy,
			ValidFromMilliseconds: 1_000,
			Version:               SchemaVersion,
		}
		encoded, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		manifest := Manifest{Payload: encoded, Signature: signTestAuthorityRecord(
			t,
			fixture.authorityKey,
			fixture.authorityID,
			"Facets service authority manifest v1\x00",
			encoded,
		)}
		digest, err := manifest.ReferenceDigest()
		if err != nil {
			t.Fatal(err)
		}
		manifestCopy := manifest
		bindings[scope] = CurrentBinding{
			Revision: 1, Digest: digest, DeploymentID: fixture.descriptor.DeploymentID,
			Manifest: &manifestCopy,
		}
	}

	path := filepath.Join(t.TempDir(), "bindings.json")
	original := []byte(`{"bindings":[],"version":1}`)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := persistBindingFile(path, fixture.descriptor.DeploymentID, bindings); err == nil {
		t.Fatal("persistence accepted a binding file larger than the loader limit")
	}
	remaining, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(remaining, original) {
		t.Fatal("oversize rejection modified the last readable binding file")
	}
}
