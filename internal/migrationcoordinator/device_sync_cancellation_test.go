package migrationcoordinator

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

type cancellationStoreStub struct {
	applyCalls int
	failOnce   bool
	state      *postgres.DeviceSyncScopeEnforcement
}

func (stub *cancellationStoreStub) ApplyDeviceSyncMigrationCancellation(
	_ context.Context,
	localDeploymentID uuid.UUID,
	evidence serviceauthority.MigrationCancellationEvidence,
	anchor serviceauthority.TrustAnchor,
	acceptedAtMilliseconds int64,
) error {
	stub.applyCalls++
	if stub.failOnce {
		stub.failOnce = false
		return errors.New("injected cancellation store failure")
	}
	cancellation, err := evidence.ValidateHistoricalCatchUp(
		anchor, acceptedAtMilliseconds,
	)
	if err != nil || cancellation.Migration == nil ||
		(localDeploymentID != cancellation.Migration.SourceDeploymentID &&
			localDeploymentID != cancellation.Migration.TargetDeploymentID) {
		return serviceauthority.ErrInvalid
	}
	digest, err := evidence.ReferenceDigest()
	if err != nil {
		return err
	}
	authority, err := postgres.DeviceSyncScopeAuthorityFromManifest(
		evidence.CancellationManifest, &digest, acceptedAtMilliseconds,
	)
	if err != nil {
		return err
	}
	state := postgres.DeviceSyncScopeWritable
	if localDeploymentID == cancellation.Migration.TargetDeploymentID {
		state = postgres.DeviceSyncScopeRetired
	}
	local := localDeploymentID
	stub.state = &postgres.DeviceSyncScopeEnforcement{
		PrincipalID: cancellation.Scope.ScopeID,
		TenantID:    cancellation.Scope.ScopeID,
		State:       state, LocalDeploymentID: &local, Authority: &authority,
	}
	return nil
}

func (stub *cancellationStoreStub) GetDeviceSyncScopeEnforcement(
	_ context.Context,
	_ uuid.UUID,
) (postgres.DeviceSyncScopeEnforcement, error) {
	if stub.state == nil {
		return postgres.DeviceSyncScopeEnforcement{},
			postgres.ErrDeviceSyncScopeEnforcementNotFound
	}
	return *stub.state, nil
}

func TestDeviceSyncCancellationCoordinatorRecoversSourceAfterDatabaseFailure(
	t *testing.T,
) {
	ctx := context.Background()
	evidence, anchor := loadCancellationMigrationFixture(t)
	cancellation, err := evidence.CancellationManifest.VerifiedPayload()
	if err != nil || cancellation.Migration == nil {
		t.Fatalf("cancellation=%+v err=%v", cancellation, err)
	}
	prepared, err := evidence.Preparation.PreparationManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	sourceID := cancellation.Migration.SourceDeploymentID
	bindings := newTargetBindingRegistry(t, sourceID)
	current, err := evidence.Preparation.CurrentManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	currentDigest, err := evidence.Preparation.CurrentManifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	currentManifest := evidence.Preparation.CurrentManifest
	if err := bindings.Activate(current.Scope, serviceauthority.CurrentBinding{
		Revision: current.Revision, Digest: currentDigest,
		DeploymentID: sourceID, Manifest: &currentManifest,
	}); err != nil {
		t.Fatal(err)
	}
	if err := bindings.ApplyMigrationPreparation(
		evidence.Preparation, anchor, prepared.ValidFromMilliseconds,
	); err != nil {
		t.Fatal(err)
	}
	preparationDigest, err := evidence.Preparation.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	preparationAuthority, err := postgres.DeviceSyncScopeAuthorityFromManifest(
		evidence.Preparation.PreparationManifest,
		&preparationDigest,
		prepared.ValidFromMilliseconds,
	)
	if err != nil {
		t.Fatal(err)
	}
	local := sourceID
	store := &cancellationStoreStub{
		failOnce: true,
		state: &postgres.DeviceSyncScopeEnforcement{
			PrincipalID:       cancellation.Scope.ScopeID,
			TenantID:          cancellation.Scope.ScopeID,
			State:             postgres.DeviceSyncScopeWritable,
			LocalDeploymentID: &local, Authority: &preparationAuthority,
		},
	}
	custody, err := NewFileArtifactCustody(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	coordinator := &DeviceSyncCancellationCoordinator{
		Store: store, Custody: custody, Bindings: bindings,
		Signer: signerForDeployment(t, prepared.ActiveDeployment),
	}
	acceptedAt := cancellation.ValidFromMilliseconds
	if _, err := coordinator.Cancel(
		ctx, evidence, anchor, time.UnixMilli(acceptedAt),
	); err == nil || store.applyCalls != 1 {
		t.Fatalf("injected cancellation failure=%v calls=%d", err, store.applyCalls)
	}
	pending, err := cancellationJournalPath(
		custody, cancellation.Scope, cancellation.Migration.MigrationID,
		cancellationFileName,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(pending); err != nil {
		t.Fatal(err)
	}
	results, err := coordinator.Recover(
		ctx, time.UnixMilli(acceptedAt+10_000),
	)
	if err != nil || len(results) != 1 ||
		!results[0].DatabasePresent ||
		results[0].State.State != postgres.DeviceSyncScopeWritable ||
		results[0].Binding.WriteFenced || store.applyCalls != 2 {
		t.Fatalf("recovered=%+v calls=%d err=%v", results, store.applyCalls, err)
	}
	completed, err := cancellationJournalPath(
		custody, cancellation.Scope, cancellation.Migration.MigrationID,
		completedCancellationFileName,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(completed); err != nil {
		t.Fatal(err)
	}
	if recovered, err := coordinator.Recover(
		ctx, time.UnixMilli(acceptedAt+20_000),
	); err != nil || len(recovered) != 0 {
		t.Fatalf("completed cancellation recovered again=%+v err=%v", recovered, err)
	}
}

func TestDeviceSyncCancellationCoordinatorAcceptsTargetBeforeDatabaseImport(
	t *testing.T,
) {
	ctx := context.Background()
	evidence, anchor := loadCancellationMigrationFixture(t)
	cancellation, err := evidence.CancellationManifest.VerifiedPayload()
	if err != nil || cancellation.Migration == nil {
		t.Fatal(err)
	}
	prepared, err := evidence.Preparation.PreparationManifest.VerifiedPayload()
	if err != nil || len(prepared.PreparedDeployments) != 1 {
		t.Fatal(err)
	}
	targetID := cancellation.Migration.TargetDeploymentID
	bindings := newTargetBindingRegistry(t, targetID)
	if err := bindings.ApplyMigrationPreparation(
		evidence.Preparation, anchor, prepared.ValidFromMilliseconds,
	); err != nil {
		t.Fatal(err)
	}
	store := &cancellationStoreStub{}
	custody, err := NewFileArtifactCustody(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	coordinator := &DeviceSyncCancellationCoordinator{
		Store: store, Custody: custody, Bindings: bindings,
		Signer: signerForDeployment(t, prepared.PreparedDeployments[0]),
	}
	result, err := coordinator.Cancel(
		ctx, evidence, anchor,
		time.UnixMilli(cancellation.ValidFromMilliseconds),
	)
	if err != nil || result.DatabasePresent || store.applyCalls != 0 ||
		result.Binding.DeploymentID != cancellation.Migration.SourceDeploymentID ||
		result.Binding.WriteFenced {
		t.Fatalf("target cancellation=%+v calls=%d err=%v", result, store.applyCalls, err)
	}
	// Model an import that began before cancellation and committed after the
	// registry-only target transition. Completed-journal startup reconciliation
	// must retire that stale standby rather than trusting completion forever.
	preparationDigest, err := evidence.Preparation.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	preparationAuthority, err := postgres.DeviceSyncScopeAuthorityFromManifest(
		evidence.Preparation.PreparationManifest,
		&preparationDigest,
		prepared.ValidFromMilliseconds,
	)
	if err != nil {
		t.Fatal(err)
	}
	local := targetID
	migrationID := cancellation.Migration.MigrationID
	store.state = &postgres.DeviceSyncScopeEnforcement{
		PrincipalID:             cancellation.Scope.ScopeID,
		TenantID:                cancellation.Scope.ScopeID,
		State:                   postgres.DeviceSyncScopeStandby,
		LocalDeploymentID:       &local,
		Authority:               &preparationAuthority,
		ActiveMigrationImportID: &migrationID,
	}
	recovered, err := coordinator.Recover(
		ctx, time.UnixMilli(cancellation.ValidFromMilliseconds+1),
	)
	if err != nil || len(recovered) != 1 || store.applyCalls != 1 ||
		recovered[0].State.State != postgres.DeviceSyncScopeRetired {
		t.Fatalf("late target import recovery=%+v calls=%d err=%v", recovered, store.applyCalls, err)
	}
}

func TestDeviceSyncCancellationRecoveryRejectsPermissiveJournal(t *testing.T) {
	ctx := context.Background()
	evidence, anchor := loadCancellationMigrationFixture(t)
	cancellation, err := evidence.CancellationManifest.VerifiedPayload()
	if err != nil || cancellation.Migration == nil {
		t.Fatal(err)
	}
	prepared, err := evidence.Preparation.PreparationManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	sourceID := cancellation.Migration.SourceDeploymentID
	bindings := newTargetBindingRegistry(t, sourceID)
	current, _ := evidence.Preparation.CurrentManifest.VerifiedPayload()
	currentDigest, _ := evidence.Preparation.CurrentManifest.ReferenceDigest()
	currentManifest := evidence.Preparation.CurrentManifest
	if err := bindings.Activate(current.Scope, serviceauthority.CurrentBinding{
		Revision: current.Revision, Digest: currentDigest,
		DeploymentID: sourceID, Manifest: &currentManifest,
	}); err != nil {
		t.Fatal(err)
	}
	if err := bindings.ApplyMigrationPreparation(
		evidence.Preparation, anchor, prepared.ValidFromMilliseconds,
	); err != nil {
		t.Fatal(err)
	}
	preparationDigest, _ := evidence.Preparation.ReferenceDigest()
	preparationAuthority, _ := postgres.DeviceSyncScopeAuthorityFromManifest(
		evidence.Preparation.PreparationManifest, &preparationDigest,
		prepared.ValidFromMilliseconds,
	)
	local := sourceID
	store := &cancellationStoreStub{
		failOnce: true,
		state: &postgres.DeviceSyncScopeEnforcement{
			PrincipalID: cancellation.Scope.ScopeID,
			TenantID:    cancellation.Scope.ScopeID, State: postgres.DeviceSyncScopeWritable,
			LocalDeploymentID: &local, Authority: &preparationAuthority,
		},
	}
	custody, err := NewFileArtifactCustody(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	coordinator := &DeviceSyncCancellationCoordinator{
		Store: store, Custody: custody, Bindings: bindings,
		Signer: signerForDeployment(t, prepared.ActiveDeployment),
	}
	acceptedAt := cancellation.ValidFromMilliseconds
	_, _ = coordinator.Cancel(ctx, evidence, anchor, time.UnixMilli(acceptedAt))
	pending, err := cancellationJournalPath(
		custody, cancellation.Scope, cancellation.Migration.MigrationID,
		cancellationFileName,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(pending, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Recover(
		ctx, time.UnixMilli(acceptedAt+1),
	); err == nil {
		t.Fatal("permissive cancellation journal was accepted")
	}
}

func loadCancellationMigrationFixture(t *testing.T) (
	serviceauthority.MigrationCancellationEvidence,
	serviceauthority.TrustAnchor,
) {
	t.Helper()
	_, currentFile, _, _ := runtime.Caller(0)
	encoded, err := os.ReadFile(filepath.Join(
		filepath.Dir(currentFile), "..", "serviceauthority", "testdata",
		"service-migration-portable-v2.json",
	))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		AuthorityAnchor      serviceauthority.TrustAnchor                   `json:"authorityAnchor"`
		CancellationEvidence serviceauthority.MigrationCancellationEvidence `json:"cancellationEvidence"`
	}
	if err := json.Unmarshal(encoded, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture.CancellationEvidence, fixture.AuthorityAnchor
}
