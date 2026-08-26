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

type retirementStoreStub struct {
	applyCalls int
	failOnce   bool
	state      postgres.DeviceSyncScopeEnforcement
}

func (stub *retirementStoreStub) ApplyDeviceSyncMigrationRetirement(
	_ context.Context,
	localDeploymentID uuid.UUID,
	evidence serviceauthority.MigrationRetirementEvidence,
	anchor serviceauthority.TrustAnchor,
	acceptedAtMilliseconds int64,
) error {
	stub.applyCalls++
	if stub.failOnce {
		stub.failOnce = false
		return errors.New("injected retirement store failure")
	}
	retirement, err := evidence.ValidateHistoricalCatchUp(
		anchor, acceptedAtMilliseconds,
	)
	if err != nil || retirement.Migration == nil {
		return serviceauthority.ErrInvalid
	}
	digest, err := evidence.ReferenceDigest()
	if err != nil {
		return err
	}
	authority, err := postgres.DeviceSyncScopeAuthorityFromManifest(
		evidence.RetirementManifest, &digest, acceptedAtMilliseconds,
	)
	if err != nil {
		return err
	}
	state := postgres.DeviceSyncScopeRetired
	if localDeploymentID == retirement.Migration.TargetDeploymentID {
		state = postgres.DeviceSyncScopeWritable
	}
	local := localDeploymentID
	stub.state = postgres.DeviceSyncScopeEnforcement{
		PrincipalID: retirement.Scope.ScopeID,
		TenantID:    retirement.Scope.ScopeID,
		State:       state, LocalDeploymentID: &local, Authority: &authority,
	}
	return nil
}

func (stub *retirementStoreStub) GetDeviceSyncScopeEnforcement(
	_ context.Context,
	_ uuid.UUID,
) (postgres.DeviceSyncScopeEnforcement, error) {
	if stub.state.Authority == nil {
		return postgres.DeviceSyncScopeEnforcement{}, errors.New("retirement state missing")
	}
	return stub.state, nil
}

func TestDeviceSyncRetirementCoordinatorRecoversTargetAndLateReverseExport(
	t *testing.T,
) {
	ctx := context.Background()
	evidence, anchor := loadRetirementMigrationFixture(t)
	retirement, err := evidence.RetirementManifest.VerifiedPayload()
	if err != nil || retirement.Migration == nil {
		t.Fatalf("retirement=%+v err=%v", retirement, err)
	}
	activation := evidence.ActivationEvidence
	activated, err := activation.ActivationManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	targetID := retirement.Migration.TargetDeploymentID
	bindings := newTargetBindingRegistry(t, targetID)
	prepared, err := activation.Preparation.PreparationManifest.VerifiedPayload()
	if err != nil || len(prepared.PreparedDeployments) != 1 {
		t.Fatal(err)
	}
	if err := bindings.ApplyMigrationPreparation(
		activation.Preparation, anchor, prepared.ValidFromMilliseconds,
	); err != nil {
		t.Fatal(err)
	}
	if err := bindings.ApplyMigrationActivation(
		activation, anchor, activated.ValidFromMilliseconds,
	); err != nil {
		t.Fatal(err)
	}
	activationDigest, err := activation.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	activationAuthority, err := postgres.DeviceSyncScopeAuthorityFromManifest(
		activation.ActivationManifest, &activationDigest,
		activated.ValidFromMilliseconds,
	)
	if err != nil {
		t.Fatal(err)
	}
	local := targetID
	store := &retirementStoreStub{
		failOnce: true,
		state: postgres.DeviceSyncScopeEnforcement{
			PrincipalID:       retirement.Scope.ScopeID,
			TenantID:          retirement.Scope.ScopeID,
			State:             postgres.DeviceSyncScopeWritable,
			LocalDeploymentID: &local, Authority: &activationAuthority,
		},
	}
	custody, err := NewFileArtifactCustody(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	coordinator := &DeviceSyncRetirementCoordinator{
		Store: store, Custody: custody, Bindings: bindings,
		Signer: signerForDeployment(t, retirement.ActiveDeployment),
	}
	acceptedAt := retirement.ValidFromMilliseconds
	if _, err := coordinator.Retire(
		ctx, evidence, anchor, time.UnixMilli(acceptedAt),
	); err == nil || store.applyCalls != 1 {
		t.Fatalf("injected retirement failure=%v calls=%d", err, store.applyCalls)
	}
	pending, err := retirementJournalPath(
		custody, retirement.Scope, retirement.Migration.MigrationID,
		retirementFileName,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(pending); err != nil {
		t.Fatal(err)
	}
	results, err := coordinator.Recover(
		ctx, time.UnixMilli(acceptedAt+1),
	)
	if err != nil || len(results) != 1 ||
		results[0].State.State != postgres.DeviceSyncScopeWritable ||
		results[0].Binding.WriteFenced || store.applyCalls != 2 {
		t.Fatalf("retirement recovery=%+v calls=%d err=%v", results, store.applyCalls, err)
	}
	if recovered, err := coordinator.Recover(
		ctx, time.UnixMilli(acceptedAt+2),
	); err != nil || len(recovered) != 0 {
		t.Fatalf("completed retirement repeated=%+v err=%v", recovered, err)
	}

	// A reverse export can commit after registry retirement if it began just
	// before the terminal transition. The completed journal remains a repair
	// seam while retirement is current.
	store.state = postgres.DeviceSyncScopeEnforcement{
		PrincipalID:              retirement.Scope.ScopeID,
		TenantID:                 retirement.Scope.ScopeID,
		State:                    postgres.DeviceSyncScopeExportFenced,
		LocalDeploymentID:        &local,
		Authority:                &activationAuthority,
		ActiveExportWriteFenceID: new(uuid.UUID),
	}
	recovered, err := coordinator.Recover(
		ctx, time.UnixMilli(acceptedAt+3),
	)
	if err != nil || len(recovered) != 1 || store.applyCalls != 3 ||
		recovered[0].State.State != postgres.DeviceSyncScopeWritable {
		t.Fatalf("late reverse export recovery=%+v calls=%d err=%v", recovered, store.applyCalls, err)
	}
}

func loadRetirementMigrationFixture(t *testing.T) (
	serviceauthority.MigrationRetirementEvidence,
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
		AuthorityAnchor    serviceauthority.TrustAnchor                 `json:"authorityAnchor"`
		RetirementEvidence serviceauthority.MigrationRetirementEvidence `json:"retirementEvidence"`
	}
	if err := json.Unmarshal(encoded, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture.RetirementEvidence, fixture.AuthorityAnchor
}
