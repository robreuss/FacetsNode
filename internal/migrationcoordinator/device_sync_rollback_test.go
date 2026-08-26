package migrationcoordinator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

type rollbackStoreStub struct {
	applyCalls int
	failOnce   bool
	state      postgres.DeviceSyncScopeEnforcement
}

type rollbackImporterStub struct {
	expected  serviceauthority.MigrationSnapshotPayload
	state     []byte
	inventory []byte
	calls     int
}

func (stub *rollbackImporterStub) PrepareDeviceSyncMigrationRollbackStandby(
	_ context.Context,
	localDeploymentID uuid.UUID,
	_ serviceauthority.MigrationActivationEvidence,
	_ serviceauthority.MigrationSnapshot,
	_ serviceauthority.TrustAnchor,
	_ int64,
	staged postgres.DeviceSyncMigrationStagedArtifacts,
) (postgres.DeviceSyncMigrationRollbackImportRecord, error) {
	stub.calls++
	state, err := io.ReadAll(staged.ServiceState)
	if err != nil {
		return postgres.DeviceSyncMigrationRollbackImportRecord{}, err
	}
	inventory, err := io.ReadAll(staged.BlobInventory)
	if err != nil {
		return postgres.DeviceSyncMigrationRollbackImportRecord{}, err
	}
	if !bytes.Equal(state, stub.state) || !bytes.Equal(inventory, stub.inventory) {
		return postgres.DeviceSyncMigrationRollbackImportRecord{}, errors.New(
			"rollback importer received different artifacts",
		)
	}
	return postgres.DeviceSyncMigrationRollbackImportRecord{
		PrincipalID:           stub.expected.Scope.ScopeID,
		MigrationID:           stub.expected.MigrationID,
		ImportingDeploymentID: localDeploymentID,
		StateCommitmentDigest: stub.expected.StateCommitmentDigest,
	}, nil
}

func (stub *rollbackStoreStub) ApplyDeviceSyncMigrationRollback(
	_ context.Context,
	localDeploymentID uuid.UUID,
	evidence serviceauthority.MigrationRollbackEvidence,
	anchor serviceauthority.TrustAnchor,
	acceptedAtMilliseconds int64,
) error {
	stub.applyCalls++
	if stub.failOnce {
		stub.failOnce = false
		return errors.New("injected rollback database failure")
	}
	rolledBack, err := evidence.ValidateHistoricalCatchUp(
		anchor, acceptedAtMilliseconds,
	)
	if err != nil || rolledBack.Migration == nil {
		return serviceauthority.ErrInvalid
	}
	digest, err := evidence.ReferenceDigest()
	if err != nil {
		return err
	}
	authority, err := postgres.DeviceSyncScopeAuthorityFromManifest(
		evidence.RollbackManifest, &digest, acceptedAtMilliseconds,
	)
	if err != nil {
		return err
	}
	local := localDeploymentID
	state := postgres.DeviceSyncScopeRetired
	if localDeploymentID == rolledBack.Migration.SourceDeploymentID {
		state = postgres.DeviceSyncScopeWritable
	}
	stub.state = postgres.DeviceSyncScopeEnforcement{
		PrincipalID: rolledBack.Scope.ScopeID,
		TenantID:    rolledBack.Scope.ScopeID,
		State:       state, LocalDeploymentID: &local, Authority: &authority,
	}
	return nil
}

func (stub *rollbackStoreStub) GetDeviceSyncScopeEnforcement(
	_ context.Context,
	_ uuid.UUID,
) (postgres.DeviceSyncScopeEnforcement, error) {
	if stub.state.Authority == nil {
		return postgres.DeviceSyncScopeEnforcement{}, errors.New("rollback not committed")
	}
	return stub.state, nil
}

func TestDeviceSyncRollbackCoordinatorRecoversCrossStoreCutover(
	t *testing.T,
) {
	ctx := context.Background()
	state := []byte("reverse canonical service state")
	preparation, anchor := loadPreparedMigrationFixture(t)
	prepared, err := preparation.PreparationManifest.VerifiedPayload()
	if err != nil || prepared.Migration == nil {
		t.Fatal(err)
	}
	inventory := encodeBlobInventory(t, prepared.Scope.ScopeID, nil)
	evidence, sourceBindings := buildRollbackEvidenceForArtifacts(
		t, preparation, anchor, state, inventory,
	)
	validated, err := evidence.TargetSnapshot.ValidateRollbackTransfer(
		evidence.ActivationEvidence, anchor, 4_000,
	)
	if err != nil {
		t.Fatal(err)
	}
	custody, err := NewFileArtifactCustody(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := custody.stagePreparedDeviceSyncRollbackTransfer(
		ctx, validated, evidence.ActivationEvidence, evidence.TargetSnapshot,
		bytes.NewReader(state), bytes.NewReader(inventory),
	); err != nil {
		t.Fatal(err)
	}
	store := &rollbackStoreStub{failOnce: true}
	coordinator := &DeviceSyncRollbackCoordinator{
		Store: store, Custody: custody, Bindings: sourceBindings,
		Signer: signerForDeployment(t, validated.SourceDeployment),
	}
	if _, err := coordinator.Rollback(
		ctx, evidence, anchor, time.UnixMilli(4_000),
	); err == nil || store.applyCalls != 1 {
		t.Fatalf("injected rollback failure=%v calls=%d", err, store.applyCalls)
	}
	identities, err := sourceBindings.CurrentBindingIdentities(
		serviceauthority.ScopeDeviceSync,
	)
	if err != nil || len(identities) != 1 || identities[0].Revision != 4 ||
		identities[0].WriteFenced {
		t.Fatalf("registry advanced before database recovery: %+v err=%v", identities, err)
	}
	results, err := coordinator.Recover(ctx, time.UnixMilli(9_500))
	if err != nil || len(results) != 1 || store.applyCalls != 2 ||
		results[0].State.State != postgres.DeviceSyncScopeWritable ||
		results[0].Binding.WriteFenced {
		t.Fatalf("rollback recovery=%+v calls=%d err=%v", results, store.applyCalls, err)
	}
	if results, err := coordinator.Recover(
		ctx, time.UnixMilli(9_600),
	); err != nil || len(results) != 0 || store.applyCalls != 2 {
		t.Fatalf("completed rollback audit=%+v calls=%d err=%v", results, store.applyCalls, err)
	}
	if result, err := coordinator.Rollback(
		ctx, evidence, anchor, time.UnixMilli(20_000),
	); err != nil || result.State.State != postgres.DeviceSyncScopeWritable ||
		store.applyCalls != 3 {
		t.Fatalf("expired exact rollback retry=%+v calls=%d err=%v", result, store.applyCalls, err)
	}
}

func TestDeviceSyncRollbackCoordinatorRecoversRetiredTargetCutover(
	t *testing.T,
) {
	ctx := context.Background()
	state := []byte("reverse target retirement state")
	preparation, anchor := loadPreparedMigrationFixture(t)
	prepared, err := preparation.PreparationManifest.VerifiedPayload()
	if err != nil || prepared.Migration == nil {
		t.Fatal(err)
	}
	inventory := encodeBlobInventory(t, prepared.Scope.ScopeID, nil)
	evidence, _ := buildRollbackEvidenceForArtifacts(
		t, preparation, anchor, state, inventory,
	)
	activation, err := evidence.ActivationEvidence.ActivationManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	validated, err := evidence.TargetSnapshot.ValidateRollbackTransfer(
		evidence.ActivationEvidence, anchor, 4_000,
	)
	if err != nil {
		t.Fatal(err)
	}
	targetBindings := newTargetBindingRegistry(
		t, activation.ActiveDeployment.DeploymentID,
	)
	if err := targetBindings.ApplyMigrationPreparation(
		preparation, anchor, 2_200,
	); err != nil {
		t.Fatal(err)
	}
	if err := targetBindings.ApplyMigrationActivation(
		evidence.ActivationEvidence, anchor, 3_200,
	); err != nil {
		t.Fatal(err)
	}
	if err := targetBindings.StageMigrationWriteFence(
		evidence.ActivationEvidence.ActivationManifest,
		validated.Snapshot, anchor, 3_600,
	); err != nil {
		t.Fatal(err)
	}
	if err := targetBindings.ConfirmMigrationWriteFenceSnapshotAt(
		validated.Snapshot.Scope, evidence.TargetSnapshot, 3_600,
	); err != nil {
		t.Fatal(err)
	}
	custody, err := NewFileArtifactCustody(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := custody.stagePreparedDeviceSyncRollbackTransfer(
		ctx, validated, evidence.ActivationEvidence, evidence.TargetSnapshot,
		bytes.NewReader(state), bytes.NewReader(inventory),
	); err != nil {
		t.Fatal(err)
	}
	store := &rollbackStoreStub{failOnce: true}
	coordinator := &DeviceSyncRollbackCoordinator{
		Store: store, Custody: custody, Bindings: targetBindings,
		Signer: signerForDeployment(t, activation.ActiveDeployment),
	}
	if _, err := coordinator.Rollback(
		ctx, evidence, anchor, time.UnixMilli(4_000),
	); err == nil || store.applyCalls != 1 {
		t.Fatalf("injected target rollback failure=%v calls=%d", err, store.applyCalls)
	}
	identities, err := targetBindings.CurrentBindingIdentities(
		serviceauthority.ScopeDeviceSync,
	)
	if err != nil || len(identities) != 1 || identities[0].Revision != 4 ||
		!identities[0].WriteFenced {
		t.Fatalf("target rollback registry=%+v err=%v", identities, err)
	}
	results, err := coordinator.Recover(ctx, time.UnixMilli(9_500))
	if err != nil || len(results) != 1 || store.applyCalls != 2 ||
		results[0].State.State != postgres.DeviceSyncScopeRetired ||
		!results[0].Binding.WriteFenced {
		t.Fatalf(
			"target rollback recovery=%+v calls=%d err=%v",
			results, store.applyCalls, err,
		)
	}
}

func TestDeviceSyncRollbackSourceExportsAndFencesExactReverseState(t *testing.T) {
	preparation, anchor := loadPreparedMigrationFixture(t)
	prepared, err := preparation.PreparationManifest.VerifiedPayload()
	if err != nil || prepared.Migration == nil {
		t.Fatal(err)
	}
	forwardSnapshot, forwardPayload := signSnapshotForArtifacts(
		t, preparation, anchor, []byte("forward state"),
		encodeBlobInventory(t, prepared.Scope.ScopeID, nil),
	)
	activation := buildActivationEvidence(
		t, preparation, forwardSnapshot, forwardPayload, anchor,
	)
	activationPayload, err := activation.ActivationManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	bindings := newTargetBindingRegistry(
		t, activationPayload.ActiveDeployment.DeploymentID,
	)
	if err := bindings.ApplyMigrationPreparation(preparation, anchor, 2_200); err != nil {
		t.Fatal(err)
	}
	if err := bindings.ApplyMigrationActivation(activation, anchor, 3_200); err != nil {
		t.Fatal(err)
	}
	state := []byte("new writes on activated target")
	inventory := encodeBlobInventory(t, prepared.Scope.ScopeID, nil)
	custody, err := NewFileArtifactCustody(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store := &sourceExportStoreStub{}
	coordinator := DeviceSyncSourceCoordinator{
		Exporter: store, Custody: custody, Bindings: bindings,
		Signer:          signerForDeployment(t, activationPayload.ActiveDeployment),
		LogicalExporter: sourceLogicalExporter(state, inventory),
	}
	request := DeviceSyncRollbackSourcePreparationRequest{
		ActivationEvidence: activation, Anchor: anchor,
		ExportWriteFenceID:      uuid.MustParse("7e000000-0000-0000-0000-000000000001"),
		SnapshotID:              uuid.MustParse("7e000000-0000-0000-0000-000000000002"),
		ServiceStateArtifactID:  uuid.MustParse("7e000000-0000-0000-0000-000000000003"),
		BlobInventoryArtifactID: uuid.MustParse("7e000000-0000-0000-0000-000000000004"),
		Now:                     time.UnixMilli(3_600),
	}
	result, err := coordinator.PrepareRollback(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	validated, err := result.Snapshot.ValidateRollbackTransfer(
		activation, anchor, 3_600,
	)
	if err != nil || validated.Snapshot.ExportingDeploymentID !=
		activationPayload.ActiveDeployment.DeploymentID ||
		validated.Snapshot.ImportingDeploymentID != prepared.Migration.SourceDeploymentID {
		t.Fatalf("reverse transfer=%+v err=%v", validated, err)
	}
	assertSourceTransferBytes(t, result.Transfer, state, inventory)
	identities, err := bindings.CurrentBindingIdentities(serviceauthority.ScopeDeviceSync)
	if err != nil || len(identities) != 1 || !identities[0].WriteFenced {
		t.Fatalf("reverse source did not stay fenced: %+v err=%v", identities, err)
	}

	// Promotion removed the unsigned draft. An exact retry after both the
	// activation and snapshot expire must reuse the already-confirmed signature
	// and final custody without materializing or signing again.
	reopenedCustody, err := NewFileArtifactCustody(custody.root)
	if err != nil {
		t.Fatal(err)
	}
	coordinator.Custody = reopenedCustody
	request.Now = time.UnixMilli(10_001)
	recovered, err := coordinator.PrepareRollback(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if store.calls != 2 || store.materializerCalls != 1 ||
		!bytes.Equal(result.Snapshot.Payload, recovered.Snapshot.Payload) ||
		result.Snapshot.Signature.Signature != recovered.Snapshot.Signature.Signature {
		t.Fatalf(
			"reverse exact retry calls=%d materializer=%d snapshot=%+v",
			store.calls, store.materializerCalls, recovered.Snapshot,
		)
	}
	assertSourceTransferBytes(t, recovered.Transfer, state, inventory)
	backwardClock := request
	backwardClock.Now = time.UnixMilli(3_500)
	if _, err := coordinator.PrepareRollback(
		context.Background(), backwardClock,
	); err == nil {
		t.Fatal("reverse recovery accepted a clock before the durable capture instant")
	}
	conflicting := request
	conflicting.SnapshotID = uuid.New()
	if _, err := coordinator.PrepareRollback(
		context.Background(), conflicting,
	); err == nil {
		t.Fatal("conflicting reverse operation reused an existing export fence")
	}
	finalStatePath := filepath.Join(
		reopenedCustody.root, "device-sync-rollback", prepared.Scope.ScopeID.String(),
		result.ExportRecord.MigrationID.String(), result.ExportRecord.SnapshotID.String(),
		serviceStateFileName,
	)
	tampered := append([]byte(nil), state...)
	tampered[0] ^= 0xff
	if err := os.WriteFile(finalStatePath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.PrepareRollback(context.Background(), request); err == nil {
		t.Fatal("corrupted final reverse custody was accepted on exact retry")
	}
}

func TestDeviceSyncRollbackSourceCannotCreateExpiredReverseExport(t *testing.T) {
	preparation, anchor := loadPreparedMigrationFixture(t)
	prepared, err := preparation.PreparationManifest.VerifiedPayload()
	if err != nil || prepared.Migration == nil {
		t.Fatal(err)
	}
	forwardSnapshot, forwardPayload := signSnapshotForArtifacts(
		t, preparation, anchor, []byte("forward state"),
		encodeBlobInventory(t, prepared.Scope.ScopeID, nil),
	)
	activation := buildActivationEvidence(
		t, preparation, forwardSnapshot, forwardPayload, anchor,
	)
	activationPayload, err := activation.ActivationManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	bindings := newTargetBindingRegistry(
		t, activationPayload.ActiveDeployment.DeploymentID,
	)
	if err := bindings.ApplyMigrationPreparation(preparation, anchor, 2_200); err != nil {
		t.Fatal(err)
	}
	if err := bindings.ApplyMigrationActivation(activation, anchor, 3_200); err != nil {
		t.Fatal(err)
	}
	store := &sourceExportStoreStub{}
	custody, err := NewFileArtifactCustody(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	coordinator := DeviceSyncSourceCoordinator{
		Exporter: store, Custody: custody, Bindings: bindings,
		Signer: signerForDeployment(t, activationPayload.ActiveDeployment),
		LogicalExporter: sourceLogicalExporter(
			[]byte("late reverse state"),
			encodeBlobInventory(t, prepared.Scope.ScopeID, nil),
		),
	}
	_, err = coordinator.PrepareRollback(
		context.Background(), DeviceSyncRollbackSourcePreparationRequest{
			ActivationEvidence: activation, Anchor: anchor,
			ExportWriteFenceID:      uuid.MustParse("7f000000-0000-0000-0000-000000000001"),
			SnapshotID:              uuid.MustParse("7f000000-0000-0000-0000-000000000002"),
			ServiceStateArtifactID:  uuid.MustParse("7f000000-0000-0000-0000-000000000003"),
			BlobInventoryArtifactID: uuid.MustParse("7f000000-0000-0000-0000-000000000004"),
			Now:                     time.UnixMilli(10_001),
		},
	)
	if err == nil {
		t.Fatal("expired activation created a fresh reverse export")
	}
	if store.record != nil || store.materializerCalls != 1 {
		t.Fatal("expired reverse operation persisted export evidence")
	}
}

func TestDeviceSyncRollbackSourceOperationRecoversCommittedExportFence(t *testing.T) {
	preparation, anchor := loadPreparedMigrationFixture(t)
	prepared, err := preparation.PreparationManifest.VerifiedPayload()
	if err != nil || prepared.Migration == nil {
		t.Fatal(err)
	}
	forwardSnapshot, forwardPayload := signSnapshotForArtifacts(
		t, preparation, anchor, []byte("forward state"),
		encodeBlobInventory(t, prepared.Scope.ScopeID, nil),
	)
	activation := buildActivationEvidence(
		t, preparation, forwardSnapshot, forwardPayload, anchor,
	)
	activationPayload, err := activation.ActivationManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	state := []byte("journaled reverse export state")
	inventory := encodeBlobInventory(t, prepared.Scope.ScopeID, nil)
	store := &sourceExportStoreStub{}
	custody, err := NewFileArtifactCustody(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	source := &DeviceSyncSourceCoordinator{
		Exporter: store, Custody: custody,
		Bindings: newTargetBindingRegistry(
			t, activationPayload.ActiveDeployment.DeploymentID,
		),
		Signer:          signerForDeployment(t, activationPayload.ActiveDeployment),
		LogicalExporter: sourceLogicalExporter(state, inventory),
	}
	operationCoordinator := DeviceSyncRollbackSourceOperationCoordinator{
		Source: source,
	}
	request := DeviceSyncRollbackSourcePreparationRequest{
		ActivationEvidence: activation, Anchor: anchor,
		ExportWriteFenceID:      uuid.MustParse("80000000-0000-0000-0000-000000000001"),
		SnapshotID:              uuid.MustParse("80000000-0000-0000-0000-000000000002"),
		ServiceStateArtifactID:  uuid.MustParse("80000000-0000-0000-0000-000000000003"),
		BlobInventoryArtifactID: uuid.MustParse("80000000-0000-0000-0000-000000000004"),
		Now:                     time.UnixMilli(3_600),
	}
	wrongSeed := make([]byte, 32)
	wrongSeed[31] = 32
	wrongSigner, err := serviceauthority.NewDeploymentSigner(
		activationPayload.ActiveDeployment.DeploymentID, wrongSeed,
	)
	if err != nil {
		t.Fatal(err)
	}
	wrongCustody, err := NewFileArtifactCustody(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	wrongStore := &sourceExportStoreStub{}
	wrongCoordinator := DeviceSyncRollbackSourceOperationCoordinator{
		Source: &DeviceSyncSourceCoordinator{
			Exporter: wrongStore, Custody: wrongCustody,
			Bindings: source.Bindings, Signer: wrongSigner,
			LogicalExporter: source.LogicalExporter,
		},
	}
	if _, err := wrongCoordinator.Begin(
		context.Background(), request,
	); err == nil || wrongStore.calls != 0 {
		t.Fatalf(
			"rollback source accepted deployment ID with wrong key calls=%d err=%v",
			wrongStore.calls, err,
		)
	}
	if operations, err := wrongCustody.listDeviceSyncRollbackSourceOperations(
		context.Background(),
	); err != nil || len(operations) != 0 {
		t.Fatalf("wrong-key rollback source journal=%+v err=%v", operations, err)
	}
	if _, err := operationCoordinator.Begin(context.Background(), request); err == nil {
		t.Fatal("rollback source operation passed without registry activation")
	}
	if store.record == nil || store.materializerCalls != 1 {
		t.Fatal("rollback source operation did not retain its committed export")
	}
	operations, err := custody.listDeviceSyncRollbackSourceOperations(
		context.Background(),
	)
	if err != nil || len(operations) != 1 || operations[0].completed {
		t.Fatalf("pending rollback source operation=%+v err=%v", operations, err)
	}
	pendingOperation := operations[0]
	statuses, err := operationCoordinator.ListStatus(
		context.Background(), time.UnixMilli(3_600),
	)
	if err != nil || len(statuses) != 1 ||
		statuses[0].State != DeviceSyncRollbackSourceOperationAccepted ||
		statuses[0].SnapshotReferenceDigest != nil ||
		statuses[0].StateCommitmentDigest != nil {
		t.Fatalf("pending rollback source status=%+v err=%v", statuses, err)
	}
	if _, err := operationCoordinator.OpenPrepared(
		context.Background(), prepared.Scope.ScopeID,
		prepared.Migration.MigrationID, request.SnapshotID,
		time.UnixMilli(3_600),
	); err == nil {
		t.Fatal("accepted-only rollback source operation exposed a handoff")
	}
	statusOnlyCoordinator := DeviceSyncRollbackSourceOperationCoordinator{
		Source: &DeviceSyncSourceCoordinator{
			Custody: custody, Signer: source.Signer,
		},
	}
	if statuses, err := statusOnlyCoordinator.ListStatus(
		context.Background(), time.UnixMilli(3_600),
	); err != nil || len(statuses) != 1 ||
		statuses[0].State != DeviceSyncRollbackSourceOperationAccepted {
		t.Fatalf("rollback source control-only status=%+v err=%v", statuses, err)
	}
	conflictingOperation := request
	conflictingOperation.SnapshotID = uuid.New()
	if _, err := operationCoordinator.Begin(
		context.Background(), conflictingOperation,
	); err == nil || store.calls != 1 {
		t.Fatalf(
			"conflicting rollback source operation calls=%d err=%v",
			store.calls, err,
		)
	}

	reopenedCustody, err := NewFileArtifactCustody(custody.root)
	if err != nil {
		t.Fatal(err)
	}
	recoveredBindings := newTargetBindingRegistry(
		t, activationPayload.ActiveDeployment.DeploymentID,
	)
	if err := recoveredBindings.ApplyMigrationPreparation(
		preparation, anchor, 2_200,
	); err != nil {
		t.Fatal(err)
	}
	if err := recoveredBindings.ApplyMigrationActivation(
		activation, anchor, 3_200,
	); err != nil {
		t.Fatal(err)
	}
	source.Custody = reopenedCustody
	source.Bindings = recoveredBindings
	if recovered, err := operationCoordinator.Recover(
		context.Background(), time.UnixMilli(3_500),
	); err == nil || recovered != nil || store.materializerCalls != 1 {
		t.Fatalf(
			"backward-clock rollback source recovery=%+v materializer=%d err=%v",
			recovered, store.materializerCalls, err,
		)
	}
	recovered, err := operationCoordinator.Recover(
		context.Background(), time.UnixMilli(3_700),
	)
	if err != nil || len(recovered) != 1 || !recovered[0].Recovered ||
		store.materializerCalls != 1 {
		t.Fatalf(
			"rollback source recovery=%+v materializer=%d err=%v",
			recovered, store.materializerCalls, err,
		)
	}
	assertSourceTransferBytes(
		t, recovered[0].Preparation.Transfer, state, inventory,
	)
	operations, err = reopenedCustody.listDeviceSyncRollbackSourceOperations(
		context.Background(),
	)
	if err != nil || len(operations) != 1 || !operations[0].completed {
		t.Fatalf("prepared rollback source operation=%+v err=%v", operations, err)
	}
	if err := reopenedCustody.completeDeviceSyncRollbackSourceOperation(
		pendingOperation, source.Signer, recovered[0].Preparation,
	); err != nil {
		t.Fatalf("stale pending operation completion retry: %v", err)
	}
	statuses, err = operationCoordinator.ListStatus(
		context.Background(), time.UnixMilli(3_800),
	)
	if err != nil || len(statuses) != 1 ||
		statuses[0].State != DeviceSyncRollbackSourceOperationPrepared ||
		statuses[0].SnapshotReferenceDigest == nil ||
		statuses[0].StateCommitmentDigest == nil {
		t.Fatalf("prepared rollback source status=%+v err=%v", statuses, err)
	}
	handoffOnlyCoordinator := DeviceSyncRollbackSourceOperationCoordinator{
		Source: &DeviceSyncSourceCoordinator{
			Custody: reopenedCustody, Signer: source.Signer,
		},
	}
	handoff, err := handoffOnlyCoordinator.OpenPrepared(
		context.Background(), prepared.Scope.ScopeID,
		prepared.Migration.MigrationID, request.SnapshotID,
		time.UnixMilli(3_800),
	)
	if err != nil || handoff.Snapshot.Signature.Signature !=
		recovered[0].Preparation.Snapshot.Signature.Signature ||
		!canonicalEqualMigrationActivationEvidence(
			handoff.ActivationEvidence, activation,
		) {
		t.Fatalf("prepared rollback source handoff=%+v err=%v", handoff, err)
	}
	handoffArtifacts, closeHandoffArtifacts, err := handoff.Transfer.OpenArtifacts()
	if err != nil {
		t.Fatal(err)
	}
	handoffState, stateErr := io.ReadAll(handoffArtifacts.ServiceState)
	handoffInventory, inventoryErr := io.ReadAll(handoffArtifacts.BlobInventory)
	closeErr := closeHandoffArtifacts()
	if stateErr != nil || inventoryErr != nil || closeErr != nil ||
		!bytes.Equal(handoffState, state) ||
		!bytes.Equal(handoffInventory, inventory) {
		t.Fatalf(
			"rollback handoff state=%q inventory=%q errors=%v",
			handoffState, handoffInventory,
			errors.Join(stateErr, inventoryErr, closeErr),
		)
	}
	if _, err := handoffOnlyCoordinator.OpenPrepared(
		context.Background(), uuid.New(), prepared.Migration.MigrationID,
		request.SnapshotID, time.UnixMilli(3_800),
	); err == nil {
		t.Fatal("rollback source handoff accepted another principal")
	}
	if _, err := handoffOnlyCoordinator.OpenPrepared(
		context.Background(), prepared.Scope.ScopeID,
		prepared.Migration.MigrationID, request.SnapshotID,
		time.UnixMilli(10_001),
	); err == nil {
		t.Fatal("expired rollback source handoff remained transferable")
	}
	second, err := operationCoordinator.Recover(
		context.Background(), time.UnixMilli(3_800),
	)
	if err != nil || len(second) != 0 || store.materializerCalls != 1 {
		t.Fatalf(
			"completed rollback source recovery=%+v materializer=%d err=%v",
			second, store.materializerCalls, err,
		)
	}
	expiredRetry := request
	expiredRetry.Now = time.UnixMilli(10_001)
	exact, err := operationCoordinator.Begin(
		context.Background(), expiredRetry,
	)
	if err != nil || exact.Recovered || store.materializerCalls != 1 ||
		exact.Preparation.Snapshot.Signature.Signature !=
			recovered[0].Preparation.Snapshot.Signature.Signature {
		t.Fatalf(
			"completed rollback source exact retry=%+v materializer=%d err=%v",
			exact, store.materializerCalls, err,
		)
	}
	serviceStatePath := filepath.Join(
		reopenedCustody.root, "device-sync-rollback",
		prepared.Scope.ScopeID.String(), prepared.Migration.MigrationID.String(),
		request.SnapshotID.String(), serviceStateFileName,
	)
	originalServiceState, err := os.ReadFile(serviceStatePath)
	if err != nil || len(originalServiceState) == 0 {
		t.Fatal(err)
	}
	tamperedServiceState := append([]byte(nil), originalServiceState...)
	tamperedServiceState[0] ^= 0xff
	if err := os.WriteFile(serviceStatePath, tamperedServiceState, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := handoffOnlyCoordinator.OpenPrepared(
		context.Background(), prepared.Scope.ScopeID,
		prepared.Migration.MigrationID, request.SnapshotID,
		time.UnixMilli(3_800),
	); err == nil {
		t.Fatal("same-length changed rollback artifact was exposed for handoff")
	}
	if err := os.WriteFile(serviceStatePath, originalServiceState, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := handoffOnlyCoordinator.OpenPrepared(
		context.Background(), prepared.Scope.ScopeID,
		prepared.Migration.MigrationID, request.SnapshotID,
		time.UnixMilli(3_800),
	); err != nil {
		t.Fatalf("restored exact rollback artifact handoff: %v", err)
	}
	operationPath := filepath.Join(
		reopenedCustody.root, rollbackSourceOperationRootName,
		prepared.Scope.ScopeID.String(), prepared.Migration.MigrationID.String(),
		request.SnapshotID.String(), rollbackSourceOperationFileName,
	)
	operationRecord, err := os.ReadFile(operationPath)
	if err != nil {
		t.Fatal(err)
	}
	preparedIndex := bytes.Index(operationRecord, []byte(`"prepared":`))
	payloadIndex := -1
	if preparedIndex >= 0 {
		relative := bytes.Index(
			operationRecord[preparedIndex:], []byte(`"payload":"`),
		)
		if relative >= 0 {
			payloadIndex = preparedIndex + relative + len(`"payload":"`)
		}
	}
	if payloadIndex < 0 || payloadIndex >= len(operationRecord) {
		t.Fatal("prepared operation payload is missing")
	}
	if operationRecord[payloadIndex] == 'A' {
		operationRecord[payloadIndex] = 'B'
	} else {
		operationRecord[payloadIndex] = 'A'
	}
	if err := os.WriteFile(operationPath, operationRecord, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := reopenedCustody.listDeviceSyncRollbackSourceOperations(
		context.Background(),
	); err == nil {
		t.Fatal("tampered prepared rollback source operation was accepted")
	}
}

func TestDeviceSyncRollbackTargetReplacesStateBeforeReadiness(t *testing.T) {
	ctx := context.Background()
	preparation, anchor := loadPreparedMigrationFixture(t)
	prepared, err := preparation.PreparationManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	state := []byte("authenticated target state replacement")
	inventory := encodeBlobInventory(t, prepared.Scope.ScopeID, nil)
	evidence, sourceBindings := buildRollbackEvidenceForArtifacts(
		t, preparation, anchor, state, inventory,
	)
	payload, err := evidence.TargetSnapshot.VerifiedPayload(nil)
	if err != nil {
		t.Fatal(err)
	}
	importer := &rollbackImporterStub{
		expected: payload, state: state, inventory: inventory,
	}
	sourceBlobs, err := relay.NewFileBlobContentStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	destinationBlobs, err := relay.NewFileBlobContentStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	custody, err := NewFileArtifactCustody(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	coordinator := DeviceSyncRollbackTargetCoordinator{
		Importer: importer, Custody: custody, BlobStore: destinationBlobs,
		Bindings: sourceBindings,
		Signer:   signerForDeployment(t, prepared.ActiveDeployment),
	}
	result, err := coordinator.Prepare(
		ctx, DeviceSyncRollbackTargetPreparationRequest{
			ActivationEvidence: evidence.ActivationEvidence,
			Snapshot:           evidence.TargetSnapshot, Anchor: anchor,
			ServiceState:  bytes.NewReader(state),
			BlobInventory: bytes.NewReader(inventory),
			BlobSource:    sourceBlobs, Now: time.UnixMilli(4_000),
		},
	)
	if err != nil || importer.calls != 1 || result.Transfer.BlobCount != 0 {
		t.Fatalf("rollback target=%+v calls=%d err=%v", result, importer.calls, err)
	}
	readiness, err := result.Readiness.VerifiedPayload(nil)
	if err != nil || readiness.ImportingDeploymentID !=
		prepared.ActiveDeployment.DeploymentID ||
		readiness.AppliedStateCommitmentDigest != payload.StateCommitmentDigest {
		t.Fatalf("rollback readiness=%+v err=%v", readiness, err)
	}
}

func buildRollbackEvidenceForArtifacts(
	t *testing.T,
	preparation serviceauthority.MigrationPreparation,
	anchor serviceauthority.TrustAnchor,
	state []byte,
	inventory []byte,
) (serviceauthority.MigrationRollbackEvidence, *serviceauthority.BindingRegistry) {
	t.Helper()
	prepared, err := preparation.PreparationManifest.VerifiedPayload()
	if err != nil || prepared.Migration == nil || len(prepared.PreparedDeployments) != 1 {
		t.Fatal(err)
	}
	forwardSnapshot, forwardPayload := signSnapshotForArtifacts(
		t, preparation, anchor, []byte("forward state"),
		encodeBlobInventory(t, prepared.Scope.ScopeID, nil),
	)
	activation := buildActivationEvidence(
		t, preparation, forwardSnapshot, forwardPayload, anchor,
	)
	activationPayload, err := activation.ActivationManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	sourceBindings := preparedSourceBindingRegistry(t, preparation, anchor, true)
	if err := sourceBindings.StageMigrationWriteFence(
		preparation.PreparationManifest, forwardPayload, anchor, 3_000,
	); err != nil {
		t.Fatal(err)
	}
	if err := sourceBindings.ConfirmMigrationWriteFenceSnapshotAt(
		prepared.Scope, forwardSnapshot, 3_000,
	); err != nil {
		t.Fatal(err)
	}
	if err := sourceBindings.ApplyMigrationActivation(activation, anchor, 3_200); err != nil {
		t.Fatal(err)
	}
	targetBindings := newTargetBindingRegistry(
		t, activationPayload.ActiveDeployment.DeploymentID,
	)
	if err := targetBindings.ApplyMigrationPreparation(preparation, anchor, 2_200); err != nil {
		t.Fatal(err)
	}
	if err := targetBindings.ApplyMigrationActivation(activation, anchor, 3_200); err != nil {
		t.Fatal(err)
	}
	stateSHA256 := sha256.Sum256(state)
	inventorySHA256 := sha256.Sum256(inventory)
	stateDigest := postgres.DeviceSyncMigrationDigest(stateSHA256)
	inventoryDigest := postgres.DeviceSyncMigrationDigest(inventorySHA256)
	commitment := postgres.DeviceSyncMigrationStateCommitment(stateDigest, inventoryDigest)
	activationDigest, err := activation.ActivationManifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	reversePayload := serviceauthority.MigrationSnapshotPayload{
		Artifacts: []serviceauthority.MigrationArtifactDescriptor{
			{ArtifactID: uuid.MustParse("7f000000-0000-0000-0000-000000000011"), ByteCount: int64(len(state)), Kind: serviceauthority.ArtifactServiceStateSnapshot, TransferDigest: stateDigest.String()},
			{ArtifactID: uuid.MustParse("7f000000-0000-0000-0000-000000000012"), ByteCount: int64(len(inventory)), Kind: serviceauthority.ArtifactBlobInventory, TransferDigest: inventoryDigest.String()},
		},
		AuthorityManifestDigest: activationDigest,
		CapturedAtMilliseconds:  3_600, ExpiresAtMilliseconds: 9_000,
		ExportWriteFenceID:    uuid.MustParse("7f000000-0000-0000-0000-000000000013"),
		ExportingDeploymentID: activationPayload.ActiveDeployment.DeploymentID,
		ImportingDeploymentID: prepared.Migration.SourceDeploymentID,
		MigrationID:           prepared.Migration.MigrationID, Scope: prepared.Scope,
		SnapshotID:            uuid.MustParse("7f000000-0000-0000-0000-000000000014"),
		StateCommitmentDigest: commitment.String(), Version: serviceauthority.SchemaVersion,
	}
	if err := targetBindings.StageMigrationWriteFence(
		activation.ActivationManifest, reversePayload, anchor, 3_600,
	); err != nil {
		t.Fatal(err)
	}
	reverseSnapshot, err := targetBindings.SignStagedMigrationSnapshotAt(
		prepared.Scope,
		signerForDeployment(t, activationPayload.ActiveDeployment), 3_600,
	)
	if err != nil {
		t.Fatal(err)
	}
	snapshotDigest, err := reverseSnapshot.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	readiness, err := signerForDeployment(t, prepared.ActiveDeployment).
		SignMigrationReadiness(serviceauthority.MigrationReadinessPayload{
			AppliedStateCommitmentDigest: commitment.String(),
			AuthorityManifestDigest:      activationDigest,
			ExpiresAtMilliseconds:        9_000,
			ImportingDeploymentID:        prepared.ActiveDeployment.DeploymentID,
			MigrationID:                  prepared.Migration.MigrationID,
			ReadyAtMilliseconds:          3_800, Scope: prepared.Scope,
			SnapshotReferenceDigest: snapshotDigest,
			Version:                 serviceauthority.SchemaVersion,
		})
	if err != nil {
		t.Fatal(err)
	}
	evidence := serviceauthority.MigrationRollbackEvidence{
		ActivationEvidence: activation, SourceReadiness: readiness,
		TargetSnapshot: reverseSnapshot,
	}
	prerequisiteDigest, err := evidence.PrerequisitesReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	rollbackUntil := *prepared.Migration.RollbackUntilMilliseconds
	rollbackPayload := serviceauthority.ManifestPayload{
		ActiveDeployment:                    prepared.ActiveDeployment,
		IssuedAtMilliseconds:                3_900,
		Migration:                           prepared.Migration,
		MigrationPrerequisiteEvidenceDigest: &prerequisiteDigest,
		PredecessorManifestDigest:           &activationDigest,
		PreparedDeployments:                 []serviceauthority.DeploymentDescriptor{},
		Revision:                            activationPayload.Revision + 1, Scope: prepared.Scope,
		Transition:             serviceauthority.TransitionMigrationRollback,
		TransportPolicy:        prepared.TransportPolicy,
		ValidFromMilliseconds:  3_900,
		ValidUntilMilliseconds: &rollbackUntil,
		Version:                serviceauthority.SchemaVersion,
	}
	evidence.RollbackManifest = signActivationTestManifest(t, rollbackPayload, anchor)
	if _, err := evidence.Validate(anchor, 4_000); err != nil {
		t.Fatalf("synthetic rollback evidence: %v", err)
	}
	return evidence, sourceBindings
}
