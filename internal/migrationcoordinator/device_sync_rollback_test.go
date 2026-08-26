package migrationcoordinator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
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
	result, err := coordinator.PrepareRollback(
		context.Background(), DeviceSyncRollbackSourcePreparationRequest{
			ActivationEvidence: activation, Anchor: anchor,
			ExportWriteFenceID:      uuid.MustParse("7e000000-0000-0000-0000-000000000001"),
			SnapshotID:              uuid.MustParse("7e000000-0000-0000-0000-000000000002"),
			ServiceStateArtifactID:  uuid.MustParse("7e000000-0000-0000-0000-000000000003"),
			BlobInventoryArtifactID: uuid.MustParse("7e000000-0000-0000-0000-000000000004"),
			Now:                     time.UnixMilli(3_600),
		},
	)
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
