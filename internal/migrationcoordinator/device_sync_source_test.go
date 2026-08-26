package migrationcoordinator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

type sourceSnapshotReadStub struct{}

func (sourceSnapshotReadStub) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("unexpected source snapshot query")
}

func (sourceSnapshotReadStub) QueryRow(context.Context, string, ...any) pgx.Row {
	return nil
}

type sourceExportStoreStub struct {
	record            *postgres.DeviceSyncMigrationExportRecord
	calls             int
	materializerCalls int
}

func (stub *sourceExportStoreStub) MaterializeAndFenceDeviceSyncMigrationExport(
	ctx context.Context,
	principalID uuid.UUID,
	localDeploymentID uuid.UUID,
	authorityRevision uint64,
	authorityManifestDigest string,
	migrationID uuid.UUID,
	exportWriteFenceID uuid.UUID,
	nowMilliseconds int64,
	materializer postgres.DeviceSyncSnapshotMaterializer,
) (postgres.DeviceSyncMigrationExportRecord, error) {
	stub.calls++
	if stub.record != nil {
		return cloneSourceExportRecord(*stub.record), nil
	}
	stub.materializerCalls++
	canonicalPayload, err := materializer(
		ctx,
		sourceSnapshotReadStub{},
		postgres.DeviceSyncScopeEnforcement{PrincipalID: principalID, TenantID: principalID},
	)
	if err != nil {
		return postgres.DeviceSyncMigrationExportRecord{}, err
	}
	var payload serviceauthority.MigrationSnapshotPayload
	if err := json.Unmarshal(canonicalPayload, &payload); err != nil {
		return postgres.DeviceSyncMigrationExportRecord{}, err
	}
	digest := sha256.Sum256(canonicalPayload)
	record := postgres.DeviceSyncMigrationExportRecord{
		PrincipalID: principalID, TenantID: principalID, MigrationID: migrationID,
		ExportWriteFenceID: exportWriteFenceID, SnapshotID: payload.SnapshotID,
		AuthorityRevision: authorityRevision, AuthorityManifestDigest: authorityManifestDigest,
		ExportingDeploymentID:    localDeploymentID,
		ImportingDeploymentID:    payload.ImportingDeploymentID,
		CanonicalSnapshotPayload: append([]byte(nil), canonicalPayload...),
		SnapshotPayloadSHA256:    hex.EncodeToString(digest[:]),
		StateCommitmentDigest:    payload.StateCommitmentDigest,
		CapturedAtMilliseconds:   payload.CapturedAtMilliseconds,
		ExpiresAtMilliseconds:    payload.ExpiresAtMilliseconds,
	}
	stub.record = &record
	return cloneSourceExportRecord(record), nil
}

func cloneSourceExportRecord(
	record postgres.DeviceSyncMigrationExportRecord,
) postgres.DeviceSyncMigrationExportRecord {
	record.CanonicalSnapshotPayload = append([]byte(nil), record.CanonicalSnapshotPayload...)
	return record
}

func TestDeviceSyncSourceCoordinatorMaterializesFencesPromotesAndRetriesExactly(t *testing.T) {
	preparation, anchor := loadPreparedMigrationFixture(t)
	prepared, err := preparation.PreparationManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	state := []byte("canonical Device Sync source state")
	inventory := encodeBlobInventory(t, prepared.Scope.ScopeID, nil)
	store := &sourceExportStoreStub{}
	custody, err := NewFileArtifactCustody(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	registry := preparedSourceBindingRegistry(t, preparation, anchor, true)
	coordinator := DeviceSyncSourceCoordinator{
		Exporter: store, Custody: custody, Bindings: registry,
		Signer:          signerForDeployment(t, prepared.ActiveDeployment),
		LogicalExporter: sourceLogicalExporter(state, inventory),
	}
	request := sourcePreparationRequest(t, preparation, anchor)
	first, err := coordinator.Prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if store.calls != 1 || store.materializerCalls != 1 {
		t.Fatalf("source export calls=%d materializer calls=%d", store.calls, store.materializerCalls)
	}
	assertSourceTransferBytes(t, first.Transfer, state, inventory)
	draftDirectory := filepath.Join(
		custody.root, sourceDraftRootName, prepared.Scope.ScopeID.String(),
		first.ExportRecord.MigrationID.String(), first.ExportRecord.SnapshotID.String(),
	)
	if _, err := os.Lstat(draftDirectory); !os.IsNotExist(err) {
		t.Fatalf("promoted source draft remains at %s err=%v", draftDirectory, err)
	}

	reopenedCustody, err := NewFileArtifactCustody(custody.root)
	if err != nil {
		t.Fatal(err)
	}
	coordinator.Custody = reopenedCustody
	expiredRetry := request
	expiredRetry.Now = time.UnixMilli(30_000)
	second, err := coordinator.Prepare(context.Background(), expiredRetry)
	if err != nil {
		t.Fatal(err)
	}
	if store.calls != 2 || store.materializerCalls != 1 ||
		!bytes.Equal(first.Snapshot.Payload, second.Snapshot.Payload) ||
		first.Snapshot.Signature.Signature != second.Snapshot.Signature.Signature {
		t.Fatal("exact source retry did not reuse the fenced export and durable signature")
	}
	assertSourceTransferBytes(t, second.Transfer, state, inventory)

	backwardClock := request
	backwardClock.Now = time.UnixMilli(2_500)
	if _, err := coordinator.Prepare(context.Background(), backwardClock); err == nil {
		t.Fatal("source recovery accepted a clock before the durable capture instant")
	}

	conflicting := expiredRetry
	conflicting.SnapshotID = uuid.New()
	if _, err := coordinator.Prepare(context.Background(), conflicting); err == nil {
		t.Fatal("conflicting source operation identity reused an existing export fence")
	}
	finalStatePath := filepath.Join(
		reopenedCustody.root, "device-sync", prepared.Scope.ScopeID.String(),
		first.ExportRecord.MigrationID.String(), first.ExportRecord.SnapshotID.String(),
		serviceStateFileName,
	)
	tampered := append([]byte(nil), state...)
	tampered[0] ^= 0xff
	if err := os.WriteFile(finalStatePath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Prepare(context.Background(), expiredRetry); err == nil {
		t.Fatal("corrupted final source custody was accepted on exact retry")
	}
}

func TestDeviceSyncSourceCoordinatorCannotCreateExpiredExport(t *testing.T) {
	preparation, anchor := loadPreparedMigrationFixture(t)
	prepared, err := preparation.PreparationManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	store := &sourceExportStoreStub{}
	custody, err := NewFileArtifactCustody(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	request := sourcePreparationRequest(t, preparation, anchor)
	request.Now = time.UnixMilli(30_000)
	coordinator := DeviceSyncSourceCoordinator{
		Exporter: store, Custody: custody,
		Bindings: preparedSourceBindingRegistry(t, preparation, anchor, true),
		Signer:   signerForDeployment(t, prepared.ActiveDeployment),
		LogicalExporter: sourceLogicalExporter(
			[]byte("state"), encodeBlobInventory(t, prepared.Scope.ScopeID, nil),
		),
	}
	if _, err := coordinator.Prepare(context.Background(), request); err == nil {
		t.Fatal("expired preparation created a new Device Sync export")
	}
	if store.record != nil || store.materializerCalls != 1 {
		t.Fatal("expired source operation persisted export evidence")
	}
}

func TestDeviceSyncSourceCoordinatorRejectsConflictingExporterCommitment(t *testing.T) {
	preparation, anchor := loadPreparedMigrationFixture(t)
	prepared, err := preparation.PreparationManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	state := []byte("state")
	inventory := encodeBlobInventory(t, prepared.Scope.ScopeID, nil)
	exporter := sourceLogicalExporter(state, inventory)
	conflictingExporter := func(
		ctx context.Context,
		tx postgres.DeviceSyncSnapshotReadTransaction,
		principalID uuid.UUID,
		stateDestination io.Writer,
		inventoryDestination io.Writer,
	) (postgres.DeviceSyncMigrationArtifactDigests, error) {
		digests, err := exporter(
			ctx, tx, principalID, stateDestination, inventoryDestination,
		)
		if err == nil {
			digests.StateCommitment[0] ^= 0xff
		}
		return digests, err
	}
	store := &sourceExportStoreStub{}
	custody, err := NewFileArtifactCustody(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	coordinator := DeviceSyncSourceCoordinator{
		Exporter: store, Custody: custody,
		Bindings:        preparedSourceBindingRegistry(t, preparation, anchor, true),
		Signer:          signerForDeployment(t, prepared.ActiveDeployment),
		LogicalExporter: conflictingExporter,
	}
	if _, err := coordinator.Prepare(
		context.Background(), sourcePreparationRequest(t, preparation, anchor),
	); err == nil {
		t.Fatal("source exporter supplied a state commitment unrelated to its artifacts")
	}
	if store.record != nil {
		t.Fatal("conflicting source state commitment reached the durable export fence")
	}
}

func TestDeviceSyncSourceCoordinatorRejectsCorruptedDurableDraft(t *testing.T) {
	preparation, anchor := loadPreparedMigrationFixture(t)
	prepared, err := preparation.PreparationManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	state := []byte("canonical Device Sync source state")
	inventory := encodeBlobInventory(t, prepared.Scope.ScopeID, nil)
	store := &sourceExportStoreStub{}
	custody, err := NewFileArtifactCustody(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	request := sourcePreparationRequest(t, preparation, anchor)
	// The first registry deliberately lacks the prepared authority binding. The
	// database callback commits a durable draft, then registry fencing fails.
	incompleteRegistry := preparedSourceBindingRegistry(t, preparation, anchor, false)
	coordinator := DeviceSyncSourceCoordinator{
		Exporter: store, Custody: custody, Bindings: incompleteRegistry,
		Signer:          signerForDeployment(t, prepared.ActiveDeployment),
		LogicalExporter: sourceLogicalExporter(state, inventory),
	}
	if _, err := coordinator.Prepare(context.Background(), request); err == nil {
		t.Fatal("source preparation unexpectedly passed without prepared authority")
	}
	if store.record == nil || store.materializerCalls != 1 {
		t.Fatal("source draft was not materialized before the simulated registry failure")
	}
	draftStatePath := filepath.Join(
		custody.root, sourceDraftRootName, prepared.Scope.ScopeID.String(),
		store.record.MigrationID.String(), store.record.SnapshotID.String(), serviceStateFileName,
	)
	tampered := append([]byte(nil), state...)
	tampered[0] ^= 0xff
	if err := os.WriteFile(draftStatePath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}

	coordinator.Bindings = preparedSourceBindingRegistry(t, preparation, anchor, true)
	if _, err := coordinator.Prepare(context.Background(), request); err == nil {
		t.Fatal("corrupted durable source draft was accepted")
	}
	if _, err := coordinator.Bindings.LoadConfirmedMigrationSnapshot(
		prepared.Scope, coordinator.Signer,
	); err == nil {
		t.Fatal("corrupted source draft caused a new migration snapshot signature")
	}
}

func sourceLogicalExporter(
	state []byte,
	inventory []byte,
) DeviceSyncLogicalStateExporter {
	return func(
		_ context.Context,
		_ postgres.DeviceSyncSnapshotReadTransaction,
		_ uuid.UUID,
		stateDestination io.Writer,
		inventoryDestination io.Writer,
	) (postgres.DeviceSyncMigrationArtifactDigests, error) {
		if _, err := stateDestination.Write(state); err != nil {
			return postgres.DeviceSyncMigrationArtifactDigests{}, err
		}
		if _, err := inventoryDestination.Write(inventory); err != nil {
			return postgres.DeviceSyncMigrationArtifactDigests{}, err
		}
		stateDigest := sha256.Sum256(state)
		inventoryDigest := sha256.Sum256(inventory)
		return postgres.DeviceSyncMigrationArtifactDigests{
			StateArtifactSHA256:    postgres.DeviceSyncMigrationDigest(stateDigest),
			StateArtifactByteCount: int64(len(state)),
			BlobInventorySHA256:    postgres.DeviceSyncMigrationDigest(inventoryDigest),
			BlobInventoryByteCount: int64(len(inventory)),
			StateCommitment: postgres.DeviceSyncMigrationStateCommitment(
				postgres.DeviceSyncMigrationDigest(stateDigest),
				postgres.DeviceSyncMigrationDigest(inventoryDigest),
			),
		}, nil
	}
}

func sourcePreparationRequest(
	t *testing.T,
	preparation serviceauthority.MigrationPreparation,
	anchor serviceauthority.TrustAnchor,
) DeviceSyncSourcePreparationRequest {
	t.Helper()
	return DeviceSyncSourcePreparationRequest{
		Preparation: preparation, Anchor: anchor,
		ExportWriteFenceID:      uuid.MustParse("71000000-0000-0000-0000-000000000001"),
		SnapshotID:              uuid.MustParse("71000000-0000-0000-0000-000000000002"),
		ServiceStateArtifactID:  uuid.MustParse("71000000-0000-0000-0000-000000000003"),
		BlobInventoryArtifactID: uuid.MustParse("71000000-0000-0000-0000-000000000004"),
		Now:                     time.UnixMilli(3_000),
	}
}

func preparedSourceBindingRegistry(
	t *testing.T,
	preparation serviceauthority.MigrationPreparation,
	anchor serviceauthority.TrustAnchor,
	applyPreparation bool,
) *serviceauthority.BindingRegistry {
	t.Helper()
	prepared, err := preparation.PreparationManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	current, err := preparation.CurrentManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	currentDigest, err := preparation.CurrentManifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "bindings.json")
	if err := os.WriteFile(path, []byte(`{"bindings":[],"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	registry, err := serviceauthority.LoadBindingRegistry(
		path, prepared.ActiveDeployment.DeploymentID,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.Close() })
	currentManifest := preparation.CurrentManifest
	if err := registry.Activate(current.Scope, serviceauthority.CurrentBinding{
		Revision: current.Revision, Digest: currentDigest,
		DeploymentID: current.ActiveDeployment.DeploymentID, Manifest: &currentManifest,
	}); err != nil {
		t.Fatal(err)
	}
	if applyPreparation {
		if err := registry.ApplyMigrationPreparation(preparation, anchor, 2_200); err != nil {
			t.Fatal(err)
		}
	}
	return registry
}

func assertSourceTransferBytes(
	t *testing.T,
	transfer PreparedDeviceSyncTransfer,
	state []byte,
	inventory []byte,
) {
	t.Helper()
	artifacts, closeArtifacts, err := transfer.OpenArtifacts()
	if err != nil {
		t.Fatal(err)
	}
	actualState, stateErr := io.ReadAll(artifacts.ServiceState)
	actualInventory, inventoryErr := io.ReadAll(artifacts.BlobInventory)
	closeErr := closeArtifacts()
	if stateErr != nil || inventoryErr != nil || closeErr != nil {
		t.Fatal(errors.Join(stateErr, inventoryErr, closeErr))
	}
	if !bytes.Equal(actualState, state) || !bytes.Equal(actualInventory, inventory) {
		t.Fatal("source transfer custody differs from materialized artifacts")
	}
}
