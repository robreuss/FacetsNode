package migrationcoordinator

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/relay"
)

func TestDeviceSyncForwardBundleRoundTripsAuthenticatedStateAndBlobs(t *testing.T) {
	ctx := context.Background()
	preparation, anchor := loadPreparedMigrationFixture(t)
	prepared, err := preparation.PreparationManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	current, err := preparation.CurrentManifest.VerifiedPayload()
	if err != nil || current.Revision != 1 {
		t.Fatalf("fixture initial authority=%+v err=%v", current, err)
	}
	initial := postgres.DeviceSyncInitialAuthorityEvidence{
		Manifest:                preparation.CurrentManifest,
		ValidatedAtMilliseconds: current.ValidFromMilliseconds,
	}
	domainID := uuid.New()
	blobBytes := []byte("opaque Device Sync portable-bundle ciphertext")
	blobID := relay.BlobID(blobBytes)
	inventory := encodeBlobInventory(
		t,
		prepared.Scope.ScopeID,
		[]postgres.DeviceSyncMigrationBlobInventoryEntry{{
			DomainID:  domainID,
			BlobID:    blobID,
			ByteCount: int64(len(blobBytes)),
		}},
	)
	state := []byte("exact Device Sync portable-bundle semantic state")
	sourceBlobs, err := relay.NewFileBlobContentStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sourceBlobs.Put(
		ctx,
		relay.BlobScope{TenantID: prepared.Scope.ScopeID, DomainID: domainID},
		blobID,
		bytes.NewReader(blobBytes),
		int64(len(blobBytes)),
	); err != nil {
		t.Fatal(err)
	}
	custody, err := NewFileArtifactCustody(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	source := DeviceSyncSourceCoordinator{
		Exporter: &sourceExportStoreStub{},
		Custody:  custody,
		Bindings: preparedSourceBindingRegistry(t, preparation, anchor, true),
		Signer:   signerForDeployment(t, prepared.ActiveDeployment),
		LogicalExporter: sourceLogicalExporter(
			state,
			inventory,
		),
	}
	request := sourcePreparationRequest(t, preparation, anchor)
	result, err := source.Prepare(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(t.TempDir(), "forward.facets-migration")
	metadata, err := WriteDeviceSyncForwardBundle(
		ctx,
		bundlePath,
		preparation,
		result.Snapshot,
		anchor,
		initial,
		result.Transfer,
		sourceBlobs,
		request.Now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.BlobCount != 1 || metadata.BlobByteCount != int64(len(blobBytes)) ||
		metadata.PrincipalID != prepared.Scope.ScopeID ||
		metadata.MigrationID != result.ExportRecord.MigrationID {
		t.Fatalf("bundle metadata=%+v", metadata)
	}
	retriedMetadata, err := WriteDeviceSyncForwardBundle(
		ctx,
		bundlePath,
		preparation,
		result.Snapshot,
		anchor,
		initial,
		result.Transfer,
		sourceBlobs,
		request.Now,
	)
	if err != nil || !reflect.DeepEqual(retriedMetadata, metadata) {
		t.Fatalf("exact bundle retry=%+v err=%v", retriedMetadata, err)
	}
	opened, openedMetadata, closeBundle, err := OpenDeviceSyncForwardBundle(
		ctx, bundlePath, request.Now,
	)
	if err != nil {
		t.Fatal(err)
	}
	actualState, stateErr := io.ReadAll(opened.ServiceState)
	actualInventory, inventoryErr := io.ReadAll(opened.BlobInventory)
	openedBlob, blobErr := opened.BlobSource.Open(
		ctx,
		relay.BlobScope{TenantID: prepared.Scope.ScopeID, DomainID: domainID},
		blobID,
	)
	var actualBlob []byte
	if blobErr == nil {
		actualBlob, blobErr = io.ReadAll(openedBlob.Reader)
		blobErr = errors.Join(blobErr, openedBlob.Reader.Close())
	}
	closeErr := closeBundle()
	if stateErr != nil || inventoryErr != nil || blobErr != nil || closeErr != nil {
		t.Fatal(stateErr, inventoryErr, blobErr, closeErr)
	}
	if !bytes.Equal(actualState, state) ||
		!bytes.Equal(actualInventory, inventory) ||
		!bytes.Equal(actualBlob, blobBytes) ||
		!reflect.DeepEqual(openedMetadata, metadata) {
		t.Fatal("opened forward bundle changed authenticated content")
	}
	if _, err := opened.BlobSource.Put(
		ctx,
		relay.BlobScope{TenantID: prepared.Scope.ScopeID, DomainID: domainID},
		blobID,
		bytes.NewReader(blobBytes),
		int64(len(blobBytes)),
	); err == nil {
		t.Fatal("received portable bundle accepted a blob mutation")
	}
}

func TestDeviceSyncForwardBundleRejectsBlobTamperingAndSymlinks(t *testing.T) {
	ctx := context.Background()
	preparation, anchor := loadPreparedMigrationFixture(t)
	prepared, err := preparation.PreparationManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	current, err := preparation.CurrentManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	initial := postgres.DeviceSyncInitialAuthorityEvidence{
		Manifest:                preparation.CurrentManifest,
		ValidatedAtMilliseconds: current.ValidFromMilliseconds,
	}
	domainID := uuid.New()
	blobBytes := []byte("tamper-evident bundle blob")
	blobID := relay.BlobID(blobBytes)
	inventory := encodeBlobInventory(
		t,
		prepared.Scope.ScopeID,
		[]postgres.DeviceSyncMigrationBlobInventoryEntry{{
			DomainID: domainID, BlobID: blobID, ByteCount: int64(len(blobBytes)),
		}},
	)
	sourceBlobs, _ := relay.NewFileBlobContentStore(t.TempDir())
	_, _ = sourceBlobs.Put(
		ctx,
		relay.BlobScope{TenantID: prepared.Scope.ScopeID, DomainID: domainID},
		blobID,
		bytes.NewReader(blobBytes),
		int64(len(blobBytes)),
	)
	custody, _ := NewFileArtifactCustody(t.TempDir())
	source := DeviceSyncSourceCoordinator{
		Exporter: &sourceExportStoreStub{}, Custody: custody,
		Bindings: preparedSourceBindingRegistry(t, preparation, anchor, true),
		Signer:   signerForDeployment(t, prepared.ActiveDeployment),
		LogicalExporter: sourceLogicalExporter(
			[]byte("tamper test state"), inventory,
		),
	}
	request := sourcePreparationRequest(t, preparation, anchor)
	result, err := source.Prepare(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(t.TempDir(), "forward.facets-migration")
	if _, err := WriteDeviceSyncForwardBundle(
		ctx, bundlePath, preparation, result.Snapshot, anchor, initial,
		result.Transfer, sourceBlobs, request.Now,
	); err != nil {
		t.Fatal(err)
	}
	unsafeParent := t.TempDir()
	if err := os.Chmod(unsafeParent, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteDeviceSyncForwardBundle(
		ctx, filepath.Join(unsafeParent, "unsafe.facets-migration"),
		preparation, result.Snapshot, anchor, initial, result.Transfer,
		sourceBlobs, request.Now,
	); err == nil {
		t.Fatal("portable bundle was staged in a writable parent directory")
	}
	blobPath := filepath.Join(
		bundlePath,
		deviceSyncPortableBlobRoot,
		prepared.Scope.ScopeID.String(),
		domainID.String(),
		blobID,
	)
	tampered := append([]byte(nil), blobBytes...)
	tampered[0] ^= 0xff
	if err := os.WriteFile(blobPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, closeBundle, err := OpenDeviceSyncForwardBundle(
		ctx, bundlePath, request.Now,
	); err == nil {
		if closeBundle != nil {
			_ = closeBundle()
		}
		t.Fatal("tampered portable bundle blob was accepted")
	}

	linkBundle := filepath.Join(t.TempDir(), "link.facets-migration")
	if err := os.Symlink(bundlePath, linkBundle); err != nil {
		t.Fatal(err)
	}
	if _, _, closeBundle, err := OpenDeviceSyncForwardBundle(
		ctx, linkBundle, request.Now,
	); err == nil {
		if closeBundle != nil {
			_ = closeBundle()
		}
		t.Fatal("symbolic-link portable bundle root was accepted")
	}
}

func TestDeviceSyncRollbackBundleRoundTripsReverseTransfer(t *testing.T) {
	ctx := context.Background()
	preparation, anchor := loadPreparedMigrationFixture(t)
	prepared, err := preparation.PreparationManifest.VerifiedPayload()
	if err != nil || prepared.Migration == nil {
		t.Fatalf("prepared migration=%+v err=%v", prepared, err)
	}
	forwardSnapshot, forwardPayload := signSnapshotForArtifacts(
		t,
		preparation,
		anchor,
		[]byte("forward state"),
		encodeBlobInventory(t, prepared.Scope.ScopeID, nil),
	)
	activation := buildActivationEvidence(
		t, preparation, forwardSnapshot, forwardPayload, anchor,
	)
	activated, err := activation.ActivationManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	bindings := newTargetBindingRegistry(
		t, activated.ActiveDeployment.DeploymentID,
	)
	if err := bindings.ApplyMigrationPreparation(
		preparation, anchor, 2_200,
	); err != nil {
		t.Fatal(err)
	}
	if err := bindings.ApplyMigrationActivation(
		activation, anchor, 3_200,
	); err != nil {
		t.Fatal(err)
	}
	domainID := uuid.New()
	blobBytes := []byte("new ciphertext written on the replacement deployment")
	blobID := relay.BlobID(blobBytes)
	inventory := encodeBlobInventory(
		t,
		prepared.Scope.ScopeID,
		[]postgres.DeviceSyncMigrationBlobInventoryEntry{{
			DomainID: domainID, BlobID: blobID, ByteCount: int64(len(blobBytes)),
		}},
	)
	state := []byte("exact reverse Device Sync state")
	blobSource, err := relay.NewFileBlobContentStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := blobSource.Put(
		ctx,
		relay.BlobScope{TenantID: prepared.Scope.ScopeID, DomainID: domainID},
		blobID,
		bytes.NewReader(blobBytes),
		int64(len(blobBytes)),
	); err != nil {
		t.Fatal(err)
	}
	custody, err := NewFileArtifactCustody(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	source := DeviceSyncSourceCoordinator{
		Exporter: &sourceExportStoreStub{},
		Custody:  custody,
		Bindings: bindings,
		Signer:   signerForDeployment(t, activated.ActiveDeployment),
		LogicalExporter: sourceLogicalExporter(
			state,
			inventory,
		),
	}
	request := DeviceSyncRollbackSourcePreparationRequest{
		ActivationEvidence:      activation,
		Anchor:                  anchor,
		ExportWriteFenceID:      uuid.New(),
		SnapshotID:              uuid.New(),
		ServiceStateArtifactID:  uuid.New(),
		BlobInventoryArtifactID: uuid.New(),
		Now:                     timeUnixMilliForPortableBundleTest(3_600),
	}
	result, err := source.PrepareRollback(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(t.TempDir(), "rollback.facets-migration")
	metadata, err := WriteDeviceSyncRollbackBundle(
		ctx,
		bundlePath,
		activation,
		result.Snapshot,
		anchor,
		result.Transfer,
		blobSource,
		request.Now,
	)
	if err != nil {
		t.Fatal(err)
	}
	opened, openedMetadata, closeBundle, err := OpenDeviceSyncRollbackBundle(
		ctx, bundlePath, request.Now,
	)
	if err != nil {
		t.Fatal(err)
	}
	actualState, stateErr := io.ReadAll(opened.ServiceState)
	actualInventory, inventoryErr := io.ReadAll(opened.BlobInventory)
	closeErr := closeBundle()
	if stateErr != nil || inventoryErr != nil || closeErr != nil {
		t.Fatal(stateErr, inventoryErr, closeErr)
	}
	if !bytes.Equal(actualState, state) ||
		!bytes.Equal(actualInventory, inventory) ||
		!reflect.DeepEqual(openedMetadata, metadata) ||
		opened.ActivationEvidence.ActivationManifest.Signature.Signature !=
			activation.ActivationManifest.Signature.Signature {
		t.Fatal("opened rollback bundle changed authenticated content")
	}
}

func timeUnixMilliForPortableBundleTest(milliseconds int64) time.Time {
	return time.UnixMilli(milliseconds)
}
