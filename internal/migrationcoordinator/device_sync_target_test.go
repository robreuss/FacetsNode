package migrationcoordinator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

type migrationFixtureSubset struct {
	AuthorityAnchor  serviceauthority.TrustAnchor `json:"authorityAnchor"`
	RollbackEvidence struct {
		ActivationEvidence serviceauthority.MigrationActivationEvidence `json:"activationEvidence"`
	} `json:"rollbackEvidence"`
}

type targetImporterStub struct {
	calls       int
	expected    serviceauthority.MigrationSnapshotPayload
	state       []byte
	inventory   []byte
	afterImport func() error
}

func (stub *targetImporterStub) ImportPreparedDeviceSyncMigrationStandby(
	_ context.Context,
	localDeploymentID uuid.UUID,
	_ serviceauthority.MigrationPreparation,
	_ serviceauthority.MigrationSnapshot,
	_ serviceauthority.TrustAnchor,
	_ postgres.DeviceSyncInitialAuthorityEvidence,
	_ int64,
	staged postgres.DeviceSyncMigrationStagedArtifacts,
) (postgres.DeviceSyncMigrationImportRecord, error) {
	stub.calls++
	state, err := ioReadAllAndRewind(staged.ServiceState)
	if err != nil {
		return postgres.DeviceSyncMigrationImportRecord{}, err
	}
	inventory, err := ioReadAllAndRewind(staged.BlobInventory)
	if err != nil {
		return postgres.DeviceSyncMigrationImportRecord{}, err
	}
	if !bytes.Equal(state, stub.state) || !bytes.Equal(inventory, stub.inventory) {
		return postgres.DeviceSyncMigrationImportRecord{}, errors.New("importer received different staged artifacts")
	}
	if stub.afterImport != nil {
		if err := stub.afterImport(); err != nil {
			return postgres.DeviceSyncMigrationImportRecord{}, err
		}
	}
	return postgres.DeviceSyncMigrationImportRecord{
		PrincipalID:           stub.expected.Scope.ScopeID,
		MigrationID:           stub.expected.MigrationID,
		ImportingDeploymentID: localDeploymentID,
		StateCommitmentDigest: stub.expected.StateCommitmentDigest,
	}, nil
}

func TestDeviceSyncTargetCoordinatorCopiesBlobsBeforeReadinessAndRetriesExactly(t *testing.T) {
	ctx := context.Background()
	principalID := uuid.MustParse("1a000000-0000-0000-0000-000000000001")
	domainID := uuid.New()
	blobBytes := []byte("opaque encrypted Device Sync migration blob")
	blobID := relay.BlobID(blobBytes)
	inventory := encodeBlobInventory(t, principalID, []postgres.DeviceSyncMigrationBlobInventoryEntry{{
		DomainID: domainID, BlobID: blobID, ByteCount: int64(len(blobBytes)),
	}})
	state := []byte("canonical service state bytes")
	preparation, anchor := loadPreparedMigrationFixture(t)
	snapshot, payload := signSnapshotForArtifacts(t, preparation, anchor, state, inventory)
	validated, err := snapshot.ValidatePreparedTransfer(preparation, anchor, 3_000)
	if err != nil {
		t.Fatal(err)
	}
	targetSigner := signerForDeployment(t, validated.TargetDeploymentOffer.Deployment)
	sourceBlobs, err := relay.NewFileBlobContentStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sourceBlobs.Put(
		ctx, relay.BlobScope{TenantID: principalID, DomainID: domainID},
		blobID, bytes.NewReader(blobBytes), int64(len(blobBytes)),
	); err != nil {
		t.Fatal(err)
	}
	targetBlobs, err := relay.NewFileBlobContentStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	custody, err := NewFileArtifactCustody(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	importer := &targetImporterStub{expected: payload, state: state, inventory: inventory}
	importer.afterImport = func() error {
		return targetBlobs.DeleteBlob(
			ctx, relay.BlobScope{TenantID: principalID, DomainID: domainID}, blobID,
		)
	}
	coordinator := DeviceSyncTargetCoordinator{
		Importer: importer, Custody: custody, BlobStore: targetBlobs, Signer: targetSigner,
	}
	request := DeviceSyncTargetPreparationRequest{
		Preparation: preparation, Snapshot: snapshot, Anchor: anchor,
		InitialAuthority: postgres.DeviceSyncInitialAuthorityEvidence{},
		ServiceState:     bytes.NewReader(state), BlobInventory: bytes.NewReader(inventory),
		BlobSource: sourceBlobs, Now: time.UnixMilli(3_000),
	}
	first, err := coordinator.Prepare(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if first.Transfer.BlobCount != 1 || first.Transfer.ByteCount != int64(len(blobBytes)) ||
		importer.calls != 1 {
		t.Fatalf("first preparation=%+v importer calls=%d", first.Transfer, importer.calls)
	}
	readinessPayload, err := first.Readiness.VerifiedPayload(nil)
	if err != nil || readinessPayload.AppliedStateCommitmentDigest != payload.StateCommitmentDigest ||
		readinessPayload.ExpiresAtMilliseconds != payload.ExpiresAtMilliseconds {
		t.Fatalf("readiness payload=%+v err=%v", readinessPayload, err)
	}
	copied, err := targetBlobs.Open(
		ctx, relay.BlobScope{TenantID: principalID, DomainID: domainID}, blobID,
	)
	if err != nil {
		t.Fatal(err)
	}
	actual, readErr := ioReadAllAndClose(copied.Reader)
	if readErr != nil || !bytes.Equal(actual, blobBytes) {
		t.Fatalf("copied blob differs err=%v", readErr)
	}

	request.ServiceState = bytes.NewReader(state)
	request.BlobInventory = bytes.NewReader(inventory)
	second, err := coordinator.Prepare(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if importer.calls != 2 || !bytes.Equal(first.Readiness.Payload, second.Readiness.Payload) ||
		first.Readiness.Signature.Signature != second.Readiness.Signature.Signature {
		t.Fatal("exact retry did not reuse durable live readiness")
	}
	readinessPath := filepath.Join(
		custody.root, "device-sync", principalID.String(), payload.MigrationID.String(),
		payload.SnapshotID.String(), readinessFileName,
	)
	attackerSeed := make([]byte, 32)
	attackerSeed[31] = 31
	attacker, err := serviceauthority.NewDeploymentSigner(
		targetSigner.DeploymentID(), attackerSeed,
	)
	if err != nil || attacker.PublicSigningKeyX963() == targetSigner.PublicSigningKeyX963() {
		t.Fatal("failed to construct alternate deployment-key attacker")
	}
	forgedReadiness, err := attacker.SignMigrationReadiness(readinessPayload)
	if err != nil {
		t.Fatal(err)
	}
	forgedRecord, err := json.Marshal(forgedReadiness)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(readinessPath, forgedRecord, 0o600); err != nil {
		t.Fatal(err)
	}
	request.ServiceState = bytes.NewReader(state)
	request.BlobInventory = bytes.NewReader(inventory)
	if _, err := coordinator.Prepare(ctx, request); err == nil {
		t.Fatal("readiness signed by a substituted deployment key was accepted")
	}
}

func TestFileArtifactCustodyRejectsSymlinkRoot(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "custody")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileArtifactCustody(link); err == nil {
		t.Fatal("symlink migration artifact custody root was accepted")
	}
}

func TestDeviceSyncTargetCoordinatorRejectsTamperedArtifactBeforeBlobCopyOrImport(t *testing.T) {
	principalID := uuid.MustParse("1a000000-0000-0000-0000-000000000001")
	inventory := encodeBlobInventory(t, principalID, nil)
	state := []byte("canonical service state bytes")
	preparation, anchor := loadPreparedMigrationFixture(t)
	snapshot, payload := signSnapshotForArtifacts(t, preparation, anchor, state, inventory)
	validated, err := snapshot.ValidatePreparedTransfer(preparation, anchor, 3_000)
	if err != nil {
		t.Fatal(err)
	}
	targetSigner := signerForDeployment(t, validated.TargetDeploymentOffer.Deployment)
	blobSource, _ := relay.NewFileBlobContentStore(t.TempDir())
	blobTarget, _ := relay.NewFileBlobContentStore(t.TempDir())
	custody, _ := NewFileArtifactCustody(t.TempDir())
	importer := &targetImporterStub{expected: payload, state: state, inventory: inventory}
	tampered := append([]byte(nil), state...)
	tampered[0] ^= 0xff
	_, err = (&DeviceSyncTargetCoordinator{
		Importer: importer, Custody: custody, BlobStore: blobTarget, Signer: targetSigner,
	}).Prepare(context.Background(), DeviceSyncTargetPreparationRequest{
		Preparation: preparation, Snapshot: snapshot, Anchor: anchor,
		ServiceState: bytes.NewReader(tampered), BlobInventory: bytes.NewReader(inventory),
		BlobSource: blobSource, Now: time.UnixMilli(3_000),
	})
	if err == nil || importer.calls != 0 {
		t.Fatalf("tampered state err=%v importer calls=%d", err, importer.calls)
	}
}

func TestWalkBlobInventoryAuthenticatesBeforeVisitorSideEffects(t *testing.T) {
	principalID := uuid.New()
	inventory := encodeBlobInventory(t, principalID, nil)
	tampered := append([]byte(nil), inventory...)
	tampered[len(tampered)-1] ^= 1
	// Model a source that signed the transfer digest of a structurally malformed
	// inventory. The internal body checksum still has to fail before visits.
	digest := sha256.Sum256(tampered)
	visits := 0
	if err := postgres.WalkDeviceSyncMigrationBlobInventory(
		context.Background(), bytes.NewReader(tampered), principalID,
		postgres.DeviceSyncMigrationDigest(digest),
		func(postgres.DeviceSyncMigrationBlobInventoryEntry) error { visits++; return nil },
	); err == nil || visits != 0 {
		t.Fatalf("tampered inventory err=%v visits=%d", err, visits)
	}
}

func TestWalkBlobInventoryRejectsBlobLargerThanRelayContract(t *testing.T) {
	principalID := uuid.New()
	inventory := encodeBlobInventory(t, principalID, []postgres.DeviceSyncMigrationBlobInventoryEntry{{
		DomainID: uuid.New(), BlobID: relay.BlobID([]byte("small")),
		ByteCount: relay.MaximumBlobByteCount + 1,
	}})
	digest := sha256.Sum256(inventory)
	visits := 0
	if err := postgres.WalkDeviceSyncMigrationBlobInventory(
		context.Background(), bytes.NewReader(inventory), principalID,
		postgres.DeviceSyncMigrationDigest(digest),
		func(postgres.DeviceSyncMigrationBlobInventoryEntry) error { visits++; return nil },
	); err == nil || visits != 0 {
		t.Fatalf("oversized blob inventory err=%v visits=%d", err, visits)
	}
}

func signSnapshotForArtifacts(
	t *testing.T,
	preparation serviceauthority.MigrationPreparation,
	anchor serviceauthority.TrustAnchor,
	state, inventory []byte,
) (serviceauthority.MigrationSnapshot, serviceauthority.MigrationSnapshotPayload) {
	t.Helper()
	prepared, err := preparation.PreparationManifest.VerifiedPayload()
	if err != nil || prepared.Migration == nil {
		t.Fatal(err)
	}
	targetOffer, err := preparation.TargetOffer.VerifiedPayload(nil)
	if err != nil {
		t.Fatal(err)
	}
	targetDeployment, err := targetOffer.DeploymentOffer.VerifiedPayload(nil)
	if err != nil {
		t.Fatal(err)
	}
	manifestDigest, err := preparation.PreparationManifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	stateDigest := sha256.Sum256(state)
	inventoryDigest := sha256.Sum256(inventory)
	commitment := postgres.DeviceSyncMigrationStateCommitment(
		postgres.DeviceSyncMigrationDigest(stateDigest),
		postgres.DeviceSyncMigrationDigest(inventoryDigest),
	)
	payload := serviceauthority.MigrationSnapshotPayload{
		Artifacts: []serviceauthority.MigrationArtifactDescriptor{
			{ArtifactID: uuid.MustParse("6f000000-0000-0000-0000-000000000011"), ByteCount: int64(len(state)), Kind: serviceauthority.ArtifactServiceStateSnapshot, TransferDigest: hex.EncodeToString(stateDigest[:])},
			{ArtifactID: uuid.MustParse("6f000000-0000-0000-0000-000000000012"), ByteCount: int64(len(inventory)), Kind: serviceauthority.ArtifactBlobInventory, TransferDigest: hex.EncodeToString(inventoryDigest[:])},
		},
		AuthorityManifestDigest: manifestDigest,
		CapturedAtMilliseconds:  2_500,
		ExpiresAtMilliseconds:   9_000,
		ExportWriteFenceID:      uuid.New(),
		ExportingDeploymentID:   prepared.ActiveDeployment.DeploymentID,
		ImportingDeploymentID:   targetDeployment.Deployment.DeploymentID,
		MigrationID:             prepared.Migration.MigrationID,
		Scope:                   prepared.Scope,
		SnapshotID:              uuid.New(),
		StateCommitmentDigest:   commitment.String(),
		Version:                 serviceauthority.SchemaVersion,
	}
	bindingPath := filepath.Join(t.TempDir(), "bindings.json")
	if err := os.WriteFile(bindingPath, []byte(`{"bindings":[],"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	registry, err := serviceauthority.LoadBindingRegistry(bindingPath, prepared.ActiveDeployment.DeploymentID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.Close() })
	current, err := preparation.CurrentManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	currentDigest, err := preparation.CurrentManifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	currentManifest := preparation.CurrentManifest
	if err := registry.Activate(current.Scope, serviceauthority.CurrentBinding{
		Revision: current.Revision, Digest: currentDigest,
		DeploymentID: current.ActiveDeployment.DeploymentID, Manifest: &currentManifest,
	}); err != nil {
		t.Fatal(err)
	}
	if err := registry.ApplyMigrationPreparation(preparation, anchor, 2_200); err != nil {
		t.Fatal(err)
	}
	if err := registry.StageMigrationWriteFence(preparation.PreparationManifest, payload, anchor, 3_000); err != nil {
		t.Fatal(err)
	}
	snapshot, err := registry.SignStagedMigrationSnapshotAt(
		prepared.Scope, signerForDeployment(t, prepared.ActiveDeployment), 3_000,
	)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot, payload
}

func loadPreparedMigrationFixture(t *testing.T) (
	serviceauthority.MigrationPreparation,
	serviceauthority.TrustAnchor,
) {
	t.Helper()
	_, currentFile, _, _ := runtime.Caller(0)
	encoded, err := os.ReadFile(filepath.Join(
		filepath.Dir(currentFile), "..", "serviceauthority", "testdata", "service-migration-portable-v2.json",
	))
	if err != nil {
		t.Fatal(err)
	}
	var fixture migrationFixtureSubset
	if err := json.Unmarshal(encoded, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture.RollbackEvidence.ActivationEvidence.Preparation, fixture.AuthorityAnchor
}

func signerForDeployment(
	t *testing.T,
	deployment serviceauthority.DeploymentDescriptor,
) *serviceauthority.DeploymentSigner {
	t.Helper()
	for scalar := byte(1); scalar <= 16; scalar++ {
		seed := make([]byte, 32)
		seed[31] = scalar
		signer, err := serviceauthority.NewDeploymentSigner(deployment.DeploymentID, seed)
		if err == nil && signer.PublicSigningKeyX963() == deployment.PublicSigningKeyX963 {
			return signer
		}
	}
	t.Fatal("fixture deployment signing key not found")
	return nil
}

func encodeBlobInventory(
	t *testing.T,
	principalID uuid.UUID,
	entries []postgres.DeviceSyncMigrationBlobInventoryEntry,
) []byte {
	t.Helper()
	var body bytes.Buffer
	body.Write([]byte("FACETS-DS-BLOBS\x00"))
	if err := binary.Write(&body, binary.BigEndian, uint16(1)); err != nil {
		t.Fatal(err)
	}
	body.Write(principalID[:])
	if err := binary.Write(&body, binary.BigEndian, uint64(len(entries))); err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		body.Write(entry.DomainID[:])
		if err := binary.Write(&body, binary.BigEndian, uint64(len(entry.BlobID))); err != nil {
			t.Fatal(err)
		}
		body.WriteString(entry.BlobID)
		if err := binary.Write(&body, binary.BigEndian, uint64(entry.ByteCount)); err != nil {
			t.Fatal(err)
		}
	}
	checksum := sha256.Sum256(body.Bytes())
	body.Write(checksum[:])
	return body.Bytes()
}

func ioReadAllAndRewind(source interface {
	io.Reader
	io.Seeker
}) ([]byte, error) {
	if _, err := source.Seek(0, 0); err != nil {
		return nil, err
	}
	value, err := io.ReadAll(source)
	if err != nil {
		return nil, err
	}
	_, seekErr := source.Seek(0, 0)
	return value, seekErr
}

func ioReadAllAndClose(source io.ReadCloser) ([]byte, error) {
	value, err := io.ReadAll(source)
	return value, errors.Join(err, source.Close())
}
