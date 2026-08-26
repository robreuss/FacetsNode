package migrationcoordinator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

const (
	sourceDraftCustodyVersion = 1
	sourceDraftRootName       = "source-device-sync"
	snapshotPayloadFileName   = "snapshot-payload.json"
)

type sourceDeviceSyncDraftMetadata struct {
	BlobInventoryArtifactID    uuid.UUID `json:"blobInventoryArtifactID"`
	CanonicalPayloadSHA256     string    `json:"canonicalPayloadSHA256"`
	MigrationID                uuid.UUID `json:"migrationID"`
	PreparationReferenceDigest string    `json:"preparationReferenceDigest"`
	PrincipalID                uuid.UUID `json:"principalID"`
	ServiceStateArtifactID     uuid.UUID `json:"serviceStateArtifactID"`
	SnapshotID                 uuid.UUID `json:"snapshotID"`
	Version                    int       `json:"version"`
}

type sourceDeviceSyncScratch struct {
	directory         string
	ServiceState      *os.File
	BlobInventory     *os.File
	ServiceStatePath  string
	BlobInventoryPath string
	closed            bool
}

func (scratch *sourceDeviceSyncScratch) SyncAndClose() error {
	if scratch == nil || scratch.closed || scratch.ServiceState == nil || scratch.BlobInventory == nil {
		return serviceauthority.ErrInvalid
	}
	scratch.closed = true
	var result error
	for _, file := range []*os.File{scratch.ServiceState, scratch.BlobInventory} {
		if err := file.Sync(); err != nil {
			result = errors.Join(result, err)
		}
		if err := file.Close(); err != nil {
			result = errors.Join(result, err)
		}
	}
	return result
}

func (scratch *sourceDeviceSyncScratch) Remove() {
	if scratch == nil {
		return
	}
	if !scratch.closed {
		_ = scratch.ServiceState.Close()
		_ = scratch.BlobInventory.Close()
		scratch.closed = true
	}
	_ = os.RemoveAll(scratch.directory)
}

type sourceDeviceSyncArtifactDraft struct {
	directory               string
	metadata                sourceDeviceSyncDraftMetadata
	serviceStateDescriptor  serviceauthority.MigrationArtifactDescriptor
	blobInventoryDescriptor serviceauthority.MigrationArtifactDescriptor
}

func (custody *FileArtifactCustody) newSourceScratch() (*sourceDeviceSyncScratch, error) {
	if custody == nil {
		return nil, serviceauthority.ErrInvalid
	}
	directory, err := os.MkdirTemp(filepath.Join(custody.root, ".staging"), "source-device-sync-*")
	if err != nil {
		return nil, fmt.Errorf("create Device Sync source scratch: %w", err)
	}
	failed := true
	defer func() {
		if failed {
			_ = os.RemoveAll(directory)
		}
	}()
	if err := os.Chmod(directory, 0o700); err != nil {
		return nil, err
	}
	statePath := filepath.Join(directory, serviceStateFileName)
	state, err := os.OpenFile(statePath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	inventoryPath := filepath.Join(directory, blobInventoryFileName)
	inventory, err := os.OpenFile(inventoryPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		_ = state.Close()
		return nil, err
	}
	failed = false
	return &sourceDeviceSyncScratch{
		directory: directory, ServiceState: state, BlobInventory: inventory,
		ServiceStatePath: statePath, BlobInventoryPath: inventoryPath,
	}, nil
}

func (custody *FileArtifactCustody) stageSourceDeviceSyncDraft(
	ctx context.Context,
	preparation serviceauthority.MigrationPreparation,
	payload serviceauthority.MigrationSnapshotPayload,
	canonicalPayload []byte,
	serviceStatePath string,
	blobInventoryPath string,
) (sourceDeviceSyncArtifactDraft, error) {
	if custody == nil || ctx == nil || serviceStatePath == "" || blobInventoryPath == "" ||
		payload.Scope.Kind != serviceauthority.ScopeDeviceSync || payload.Validate(nil) != nil {
		return sourceDeviceSyncArtifactDraft{}, serviceauthority.ErrInvalid
	}
	encodedPayload, err := json.Marshal(payload)
	if err != nil || !bytes.Equal(encodedPayload, canonicalPayload) {
		return sourceDeviceSyncArtifactDraft{}, serviceauthority.ErrInvalid
	}
	stateDescriptor, inventoryDescriptor, err := migrationArtifactDescriptors(payload)
	if err != nil {
		return sourceDeviceSyncArtifactDraft{}, err
	}
	preparationDigest, err := preparation.ReferenceDigest()
	if err != nil {
		return sourceDeviceSyncArtifactDraft{}, err
	}
	payloadDigest := sha256.Sum256(canonicalPayload)
	metadata := sourceDeviceSyncDraftMetadata{
		BlobInventoryArtifactID: inventoryDescriptor.ArtifactID,
		CanonicalPayloadSHA256:  hex.EncodeToString(payloadDigest[:]),
		MigrationID:             payload.MigrationID, PreparationReferenceDigest: preparationDigest,
		PrincipalID: payload.Scope.ScopeID, ServiceStateArtifactID: stateDescriptor.ArtifactID,
		SnapshotID: payload.SnapshotID, Version: sourceDraftCustodyVersion,
	}
	if err := validateSourceDraftMetadata(metadata); err != nil {
		return sourceDeviceSyncArtifactDraft{}, err
	}
	draft := sourceDeviceSyncArtifactDraft{
		directory: custody.sourceDraftDirectory(metadata), metadata: metadata,
		serviceStateDescriptor: stateDescriptor, blobInventoryDescriptor: inventoryDescriptor,
	}
	preparationRecord, err := json.Marshal(preparation)
	if err != nil {
		return sourceDeviceSyncArtifactDraft{}, err
	}
	metadataRecord, err := json.Marshal(metadata)
	if err != nil {
		return sourceDeviceSyncArtifactDraft{}, err
	}

	state, err := os.Open(serviceStatePath)
	if err != nil {
		return sourceDeviceSyncArtifactDraft{}, err
	}
	defer state.Close()
	inventory, err := os.Open(blobInventoryPath)
	if err != nil {
		return sourceDeviceSyncArtifactDraft{}, err
	}
	defer inventory.Close()

	custody.mu.Lock()
	defer custody.mu.Unlock()
	if found, err := verifySourceDraftDirectory(
		ctx, draft, preparationRecord, canonicalPayload, metadataRecord,
	); found || err != nil {
		return draft, err
	}

	stagingDirectory, err := os.MkdirTemp(
		filepath.Join(custody.root, ".staging"), "source-draft-*",
	)
	if err != nil {
		return sourceDeviceSyncArtifactDraft{}, err
	}
	defer func() { _ = os.RemoveAll(stagingDirectory) }()
	if err := os.Chmod(stagingDirectory, 0o700); err != nil {
		return sourceDeviceSyncArtifactDraft{}, err
	}
	if err := stageExactArtifact(
		ctx, filepath.Join(stagingDirectory, serviceStateFileName), state, stateDescriptor,
	); err != nil {
		return sourceDeviceSyncArtifactDraft{}, err
	}
	if err := stageExactArtifact(
		ctx, filepath.Join(stagingDirectory, blobInventoryFileName), inventory, inventoryDescriptor,
	); err != nil {
		return sourceDeviceSyncArtifactDraft{}, err
	}
	for name, value := range map[string][]byte{
		preparationFileName:     preparationRecord,
		snapshotPayloadFileName: canonicalPayload,
		metadataFileName:        metadataRecord,
	} {
		if len(value) > maximumEvidenceByteCount {
			return sourceDeviceSyncArtifactDraft{}, errors.New("Device Sync source draft evidence is too large")
		}
		if err := writeSyncedProtectedFile(filepath.Join(stagingDirectory, name), value); err != nil {
			return sourceDeviceSyncArtifactDraft{}, err
		}
	}
	if err := syncCustodyDirectory(stagingDirectory); err != nil {
		return sourceDeviceSyncArtifactDraft{}, err
	}
	parent := filepath.Dir(draft.directory)
	if err := ensurePrivateCustodyDirectory(custody.root, parent); err != nil {
		return sourceDeviceSyncArtifactDraft{}, err
	}
	if err := os.Rename(stagingDirectory, draft.directory); err != nil {
		return sourceDeviceSyncArtifactDraft{}, fmt.Errorf("commit Device Sync source draft: %w", err)
	}
	if err := syncCustodyDirectory(parent); err != nil {
		return sourceDeviceSyncArtifactDraft{}, err
	}
	return draft, nil
}

func (custody *FileArtifactCustody) openSourceDeviceSyncDraft(
	ctx context.Context,
	preparation serviceauthority.MigrationPreparation,
	payload serviceauthority.MigrationSnapshotPayload,
	canonicalPayload []byte,
) (sourceDeviceSyncArtifactDraft, error) {
	if custody == nil || ctx == nil || payload.Validate(nil) != nil {
		return sourceDeviceSyncArtifactDraft{}, serviceauthority.ErrInvalid
	}
	stateDescriptor, inventoryDescriptor, err := migrationArtifactDescriptors(payload)
	if err != nil {
		return sourceDeviceSyncArtifactDraft{}, err
	}
	preparationDigest, err := preparation.ReferenceDigest()
	if err != nil {
		return sourceDeviceSyncArtifactDraft{}, err
	}
	payloadDigest := sha256.Sum256(canonicalPayload)
	metadata := sourceDeviceSyncDraftMetadata{
		BlobInventoryArtifactID: inventoryDescriptor.ArtifactID,
		CanonicalPayloadSHA256:  hex.EncodeToString(payloadDigest[:]),
		MigrationID:             payload.MigrationID, PreparationReferenceDigest: preparationDigest,
		PrincipalID: payload.Scope.ScopeID, ServiceStateArtifactID: stateDescriptor.ArtifactID,
		SnapshotID: payload.SnapshotID, Version: sourceDraftCustodyVersion,
	}
	draft := sourceDeviceSyncArtifactDraft{
		directory: custody.sourceDraftDirectory(metadata), metadata: metadata,
		serviceStateDescriptor: stateDescriptor, blobInventoryDescriptor: inventoryDescriptor,
	}
	preparationRecord, err := json.Marshal(preparation)
	if err != nil {
		return sourceDeviceSyncArtifactDraft{}, err
	}
	metadataRecord, err := json.Marshal(metadata)
	if err != nil {
		return sourceDeviceSyncArtifactDraft{}, err
	}
	custody.mu.Lock()
	defer custody.mu.Unlock()
	found, err := verifySourceDraftDirectory(
		ctx, draft, preparationRecord, canonicalPayload, metadataRecord,
	)
	if err != nil {
		return sourceDeviceSyncArtifactDraft{}, err
	}
	if !found {
		return sourceDeviceSyncArtifactDraft{}, errors.New("Device Sync source draft is missing")
	}
	return draft, nil
}

func (custody *FileArtifactCustody) promoteSourceDeviceSyncDraft(
	ctx context.Context,
	draft sourceDeviceSyncArtifactDraft,
	validated serviceauthority.ValidatedMigrationTransfer,
	preparation serviceauthority.MigrationPreparation,
	snapshot serviceauthority.MigrationSnapshot,
) (PreparedDeviceSyncTransfer, error) {
	if draft.metadata.PrincipalID != validated.Snapshot.Scope.ScopeID ||
		draft.metadata.MigrationID != validated.Snapshot.MigrationID ||
		draft.metadata.SnapshotID != validated.Snapshot.SnapshotID {
		return PreparedDeviceSyncTransfer{}, serviceauthority.ErrInvalid
	}
	state, err := openProtectedArtifact(
		filepath.Join(draft.directory, serviceStateFileName), draft.serviceStateDescriptor,
	)
	if err != nil {
		return PreparedDeviceSyncTransfer{}, err
	}
	inventory, err := openProtectedArtifact(
		filepath.Join(draft.directory, blobInventoryFileName), draft.blobInventoryDescriptor,
	)
	if err != nil {
		_ = state.Close()
		return PreparedDeviceSyncTransfer{}, err
	}
	transfer, stageErr := custody.stagePreparedDeviceSyncTransfer(
		ctx, validated, preparation, snapshot, state, inventory,
	)
	closeErr := errors.Join(state.Close(), inventory.Close())
	if stageErr != nil || closeErr != nil {
		return PreparedDeviceSyncTransfer{}, errors.Join(stageErr, closeErr)
	}
	if err := custody.removeSourceDraft(draft); err != nil {
		return PreparedDeviceSyncTransfer{}, err
	}
	return transfer, nil
}

func (custody *FileArtifactCustody) sourceDraftDirectory(
	metadata sourceDeviceSyncDraftMetadata,
) string {
	return filepath.Join(
		custody.root, sourceDraftRootName, metadata.PrincipalID.String(),
		metadata.MigrationID.String(), metadata.SnapshotID.String(),
	)
}

func (custody *FileArtifactCustody) removeSourceDraft(draft sourceDeviceSyncArtifactDraft) error {
	if custody == nil || draft.directory == "" || draft.directory != custody.sourceDraftDirectory(draft.metadata) {
		return serviceauthority.ErrInvalid
	}
	custody.mu.Lock()
	defer custody.mu.Unlock()
	info, err := os.Lstat(draft.directory)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("Device Sync source draft directory is unsafe")
	}
	if err := os.RemoveAll(draft.directory); err != nil {
		return err
	}
	return syncCustodyDirectory(filepath.Dir(draft.directory))
}

func verifySourceDraftDirectory(
	ctx context.Context,
	draft sourceDeviceSyncArtifactDraft,
	preparationRecord []byte,
	canonicalPayload []byte,
	metadataRecord []byte,
) (bool, error) {
	info, err := os.Lstat(draft.directory)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return true, errors.New("existing Device Sync source draft directory is unsafe")
	}
	for name, expected := range map[string][]byte{
		preparationFileName:     preparationRecord,
		snapshotPayloadFileName: canonicalPayload,
		metadataFileName:        metadataRecord,
	} {
		actual, err := readProtectedRecord(filepath.Join(draft.directory, name), maximumEvidenceByteCount)
		if err != nil || !bytes.Equal(actual, expected) {
			return true, errors.New("existing Device Sync source draft conflicts with export evidence")
		}
	}
	for name, descriptor := range map[string]serviceauthority.MigrationArtifactDescriptor{
		serviceStateFileName:  draft.serviceStateDescriptor,
		blobInventoryFileName: draft.blobInventoryDescriptor,
	} {
		file, err := openProtectedArtifact(filepath.Join(draft.directory, name), descriptor)
		if err != nil {
			return true, err
		}
		hash := sha256.New()
		_, copyErr := io.Copy(hash, &custodyContextReader{ctx: ctx, reader: file})
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil {
			return true, errors.Join(copyErr, closeErr)
		}
		if hex.EncodeToString(hash.Sum(nil)) != descriptor.TransferDigest {
			return true, errors.New("existing Device Sync source draft artifact is corrupted")
		}
	}
	return true, nil
}

func validateSourceDraftMetadata(metadata sourceDeviceSyncDraftMetadata) error {
	if metadata.Version != sourceDraftCustodyVersion || metadata.PrincipalID == uuid.Nil ||
		metadata.MigrationID == uuid.Nil || metadata.SnapshotID == uuid.Nil ||
		metadata.ServiceStateArtifactID == uuid.Nil || metadata.BlobInventoryArtifactID == uuid.Nil ||
		metadata.ServiceStateArtifactID == metadata.BlobInventoryArtifactID ||
		len(metadata.CanonicalPayloadSHA256) != sha256.Size*2 ||
		len(metadata.PreparationReferenceDigest) != sha256.Size*2 {
		return serviceauthority.ErrInvalid
	}
	for _, digest := range []string{
		metadata.CanonicalPayloadSHA256, metadata.PreparationReferenceDigest,
	} {
		decoded, err := hex.DecodeString(digest)
		if err != nil || hex.EncodeToString(decoded) != digest {
			return serviceauthority.ErrInvalid
		}
	}
	return nil
}
