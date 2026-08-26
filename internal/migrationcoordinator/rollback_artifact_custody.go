package migrationcoordinator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

const rollbackActivationEvidenceFileName = "rollback-activation-evidence.json"

// stagePreparedDeviceSyncRollbackTransfer durably binds the reverse artifact
// bytes to the exact activation evidence and target-signed snapshot. It uses a
// distinct custody root so a forward transfer can never satisfy rollback
// recovery by path coincidence.
func (custody *FileArtifactCustody) stagePreparedDeviceSyncRollbackTransfer(
	ctx context.Context,
	validated serviceauthority.ValidatedMigrationRollbackTransfer,
	activation serviceauthority.MigrationActivationEvidence,
	snapshot serviceauthority.MigrationSnapshot,
	serviceState io.Reader,
	blobInventory io.Reader,
) (PreparedDeviceSyncTransfer, error) {
	if custody == nil || ctx == nil || serviceState == nil || blobInventory == nil {
		return PreparedDeviceSyncTransfer{}, serviceauthority.ErrInvalid
	}
	transfer, activationRecord, snapshotRecord, metadataRecord, err :=
		custody.expectedPreparedDeviceSyncRollbackTransfer(
			validated, activation, snapshot,
		)
	if err != nil {
		return PreparedDeviceSyncTransfer{}, err
	}

	custody.mu.Lock()
	defer custody.mu.Unlock()
	if info, err := os.Lstat(transfer.directory); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm()&0o077 != 0 {
			return PreparedDeviceSyncTransfer{}, errors.New(
				"existing rollback artifact custody directory is unsafe",
			)
		}
		if err := verifyExistingDeviceSyncRollbackTransfer(
			ctx, transfer, activationRecord, snapshotRecord, metadataRecord,
		); err != nil {
			return PreparedDeviceSyncTransfer{}, err
		}
		return transfer, nil
	} else if !os.IsNotExist(err) {
		return PreparedDeviceSyncTransfer{}, err
	}

	stagingDirectory, err := os.MkdirTemp(
		filepath.Join(custody.root, ".staging"), "device-sync-rollback-*",
	)
	if err != nil {
		return PreparedDeviceSyncTransfer{}, err
	}
	defer func() { _ = os.RemoveAll(stagingDirectory) }()
	if err := os.Chmod(stagingDirectory, 0o700); err != nil {
		return PreparedDeviceSyncTransfer{}, err
	}
	if err := stageExactArtifact(
		ctx, filepath.Join(stagingDirectory, serviceStateFileName),
		serviceState, transfer.serviceStateDescriptor,
	); err != nil {
		return PreparedDeviceSyncTransfer{}, err
	}
	if err := stageExactArtifact(
		ctx, filepath.Join(stagingDirectory, blobInventoryFileName),
		blobInventory, transfer.blobInventoryDescriptor,
	); err != nil {
		return PreparedDeviceSyncTransfer{}, err
	}
	for name, value := range map[string][]byte{
		rollbackActivationEvidenceFileName: activationRecord,
		snapshotFileName:                   snapshotRecord,
		metadataFileName:                   metadataRecord,
	} {
		if len(value) == 0 || len(value) > maximumEvidenceByteCount {
			return PreparedDeviceSyncTransfer{}, serviceauthority.ErrInvalid
		}
		if err := writeSyncedProtectedFile(
			filepath.Join(stagingDirectory, name), value,
		); err != nil {
			return PreparedDeviceSyncTransfer{}, err
		}
	}
	if err := syncCustodyDirectory(stagingDirectory); err != nil {
		return PreparedDeviceSyncTransfer{}, err
	}
	parent := filepath.Dir(transfer.directory)
	if err := ensurePrivateCustodyDirectory(custody.root, parent); err != nil {
		return PreparedDeviceSyncTransfer{}, err
	}
	if err := os.Rename(stagingDirectory, transfer.directory); err != nil {
		return PreparedDeviceSyncTransfer{}, fmt.Errorf(
			"commit rollback artifact custody: %w", err,
		)
	}
	if err := syncCustodyDirectory(parent); err != nil {
		return PreparedDeviceSyncTransfer{}, err
	}
	return transfer, nil
}

func (custody *FileArtifactCustody) openPreparedDeviceSyncRollbackTransfer(
	ctx context.Context,
	validated serviceauthority.ValidatedMigrationRollbackTransfer,
	activation serviceauthority.MigrationActivationEvidence,
	snapshot serviceauthority.MigrationSnapshot,
) (PreparedDeviceSyncTransfer, bool, error) {
	if custody == nil || ctx == nil {
		return PreparedDeviceSyncTransfer{}, false, serviceauthority.ErrInvalid
	}
	transfer, activationRecord, snapshotRecord, metadataRecord, err :=
		custody.expectedPreparedDeviceSyncRollbackTransfer(
			validated, activation, snapshot,
		)
	if err != nil {
		return PreparedDeviceSyncTransfer{}, false, err
	}
	custody.mu.Lock()
	defer custody.mu.Unlock()
	info, err := os.Lstat(transfer.directory)
	if os.IsNotExist(err) {
		return PreparedDeviceSyncTransfer{}, false, nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 {
		return PreparedDeviceSyncTransfer{}, true, errors.New(
			"existing rollback artifact custody directory is unsafe",
		)
	}
	if err := verifyExistingDeviceSyncRollbackTransfer(
		ctx, transfer, activationRecord, snapshotRecord, metadataRecord,
	); err != nil {
		return PreparedDeviceSyncTransfer{}, true, err
	}
	return transfer, true, nil
}

func (custody *FileArtifactCustody) expectedPreparedDeviceSyncRollbackTransfer(
	validated serviceauthority.ValidatedMigrationRollbackTransfer,
	activation serviceauthority.MigrationActivationEvidence,
	snapshot serviceauthority.MigrationSnapshot,
) (PreparedDeviceSyncTransfer, []byte, []byte, []byte, error) {
	if custody == nil || validated.Snapshot.Scope.Kind !=
		serviceauthority.ScopeDeviceSync || validated.Snapshot.Scope.ScopeID == uuid.Nil {
		return PreparedDeviceSyncTransfer{}, nil, nil, nil, serviceauthority.ErrInvalid
	}
	state, inventory, err := migrationArtifactDescriptors(validated.Snapshot)
	if err != nil {
		return PreparedDeviceSyncTransfer{}, nil, nil, nil, err
	}
	inventoryDigest, err := migrationDigest(inventory.TransferDigest)
	if err != nil {
		return PreparedDeviceSyncTransfer{}, nil, nil, nil, err
	}
	snapshotDigest, err := snapshot.ReferenceDigest()
	if err != nil {
		return PreparedDeviceSyncTransfer{}, nil, nil, nil, err
	}
	metadata := fileArtifactCustodyMetadata{
		BlobInventoryArtifactID: inventory.ArtifactID,
		MigrationID:             validated.Migration.MigrationID,
		PrincipalID:             validated.Snapshot.Scope.ScopeID,
		ServiceStateArtifactID:  state.ArtifactID,
		SnapshotID:              validated.Snapshot.SnapshotID,
		SnapshotReferenceDigest: snapshotDigest,
		Version:                 artifactCustodyVersion,
	}
	if err := validateCustodyMetadata(metadata); err != nil {
		return PreparedDeviceSyncTransfer{}, nil, nil, nil, err
	}
	transfer := PreparedDeviceSyncTransfer{
		directory: filepath.Join(
			custody.root, "device-sync-rollback", metadata.PrincipalID.String(),
			metadata.MigrationID.String(), metadata.SnapshotID.String(),
		),
		metadata: metadata, serviceStateDescriptor: state,
		blobInventoryDescriptor: inventory, blobInventoryDigest: inventoryDigest,
	}
	activationRecord, err := json.Marshal(activation)
	if err != nil {
		return PreparedDeviceSyncTransfer{}, nil, nil, nil, err
	}
	snapshotRecord, err := json.Marshal(snapshot)
	if err != nil {
		return PreparedDeviceSyncTransfer{}, nil, nil, nil, err
	}
	metadataRecord, err := json.Marshal(metadata)
	if err != nil {
		return PreparedDeviceSyncTransfer{}, nil, nil, nil, err
	}
	return transfer, activationRecord, snapshotRecord, metadataRecord, nil
}

func verifyExistingDeviceSyncRollbackTransfer(
	ctx context.Context,
	transfer PreparedDeviceSyncTransfer,
	activationRecord []byte,
	snapshotRecord []byte,
	metadataRecord []byte,
) error {
	for name, expected := range map[string][]byte{
		rollbackActivationEvidenceFileName: activationRecord,
		snapshotFileName:                   snapshotRecord,
		metadataFileName:                   metadataRecord,
	} {
		actual, err := readProtectedRecord(
			filepath.Join(transfer.directory, name), maximumEvidenceByteCount,
		)
		if err != nil || !bytes.Equal(actual, expected) {
			return errors.New("existing rollback custody conflicts with signed evidence")
		}
	}
	for name, descriptor := range map[string]serviceauthority.MigrationArtifactDescriptor{
		serviceStateFileName:  transfer.serviceStateDescriptor,
		blobInventoryFileName: transfer.blobInventoryDescriptor,
	} {
		file, err := openProtectedArtifact(filepath.Join(transfer.directory, name), descriptor)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(io.Discard, &custodyContextReader{ctx: ctx, reader: file})
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil {
			return errors.Join(copyErr, closeErr)
		}
	}
	return nil
}
