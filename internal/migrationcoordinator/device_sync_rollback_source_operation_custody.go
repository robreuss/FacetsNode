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
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

const (
	rollbackSourceOperationRootName = "device-sync-rollback-source-operations"
	rollbackSourceOperationFileName = "operation.json"
)

type deviceSyncRollbackSourceOperationRecord struct {
	Acceptance         serviceauthority.MigrationRollbackSourceAcceptance `json:"acceptance"`
	ActivationEvidence serviceauthority.MigrationActivationEvidence       `json:"activationEvidence"`
	Prepared           *serviceauthority.MigrationRollbackSourcePrepared  `json:"prepared,omitempty"`
	Version            int                                                `json:"version"`
}

type deviceSyncRollbackSourceOperation struct {
	completed bool
	encoded   []byte
	path      string
	record    deviceSyncRollbackSourceOperationRecord
	request   DeviceSyncRollbackSourcePreparationRequest
}

func (custody *FileArtifactCustody) stageDeviceSyncRollbackSourceOperation(
	ctx context.Context,
	signer *serviceauthority.DeploymentSigner,
	request DeviceSyncRollbackSourcePreparationRequest,
) (deviceSyncRollbackSourceOperation, error) {
	if custody == nil || ctx == nil || signer == nil || request.Now.IsZero() ||
		request.Now.UnixMilli() < 0 {
		return deviceSyncRollbackSourceOperation{}, serviceauthority.ErrInvalid
	}
	acceptedAt := request.Now.UnixMilli()
	activationManifest, err := request.ActivationEvidence.ActivationManifest.VerifiedPayload()
	if err != nil {
		return deviceSyncRollbackSourceOperation{}, serviceauthority.ErrInvalid
	}
	activation, historicalErr := request.ActivationEvidence.Validate(
		request.Anchor, activationManifest.ValidFromMilliseconds,
	)
	_, liveErr := request.ActivationEvidence.Validate(request.Anchor, acceptedAt)
	if historicalErr != nil || activation.Migration == nil ||
		activation.Scope.Kind != serviceauthority.ScopeDeviceSync ||
		activation.ActiveDeployment.DeploymentID != signer.DeploymentID() ||
		activation.ActiveDeployment.PublicSigningKeyX963 !=
			signer.PublicSigningKeyX963() ||
		activation.ActiveDeployment.SigningKeyFingerprint !=
			signer.SigningKeyFingerprint() ||
		activation.Migration.TargetDeploymentID != signer.DeploymentID() ||
		request.ExportWriteFenceID == uuid.Nil || request.SnapshotID == uuid.Nil ||
		request.ServiceStateArtifactID == uuid.Nil ||
		request.BlobInventoryArtifactID == uuid.Nil ||
		request.ServiceStateArtifactID == request.BlobInventoryArtifactID {
		return deviceSyncRollbackSourceOperation{}, serviceauthority.ErrInvalid
	}
	evidenceDigest, err := request.ActivationEvidence.ReferenceDigest()
	if err != nil {
		return deviceSyncRollbackSourceOperation{}, err
	}
	acceptancePayload := serviceauthority.MigrationRollbackSourceAcceptancePayload{
		AcceptedAtMilliseconds:   acceptedAt,
		ActivationEvidenceDigest: evidenceDigest,
		BlobInventoryArtifactID:  request.BlobInventoryArtifactID,
		ExportWriteFenceID:       request.ExportWriteFenceID,
		LocalDeploymentID:        signer.DeploymentID(),
		MigrationID:              activation.Migration.MigrationID,
		Scope:                    activation.Scope,
		ServiceStateArtifactID:   request.ServiceStateArtifactID,
		SnapshotID:               request.SnapshotID,
		Version:                  serviceauthority.SchemaVersion,
	}
	operationDirectory := custody.rollbackSourceOperationDirectory(acceptancePayload)
	operationPath := filepath.Join(operationDirectory, rollbackSourceOperationFileName)

	custody.mu.Lock()
	defer custody.mu.Unlock()
	snapshotDirectories, err := readPrivateOperationDirectories(
		filepath.Dir(operationDirectory),
	)
	if err != nil {
		return deviceSyncRollbackSourceOperation{}, err
	}
	for _, candidate := range snapshotDirectories {
		if candidate.Name() != acceptancePayload.SnapshotID.String() {
			return deviceSyncRollbackSourceOperation{}, errors.New(
				"Device Sync rollback source migration already has another operation",
			)
		}
	}
	encoded, readErr := readProtectedRecord(operationPath, maximumEvidenceByteCount)
	if readErr == nil {
		operation, decodeErr := decodeDeviceSyncRollbackSourceOperation(encoded)
		if decodeErr != nil || !sameRollbackSourceOperationRequest(
			operation.request, request,
		) || operation.record.Acceptance.Signature.PublicSigningKeyX963 !=
			signer.PublicSigningKeyX963() ||
			operation.record.Acceptance.Signature.SigningKeyFingerprint !=
				signer.SigningKeyFingerprint() ||
			acceptedAt < operation.request.Now.UnixMilli() {
			return deviceSyncRollbackSourceOperation{}, errors.New(
				"stored Device Sync rollback source operation conflicts with request",
			)
		}
		operation.encoded = encoded
		operation.path = operationPath
		return operation, nil
	}
	if !os.IsNotExist(readErr) {
		return deviceSyncRollbackSourceOperation{}, readErr
	}
	if liveErr != nil {
		return deviceSyncRollbackSourceOperation{}, serviceauthority.ErrInvalid
	}

	acceptance, err := signer.SignMigrationRollbackSourceAcceptance(acceptancePayload)
	if err != nil {
		return deviceSyncRollbackSourceOperation{}, err
	}
	record := deviceSyncRollbackSourceOperationRecord{
		Acceptance:         acceptance,
		ActivationEvidence: request.ActivationEvidence,
		Version:            artifactCustodyVersion,
	}
	encoded, err = json.Marshal(record)
	if err != nil || len(encoded) == 0 || len(encoded) > maximumEvidenceByteCount {
		return deviceSyncRollbackSourceOperation{}, serviceauthority.ErrInvalid
	}
	if err := ensurePrivateCustodyDirectory(custody.root, operationDirectory); err != nil {
		return deviceSyncRollbackSourceOperation{}, err
	}
	if err := writeAtomicOperationRecord(operationPath, encoded); err != nil {
		return deviceSyncRollbackSourceOperation{}, err
	}
	return deviceSyncRollbackSourceOperation{
		encoded: encoded, path: operationPath,
		record: record, request: request,
	}, nil
}

func (custody *FileArtifactCustody) completeDeviceSyncRollbackSourceOperation(
	operation deviceSyncRollbackSourceOperation,
	signer *serviceauthority.DeploymentSigner,
	preparation DeviceSyncRollbackSourcePreparationResult,
) error {
	if custody == nil || signer == nil || operation.path == "" {
		return serviceauthority.ErrInvalid
	}
	acceptance, err := operation.record.Acceptance.VerifiedPayload()
	if err != nil || operation.path != filepath.Join(
		custody.rollbackSourceOperationDirectory(acceptance),
		rollbackSourceOperationFileName,
	) {
		return serviceauthority.ErrInvalid
	}
	snapshotPayload, snapshotErr := preparation.Snapshot.VerifiedPayload(nil)
	snapshotDigest, snapshotDigestErr := preparation.Snapshot.ReferenceDigest()
	acceptanceDigest, acceptanceDigestErr := operation.record.Acceptance.ReferenceDigest()
	stateArtifact, inventoryArtifact, descriptorErr :=
		migrationArtifactDescriptors(snapshotPayload)
	if snapshotErr != nil || snapshotDigestErr != nil || acceptanceDigestErr != nil ||
		descriptorErr != nil ||
		signer.DeploymentID() != acceptance.LocalDeploymentID ||
		signer.PublicSigningKeyX963() !=
			operation.record.Acceptance.Signature.PublicSigningKeyX963 ||
		signer.SigningKeyFingerprint() !=
			operation.record.Acceptance.Signature.SigningKeyFingerprint ||
		preparation.ExportRecord.PrincipalID != acceptance.Scope.ScopeID ||
		preparation.ExportRecord.MigrationID != acceptance.MigrationID ||
		preparation.ExportRecord.SnapshotID != acceptance.SnapshotID ||
		preparation.ExportRecord.ExportWriteFenceID != acceptance.ExportWriteFenceID ||
		preparation.ExportRecord.ExportingDeploymentID != acceptance.LocalDeploymentID ||
		snapshotPayload.Scope != acceptance.Scope ||
		snapshotPayload.MigrationID != acceptance.MigrationID ||
		snapshotPayload.SnapshotID != acceptance.SnapshotID ||
		snapshotPayload.ExportWriteFenceID != acceptance.ExportWriteFenceID ||
		snapshotPayload.ExportingDeploymentID != acceptance.LocalDeploymentID ||
		preparation.Snapshot.Signature.PublicSigningKeyX963 !=
			signer.PublicSigningKeyX963() ||
		preparation.Snapshot.Signature.SigningKeyFingerprint !=
			signer.SigningKeyFingerprint() ||
		stateArtifact.ArtifactID != acceptance.ServiceStateArtifactID ||
		inventoryArtifact.ArtifactID != acceptance.BlobInventoryArtifactID ||
		preparation.ExportRecord.StateCommitmentDigest !=
			snapshotPayload.StateCommitmentDigest {
		return serviceauthority.ErrInvalid
	}
	preparedPayload := serviceauthority.MigrationRollbackSourcePreparedPayload{
		AcceptanceReferenceDigest: acceptanceDigest,
		LocalDeploymentID:         signer.DeploymentID(),
		MigrationID:               acceptance.MigrationID,
		Scope:                     acceptance.Scope,
		SnapshotID:                acceptance.SnapshotID,
		SnapshotReferenceDigest:   snapshotDigest,
		StateCommitmentDigest:     snapshotPayload.StateCommitmentDigest,
		Version:                   serviceauthority.SchemaVersion,
	}
	if operation.completed {
		stored, err := operation.record.Prepared.VerifiedPayload()
		if err != nil || stored != preparedPayload {
			return errors.New("completed Device Sync rollback source operation conflicts")
		}
		return nil
	}
	prepared, err := signer.SignMigrationRollbackSourcePrepared(preparedPayload)
	if err != nil {
		return err
	}
	completedRecord := operation.record
	completedRecord.Prepared = &prepared
	completedEncoded, err := json.Marshal(completedRecord)
	if err != nil || len(completedEncoded) > maximumEvidenceByteCount {
		return serviceauthority.ErrInvalid
	}

	custody.mu.Lock()
	defer custody.mu.Unlock()
	actual, err := readProtectedRecord(operation.path, maximumEvidenceByteCount)
	if err != nil {
		return errors.New("Device Sync rollback source operation changed before completion")
	}
	if !bytes.Equal(actual, operation.encoded) {
		concurrent, decodeErr := decodeDeviceSyncRollbackSourceOperation(actual)
		if decodeErr == nil && concurrent.completed {
			stored, preparedErr := concurrent.record.Prepared.VerifiedPayload()
			if preparedErr == nil && stored == preparedPayload {
				return nil
			}
		}
		return errors.New("Device Sync rollback source operation changed before completion")
	}
	return writeAtomicOperationRecord(operation.path, completedEncoded)
}

func writeAtomicOperationRecord(path string, encoded []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".operation-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := io.Copy(temporary, bytes.NewReader(encoded)); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return syncCustodyDirectory(filepath.Dir(path))
}

func (custody *FileArtifactCustody) listDeviceSyncRollbackSourceOperations(
	ctx context.Context,
) ([]deviceSyncRollbackSourceOperation, error) {
	if custody == nil || ctx == nil {
		return nil, serviceauthority.ErrInvalid
	}
	paths, err := rollbackSourceOperationPaths(
		filepath.Join(custody.root, rollbackSourceOperationRootName),
	)
	if err != nil {
		return nil, err
	}
	operations := make([]deviceSyncRollbackSourceOperation, 0, len(paths))
	for _, path := range paths {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		encoded, err := readProtectedRecord(path, maximumEvidenceByteCount)
		if err != nil {
			return nil, err
		}
		operation, err := decodeDeviceSyncRollbackSourceOperation(encoded)
		if err != nil {
			return nil, err
		}
		acceptance, err := operation.record.Acceptance.VerifiedPayload()
		if err != nil || path != filepath.Join(
			custody.rollbackSourceOperationDirectory(acceptance),
			rollbackSourceOperationFileName,
		) {
			return nil, errors.New("Device Sync rollback source operation path conflicts")
		}
		operation.encoded = encoded
		operation.path = path
		operations = append(operations, operation)
	}
	sort.Slice(operations, func(left, right int) bool {
		leftAcceptance, _ := operations[left].record.Acceptance.VerifiedPayload()
		rightAcceptance, _ := operations[right].record.Acceptance.VerifiedPayload()
		if comparison := bytes.Compare(
			leftAcceptance.Scope.ScopeID[:], rightAcceptance.Scope.ScopeID[:],
		); comparison != 0 {
			return comparison < 0
		}
		if comparison := bytes.Compare(
			leftAcceptance.MigrationID[:], rightAcceptance.MigrationID[:],
		); comparison != 0 {
			return comparison < 0
		}
		return bytes.Compare(
			leftAcceptance.SnapshotID[:], rightAcceptance.SnapshotID[:],
		) < 0
	})
	return operations, nil
}

func decodeDeviceSyncRollbackSourceOperation(
	encoded []byte,
) (deviceSyncRollbackSourceOperation, error) {
	var record deviceSyncRollbackSourceOperationRecord
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil || ensureJSONEOF(decoder) != nil {
		return deviceSyncRollbackSourceOperation{}, serviceauthority.ErrInvalid
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(canonical, encoded) ||
		record.Version != artifactCustodyVersion {
		return deviceSyncRollbackSourceOperation{}, serviceauthority.ErrInvalid
	}
	acceptance, err := record.Acceptance.VerifiedPayload()
	current, currentErr :=
		record.ActivationEvidence.Preparation.CurrentManifest.VerifiedPayload()
	if err != nil || currentErr != nil {
		return deviceSyncRollbackSourceOperation{}, serviceauthority.ErrInvalid
	}
	signature := record.ActivationEvidence.Preparation.CurrentManifest.Signature
	anchor := serviceauthority.TrustAnchor{
		PublicSigningKeyX963:  signature.PublicSigningKeyX963,
		Scope:                 current.Scope,
		SignerID:              signature.SignerID,
		SigningKeyFingerprint: signature.SigningKeyFingerprint,
		Version:               serviceauthority.SchemaVersion,
	}
	activation, validationErr := record.ActivationEvidence.Validate(
		anchor, acceptance.AcceptedAtMilliseconds,
	)
	evidenceDigest, digestErr := record.ActivationEvidence.ReferenceDigest()
	if validationErr != nil || digestErr != nil || activation.Migration == nil ||
		acceptance.ActivationEvidenceDigest != evidenceDigest ||
		acceptance.Scope != activation.Scope ||
		acceptance.MigrationID != activation.Migration.MigrationID ||
		acceptance.LocalDeploymentID != activation.ActiveDeployment.DeploymentID ||
		acceptance.LocalDeploymentID != activation.Migration.TargetDeploymentID ||
		record.Acceptance.Signature.PublicSigningKeyX963 !=
			activation.ActiveDeployment.PublicSigningKeyX963 ||
		record.Acceptance.Signature.SigningKeyFingerprint !=
			activation.ActiveDeployment.SigningKeyFingerprint {
		return deviceSyncRollbackSourceOperation{}, serviceauthority.ErrInvalid
	}
	completed := record.Prepared != nil
	if completed {
		prepared, preparedErr := record.Prepared.VerifiedPayload()
		acceptanceDigest, acceptanceDigestErr := record.Acceptance.ReferenceDigest()
		if preparedErr != nil || acceptanceDigestErr != nil ||
			prepared.AcceptanceReferenceDigest != acceptanceDigest ||
			prepared.LocalDeploymentID != acceptance.LocalDeploymentID ||
			prepared.MigrationID != acceptance.MigrationID ||
			prepared.Scope != acceptance.Scope ||
			prepared.SnapshotID != acceptance.SnapshotID ||
			record.Prepared.Signature.PublicSigningKeyX963 !=
				activation.ActiveDeployment.PublicSigningKeyX963 ||
			record.Prepared.Signature.SigningKeyFingerprint !=
				activation.ActiveDeployment.SigningKeyFingerprint {
			return deviceSyncRollbackSourceOperation{}, serviceauthority.ErrInvalid
		}
	}
	request := DeviceSyncRollbackSourcePreparationRequest{
		ActivationEvidence:      record.ActivationEvidence,
		Anchor:                  anchor,
		ExportWriteFenceID:      acceptance.ExportWriteFenceID,
		SnapshotID:              acceptance.SnapshotID,
		ServiceStateArtifactID:  acceptance.ServiceStateArtifactID,
		BlobInventoryArtifactID: acceptance.BlobInventoryArtifactID,
		Now:                     time.UnixMilli(acceptance.AcceptedAtMilliseconds),
	}
	return deviceSyncRollbackSourceOperation{
		completed: completed, record: record, request: request,
	}, nil
}

func sameRollbackSourceOperationRequest(
	left DeviceSyncRollbackSourcePreparationRequest,
	right DeviceSyncRollbackSourcePreparationRequest,
) bool {
	left.Now = right.Now
	return left.Anchor == right.Anchor &&
		left.ExportWriteFenceID == right.ExportWriteFenceID &&
		left.SnapshotID == right.SnapshotID &&
		left.ServiceStateArtifactID == right.ServiceStateArtifactID &&
		left.BlobInventoryArtifactID == right.BlobInventoryArtifactID &&
		canonicalEqualMigrationActivationEvidence(
			left.ActivationEvidence, right.ActivationEvidence,
		)
}

func canonicalEqualMigrationActivationEvidence(
	left serviceauthority.MigrationActivationEvidence,
	right serviceauthority.MigrationActivationEvidence,
) bool {
	leftRecord, leftErr := json.Marshal(left)
	rightRecord, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftRecord, rightRecord)
}

func (custody *FileArtifactCustody) rollbackSourceOperationDirectory(
	acceptance serviceauthority.MigrationRollbackSourceAcceptancePayload,
) string {
	return filepath.Join(
		custody.root, rollbackSourceOperationRootName,
		acceptance.Scope.ScopeID.String(), acceptance.MigrationID.String(),
		acceptance.SnapshotID.String(),
	)
}

func rollbackSourceOperationPaths(base string) ([]string, error) {
	principalDirectories, err := readPrivateOperationDirectories(base)
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0)
	for _, principal := range principalDirectories {
		principalID, err := uuid.Parse(principal.Name())
		if err != nil || principalID.String() != principal.Name() {
			return nil, errors.New("Device Sync rollback source custody has unsafe principal path")
		}
		principalPath := filepath.Join(base, principal.Name())
		migrationDirectories, err := readPrivateOperationDirectories(principalPath)
		if err != nil {
			return nil, err
		}
		for _, migration := range migrationDirectories {
			migrationID, err := uuid.Parse(migration.Name())
			if err != nil || migrationID.String() != migration.Name() {
				return nil, errors.New("Device Sync rollback source custody has unsafe migration path")
			}
			migrationPath := filepath.Join(principalPath, migration.Name())
			snapshotDirectories, err := readPrivateOperationDirectories(migrationPath)
			if err != nil {
				return nil, err
			}
			for _, snapshot := range snapshotDirectories {
				snapshotID, err := uuid.Parse(snapshot.Name())
				if err != nil || snapshotID.String() != snapshot.Name() {
					return nil, errors.New("Device Sync rollback source custody has unsafe snapshot path")
				}
				operationPath := filepath.Join(
					migrationPath, snapshot.Name(), rollbackSourceOperationFileName,
				)
				if _, err := os.Lstat(operationPath); os.IsNotExist(err) {
					return nil, errors.New("Device Sync rollback source custody lacks an operation record")
				} else if err != nil {
					return nil, err
				}
				paths = append(paths, operationPath)
			}
		}
	}
	return paths, nil
}

func readPrivateOperationDirectories(path string) ([]os.DirEntry, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("Device Sync rollback source custody directory is unsafe: %s", path)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		entryInfo, err := entry.Info()
		if err != nil || !entryInfo.IsDir() || entryInfo.Mode()&os.ModeSymlink != 0 ||
			entryInfo.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("Device Sync rollback source custody entry is unsafe: %s", entry.Name())
		}
	}
	return entries, nil
}
