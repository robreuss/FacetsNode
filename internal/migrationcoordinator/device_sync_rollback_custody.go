package migrationcoordinator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

const (
	rollbackJournalFileName          = "rollback.json"
	completedRollbackJournalFileName = "rollback-completed.json"
)

type deviceSyncRollbackJournalRecord struct {
	Acceptance serviceauthority.MigrationRollbackAcceptance `json:"acceptance"`
	Evidence   serviceauthority.MigrationRollbackEvidence   `json:"evidence"`
	Version    int                                          `json:"version"`
}

type deviceSyncRollbackJournal struct {
	anchor    serviceauthority.TrustAnchor
	completed bool
	record    deviceSyncRollbackJournalRecord
	transfer  PreparedDeviceSyncTransfer
}

func (custody *FileArtifactCustody) stageDeviceSyncRollbackJournal(
	ctx context.Context,
	signer *serviceauthority.DeploymentSigner,
	evidence serviceauthority.MigrationRollbackEvidence,
	anchor serviceauthority.TrustAnchor,
	acceptedAtMilliseconds int64,
) (deviceSyncRollbackJournal, error) {
	if custody == nil || ctx == nil || signer == nil || acceptedAtMilliseconds < 0 {
		return deviceSyncRollbackJournal{}, serviceauthority.ErrInvalid
	}
	rollbackManifest, err := evidence.RollbackManifest.VerifiedPayload()
	if err != nil {
		return deviceSyncRollbackJournal{}, serviceauthority.ErrInvalid
	}
	rolledBack, err := evidence.ValidateHistoricalCatchUp(
		anchor, rollbackManifest.ValidFromMilliseconds,
	)
	if err != nil || rolledBack.Migration == nil ||
		rolledBack.Scope.Kind != serviceauthority.ScopeDeviceSync {
		return deviceSyncRollbackJournal{}, serviceauthority.ErrInvalid
	}
	localDeploymentID := signer.DeploymentID()
	if localDeploymentID != rolledBack.Migration.SourceDeploymentID &&
		localDeploymentID != rolledBack.Migration.TargetDeploymentID {
		return deviceSyncRollbackJournal{}, serviceauthority.ErrInvalid
	}
	validated, err := evidence.TargetSnapshot.ValidateRollbackTransfer(
		evidence.ActivationEvidence, anchor, rollbackManifest.ValidFromMilliseconds,
	)
	if err != nil {
		return deviceSyncRollbackJournal{}, err
	}
	transfer, found, err := custody.openPreparedDeviceSyncRollbackTransfer(
		ctx, validated, evidence.ActivationEvidence, evidence.TargetSnapshot,
	)
	if err != nil {
		return deviceSyncRollbackJournal{}, err
	}
	if !found {
		return deviceSyncRollbackJournal{}, errors.New(
			"Device Sync rollback lacks exact local reverse-transfer custody",
		)
	}
	digest, err := evidence.ReferenceDigest()
	if err != nil {
		return deviceSyncRollbackJournal{}, err
	}
	custody.mu.Lock()
	defer custody.mu.Unlock()
	for _, candidate := range []struct {
		name      string
		completed bool
	}{
		{name: rollbackJournalFileName},
		{name: completedRollbackJournalFileName, completed: true},
	} {
		path := filepath.Join(transfer.directory, candidate.name)
		existing, readErr := readProtectedRecord(path, maximumEvidenceByteCount)
		if readErr == nil {
			decoded, decodedAnchor, decodeErr := decodeDeviceSyncRollbackJournalRecord(
				existing,
			)
			existingAcceptance, acceptanceErr := decoded.Acceptance.VerifiedPayload()
			if decodeErr != nil || acceptanceErr != nil ||
				existingAcceptance.LocalDeploymentID != localDeploymentID ||
				existingAcceptance.RollbackEvidenceDigest != digest ||
				acceptedAtMilliseconds < existingAcceptance.AcceptedAtMilliseconds ||
				decoded.Acceptance.Signature.PublicSigningKeyX963 !=
					signer.PublicSigningKeyX963() ||
				decoded.Acceptance.Signature.SigningKeyFingerprint !=
					signer.SigningKeyFingerprint() {
				return deviceSyncRollbackJournal{}, errors.New(
					"stored Device Sync rollback journal conflicts with evidence",
				)
			}
			return deviceSyncRollbackJournal{
				anchor: decodedAnchor, completed: candidate.completed,
				record: decoded, transfer: transfer,
			}, nil
		}
		if !os.IsNotExist(readErr) {
			return deviceSyncRollbackJournal{}, readErr
		}
	}
	if _, err := evidence.ValidateHistoricalCatchUp(
		anchor, acceptedAtMilliseconds,
	); err != nil {
		return deviceSyncRollbackJournal{}, serviceauthority.ErrInvalid
	}
	acceptance, err := signer.SignMigrationRollbackAcceptance(
		serviceauthority.MigrationRollbackAcceptancePayload{
			AcceptedAtMilliseconds: acceptedAtMilliseconds,
			LocalDeploymentID:      localDeploymentID,
			MigrationID:            rolledBack.Migration.MigrationID,
			RollbackEvidenceDigest: digest,
			Scope:                  rolledBack.Scope,
			Version:                serviceauthority.SchemaVersion,
		},
	)
	if err != nil {
		return deviceSyncRollbackJournal{}, err
	}
	record := deviceSyncRollbackJournalRecord{
		Acceptance: acceptance, Evidence: evidence, Version: artifactCustodyVersion,
	}
	encoded, err := json.Marshal(record)
	if err != nil || len(encoded) == 0 || len(encoded) > maximumEvidenceByteCount {
		return deviceSyncRollbackJournal{}, serviceauthority.ErrInvalid
	}
	temporary, err := os.CreateTemp(transfer.directory, ".rollback-*")
	if err != nil {
		return deviceSyncRollbackJournal{}, err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return deviceSyncRollbackJournal{}, err
	}
	if _, err := io.Copy(temporary, bytes.NewReader(encoded)); err != nil {
		_ = temporary.Close()
		return deviceSyncRollbackJournal{}, err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return deviceSyncRollbackJournal{}, err
	}
	if err := temporary.Close(); err != nil {
		return deviceSyncRollbackJournal{}, err
	}
	if err := os.Rename(
		temporaryPath, filepath.Join(transfer.directory, rollbackJournalFileName),
	); err != nil {
		return deviceSyncRollbackJournal{}, err
	}
	if err := syncCustodyDirectory(transfer.directory); err != nil {
		return deviceSyncRollbackJournal{}, err
	}
	return deviceSyncRollbackJournal{
		anchor: anchor, record: record, transfer: transfer,
	}, nil
}

func (custody *FileArtifactCustody) completeDeviceSyncRollbackJournal(
	journal deviceSyncRollbackJournal,
) error {
	if custody == nil || journal.transfer.directory == "" {
		return serviceauthority.ErrInvalid
	}
	if journal.completed {
		return nil
	}
	custody.mu.Lock()
	defer custody.mu.Unlock()
	pending := filepath.Join(journal.transfer.directory, rollbackJournalFileName)
	completed := filepath.Join(
		journal.transfer.directory, completedRollbackJournalFileName,
	)
	if existing, err := readProtectedRecord(completed, maximumEvidenceByteCount); err == nil {
		decoded, _, decodeErr := decodeDeviceSyncRollbackJournalRecord(existing)
		if decodeErr != nil || !sameMigrationRollbackAcceptance(
			decoded.Acceptance, journal.record.Acceptance,
		) {
			return errors.New("completed Device Sync rollback journal conflicts")
		}
		if err := os.Remove(pending); err != nil && !os.IsNotExist(err) {
			return err
		}
		return syncCustodyDirectory(journal.transfer.directory)
	} else if !os.IsNotExist(err) {
		return err
	}
	encoded, err := readProtectedRecord(pending, maximumEvidenceByteCount)
	if err != nil {
		return err
	}
	decoded, _, err := decodeDeviceSyncRollbackJournalRecord(encoded)
	if err != nil || !sameMigrationRollbackAcceptance(
		decoded.Acceptance, journal.record.Acceptance,
	) {
		return errors.New("pending Device Sync rollback journal conflicts")
	}
	if err := os.Rename(pending, completed); err != nil {
		return err
	}
	return syncCustodyDirectory(journal.transfer.directory)
}

func (custody *FileArtifactCustody) listDeviceSyncRollbackJournals(
	ctx context.Context,
) ([]deviceSyncRollbackJournal, error) {
	if custody == nil || ctx == nil {
		return nil, serviceauthority.ErrInvalid
	}
	custody.mu.Lock()
	defer custody.mu.Unlock()
	base := filepath.Join(custody.root, "device-sync-rollback")
	if _, err := os.Lstat(base); os.IsNotExist(err) {
		return []deviceSyncRollbackJournal{}, nil
	} else if err != nil || rejectUnsafeCustodyDirectory(base) != nil {
		return nil, errors.New("Device Sync rollback custody root is unsafe")
	}
	paths, err := rollbackJournalPaths(base)
	if err != nil {
		return nil, err
	}
	journals := make([]deviceSyncRollbackJournal, 0, len(paths))
	for _, path := range paths {
		encoded, err := readProtectedRecord(path.path, maximumEvidenceByteCount)
		if err != nil {
			return nil, err
		}
		record, anchor, err := decodeDeviceSyncRollbackJournalRecord(encoded)
		if err != nil {
			return nil, err
		}
		acceptance, err := record.Acceptance.VerifiedPayload()
		if err != nil {
			return nil, err
		}
		validated, err := record.Evidence.TargetSnapshot.ValidateRollbackTransfer(
			record.Evidence.ActivationEvidence, anchor,
			acceptance.AcceptedAtMilliseconds,
		)
		if err != nil {
			return nil, err
		}
		transfer, activationRecord, snapshotRecord, metadataRecord, err :=
			custody.expectedPreparedDeviceSyncRollbackTransfer(
				validated, record.Evidence.ActivationEvidence,
				record.Evidence.TargetSnapshot,
			)
		if err != nil || filepath.Dir(path.path) != transfer.directory {
			return nil, errors.New("Device Sync rollback journal path conflicts")
		}
		if err := verifyExistingDeviceSyncRollbackTransfer(
			ctx, transfer, activationRecord, snapshotRecord, metadataRecord,
		); err != nil {
			return nil, err
		}
		journals = append(journals, deviceSyncRollbackJournal{
			anchor: anchor, completed: path.completed, record: record, transfer: transfer,
		})
	}
	sort.Slice(journals, func(left, right int) bool {
		leftPayload, _ := journals[left].record.Acceptance.VerifiedPayload()
		rightPayload, _ := journals[right].record.Acceptance.VerifiedPayload()
		if leftPayload.Scope.ScopeID != rightPayload.Scope.ScopeID {
			return bytes.Compare(
				leftPayload.Scope.ScopeID[:], rightPayload.Scope.ScopeID[:],
			) < 0
		}
		return bytes.Compare(
			leftPayload.MigrationID[:], rightPayload.MigrationID[:],
		) < 0
	})
	return journals, nil
}

func decodeDeviceSyncRollbackJournalRecord(
	encoded []byte,
) (deviceSyncRollbackJournalRecord, serviceauthority.TrustAnchor, error) {
	var record deviceSyncRollbackJournalRecord
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil || ensureJSONEOF(decoder) != nil {
		return record, serviceauthority.TrustAnchor{}, serviceauthority.ErrInvalid
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(canonical, encoded) ||
		record.Version != artifactCustodyVersion {
		return record, serviceauthority.TrustAnchor{}, serviceauthority.ErrInvalid
	}
	current, err := record.Evidence.ActivationEvidence.Preparation.CurrentManifest.VerifiedPayload()
	if err != nil {
		return record, serviceauthority.TrustAnchor{}, serviceauthority.ErrInvalid
	}
	signature := record.Evidence.ActivationEvidence.Preparation.CurrentManifest.Signature
	anchor := serviceauthority.TrustAnchor{
		PublicSigningKeyX963: signature.PublicSigningKeyX963,
		Scope:                current.Scope, SignerID: signature.SignerID,
		SigningKeyFingerprint: signature.SigningKeyFingerprint,
		Version:               serviceauthority.SchemaVersion,
	}
	acceptance, err := record.Acceptance.VerifiedPayload()
	rolledBack, validationErr := record.Evidence.ValidateHistoricalCatchUp(
		anchor, acceptance.AcceptedAtMilliseconds,
	)
	digest, digestErr := record.Evidence.ReferenceDigest()
	if err != nil || validationErr != nil || digestErr != nil ||
		rolledBack.Migration == nil || acceptance.Scope != rolledBack.Scope ||
		acceptance.MigrationID != rolledBack.Migration.MigrationID ||
		acceptance.RollbackEvidenceDigest != digest ||
		(acceptance.LocalDeploymentID != rolledBack.Migration.SourceDeploymentID &&
			acceptance.LocalDeploymentID != rolledBack.Migration.TargetDeploymentID) {
		return record, serviceauthority.TrustAnchor{}, serviceauthority.ErrInvalid
	}
	return record, anchor, nil
}

func sameMigrationRollbackAcceptance(
	left serviceauthority.MigrationRollbackAcceptance,
	right serviceauthority.MigrationRollbackAcceptance,
) bool {
	return bytes.Equal(left.Payload, right.Payload) && left.Signature == right.Signature
}

type rollbackJournalPath struct {
	path      string
	completed bool
}

func rollbackJournalPaths(base string) ([]rollbackJournalPath, error) {
	principals, err := os.ReadDir(base)
	if err != nil {
		return nil, err
	}
	paths := make([]rollbackJournalPath, 0)
	for _, principal := range principals {
		principalPath := filepath.Join(base, principal.Name())
		if _, err := uuid.Parse(principal.Name()); err != nil ||
			principal.Type()&os.ModeSymlink != 0 || !principal.IsDir() ||
			rejectUnsafeCustodyDirectory(principalPath) != nil {
			return nil, errors.New("Device Sync rollback custody has unsafe principal path")
		}
		migrations, err := os.ReadDir(principalPath)
		if err != nil {
			return nil, err
		}
		for _, migration := range migrations {
			migrationPath := filepath.Join(principalPath, migration.Name())
			if _, err := uuid.Parse(migration.Name()); err != nil ||
				migration.Type()&os.ModeSymlink != 0 || !migration.IsDir() ||
				rejectUnsafeCustodyDirectory(migrationPath) != nil {
				return nil, errors.New("Device Sync rollback custody has unsafe migration path")
			}
			snapshots, err := os.ReadDir(migrationPath)
			if err != nil {
				return nil, err
			}
			for _, snapshot := range snapshots {
				snapshotPath := filepath.Join(migrationPath, snapshot.Name())
				if _, err := uuid.Parse(snapshot.Name()); err != nil ||
					snapshot.Type()&os.ModeSymlink != 0 || !snapshot.IsDir() ||
					rejectUnsafeCustodyDirectory(snapshotPath) != nil {
					return nil, errors.New("Device Sync rollback custody has unsafe snapshot path")
				}
				foundJournal := false
				for _, candidate := range []rollbackJournalPath{
					{path: filepath.Join(snapshotPath, rollbackJournalFileName)},
					{path: filepath.Join(snapshotPath, completedRollbackJournalFileName), completed: true},
				} {
					if _, err := os.Lstat(candidate.path); err == nil {
						if foundJournal {
							return nil, errors.New(
								"Device Sync rollback custody has conflicting journal states",
							)
						}
						foundJournal = true
						paths = append(paths, candidate)
					} else if !os.IsNotExist(err) {
						return nil, err
					}
				}
			}
		}
	}
	return paths, nil
}
