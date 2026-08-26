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

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

const (
	deviceSyncRetirementDirectoryName = "device-sync-retirements"
	retirementFileName                = "retirement.json"
	completedRetirementFileName       = "retirement-completed.json"
)

type deviceSyncRetirementJournalRecord struct {
	Acceptance serviceauthority.MigrationRetirementAcceptance `json:"acceptance"`
	Evidence   serviceauthority.MigrationRetirementEvidence   `json:"evidence"`
	Version    int                                            `json:"version"`
}

type deviceSyncRetirementJournal struct {
	anchor    serviceauthority.TrustAnchor
	completed bool
	directory string
	record    deviceSyncRetirementJournalRecord
}

func (custody *FileArtifactCustody) stageDeviceSyncRetirementJournal(
	ctx context.Context,
	signer *serviceauthority.DeploymentSigner,
	evidence serviceauthority.MigrationRetirementEvidence,
	anchor serviceauthority.TrustAnchor,
	acceptedAtMilliseconds int64,
) (deviceSyncRetirementJournal, error) {
	if custody == nil || ctx == nil || signer == nil || acceptedAtMilliseconds < 0 {
		return deviceSyncRetirementJournal{}, serviceauthority.ErrInvalid
	}
	retirement, err := evidence.RetirementManifest.VerifiedPayload()
	if err != nil || retirement.Migration == nil ||
		(signer.DeploymentID() != retirement.Migration.SourceDeploymentID &&
			signer.DeploymentID() != retirement.Migration.TargetDeploymentID) {
		return deviceSyncRetirementJournal{}, serviceauthority.ErrInvalid
	}
	if _, err := evidence.ValidateHistoricalCatchUp(
		anchor, retirement.ValidFromMilliseconds,
	); err != nil {
		return deviceSyncRetirementJournal{}, serviceauthority.ErrInvalid
	}
	directory := custody.retirementDirectory(
		retirement.Scope.ScopeID, retirement.Migration.MigrationID,
	)
	evidenceDigest, err := evidence.ReferenceDigest()
	if err != nil {
		return deviceSyncRetirementJournal{}, err
	}
	custody.mu.Lock()
	defer custody.mu.Unlock()
	if err := ensurePrivateSyncedOperationDirectory(custody.root, directory); err != nil {
		return deviceSyncRetirementJournal{}, err
	}
	for _, candidate := range []struct {
		name      string
		completed bool
	}{
		{name: retirementFileName},
		{name: completedRetirementFileName, completed: true},
	} {
		path := filepath.Join(directory, candidate.name)
		existingBytes, readErr := readProtectedRecord(path, maximumEvidenceByteCount)
		if readErr == nil {
			existing, existingAnchor, validationErr :=
				decodeDeviceSyncRetirementJournalRecord(existingBytes)
			acceptance, acceptanceErr := existing.Acceptance.VerifiedPayload()
			if validationErr != nil || acceptanceErr != nil ||
				acceptance.LocalDeploymentID != signer.DeploymentID() ||
				acceptance.RetirementEvidenceDigest != evidenceDigest ||
				acceptedAtMilliseconds < acceptance.AcceptedAtMilliseconds ||
				existing.Acceptance.Signature.PublicSigningKeyX963 !=
					signer.PublicSigningKeyX963() ||
				existing.Acceptance.Signature.SigningKeyFingerprint !=
					signer.SigningKeyFingerprint() || existingAnchor != anchor {
				return deviceSyncRetirementJournal{}, errors.New(
					"stored Device Sync retirement journal conflicts with requested evidence",
				)
			}
			return deviceSyncRetirementJournal{
				anchor: existingAnchor, completed: candidate.completed,
				directory: directory, record: existing,
			}, nil
		}
		if !os.IsNotExist(readErr) {
			return deviceSyncRetirementJournal{}, readErr
		}
	}
	record, err := buildDeviceSyncRetirementJournalRecord(
		signer, evidence, anchor, acceptedAtMilliseconds,
	)
	if err != nil {
		return deviceSyncRetirementJournal{}, err
	}
	encoded, err := json.Marshal(record)
	if err != nil || len(encoded) == 0 || len(encoded) > maximumEvidenceByteCount {
		return deviceSyncRetirementJournal{}, serviceauthority.ErrInvalid
	}
	temporary, err := os.CreateTemp(directory, ".retirement-*")
	if err != nil {
		return deviceSyncRetirementJournal{}, err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return deviceSyncRetirementJournal{}, err
	}
	if _, err := io.Copy(temporary, bytes.NewReader(encoded)); err != nil {
		_ = temporary.Close()
		return deviceSyncRetirementJournal{}, err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return deviceSyncRetirementJournal{}, err
	}
	if err := temporary.Close(); err != nil {
		return deviceSyncRetirementJournal{}, err
	}
	if err := os.Rename(
		temporaryPath, filepath.Join(directory, retirementFileName),
	); err != nil {
		return deviceSyncRetirementJournal{}, err
	}
	if err := syncCustodyDirectory(directory); err != nil {
		return deviceSyncRetirementJournal{}, err
	}
	return deviceSyncRetirementJournal{
		anchor: anchor, directory: directory, record: record,
	}, nil
}

func (custody *FileArtifactCustody) completeDeviceSyncRetirementJournal(
	journal deviceSyncRetirementJournal,
) error {
	if custody == nil || journal.directory == "" ||
		len(journal.record.Acceptance.Payload) == 0 {
		return serviceauthority.ErrInvalid
	}
	if journal.completed {
		return nil
	}
	custody.mu.Lock()
	defer custody.mu.Unlock()
	pending := filepath.Join(journal.directory, retirementFileName)
	completed := filepath.Join(journal.directory, completedRetirementFileName)
	if encoded, err := readProtectedRecord(completed, maximumEvidenceByteCount); err == nil {
		record, _, validationErr := decodeDeviceSyncRetirementJournalRecord(encoded)
		if validationErr != nil || !sameMigrationRetirementAcceptance(
			record.Acceptance, journal.record.Acceptance,
		) {
			return errors.New("completed Device Sync retirement journal conflicts with transition")
		}
		if _, err := os.Lstat(pending); err == nil {
			if err := os.Remove(pending); err != nil {
				return err
			}
		} else if !os.IsNotExist(err) {
			return err
		}
		return syncCustodyDirectory(journal.directory)
	} else if !os.IsNotExist(err) {
		return err
	}
	encoded, err := readProtectedRecord(pending, maximumEvidenceByteCount)
	if err != nil {
		return err
	}
	record, _, err := decodeDeviceSyncRetirementJournalRecord(encoded)
	if err != nil || !sameMigrationRetirementAcceptance(
		record.Acceptance, journal.record.Acceptance,
	) {
		return errors.New("pending Device Sync retirement journal conflicts with transition")
	}
	if err := os.Rename(pending, completed); err != nil {
		return err
	}
	return syncCustodyDirectory(journal.directory)
}

func (custody *FileArtifactCustody) listDeviceSyncRetirementJournals(
	ctx context.Context,
) ([]deviceSyncRetirementJournal, error) {
	if custody == nil || ctx == nil {
		return nil, serviceauthority.ErrInvalid
	}
	custody.mu.Lock()
	defer custody.mu.Unlock()
	base := filepath.Join(custody.root, deviceSyncRetirementDirectoryName)
	if _, err := os.Lstat(base); os.IsNotExist(err) {
		return []deviceSyncRetirementJournal{}, nil
	} else if err != nil || rejectUnsafeCustodyDirectory(base) != nil {
		return nil, errors.New("Device Sync retirement custody root is unsafe")
	}
	paths, err := terminalJournalPaths(
		base, retirementFileName, completedRetirementFileName, "retirement",
	)
	if err != nil {
		return nil, err
	}
	journals := make([]deviceSyncRetirementJournal, 0, len(paths))
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		encoded, err := readProtectedRecord(path, maximumEvidenceByteCount)
		if err != nil {
			return nil, err
		}
		record, anchor, err := decodeDeviceSyncRetirementJournalRecord(encoded)
		if err != nil {
			return nil, err
		}
		acceptance, err := record.Acceptance.VerifiedPayload()
		if err != nil {
			return nil, err
		}
		expected := custody.retirementDirectory(
			acceptance.Scope.ScopeID, acceptance.MigrationID,
		)
		if filepath.Dir(path) != expected || rejectUnsafeCustodyDirectory(expected) != nil {
			return nil, errors.New("Device Sync retirement journal path conflicts with evidence")
		}
		journals = append(journals, deviceSyncRetirementJournal{
			anchor: anchor, directory: expected, record: record,
			completed: filepath.Base(path) == completedRetirementFileName,
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
		return bytes.Compare(leftPayload.MigrationID[:], rightPayload.MigrationID[:]) < 0
	})
	return journals, nil
}

func buildDeviceSyncRetirementJournalRecord(
	signer *serviceauthority.DeploymentSigner,
	evidence serviceauthority.MigrationRetirementEvidence,
	anchor serviceauthority.TrustAnchor,
	acceptedAtMilliseconds int64,
) (deviceSyncRetirementJournalRecord, error) {
	if signer == nil {
		return deviceSyncRetirementJournalRecord{}, serviceauthority.ErrInvalid
	}
	retirement, err := evidence.ValidateHistoricalCatchUp(anchor, acceptedAtMilliseconds)
	if err != nil || retirement.Migration == nil ||
		retirement.Scope.Kind != serviceauthority.ScopeDeviceSync ||
		(signer.DeploymentID() != retirement.Migration.SourceDeploymentID &&
			signer.DeploymentID() != retirement.Migration.TargetDeploymentID) {
		return deviceSyncRetirementJournalRecord{}, serviceauthority.ErrInvalid
	}
	digest, err := evidence.ReferenceDigest()
	if err != nil {
		return deviceSyncRetirementJournalRecord{}, err
	}
	acceptance, err := signer.SignMigrationRetirementAcceptance(
		serviceauthority.MigrationRetirementAcceptancePayload{
			AcceptedAtMilliseconds: acceptedAtMilliseconds,
			LocalDeploymentID:      signer.DeploymentID(), MigrationID: retirement.Migration.MigrationID,
			RetirementEvidenceDigest: digest, Scope: retirement.Scope,
			Version: serviceauthority.SchemaVersion,
		},
	)
	if err != nil {
		return deviceSyncRetirementJournalRecord{}, err
	}
	return deviceSyncRetirementJournalRecord{
		Acceptance: acceptance, Evidence: evidence, Version: artifactCustodyVersion,
	}, nil
}

func decodeDeviceSyncRetirementJournalRecord(
	encoded []byte,
) (deviceSyncRetirementJournalRecord, serviceauthority.TrustAnchor, error) {
	var record deviceSyncRetirementJournalRecord
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil || ensureJSONEOF(decoder) != nil {
		return record, serviceauthority.TrustAnchor{}, serviceauthority.ErrInvalid
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(canonical, encoded) || record.Version != artifactCustodyVersion {
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
	if err != nil {
		return record, serviceauthority.TrustAnchor{}, serviceauthority.ErrInvalid
	}
	retirement, err := record.Evidence.ValidateHistoricalCatchUp(
		anchor, acceptance.AcceptedAtMilliseconds,
	)
	digest, digestErr := record.Evidence.ReferenceDigest()
	if err != nil || digestErr != nil || retirement.Migration == nil ||
		acceptance.Scope != retirement.Scope ||
		acceptance.MigrationID != retirement.Migration.MigrationID ||
		acceptance.RetirementEvidenceDigest != digest ||
		(acceptance.LocalDeploymentID != retirement.Migration.SourceDeploymentID &&
			acceptance.LocalDeploymentID != retirement.Migration.TargetDeploymentID) {
		return record, serviceauthority.TrustAnchor{}, serviceauthority.ErrInvalid
	}
	return record, anchor, nil
}

func sameMigrationRetirementAcceptance(
	left serviceauthority.MigrationRetirementAcceptance,
	right serviceauthority.MigrationRetirementAcceptance,
) bool {
	return bytes.Equal(left.Payload, right.Payload) && left.Signature == right.Signature
}

func terminalJournalPaths(
	base string,
	pendingName string,
	completedName string,
	label string,
) ([]string, error) {
	principals, err := os.ReadDir(base)
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0)
	for _, principal := range principals {
		principalPath := filepath.Join(base, principal.Name())
		if _, err := uuid.Parse(principal.Name()); err != nil ||
			principal.Type()&os.ModeSymlink != 0 || !principal.IsDir() ||
			rejectUnsafeCustodyDirectory(principalPath) != nil {
			return nil, fmt.Errorf("Device Sync %s custody contains an unsafe principal path", label)
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
				return nil, fmt.Errorf("Device Sync %s custody contains an unsafe migration path", label)
			}
			pending := filepath.Join(migrationPath, pendingName)
			completed := filepath.Join(migrationPath, completedName)
			if _, err := os.Lstat(pending); err == nil {
				paths = append(paths, pending)
				continue
			} else if !os.IsNotExist(err) {
				return nil, err
			}
			if _, err := os.Lstat(completed); err == nil {
				paths = append(paths, completed)
			} else if !os.IsNotExist(err) {
				return nil, err
			}
		}
	}
	return paths, nil
}

func (custody *FileArtifactCustody) retirementDirectory(
	principalID uuid.UUID,
	migrationID uuid.UUID,
) string {
	return filepath.Join(
		custody.root, deviceSyncRetirementDirectoryName,
		principalID.String(), migrationID.String(),
	)
}

func retirementJournalPath(
	custody *FileArtifactCustody,
	scope serviceauthority.Scope,
	migrationID uuid.UUID,
	name string,
) (string, error) {
	if custody == nil || scope.Kind != serviceauthority.ScopeDeviceSync ||
		scope.Validate() != nil || migrationID == uuid.Nil ||
		(name != retirementFileName && name != completedRetirementFileName) {
		return "", fmt.Errorf("invalid Device Sync retirement journal path")
	}
	return filepath.Join(custody.retirementDirectory(scope.ScopeID, migrationID), name), nil
}
