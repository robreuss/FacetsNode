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
	"strings"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

const (
	deviceSyncCancellationDirectoryName = "device-sync-cancellations"
	cancellationFileName                = "cancellation.json"
	completedCancellationFileName       = "cancellation-completed.json"
)

type deviceSyncCancellationJournalRecord struct {
	Acceptance serviceauthority.MigrationCancellationAcceptance `json:"acceptance"`
	Evidence   serviceauthority.MigrationCancellationEvidence   `json:"evidence"`
	Version    int                                              `json:"version"`
}

type deviceSyncCancellationJournal struct {
	anchor    serviceauthority.TrustAnchor
	completed bool
	directory string
	record    deviceSyncCancellationJournalRecord
}

// stageDeviceSyncCancellationJournal persists live, deployment-signed
// acceptance independently of snapshot custody. Cancellation is valid before
// a source export or target import exists, so its restart journal is keyed only
// by authenticated scope and migration identities.
func (custody *FileArtifactCustody) stageDeviceSyncCancellationJournal(
	ctx context.Context,
	signer *serviceauthority.DeploymentSigner,
	evidence serviceauthority.MigrationCancellationEvidence,
	anchor serviceauthority.TrustAnchor,
	acceptedAtMilliseconds int64,
) (deviceSyncCancellationJournal, error) {
	if custody == nil || ctx == nil || signer == nil ||
		acceptedAtMilliseconds < 0 {
		return deviceSyncCancellationJournal{}, serviceauthority.ErrInvalid
	}
	cancellation, err := evidence.CancellationManifest.VerifiedPayload()
	if err != nil || cancellation.Migration == nil ||
		(signer.DeploymentID() != cancellation.Migration.SourceDeploymentID &&
			signer.DeploymentID() != cancellation.Migration.TargetDeploymentID) {
		return deviceSyncCancellationJournal{}, serviceauthority.ErrInvalid
	}
	// Validate at the signed terminal instant before locating an exact retained
	// journal. This permits an idempotent retry after terminal expiry without
	// permitting a new late acceptance.
	if _, err := evidence.Validate(anchor, cancellation.ValidFromMilliseconds); err != nil {
		return deviceSyncCancellationJournal{}, serviceauthority.ErrInvalid
	}
	directory := custody.cancellationDirectory(
		cancellation.Scope.ScopeID,
		cancellation.Migration.MigrationID,
	)
	evidenceDigest, err := evidence.ReferenceDigest()
	if err != nil {
		return deviceSyncCancellationJournal{}, err
	}

	custody.mu.Lock()
	defer custody.mu.Unlock()
	if err := ensurePrivateSyncedOperationDirectory(custody.root, directory); err != nil {
		return deviceSyncCancellationJournal{}, err
	}
	for _, candidate := range []struct {
		name      string
		completed bool
	}{
		{name: cancellationFileName},
		{name: completedCancellationFileName, completed: true},
	} {
		path := filepath.Join(directory, candidate.name)
		existingBytes, readErr := readProtectedRecord(path, maximumEvidenceByteCount)
		if readErr == nil {
			existing, existingAnchor, validationErr :=
				decodeDeviceSyncCancellationJournalRecord(existingBytes)
			acceptance, acceptanceErr := existing.Acceptance.VerifiedPayload()
			if validationErr != nil || acceptanceErr != nil ||
				acceptance.LocalDeploymentID != signer.DeploymentID() ||
				acceptance.CancellationEvidenceDigest != evidenceDigest ||
				acceptedAtMilliseconds < acceptance.AcceptedAtMilliseconds ||
				existing.Acceptance.Signature.PublicSigningKeyX963 !=
					signer.PublicSigningKeyX963() ||
				existing.Acceptance.Signature.SigningKeyFingerprint !=
					signer.SigningKeyFingerprint() ||
				existingAnchor != anchor {
				return deviceSyncCancellationJournal{}, errors.New(
					"stored Device Sync cancellation journal conflicts with requested evidence",
				)
			}
			return deviceSyncCancellationJournal{
				anchor: existingAnchor, completed: candidate.completed,
				directory: directory, record: existing,
			}, nil
		}
		if !os.IsNotExist(readErr) {
			return deviceSyncCancellationJournal{}, readErr
		}
	}
	record, _, err := buildDeviceSyncCancellationJournalRecord(
		signer, evidence, anchor, acceptedAtMilliseconds,
	)
	if err != nil {
		return deviceSyncCancellationJournal{}, err
	}
	encoded, err := json.Marshal(record)
	if err != nil || len(encoded) == 0 || len(encoded) > maximumEvidenceByteCount {
		return deviceSyncCancellationJournal{}, serviceauthority.ErrInvalid
	}
	temporary, err := os.CreateTemp(directory, ".cancellation-*")
	if err != nil {
		return deviceSyncCancellationJournal{}, err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return deviceSyncCancellationJournal{}, err
	}
	if _, err := io.Copy(temporary, bytes.NewReader(encoded)); err != nil {
		_ = temporary.Close()
		return deviceSyncCancellationJournal{}, err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return deviceSyncCancellationJournal{}, err
	}
	if err := temporary.Close(); err != nil {
		return deviceSyncCancellationJournal{}, err
	}
	if err := os.Rename(
		temporaryPath, filepath.Join(directory, cancellationFileName),
	); err != nil {
		return deviceSyncCancellationJournal{}, err
	}
	if err := syncCustodyDirectory(directory); err != nil {
		return deviceSyncCancellationJournal{}, err
	}
	return deviceSyncCancellationJournal{
		anchor: anchor, directory: directory, record: record,
	}, nil
}

func (custody *FileArtifactCustody) completeDeviceSyncCancellationJournal(
	journal deviceSyncCancellationJournal,
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
	pending := filepath.Join(journal.directory, cancellationFileName)
	completed := filepath.Join(journal.directory, completedCancellationFileName)
	if encoded, err := readProtectedRecord(completed, maximumEvidenceByteCount); err == nil {
		record, _, validationErr := decodeDeviceSyncCancellationJournalRecord(encoded)
		if validationErr != nil || !sameMigrationCancellationAcceptance(
			record.Acceptance, journal.record.Acceptance,
		) {
			return errors.New("completed Device Sync cancellation journal conflicts with transition")
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
	record, _, err := decodeDeviceSyncCancellationJournalRecord(encoded)
	if err != nil || !sameMigrationCancellationAcceptance(
		record.Acceptance, journal.record.Acceptance,
	) {
		return errors.New("pending Device Sync cancellation journal conflicts with transition")
	}
	if err := os.Rename(pending, completed); err != nil {
		return err
	}
	return syncCustodyDirectory(journal.directory)
}

func (custody *FileArtifactCustody) listDeviceSyncCancellationJournals(
	ctx context.Context,
) ([]deviceSyncCancellationJournal, error) {
	if custody == nil || ctx == nil {
		return nil, serviceauthority.ErrInvalid
	}
	custody.mu.Lock()
	defer custody.mu.Unlock()
	base := filepath.Join(custody.root, deviceSyncCancellationDirectoryName)
	if _, err := os.Lstat(base); os.IsNotExist(err) {
		return []deviceSyncCancellationJournal{}, nil
	} else if err != nil || rejectUnsafeCustodyDirectory(base) != nil {
		return nil, errors.New("Device Sync cancellation custody root is unsafe")
	}
	paths, err := cancellationJournalPaths(base)
	if err != nil {
		return nil, err
	}
	journals := make([]deviceSyncCancellationJournal, 0, len(paths))
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		encoded, err := readProtectedRecord(path, maximumEvidenceByteCount)
		if err != nil {
			return nil, err
		}
		record, anchor, err := decodeDeviceSyncCancellationJournalRecord(encoded)
		if err != nil {
			return nil, err
		}
		acceptance, err := record.Acceptance.VerifiedPayload()
		if err != nil {
			return nil, err
		}
		expected := custody.cancellationDirectory(
			acceptance.Scope.ScopeID, acceptance.MigrationID,
		)
		if filepath.Dir(path) != expected ||
			rejectUnsafeCustodyDirectory(expected) != nil {
			return nil, errors.New("Device Sync cancellation journal path conflicts with evidence")
		}
		journals = append(journals, deviceSyncCancellationJournal{
			anchor: anchor, directory: expected, record: record,
			completed: filepath.Base(path) == completedCancellationFileName,
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

func buildDeviceSyncCancellationJournalRecord(
	signer *serviceauthority.DeploymentSigner,
	evidence serviceauthority.MigrationCancellationEvidence,
	anchor serviceauthority.TrustAnchor,
	acceptedAtMilliseconds int64,
) (
	deviceSyncCancellationJournalRecord,
	serviceauthority.ManifestPayload,
	error,
) {
	if signer == nil {
		return deviceSyncCancellationJournalRecord{}, serviceauthority.ManifestPayload{},
			serviceauthority.ErrInvalid
	}
	cancellation, err := evidence.ValidateHistoricalCatchUp(
		anchor, acceptedAtMilliseconds,
	)
	if err != nil || cancellation.Migration == nil ||
		cancellation.Scope.Kind != serviceauthority.ScopeDeviceSync ||
		(signer.DeploymentID() != cancellation.Migration.SourceDeploymentID &&
			signer.DeploymentID() != cancellation.Migration.TargetDeploymentID) {
		return deviceSyncCancellationJournalRecord{}, serviceauthority.ManifestPayload{},
			serviceauthority.ErrInvalid
	}
	digest, err := evidence.ReferenceDigest()
	if err != nil {
		return deviceSyncCancellationJournalRecord{}, serviceauthority.ManifestPayload{}, err
	}
	acceptance, err := signer.SignMigrationCancellationAcceptance(
		serviceauthority.MigrationCancellationAcceptancePayload{
			AcceptedAtMilliseconds:     acceptedAtMilliseconds,
			CancellationEvidenceDigest: digest,
			LocalDeploymentID:          signer.DeploymentID(),
			MigrationID:                cancellation.Migration.MigrationID,
			Scope:                      cancellation.Scope,
			Version:                    serviceauthority.SchemaVersion,
		},
	)
	if err != nil {
		return deviceSyncCancellationJournalRecord{}, serviceauthority.ManifestPayload{}, err
	}
	return deviceSyncCancellationJournalRecord{
		Acceptance: acceptance, Evidence: evidence, Version: artifactCustodyVersion,
	}, cancellation, nil
}

func decodeDeviceSyncCancellationJournalRecord(
	encoded []byte,
) (deviceSyncCancellationJournalRecord, serviceauthority.TrustAnchor, error) {
	var record deviceSyncCancellationJournalRecord
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
	current, err := record.Evidence.Preparation.CurrentManifest.VerifiedPayload()
	if err != nil {
		return record, serviceauthority.TrustAnchor{}, serviceauthority.ErrInvalid
	}
	signature := record.Evidence.Preparation.CurrentManifest.Signature
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
	cancellation, err := record.Evidence.ValidateHistoricalCatchUp(
		anchor, acceptance.AcceptedAtMilliseconds,
	)
	digest, digestErr := record.Evidence.ReferenceDigest()
	if err != nil || digestErr != nil || cancellation.Migration == nil ||
		acceptance.Scope != cancellation.Scope ||
		acceptance.MigrationID != cancellation.Migration.MigrationID ||
		acceptance.CancellationEvidenceDigest != digest ||
		(acceptance.LocalDeploymentID != cancellation.Migration.SourceDeploymentID &&
			acceptance.LocalDeploymentID != cancellation.Migration.TargetDeploymentID) {
		return record, serviceauthority.TrustAnchor{}, serviceauthority.ErrInvalid
	}
	return record, anchor, nil
}

func sameMigrationCancellationAcceptance(
	left serviceauthority.MigrationCancellationAcceptance,
	right serviceauthority.MigrationCancellationAcceptance,
) bool {
	return bytes.Equal(left.Payload, right.Payload) && left.Signature == right.Signature
}

func cancellationJournalPaths(base string) ([]string, error) {
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
			return nil, errors.New("Device Sync cancellation custody contains an unsafe principal path")
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
				return nil, errors.New("Device Sync cancellation custody contains an unsafe migration path")
			}
			pending := filepath.Join(migrationPath, cancellationFileName)
			completed := filepath.Join(migrationPath, completedCancellationFileName)
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

func ensurePrivateSyncedOperationDirectory(root, destination string) error {
	if err := ensurePrivateCustodyDirectory(root, destination); err != nil {
		return err
	}
	relative, err := filepath.Rel(root, destination)
	if err != nil {
		return err
	}
	current := root
	if err := syncCustodyDirectory(current); err != nil {
		return err
	}
	components := strings.Split(filepath.Clean(relative), string(filepath.Separator))
	for index, component := range components {
		current = filepath.Join(current, component)
		if index+1 < len(components) {
			if err := syncCustodyDirectory(current); err != nil {
				return err
			}
		}
	}
	return nil
}

func (custody *FileArtifactCustody) cancellationDirectory(
	principalID uuid.UUID,
	migrationID uuid.UUID,
) string {
	return filepath.Join(
		custody.root, deviceSyncCancellationDirectoryName,
		principalID.String(), migrationID.String(),
	)
}

func cancellationJournalPath(
	custody *FileArtifactCustody,
	scope serviceauthority.Scope,
	migrationID uuid.UUID,
	name string,
) (string, error) {
	if custody == nil || scope.Kind != serviceauthority.ScopeDeviceSync ||
		scope.Validate() != nil || migrationID == uuid.Nil ||
		(name != cancellationFileName && name != completedCancellationFileName) {
		return "", fmt.Errorf("invalid Device Sync cancellation journal path")
	}
	return filepath.Join(
		custody.cancellationDirectory(scope.ScopeID, migrationID), name,
	), nil
}
