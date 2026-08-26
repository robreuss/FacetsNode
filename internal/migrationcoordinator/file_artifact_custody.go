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
	"sort"
	"strings"
	"sync"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

const (
	artifactCustodyVersion      = 1
	maximumEvidenceByteCount    = 8 * 1024 * 1024
	serviceStateFileName        = "service-state.bin"
	blobInventoryFileName       = "blob-inventory.bin"
	preparationFileName         = "preparation.json"
	snapshotFileName            = "snapshot.json"
	metadataFileName            = "metadata.json"
	readinessFileName           = "readiness.json"
	activationFileName          = "activation.json"
	completedActivationFileName = "activation-completed.json"
)

type fileArtifactCustodyMetadata struct {
	BlobInventoryArtifactID uuid.UUID `json:"blobInventoryArtifactID"`
	MigrationID             uuid.UUID `json:"migrationID"`
	PrincipalID             uuid.UUID `json:"principalID"`
	ServiceStateArtifactID  uuid.UUID `json:"serviceStateArtifactID"`
	SnapshotID              uuid.UUID `json:"snapshotID"`
	SnapshotReferenceDigest string    `json:"snapshotReferenceDigest"`
	Version                 int       `json:"version"`
}

type deviceSyncActivationJournalRecord struct {
	Acceptance serviceauthority.MigrationActivationAcceptance `json:"acceptance"`
	Evidence   serviceauthority.MigrationActivationEvidence   `json:"evidence"`
	Version    int                                            `json:"version"`
}

type deviceSyncActivationJournal struct {
	anchor    serviceauthority.TrustAnchor
	completed bool
	record    deviceSyncActivationJournalRecord
	transfer  PreparedDeviceSyncTransfer
}

// FileArtifactCustody owns exact authenticated migration artifact bytes. Each
// transfer is committed by an atomic directory rename after every file and the
// staging directory are synced. Signed evidence is retained beside the bytes;
// the path is derived only from authenticated UUIDs.
type FileArtifactCustody struct {
	root string
	mu   sync.Mutex
}

func NewFileArtifactCustody(root string) (*FileArtifactCustody, error) {
	if root == "" || !filepath.IsAbs(root) {
		return nil, errors.New("migration artifact custody root must be absolute")
	}
	root = filepath.Clean(root)
	if info, err := os.Lstat(root); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("migration artifact custody root is not a directory")
		}
	} else if os.IsNotExist(err) {
		if err := os.MkdirAll(root, 0o700); err != nil {
			return nil, fmt.Errorf("create migration artifact custody root: %w", err)
		}
	} else {
		return nil, err
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return nil, fmt.Errorf("protect migration artifact custody root: %w", err)
	}
	if err := ensurePrivateCustodyDirectory(root, filepath.Join(root, ".staging")); err != nil {
		return nil, fmt.Errorf("create migration artifact custody root: %w", err)
	}
	if err := rejectUnsafeCustodyDirectory(root); err != nil {
		return nil, err
	}
	return &FileArtifactCustody{root: root}, nil
}

type PreparedDeviceSyncTransfer struct {
	directory               string
	metadata                fileArtifactCustodyMetadata
	serviceStateDescriptor  serviceauthority.MigrationArtifactDescriptor
	blobInventoryDescriptor serviceauthority.MigrationArtifactDescriptor
	blobInventoryDigest     postgres.DeviceSyncMigrationDigest
}

func (transfer PreparedDeviceSyncTransfer) BlobInventoryDigest() postgres.DeviceSyncMigrationDigest {
	return transfer.blobInventoryDigest
}

func (transfer PreparedDeviceSyncTransfer) OpenBlobInventory() (*os.File, error) {
	return openProtectedArtifact(
		filepath.Join(transfer.directory, blobInventoryFileName),
		transfer.blobInventoryDescriptor,
	)
}

func (transfer PreparedDeviceSyncTransfer) OpenArtifacts() (
	postgres.DeviceSyncMigrationStagedArtifacts,
	func() error,
	error,
) {
	state, err := openProtectedArtifact(
		filepath.Join(transfer.directory, serviceStateFileName),
		transfer.serviceStateDescriptor,
	)
	if err != nil {
		return postgres.DeviceSyncMigrationStagedArtifacts{}, nil, err
	}
	inventory, err := transfer.OpenBlobInventory()
	if err != nil {
		_ = state.Close()
		return postgres.DeviceSyncMigrationStagedArtifacts{}, nil, err
	}
	closeArtifacts := func() error {
		return errors.Join(state.Close(), inventory.Close())
	}
	return postgres.DeviceSyncMigrationStagedArtifacts{
		ServiceState:  state,
		BlobInventory: inventory,
	}, closeArtifacts, nil
}

func (custody *FileArtifactCustody) stagePreparedDeviceSyncTransfer(
	ctx context.Context,
	validated serviceauthority.ValidatedMigrationTransfer,
	preparation serviceauthority.MigrationPreparation,
	snapshot serviceauthority.MigrationSnapshot,
	serviceState io.Reader,
	blobInventory io.Reader,
) (PreparedDeviceSyncTransfer, error) {
	if custody == nil || ctx == nil || serviceState == nil || blobInventory == nil ||
		validated.Snapshot.Scope.Kind != serviceauthority.ScopeDeviceSync ||
		validated.Snapshot.Scope.ScopeID == uuid.Nil {
		return PreparedDeviceSyncTransfer{}, serviceauthority.ErrInvalid
	}
	transfer, preparationRecord, snapshotRecord, metadataRecord, err :=
		custody.expectedPreparedDeviceSyncTransfer(validated, preparation, snapshot)
	if err != nil {
		return PreparedDeviceSyncTransfer{}, err
	}

	custody.mu.Lock()
	defer custody.mu.Unlock()
	if info, err := os.Lstat(transfer.directory); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
			return PreparedDeviceSyncTransfer{}, errors.New(
				"existing migration artifact custody directory is unsafe",
			)
		}
		if err := verifyExistingPreparedTransfer(
			ctx, transfer, preparationRecord, snapshotRecord, metadataRecord,
		); err != nil {
			return PreparedDeviceSyncTransfer{}, err
		}
		return transfer, nil
	} else if !os.IsNotExist(err) {
		return PreparedDeviceSyncTransfer{}, err
	}

	stagingDirectory, err := os.MkdirTemp(filepath.Join(custody.root, ".staging"), "device-sync-*")
	if err != nil {
		return PreparedDeviceSyncTransfer{}, fmt.Errorf("create migration artifact staging directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(stagingDirectory) }()
	if err := os.Chmod(stagingDirectory, 0o700); err != nil {
		return PreparedDeviceSyncTransfer{}, err
	}
	if err := stageExactArtifact(
		ctx, filepath.Join(stagingDirectory, serviceStateFileName), serviceState,
		transfer.serviceStateDescriptor,
	); err != nil {
		return PreparedDeviceSyncTransfer{}, err
	}
	if err := stageExactArtifact(
		ctx, filepath.Join(stagingDirectory, blobInventoryFileName), blobInventory,
		transfer.blobInventoryDescriptor,
	); err != nil {
		return PreparedDeviceSyncTransfer{}, err
	}
	for name, value := range map[string][]byte{
		preparationFileName: preparationRecord,
		snapshotFileName:    snapshotRecord,
		metadataFileName:    metadataRecord,
	} {
		if len(value) > maximumEvidenceByteCount {
			return PreparedDeviceSyncTransfer{}, errors.New(
				"migration artifact custody evidence exceeds the bounded record size",
			)
		}
		if err := writeSyncedProtectedFile(filepath.Join(stagingDirectory, name), value); err != nil {
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
		return PreparedDeviceSyncTransfer{}, fmt.Errorf("commit migration artifact custody: %w", err)
	}
	if err := syncCustodyDirectory(parent); err != nil {
		return PreparedDeviceSyncTransfer{}, err
	}
	return transfer, nil
}

// openPreparedDeviceSyncTransfer verifies exact already-committed custody
// without requiring caller-provided streams. It is the restart/lost-response
// recovery seam after a source draft has already been promoted.
func (custody *FileArtifactCustody) openPreparedDeviceSyncTransfer(
	ctx context.Context,
	validated serviceauthority.ValidatedMigrationTransfer,
	preparation serviceauthority.MigrationPreparation,
	snapshot serviceauthority.MigrationSnapshot,
) (PreparedDeviceSyncTransfer, bool, error) {
	if custody == nil || ctx == nil {
		return PreparedDeviceSyncTransfer{}, false, serviceauthority.ErrInvalid
	}
	transfer, preparationRecord, snapshotRecord, metadataRecord, err :=
		custody.expectedPreparedDeviceSyncTransfer(validated, preparation, snapshot)
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
			"existing migration artifact custody directory is unsafe",
		)
	}
	if err := verifyExistingPreparedTransfer(
		ctx, transfer, preparationRecord, snapshotRecord, metadataRecord,
	); err != nil {
		return PreparedDeviceSyncTransfer{}, true, err
	}
	return transfer, true, nil
}

func (custody *FileArtifactCustody) expectedPreparedDeviceSyncTransfer(
	validated serviceauthority.ValidatedMigrationTransfer,
	preparation serviceauthority.MigrationPreparation,
	snapshot serviceauthority.MigrationSnapshot,
) (PreparedDeviceSyncTransfer, []byte, []byte, []byte, error) {
	if custody == nil || validated.Snapshot.Scope.Kind != serviceauthority.ScopeDeviceSync ||
		validated.Snapshot.Scope.ScopeID == uuid.Nil {
		return PreparedDeviceSyncTransfer{}, nil, nil, nil, serviceauthority.ErrInvalid
	}
	stateDescriptor, inventoryDescriptor, err := migrationArtifactDescriptors(validated.Snapshot)
	if err != nil {
		return PreparedDeviceSyncTransfer{}, nil, nil, nil, err
	}
	inventoryDigest, err := migrationDigest(inventoryDescriptor.TransferDigest)
	if err != nil {
		return PreparedDeviceSyncTransfer{}, nil, nil, nil, err
	}
	snapshotReferenceDigest, err := snapshot.ReferenceDigest()
	if err != nil {
		return PreparedDeviceSyncTransfer{}, nil, nil, nil, serviceauthority.ErrInvalid
	}
	metadata := fileArtifactCustodyMetadata{
		BlobInventoryArtifactID: inventoryDescriptor.ArtifactID,
		MigrationID:             validated.Migration.MigrationID,
		PrincipalID:             validated.Snapshot.Scope.ScopeID,
		ServiceStateArtifactID:  stateDescriptor.ArtifactID,
		SnapshotID:              validated.Snapshot.SnapshotID,
		SnapshotReferenceDigest: snapshotReferenceDigest,
		Version:                 artifactCustodyVersion,
	}
	if err := validateCustodyMetadata(metadata); err != nil {
		return PreparedDeviceSyncTransfer{}, nil, nil, nil, err
	}
	transfer := PreparedDeviceSyncTransfer{
		directory: custody.transferDirectory(metadata), metadata: metadata,
		serviceStateDescriptor: stateDescriptor, blobInventoryDescriptor: inventoryDescriptor,
		blobInventoryDigest: inventoryDigest,
	}
	preparationRecord, err := json.Marshal(preparation)
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
	return transfer, preparationRecord, snapshotRecord, metadataRecord, nil
}

func (custody *FileArtifactCustody) loadLiveReadiness(
	transfer PreparedDeviceSyncTransfer,
	snapshot serviceauthority.MigrationSnapshot,
	nowMilliseconds int64,
) (serviceauthority.MigrationReadiness, bool, error) {
	if custody == nil || nowMilliseconds < 0 || transfer.directory == "" {
		return serviceauthority.MigrationReadiness{}, false, serviceauthority.ErrInvalid
	}
	custody.mu.Lock()
	defer custody.mu.Unlock()
	return loadLiveReadinessLocked(transfer, snapshot, nowMilliseconds)
}

func loadLiveReadinessLocked(
	transfer PreparedDeviceSyncTransfer,
	snapshot serviceauthority.MigrationSnapshot,
	nowMilliseconds int64,
) (serviceauthority.MigrationReadiness, bool, error) {
	encoded, err := readProtectedRecord(
		filepath.Join(transfer.directory, readinessFileName), maximumEvidenceByteCount,
	)
	if os.IsNotExist(err) {
		return serviceauthority.MigrationReadiness{}, false, nil
	}
	if err != nil {
		return serviceauthority.MigrationReadiness{}, false, err
	}
	var readiness serviceauthority.MigrationReadiness
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&readiness); err != nil {
		return serviceauthority.MigrationReadiness{}, false, err
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return serviceauthority.MigrationReadiness{}, false, err
	}
	payload, err := readiness.VerifiedPayload(nil)
	snapshotDigest, digestErr := snapshot.ReferenceDigest()
	if err != nil {
		return serviceauthority.MigrationReadiness{}, false, errors.New(
			"stored migration readiness signature is invalid",
		)
	}
	if digestErr != nil || payload.MigrationID != transfer.metadata.MigrationID ||
		payload.Scope.ScopeID != transfer.metadata.PrincipalID ||
		payload.SnapshotReferenceDigest != snapshotDigest {
		return serviceauthority.MigrationReadiness{}, false, errors.New(
			"stored migration readiness conflicts with staged transfer",
		)
	}
	if nowMilliseconds < payload.ReadyAtMilliseconds {
		return serviceauthority.MigrationReadiness{}, false, errors.New(
			"migration readiness clock moved before the durable readiness instant",
		)
	}
	if nowMilliseconds >= payload.ExpiresAtMilliseconds {
		return serviceauthority.MigrationReadiness{}, false, nil
	}
	return readiness, true, nil
}

func (custody *FileArtifactCustody) storeReadiness(
	transfer PreparedDeviceSyncTransfer,
	snapshot serviceauthority.MigrationSnapshot,
	readiness serviceauthority.MigrationReadiness,
) (serviceauthority.MigrationReadiness, error) {
	if custody == nil || transfer.directory == "" {
		return serviceauthority.MigrationReadiness{}, serviceauthority.ErrInvalid
	}
	payload, err := readiness.VerifiedPayload(nil)
	if err != nil || payload.MigrationID != transfer.metadata.MigrationID ||
		payload.Scope.ScopeID != transfer.metadata.PrincipalID ||
		payload.SnapshotReferenceDigest != transfer.metadata.SnapshotReferenceDigest {
		return serviceauthority.MigrationReadiness{}, serviceauthority.ErrInvalid
	}
	encoded, err := json.Marshal(readiness)
	if err != nil {
		return serviceauthority.MigrationReadiness{}, err
	}
	custody.mu.Lock()
	defer custody.mu.Unlock()
	if existing, found, err := loadLiveReadinessLocked(
		transfer, snapshot, payload.ReadyAtMilliseconds,
	); err != nil {
		return serviceauthority.MigrationReadiness{}, err
	} else if found {
		return existing, nil
	}
	temporary, err := os.CreateTemp(transfer.directory, ".readiness-*")
	if err != nil {
		return serviceauthority.MigrationReadiness{}, err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return serviceauthority.MigrationReadiness{}, err
	}
	if _, err := io.Copy(temporary, bytes.NewReader(encoded)); err != nil {
		_ = temporary.Close()
		return serviceauthority.MigrationReadiness{}, err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return serviceauthority.MigrationReadiness{}, err
	}
	if err := temporary.Close(); err != nil {
		return serviceauthority.MigrationReadiness{}, err
	}
	if err := os.Rename(temporaryPath, filepath.Join(transfer.directory, readinessFileName)); err != nil {
		return serviceauthority.MigrationReadiness{}, err
	}
	if err := syncCustodyDirectory(transfer.directory); err != nil {
		return serviceauthority.MigrationReadiness{}, err
	}
	return readiness, nil
}

// stageDeviceSyncActivationJournal durably records the exact activation
// evidence and the instant at which it was still live before either the
// registry or database is advanced. The protected record is the restart seam
// that prevents a cross-store crash from becoming unrecoverable after the
// short-lived terminal Manifest expires.
func (custody *FileArtifactCustody) stageDeviceSyncActivationJournal(
	ctx context.Context,
	signer *serviceauthority.DeploymentSigner,
	evidence serviceauthority.MigrationActivationEvidence,
	anchor serviceauthority.TrustAnchor,
	acceptedAtMilliseconds int64,
) (deviceSyncActivationJournal, error) {
	if custody == nil || ctx == nil || signer == nil ||
		acceptedAtMilliseconds < 0 {
		return deviceSyncActivationJournal{}, serviceauthority.ErrInvalid
	}
	localDeploymentID := signer.DeploymentID()
	activation, err := evidence.ActivationManifest.VerifiedPayload()
	if err != nil || activation.Migration == nil ||
		(localDeploymentID != activation.Migration.SourceDeploymentID &&
			localDeploymentID != activation.Migration.TargetDeploymentID) {
		return deviceSyncActivationJournal{}, serviceauthority.ErrInvalid
	}
	// Locate an exact preexisting pending/completed journal using evidence
	// validated at the signed activation instant. This allows an exact retry to
	// recover after terminal expiry without permitting a new late acceptance.
	if _, err := evidence.Validate(anchor, activation.ValidFromMilliseconds); err != nil {
		return deviceSyncActivationJournal{}, serviceauthority.ErrInvalid
	}
	validated, err := evidence.Snapshot.ValidatePreparedTransfer(
		evidence.Preparation, anchor, activation.ValidFromMilliseconds,
	)
	if err != nil {
		return deviceSyncActivationJournal{}, err
	}
	evidenceDigest, err := evidence.ReferenceDigest()
	if err != nil {
		return deviceSyncActivationJournal{}, err
	}
	transfer, found, err := custody.openPreparedDeviceSyncTransfer(
		ctx, validated, evidence.Preparation, evidence.Snapshot,
	)
	if err != nil {
		return deviceSyncActivationJournal{}, err
	}
	if !found {
		return deviceSyncActivationJournal{}, errors.New(
			"Device Sync activation lacks exact local migration artifact custody",
		)
	}
	custody.mu.Lock()
	defer custody.mu.Unlock()
	path := filepath.Join(transfer.directory, activationFileName)
	for _, candidate := range []struct {
		path      string
		completed bool
	}{
		{path: path},
		{path: filepath.Join(transfer.directory, completedActivationFileName), completed: true},
	} {
		if existingBytes, readErr := readProtectedRecord(
			candidate.path, maximumEvidenceByteCount,
		); readErr == nil {
			existing, anchor, validationErr := decodeDeviceSyncActivationJournalRecord(
				existingBytes,
			)
			acceptance, acceptanceErr := existing.Acceptance.VerifiedPayload()
			if validationErr != nil || acceptanceErr != nil ||
				acceptance.LocalDeploymentID != localDeploymentID ||
				acceptance.ActivationEvidenceDigest != evidenceDigest ||
				acceptedAtMilliseconds < acceptance.AcceptedAtMilliseconds ||
				existing.Acceptance.Signature.PublicSigningKeyX963 !=
					signer.PublicSigningKeyX963() ||
				existing.Acceptance.Signature.SigningKeyFingerprint !=
					signer.SigningKeyFingerprint() {
				return deviceSyncActivationJournal{}, errors.New(
					"stored Device Sync activation journal conflicts with requested evidence",
				)
			}
			return deviceSyncActivationJournal{
				anchor: anchor, completed: candidate.completed,
				record: existing, transfer: transfer,
			}, nil
		} else if !os.IsNotExist(readErr) {
			return deviceSyncActivationJournal{}, readErr
		}
	}
	record, _, err := buildDeviceSyncActivationJournalRecord(
		signer, evidence, anchor, acceptedAtMilliseconds,
	)
	if err != nil {
		return deviceSyncActivationJournal{}, err
	}
	encoded, err := json.Marshal(record)
	if err != nil || len(encoded) == 0 || len(encoded) > maximumEvidenceByteCount {
		return deviceSyncActivationJournal{}, serviceauthority.ErrInvalid
	}
	temporary, err := os.CreateTemp(transfer.directory, ".activation-*")
	if err != nil {
		return deviceSyncActivationJournal{}, err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return deviceSyncActivationJournal{}, err
	}
	if _, err := io.Copy(temporary, bytes.NewReader(encoded)); err != nil {
		_ = temporary.Close()
		return deviceSyncActivationJournal{}, err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return deviceSyncActivationJournal{}, err
	}
	if err := temporary.Close(); err != nil {
		return deviceSyncActivationJournal{}, err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return deviceSyncActivationJournal{}, err
	}
	if err := syncCustodyDirectory(transfer.directory); err != nil {
		return deviceSyncActivationJournal{}, err
	}
	return deviceSyncActivationJournal{
		anchor: anchor, record: record, transfer: transfer,
	}, nil
}

func (custody *FileArtifactCustody) completeDeviceSyncActivationJournal(
	journal deviceSyncActivationJournal,
) error {
	if custody == nil || journal.transfer.directory == "" ||
		len(journal.record.Acceptance.Payload) == 0 {
		return serviceauthority.ErrInvalid
	}
	if journal.completed {
		return nil
	}
	custody.mu.Lock()
	defer custody.mu.Unlock()
	pending := filepath.Join(journal.transfer.directory, activationFileName)
	completed := filepath.Join(journal.transfer.directory, completedActivationFileName)
	if encoded, err := readProtectedRecord(completed, maximumEvidenceByteCount); err == nil {
		record, _, validationErr := decodeDeviceSyncActivationJournalRecord(encoded)
		if validationErr != nil || !sameMigrationActivationAcceptance(
			record.Acceptance, journal.record.Acceptance,
		) {
			return errors.New("completed Device Sync activation journal conflicts with cutover")
		}
		if _, err := os.Lstat(pending); err == nil {
			if err := os.Remove(pending); err != nil {
				return err
			}
		} else if !os.IsNotExist(err) {
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
	record, _, err := decodeDeviceSyncActivationJournalRecord(encoded)
	if err != nil || !sameMigrationActivationAcceptance(
		record.Acceptance, journal.record.Acceptance,
	) {
		return errors.New("pending Device Sync activation journal conflicts with cutover")
	}
	if err := os.Rename(pending, completed); err != nil {
		return err
	}
	return syncCustodyDirectory(journal.transfer.directory)
}

// listDeviceSyncActivationJournals validates every persisted activation
// record and its underlying exact transfer before returning deterministic
// recovery work. Unknown, unsafe, or malformed custody paths fail the whole
// scan rather than being silently ignored.
func (custody *FileArtifactCustody) listDeviceSyncActivationJournals(
	ctx context.Context,
) ([]deviceSyncActivationJournal, error) {
	if custody == nil || ctx == nil {
		return nil, serviceauthority.ErrInvalid
	}
	custody.mu.Lock()
	defer custody.mu.Unlock()
	base := filepath.Join(custody.root, "device-sync")
	if _, err := os.Lstat(base); os.IsNotExist(err) {
		return []deviceSyncActivationJournal{}, nil
	} else if err != nil || rejectUnsafeCustodyDirectory(base) != nil {
		return nil, errors.New("Device Sync activation custody root is unsafe")
	}
	paths, err := activationJournalPaths(base)
	if err != nil {
		return nil, err
	}
	journals := make([]deviceSyncActivationJournal, 0, len(paths))
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		encoded, err := readProtectedRecord(path, maximumEvidenceByteCount)
		if err != nil {
			return nil, err
		}
		record, anchor, err := decodeDeviceSyncActivationJournalRecord(encoded)
		if err != nil {
			return nil, err
		}
		acceptance, err := record.Acceptance.VerifiedPayload()
		if err != nil {
			return nil, err
		}
		validated, err := record.Evidence.Snapshot.ValidatePreparedTransfer(
			record.Evidence.Preparation,
			anchor,
			acceptance.AcceptedAtMilliseconds,
		)
		if err != nil {
			return nil, serviceauthority.ErrInvalid
		}
		transfer, preparationRecord, snapshotRecord, metadataRecord, err :=
			custody.expectedPreparedDeviceSyncTransfer(
				validated, record.Evidence.Preparation, record.Evidence.Snapshot,
			)
		if err != nil || filepath.Dir(path) != transfer.directory {
			return nil, errors.New("Device Sync activation journal path conflicts with evidence")
		}
		if err := verifyExistingPreparedTransfer(
			ctx, transfer, preparationRecord, snapshotRecord, metadataRecord,
		); err != nil {
			return nil, err
		}
		journals = append(journals, deviceSyncActivationJournal{
			anchor: anchor, record: record, transfer: transfer,
		})
	}
	sort.Slice(journals, func(left, right int) bool {
		leftPayload, _ := journals[left].record.Evidence.ActivationManifest.VerifiedPayload()
		rightPayload, _ := journals[right].record.Evidence.ActivationManifest.VerifiedPayload()
		if leftPayload.Scope.ScopeID != rightPayload.Scope.ScopeID {
			return bytes.Compare(leftPayload.Scope.ScopeID[:], rightPayload.Scope.ScopeID[:]) < 0
		}
		return bytes.Compare(
			leftPayload.Migration.MigrationID[:],
			rightPayload.Migration.MigrationID[:],
		) < 0
	})
	return journals, nil
}

func buildDeviceSyncActivationJournalRecord(
	signer *serviceauthority.DeploymentSigner,
	evidence serviceauthority.MigrationActivationEvidence,
	anchor serviceauthority.TrustAnchor,
	acceptedAtMilliseconds int64,
) (deviceSyncActivationJournalRecord, serviceauthority.ValidatedMigrationTransfer, error) {
	if signer == nil {
		return deviceSyncActivationJournalRecord{},
			serviceauthority.ValidatedMigrationTransfer{}, serviceauthority.ErrInvalid
	}
	localDeploymentID := signer.DeploymentID()
	activation, err := evidence.ValidateHistoricalCatchUp(anchor, acceptedAtMilliseconds)
	if err != nil || activation.Migration == nil ||
		activation.Scope.Kind != serviceauthority.ScopeDeviceSync ||
		(localDeploymentID != activation.Migration.SourceDeploymentID &&
			localDeploymentID != activation.Migration.TargetDeploymentID) {
		return deviceSyncActivationJournalRecord{},
			serviceauthority.ValidatedMigrationTransfer{}, serviceauthority.ErrInvalid
	}
	validated, err := evidence.Snapshot.ValidatePreparedTransfer(
		evidence.Preparation, anchor, acceptedAtMilliseconds,
	)
	if err != nil {
		return deviceSyncActivationJournalRecord{},
			serviceauthority.ValidatedMigrationTransfer{}, err
	}
	digest, err := evidence.ReferenceDigest()
	if err != nil {
		return deviceSyncActivationJournalRecord{},
			serviceauthority.ValidatedMigrationTransfer{}, err
	}
	snapshotDigest, err := evidence.Snapshot.ReferenceDigest()
	if err != nil {
		return deviceSyncActivationJournalRecord{},
			serviceauthority.ValidatedMigrationTransfer{}, err
	}
	acceptance, err := signer.SignMigrationActivationAcceptance(
		serviceauthority.MigrationActivationAcceptancePayload{
			AcceptedAtMilliseconds:   acceptedAtMilliseconds,
			ActivationEvidenceDigest: digest,
			LocalDeploymentID:        localDeploymentID,
			MigrationID:              activation.Migration.MigrationID,
			Scope:                    activation.Scope,
			SnapshotReferenceDigest:  snapshotDigest,
			Version:                  serviceauthority.SchemaVersion,
		},
	)
	if err != nil {
		return deviceSyncActivationJournalRecord{},
			serviceauthority.ValidatedMigrationTransfer{}, err
	}
	return deviceSyncActivationJournalRecord{
		Acceptance: acceptance,
		Evidence:   evidence,
		Version:    artifactCustodyVersion,
	}, validated, nil
}

func decodeDeviceSyncActivationJournalRecord(
	encoded []byte,
) (deviceSyncActivationJournalRecord, serviceauthority.TrustAnchor, error) {
	var record deviceSyncActivationJournalRecord
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
		PublicSigningKeyX963:  signature.PublicSigningKeyX963,
		Scope:                 current.Scope,
		SignerID:              signature.SignerID,
		SigningKeyFingerprint: signature.SigningKeyFingerprint,
		Version:               serviceauthority.SchemaVersion,
	}
	acceptance, err := record.Acceptance.VerifiedPayload()
	if err != nil {
		return record, serviceauthority.TrustAnchor{}, serviceauthority.ErrInvalid
	}
	activation, err := record.Evidence.ValidateHistoricalCatchUp(
		anchor, acceptance.AcceptedAtMilliseconds,
	)
	evidenceDigest, digestErr := record.Evidence.ReferenceDigest()
	snapshotDigest, snapshotDigestErr := record.Evidence.Snapshot.ReferenceDigest()
	if err != nil || digestErr != nil || snapshotDigestErr != nil ||
		activation.Migration == nil || acceptance.Scope != activation.Scope ||
		acceptance.MigrationID != activation.Migration.MigrationID ||
		acceptance.ActivationEvidenceDigest != evidenceDigest ||
		acceptance.SnapshotReferenceDigest != snapshotDigest ||
		(acceptance.LocalDeploymentID != activation.Migration.SourceDeploymentID &&
			acceptance.LocalDeploymentID != activation.Migration.TargetDeploymentID) {
		return record, serviceauthority.TrustAnchor{}, serviceauthority.ErrInvalid
	}
	return record, anchor, nil
}

func sameMigrationActivationAcceptance(
	left serviceauthority.MigrationActivationAcceptance,
	right serviceauthority.MigrationActivationAcceptance,
) bool {
	return bytes.Equal(left.Payload, right.Payload) && left.Signature == right.Signature
}

func activationJournalPaths(base string) ([]string, error) {
	principals, err := os.ReadDir(base)
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0)
	for _, principal := range principals {
		principalPath := filepath.Join(base, principal.Name())
		if _, err := uuid.Parse(principal.Name()); err != nil || principal.Type()&os.ModeSymlink != 0 ||
			!principal.IsDir() || rejectUnsafeCustodyDirectory(principalPath) != nil {
			return nil, errors.New("Device Sync activation custody contains an unsafe principal path")
		}
		migrations, err := os.ReadDir(principalPath)
		if err != nil {
			return nil, err
		}
		for _, migration := range migrations {
			migrationPath := filepath.Join(principalPath, migration.Name())
			if _, err := uuid.Parse(migration.Name()); err != nil || migration.Type()&os.ModeSymlink != 0 ||
				!migration.IsDir() || rejectUnsafeCustodyDirectory(migrationPath) != nil {
				return nil, errors.New("Device Sync activation custody contains an unsafe migration path")
			}
			snapshots, err := os.ReadDir(migrationPath)
			if err != nil {
				return nil, err
			}
			for _, snapshot := range snapshots {
				snapshotPath := filepath.Join(migrationPath, snapshot.Name())
				if _, err := uuid.Parse(snapshot.Name()); err != nil || snapshot.Type()&os.ModeSymlink != 0 ||
					!snapshot.IsDir() || rejectUnsafeCustodyDirectory(snapshotPath) != nil {
					return nil, errors.New("Device Sync activation custody contains an unsafe snapshot path")
				}
				activationPath := filepath.Join(snapshotPath, activationFileName)
				if _, err := os.Lstat(activationPath); err == nil {
					paths = append(paths, activationPath)
				} else if !os.IsNotExist(err) {
					return nil, err
				}
			}
		}
	}
	return paths, nil
}

func (custody *FileArtifactCustody) transferDirectory(metadata fileArtifactCustodyMetadata) string {
	return filepath.Join(
		custody.root,
		"device-sync",
		metadata.PrincipalID.String(),
		metadata.MigrationID.String(),
		metadata.SnapshotID.String(),
	)
}

func migrationArtifactDescriptors(
	snapshot serviceauthority.MigrationSnapshotPayload,
) (serviceauthority.MigrationArtifactDescriptor, serviceauthority.MigrationArtifactDescriptor, error) {
	// This coordinator checkpoint has exact custody for only these two artifact
	// kinds. Reject rather than silently declaring readiness while ignoring a
	// future onion, TLS, or route-custody descriptor.
	if len(snapshot.Artifacts) != 2 {
		return serviceauthority.MigrationArtifactDescriptor{},
			serviceauthority.MigrationArtifactDescriptor{}, serviceauthority.ErrInvalid
	}
	var state *serviceauthority.MigrationArtifactDescriptor
	var inventory *serviceauthority.MigrationArtifactDescriptor
	for index := range snapshot.Artifacts {
		descriptor := &snapshot.Artifacts[index]
		switch descriptor.Kind {
		case serviceauthority.ArtifactServiceStateSnapshot:
			if state != nil {
				return serviceauthority.MigrationArtifactDescriptor{}, serviceauthority.MigrationArtifactDescriptor{}, serviceauthority.ErrInvalid
			}
			copy := *descriptor
			state = &copy
		case serviceauthority.ArtifactBlobInventory:
			if inventory != nil {
				return serviceauthority.MigrationArtifactDescriptor{}, serviceauthority.MigrationArtifactDescriptor{}, serviceauthority.ErrInvalid
			}
			copy := *descriptor
			inventory = &copy
		}
	}
	if state == nil || inventory == nil || state.Validate() != nil || inventory.Validate() != nil {
		return serviceauthority.MigrationArtifactDescriptor{}, serviceauthority.MigrationArtifactDescriptor{}, serviceauthority.ErrInvalid
	}
	return *state, *inventory, nil
}

func validateCustodyMetadata(metadata fileArtifactCustodyMetadata) error {
	if metadata.Version != artifactCustodyVersion || metadata.PrincipalID == uuid.Nil ||
		metadata.MigrationID == uuid.Nil || metadata.SnapshotID == uuid.Nil ||
		metadata.ServiceStateArtifactID == uuid.Nil || metadata.BlobInventoryArtifactID == uuid.Nil ||
		metadata.ServiceStateArtifactID == metadata.BlobInventoryArtifactID ||
		len(metadata.SnapshotReferenceDigest) != sha256.Size*2 {
		return serviceauthority.ErrInvalid
	}
	decoded, err := hex.DecodeString(metadata.SnapshotReferenceDigest)
	if err != nil || hex.EncodeToString(decoded) != metadata.SnapshotReferenceDigest {
		return serviceauthority.ErrInvalid
	}
	return nil
}

func stageExactArtifact(
	ctx context.Context,
	path string,
	source io.Reader,
	descriptor serviceauthority.MigrationArtifactDescriptor,
) error {
	if descriptor.Validate() != nil {
		return serviceauthority.ErrInvalid
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	hash := sha256.New()
	contextSource := &custodyContextReader{ctx: ctx, reader: source}
	limited := &io.LimitedReader{R: contextSource, N: descriptor.ByteCount}
	written, copyErr := io.Copy(io.MultiWriter(file, hash), limited)
	if copyErr != nil {
		_ = file.Close()
		return copyErr
	}
	extra, extraErr := io.CopyN(io.Discard, contextSource, 1)
	if extraErr != nil && !errors.Is(extraErr, io.EOF) {
		_ = file.Close()
		return extraErr
	}
	if written != descriptor.ByteCount || hex.EncodeToString(hash.Sum(nil)) != descriptor.TransferDigest {
		_ = file.Close()
		return errors.New("migration artifact differs from signed descriptor")
	}
	if extra != 0 {
		_ = file.Close()
		return errors.New("migration artifact exceeds signed descriptor byte count")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func verifyExistingPreparedTransfer(
	ctx context.Context,
	transfer PreparedDeviceSyncTransfer,
	preparation, snapshot, metadata []byte,
) error {
	for name, expected := range map[string][]byte{
		preparationFileName: preparation,
		snapshotFileName:    snapshot,
		metadataFileName:    metadata,
	} {
		actual, err := readProtectedRecord(
			filepath.Join(transfer.directory, name), maximumEvidenceByteCount,
		)
		if err != nil || !bytes.Equal(actual, expected) {
			return errors.New("existing migration artifact custody conflicts with signed transfer")
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
		hash := sha256.New()
		_, copyErr := io.Copy(hash, &custodyContextReader{ctx: ctx, reader: file})
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil {
			return errors.Join(copyErr, closeErr)
		}
		if hex.EncodeToString(hash.Sum(nil)) != descriptor.TransferDigest {
			return errors.New("existing migration artifact custody digest conflicts with signed transfer")
		}
	}
	return nil
}

func openProtectedArtifact(
	path string,
	descriptor serviceauthority.MigrationArtifactDescriptor,
) (*os.File, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil || !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 ||
		pathInfo.Mode().Perm()&0o077 != 0 || pathInfo.Size() != descriptor.ByteCount {
		return nil, errors.New("migration artifact custody file metadata is invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 ||
		info.Size() != descriptor.ByteCount || !os.SameFile(pathInfo, info) {
		_ = file.Close()
		return nil, errors.New("migration artifact custody file metadata is invalid")
	}
	return file, nil
}

func readProtectedRecord(path string, maximumByteCount int64) ([]byte, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if maximumByteCount < 0 || !pathInfo.Mode().IsRegular() ||
		pathInfo.Mode()&os.ModeSymlink != 0 || pathInfo.Mode().Perm()&0o077 != 0 ||
		pathInfo.Size() < 0 || pathInfo.Size() > maximumByteCount {
		return nil, errors.New("migration custody record metadata is invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !os.SameFile(pathInfo, info) {
		_ = file.Close()
		return nil, errors.New("migration custody record identity changed while opening")
	}
	value, readErr := io.ReadAll(io.LimitReader(file, maximumByteCount+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return nil, errors.Join(readErr, closeErr)
	}
	if int64(len(value)) != pathInfo.Size() {
		return nil, errors.New("migration custody record size changed while reading")
	}
	return value, nil
}

func writeSyncedProtectedFile(path string, value []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(file, bytes.NewReader(value)); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func rejectUnsafeCustodyDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("migration artifact custody directory is not private")
	}
	return nil
}

func ensurePrivateCustodyDirectory(root, destination string) error {
	relative, err := filepath.Rel(root, destination)
	if err != nil || relative == "." || relative == ".." ||
		len(relative) >= 3 && relative[:3] == ".."+string(filepath.Separator) {
		return errors.New("migration artifact custody directory escapes its root")
	}
	current := root
	for _, component := range strings.Split(filepath.Clean(relative), string(filepath.Separator)) {
		current = filepath.Join(current, component)
		if err := os.Mkdir(current, 0o700); err != nil && !os.IsExist(err) {
			return err
		}
		if err := rejectUnsafeCustodyDirectory(current); err != nil {
			return err
		}
	}
	return nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("migration custody record contains trailing JSON")
		}
		return err
	}
	return nil
}

func syncCustodyDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	err = directory.Sync()
	return errors.Join(err, directory.Close())
}

type custodyContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *custodyContextReader) Read(value []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(value)
}
