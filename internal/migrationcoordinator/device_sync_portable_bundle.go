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
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

const (
	deviceSyncPortableBundleVersion = 1
	deviceSyncPortableBundleFile    = "bundle.json"
	deviceSyncPortableBlobRoot      = "blobs"
)

type DeviceSyncPortableBundleKind string

const (
	DeviceSyncPortableBundleForward  DeviceSyncPortableBundleKind = "forward"
	DeviceSyncPortableBundleRollback DeviceSyncPortableBundleKind = "rollback"
)

// DeviceSyncPortableBundleMetadata is the small, transport-neutral index for
// an attended Device Sync move. It is not authority: every field is checked
// against the signed preparation/activation and deployment-signed snapshot,
// and every artifact/blob byte is hashed again before use.
type DeviceSyncPortableBundleMetadata struct {
	ActivationEvidence *serviceauthority.MigrationActivationEvidence `json:"activationEvidence,omitempty"`
	Anchor             serviceauthority.TrustAnchor                  `json:"anchor"`
	BlobByteCount      int64                                         `json:"blobByteCount"`
	BlobCount          int64                                         `json:"blobCount"`
	InitialAuthority   *postgres.DeviceSyncInitialAuthorityEvidence  `json:"initialAuthority,omitempty"`
	Kind               DeviceSyncPortableBundleKind                  `json:"kind"`
	MigrationID        uuid.UUID                                     `json:"migrationID"`
	Preparation        *serviceauthority.MigrationPreparation        `json:"preparation,omitempty"`
	PrincipalID        uuid.UUID                                     `json:"principalID"`
	Snapshot           serviceauthority.MigrationSnapshot            `json:"snapshot"`
	SnapshotID         uuid.UUID                                     `json:"snapshotID"`
	Version            int                                           `json:"version"`
}

// WriteDeviceSyncForwardBundle copies exact protected source artifacts and
// content-addressed ciphertext blobs into a new atomic directory. The output
// path must not exist. Moving that directory is an operator transport action;
// it does not itself grant target authority.
func WriteDeviceSyncForwardBundle(
	ctx context.Context,
	outputDirectory string,
	preparation serviceauthority.MigrationPreparation,
	snapshot serviceauthority.MigrationSnapshot,
	anchor serviceauthority.TrustAnchor,
	initial postgres.DeviceSyncInitialAuthorityEvidence,
	transfer PreparedDeviceSyncTransfer,
	blobSource relay.BlobContentStore,
	now time.Time,
) (DeviceSyncPortableBundleMetadata, error) {
	if ctx == nil || now.IsZero() || blobSource == nil {
		return DeviceSyncPortableBundleMetadata{}, serviceauthority.ErrInvalid
	}
	validated, err := snapshot.ValidatePreparedTransfer(
		preparation, anchor, now.UnixMilli(),
	)
	if err != nil {
		return DeviceSyncPortableBundleMetadata{}, err
	}
	if err := validateDeviceSyncInitialAuthority(
		initial, anchor, validated.Snapshot.Scope,
	); err != nil {
		return DeviceSyncPortableBundleMetadata{}, err
	}
	metadata := DeviceSyncPortableBundleMetadata{
		Anchor:           anchor,
		InitialAuthority: &initial,
		Kind:             DeviceSyncPortableBundleForward,
		MigrationID:      validated.Migration.MigrationID,
		Preparation:      &preparation,
		PrincipalID:      validated.Snapshot.Scope.ScopeID,
		Snapshot:         snapshot,
		SnapshotID:       validated.Snapshot.SnapshotID,
		Version:          deviceSyncPortableBundleVersion,
	}
	return writeDeviceSyncPortableBundle(
		ctx, outputDirectory, metadata, validated.Snapshot,
		transfer, blobSource, now,
	)
}

// WriteDeviceSyncRollbackBundle is the reverse-transfer counterpart. The
// active replacement must already have produced the journaled rollback source
// handoff; the old source remains non-writable until separate authority-signed
// rollback evidence is applied on both deployments.
func WriteDeviceSyncRollbackBundle(
	ctx context.Context,
	outputDirectory string,
	activation serviceauthority.MigrationActivationEvidence,
	snapshot serviceauthority.MigrationSnapshot,
	anchor serviceauthority.TrustAnchor,
	transfer PreparedDeviceSyncTransfer,
	blobSource relay.BlobContentStore,
	now time.Time,
) (DeviceSyncPortableBundleMetadata, error) {
	if ctx == nil || now.IsZero() || blobSource == nil {
		return DeviceSyncPortableBundleMetadata{}, serviceauthority.ErrInvalid
	}
	validated, err := snapshot.ValidateRollbackTransfer(
		activation, anchor, now.UnixMilli(),
	)
	if err != nil {
		return DeviceSyncPortableBundleMetadata{}, err
	}
	metadata := DeviceSyncPortableBundleMetadata{
		ActivationEvidence: &activation,
		Anchor:             anchor,
		Kind:               DeviceSyncPortableBundleRollback,
		MigrationID:        validated.Migration.MigrationID,
		PrincipalID:        validated.Snapshot.Scope.ScopeID,
		Snapshot:           snapshot,
		SnapshotID:         validated.Snapshot.SnapshotID,
		Version:            deviceSyncPortableBundleVersion,
	}
	return writeDeviceSyncPortableBundle(
		ctx, outputDirectory, metadata, validated.Snapshot,
		transfer, blobSource, now,
	)
}

func writeDeviceSyncPortableBundle(
	ctx context.Context,
	outputDirectory string,
	metadata DeviceSyncPortableBundleMetadata,
	snapshot serviceauthority.MigrationSnapshotPayload,
	transfer PreparedDeviceSyncTransfer,
	blobSource relay.BlobContentStore,
	now time.Time,
) (DeviceSyncPortableBundleMetadata, error) {
	if outputDirectory == "" || !filepath.IsAbs(outputDirectory) {
		return DeviceSyncPortableBundleMetadata{}, errors.New(
			"Device Sync migration bundle path must be absolute",
		)
	}
	outputDirectory = filepath.Clean(outputDirectory)
	if _, err := os.Lstat(outputDirectory); err == nil {
		existing, _, _, _, closeBundle, openErr := openDeviceSyncPortableBundle(
			ctx, outputDirectory, now,
		)
		if openErr != nil {
			return DeviceSyncPortableBundleMetadata{}, errors.New(
				"existing Device Sync migration bundle is invalid",
			)
		}
		closeErr := closeBundle()
		metadata.BlobCount = existing.BlobCount
		metadata.BlobByteCount = existing.BlobByteCount
		existingRecord, existingErr := json.Marshal(existing)
		expectedRecord, expectedErr := json.Marshal(metadata)
		if closeErr != nil || existingErr != nil || expectedErr != nil ||
			!bytes.Equal(existingRecord, expectedRecord) {
			return DeviceSyncPortableBundleMetadata{}, errors.New(
				"existing Device Sync migration bundle conflicts with request",
			)
		}
		return existing, nil
	} else if !os.IsNotExist(err) {
		return DeviceSyncPortableBundleMetadata{}, err
	}
	parent := filepath.Dir(outputDirectory)
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return DeviceSyncPortableBundleMetadata{}, errors.New(
			"Device Sync migration bundle parent is not a safe directory",
		)
	}
	staging, err := os.MkdirTemp(parent, ".facets-device-sync-bundle-*")
	if err != nil {
		return DeviceSyncPortableBundleMetadata{}, err
	}
	defer func() { _ = os.RemoveAll(staging) }()
	if err := os.Chmod(staging, 0o700); err != nil {
		return DeviceSyncPortableBundleMetadata{}, err
	}

	stateDescriptor, inventoryDescriptor, err := migrationArtifactDescriptors(snapshot)
	if err != nil {
		return DeviceSyncPortableBundleMetadata{}, err
	}
	artifacts, closeArtifacts, err := transfer.OpenArtifacts()
	if err != nil {
		return DeviceSyncPortableBundleMetadata{}, err
	}
	stateErr := stageExactArtifact(
		ctx, filepath.Join(staging, serviceStateFileName),
		artifacts.ServiceState, stateDescriptor,
	)
	inventoryErr := stageExactArtifact(
		ctx, filepath.Join(staging, blobInventoryFileName),
		artifacts.BlobInventory, inventoryDescriptor,
	)
	closeErr := closeArtifacts()
	if stateErr != nil || inventoryErr != nil || closeErr != nil {
		return DeviceSyncPortableBundleMetadata{}, errors.Join(
			stateErr, inventoryErr, closeErr,
		)
	}

	bundleBlobRoot := filepath.Join(staging, deviceSyncPortableBlobRoot)
	bundleBlobs, err := relay.NewFileBlobContentStore(bundleBlobRoot)
	if err != nil {
		return DeviceSyncPortableBundleMetadata{}, err
	}
	inventory, err := os.Open(filepath.Join(staging, blobInventoryFileName))
	if err != nil {
		return DeviceSyncPortableBundleMetadata{}, err
	}
	report, copyErr := CopyDeviceSyncMigrationBlobs(
		ctx, inventory, snapshot.Scope.ScopeID, transfer.BlobInventoryDigest(),
		blobSource, bundleBlobs,
	)
	closeErr = inventory.Close()
	if copyErr != nil || closeErr != nil {
		return DeviceSyncPortableBundleMetadata{}, errors.Join(copyErr, closeErr)
	}
	inventory, err = os.Open(filepath.Join(staging, blobInventoryFileName))
	if err != nil {
		return DeviceSyncPortableBundleMetadata{}, err
	}
	verified, verifyErr := VerifyDeviceSyncMigrationBlobs(
		ctx, inventory, snapshot.Scope.ScopeID, transfer.BlobInventoryDigest(),
		bundleBlobs,
	)
	closeErr = inventory.Close()
	if verifyErr != nil || closeErr != nil {
		return DeviceSyncPortableBundleMetadata{}, errors.Join(verifyErr, closeErr)
	}
	if verified != report {
		return DeviceSyncPortableBundleMetadata{}, errors.New(
			"Device Sync migration bundle blob verification changed totals",
		)
	}
	metadata.BlobCount = report.BlobCount
	metadata.BlobByteCount = report.ByteCount
	encoded, err := json.Marshal(metadata)
	if err != nil || len(encoded) == 0 || len(encoded) > maximumEvidenceByteCount {
		return DeviceSyncPortableBundleMetadata{}, serviceauthority.ErrInvalid
	}
	if err := writeSyncedProtectedFile(
		filepath.Join(staging, deviceSyncPortableBundleFile), encoded,
	); err != nil {
		return DeviceSyncPortableBundleMetadata{}, err
	}
	_ = os.Remove(filepath.Join(bundleBlobRoot, ".staging"))
	if err := syncCustodyDirectory(bundleBlobRoot); err != nil {
		return DeviceSyncPortableBundleMetadata{}, err
	}
	if err := syncCustodyDirectory(staging); err != nil {
		return DeviceSyncPortableBundleMetadata{}, err
	}
	if err := os.Rename(staging, outputDirectory); err != nil {
		return DeviceSyncPortableBundleMetadata{}, fmt.Errorf(
			"commit Device Sync migration bundle: %w", err,
		)
	}
	if err := syncCustodyDirectory(parent); err != nil {
		return DeviceSyncPortableBundleMetadata{}, err
	}
	return metadata, nil
}

// OpenDeviceSyncForwardBundle revalidates an attended transfer and returns
// the exact target-coordinator request plus a bounded close function. It never
// creates files or mutates the received bundle.
func OpenDeviceSyncForwardBundle(
	ctx context.Context,
	directory string,
	now time.Time,
) (
	DeviceSyncTargetPreparationRequest,
	DeviceSyncPortableBundleMetadata,
	func() error,
	error,
) {
	metadata, state, inventory, blobs, closeBundle, err :=
		openDeviceSyncPortableBundle(ctx, directory, now)
	if err != nil {
		return DeviceSyncTargetPreparationRequest{},
			DeviceSyncPortableBundleMetadata{}, nil, err
	}
	if metadata.Kind != DeviceSyncPortableBundleForward ||
		metadata.Preparation == nil || metadata.InitialAuthority == nil ||
		metadata.ActivationEvidence != nil {
		_ = closeBundle()
		return DeviceSyncTargetPreparationRequest{},
			DeviceSyncPortableBundleMetadata{}, nil, serviceauthority.ErrInvalid
	}
	request := DeviceSyncTargetPreparationRequest{
		Preparation:      *metadata.Preparation,
		Snapshot:         metadata.Snapshot,
		Anchor:           metadata.Anchor,
		InitialAuthority: *metadata.InitialAuthority,
		ServiceState:     state,
		BlobInventory:    inventory,
		BlobSource:       blobs,
		Now:              now,
	}
	return request, metadata, closeBundle, nil
}

// OpenDeviceSyncRollbackBundle is the exact reverse-transfer reader used by
// the retired source while it is being prepared as rollback standby.
func OpenDeviceSyncRollbackBundle(
	ctx context.Context,
	directory string,
	now time.Time,
) (
	DeviceSyncRollbackTargetPreparationRequest,
	DeviceSyncPortableBundleMetadata,
	func() error,
	error,
) {
	metadata, state, inventory, blobs, closeBundle, err :=
		openDeviceSyncPortableBundle(ctx, directory, now)
	if err != nil {
		return DeviceSyncRollbackTargetPreparationRequest{},
			DeviceSyncPortableBundleMetadata{}, nil, err
	}
	if metadata.Kind != DeviceSyncPortableBundleRollback ||
		metadata.ActivationEvidence == nil || metadata.Preparation != nil ||
		metadata.InitialAuthority != nil {
		_ = closeBundle()
		return DeviceSyncRollbackTargetPreparationRequest{},
			DeviceSyncPortableBundleMetadata{}, nil, serviceauthority.ErrInvalid
	}
	request := DeviceSyncRollbackTargetPreparationRequest{
		ActivationEvidence: *metadata.ActivationEvidence,
		Snapshot:           metadata.Snapshot,
		Anchor:             metadata.Anchor,
		ServiceState:       state,
		BlobInventory:      inventory,
		BlobSource:         blobs,
		Now:                now,
	}
	return request, metadata, closeBundle, nil
}

func openDeviceSyncPortableBundle(
	ctx context.Context,
	directory string,
	now time.Time,
) (
	DeviceSyncPortableBundleMetadata,
	*os.File,
	*os.File,
	relay.BlobContentStore,
	func() error,
	error,
) {
	empty := func() (DeviceSyncPortableBundleMetadata, *os.File, *os.File, relay.BlobContentStore, func() error, error) {
		return DeviceSyncPortableBundleMetadata{}, nil, nil, nil, nil,
			serviceauthority.ErrInvalid
	}
	if ctx == nil || directory == "" || !filepath.IsAbs(directory) || now.IsZero() {
		return empty()
	}
	directory = filepath.Clean(directory)
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 {
		return empty()
	}
	if err := rejectPortableBundleSymlinks(ctx, directory); err != nil {
		return DeviceSyncPortableBundleMetadata{}, nil, nil, nil, nil, err
	}
	encoded, err := readProtectedRecord(
		filepath.Join(directory, deviceSyncPortableBundleFile),
		maximumEvidenceByteCount,
	)
	if err != nil {
		return DeviceSyncPortableBundleMetadata{}, nil, nil, nil, nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var metadata DeviceSyncPortableBundleMetadata
	if err := decoder.Decode(&metadata); err != nil || ensureJSONEOF(decoder) != nil {
		return empty()
	}
	canonical, err := json.Marshal(metadata)
	if err != nil || !bytes.Equal(canonical, encoded) ||
		metadata.Version != deviceSyncPortableBundleVersion ||
		metadata.PrincipalID == uuid.Nil || metadata.MigrationID == uuid.Nil ||
		metadata.SnapshotID == uuid.Nil || metadata.BlobCount < 0 ||
		metadata.BlobByteCount < 0 {
		return empty()
	}
	var snapshot serviceauthority.MigrationSnapshotPayload
	switch metadata.Kind {
	case DeviceSyncPortableBundleForward:
		if metadata.Preparation == nil || metadata.InitialAuthority == nil ||
			metadata.ActivationEvidence != nil {
			return empty()
		}
		validated, err := metadata.Snapshot.ValidatePreparedTransfer(
			*metadata.Preparation, metadata.Anchor, now.UnixMilli(),
		)
		if err != nil || validateDeviceSyncInitialAuthority(
			*metadata.InitialAuthority, metadata.Anchor, validated.Snapshot.Scope,
		) != nil {
			return empty()
		}
		snapshot = validated.Snapshot
	case DeviceSyncPortableBundleRollback:
		if metadata.ActivationEvidence == nil || metadata.Preparation != nil ||
			metadata.InitialAuthority != nil {
			return empty()
		}
		validated, err := metadata.Snapshot.ValidateRollbackTransfer(
			*metadata.ActivationEvidence, metadata.Anchor, now.UnixMilli(),
		)
		if err != nil {
			return empty()
		}
		snapshot = validated.Snapshot
	default:
		return empty()
	}
	if metadata.PrincipalID != snapshot.Scope.ScopeID ||
		metadata.MigrationID != snapshot.MigrationID ||
		metadata.SnapshotID != snapshot.SnapshotID {
		return empty()
	}
	stateDescriptor, inventoryDescriptor, err := migrationArtifactDescriptors(snapshot)
	if err != nil {
		return empty()
	}
	state, err := openProtectedArtifact(
		filepath.Join(directory, serviceStateFileName), stateDescriptor,
	)
	if err != nil {
		return DeviceSyncPortableBundleMetadata{}, nil, nil, nil, nil, err
	}
	inventory, err := openProtectedArtifact(
		filepath.Join(directory, blobInventoryFileName), inventoryDescriptor,
	)
	if err != nil {
		_ = state.Close()
		return DeviceSyncPortableBundleMetadata{}, nil, nil, nil, nil, err
	}
	blobs := &deviceSyncPortableBundleBlobStore{
		root: filepath.Join(directory, deviceSyncPortableBlobRoot),
	}
	inventoryDigest, err := migrationDigest(inventoryDescriptor.TransferDigest)
	if err != nil {
		_ = state.Close()
		_ = inventory.Close()
		return DeviceSyncPortableBundleMetadata{}, nil, nil, nil, nil, err
	}
	verified, err := VerifyDeviceSyncMigrationBlobs(
		ctx, inventory, snapshot.Scope.ScopeID,
		inventoryDigest,
		blobs,
	)
	if err != nil || verified.BlobCount != metadata.BlobCount ||
		verified.ByteCount != metadata.BlobByteCount {
		_ = state.Close()
		_ = inventory.Close()
		if err == nil {
			err = errors.New("Device Sync migration bundle blob totals conflict")
		}
		return DeviceSyncPortableBundleMetadata{}, nil, nil, nil, nil, err
	}
	if _, err := inventory.Seek(0, io.SeekStart); err != nil {
		_ = state.Close()
		_ = inventory.Close()
		return DeviceSyncPortableBundleMetadata{}, nil, nil, nil, nil, err
	}
	closeBundle := func() error { return errors.Join(state.Close(), inventory.Close()) }
	return metadata, state, inventory, blobs, closeBundle, nil
}

func validateDeviceSyncInitialAuthority(
	initial postgres.DeviceSyncInitialAuthorityEvidence,
	anchor serviceauthority.TrustAnchor,
	scope serviceauthority.Scope,
) error {
	payload, err := initial.Manifest.Authorize(
		anchor, initial.ValidatedAtMilliseconds,
	)
	if err != nil || payload.Scope != scope || payload.Revision != 1 ||
		payload.Transition != serviceauthority.TransitionInitialActivation {
		return serviceauthority.ErrInvalid
	}
	return nil
}

func rejectPortableBundleSymlinks(ctx context.Context, root string) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("Device Sync migration bundle contains a symbolic link")
		}
		return nil
	})
}

type deviceSyncPortableBundleBlobStore struct{ root string }

func (*deviceSyncPortableBundleBlobStore) Put(
	context.Context,
	relay.BlobScope,
	string,
	io.Reader,
	int64,
) (relay.BlobContentResult, error) {
	return relay.BlobContentResult{}, errors.New(
		"received Device Sync migration bundle is read-only",
	)
}

func (store *deviceSyncPortableBundleBlobStore) Open(
	ctx context.Context,
	scope relay.BlobScope,
	blobID string,
) (relay.BlobContent, error) {
	if store == nil || ctx == nil || scope.TenantID == uuid.Nil ||
		scope.DomainID == uuid.Nil || relay.ValidateBlobID(blobID) != nil {
		return relay.BlobContent{}, serviceauthority.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return relay.BlobContent{}, err
	}
	path := filepath.Join(
		store.root, scope.TenantID.String(), scope.DomainID.String(), blobID,
	)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() < 0 || info.Size() > relay.MaximumBlobByteCount {
		return relay.BlobContent{}, errors.New(
			"Device Sync migration bundle blob has invalid metadata",
		)
	}
	file, err := os.Open(path)
	if err != nil {
		return relay.BlobContent{}, err
	}
	return relay.BlobContent{Reader: file, ByteCount: info.Size()}, nil
}
