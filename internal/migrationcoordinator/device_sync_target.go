package migrationcoordinator

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

// DeviceSyncStandbyImporter is the exact target database boundary required by
// the headless coordinator. Implementations must preserve the atomic import
// evidence and non-writable standby guarantees of postgres.RelayStore.
type DeviceSyncStandbyImporter interface {
	ImportPreparedDeviceSyncMigrationStandby(
		context.Context,
		uuid.UUID,
		serviceauthority.MigrationPreparation,
		serviceauthority.MigrationSnapshot,
		serviceauthority.TrustAnchor,
		postgres.DeviceSyncInitialAuthorityEvidence,
		int64,
		postgres.DeviceSyncMigrationStagedArtifacts,
	) (postgres.DeviceSyncMigrationImportRecord, error)
}

// DeviceSyncTargetPreparationRequest contains signed authority evidence plus
// transfer streams. BlobSource may be a local store, an authenticated remote
// transfer client, or another bounded implementation; this package does not
// choose a network route or silently fall back between transports.
type DeviceSyncTargetPreparationRequest struct {
	Preparation      serviceauthority.MigrationPreparation
	Snapshot         serviceauthority.MigrationSnapshot
	Anchor           serviceauthority.TrustAnchor
	InitialAuthority postgres.DeviceSyncInitialAuthorityEvidence
	ServiceState     io.Reader
	BlobInventory    io.Reader
	BlobSource       relay.BlobContentStore
	Now              time.Time
}

type DeviceSyncBlobTransferReport struct {
	BlobCount int64
	ByteCount int64
}

type DeviceSyncTargetPreparationResult struct {
	ImportRecord postgres.DeviceSyncMigrationImportRecord
	Readiness    serviceauthority.MigrationReadiness
	Transfer     DeviceSyncBlobTransferReport
}

// DeviceSyncTargetCoordinator stages authenticated artifacts, copies every
// content-addressed encrypted blob, imports exact logical state, and only then
// signs deployment readiness. It does not activate authority or contact Facets
// authority; readiness remains evidence for a separately authorized cutover.
type DeviceSyncTargetCoordinator struct {
	Importer  DeviceSyncStandbyImporter
	Custody   *FileArtifactCustody
	BlobStore relay.BlobContentStore
	Signer    *serviceauthority.DeploymentSigner
}

func (coordinator *DeviceSyncTargetCoordinator) Prepare(
	ctx context.Context,
	request DeviceSyncTargetPreparationRequest,
) (DeviceSyncTargetPreparationResult, error) {
	if coordinator == nil || coordinator.Importer == nil || coordinator.Custody == nil ||
		coordinator.BlobStore == nil || coordinator.Signer == nil || ctx == nil ||
		request.ServiceState == nil || request.BlobInventory == nil || request.BlobSource == nil ||
		request.Now.IsZero() {
		return DeviceSyncTargetPreparationResult{}, serviceauthority.ErrInvalid
	}
	nowMilliseconds := request.Now.UnixMilli()
	validated, err := request.Snapshot.ValidatePreparedTransfer(
		request.Preparation, request.Anchor, nowMilliseconds,
	)
	if err != nil || validated.Snapshot.Scope.Kind != serviceauthority.ScopeDeviceSync ||
		validated.Snapshot.ImportingDeploymentID != coordinator.Signer.DeploymentID() {
		return DeviceSyncTargetPreparationResult{}, serviceauthority.ErrInvalid
	}
	staged, err := coordinator.Custody.stagePreparedDeviceSyncTransfer(
		ctx, validated, request.Preparation, request.Snapshot,
		request.ServiceState, request.BlobInventory,
	)
	if err != nil {
		return DeviceSyncTargetPreparationResult{}, fmt.Errorf(
			"stage Device Sync migration artifacts: %w", err,
		)
	}

	inventory, err := staged.OpenBlobInventory()
	if err != nil {
		return DeviceSyncTargetPreparationResult{}, err
	}
	report, copyErr := CopyDeviceSyncMigrationBlobs(
		ctx,
		inventory,
		validated.Snapshot.Scope.ScopeID,
		staged.BlobInventoryDigest(),
		request.BlobSource,
		coordinator.BlobStore,
	)
	closeErr := inventory.Close()
	if copyErr != nil || closeErr != nil {
		return DeviceSyncTargetPreparationResult{}, errors.Join(copyErr, closeErr)
	}

	artifacts, closeArtifacts, err := staged.OpenArtifacts()
	if err != nil {
		return DeviceSyncTargetPreparationResult{}, err
	}
	imported, importErr := coordinator.Importer.ImportPreparedDeviceSyncMigrationStandby(
		ctx,
		coordinator.Signer.DeploymentID(),
		request.Preparation,
		request.Snapshot,
		request.Anchor,
		request.InitialAuthority,
		nowMilliseconds,
		artifacts,
	)
	closeErr = closeArtifacts()
	if importErr != nil || closeErr != nil {
		return DeviceSyncTargetPreparationResult{}, errors.Join(importErr, closeErr)
	}
	if imported.PrincipalID != validated.Snapshot.Scope.ScopeID ||
		imported.MigrationID != validated.Migration.MigrationID ||
		imported.ImportingDeploymentID != coordinator.Signer.DeploymentID() ||
		imported.StateCommitmentDigest != validated.Snapshot.StateCommitmentDigest {
		return DeviceSyncTargetPreparationResult{}, errors.New(
			"Device Sync migration import record differs from authenticated transfer",
		)
	}
	// The pre-import pass avoids committing a standby that is known to be
	// missing content. Repeat after the database rows become authoritative so
	// orphan maintenance cannot win a filesystem/database commit gap. Put is
	// content-addressed and idempotent, so this also repairs a file removed in
	// that narrow interval and independently revalidates existing bytes.
	inventory, err = staged.OpenBlobInventory()
	if err != nil {
		return DeviceSyncTargetPreparationResult{}, err
	}
	confirmedReport, confirmErr := CopyDeviceSyncMigrationBlobs(
		ctx,
		inventory,
		validated.Snapshot.Scope.ScopeID,
		staged.BlobInventoryDigest(),
		request.BlobSource,
		coordinator.BlobStore,
	)
	closeErr = inventory.Close()
	if confirmErr != nil || closeErr != nil {
		return DeviceSyncTargetPreparationResult{}, errors.Join(confirmErr, closeErr)
	}
	if confirmedReport != report {
		return DeviceSyncTargetPreparationResult{}, errors.New(
			"Device Sync migration post-import blob inventory differs from staged transfer",
		)
	}
	inventory, err = staged.OpenBlobInventory()
	if err != nil {
		return DeviceSyncTargetPreparationResult{}, err
	}
	verifiedReport, verifyErr := VerifyDeviceSyncMigrationBlobs(
		ctx,
		inventory,
		validated.Snapshot.Scope.ScopeID,
		staged.BlobInventoryDigest(),
		coordinator.BlobStore,
	)
	closeErr = inventory.Close()
	if verifyErr != nil || closeErr != nil {
		return DeviceSyncTargetPreparationResult{}, errors.Join(verifyErr, closeErr)
	}
	if verifiedReport != report {
		return DeviceSyncTargetPreparationResult{}, errors.New(
			"Device Sync migration verified blob inventory differs from transferred content",
		)
	}

	if existing, found, err := coordinator.Custody.loadLiveReadiness(
		staged, request.Snapshot, nowMilliseconds,
	); err != nil {
		return DeviceSyncTargetPreparationResult{}, err
	} else if found {
		if existing.Signature.SignerID != coordinator.Signer.DeploymentID() ||
			existing.Signature.PublicSigningKeyX963 != coordinator.Signer.PublicSigningKeyX963() ||
			existing.Signature.SigningKeyFingerprint != coordinator.Signer.SigningKeyFingerprint() {
			return DeviceSyncTargetPreparationResult{}, errors.New(
				"stored migration readiness is not signed by the importing deployment",
			)
		}
		return DeviceSyncTargetPreparationResult{
			ImportRecord: imported,
			Readiness:    existing,
			Transfer:     report,
		}, nil
	}
	snapshotReferenceDigest, err := request.Snapshot.ReferenceDigest()
	if err != nil {
		return DeviceSyncTargetPreparationResult{}, serviceauthority.ErrInvalid
	}
	expiresAt := nowMilliseconds + serviceauthority.MaximumMigrationReadinessLifetime.Milliseconds()
	if expiresAt < nowMilliseconds || expiresAt > validated.Snapshot.ExpiresAtMilliseconds {
		expiresAt = validated.Snapshot.ExpiresAtMilliseconds
	}
	readiness, err := coordinator.Signer.SignMigrationReadiness(
		serviceauthority.MigrationReadinessPayload{
			AppliedStateCommitmentDigest: validated.Snapshot.StateCommitmentDigest,
			AuthorityManifestDigest:      validated.Snapshot.AuthorityManifestDigest,
			ExpiresAtMilliseconds:        expiresAt,
			ImportingDeploymentID:        coordinator.Signer.DeploymentID(),
			MigrationID:                  validated.Migration.MigrationID,
			ReadyAtMilliseconds:          nowMilliseconds,
			Scope:                        validated.Snapshot.Scope,
			SnapshotReferenceDigest:      snapshotReferenceDigest,
			Version:                      serviceauthority.SchemaVersion,
		},
	)
	if err != nil {
		return DeviceSyncTargetPreparationResult{}, err
	}
	readiness, err = coordinator.Custody.storeReadiness(
		staged, request.Snapshot, readiness,
	)
	if err != nil {
		return DeviceSyncTargetPreparationResult{}, err
	}
	return DeviceSyncTargetPreparationResult{
		ImportRecord: imported,
		Readiness:    readiness,
		Transfer:     report,
	}, nil
}

// VerifyDeviceSyncMigrationBlobs independently opens the target's durable
// content and hashes every byte. This keeps readiness from depending only on a
// storage adapter's acknowledgement that Put succeeded.
func VerifyDeviceSyncMigrationBlobs(
	ctx context.Context,
	inventory io.ReadSeeker,
	principalID uuid.UUID,
	inventoryDigest postgres.DeviceSyncMigrationDigest,
	store relay.BlobContentStore,
) (DeviceSyncBlobTransferReport, error) {
	if ctx == nil || inventory == nil || principalID == uuid.Nil || store == nil {
		return DeviceSyncBlobTransferReport{}, serviceauthority.ErrInvalid
	}
	var report DeviceSyncBlobTransferReport
	err := postgres.WalkDeviceSyncMigrationBlobInventory(
		ctx, inventory, principalID, inventoryDigest,
		func(entry postgres.DeviceSyncMigrationBlobInventoryEntry) error {
			content, err := store.Open(ctx, relay.BlobScope{
				TenantID: principalID, DomainID: entry.DomainID,
			}, entry.BlobID)
			if err != nil {
				return fmt.Errorf("open target blob: %w", err)
			}
			if content.ByteCount != entry.ByteCount {
				_ = content.Reader.Close()
				return errors.New("target blob byte count differs from signed inventory")
			}
			hasher := sha256.New()
			limited := &io.LimitedReader{
				R: &coordinatorContextReader{ctx: ctx, reader: content.Reader},
				N: entry.ByteCount + 1,
			}
			written, hashErr := io.Copy(hasher, limited)
			closeErr := content.Reader.Close()
			if hashErr != nil || closeErr != nil {
				return errors.Join(hashErr, closeErr)
			}
			if written != entry.ByteCount ||
				base64.RawURLEncoding.EncodeToString(hasher.Sum(nil)) != entry.BlobID {
				return errors.New("target blob content differs from signed inventory identity")
			}
			if report.BlobCount == math.MaxInt64 || entry.ByteCount > math.MaxInt64-report.ByteCount {
				return errors.New("Device Sync migration verified blob totals overflow")
			}
			report.BlobCount++
			report.ByteCount += entry.ByteCount
			return nil
		},
	)
	if err != nil {
		return DeviceSyncBlobTransferReport{}, err
	}
	return report, nil
}

// CopyDeviceSyncMigrationBlobs walks an already authenticated canonical
// inventory and copies each content-addressed ciphertext blob idempotently.
// BlobContentStore.Put independently verifies byte count and SHA-256 identity,
// including when the destination already has a file with the same name.
func CopyDeviceSyncMigrationBlobs(
	ctx context.Context,
	inventory io.ReadSeeker,
	principalID uuid.UUID,
	inventoryDigest postgres.DeviceSyncMigrationDigest,
	source relay.BlobContentStore,
	destination relay.BlobContentStore,
) (DeviceSyncBlobTransferReport, error) {
	if ctx == nil || inventory == nil || principalID == uuid.Nil || source == nil || destination == nil {
		return DeviceSyncBlobTransferReport{}, serviceauthority.ErrInvalid
	}
	var report DeviceSyncBlobTransferReport
	err := postgres.WalkDeviceSyncMigrationBlobInventory(
		ctx, inventory, principalID, inventoryDigest,
		func(entry postgres.DeviceSyncMigrationBlobInventoryEntry) error {
			content, err := source.Open(ctx, relay.BlobScope{
				TenantID: principalID,
				DomainID: entry.DomainID,
			}, entry.BlobID)
			if err != nil {
				return fmt.Errorf("open source blob: %w", err)
			}
			if content.ByteCount != entry.ByteCount {
				_ = content.Reader.Close()
				return errors.New("source blob byte count differs from signed inventory")
			}
			result, putErr := destination.Put(
				ctx,
				relay.BlobScope{TenantID: principalID, DomainID: entry.DomainID},
				entry.BlobID,
				content.Reader,
				entry.ByteCount,
			)
			closeErr := content.Reader.Close()
			if putErr != nil || closeErr != nil {
				return errors.Join(putErr, closeErr)
			}
			if result.ByteCount != entry.ByteCount {
				return errors.New("destination blob byte count differs from signed inventory")
			}
			if report.BlobCount == math.MaxInt64 {
				return errors.New("Device Sync migration blob transfer totals overflow")
			}
			report.BlobCount++
			if entry.ByteCount > math.MaxInt64-report.ByteCount {
				return errors.New("Device Sync migration blob transfer byte total overflows")
			}
			report.ByteCount += entry.ByteCount
			return nil
		},
	)
	if err != nil {
		return DeviceSyncBlobTransferReport{}, err
	}
	return report, nil
}

func migrationDigest(value string) (postgres.DeviceSyncMigrationDigest, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != value {
		return postgres.DeviceSyncMigrationDigest{}, serviceauthority.ErrInvalid
	}
	var digest postgres.DeviceSyncMigrationDigest
	copy(digest[:], decoded)
	return digest, nil
}

type coordinatorContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *coordinatorContextReader) Read(value []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(value)
}
