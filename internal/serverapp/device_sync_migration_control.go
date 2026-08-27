package serverapp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/robreuss/FacetsNode/internal/config"
	"github.com/robreuss/FacetsNode/internal/migrationcoordinator"
	"github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

const deviceSyncMigrationControlVersion = 1

type deviceSyncMigrationSourceRequest struct {
	Anchor                  serviceauthority.TrustAnchor          `json:"anchor"`
	BlobInventoryArtifactID uuid.UUID                             `json:"blobInventoryArtifactID"`
	ExportWriteFenceID      uuid.UUID                             `json:"exportWriteFenceID"`
	Preparation             serviceauthority.MigrationPreparation `json:"preparation"`
	ServiceStateArtifactID  uuid.UUID                             `json:"serviceStateArtifactID"`
	SnapshotID              uuid.UUID                             `json:"snapshotID"`
	Version                 int                                   `json:"version"`
}

type deviceSyncMigrationTargetOfferRequest struct {
	CustodyAgreementKeyFingerprint string                 `json:"custodyAgreementKeyFingerprint"`
	CustodyAgreementPublicKeyX963  string                 `json:"custodyAgreementPublicKeyX963"`
	ExpiresAtMilliseconds          int64                  `json:"expiresAtMilliseconds"`
	MigrationID                    uuid.UUID              `json:"migrationID"`
	Scope                          serviceauthority.Scope `json:"scope"`
	SourceManifestDigest           string                 `json:"sourceManifestDigest"`
	Version                        int                    `json:"version"`
}

type deviceSyncMigrationRollbackSourceRequest struct {
	ActivationEvidence      serviceauthority.MigrationActivationEvidence `json:"activationEvidence"`
	Anchor                  serviceauthority.TrustAnchor                 `json:"anchor"`
	BlobInventoryArtifactID uuid.UUID                                    `json:"blobInventoryArtifactID"`
	ExportWriteFenceID      uuid.UUID                                    `json:"exportWriteFenceID"`
	ServiceStateArtifactID  uuid.UUID                                    `json:"serviceStateArtifactID"`
	SnapshotID              uuid.UUID                                    `json:"snapshotID"`
	Version                 int                                          `json:"version"`
}

type deviceSyncMigrationActivationRequest struct {
	Anchor   serviceauthority.TrustAnchor                 `json:"anchor"`
	Evidence serviceauthority.MigrationActivationEvidence `json:"evidence"`
	Version  int                                          `json:"version"`
}

type deviceSyncMigrationRollbackRequest struct {
	Anchor   serviceauthority.TrustAnchor               `json:"anchor"`
	Evidence serviceauthority.MigrationRollbackEvidence `json:"evidence"`
	Version  int                                        `json:"version"`
}

type deviceSyncMigrationRollbackSettlementRequest struct {
	Anchor          serviceauthority.TrustAnchor `json:"anchor"`
	CurrentManifest serviceauthority.Manifest    `json:"currentManifest"`
	Successor       serviceauthority.Manifest    `json:"successor"`
	Version         int                          `json:"version"`
}

type deviceSyncMigrationControlResponse struct {
	Action            string                                                 `json:"action"`
	AuthorityDigest   string                                                 `json:"authorityDigest,omitempty"`
	AuthorityRevision uint64                                                 `json:"authorityRevision,omitempty"`
	BlobByteCount     int64                                                  `json:"blobByteCount,omitempty"`
	BlobCount         int64                                                  `json:"blobCount,omitempty"`
	Bundle            *migrationcoordinator.DeviceSyncPortableBundleMetadata `json:"bundle,omitempty"`
	DeploymentID      uuid.UUID                                              `json:"deploymentID"`
	MigrationID       *uuid.UUID                                             `json:"migrationID,omitempty"`
	PrincipalID       *uuid.UUID                                             `json:"principalID,omitempty"`
	Readiness         *serviceauthority.MigrationReadiness                   `json:"readiness,omitempty"`
	Snapshot          *serviceauthority.MigrationSnapshot                    `json:"snapshot,omitempty"`
	State             postgres.DeviceSyncScopeEnforcementState               `json:"state,omitempty"`
	TargetOffer       *serviceauthority.MigrationTargetOffer                 `json:"targetOffer,omitempty"`
	Version           int                                                    `json:"version"`
	WriteFenced       bool                                                   `json:"writeFenced"`
}

type deviceSyncMigrationControlRuntime struct {
	configuration config.Config
	pool          *pgxpool.Pool
	store         *postgres.RelayStore
	blobs         relay.BlobContentStore
	custody       *migrationcoordinator.FileArtifactCustody
	bindings      *serviceauthority.BindingRegistry
	signer        *serviceauthority.DeploymentSigner
}

// runDeviceSyncMigrationControl is an offline, OS-access-controlled operator
// surface. It opens no listener and requires exclusive access to the binding
// registry, so the data-plane process must be stopped for every stage.
func runDeviceSyncMigrationControl(
	ctx context.Context,
	service config.Service,
	arguments []string,
	output io.Writer,
	now func() time.Time,
) error {
	if ctx == nil || service != config.DeviceSync || output == nil || now == nil ||
		len(arguments) == 0 {
		return deviceSyncMigrationUsageError()
	}
	action := arguments[0]
	expectedArgumentCount := map[string]int{
		"target-offer":            2,
		"source-prepare":          3,
		"target-prepare":          2,
		"activate":                2,
		"rollback-source-prepare": 3,
		"rollback-target-prepare": 2,
		"rollback-apply":          2,
		"rollback-settle":         2,
	}
	if expectedArgumentCount[action] == 0 ||
		len(arguments) != expectedArgumentCount[action] {
		return deviceSyncMigrationUsageError()
	}
	runtime, err := openDeviceSyncMigrationControlRuntime(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = runtime.close() }()
	instant := now()
	if instant.IsZero() || instant.UnixMilli() < 0 {
		return serviceauthority.ErrInvalid
	}

	var response deviceSyncMigrationControlResponse
	switch action {
	case "target-offer":
		var request deviceSyncMigrationTargetOfferRequest
		if err := readPrivateControlJSON(arguments[1], &request); err != nil {
			return fmt.Errorf("read target-offer request: %w", err)
		}
		response, err = runtime.issueTargetOffer(request, instant)
	case "source-prepare":
		var request deviceSyncMigrationSourceRequest
		if err := readPrivateControlJSON(arguments[1], &request); err != nil {
			return fmt.Errorf("read source preparation request: %w", err)
		}
		response, err = runtime.prepareSource(
			ctx, request, arguments[2], instant,
		)
	case "target-prepare":
		response, err = runtime.prepareTarget(ctx, arguments[1], instant)
	case "activate":
		var request deviceSyncMigrationActivationRequest
		if err := readPrivateControlJSON(arguments[1], &request); err != nil {
			return fmt.Errorf("read activation request: %w", err)
		}
		response, err = runtime.activate(ctx, request, instant)
	case "rollback-source-prepare":
		var request deviceSyncMigrationRollbackSourceRequest
		if err := readPrivateControlJSON(arguments[1], &request); err != nil {
			return fmt.Errorf("read rollback source request: %w", err)
		}
		response, err = runtime.prepareRollbackSource(
			ctx, request, arguments[2], instant,
		)
	case "rollback-target-prepare":
		response, err = runtime.prepareRollbackTarget(
			ctx, arguments[1], instant,
		)
	case "rollback-apply":
		var request deviceSyncMigrationRollbackRequest
		if err := readPrivateControlJSON(arguments[1], &request); err != nil {
			return fmt.Errorf("read rollback request: %w", err)
		}
		response, err = runtime.rollback(ctx, request, instant)
	case "rollback-settle":
		var request deviceSyncMigrationRollbackSettlementRequest
		if err := readPrivateControlJSON(arguments[1], &request); err != nil {
			return fmt.Errorf("read rollback settlement request: %w", err)
		}
		response, err = runtime.settleRollback(ctx, request, instant)
	}
	if err != nil {
		return fmt.Errorf("%s: %w", action, err)
	}
	return writeDeviceSyncMigrationControlResponse(output, response)
}

func (runtime *deviceSyncMigrationControlRuntime) issueTargetOffer(
	control deviceSyncMigrationTargetOfferRequest,
	now time.Time,
) (deviceSyncMigrationControlResponse, error) {
	if control.Version != deviceSyncMigrationControlVersion ||
		control.Scope.Kind != serviceauthority.ScopeDeviceSync ||
		control.ExpiresAtMilliseconds <= now.UnixMilli() {
		return deviceSyncMigrationControlResponse{}, serviceauthority.ErrInvalid
	}
	template, err := serviceauthority.LoadDeploymentOfferTemplate(
		runtime.configuration.DeploymentRoutePolicyFile, runtime.signer,
	)
	if err != nil {
		return deviceSyncMigrationControlResponse{}, err
	}
	expiresAt := time.UnixMilli(control.ExpiresAtMilliseconds)
	deploymentOffer, err := template.SignOffer(runtime.signer, now, expiresAt)
	if err != nil {
		return deviceSyncMigrationControlResponse{}, err
	}
	targetOffer, err := runtime.signer.SignMigrationTargetOffer(
		serviceauthority.MigrationTargetOfferPayload{
			CustodyAgreementKeyFingerprint: control.CustodyAgreementKeyFingerprint,
			CustodyAgreementPublicKeyX963:  control.CustodyAgreementPublicKeyX963,
			DeploymentOffer:                deploymentOffer,
			ExpiresAtMilliseconds:          control.ExpiresAtMilliseconds,
			IssuedAtMilliseconds:           now.UnixMilli(),
			MigrationID:                    control.MigrationID,
			Scope:                          control.Scope,
			SourceManifestDigest:           control.SourceManifestDigest,
			Version:                        serviceauthority.SchemaVersion,
		},
	)
	if err != nil {
		return deviceSyncMigrationControlResponse{}, err
	}
	return deviceSyncMigrationControlResponse{
		Action:       "target-offer",
		DeploymentID: runtime.signer.DeploymentID(),
		MigrationID:  optionalControlUUID(control.MigrationID),
		PrincipalID:  optionalControlUUID(control.Scope.ScopeID),
		TargetOffer:  &targetOffer,
		Version:      deviceSyncMigrationControlVersion,
	}, nil
}

func openDeviceSyncMigrationControlRuntime(
	ctx context.Context,
) (*deviceSyncMigrationControlRuntime, error) {
	configuration, err := config.Load(config.DeviceSync)
	if err != nil {
		return nil, fmt.Errorf("configuration rejected: %w", err)
	}
	poolConfiguration, err := pgxpool.ParseConfig(configuration.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("database URL rejected: %w", err)
	}
	poolConfiguration.MaxConns = configuration.DatabaseConns
	poolConfiguration.MinConns = 1
	poolConfiguration.MaxConnLifetime = time.Hour
	poolConfiguration.MaxConnIdleTime = 15 * time.Minute
	pool, err := pgxpool.NewWithConfig(ctx, poolConfiguration)
	if err != nil {
		return nil, fmt.Errorf("database pool failed: %w", err)
	}
	failed := true
	defer func() {
		if failed {
			pool.Close()
		}
	}()
	startupContext, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := pool.Ping(startupContext); err != nil {
		return nil, fmt.Errorf("database unavailable: %w", err)
	}
	if err := postgres.Migrate(startupContext, pool); err != nil {
		return nil, fmt.Errorf("database migration failed: %w", err)
	}
	store, err := postgres.NewDeviceSyncAuthorityBoundRelayStore(
		pool,
		configuration.DeploymentID,
		configuration.BlobUploadTTL,
		configuration.CheckpointFenceTTL,
	)
	if err != nil {
		return nil, fmt.Errorf("authority-bound store rejected: %w", err)
	}
	blobs, err := relay.NewFileBlobContentStore(configuration.BlobRoot)
	if err != nil {
		return nil, fmt.Errorf("blob store rejected: %w", err)
	}
	signer, err := serviceauthority.LoadDeploymentSigner(
		configuration.DeploymentID,
		configuration.DeploymentSigningKeyFile,
	)
	if err != nil {
		return nil, fmt.Errorf("deployment signing custody rejected: %w", err)
	}
	if _, err := serviceauthority.LoadDeploymentOfferTemplate(
		configuration.DeploymentRoutePolicyFile, signer,
	); err != nil {
		return nil, fmt.Errorf("deployment route policy rejected: %w", err)
	}
	bindings, err := serviceauthority.LoadBindingRegistry(
		configuration.ServiceAuthorityBindingsFile,
		configuration.DeploymentID,
	)
	if err != nil {
		return nil, fmt.Errorf("service authority bindings rejected: %w", err)
	}
	authorityDirectory, err := filepath.Abs(filepath.Dir(
		configuration.ServiceAuthorityBindingsFile,
	))
	if err != nil {
		_ = bindings.Close()
		return nil, fmt.Errorf("migration custody path rejected: %w", err)
	}
	custody, err := migrationcoordinator.NewFileArtifactCustody(
		filepath.Join(authorityDirectory, "migration-custody"),
	)
	if err != nil {
		_ = bindings.Close()
		return nil, fmt.Errorf("migration custody rejected: %w", err)
	}
	failed = false
	return &deviceSyncMigrationControlRuntime{
		configuration: configuration,
		pool:          pool,
		store:         store,
		blobs:         blobs,
		custody:       custody,
		bindings:      bindings,
		signer:        signer,
	}, nil
}

func (runtime *deviceSyncMigrationControlRuntime) close() error {
	if runtime == nil {
		return nil
	}
	var err error
	if runtime.bindings != nil {
		err = runtime.bindings.Close()
	}
	if runtime.pool != nil {
		runtime.pool.Close()
	}
	return err
}

func (runtime *deviceSyncMigrationControlRuntime) prepareSource(
	ctx context.Context,
	control deviceSyncMigrationSourceRequest,
	bundleDirectory string,
	now time.Time,
) (deviceSyncMigrationControlResponse, error) {
	if control.Version != deviceSyncMigrationControlVersion {
		return deviceSyncMigrationControlResponse{}, serviceauthority.ErrInvalid
	}
	prepared, _, err := control.Preparation.Validate(
		control.Anchor, now.UnixMilli(),
	)
	if err != nil || prepared.SourceDeploymentID != runtime.signer.DeploymentID() {
		return deviceSyncMigrationControlResponse{}, serviceauthority.ErrInvalid
	}
	preparedManifest, err := control.Preparation.PreparationManifest.VerifiedPayload()
	if err != nil {
		return deviceSyncMigrationControlResponse{}, err
	}
	preparationDigest, err := control.Preparation.ReferenceDigest()
	if err != nil {
		return deviceSyncMigrationControlResponse{}, err
	}
	// Registry first and PostgreSQL second is intentionally fail-closed. An
	// interrupted command leaves the data plane unready; an exact retry repairs
	// the database from the same signed preparation.
	if err := runtime.bindings.ApplyMigrationPreparation(
		control.Preparation, control.Anchor, now.UnixMilli(),
	); err != nil {
		return deviceSyncMigrationControlResponse{}, err
	}
	if err := runtime.store.AdvanceDeviceSyncWritableAuthority(
		ctx,
		preparedManifest.Scope.ScopeID,
		runtime.signer.DeploymentID(),
		control.Preparation.PreparationManifest,
		&preparationDigest,
		now.UnixMilli(),
	); err != nil {
		return deviceSyncMigrationControlResponse{}, err
	}
	state, err := runtime.store.GetDeviceSyncScopeEnforcement(
		ctx, preparedManifest.Scope.ScopeID,
	)
	if err != nil {
		return deviceSyncMigrationControlResponse{}, err
	}
	initial, err := initialDeviceSyncAuthorityFromState(state)
	if err != nil {
		return deviceSyncMigrationControlResponse{}, err
	}
	coordinator := migrationcoordinator.DeviceSyncSourceCoordinator{
		Exporter: runtime.store,
		Custody:  runtime.custody,
		Bindings: runtime.bindings,
		Signer:   runtime.signer,
	}
	result, err := coordinator.Prepare(
		ctx,
		migrationcoordinator.DeviceSyncSourcePreparationRequest{
			Preparation:             control.Preparation,
			Anchor:                  control.Anchor,
			ExportWriteFenceID:      control.ExportWriteFenceID,
			SnapshotID:              control.SnapshotID,
			ServiceStateArtifactID:  control.ServiceStateArtifactID,
			BlobInventoryArtifactID: control.BlobInventoryArtifactID,
			Now:                     now,
		},
	)
	if err != nil {
		return deviceSyncMigrationControlResponse{}, err
	}
	bundlePath, err := filepath.Abs(bundleDirectory)
	if err != nil {
		return deviceSyncMigrationControlResponse{}, err
	}
	bundle, err := migrationcoordinator.WriteDeviceSyncForwardBundle(
		ctx,
		bundlePath,
		control.Preparation,
		result.Snapshot,
		control.Anchor,
		initial,
		result.Transfer,
		runtime.blobs,
		now,
	)
	if err != nil {
		return deviceSyncMigrationControlResponse{}, err
	}
	return deviceSyncMigrationControlResponse{
		Action:       "source-prepare",
		Bundle:       &bundle,
		DeploymentID: runtime.signer.DeploymentID(),
		MigrationID:  optionalControlUUID(result.ExportRecord.MigrationID),
		PrincipalID:  optionalControlUUID(result.ExportRecord.PrincipalID),
		Snapshot:     &result.Snapshot,
		State:        postgres.DeviceSyncScopeExportFenced,
		Version:      deviceSyncMigrationControlVersion,
		WriteFenced:  true,
	}, nil
}

func (runtime *deviceSyncMigrationControlRuntime) prepareTarget(
	ctx context.Context,
	bundleDirectory string,
	now time.Time,
) (deviceSyncMigrationControlResponse, error) {
	bundlePath, err := filepath.Abs(bundleDirectory)
	if err != nil {
		return deviceSyncMigrationControlResponse{}, err
	}
	request, bundle, closeBundle, err :=
		migrationcoordinator.OpenDeviceSyncForwardBundle(ctx, bundlePath, now)
	if err != nil {
		return deviceSyncMigrationControlResponse{}, err
	}
	defer func() { _ = closeBundle() }()
	coordinator := migrationcoordinator.DeviceSyncTargetCoordinator{
		Importer:  runtime.store,
		Custody:   runtime.custody,
		BlobStore: runtime.blobs,
		Bindings:  runtime.bindings,
		Signer:    runtime.signer,
	}
	result, err := coordinator.Prepare(ctx, request)
	closeErr := closeBundle()
	closeBundle = func() error { return nil }
	if err != nil || closeErr != nil {
		return deviceSyncMigrationControlResponse{}, errors.Join(err, closeErr)
	}
	return deviceSyncMigrationControlResponse{
		Action:        "target-prepare",
		BlobByteCount: result.Transfer.ByteCount,
		BlobCount:     result.Transfer.BlobCount,
		Bundle:        &bundle,
		DeploymentID:  runtime.signer.DeploymentID(),
		MigrationID:   optionalControlUUID(result.ImportRecord.MigrationID),
		PrincipalID:   optionalControlUUID(result.ImportRecord.PrincipalID),
		Readiness:     &result.Readiness,
		State:         postgres.DeviceSyncScopeStandby,
		Version:       deviceSyncMigrationControlVersion,
		WriteFenced:   true,
	}, nil
}

func (runtime *deviceSyncMigrationControlRuntime) activate(
	ctx context.Context,
	control deviceSyncMigrationActivationRequest,
	now time.Time,
) (deviceSyncMigrationControlResponse, error) {
	if control.Version != deviceSyncMigrationControlVersion {
		return deviceSyncMigrationControlResponse{}, serviceauthority.ErrInvalid
	}
	coordinator := migrationcoordinator.DeviceSyncActivationCoordinator{
		Store: runtime.store, Custody: runtime.custody,
		Bindings: runtime.bindings, Signer: runtime.signer,
	}
	result, err := coordinator.Activate(
		ctx, control.Evidence, control.Anchor, now,
	)
	if err != nil {
		return deviceSyncMigrationControlResponse{}, err
	}
	activated, err := control.Evidence.ActivationManifest.VerifiedPayload()
	if err != nil || activated.Migration == nil {
		return deviceSyncMigrationControlResponse{}, serviceauthority.ErrInvalid
	}
	return deviceSyncMigrationTerminalResponse(
		"activate", runtime.signer.DeploymentID(),
		optionalControlUUID(activated.Migration.MigrationID), result.Binding, result.State,
	), nil
}

func (runtime *deviceSyncMigrationControlRuntime) prepareRollbackSource(
	ctx context.Context,
	control deviceSyncMigrationRollbackSourceRequest,
	bundleDirectory string,
	now time.Time,
) (deviceSyncMigrationControlResponse, error) {
	if control.Version != deviceSyncMigrationControlVersion {
		return deviceSyncMigrationControlResponse{}, serviceauthority.ErrInvalid
	}
	operations := migrationcoordinator.DeviceSyncRollbackSourceOperationCoordinator{
		Source: &migrationcoordinator.DeviceSyncSourceCoordinator{
			Exporter: runtime.store,
			Custody:  runtime.custody,
			Bindings: runtime.bindings,
			Signer:   runtime.signer,
		},
	}
	result, err := operations.Begin(
		ctx,
		migrationcoordinator.DeviceSyncRollbackSourcePreparationRequest{
			ActivationEvidence:      control.ActivationEvidence,
			Anchor:                  control.Anchor,
			ExportWriteFenceID:      control.ExportWriteFenceID,
			SnapshotID:              control.SnapshotID,
			ServiceStateArtifactID:  control.ServiceStateArtifactID,
			BlobInventoryArtifactID: control.BlobInventoryArtifactID,
			Now:                     now,
		},
	)
	if err != nil {
		return deviceSyncMigrationControlResponse{}, err
	}
	bundlePath, err := filepath.Abs(bundleDirectory)
	if err != nil {
		return deviceSyncMigrationControlResponse{}, err
	}
	bundle, err := migrationcoordinator.WriteDeviceSyncRollbackBundle(
		ctx,
		bundlePath,
		control.ActivationEvidence,
		result.Preparation.Snapshot,
		control.Anchor,
		result.Preparation.Transfer,
		runtime.blobs,
		now,
	)
	if err != nil {
		return deviceSyncMigrationControlResponse{}, err
	}
	return deviceSyncMigrationControlResponse{
		Action:       "rollback-source-prepare",
		Bundle:       &bundle,
		DeploymentID: runtime.signer.DeploymentID(),
		MigrationID:  optionalControlUUID(result.Preparation.ExportRecord.MigrationID),
		PrincipalID:  optionalControlUUID(result.Preparation.ExportRecord.PrincipalID),
		Snapshot:     &result.Preparation.Snapshot,
		State:        postgres.DeviceSyncScopeExportFenced,
		Version:      deviceSyncMigrationControlVersion,
		WriteFenced:  true,
	}, nil
}

func (runtime *deviceSyncMigrationControlRuntime) prepareRollbackTarget(
	ctx context.Context,
	bundleDirectory string,
	now time.Time,
) (deviceSyncMigrationControlResponse, error) {
	bundlePath, err := filepath.Abs(bundleDirectory)
	if err != nil {
		return deviceSyncMigrationControlResponse{}, err
	}
	request, bundle, closeBundle, err :=
		migrationcoordinator.OpenDeviceSyncRollbackBundle(ctx, bundlePath, now)
	if err != nil {
		return deviceSyncMigrationControlResponse{}, err
	}
	defer func() { _ = closeBundle() }()
	coordinator := migrationcoordinator.DeviceSyncRollbackTargetCoordinator{
		Importer:  runtime.store,
		Custody:   runtime.custody,
		BlobStore: runtime.blobs,
		Bindings:  runtime.bindings,
		Signer:    runtime.signer,
	}
	result, err := coordinator.Prepare(ctx, request)
	closeErr := closeBundle()
	closeBundle = func() error { return nil }
	if err != nil || closeErr != nil {
		return deviceSyncMigrationControlResponse{}, errors.Join(err, closeErr)
	}
	return deviceSyncMigrationControlResponse{
		Action:        "rollback-target-prepare",
		BlobByteCount: result.Transfer.ByteCount,
		BlobCount:     result.Transfer.BlobCount,
		Bundle:        &bundle,
		DeploymentID:  runtime.signer.DeploymentID(),
		MigrationID:   optionalControlUUID(result.ImportRecord.MigrationID),
		PrincipalID:   optionalControlUUID(result.ImportRecord.PrincipalID),
		Readiness:     &result.Readiness,
		State:         postgres.DeviceSyncScopeRollbackStandby,
		Version:       deviceSyncMigrationControlVersion,
		WriteFenced:   true,
	}, nil
}

func (runtime *deviceSyncMigrationControlRuntime) rollback(
	ctx context.Context,
	control deviceSyncMigrationRollbackRequest,
	now time.Time,
) (deviceSyncMigrationControlResponse, error) {
	if control.Version != deviceSyncMigrationControlVersion {
		return deviceSyncMigrationControlResponse{}, serviceauthority.ErrInvalid
	}
	coordinator := migrationcoordinator.DeviceSyncRollbackCoordinator{
		Store: runtime.store, Custody: runtime.custody,
		Bindings: runtime.bindings, Signer: runtime.signer,
	}
	result, err := coordinator.Rollback(
		ctx, control.Evidence, control.Anchor, now,
	)
	if err != nil {
		return deviceSyncMigrationControlResponse{}, err
	}
	rolledBack, err := control.Evidence.RollbackManifest.VerifiedPayload()
	if err != nil || rolledBack.Migration == nil {
		return deviceSyncMigrationControlResponse{}, serviceauthority.ErrInvalid
	}
	return deviceSyncMigrationTerminalResponse(
		"rollback-apply", runtime.signer.DeploymentID(),
		optionalControlUUID(rolledBack.Migration.MigrationID), result.Binding, result.State,
	), nil
}

// settleRollback installs the ordinary, non-expiring authority successor that
// follows a successful bounded rollback. The restored source must complete
// this step before the rollback Manifest expires; the retired replacement is
// not named by the successor and therefore cannot install it.
func (runtime *deviceSyncMigrationControlRuntime) settleRollback(
	ctx context.Context,
	control deviceSyncMigrationRollbackSettlementRequest,
	now time.Time,
) (deviceSyncMigrationControlResponse, error) {
	if control.Version != deviceSyncMigrationControlVersion {
		return deviceSyncMigrationControlResponse{}, serviceauthority.ErrInvalid
	}
	current, err := control.CurrentManifest.VerifiedPayload()
	if err != nil || current.Transition != serviceauthority.TransitionMigrationRollback ||
		current.Migration == nil ||
		current.ActiveDeployment.DeploymentID != runtime.signer.DeploymentID() {
		return deviceSyncMigrationControlResponse{}, serviceauthority.ErrInvalid
	}
	next, err := control.Successor.VerifiedPayload()
	if err != nil || next.Transition != serviceauthority.TransitionPolicyUpdate ||
		next.Migration != nil || next.ActiveDeployment.DeploymentID != runtime.signer.DeploymentID() ||
		!reflect.DeepEqual(next.ActiveDeployment, current.ActiveDeployment) ||
		!reflect.DeepEqual(next.TransportPolicy, current.TransportPolicy) {
		return deviceSyncMigrationControlResponse{}, serviceauthority.ErrInvalid
	}
	successorDigest, err := control.Successor.ReferenceDigest()
	if err != nil {
		return deviceSyncMigrationControlResponse{}, err
	}
	identities, err := runtime.bindings.CurrentBindingIdentities(
		serviceauthority.ScopeDeviceSync,
	)
	if err != nil {
		return deviceSyncMigrationControlResponse{}, err
	}
	exactRetry := false
	for _, identity := range identities {
		if identity.Scope != next.Scope {
			continue
		}
		exactRetry = identity.Revision == next.Revision &&
			identity.Digest == successorDigest &&
			identity.DeploymentID == runtime.signer.DeploymentID() &&
			identity.TransitionEvidenceDigest == nil && !identity.WriteFenced
		break
	}
	if !exactRetry {
		if _, err := control.CurrentManifest.Authorize(
			control.Anchor, now.UnixMilli(),
		); err != nil {
			return deviceSyncMigrationControlResponse{}, err
		}
	}
	if err := runtime.bindings.ApplyServiceAuthoritySuccessor(
		control.CurrentManifest, control.Successor, control.Anchor, now.UnixMilli(),
	); err != nil {
		return deviceSyncMigrationControlResponse{}, err
	}
	if err := runtime.store.AdvanceDeviceSyncWritableAuthority(
		ctx, next.Scope.ScopeID, runtime.signer.DeploymentID(),
		control.Successor, nil, now.UnixMilli(),
	); err != nil {
		return deviceSyncMigrationControlResponse{}, err
	}
	state, err := runtime.store.GetDeviceSyncScopeEnforcement(ctx, next.Scope.ScopeID)
	if err != nil {
		return deviceSyncMigrationControlResponse{}, err
	}
	identities, err = runtime.bindings.CurrentBindingIdentities(
		serviceauthority.ScopeDeviceSync,
	)
	if err != nil {
		return deviceSyncMigrationControlResponse{}, err
	}
	for _, identity := range identities {
		if identity.Scope == next.Scope && identity.Revision == next.Revision &&
			identity.Digest == successorDigest && !identity.WriteFenced {
			return deviceSyncMigrationTerminalResponse(
				"rollback-settle", runtime.signer.DeploymentID(), nil, identity, state,
			), nil
		}
	}
	return deviceSyncMigrationControlResponse{}, errors.New(
		"Device Sync rollback settlement registry identity is unavailable",
	)
}

func initialDeviceSyncAuthorityFromState(
	state postgres.DeviceSyncScopeEnforcement,
) (postgres.DeviceSyncInitialAuthorityEvidence, error) {
	if state.InitialAuthorityValidatedAtMilliseconds == nil ||
		len(state.InitialAuthorityManifestRecord) == 0 {
		return postgres.DeviceSyncInitialAuthorityEvidence{},
			errors.New("Device Sync source lacks initial authority evidence")
	}
	decoder := json.NewDecoder(bytes.NewReader(state.InitialAuthorityManifestRecord))
	decoder.DisallowUnknownFields()
	var manifest serviceauthority.Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return postgres.DeviceSyncInitialAuthorityEvidence{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return postgres.DeviceSyncInitialAuthorityEvidence{},
			serviceauthority.ErrInvalid
	}
	canonical, err := json.Marshal(manifest)
	if err != nil || !bytes.Equal(canonical, state.InitialAuthorityManifestRecord) {
		return postgres.DeviceSyncInitialAuthorityEvidence{},
			serviceauthority.ErrInvalid
	}
	return postgres.DeviceSyncInitialAuthorityEvidence{
		Manifest:                manifest,
		ValidatedAtMilliseconds: *state.InitialAuthorityValidatedAtMilliseconds,
	}, nil
}

func deviceSyncMigrationTerminalResponse(
	action string,
	localDeploymentID uuid.UUID,
	migrationID *uuid.UUID,
	binding serviceauthority.BindingIdentity,
	state postgres.DeviceSyncScopeEnforcement,
) deviceSyncMigrationControlResponse {
	return deviceSyncMigrationControlResponse{
		Action:            action,
		AuthorityDigest:   binding.Digest,
		AuthorityRevision: binding.Revision,
		DeploymentID:      localDeploymentID,
		MigrationID:       migrationID,
		PrincipalID:       optionalControlUUID(binding.Scope.ScopeID),
		State:             state.State,
		Version:           deviceSyncMigrationControlVersion,
		WriteFenced:       binding.WriteFenced,
	}
}

func optionalControlUUID(value uuid.UUID) *uuid.UUID {
	if value == uuid.Nil {
		return nil
	}
	copy := value
	return &copy
}

func readPrivateControlJSON(path string, destination any) error {
	if path == "" || destination == nil {
		return serviceauthority.ErrInvalid
	}
	resolved, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if err := validatePrivateControlDirectory(filepath.Dir(resolved)); err != nil {
		return err
	}
	info, err := os.Lstat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 ||
		info.Size() > 8*1024*1024 {
		return errors.New("Device Sync migration control input is not a private bounded file")
	}
	file, err := os.Open(resolved)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() ||
		openedInfo.Mode().Perm()&0o077 != 0 || openedInfo.Size() <= 0 ||
		openedInfo.Size() > 8*1024*1024 || !os.SameFile(info, openedInfo) {
		return errors.New("Device Sync migration control input changed while opening")
	}
	decoder := json.NewDecoder(io.LimitReader(file, 8*1024*1024+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return serviceauthority.ErrInvalid
	}
	return nil
}

func validatePrivateControlDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o022 != 0 {
		return errors.New("Device Sync migration control directory is not owner-controlled")
	}
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	openedInfo, err := directory.Stat()
	if err != nil || !openedInfo.IsDir() || openedInfo.Mode().Perm()&0o022 != 0 ||
		!os.SameFile(info, openedInfo) {
		return errors.New("Device Sync migration control directory changed while opening")
	}
	return nil
}

func writeDeviceSyncMigrationControlResponse(
	output io.Writer,
	response deviceSyncMigrationControlResponse,
) error {
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(response); err != nil {
		return fmt.Errorf("write Device Sync migration control response: %w", err)
	}
	return nil
}

func deviceSyncMigrationUsageError() error {
	return errors.New(
		"usage: facets-device-sync-server migration " +
			"target-offer <private-request.json> | " +
			"source-prepare <private-request.json> <new-bundle-directory> | " +
			"target-prepare <bundle-directory> | " +
			"activate <private-request.json> | " +
			"rollback-source-prepare <private-request.json> <new-bundle-directory> | " +
			"rollback-target-prepare <bundle-directory> | " +
			"rollback-apply <private-request.json> | " +
			"rollback-settle <private-request.json>",
	)
}
