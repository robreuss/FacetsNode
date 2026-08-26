package serverapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/robreuss/FacetsNode/internal/config"
	"github.com/robreuss/FacetsNode/internal/migrationcoordinator"
	"github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

const deviceSyncRollbackSourceControlVersion = 1

type deviceSyncRollbackSourceOperations interface {
	ListStatus(
		context.Context,
		time.Time,
	) ([]migrationcoordinator.DeviceSyncRollbackSourceOperationStatus, error)
	Recover(
		context.Context,
		time.Time,
	) ([]migrationcoordinator.DeviceSyncRollbackSourceOperationResult, error)
}

type deviceSyncRollbackSourceControlResponse struct {
	Action                  string                                                         `json:"action"`
	Operations              []migrationcoordinator.DeviceSyncRollbackSourceOperationStatus `json:"operations"`
	RecoveredOperationCount int                                                            `json:"recoveredOperationCount"`
	Version                 int                                                            `json:"version"`
}

func runDeviceSyncRollbackSourceControl(
	ctx context.Context,
	service config.Service,
	arguments []string,
	output io.Writer,
	now func() time.Time,
) error {
	if ctx == nil || service != config.DeviceSync || output == nil || now == nil ||
		len(arguments) != 1 ||
		(arguments[0] != "status" && arguments[0] != "recover") {
		return errors.New(
			"usage: facets-device-sync-server rollback-source status|recover",
		)
	}
	configuration, err := config.Load(config.DeviceSync)
	if err != nil {
		return fmt.Errorf("configuration rejected: %w", err)
	}
	signer, err := serviceauthority.LoadDeploymentSigner(
		configuration.DeploymentID,
		configuration.DeploymentSigningKeyFile,
	)
	if err != nil {
		return fmt.Errorf("deployment signing custody rejected: %w", err)
	}
	authorityDirectory, err := filepath.Abs(filepath.Dir(
		configuration.ServiceAuthorityBindingsFile,
	))
	if err != nil {
		return fmt.Errorf("migration custody path rejected: %w", err)
	}
	custodyRoot := filepath.Join(authorityDirectory, "migration-custody")
	if arguments[0] == "status" {
		custody, err := migrationcoordinator.InspectFileArtifactCustody(custodyRoot)
		if err != nil {
			return fmt.Errorf("migration custody status rejected: %w", err)
		}
		coordinator := &migrationcoordinator.DeviceSyncRollbackSourceOperationCoordinator{
			Source: &migrationcoordinator.DeviceSyncSourceCoordinator{
				Custody: custody,
				Signer:  signer,
			},
		}
		return executeDeviceSyncRollbackSourceControl(
			ctx, arguments[0], coordinator, output, now(),
		)
	}

	custody, err := migrationcoordinator.NewFileArtifactCustody(custodyRoot)
	if err != nil {
		return fmt.Errorf("migration custody rejected: %w", err)
	}
	poolConfiguration, err := pgxpool.ParseConfig(configuration.DatabaseURL)
	if err != nil {
		return fmt.Errorf("database URL rejected: %w", err)
	}
	poolConfiguration.MaxConns = configuration.DatabaseConns
	poolConfiguration.MinConns = 1
	poolConfiguration.MaxConnLifetime = time.Hour
	poolConfiguration.MaxConnIdleTime = 15 * time.Minute
	pool, err := pgxpool.NewWithConfig(ctx, poolConfiguration)
	if err != nil {
		return fmt.Errorf("database pool failed: %w", err)
	}
	defer pool.Close()
	startupContext, startupCancel := context.WithTimeout(ctx, 30*time.Second)
	defer startupCancel()
	if err := pool.Ping(startupContext); err != nil {
		return fmt.Errorf("database unavailable: %w", err)
	}
	store, err := postgres.NewDeviceSyncAuthorityBoundRelayStore(
		pool,
		configuration.DeploymentID,
		configuration.BlobUploadTTL,
		configuration.CheckpointFenceTTL,
	)
	if err != nil {
		return fmt.Errorf("authority-bound store rejected: %w", err)
	}
	bindings, err := serviceauthority.LoadBindingRegistry(
		configuration.ServiceAuthorityBindingsFile,
		configuration.DeploymentID,
	)
	if err != nil {
		return fmt.Errorf("service authority bindings rejected: %w", err)
	}
	defer func() { _ = bindings.Close() }()
	coordinator := &migrationcoordinator.DeviceSyncRollbackSourceOperationCoordinator{
		Source: &migrationcoordinator.DeviceSyncSourceCoordinator{
			Exporter: store,
			Custody:  custody,
			Bindings: bindings,
			Signer:   signer,
		},
	}
	return executeDeviceSyncRollbackSourceControl(
		ctx, arguments[0], coordinator, output, now(),
	)
}

func executeDeviceSyncRollbackSourceControl(
	ctx context.Context,
	action string,
	operations deviceSyncRollbackSourceOperations,
	output io.Writer,
	now time.Time,
) error {
	if ctx == nil || operations == nil || output == nil || now.IsZero() ||
		(action != "status" && action != "recover") {
		return serviceauthority.ErrInvalid
	}
	recoveredCount := 0
	if action == "recover" {
		recovered, err := operations.Recover(ctx, now)
		if err != nil {
			return fmt.Errorf("recover rollback source operations: %w", err)
		}
		recoveredCount = len(recovered)
	}
	statuses, err := operations.ListStatus(ctx, now)
	if err != nil {
		return fmt.Errorf("list rollback source operations: %w", err)
	}
	response := deviceSyncRollbackSourceControlResponse{
		Action:                  action,
		Operations:              statuses,
		RecoveredOperationCount: recoveredCount,
		Version:                 deviceSyncRollbackSourceControlVersion,
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(response); err != nil {
		return fmt.Errorf("write rollback source control status: %w", err)
	}
	return nil
}
