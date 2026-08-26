package serverapp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/robreuss/FacetsNode/internal/computepool"
	"github.com/robreuss/FacetsNode/internal/config"
	"github.com/robreuss/FacetsNode/internal/httpapi"
	"github.com/robreuss/FacetsNode/internal/keycustody"
	"github.com/robreuss/FacetsNode/internal/migrationcoordinator"
	"github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
	"github.com/robreuss/FacetsNode/internal/sharedspaces"
)

func Main(service config.Service) {
	if len(os.Args) == 3 && os.Args[1] == "healthcheck" {
		healthcheck(os.Args[2])
		return
	}
	if len(os.Args) >= 2 && os.Args[1] == "issue-account-admission" {
		if err := issueAccountAdmission(service, os.Args[2:]); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "issue Device Sync account admission: %v\n", err)
			os.Exit(1)
		}
		return
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("service", service)
	configuration, err := config.Load(service)
	if err != nil {
		logger.Error("configuration rejected", "error", err)
		os.Exit(1)
	}
	poolConfiguration, err := pgxpool.ParseConfig(configuration.DatabaseURL)
	if err != nil {
		logger.Error("database URL rejected", "error", err)
		os.Exit(1)
	}
	poolConfiguration.MaxConns = configuration.DatabaseConns
	poolConfiguration.MinConns = 1
	poolConfiguration.MaxConnLifetime = time.Hour
	poolConfiguration.MaxConnIdleTime = 15 * time.Minute

	rootContext, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	pool, err := pgxpool.NewWithConfig(rootContext, poolConfiguration)
	if err != nil {
		logger.Error("database pool failed", "error", err)
		os.Exit(1)
	}
	defer pool.Close()
	startupContext, startupCancel := context.WithTimeout(rootContext, 30*time.Second)
	defer startupCancel()
	if err := pool.Ping(startupContext); err != nil {
		logger.Error("database unavailable", "error", err)
		os.Exit(1)
	}
	if service == config.ComputePool {
		if err := runComputePoolService(
			rootContext,
			pool,
			configuration,
			logger,
		); err != nil {
			logger.Error("Compute Pool Service failed", "error", err)
			os.Exit(1)
		}
		return
	}
	if err := postgres.Migrate(startupContext, pool); err != nil {
		logger.Error("database migration failed", "error", err)
		os.Exit(1)
	}

	store := postgres.NewStore(pool)
	var relayStore *postgres.RelayStore
	if service == config.DeviceSync {
		relayStore, err = postgres.NewDeviceSyncAuthorityBoundRelayStore(
			pool,
			configuration.DeploymentID,
			configuration.BlobUploadTTL,
			configuration.CheckpointFenceTTL,
		)
		if err != nil {
			logger.Error("Device Sync authority-bound store rejected", "error", err)
			os.Exit(1)
		}
	} else {
		relayStore = postgres.NewRelayStore(
			pool,
			configuration.BlobUploadTTL,
			configuration.CheckpointFenceTTL,
		)
	}
	blobMaintenanceStore := relay.BlobMaintenanceStore(relayStore)
	blobContentStore, err := relay.NewFileBlobContentStore(configuration.BlobRoot)
	if err != nil {
		logger.Error("blob store configuration rejected", "error", err)
		os.Exit(1)
	}
	blobUploadContentStore, err := relay.NewFileBlobUploadContentStore(configuration.BlobRoot, blobContentStore)
	if err != nil {
		logger.Error("blob upload store configuration rejected", "error", err)
		os.Exit(1)
	}
	api, err := httpapi.NewWithRelay(store, relayStore, blobContentStore, logger, configuration.OperatorToken, blobUploadContentStore)
	if err != nil {
		logger.Error("relay API configuration rejected", "error", err)
		os.Exit(1)
	}
	api.SetServiceIdentity(string(service))
	if len(configuration.OnionIngressToken) != 0 {
		if err := api.SetOnionIngressToken(configuration.OnionIngressToken); err != nil {
			logger.Error("onion ingress configuration rejected", "error", err)
			os.Exit(1)
		}
		logger.Info("privacy-safe onion ingress traffic policy enabled")
	}
	// Device Sync production startup is never allowed to fall through to a
	// non-authority mode. Config.Load enforces the same requirement; this guard
	// keeps the execution path fail-closed if configuration validation changes.
	if service == config.DeviceSync && configuration.DeploymentID == uuid.Nil {
		logger.Error("Device Sync service authority deployment is required")
		os.Exit(1)
	}
	if configuration.DeploymentID != uuid.Nil {
		deploymentSigner, err := serviceauthority.LoadDeploymentSigner(
			configuration.DeploymentID,
			configuration.DeploymentSigningKeyFile,
		)
		if err != nil {
			logger.Error("deployment signing custody rejected", "error", err)
			os.Exit(1)
		}
		if _, err := serviceauthority.LoadDeploymentOfferTemplate(
			configuration.DeploymentRoutePolicyFile,
			deploymentSigner,
		); err != nil {
			logger.Error("deployment route policy rejected", "error", err)
			os.Exit(1)
		}
		bindings, err := serviceauthority.LoadBindingRegistry(
			configuration.ServiceAuthorityBindingsFile,
			configuration.DeploymentID,
		)
		if err != nil {
			logger.Error("service authority bindings rejected", "error", err)
			os.Exit(1)
		}
		defer func() {
			if err := bindings.Close(); err != nil {
				logger.Error("service authority binding lock release failed", "error", err)
			}
		}()
		scopeKind := serviceauthority.ScopeDeviceSync
		if service == config.SharedSpaces {
			scopeKind = serviceauthority.ScopeSharedSpace
		}
		if service == config.DeviceSync {
			authorityStateDirectory, err := filepath.Abs(filepath.Dir(
				configuration.ServiceAuthorityBindingsFile,
			))
			if err != nil {
				logger.Error(
					"Device Sync migration custody path rejected",
					"error", err,
				)
				os.Exit(1)
			}
			migrationCustody, err := migrationcoordinator.NewFileArtifactCustody(
				filepath.Join(authorityStateDirectory, "migration-custody"),
			)
			if err != nil {
				logger.Error(
					"Device Sync migration custody rejected",
					"error", err,
				)
				os.Exit(1)
			}
			activationCoordinator := migrationcoordinator.DeviceSyncActivationCoordinator{
				Store: relayStore, Custody: migrationCustody,
				Bindings: bindings, Signer: deploymentSigner,
			}
			recovered, err := activationCoordinator.Recover(
				startupContext,
				time.Now(),
			)
			if err != nil {
				logger.Error(
					"Device Sync migration activation recovery rejected",
					"error", err,
				)
				os.Exit(1)
			}
			if len(recovered) != 0 {
				logger.Info(
					"Device Sync migration activation recovery completed",
					"scope_count", len(recovered),
				)
			}
			cancellationCoordinator := migrationcoordinator.DeviceSyncCancellationCoordinator{
				Store: relayStore, Custody: migrationCustody,
				Bindings: bindings, Signer: deploymentSigner,
			}
			cancelled, err := cancellationCoordinator.Recover(
				startupContext,
				time.Now(),
			)
			if err != nil {
				logger.Error(
					"Device Sync migration cancellation recovery rejected",
					"error", err,
				)
				os.Exit(1)
			}
			if len(cancelled) != 0 {
				logger.Info(
					"Device Sync migration cancellation recovery completed",
					"scope_count", len(cancelled),
				)
			}
			rollbackCoordinator := migrationcoordinator.DeviceSyncRollbackCoordinator{
				Store: relayStore, Custody: migrationCustody,
				Bindings: bindings, Signer: deploymentSigner,
			}
			rolledBack, err := rollbackCoordinator.Recover(
				startupContext,
				time.Now(),
			)
			if err != nil {
				logger.Error(
					"Device Sync migration rollback recovery rejected",
					"error", err,
				)
				os.Exit(1)
			}
			if len(rolledBack) != 0 {
				logger.Info(
					"Device Sync migration rollback recovery completed",
					"scope_count", len(rolledBack),
				)
			}
			retirementCoordinator := migrationcoordinator.DeviceSyncRetirementCoordinator{
				Store: relayStore, Custody: migrationCustody,
				Bindings: bindings, Signer: deploymentSigner,
			}
			retired, err := retirementCoordinator.Recover(
				startupContext,
				time.Now(),
			)
			if err != nil {
				logger.Error(
					"Device Sync migration retirement recovery rejected",
					"error", err,
				)
				os.Exit(1)
			}
			if len(retired) != 0 {
				logger.Info(
					"Device Sync migration retirement recovery completed",
					"scope_count", len(retired),
				)
			}
			if err := reconcileDeviceSyncServiceAuthority(
				startupContext,
				relayStore,
				bindings,
				time.Now().UnixMilli(),
			); err != nil {
				logger.Error(
					"Device Sync service authority readiness rejected",
					"error", err,
				)
				os.Exit(1)
			}
			blobMaintenanceStore, err = newDeviceSyncBlobMaintenanceStore(
				relayStore,
				bindings,
				relayStore,
			)
			if err != nil {
				logger.Error(
					"Device Sync blob maintenance authority rejected",
					"error", err,
				)
				os.Exit(1)
			}
		}
		api.SetServiceAuthorityDeployment(deploymentSigner, bindings, scopeKind)
		logger.Info(
			"Facets deployment authentication enabled",
			"deployment_id", configuration.DeploymentID,
			"signing_key_fingerprint", deploymentSigner.SigningKeyFingerprint(),
		)
	}
	if service == config.DeviceSync {
		api.SetDeviceSyncStore(relayStore)
	}
	if service == config.SharedSpaces {
		managedContentKeys, err := keycustody.NewManagedContentKeys(
			configuration.ManagedKeyEncryptionKey,
		)
		if err != nil {
			logger.Error("managed content-key custody rejected", "error", err)
			os.Exit(1)
		}
		api.SetSharedSpacesStore(postgres.NewSharedSpacesStore(pool, managedContentKeys))
		computeCapabilitySigner, err := sharedspaces.NewComputeCapabilitySigner(
			configuration.ComputeCapabilitySigningSeed,
			configuration.PublicURL,
		)
		if err != nil {
			logger.Error("compute capability signing authority rejected", "error", err)
			os.Exit(1)
		}
		api.SetSharedSpacesComputeCapabilitySigner(computeCapabilitySigner)
	}
	if err := api.SetTrafficLimits(configuration.TrafficLimits); err != nil {
		logger.Error("traffic limits rejected", "error", err)
		os.Exit(1)
	}
	relayWakeListener := postgres.NewRelayWakeListener(pool)
	api.SetRelayWakeNotifier(postgres.NewRelayWakeNotifier(pool))
	relayWakeContext, cancelRelayWake := context.WithCancel(rootContext)
	defer cancelRelayWake()
	relayWakeDone := make(chan struct{})
	go func() {
		defer close(relayWakeDone)
		relayWakeListener.Run(relayWakeContext, api.ReceiveRelayWake, func(err error) {
			logger.Warn("cross-instance relay wake listener unavailable", "error", err)
		})
	}()

	httpServer := &http.Server{
		Addr:              configuration.ListenAddress,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       configuration.TransferPeriod,
		WriteTimeout:      configuration.TransferPeriod,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1_024,
	}
	go cleanupLoop(rootContext, logger, store, configuration.CleanupPeriod)
	go blobMaintenanceLoop(rootContext, logger, blobMaintenanceStore, blobContentStore, blobUploadContentStore, configuration.CleanupPeriod, configuration.BlobOrphanGrace)
	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("Facets server listening", "address", configuration.ListenAddress, "go_version", runtime.Version())
		serverErrors <- httpServer.ListenAndServe()
	}()

	select {
	case <-rootContext.Done():
		logger.Info("shutdown requested")
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error("HTTP server failed", "error", err)
			os.Exit(1)
		}
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), configuration.ShutdownPeriod)
	defer cancel()
	if err := httpServer.Shutdown(shutdownContext); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
		os.Exit(1)
	}
	cancelRelayWake()
	select {
	case <-relayWakeDone:
	case <-shutdownContext.Done():
		logger.Warn("cross-instance relay wake listener shutdown timed out")
	}
	logger.Info("shutdown complete")
}

func runComputePoolService(
	rootContext context.Context,
	pool *pgxpool.Pool,
	configuration config.Config,
	logger *slog.Logger,
) error {
	startupContext, startupCancel := context.WithTimeout(rootContext, 30*time.Second)
	defer startupCancel()
	if err := postgres.MigrateComputePool(startupContext, pool); err != nil {
		return fmt.Errorf("Compute Pool database migration failed: %w", err)
	}
	deploymentSigner, err := serviceauthority.LoadDeploymentSigner(
		configuration.DeploymentID,
		configuration.DeploymentSigningKeyFile,
	)
	if err != nil {
		return fmt.Errorf("Compute Pool deployment signing custody rejected: %w", err)
	}
	if _, err := serviceauthority.LoadDeploymentOfferTemplate(
		configuration.DeploymentRoutePolicyFile,
		deploymentSigner,
	); err != nil {
		return fmt.Errorf("Compute Pool deployment route policy rejected: %w", err)
	}
	bindings, err := serviceauthority.LoadBindingRegistry(
		configuration.ServiceAuthorityBindingsFile,
		configuration.DeploymentID,
	)
	if err != nil {
		return fmt.Errorf("Compute Pool service authority bindings rejected: %w", err)
	}
	defer func() {
		if err := bindings.Close(); err != nil {
			logger.Error("Compute Pool service authority binding lock release failed", "error", err)
		}
	}()
	handler, err := computepool.NewHTTPHandler(
		postgres.NewComputePoolStore(pool),
		deploymentSigner,
		bindings,
		configuration.OperatorToken,
	)
	if err != nil {
		return fmt.Errorf("Compute Pool HTTP authority rejected: %w", err)
	}
	server := &http.Server{
		Addr:              configuration.ListenAddress,
		Handler:           handler.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       configuration.TransferPeriod,
		WriteTimeout:      configuration.TransferPeriod,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1_024,
	}
	serverErrors := make(chan error, 1)
	go func() {
		logger.Info(
			"Facets Compute Pool Service listening",
			"address",
			configuration.ListenAddress,
			"go_version",
			runtime.Version(),
			"deployment_id",
			configuration.DeploymentID,
			"signing_key_fingerprint",
			deploymentSigner.SigningKeyFingerprint(),
		)
		serverErrors <- server.ListenAndServe()
	}()

	select {
	case <-rootContext.Done():
		logger.Info("Compute Pool shutdown requested")
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("Compute Pool HTTP server failed: %w", err)
		}
	}
	shutdownContext, shutdownCancel := context.WithTimeout(
		context.Background(),
		configuration.ShutdownPeriod,
	)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownContext); err != nil {
		return fmt.Errorf("Compute Pool graceful shutdown failed: %w", err)
	}
	logger.Info("Compute Pool shutdown complete")
	return nil
}

func blobMaintenanceLoop(ctx context.Context, logger *slog.Logger, store relay.BlobMaintenanceStore, blobs relay.BlobContentMaintenanceStore, uploads relay.BlobUploadMaintenanceContentStore, period, grace time.Duration) {
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			maintenanceContext, cancel := context.WithTimeout(ctx, 30*time.Second)
			err := reconcileBlobFiles(maintenanceContext, store, blobs, uploads, now.UnixMilli(), grace.Milliseconds())
			cancel()
			if err != nil && !errors.Is(err, context.Canceled) {
				logger.Error("blob maintenance failed", "error", err)
			}
		}
	}
}

func reconcileBlobFiles(ctx context.Context, store relay.BlobMaintenanceStore, blobs relay.BlobContentMaintenanceStore, uploads relay.BlobUploadMaintenanceContentStore, nowMilliseconds, graceMilliseconds int64) error {
	var maintenanceErr error
	_, expiryErr := store.ExpireBlobUploads(
		ctx, nowMilliseconds, graceMilliseconds,
	)
	maintenanceErr = errors.Join(maintenanceErr, expiryErr)
	if errors.Is(expiryErr, context.Canceled) ||
		errors.Is(expiryErr, context.DeadlineExceeded) {
		return maintenanceErr
	}
	finalCandidates, err := blobs.BlobCandidates(ctx)
	if err != nil {
		return errors.Join(maintenanceErr, err)
	}
	for _, candidate := range finalCandidates {
		_, err := store.DeleteBlobIfUnauthorized(ctx, candidate, nowMilliseconds, graceMilliseconds, func() error {
			return blobs.DeleteBlob(ctx, candidate.Scope, candidate.BlobID)
		})
		if err != nil {
			maintenanceErr = errors.Join(maintenanceErr, err)
			if errors.Is(err, context.Canceled) ||
				errors.Is(err, context.DeadlineExceeded) {
				return maintenanceErr
			}
		}
	}
	uploadCandidates, err := uploads.UploadCandidates(ctx)
	if err != nil {
		return errors.Join(maintenanceErr, err)
	}
	for _, candidate := range uploadCandidates {
		_, err := store.DeleteBlobUploadIfUnauthorized(ctx, candidate, nowMilliseconds, graceMilliseconds, func() error {
			return uploads.DeleteUpload(ctx, candidate.Scope, candidate.UploadID)
		})
		if err != nil {
			maintenanceErr = errors.Join(maintenanceErr, err)
			if errors.Is(err, context.Canceled) ||
				errors.Is(err, context.DeadlineExceeded) {
				return maintenanceErr
			}
		}
	}
	return maintenanceErr
}

type expiryStore interface {
	PurgeExpired(context.Context, int64) error
}

func cleanupLoop(ctx context.Context, logger *slog.Logger, store expiryStore, period time.Duration) {
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			purgeContext, cancel := context.WithTimeout(ctx, 30*time.Second)
			err := store.PurgeExpired(purgeContext, now.UnixMilli())
			cancel()
			if err != nil && !errors.Is(err, context.Canceled) {
				logger.Error("expiry purge failed", "error", err)
			}
		}
	}
}

func healthcheck(url string) {
	client := http.Client{Timeout: 2 * time.Second}
	response, err := client.Get(url)
	if err != nil || response.StatusCode != http.StatusOK {
		os.Exit(1)
	}
	_ = response.Body.Close()
}
