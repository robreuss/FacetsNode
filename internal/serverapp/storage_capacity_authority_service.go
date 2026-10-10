package serverapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/robreuss/FacetsNode/internal/config"
	"github.com/robreuss/FacetsNode/internal/storageauthority"
	"github.com/robreuss/FacetsNode/internal/storagecapacity"
)

func runStorageCapacityAuthorityService(
	rootContext context.Context,
	pool *pgxpool.Pool,
	configuration config.Config,
	logger *slog.Logger,
	initialize bool,
) error {
	if rootContext == nil || pool == nil || logger == nil ||
		configuration.Service != config.StorageCapacityAuthority ||
		configuration.StorageCapacityPoolID == uuid.Nil {
		return storageauthority.ErrInvalid
	}
	startupContext, startupCancel := context.WithTimeout(rootContext, 30*time.Second)
	defer startupCancel()
	if initialize {
		if _, err := storagecapacity.NewFileSystemProvider(configuration.StorageCapacityPoolRoot); err != nil {
			return fmt.Errorf("physical capacity probe rejected: %w", err)
		}
		if err := storageauthority.InitializePhysicalPool(
			startupContext,
			pool,
			configuration.StorageCapacityPoolRoot,
			configuration.StorageCapacityPoolID,
		); err != nil {
			return fmt.Errorf("physical pool initialization rejected: %w", err)
		}
		logger.Info("Storage Capacity Authority physical pool initialized", "pool_id", configuration.StorageCapacityPoolID)
		return nil
	}
	identity, err := storagecapacity.LoadPhysicalPoolIdentity(configuration.StorageCapacityPoolRoot)
	if err != nil || identity.PoolID != configuration.StorageCapacityPoolID {
		return fmt.Errorf("physical pool identity rejected: %w", storageauthority.ErrInvalid)
	}
	capacity, err := storagecapacity.NewFileSystemProvider(configuration.StorageCapacityPoolRoot)
	if err != nil {
		return fmt.Errorf("physical capacity probe rejected: %w", err)
	}
	ledger, err := storageauthority.OpenPhysicalPool(
		startupContext,
		pool,
		configuration.StorageCapacityPoolRoot,
		capacity,
	)
	if err != nil {
		return fmt.Errorf("storage authority ledger rejected: %w", err)
	}
	peers, err := storageauthority.LoadCapacityPeerRegistry(configuration.StorageCapacityPeerRegistryFile)
	if err != nil {
		return fmt.Errorf("storage authority peer registry rejected: %w", err)
	}
	startupObserved := time.Now().UnixMilli()
	if err := reconcileAllExpired(startupContext, ledger, startupObserved); err != nil {
		return fmt.Errorf("initial storage reservation reconciliation rejected: %w", err)
	}
	if _, err := ledger.RefreshReadiness(startupContext, startupObserved); err != nil {
		return fmt.Errorf("initial storage readiness rejected: %w", err)
	}
	privateHandler, err := storageauthority.NewPrivateHTTPHandler(ledger, peers)
	if err != nil {
		return fmt.Errorf("private storage authority handler rejected: %w", err)
	}
	server := newStorageCapacityAuthorityHTTPServer(
		configuration,
		storageCapacityAuthorityHealthHandler(ledger, privateHandler.Handler()),
	)
	backgroundContext, cancelBackground := context.WithCancel(rootContext)
	backgroundDone := make(chan struct{})
	go func() {
		defer close(backgroundDone)
		storageCapacityAuthorityMaintenanceLoop(
			backgroundContext,
			ledger,
			configuration.StorageCapacityReadinessPeriod,
			logger,
		)
	}()
	serverErrors := make(chan error, 1)
	go func() {
		logger.Info(
			"Facets Storage Capacity Authority listening",
			"address", configuration.ListenAddress,
			"go_version", runtime.Version(),
			"pool_id", configuration.StorageCapacityPoolID,
		)
		serverErrors <- server.ListenAndServe()
	}()

	select {
	case <-rootContext.Done():
		logger.Info("Storage Capacity Authority shutdown requested")
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			cancelBackground()
			return fmt.Errorf("Storage Capacity Authority HTTP server failed: %w", err)
		}
	}
	shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), configuration.ShutdownPeriod)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownContext); err != nil {
		cancelBackground()
		return fmt.Errorf("Storage Capacity Authority graceful shutdown failed: %w", err)
	}
	cancelBackground()
	select {
	case <-backgroundDone:
	case <-shutdownContext.Done():
		return fmt.Errorf("Storage Capacity Authority maintenance shutdown timed out: %w", shutdownContext.Err())
	}
	logger.Info("Storage Capacity Authority shutdown complete")
	return nil
}

func newStorageCapacityAuthorityHTTPServer(
	configuration config.Config,
	handler http.Handler,
) *http.Server {
	return &http.Server{
		Addr: configuration.ListenAddress, Handler: handler,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second,
		MaxHeaderBytes: 8 * 1_024,
	}
}

func storageCapacityAuthorityHealthHandler(
	ledger *storageauthority.Ledger,
	private http.Handler,
) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /livez", func(writer http.ResponseWriter, _ *http.Request) {
		writeStorageCapacityHealth(writer, http.StatusOK, "live")
	})
	mux.HandleFunc("GET /readyz", func(writer http.ResponseWriter, request *http.Request) {
		if ledger == nil {
			writeStorageCapacityHealth(writer, http.StatusServiceUnavailable, "unavailable")
			return
		}
		if _, err := ledger.CoarseReadiness(request.Context()); err != nil {
			writeStorageCapacityHealth(writer, http.StatusServiceUnavailable, "unavailable")
			return
		}
		writeStorageCapacityHealth(writer, http.StatusOK, "ready")
	})
	mux.Handle("/", private)
	return mux
}

func writeStorageCapacityHealth(writer http.ResponseWriter, status int, state string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]string{"status": state})
}

func storageCapacityAuthorityMaintenanceLoop(
	ctx context.Context,
	ledger *storageauthority.Ledger,
	period time.Duration,
	logger *slog.Logger,
) {
	if ctx == nil || ledger == nil || period <= 0 || logger == nil {
		return
	}
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case observed := <-ticker.C:
			if err := reconcileAllExpired(ctx, ledger, observed.UnixMilli()); err != nil {
				logger.Warn("storage reservation expiry reconciliation failed", "error", err)
			}
			readiness, err := ledger.RefreshReadiness(ctx, observed.UnixMilli())
			if err != nil {
				logger.Warn("storage readiness refresh failed", "error", err)
			} else {
				logger.Debug("storage readiness refreshed", "state", readiness.State, "revision", readiness.Revision)
			}
		}
	}
}

func reconcileAllExpired(
	ctx context.Context,
	ledger *storageauthority.Ledger,
	observedAtMilliseconds int64,
) error {
	for {
		expired, err := ledger.ReconcileExpired(ctx, observedAtMilliseconds, 256)
		if err != nil {
			return err
		}
		if len(expired) < 256 {
			return nil
		}
	}
}
