package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/robreuss/FacetsNode/internal/config"
	"github.com/robreuss/FacetsNode/internal/httpapi"
	"github.com/robreuss/FacetsNode/internal/postgres"
)

func main() {
	if len(os.Args) == 3 && os.Args[1] == "healthcheck" {
		healthcheck(os.Args[2])
		return
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	configuration, err := config.Load()
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

	rootContext, stop := signal.NotifyContext(
		context.Background(), syscall.SIGINT, syscall.SIGTERM,
	)
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
	if err := postgres.Migrate(startupContext, pool); err != nil {
		logger.Error("database migration failed", "error", err)
		os.Exit(1)
	}
	store := postgres.NewStore(pool)
	api := httpapi.New(store, logger)
	httpServer := &http.Server{
		Addr:              configuration.ListenAddress,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1_024,
	}

	go cleanupLoop(rootContext, logger, store, configuration.CleanupPeriod)
	serverErrors := make(chan error, 1)
	go func() {
		logger.Info(
			"facets node listening",
			"address", configuration.ListenAddress,
			"go_version", runtime.Version(),
		)
		serverErrors <- httpServer.ListenAndServe()
	}()

	select {
	case <-rootContext.Done():
		logger.Info("shutdown requested")
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error("http server failed", "error", err)
			os.Exit(1)
		}
	}
	shutdownContext, cancel := context.WithTimeout(
		context.Background(), configuration.ShutdownPeriod,
	)
	defer cancel()
	if err := httpServer.Shutdown(shutdownContext); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
		os.Exit(1)
	}
	logger.Info("shutdown complete")
}

type expiryStore interface {
	PurgeExpired(context.Context, int64) error
}

func cleanupLoop(
	ctx context.Context,
	logger *slog.Logger,
	store expiryStore,
	period time.Duration,
) {
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
