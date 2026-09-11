package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/robreuss/FacetsNode/internal/boxcontrol"
)

type configuration struct {
	databaseURL          string
	listenAddress        string
	publicURL            string
	displayName          string
	identityKeyFile      string
	deviceSyncPrivateURL string
	deviceSyncToken      string
	deviceSyncPublicURL  string
}

func main() {
	if len(os.Args) == 3 && os.Args[1] == "healthcheck" {
		response, err := (&http.Client{Timeout: 3 * time.Second}).Get(os.Args[2])
		if err != nil || response.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		response.Body.Close()
		return
	}
	config, err := loadConfiguration()
	if err != nil {
		fatal("configuration rejected", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	pool, err := openDatabase(ctx, config.databaseURL)
	if err != nil {
		fatal("database unavailable", err)
	}
	defer pool.Close()
	store := boxcontrol.NewPostgresStore(pool)
	startup, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := store.Migrate(startup); err != nil {
		fatal("database migration failed", err)
	}
	if len(os.Args) >= 2 && os.Args[1] == "initialize" {
		if err := initialize(startup, store, config.identityKeyFile, os.Args[2:]); err != nil {
			fatal("Box initialization failed", err)
		}
		return
	}
	privateKey, err := loadIdentityKey(config.identityKeyFile)
	if err != nil {
		fatal("Box identity unavailable", err)
	}
	if _, err := store.State(startup); err != nil {
		fatal("Box has not been initialized", err)
	}
	deviceSync, err := boxcontrol.NewDeviceSyncHTTPClient(
		config.deviceSyncPrivateURL, config.deviceSyncToken, nil,
	)
	if err != nil {
		fatal("Device Sync controller channel rejected", err)
	}
	service, err := boxcontrol.NewService(
		store,
		deviceSync,
		privateKey,
		config.publicURL,
		config.displayName,
		[]boxcontrol.ServiceDescriptor{{Kind: "device-sync", Endpoint: config.deviceSyncPublicURL}},
		slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("service", "facets-box-controller"),
	)
	if err != nil {
		fatal("Box controller rejected", err)
	}
	server := &http.Server{
		Addr: config.listenAddress, Handler: service.Handler(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 16 * 1024,
	}
	errorsChannel := make(chan error, 1)
	go func() {
		slog.Info("Facets Box controller listening", "address", config.listenAddress, "go_version", runtime.Version())
		errorsChannel <- server.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
	case err := <-errorsChannel:
		if !errors.Is(err, http.ErrServerClosed) {
			fatal("Box controller failed", err)
		}
	}
	shutdown, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdown); err != nil {
		fatal("Box controller shutdown failed", err)
	}
}

func loadConfiguration() (configuration, error) {
	config := configuration{
		databaseURL:          os.Getenv("FACETS_BOX_CONTROLLER_DATABASE_URL"),
		listenAddress:        environment("FACETS_BOX_CONTROLLER_LISTEN_ADDR", ":8081"),
		publicURL:            os.Getenv("FACETS_BOX_PUBLIC_URL"),
		displayName:          environment("FACETS_BOX_DISPLAY_NAME", "Facets Box"),
		identityKeyFile:      environment("FACETS_BOX_IDENTITY_KEY_FILE", "/var/lib/facets-box-controller/identity-key"),
		deviceSyncPrivateURL: environment("FACETS_BOX_DEVICE_SYNC_PRIVATE_URL", "http://server:8080"),
		deviceSyncToken:      os.Getenv("FACETS_DEVICE_SYNC_BOX_CONTROLLER_TOKEN"),
		deviceSyncPublicURL:  os.Getenv("FACETS_BOX_DEVICE_SYNC_URL"),
	}
	if config.databaseURL == "" || config.publicURL == "" || config.deviceSyncToken == "" || config.deviceSyncPublicURL == "" {
		return configuration{}, errors.New("database, public URL, Device Sync URL, and controller token are required")
	}
	return config, nil
}

func openDatabase(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, err
	}
	poolConfig.MaxConns = 5
	poolConfig.MinConns = 1
	poolConfig.MaxConnLifetime = time.Hour
	poolConfig.MaxConnIdleTime = 15 * time.Minute
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return pool, nil
}

func initialize(ctx context.Context, store *boxcontrol.PostgresStore, identityKeyFile string, arguments []string) error {
	flags := flag.NewFlagSet("initialize", flag.ContinueOnError)
	activationFlag := flags.String("activation-code", "", "optional one-time activation code")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return errors.New("initialize accepts only --activation-code")
	}
	activationCode := strings.TrimSpace(*activationFlag)
	if activationCode == "" {
		var err error
		activationCode, err = boxcontrol.GenerateActivationCode()
		if err != nil {
			return err
		}
	}
	if len(activationCode) < 12 || len(activationCode) > 128 {
		return errors.New("activation code must contain 12 to 128 characters")
	}
	verifier, err := boxcontrolHashActivation(activationCode)
	if err != nil {
		return err
	}
	if _, err := ensureIdentityKey(identityKeyFile); err != nil {
		return err
	}
	if err := store.Initialize(ctx, boxcontrol.State{BoxID: uuid.New(), ActivationVerifier: verifier}); err != nil {
		return err
	}
	fmt.Printf("Facets Box one-time activation code: %s\n", activationCode)
	return nil
}

// Kept as a narrow exported-through-command wrapper so activation and owner
// verifiers use the same versioned Argon2id implementation.
func boxcontrolHashActivation(value string) (string, error) {
	return boxcontrol.HashActivationCode(value)
}

func ensureIdentityKey(path string) (ed25519.PrivateKey, error) {
	if key, err := loadIdentityKey(path); err == nil {
		return key, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if _, err := file.WriteString(base64.RawURLEncoding.EncodeToString(privateKey)); err != nil {
		return nil, err
	}
	if err := file.Sync(); err != nil {
		return nil, err
	}
	return privateKey, nil
}

func loadIdentityKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(decoded) != ed25519.PrivateKeySize {
		return nil, errors.New("identity key is invalid")
	}
	return ed25519.PrivateKey(decoded), nil
}

func environment(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func fatal(message string, err error) {
	slog.Error(message, "error_type", fmt.Sprintf("%T", err), "error", err)
	os.Exit(1)
}
