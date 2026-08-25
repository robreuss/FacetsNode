package serverapp

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/robreuss/FacetsNode/internal/config"
	"github.com/robreuss/FacetsNode/internal/devicesync"
	"github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

func issueAccountAdmission(service config.Service, arguments []string) error {
	if service != config.DeviceSync {
		return fmt.Errorf("account admissions are available only for Facets Device Sync Server")
	}
	configuration, err := config.Load(service)
	if err != nil {
		return err
	}
	flags := flag.NewFlagSet("issue-account-admission", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	endpoint := flags.String("endpoint", configuration.PublicURL, "client-visible Device Sync HTTPS endpoint")
	lifetime := flags.Duration("lifetime", 15*time.Minute, "one-time credential lifetime")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("issue-account-admission accepts flags only")
	}
	if *endpoint == "" {
		return fmt.Errorf("FACETS_DEVICE_SYNC_PUBLIC_URL or --endpoint is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	poolConfiguration, err := pgxpool.ParseConfig(configuration.DatabaseURL)
	if err != nil {
		return fmt.Errorf("database URL rejected: %w", err)
	}
	poolConfiguration.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(ctx, poolConfiguration)
	if err != nil {
		return fmt.Errorf("database pool failed: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("database unavailable: %w", err)
	}
	if err := postgres.Migrate(ctx, pool); err != nil {
		return fmt.Errorf("database migration failed: %w", err)
	}
	store := postgres.NewRelayStore(pool, configuration.BlobUploadTTL, configuration.CheckpointFenceTTL)
	signer, err := serviceauthority.LoadDeploymentSigner(
		configuration.DeploymentID,
		configuration.DeploymentSigningKeyFile,
	)
	if err != nil {
		return fmt.Errorf("deployment signing custody rejected: %w", err)
	}
	template, err := serviceauthority.LoadDeploymentOfferTemplate(
		configuration.DeploymentRoutePolicyFile,
		signer,
	)
	if err != nil {
		return fmt.Errorf("deployment route policy rejected: %w", err)
	}
	now := time.Now()
	expiresAt := now.Add(*lifetime)
	offer, err := template.SignOffer(signer, now, expiresAt)
	if err != nil {
		return fmt.Errorf("sign deployment offer: %w", err)
	}
	issued, err := devicesync.IssueAccountBootstrap(
		ctx, store, *endpoint, offer, *lifetime, now, nil,
	)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(issued); err != nil {
		return fmt.Errorf("write account bootstrap: %w", err)
	}
	return nil
}
