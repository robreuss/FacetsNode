package serverapp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/robreuss/FacetsNode/internal/computequeue"
	"github.com/robreuss/FacetsNode/internal/config"
	"github.com/robreuss/FacetsNode/internal/jobcustody"
	"github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
	"github.com/robreuss/FacetsNode/internal/storageauthority"
	"github.com/robreuss/FacetsNode/internal/storagecapacity"
)

type jobCustodyWallClock struct{}

func (jobCustodyWallClock) Now() time.Time { return time.Now() }

// jobCustodyRuntime owns the service-local database, private filesystem, trust
// configuration, and physical-capacity client. It deliberately has no HTTP
// admission handler: transport authentication must supply the expected signer
// and route grant rather than accepting requester-echoed trust fields.
type jobCustodyRuntime struct {
	Coordinator      *jobcustody.Coordinator
	AdmissionPermits *jobcustody.AdmissionPermitVerifier
	content          *jobcustody.ContentStore
	bindings         *serviceauthority.BindingRegistry
}

func (runtime *jobCustodyRuntime) Close() error {
	if runtime == nil {
		return nil
	}
	var failures []error
	if runtime.content != nil {
		failures = append(failures, runtime.content.Close())
	}
	if runtime.bindings != nil {
		failures = append(failures, runtime.bindings.Close())
	}
	return errors.Join(failures...)
}

func prepareJobCustodyRuntime(
	ctx context.Context,
	pool *pgxpool.Pool,
	configuration config.Config,
) (_ *jobCustodyRuntime, result error) {
	if ctx == nil || pool == nil || validateJobCustodyConfiguration(configuration) != nil {
		return nil, serviceauthority.ErrInvalid
	}
	if err := requireDedicatedJobCustodyDatabase(ctx, pool); err != nil {
		return nil, fmt.Errorf("Job custody dedicated database rejected: %w", err)
	}
	if err := postgres.MigrateJobCustody(ctx, pool); err != nil {
		return nil, fmt.Errorf("Job custody database migration failed: %w", err)
	}
	if err := requireDedicatedJobCustodyDatabase(ctx, pool); err != nil {
		return nil, fmt.Errorf("Job custody dedicated database rejected after migration: %w", err)
	}
	signer, err := loadJobCustodyDeploymentAuthority(configuration)
	if err != nil {
		return nil, err
	}
	bindings, err := serviceauthority.LoadBindingRegistry(
		configuration.ServiceAuthorityBindingsFile,
		configuration.DeploymentID,
	)
	if err != nil {
		return nil, fmt.Errorf("Job custody authority bindings rejected: %w", err)
	}
	runtime := &jobCustodyRuntime{bindings: bindings}
	defer func() {
		if result != nil {
			_ = runtime.Close()
		}
	}()
	verifier, err := computequeue.LoadJobCustodyP256AdmissionVerifier(
		configuration.JobCustodyAdmissionKeysFile,
	)
	if err != nil {
		return nil, fmt.Errorf("Job custody admission trust rejected: %w", err)
	}
	permitVerifier, err := jobcustody.LoadAdmissionPermitVerifier(
		configuration.JobCustodyAdmissionAuthoritiesFile,
	)
	if err != nil {
		return nil, fmt.Errorf("Job custody Box admission authority rejected: %w", err)
	}
	runtime.AdmissionPermits = permitVerifier
	privateTransport := http.DefaultTransport.(*http.Transport).Clone()
	privateTransport.Proxy = nil
	capacityClient, err := storageauthority.NewPrivateHTTPClient(
		configuration.StorageCapacityAuthorityURL,
		&http.Client{Transport: privateTransport, Timeout: 15 * time.Second},
		signer,
		storagecapacity.ServiceBinding{
			Kind: storagecapacity.ServiceJobCustody, InstanceID: configuration.DeploymentID,
		},
		configuration.StorageCapacityPoolID,
	)
	if err != nil {
		return nil, fmt.Errorf("Job custody storage capacity authority rejected: %w", err)
	}
	content, err := jobcustody.OpenContentStore(configuration.JobCustodyRoot)
	if err != nil {
		return nil, fmt.Errorf("Job custody protected object store rejected: %w", err)
	}
	runtime.content = content
	clock := jobCustodyWallClock{}
	ledger, err := postgres.NewJobCustodyStore(
		pool,
		jobCustodyStoreLimits(configuration),
		clock,
	)
	if err != nil {
		return nil, fmt.Errorf("Job custody store limits rejected: %w", err)
	}
	runtime.Coordinator = &jobcustody.Coordinator{
		Ledger: ledger, Content: content,
		Capacity: jobCustodyCapacityAuthority{
			client: capacityClient, lifetime: configuration.StorageCapacityReservationTTL,
		},
		Verifier:      verifier,
		ReceiptSigner: signer,
		Clock:         clock,
	}
	return runtime, nil
}

func loadJobCustodyDeploymentAuthority(
	configuration config.Config,
) (*serviceauthority.DeploymentSigner, error) {
	signer, err := serviceauthority.LoadDeploymentSigner(
		configuration.DeploymentID,
		configuration.DeploymentSigningKeyFile,
	)
	if err != nil {
		return nil, fmt.Errorf("Job custody deployment signing authority rejected: %w", err)
	}
	template, err := serviceauthority.LoadDeploymentOfferTemplate(
		configuration.DeploymentRoutePolicyFile,
		signer,
	)
	if err != nil {
		return nil, fmt.Errorf("Job custody route policy rejected: %w", err)
	}
	if !template.ContainsControlEndpoint(configuration.PublicURL) {
		return nil, fmt.Errorf("Job custody route policy rejected: %w", serviceauthority.ErrInvalid)
	}
	return signer, nil
}

func validateJobCustodyConfiguration(configuration config.Config) error {
	if configuration.Service != config.JobCustody || configuration.DatabaseURL == "" ||
		configuration.ListenAddress == "" || configuration.PublicURL == "" ||
		configuration.DeploymentID == uuid.Nil || configuration.DeploymentSigningKeyFile == "" ||
		configuration.DeploymentRoutePolicyFile == "" || configuration.ServiceAuthorityBindingsFile == "" ||
		configuration.JobCustodyRoot == "" || configuration.JobCustodyAdmissionKeysFile == "" ||
		configuration.JobCustodyAdmissionAuthoritiesFile == "" ||
		configuration.StorageCapacityAuthorityURL == "" || configuration.StorageCapacityPoolID == uuid.Nil ||
		configuration.StorageCapacityReservationTTL < storageauthority.MinimumPrivateReservationLifetime ||
		configuration.StorageCapacityReservationTTL > storageauthority.MaximumPrivateReservationLifetime ||
		configuration.JobCustodyMaximumAdmissions <= 0 ||
		configuration.JobCustodyMaximumStagingBytes <= 0 ||
		configuration.JobCustodyMaximumCustodyBytes <= 0 ||
		configuration.JobCustodyMaximumStagingBytes > configuration.JobCustodyMaximumCustodyBytes ||
		configuration.BlobRoot != "" {
		return serviceauthority.ErrInvalid
	}
	return nil
}

var jobCustodyDatabaseTables = map[string]struct{}{
	"facets_job_custody_schema_migrations": {},
	"job_custody_ledger":                   {},
	"job_custody_admissions":               {},
	"job_custody_chunks":                   {},
}

func requireDedicatedJobCustodyDatabase(ctx context.Context, pool *pgxpool.Pool) error {
	rows, err := pool.Query(ctx, `
		SELECT class.relname
		FROM pg_catalog.pg_class AS class
		JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=class.relnamespace
		WHERE namespace.nspname='public' AND class.relkind IN ('r','p')
		ORDER BY class.relname
	`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var tables []string
	for rows.Next() {
		var table string
		if rows.Scan(&table) != nil {
			return serviceauthority.ErrInvalid
		}
		tables = append(tables, table)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return validateJobCustodyDatabaseTables(tables)
}

func validateJobCustodyDatabaseTables(tables []string) error {
	seen := make(map[string]struct{}, len(tables))
	for _, table := range tables {
		if _, allowed := jobCustodyDatabaseTables[table]; !allowed {
			return serviceauthority.ErrInvalid
		}
		if _, duplicate := seen[table]; duplicate {
			return serviceauthority.ErrInvalid
		}
		seen[table] = struct{}{}
	}
	return nil
}

func jobCustodyStoreLimits(configuration config.Config) postgres.JobCustodyStoreLimits {
	return postgres.JobCustodyStoreLimits{
		MaximumAdmissions:   configuration.JobCustodyMaximumAdmissions,
		MaximumStagingBytes: configuration.JobCustodyMaximumStagingBytes,
		MaximumCustodyBytes: configuration.JobCustodyMaximumCustodyBytes,
	}
}
