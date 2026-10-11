package serverapp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"runtime"
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

type jobCustodyDatabaseReadiness interface {
	Ping(context.Context) error
}

type jobCustodyCapacityReadiness interface {
	Readiness(
		context.Context,
		storageauthority.PrivateReadinessRequest,
	) (storagecapacity.CoarseReadinessSnapshot, error)
}

// jobCustodyReadiness composes the dependencies required to continue serving
// already accepted custody. Capacity pressure must not make reads, delivery,
// acknowledgement, release, or cleanup unavailable.
type jobCustodyReadiness struct {
	database      jobCustodyDatabaseReadiness
	inputContent  *jobcustody.ContentStore
	resultContent *jobcustody.ContentStore
}

func (probe jobCustodyReadiness) Check(ctx context.Context) error {
	if ctx == nil || probe.database == nil || probe.inputContent == nil ||
		probe.resultContent == nil {
		return jobcustody.ErrUnavailable
	}
	if err := probe.database.Ping(ctx); err != nil {
		return jobcustody.ErrUnavailable
	}
	if err := probe.inputContent.Readiness(); err != nil {
		return jobcustody.ErrUnavailable
	}
	if err := probe.resultContent.Readiness(); err != nil {
		return jobcustody.ErrUnavailable
	}
	return nil
}

// jobCustodyAdmissionReadiness returns only the shared authority's coarse,
// content-blind admission state. It is advisory: only atomic reservation can
// grant capacity to a new admission.
type jobCustodyAdmissionReadiness struct {
	capacity     jobCustodyCapacityReadiness
	newOperation func() uuid.UUID
}

func (probe jobCustodyAdmissionReadiness) Snapshot(
	ctx context.Context,
) (storagecapacity.CoarseReadinessSnapshot, error) {
	if ctx == nil || probe.capacity == nil || probe.newOperation == nil {
		return storagecapacity.CoarseReadinessSnapshot{}, jobcustody.ErrUnavailable
	}
	operationID := probe.newOperation()
	if operationID == uuid.Nil {
		return storagecapacity.CoarseReadinessSnapshot{}, jobcustody.ErrUnavailable
	}
	readiness, err := probe.capacity.Readiness(
		ctx,
		storageauthority.PrivateReadinessRequest{
			ProtocolVersion: storagecapacity.AuthorityProtocolVersion,
			OperationID:     operationID,
		},
	)
	if err != nil || readiness.Validate() != nil {
		return storagecapacity.CoarseReadinessSnapshot{}, jobcustody.ErrUnavailable
	}
	return readiness, nil
}

func runJobCustodyService(
	rootContext context.Context,
	pool *pgxpool.Pool,
	configuration config.Config,
	logger *slog.Logger,
) error {
	if rootContext == nil || pool == nil || logger == nil ||
		validateJobCustodyConfiguration(configuration) != nil {
		return serviceauthority.ErrInvalid
	}
	startupContext, startupCancel := context.WithTimeout(rootContext, 30*time.Second)
	defer startupCancel()
	runtimeState, err := prepareJobCustodyRuntime(startupContext, pool, configuration)
	if err != nil {
		return err
	}
	releaseCustody := true
	defer func() {
		if releaseCustody {
			_ = runtimeState.Close()
		}
	}()
	if _, err := runtimeState.Delivery.ReconcilePendingReleases(
		startupContext, jobcustody.MaximumPendingResultReleaseBatchSize,
	); err != nil {
		return fmt.Errorf("Job custody pending result release reconciliation failed: %w", err)
	}
	if _, err := runtimeState.Delivery.ReconcileExpiredResults(
		startupContext, jobcustody.MaximumResultExpiryBatchSize,
	); err != nil {
		return fmt.Errorf("Job custody expired result reconciliation failed: %w", err)
	}
	if _, err := runtimeState.InputExpiry.ReconcileExpiredAdmissions(
		startupContext, jobcustody.MaximumAdmissionExpiryBatchSize,
	); err != nil {
		return fmt.Errorf("Job custody expired input reconciliation failed: %w", err)
	}
	readinessProbe := jobCustodyReadiness{
		database: pool, inputContent: runtimeState.content,
		resultContent: runtimeState.resultContent,
	}
	readiness := func(ctx context.Context) error {
		readinessContext, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return readinessProbe.Check(readinessContext)
	}
	admissionReadinessProbe := jobCustodyAdmissionReadiness{
		capacity: runtimeState.capacityReadiness, newOperation: uuid.New,
	}
	admissionReadiness := func(ctx context.Context) (storagecapacity.CoarseReadinessSnapshot, error) {
		readinessContext, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return admissionReadinessProbe.Snapshot(readinessContext)
	}
	handler, err := jobcustody.NewHTTPHandler(
		runtimeState.Coordinator,
		runtimeState.WorkerClaims,
		runtimeState.Results,
		runtimeState.Delivery,
		runtimeState.AdmissionPermits,
		configuration.TrafficLimits,
		readiness,
		admissionReadiness,
	)
	if err != nil {
		return fmt.Errorf("Job custody HTTP authority rejected: %w", err)
	}
	server := newJobCustodyHTTPServer(configuration, handler.Handler())
	maintenanceContext, stopMaintenance := context.WithCancel(rootContext)
	maintenanceDone := make(chan struct{})
	go func() {
		defer close(maintenanceDone)
		jobCustodyMaintenanceLoop(
			maintenanceContext, runtimeState.Delivery, runtimeState.InputExpiry,
			configuration.CleanupPeriod, logger,
		)
	}()
	serverErrors := make(chan error, 1)
	go func() {
		logger.Info(
			"Facets Job Custody Service listening",
			"address", configuration.ListenAddress,
			"go_version", runtime.Version(),
			"deployment_id", configuration.DeploymentID,
			"signing_key_fingerprint", runtimeState.Coordinator.ReceiptSigner.SigningKeyFingerprint(),
		)
		serverErrors <- server.ListenAndServe()
	}()
	retainCustody, err := finishJobCustodyHTTPServer(
		rootContext, server, serverErrors, configuration.ShutdownPeriod,
	)
	stopMaintenance()
	<-maintenanceDone
	if retainCustody {
		// A forced-close handler may still own the database or private content
		// root. Keep process-scoped custody until Main exits rather than admit a
		// second writer over an unwinding request.
		releaseCustody = false
	}
	if err != nil {
		return err
	}
	logger.Info("Job custody shutdown complete")
	return nil
}

func jobCustodyMaintenanceLoop(
	ctx context.Context,
	delivery *jobcustody.ResultDeliveryCoordinator,
	inputExpiry *jobcustody.AdmissionExpiryCoordinator,
	period time.Duration,
	logger *slog.Logger,
) {
	if ctx == nil || delivery == nil || inputExpiry == nil || period <= 0 || logger == nil {
		return
	}
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reconcileContext, cancel := context.WithTimeout(ctx, 30*time.Second)
			err := reconcileAllPendingJobCustodyReleases(reconcileContext, delivery)
			if err == nil {
				err = reconcileAllExpiredJobCustodyResults(reconcileContext, delivery)
			}
			if err == nil {
				err = reconcileAllExpiredJobCustodyAdmissions(reconcileContext, inputExpiry)
			}
			cancel()
			if err != nil && !errors.Is(err, context.Canceled) {
				logger.Warn("Job custody maintenance failed", "error", err)
			}
		}
	}
}

func reconcileAllExpiredJobCustodyAdmissions(
	ctx context.Context,
	coordinator *jobcustody.AdmissionExpiryCoordinator,
) error {
	if ctx == nil || coordinator == nil {
		return jobcustody.ErrInvalid
	}
	for {
		completed, err := coordinator.ReconcileExpiredAdmissions(
			ctx, jobcustody.MaximumAdmissionExpiryBatchSize,
		)
		if err != nil {
			return err
		}
		if completed < jobcustody.MaximumAdmissionExpiryBatchSize {
			return nil
		}
	}
}

func reconcileAllExpiredJobCustodyResults(
	ctx context.Context,
	delivery *jobcustody.ResultDeliveryCoordinator,
) error {
	if ctx == nil || delivery == nil {
		return jobcustody.ErrInvalid
	}
	for {
		completed, err := delivery.ReconcileExpiredResults(
			ctx, jobcustody.MaximumResultExpiryBatchSize,
		)
		if err != nil {
			return err
		}
		if completed < jobcustody.MaximumResultExpiryBatchSize {
			return nil
		}
	}
}

func reconcileAllPendingJobCustodyReleases(
	ctx context.Context,
	delivery *jobcustody.ResultDeliveryCoordinator,
) error {
	if ctx == nil || delivery == nil {
		return jobcustody.ErrInvalid
	}
	for {
		completed, err := delivery.ReconcilePendingReleases(
			ctx, jobcustody.MaximumPendingResultReleaseBatchSize,
		)
		if err != nil {
			return err
		}
		if completed < jobcustody.MaximumPendingResultReleaseBatchSize {
			return nil
		}
	}
}

func newJobCustodyHTTPServer(
	configuration config.Config,
	handler http.Handler,
) *http.Server {
	return &http.Server{
		Addr:              configuration.ListenAddress,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       configuration.TransferPeriod,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}
}

func finishJobCustodyHTTPServer(
	rootContext context.Context,
	server *http.Server,
	serverErrors <-chan error,
	shutdownPeriod time.Duration,
) (bool, error) {
	var serveErr error
	select {
	case <-rootContext.Done():
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			serveErr = fmt.Errorf("Job custody HTTP server failed: %w", err)
		}
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), shutdownPeriod)
	defer cancel()
	if err := server.Shutdown(shutdownContext); err != nil {
		_ = server.Close()
		return true, errors.Join(
			serveErr,
			fmt.Errorf("Job custody graceful shutdown failed: %w", err),
		)
	}
	return false, serveErr
}

// jobCustodyRuntime owns the service-local database, private filesystem, trust
// configuration, and physical-capacity client. It deliberately has no HTTP
// admission handler: transport authentication must supply the expected signer
// and route grant rather than accepting requester-echoed trust fields.
type jobCustodyRuntime struct {
	Coordinator       *jobcustody.Coordinator
	WorkerClaims      *jobcustody.WorkerClaimCoordinator
	Results           *jobcustody.ResultCoordinator
	Delivery          *jobcustody.ResultDeliveryCoordinator
	InputExpiry       *jobcustody.AdmissionExpiryCoordinator
	AdmissionPermits  *jobcustody.AdmissionPermitVerifier
	capacityReadiness jobCustodyCapacityReadiness
	content           *jobcustody.ContentStore
	resultContent     *jobcustody.ContentStore
	bindings          *serviceauthority.BindingRegistry
}

func (runtime *jobCustodyRuntime) Close() error {
	if runtime == nil {
		return nil
	}
	var failures []error
	if runtime.content != nil {
		failures = append(failures, runtime.content.Close())
	}
	if runtime.resultContent != nil {
		failures = append(failures, runtime.resultContent.Close())
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
	runtime.capacityReadiness = capacityClient
	content, err := jobcustody.OpenContentStore(configuration.JobCustodyRoot)
	if err != nil {
		return nil, fmt.Errorf("Job custody protected object store rejected: %w", err)
	}
	runtime.content = content
	resultContent, err := jobcustody.OpenContentStore(
		filepath.Join(configuration.JobCustodyRoot, "results"),
	)
	if err != nil {
		return nil, fmt.Errorf("Job custody protected result store rejected: %w", err)
	}
	runtime.resultContent = resultContent
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
	runtime.WorkerClaims = &jobcustody.WorkerClaimCoordinator{
		Ledger: ledger, Content: content, Clock: clock,
	}
	runtime.Results = &jobcustody.ResultCoordinator{
		Ledger: ledger, Content: resultContent,
		Capacity: jobCustodyCapacityAuthority{
			client: capacityClient, lifetime: configuration.StorageCapacityReservationTTL,
		},
		ReceiptSigner: signer, Clock: clock,
	}
	runtime.Delivery = &jobcustody.ResultDeliveryCoordinator{
		Ledger: ledger, Content: resultContent, ReceiptSigner: signer, Clock: clock,
	}
	runtime.InputExpiry = &jobcustody.AdmissionExpiryCoordinator{
		Ledger: ledger, Content: content, ReceiptSigner: signer, Clock: clock,
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
		configuration.BlobRoot != "" || configuration.TransferPeriod <= 0 ||
		configuration.ShutdownPeriod <= 0 || configuration.CleanupPeriod <= 0 {
		return serviceauthority.ErrInvalid
	}
	return nil
}

var jobCustodyDatabaseTables = map[string]struct{}{
	"facets_job_custody_schema_migrations": {},
	"job_custody_ledger":                   {},
	"job_custody_admissions":               {},
	"job_custody_chunks":                   {},
	"job_custody_worker_claims":            {},
	"job_custody_results":                  {},
	"job_custody_result_chunks":            {},
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
