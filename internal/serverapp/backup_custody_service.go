package serverapp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/robreuss/FacetsNode/internal/backupcustody"
	"github.com/robreuss/FacetsNode/internal/config"
	"github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

type backupCustodyWallClock struct{}

func (backupCustodyWallClock) Now() time.Time { return time.Now() }

type backupCustodyStandby struct {
	accountID  uuid.UUID
	claimID    uuid.UUID
	admission  backupcustody.AccountAdmissionReference
	enrollment serviceauthority.InitialEnrollment
}

type backupCustodyDurableAuthority struct {
	revision     uint64
	digest       string
	deploymentID uuid.UUID
	state        string
}

type backupCustodyAuthorityHealth struct {
	mu        sync.Mutex
	healthy   atomic.Bool
	reconcile func(context.Context) error
	timeout   time.Duration
}

func newBackupCustodyAuthorityHealth(
	timeout time.Duration,
	reconcile func(context.Context) error,
) *backupCustodyAuthorityHealth {
	health := &backupCustodyAuthorityHealth{reconcile: reconcile, timeout: timeout}
	health.healthy.Store(true)
	return health
}

func (health *backupCustodyAuthorityHealth) reconcileAfterProvision() error {
	health.mu.Lock()
	defer health.mu.Unlock()
	// This is an authority-state linearization, not part of the caller's
	// transport lifetime. Bound it independently so cancellation cannot turn a
	// sound durable provision into a process-wide readiness failure. Serializing
	// also prevents an older result from overwriting a newer health result.
	ctx, cancel := context.WithTimeout(context.Background(), health.timeout)
	defer cancel()
	err := health.reconcile(ctx)
	health.healthy.Store(err == nil)
	return err
}

func (health *backupCustodyAuthorityHealth) check() error {
	if health == nil || !health.healthy.Load() {
		return serviceauthority.ErrBindingUnavailable
	}
	return nil
}

func runBackupCustodyService(
	rootContext context.Context,
	pool *pgxpool.Pool,
	configuration config.Config,
	logger *slog.Logger,
) error {
	if err := validateBackupCustodyConfiguration(configuration); err != nil {
		return err
	}
	startupContext, startupCancel := context.WithTimeout(rootContext, 30*time.Second)
	defer startupCancel()
	if err := requireDedicatedBackupCustodyDatabase(startupContext, pool); err != nil {
		return fmt.Errorf("Backup custody dedicated database rejected: %w", err)
	}
	if err := postgres.MigrateBackupCustody(startupContext, pool); err != nil {
		return fmt.Errorf("Backup custody database migration failed: %w", err)
	}
	if err := requireDedicatedBackupCustodyDatabase(startupContext, pool); err != nil {
		return fmt.Errorf("Backup custody dedicated database rejected after migration: %w", err)
	}
	signer, err := loadBackupCustodyDeploymentAuthority(configuration)
	if err != nil {
		return err
	}
	bindings, err := serviceauthority.LoadBindingRegistry(
		configuration.ServiceAuthorityBindingsFile,
		configuration.DeploymentID,
	)
	if err != nil {
		return fmt.Errorf("Backup custody authority bindings rejected: %w", err)
	}
	releaseCustody := true
	defer func() {
		if releaseCustody {
			_ = bindings.Close()
		}
	}()
	authority, err := loadBackupAccountAdmissionAuthority(
		configuration.BackupAccountAdmissionKeyFile,
		configuration.DeploymentID,
	)
	if err != nil {
		return fmt.Errorf("Backup account admission authority rejected: %w", err)
	}
	content, err := backupcustody.OpenContentStore(configuration.BackupCustodyRoot)
	if err != nil {
		return fmt.Errorf("Backup ciphertext custody rejected: %w", err)
	}
	defer func() {
		if releaseCustody {
			_ = content.Close()
		}
	}()
	journalPath := filepath.Join(
		filepath.Dir(configuration.ServiceAuthorityBindingsFile),
		"backup-account-claims",
	)
	journal, err := backupcustody.OpenPreparedAccountJournal(journalPath)
	if err != nil {
		return fmt.Errorf("Backup prepared-account custody rejected: %w", err)
	}
	defer func() {
		if releaseCustody {
			_ = journal.Close()
		}
	}()
	store, err := postgres.NewBackupCustodyStore(
		pool,
		configuration.DeploymentID,
		backupCustodyStoreLimits(configuration),
	)
	if err != nil {
		return fmt.Errorf("Backup custody store limits rejected: %w", err)
	}
	clock := backupCustodyWallClock{}
	provisioning := &backupcustody.ProvisioningCustody{
		Store:    store,
		Journal:  journal,
		Registry: bindings,
		Signer:   signer,
		Clock:    clock,
	}
	if err := recoverBackupCustodyStandbyAccounts(
		startupContext,
		pool,
		store,
		provisioning,
		authority,
	); err != nil {
		return fmt.Errorf("Backup standby account recovery rejected: %w", err)
	}
	if err := reconcileBackupCustodyAuthorityState(
		startupContext,
		pool,
		store,
		bindings,
		configuration.DeploymentID,
	); err != nil {
		return fmt.Errorf("Backup custody authority readiness rejected: %w", err)
	}
	authorityHealth := newBackupCustodyAuthorityHealth(
		30*time.Second,
		func(ctx context.Context) error {
			return reconcileBackupCustodyAuthorityState(
				ctx,
				pool,
				store,
				bindings,
				configuration.DeploymentID,
			)
		},
	)
	readiness := func(ctx context.Context) error {
		readinessContext, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := pool.Ping(readinessContext); err != nil {
			return err
		}
		if err := authorityHealth.check(); err != nil {
			return err
		}
		if err := probeBackupCustodyRegistry(bindings); err != nil {
			authorityHealth.healthy.Store(false)
			return err
		}
		return nil
	}
	afterProvision := func() error {
		return authorityHealth.reconcileAfterProvision()
	}
	coordinator := &backupcustody.Coordinator{
		Store:                  store,
		Content:                content,
		Registry:               bindings,
		Signer:                 signer,
		AuthorityHistory:       store,
		Clock:                  clock,
		MaximumChunkBytes:      uint64(configuration.BackupMaximumChunkBytes),
		MaximumGenerationBytes: uint64(configuration.BackupMaximumGenerationBytes),
		NewID:                  uuid.New,
	}
	handler, err := backupcustody.NewHTTPHandler(
		coordinator,
		provisioning,
		authority,
		signer,
		bindings,
		uint64(configuration.BackupMaximumChunkBytes),
		configuration.TransferPeriod,
		configuration.TrafficLimits,
		readiness,
		afterProvision,
	)
	if err != nil {
		return fmt.Errorf("Backup custody HTTP authority rejected: %w", err)
	}
	server := newBackupCustodyHTTPServer(configuration, handler.Handler())
	serverErrors := make(chan error, 1)
	go func() {
		logger.Info(
			"Facets Backup Custody Service listening",
			"address", configuration.ListenAddress,
			"go_version", runtime.Version(),
			"deployment_id", configuration.DeploymentID,
			"signing_key_fingerprint", signer.SigningKeyFingerprint(),
		)
		serverErrors <- server.ListenAndServe()
	}()
	retainCustody, err := finishBackupCustodyHTTPServer(
		rootContext, server, serverErrors, configuration.ShutdownPeriod,
	)
	if retainCustody {
		// Keep exclusive authority/content custody held until Main immediately
		// calls os.Exit. Closing these resources while a forced-close handler is
		// still unwinding could admit a second writer.
		releaseCustody = false
	}
	if err != nil {
		return err
	}
	logger.Info("Backup custody shutdown complete")
	return nil
}

func finishBackupCustodyHTTPServer(
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
			serveErr = fmt.Errorf("Backup custody HTTP server failed: %w", err)
		}
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), shutdownPeriod)
	defer cancel()
	retainCustody, shutdownErr := shutdownBackupCustodyHTTPServer(server, shutdownContext)
	if shutdownErr != nil {
		return retainCustody, errors.Join(
			serveErr,
			fmt.Errorf("Backup custody graceful shutdown failed: %w", shutdownErr),
		)
	}
	return false, serveErr
}

func loadBackupCustodyDeploymentAuthority(configuration config.Config) (*serviceauthority.DeploymentSigner, error) {
	signer, err := serviceauthority.LoadDeploymentSigner(
		configuration.DeploymentID,
		configuration.DeploymentSigningKeyFile,
	)
	if err != nil {
		return nil, fmt.Errorf("Backup custody deployment signing authority rejected: %w", err)
	}
	template, err := serviceauthority.LoadDeploymentOfferTemplate(
		configuration.DeploymentRoutePolicyFile,
		signer,
	)
	if err != nil {
		return nil, fmt.Errorf("Backup custody route policy rejected: %w", err)
	}
	if !template.ContainsControlEndpoint(configuration.PublicURL) {
		return nil, fmt.Errorf("Backup custody route policy rejected: %w", serviceauthority.ErrInvalid)
	}
	return signer, nil
}

func newBackupCustodyHTTPServer(configuration config.Config, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              configuration.ListenAddress,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       configuration.TransferPeriod,
		// Reads stream authenticated opaque generations of up to the configured
		// generation limit. An absolute WriteTimeout would truncate legitimate
		// local or hosted restores; bounded storage concurrency and shutdown own
		// the long-lived response instead.
		WriteTimeout:   0,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 16 * 1024,
	}
}

// shutdownBackupCustodyHTTPServer reports whether process-scoped custody must
// remain held until immediate process exit. A handler that ignores cancellation
// can outlive both Shutdown and Close; releasing writer/authority locks then
// would allow a second process to overlap it.
func shutdownBackupCustodyHTTPServer(server *http.Server, ctx context.Context) (bool, error) {
	if err := server.Shutdown(ctx); err != nil {
		_ = server.Close()
		return true, err
	}
	return false, nil
}

func validateBackupCustodyConfiguration(configuration config.Config) error {
	if configuration.Service != config.BackupCustody || configuration.DatabaseURL == "" ||
		configuration.DeploymentID == uuid.Nil || configuration.DeploymentSigningKeyFile == "" ||
		configuration.DeploymentRoutePolicyFile == "" || configuration.ServiceAuthorityBindingsFile == "" ||
		configuration.BackupAccountAdmissionKeyFile == "" || configuration.BackupCustodyRoot == "" ||
		configuration.BlobRoot != "" || configuration.BackupMaximumChunkBytes <= 0 ||
		configuration.BackupMaximumGenerationBytes <= 0 || configuration.TransferPeriod <= 0 {
		return serviceauthority.ErrInvalid
	}
	return nil
}

var backupCustodyDatabaseTables = map[string]struct{}{
	"facets_backup_custody_schema_migrations":     {},
	"backup_custody_accounts":                     {},
	"backup_custody_requests":                     {},
	"backup_custody_authority_history":            {},
	"backup_custody_account_control":              {},
	"backup_custody_control_commands":             {},
	"backup_custody_targets":                      {},
	"backup_custody_credential_grants":            {},
	"backup_custody_credential_grant_transitions": {},
	"backup_custody_uploads":                      {},
	"backup_custody_generations":                  {},
	"backup_custody_upload_chunks":                {},
	"backup_custody_retention_receipts":           {},
}

func requireDedicatedBackupCustodyDatabase(ctx context.Context, pool *pgxpool.Pool) error {
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
	return validateBackupCustodyDatabaseTables(tables)
}

func validateBackupCustodyDatabaseTables(tables []string) error {
	seen := make(map[string]struct{}, len(tables))
	for _, table := range tables {
		if _, allowed := backupCustodyDatabaseTables[table]; !allowed {
			return serviceauthority.ErrInvalid
		}
		if _, duplicate := seen[table]; duplicate {
			return serviceauthority.ErrInvalid
		}
		seen[table] = struct{}{}
	}
	return nil
}

func backupCustodyStoreLimits(configuration config.Config) postgres.BackupCustodyStoreLimits {
	return postgres.BackupCustodyStoreLimits{
		MaximumActiveUploads:                  configuration.BackupMaximumActiveUploads,
		MaximumTargets:                        configuration.BackupMaximumTargets,
		MaximumGenerations:                    configuration.BackupMaximumGenerations,
		MaximumRequests:                       configuration.BackupMaximumRequests,
		MaximumRetentionProofs:                configuration.BackupMaximumRetentionProofs,
		MaximumControlRecords:                 configuration.BackupMaximumControlRecords,
		MaximumCredentialLifetimeMilliseconds: configuration.BackupMaximumCredentialLifetime.Milliseconds(),
		MaximumChunksPerUpload:                configuration.BackupMaximumChunksPerUpload,
		MaximumChunkBytes:                     configuration.BackupMaximumChunkBytes,
		MaximumStagingBytes:                   configuration.BackupMaximumStagingBytes,
		MaximumCommittedBytes:                 configuration.BackupMaximumCommittedBytes,
	}
}

func recoverBackupCustodyStandbyAccounts(
	ctx context.Context,
	pool *pgxpool.Pool,
	store *postgres.BackupCustodyStore,
	provisioning *backupcustody.ProvisioningCustody,
	authority *backupAccountAdmissionAuthority,
) error {
	// The journal deliberately exposes exact-account lookup only. Prepared-only
	// claims with no DB row are resumed by the client's exact claim replay; this
	// checkpoint makes no global orphan-enumeration or cleanup claim.
	accounts, err := loadBackupCustodyAccounts(ctx, pool, store)
	if err != nil {
		return err
	}
	for _, account := range accounts {
		if account.state != backupcustody.AccountStateStandby {
			continue
		}
		candidate := backupCustodyStandby{
			accountID: account.record.AccountID,
			claimID:   account.record.ClaimID,
			admission: account.record.Admission,
		}
		if decodeCanonicalStored(account.record.InitialEnrollmentRecord, &candidate.enrollment) != nil {
			return serviceauthority.ErrInvalid
		}
		credential, err := authority.credential(
			candidate.admission,
			authority.deploymentID,
			candidate.enrollment.DeploymentOffer,
		)
		if err != nil || !authority.VerifyAccountAdmission(credential, candidate.enrollment) {
			return serviceauthority.ErrInvalid
		}
		if err := provisioning.ProvisionAccount(
			ctx,
			credential,
			candidate.claimID,
			candidate.enrollment,
			account.record.InitialControlAnchor,
		); err != nil {
			return err
		}
	}
	return nil
}

func reconcileBackupCustodyAuthorityState(
	ctx context.Context,
	pool *pgxpool.Pool,
	store *postgres.BackupCustodyStore,
	bindings *serviceauthority.BindingRegistry,
	deploymentID uuid.UUID,
) error {
	identities, err := bindings.CurrentBindingIdentities(serviceauthority.ScopeBackupCustody)
	if err != nil {
		return err
	}
	for _, foreignKind := range []serviceauthority.ScopeKind{
		serviceauthority.ScopeDeviceSync,
		serviceauthority.ScopeSharedSpace,
		serviceauthority.ScopeComputePool,
	} {
		foreign, err := bindings.CurrentBindingIdentities(foreignKind)
		if err != nil || len(foreign) != 0 {
			return serviceauthority.ErrBindingUnavailable
		}
	}
	durable := make(map[uuid.UUID]backupCustodyDurableAuthority)
	accounts, err := loadBackupCustodyAccounts(ctx, pool, store)
	if err != nil {
		return err
	}
	for _, account := range accounts {
		if err := store.ValidateControlLedger(ctx, account.record.AccountID); err != nil {
			return serviceauthority.ErrBindingUnavailable
		}
		current := backupCustodyDurableAuthority{
			revision:     account.record.AuthorityRevision,
			digest:       account.record.AuthorityManifestDigest,
			deploymentID: account.record.DeploymentID,
			state:        account.state,
		}
		if account.record.AccountID == uuid.Nil || current.revision == 0 ||
			current.deploymentID != deploymentID || current.state != backupcustody.AccountStateWritable {
			return serviceauthority.ErrBindingUnavailable
		}
		if _, duplicate := durable[account.record.AccountID]; duplicate {
			return serviceauthority.ErrBindingUnavailable
		}
		durable[account.record.AccountID] = current
	}
	if len(durable) != len(identities) {
		return serviceauthority.ErrBindingUnavailable
	}
	for _, identity := range identities {
		current, exists := durable[identity.Scope.ScopeID]
		if !exists || identity.Scope.Kind != serviceauthority.ScopeBackupCustody || identity.WriteFenced ||
			identity.TransitionEvidenceDigest != nil || current.revision != identity.Revision ||
			current.digest != identity.Digest || current.deploymentID != identity.DeploymentID {
			return serviceauthority.ErrBindingUnavailable
		}
	}
	return nil
}

func probeBackupCustodyRegistry(bindings *serviceauthority.BindingRegistry) error {
	if bindings == nil {
		return serviceauthority.ErrBindingUnavailable
	}
	if _, err := bindings.CurrentBindingIdentities(serviceauthority.ScopeBackupCustody); err != nil {
		return err
	}
	for _, foreignKind := range []serviceauthority.ScopeKind{
		serviceauthority.ScopeDeviceSync,
		serviceauthority.ScopeSharedSpace,
		serviceauthority.ScopeComputePool,
	} {
		foreign, err := bindings.CurrentBindingIdentities(foreignKind)
		if err != nil || len(foreign) != 0 {
			return serviceauthority.ErrBindingUnavailable
		}
	}
	return nil
}

type backupCustodyAccountSnapshot struct {
	record backupcustody.AccountRecord
	state  string
}

func loadBackupCustodyAccounts(
	ctx context.Context,
	pool *pgxpool.Pool,
	store *postgres.BackupCustodyStore,
) ([]backupCustodyAccountSnapshot, error) {
	type identity struct {
		accountID   uuid.UUID
		claimID     uuid.UUID
		admissionID uuid.UUID
		state       string
	}
	rows, err := pool.Query(ctx, `SELECT account_id,claim_id,admission_id,state FROM backup_custody_accounts ORDER BY account_id`)
	if err != nil {
		return nil, err
	}
	var identities []identity
	for rows.Next() {
		var candidate identity
		if err := rows.Scan(&candidate.accountID, &candidate.claimID, &candidate.admissionID, &candidate.state); err != nil ||
			candidate.accountID == uuid.Nil || candidate.claimID == uuid.Nil || candidate.admissionID == uuid.Nil ||
			(candidate.state != backupcustody.AccountStateStandby && candidate.state != backupcustody.AccountStateWritable) {
			rows.Close()
			return nil, serviceauthority.ErrInvalid
		}
		identities = append(identities, candidate)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	var snapshots []backupCustodyAccountSnapshot
	for _, candidate := range identities {
		record, loadedState, err := store.LoadAccountClaim(
			ctx,
			candidate.accountID,
			candidate.claimID,
			candidate.admissionID,
		)
		if err != nil || loadedState != candidate.state || record.AccountID != candidate.accountID ||
			record.ClaimID != candidate.claimID || record.Admission.AdmissionID != candidate.admissionID {
			return nil, serviceauthority.ErrInvalid
		}
		snapshots = append(snapshots, backupCustodyAccountSnapshot{record: record, state: candidate.state})
	}
	return snapshots, nil
}

func decodeCanonicalStored(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return serviceauthority.ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return serviceauthority.ErrInvalid
	}
	encoded, err := json.Marshal(target)
	if err != nil || !bytes.Equal(encoded, data) {
		return serviceauthority.ErrInvalid
	}
	return nil
}
