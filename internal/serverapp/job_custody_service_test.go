package serverapp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/robreuss/FacetsNode/internal/computequeue"
	"github.com/robreuss/FacetsNode/internal/config"
	"github.com/robreuss/FacetsNode/internal/jobcustody"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
	"github.com/robreuss/FacetsNode/internal/testpostgres"
)

func TestJobCustodyConfigurationAndStoreLimitsRemainServiceLocal(t *testing.T) {
	configuration := config.Config{
		Service: config.JobCustody, ListenAddress: "127.0.0.1:8080",
		DatabaseURL: "postgres://job-custody", PublicURL: "https://job-custody.example",
		DeploymentID: uuid.New(), DeploymentSigningKeyFile: "/keys/deployment",
		DeploymentRoutePolicyFile: "/config/route.json", ServiceAuthorityBindingsFile: "/config/bindings.json",
		JobCustodyRoot: "/custody", JobCustodyAdmissionKeysFile: "/config/admission-keys.json",
		JobCustodyAdmissionAuthoritiesFile: "/config/admission-authorities.json",
		StorageCapacityAuthorityURL:        "https://capacity.example", StorageCapacityPoolID: uuid.New(),
		StorageCapacityReservationTTL: 5 * time.Minute,
		TransferPeriod:                time.Minute,
		ShutdownPeriod:                5 * time.Second,
		JobCustodyMaximumAdmissions:   11, JobCustodyMaximumStagingBytes: 12,
		JobCustodyMaximumCustodyBytes: 13,
	}
	if err := validateJobCustodyConfiguration(configuration); err != nil {
		t.Fatal(err)
	}
	limits := jobCustodyStoreLimits(configuration)
	if limits.MaximumAdmissions != 11 || limits.MaximumStagingBytes != 12 || limits.MaximumCustodyBytes != 13 {
		t.Fatalf("Job custody limits=%+v", limits)
	}
	configuration.JobCustodyMaximumCustodyBytes = 10
	if err := validateJobCustodyConfiguration(configuration); !errors.Is(err, serviceauthority.ErrInvalid) {
		t.Fatalf("inconsistent custody limits mapped to %v", err)
	}
}

func TestJobCustodyDatabaseTableAllowlistRejectsEveryForeignService(t *testing.T) {
	allowed := []string{
		"facets_job_custody_schema_migrations",
		"job_custody_ledger",
		"job_custody_admissions",
		"job_custody_chunks",
		"job_custody_worker_claims",
	}
	for name, tables := range map[string][]string{
		"empty":            nil,
		"Job Custody only": allowed,
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateJobCustodyDatabaseTables(tables); err != nil {
				t.Fatal(err)
			}
		})
	}
	for name, foreign := range map[string]string{
		"relay":        "relay_tenants",
		"Backup":       "backup_custody_accounts",
		"Device Sync":  "device_sync_principals",
		"Shared Space": "shared_space_participants",
		"Compute Pool": "compute_pool_jobs",
		"unknown":      "operator_notes",
	} {
		t.Run(name, func(t *testing.T) {
			tables := append(append([]string(nil), allowed...), foreign)
			if err := validateJobCustodyDatabaseTables(tables); err == nil {
				t.Fatalf("foreign table %q accepted", foreign)
			}
		})
	}
	if err := validateJobCustodyDatabaseTables([]string{"job_custody_ledger", "job_custody_ledger"}); err == nil {
		t.Fatal("duplicate catalog table identity accepted")
	}
}

func TestJobCustodyRuntimeAssemblyReopensExactIsolatedState(t *testing.T) {
	databaseURL := os.Getenv("FACETS_JOB_CUSTODY_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("FACETS_JOB_CUSTODY_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	databaseLock, err := testpostgres.AcquireDisposableDatabaseLock(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer databaseLock.Close()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	reset := func() {
		if _, err := pool.Exec(ctx, `
			DROP TABLE IF EXISTS job_custody_worker_claims,job_custody_chunks,job_custody_admissions,
				job_custody_ledger CASCADE;
			DROP TABLE IF EXISTS facets_job_custody_schema_migrations;
		`); err != nil {
			t.Fatal(err)
		}
	}
	reset()
	defer reset()
	configuration := writeJobCustodyRuntimeConfiguration(t, databaseURL)
	runtime, err := prepareJobCustodyRuntime(ctx, pool, configuration)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.Coordinator == nil || runtime.WorkerClaims == nil || runtime.AdmissionPermits == nil ||
		runtime.content == nil || runtime.bindings == nil {
		t.Fatal("Job custody runtime omitted a required authority or custody component")
	}
	if _, err := prepareJobCustodyRuntime(ctx, pool, configuration); err == nil {
		t.Fatal("a second runtime acquired the same authority and content custody")
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := prepareJobCustodyRuntime(ctx, pool, configuration)
	if err != nil {
		t.Fatalf("exact runtime restart rejected: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeJobCustodyRuntimeConfiguration(t *testing.T, databaseURL string) config.Config {
	t.Helper()
	root := t.TempDir()
	deploymentID := uuid.MustParse("8b000000-0000-0000-0000-000000000001")
	seed := bytes.Repeat([]byte{0}, 32)
	seed[31] = 7
	signer, err := serviceauthority.NewDeploymentSigner(deploymentID, seed)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "https://job-custody.example"
	routeID := uuid.MustParse("8b000000-0000-0000-0000-000000000002")
	route := serviceauthority.TransportRoute{
		Endpoint: endpoint, Kind: serviceauthority.RouteDirectHTTPS,
		NetworkScope: serviceauthority.NetworkPublic, RouteID: routeID,
		ServerAuthentication: serviceauthority.ServerAuthentication{Kind: "web_pki"},
	}
	template := serviceauthority.DeploymentOfferTemplate{
		Version: serviceauthority.SchemaVersion,
		Deployment: serviceauthority.DeploymentDescriptor{
			Version: serviceauthority.SchemaVersion, DeploymentID: deploymentID,
			CreatedAtMilliseconds: 900, PublicSigningKeyX963: signer.PublicSigningKeyX963(),
			SigningKeyFingerprint: signer.SigningKeyFingerprint(),
			Routes:                []serviceauthority.TransportRoute{route},
		},
		TransportPolicy: serviceauthority.TransportPolicy{
			Version: serviceauthority.SchemaVersion, AllowsPublicDirectBulkTransfer: true,
			ControlRouteIDs: []uuid.UUID{routeID}, MessageRouteIDs: []uuid.UUID{routeID},
			BulkRouteIDs: []uuid.UUID{routeID},
		},
	}
	signingPath := filepath.Join(root, "deployment-signing-key")
	routePath := filepath.Join(root, "deployment-route-policy.json")
	bindingPath := filepath.Join(root, "service-authority-bindings.json")
	admissionPath := filepath.Join(root, "admission-keys.json")
	authoritiesPath := filepath.Join(root, "admission-authorities.json")
	if err := os.WriteFile(signingPath, []byte(base64.RawURLEncoding.EncodeToString(seed)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeProtectedJSON(t, routePath, template, false)
	writeProtectedJSON(t, bindingPath, serviceauthority.BindingFile{
		Bindings: []serviceauthority.BindingFileEntry{}, Version: serviceauthority.SchemaVersion,
	}, false)
	sourceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeProtectedJSON(t, admissionPath, computequeue.JobCustodyAdmissionKeyFile{
		Keys: []computequeue.JobCustodyAdmissionKeyFileEntry{{
			PublicKeyX963: base64.RawURLEncoding.EncodeToString(elliptic.Marshal(
				elliptic.P256(), sourceKey.PublicKey.X, sourceKey.PublicKey.Y,
			)),
			Signer: computequeue.ReceiptSignerBinding{
				SignerID: "source.fixture", SigningKeyID: "source.fixture.key",
				SigningKeyRevision: 1,
				SignatureProfileID: computequeue.JobCustodyP256AdmissionSignatureProfile,
			},
		}},
		Version: computequeue.JobCustodyAdmissionKeyFileVersion,
	}, true)
	controllerPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeProtectedJSON(t, authoritiesPath, jobcustody.AdmissionPermitKeyFile{
		Authorities: []jobcustody.AdmissionPermitKeyFileEntry{{
			AuthorityID: uuid.MustParse("8c000000-0000-0000-0000-000000000001"),
			PublicKey:   base64.RawURLEncoding.EncodeToString(controllerPublicKey),
		}},
		Version: jobcustody.AdmissionPermitKeyFileVersion,
	}, true)
	return config.Config{
		Service: config.JobCustody, ListenAddress: "127.0.0.1:8080",
		DatabaseURL: databaseURL, PublicURL: endpoint,
		DeploymentID: deploymentID, DeploymentSigningKeyFile: signingPath,
		DeploymentRoutePolicyFile: routePath, ServiceAuthorityBindingsFile: bindingPath,
		JobCustodyRoot: filepath.Join(root, "custody"), JobCustodyAdmissionKeysFile: admissionPath,
		JobCustodyAdmissionAuthoritiesFile: authoritiesPath,
		StorageCapacityAuthorityURL:        "https://capacity.example",
		StorageCapacityPoolID:              uuid.MustParse("8a000000-0000-0000-0000-000000000001"),
		StorageCapacityReservationTTL:      5 * time.Minute,
		TransferPeriod:                     time.Minute,
		ShutdownPeriod:                     5 * time.Second,
		JobCustodyMaximumAdmissions:        10, JobCustodyMaximumStagingBytes: 1 << 20,
		JobCustodyMaximumCustodyBytes: 2 << 20,
	}
}

func writeProtectedJSON(t *testing.T, path string, value any, newline bool) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if newline {
		encoded = append(encoded, '\n')
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}
