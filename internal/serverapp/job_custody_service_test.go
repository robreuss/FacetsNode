package serverapp

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/config"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

func TestJobCustodyConfigurationAndStoreLimitsRemainServiceLocal(t *testing.T) {
	configuration := config.Config{
		Service: config.JobCustody, ListenAddress: "127.0.0.1:8080",
		DatabaseURL: "postgres://job-custody", PublicURL: "https://job-custody.example",
		DeploymentID: uuid.New(), DeploymentSigningKeyFile: "/keys/deployment",
		DeploymentRoutePolicyFile: "/config/route.json", ServiceAuthorityBindingsFile: "/config/bindings.json",
		JobCustodyRoot: "/custody", JobCustodyAdmissionKeysFile: "/config/admission-keys.json",
		StorageCapacityAuthorityURL: "https://capacity.example", StorageCapacityPoolID: uuid.New(),
		StorageCapacityReservationTTL: 5 * time.Minute,
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
