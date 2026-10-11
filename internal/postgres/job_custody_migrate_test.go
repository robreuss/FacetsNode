package postgres

import (
	"strings"
	"testing"
)

func TestJobCustodyMigrationIsIsolatedAndContentBlind(t *testing.T) {
	var body []byte
	for _, name := range []string{
		"job_custody_migrations/001_job_custody.sql",
		"job_custody_migrations/002_job_custody_receipts.sql",
		"job_custody_migrations/003_job_custody_worker_route.sql",
		"job_custody_migrations/004_job_custody_results.sql",
	} {
		part, err := jobCustodyMigrationFiles.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		body = append(body, part...)
	}
	text := string(body)
	for _, required := range []string{
		"job_custody_ledger", "job_custody_admissions", "job_custody_chunks",
		"job_custody_worker_claims", "job_custody_results", "job_custody_result_chunks",
		"envelope_record", "expected_signer_id",
		"protected_byte_count", "route_authority_id", "worker_capabilities_digest",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("Job Custody migration is missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"space_id", "object_id", "prompt", "model_id", "credential",
		"result_payload", "account_id", "participant_id", "shared_spaces",
		"device_sync", "backup_custody", "ON DELETE CASCADE",
	} {
		if strings.Contains(strings.ToUpper(text), strings.ToUpper(forbidden)) {
			t.Fatalf("Job Custody migration contains forbidden authority or metadata %q", forbidden)
		}
	}
}
