package postgres

import (
	"strings"
	"testing"
)

func TestJobCustodyMigrationIsIsolatedAndContentBlind(t *testing.T) {
	body, err := jobCustodyMigrationFiles.ReadFile("job_custody_migrations/001_job_custody.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, required := range []string{
		"job_custody_ledger", "job_custody_admissions", "job_custody_chunks",
		"envelope_record", "expected_signer_id", "protected_byte_count",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("Job Custody migration is missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"space_id", "object_id", "prompt", "model_id", "credential",
		"result", "account_id", "participant_id", "shared_spaces",
		"device_sync", "backup_custody", "ON DELETE CASCADE",
	} {
		if strings.Contains(strings.ToUpper(text), strings.ToUpper(forbidden)) {
			t.Fatalf("Job Custody migration contains forbidden authority or metadata %q", forbidden)
		}
	}
}
