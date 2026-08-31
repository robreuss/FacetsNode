package postgres

import (
	"strings"
	"testing"
)

func TestBackupCustodyMigrationIsDedicatedAndHasNoCascadeDelete(t *testing.T) {
	body, err := backupCustodyMigrationFiles.ReadFile("backup_custody_migrations/001_backup_custody.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, required := range []string{"backup_custody_accounts", "backup_custody_targets", "backup_custody_uploads", "backup_custody_generations", "backup_custody_retention_receipts"} {
		if !strings.Contains(text, required) {
			t.Fatalf("missing %s", required)
		}
	}
	if strings.Contains(strings.ToUpper(text), "ON DELETE CASCADE") {
		t.Fatal("destructive cascade entered append-only schema")
	}
	for _, forbidden := range []string{"relay_tenants", "shared_spaces", "device_sync"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("schema coupled to %s", forbidden)
		}
	}
}
