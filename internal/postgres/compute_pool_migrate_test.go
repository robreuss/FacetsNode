package postgres

import (
	"strings"
	"testing"
)

func TestComputePoolMigrationsContainNoSpaceOrMembershipAuthority(t *testing.T) {
	contents, err := computePoolMigrationFiles.ReadFile(
		"compute_pool_migrations/001_compute_pool_authority.sql",
	)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ToLower(string(contents))
	for _, forbidden := range []string{
		"shared_space",
		"participant",
		"membership",
		"content_key",
		"device_sync",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("Compute Pool migration contains foreign authority %q", forbidden)
		}
	}
	for _, required := range []string{
		"create table compute_pools",
		"create table compute_pool_worker_enrollments",
		"create table compute_pool_offerings",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("Compute Pool migration is missing %q", required)
		}
	}
}
