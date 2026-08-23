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

func TestSharedSpaceComputeBindingMigrationContainsNoPoolAuthority(t *testing.T) {
	contents, err := migrationFiles.ReadFile(
		"migrations/029_shared_space_compute_bindings.sql",
	)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ToLower(string(contents))
	for _, forbidden := range []string{
		"create table compute_pools",
		"references compute_pools",
		"pool_payload",
		"worker_enrollment",
		"compute_offering",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("Shared Space binding migration contains Pool authority %q", forbidden)
		}
	}
	for _, required := range []string{
		"create table shared_space_compute_bindings",
		"create table shared_space_compute_binding_changes",
		"binding_id uuid not null",
		"pool_id uuid not null",
		"add column compute_binding_id uuid",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("Shared Space binding migration is missing %q", required)
		}
	}
}
