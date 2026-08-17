package config_test

import (
	"testing"
	"time"

	"github.com/robreuss/FacetsNode/internal/config"
)

func TestBlobMaintenanceDefaultsAndOverrides(t *testing.T) {
	t.Setenv("FACETS_NODE_DATABASE_URL", "postgres://example.invalid/facets")
	configuration, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if configuration.BlobUploadTTL != 7*24*time.Hour || configuration.BlobOrphanGrace != 24*time.Hour {
		t.Fatalf("defaults ttl=%s grace=%s", configuration.BlobUploadTTL, configuration.BlobOrphanGrace)
	}
	if configuration.CheckpointFenceTTL != 2*time.Hour {
		t.Fatalf("default checkpoint fence TTL=%s", configuration.CheckpointFenceTTL)
	}
	t.Setenv("FACETS_NODE_BLOB_UPLOAD_TTL", "2h")
	t.Setenv("FACETS_NODE_BLOB_ORPHAN_GRACE", "15m")
	t.Setenv("FACETS_NODE_CHECKPOINT_FENCE_TTL", "6h")
	configuration, err = config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if configuration.BlobUploadTTL != 2*time.Hour || configuration.BlobOrphanGrace != 15*time.Minute {
		t.Fatalf("overrides ttl=%s grace=%s", configuration.BlobUploadTTL, configuration.BlobOrphanGrace)
	}
	if configuration.CheckpointFenceTTL != 6*time.Hour {
		t.Fatalf("checkpoint fence override=%s", configuration.CheckpointFenceTTL)
	}
}

func TestCheckpointFenceTTLRejectsOutOfRangeDurations(t *testing.T) {
	t.Setenv("FACETS_NODE_DATABASE_URL", "postgres://example.invalid/facets")
	for _, value := range []string{"0s", "4m59s", "25h", "invalid"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("FACETS_NODE_CHECKPOINT_FENCE_TTL", value)
			if _, err := config.Load(); err == nil {
				t.Fatal("out-of-range checkpoint fence TTL accepted")
			}
		})
	}
}

func TestCheckpointFenceTTLAcceptsInclusiveBounds(t *testing.T) {
	for _, value := range []string{"5m", "24h"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("FACETS_NODE_DATABASE_URL", "postgres://example.invalid/facets")
			t.Setenv("FACETS_NODE_CHECKPOINT_FENCE_TTL", value)
			if _, err := config.Load(); err != nil {
				t.Fatalf("valid checkpoint fence TTL rejected: %v", err)
			}
		})
	}
}

func TestBlobMaintenanceRejectsNonPositiveDurations(t *testing.T) {
	t.Setenv("FACETS_NODE_DATABASE_URL", "postgres://example.invalid/facets")
	for _, variable := range []string{"FACETS_NODE_BLOB_UPLOAD_TTL", "FACETS_NODE_BLOB_ORPHAN_GRACE"} {
		t.Run(variable, func(t *testing.T) {
			t.Setenv(variable, "0s")
			if _, err := config.Load(); err == nil {
				t.Fatal("non-positive duration accepted")
			}
		})
	}
}
