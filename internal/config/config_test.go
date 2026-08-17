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
	t.Setenv("FACETS_NODE_BLOB_UPLOAD_TTL", "2h")
	t.Setenv("FACETS_NODE_BLOB_ORPHAN_GRACE", "15m")
	configuration, err = config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if configuration.BlobUploadTTL != 2*time.Hour || configuration.BlobOrphanGrace != 15*time.Minute {
		t.Fatalf("overrides ttl=%s grace=%s", configuration.BlobUploadTTL, configuration.BlobOrphanGrace)
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
