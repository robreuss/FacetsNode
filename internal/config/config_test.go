package config_test

import (
	"testing"
	"time"

	"github.com/robreuss/FacetsNode/internal/config"
	"github.com/robreuss/FacetsNode/internal/traffic"
)

func TestBlobMaintenanceDefaultsAndOverrides(t *testing.T) {
	t.Setenv("FACETS_DEVICE_SYNC_DATABASE_URL", "postgres://example.invalid/facets")
	configuration, err := config.Load(config.DeviceSync)
	if err != nil {
		t.Fatal(err)
	}
	if configuration.BlobUploadTTL != 7*24*time.Hour || configuration.BlobOrphanGrace != 24*time.Hour {
		t.Fatalf("defaults ttl=%s grace=%s", configuration.BlobUploadTTL, configuration.BlobOrphanGrace)
	}
	if configuration.CheckpointFenceTTL != 2*time.Hour {
		t.Fatalf("default checkpoint fence TTL=%s", configuration.CheckpointFenceTTL)
	}
	t.Setenv("FACETS_DEVICE_SYNC_BLOB_UPLOAD_TTL", "2h")
	t.Setenv("FACETS_DEVICE_SYNC_BLOB_ORPHAN_GRACE", "15m")
	t.Setenv("FACETS_DEVICE_SYNC_CHECKPOINT_FENCE_TTL", "6h")
	configuration, err = config.Load(config.DeviceSync)
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

func TestTrafficLimitDefaultsOverridesAndHardCaps(t *testing.T) {
	t.Setenv("FACETS_DEVICE_SYNC_DATABASE_URL", "postgres://example.invalid/facets")
	configuration, err := config.Load(config.DeviceSync)
	if err != nil {
		t.Fatal(err)
	}
	if configuration.TrafficLimits != traffic.DefaultLimits() {
		t.Fatalf("traffic defaults=%+v", configuration.TrafficLimits)
	}
	t.Setenv("FACETS_DEVICE_SYNC_TRAFFIC_RELAY_MESSAGE_RATE_PER_MINUTE", "42")
	t.Setenv("FACETS_DEVICE_SYNC_TRAFFIC_RELAY_MESSAGE_BURST", "7")
	t.Setenv("FACETS_DEVICE_SYNC_TRAFFIC_RELAY_MESSAGE_CONNECTION_RATE_PER_MINUTE", "84")
	t.Setenv("FACETS_DEVICE_SYNC_TRAFFIC_RELAY_MESSAGE_CONNECTION_BURST", "14")
	t.Setenv("FACETS_DEVICE_SYNC_TRAFFIC_RELAY_MESSAGE_CONCURRENCY", "3")
	configuration, err = config.Load(config.DeviceSync)
	if err != nil {
		t.Fatal(err)
	}
	if got := configuration.TrafficLimits[traffic.SurfaceRelayMessage]; got != (traffic.Limit{RequestsPerMinute: 42, Burst: 7, ConnectionRequestsPerMinute: 84, ConnectionBurst: 14, Concurrency: 3}) {
		t.Fatalf("relay message limits=%+v", got)
	}
	for name, value := range map[string]string{
		"FACETS_DEVICE_SYNC_TRAFFIC_RENDEZVOUS_RATE_PER_MINUTE":   "0",
		"FACETS_DEVICE_SYNC_TRAFFIC_STORAGE_BURST":                "10001",
		"FACETS_DEVICE_SYNC_TRAFFIC_MANAGEMENT_CONCURRENCY":       "1025",
		"FACETS_DEVICE_SYNC_TRAFFIC_CHECKPOINT_ADMIN_CONCURRENCY": "invalid",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, value)
			if _, err := config.Load(config.DeviceSync); err == nil {
				t.Fatalf("invalid %s=%q accepted", name, value)
			}
		})
	}
}

func TestCheckpointFenceTTLRejectsOutOfRangeDurations(t *testing.T) {
	t.Setenv("FACETS_DEVICE_SYNC_DATABASE_URL", "postgres://example.invalid/facets")
	for _, value := range []string{"0s", "4m59s", "25h", "invalid"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("FACETS_DEVICE_SYNC_CHECKPOINT_FENCE_TTL", value)
			if _, err := config.Load(config.DeviceSync); err == nil {
				t.Fatal("out-of-range checkpoint fence TTL accepted")
			}
		})
	}
}

func TestCheckpointFenceTTLAcceptsInclusiveBounds(t *testing.T) {
	for _, value := range []string{"5m", "24h"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("FACETS_DEVICE_SYNC_DATABASE_URL", "postgres://example.invalid/facets")
			t.Setenv("FACETS_DEVICE_SYNC_CHECKPOINT_FENCE_TTL", value)
			if _, err := config.Load(config.DeviceSync); err != nil {
				t.Fatalf("valid checkpoint fence TTL rejected: %v", err)
			}
		})
	}
}

func TestBlobMaintenanceRejectsNonPositiveDurations(t *testing.T) {
	t.Setenv("FACETS_DEVICE_SYNC_DATABASE_URL", "postgres://example.invalid/facets")
	for _, variable := range []string{"FACETS_DEVICE_SYNC_BLOB_UPLOAD_TTL", "FACETS_DEVICE_SYNC_BLOB_ORPHAN_GRACE"} {
		t.Run(variable, func(t *testing.T) {
			t.Setenv(variable, "0s")
			if _, err := config.Load(config.DeviceSync); err == nil {
				t.Fatal("non-positive duration accepted")
			}
		})
	}
}

func TestServicesUseIndependentEnvironmentNamespaces(t *testing.T) {
	t.Setenv("FACETS_DEVICE_SYNC_DATABASE_URL", "postgres://example.invalid/device_sync")
	t.Setenv("FACETS_DEVICE_SYNC_LISTEN_ADDR", ":8081")
	t.Setenv("FACETS_SHARED_SPACES_DATABASE_URL", "postgres://example.invalid/shared_spaces")
	t.Setenv("FACETS_SHARED_SPACES_LISTEN_ADDR", ":8082")

	deviceSync, err := config.Load(config.DeviceSync)
	if err != nil {
		t.Fatal(err)
	}
	sharedSpaces, err := config.Load(config.SharedSpaces)
	if err != nil {
		t.Fatal(err)
	}
	if deviceSync.Service != config.DeviceSync || deviceSync.ListenAddress != ":8081" || deviceSync.BlobRoot != "/var/lib/facets-device-sync/blobs" {
		t.Fatalf("device sync configuration=%+v", deviceSync)
	}
	if sharedSpaces.Service != config.SharedSpaces || sharedSpaces.ListenAddress != ":8082" || sharedSpaces.BlobRoot != "/var/lib/facets-shared-spaces/blobs" {
		t.Fatalf("shared spaces configuration=%+v", sharedSpaces)
	}
}

func TestLegacyNodeEnvironmentIsNotACompatibilityFallback(t *testing.T) {
	t.Setenv("FACETS_NODE_DATABASE_URL", "postgres://example.invalid/legacy")
	if _, err := config.Load(config.DeviceSync); err == nil {
		t.Fatal("legacy Facets Node configuration unexpectedly enabled Device Sync")
	}
}

func TestUnsupportedServiceIsRejected(t *testing.T) {
	if _, err := config.Load(config.Service("other")); err == nil {
		t.Fatal("unsupported service accepted")
	}
}
