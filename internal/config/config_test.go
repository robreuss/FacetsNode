package config_test

import (
	"bytes"
	"encoding/base64"
	"testing"
	"time"

	"github.com/google/uuid"

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
	managedKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	computeSeed := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x43}, 32))
	t.Setenv("FACETS_SHARED_SPACES_MANAGED_KEY_ENCRYPTION_KEY", managedKey)
	t.Setenv("FACETS_SHARED_SPACES_COMPUTE_CAPABILITY_SIGNING_SEED", computeSeed)
	t.Setenv("FACETS_SHARED_SPACES_PUBLIC_URL", "https://shared-spaces.example")

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
	if !bytes.Equal(sharedSpaces.ManagedKeyEncryptionKey, bytes.Repeat([]byte{0x42}, 32)) {
		t.Fatal("Shared Spaces managed key-encryption key was not decoded")
	}
	if !bytes.Equal(sharedSpaces.ComputeCapabilitySigningSeed, bytes.Repeat([]byte{0x43}, 32)) {
		t.Fatal("Shared Spaces compute capability signing seed was not decoded")
	}
	if sharedSpaces.PublicURL != "https://shared-spaces.example" {
		t.Fatalf("Shared Spaces public URL=%q", sharedSpaces.PublicURL)
	}
}

func TestSharedSpacesRequiresStrictManagedKeyEncryptionKey(t *testing.T) {
	t.Setenv("FACETS_SHARED_SPACES_DATABASE_URL", "postgres://example.invalid/shared_spaces")
	t.Setenv(
		"FACETS_SHARED_SPACES_COMPUTE_CAPABILITY_SIGNING_SEED",
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x43}, 32)),
	)
	t.Setenv("FACETS_SHARED_SPACES_PUBLIC_URL", "https://shared-spaces.example")
	for _, value := range []string{
		"",
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 31)),
		base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32)),
		"not-base64url",
	} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("FACETS_SHARED_SPACES_MANAGED_KEY_ENCRYPTION_KEY", value)
			if _, err := config.Load(config.SharedSpaces); err == nil {
				t.Fatal("invalid managed key-encryption key accepted")
			}
		})
	}
}

func TestSharedSpacesRequiresStrictComputeCapabilitySigningAuthority(t *testing.T) {
	t.Setenv("FACETS_SHARED_SPACES_DATABASE_URL", "postgres://example.invalid/shared_spaces")
	t.Setenv(
		"FACETS_SHARED_SPACES_MANAGED_KEY_ENCRYPTION_KEY",
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32)),
	)
	t.Setenv("FACETS_SHARED_SPACES_PUBLIC_URL", "https://shared-spaces.example")
	for _, value := range []string{
		"",
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x43}, 31)),
		base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{0x43}, 32)),
		"not-base64url",
	} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("FACETS_SHARED_SPACES_COMPUTE_CAPABILITY_SIGNING_SEED", value)
			if _, err := config.Load(config.SharedSpaces); err == nil {
				t.Fatal("invalid compute capability signing seed accepted")
			}
		})
	}
}

func TestSharedSpacesRequiresPublicURL(t *testing.T) {
	t.Setenv("FACETS_SHARED_SPACES_DATABASE_URL", "postgres://example.invalid/shared_spaces")
	t.Setenv(
		"FACETS_SHARED_SPACES_MANAGED_KEY_ENCRYPTION_KEY",
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32)),
	)
	t.Setenv(
		"FACETS_SHARED_SPACES_COMPUTE_CAPABILITY_SIGNING_SEED",
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x43}, 32)),
	)
	if _, err := config.Load(config.SharedSpaces); err == nil {
		t.Fatal("missing Shared Spaces public URL accepted")
	}
}

func TestDeviceSyncDoesNotConsumeSharedSpacesManagedKey(t *testing.T) {
	t.Setenv("FACETS_DEVICE_SYNC_DATABASE_URL", "postgres://example.invalid/device_sync")
	t.Setenv("FACETS_SHARED_SPACES_MANAGED_KEY_ENCRYPTION_KEY", "invalid")
	t.Setenv("FACETS_SHARED_SPACES_COMPUTE_CAPABILITY_SIGNING_SEED", "invalid")
	configuration, err := config.Load(config.DeviceSync)
	if err != nil {
		t.Fatal(err)
	}
	if configuration.ManagedKeyEncryptionKey != nil {
		t.Fatal("Device Sync consumed Shared Spaces key custody configuration")
	}
	if configuration.ComputeCapabilitySigningSeed != nil {
		t.Fatal("Device Sync consumed Shared Spaces compute signing configuration")
	}
}

func TestLegacyNodeEnvironmentIsNotACompatibilityFallback(t *testing.T) {
	t.Setenv("FACETS_NODE_DATABASE_URL", "postgres://example.invalid/legacy")
	if _, err := config.Load(config.DeviceSync); err == nil {
		t.Fatal("legacy Facets Node configuration unexpectedly enabled Device Sync")
	}
}

func TestDeploymentAuthenticationConfigurationIsAllOrNothing(t *testing.T) {
	t.Setenv("FACETS_DEVICE_SYNC_DATABASE_URL", "postgres://example.invalid/device_sync")
	deploymentID := uuid.MustParse("63000000-0000-0000-0000-000000000001")
	t.Setenv("FACETS_DEVICE_SYNC_DEPLOYMENT_ID", deploymentID.String())
	if _, err := config.Load(config.DeviceSync); err == nil {
		t.Fatal("partial deployment authentication configuration accepted")
	}
	t.Setenv(
		"FACETS_DEVICE_SYNC_DEPLOYMENT_SIGNING_KEY_FILE",
		"/var/lib/facets-device-sync/deployment-signing-key",
	)
	t.Setenv(
		"FACETS_DEVICE_SYNC_SERVICE_AUTHORITY_BINDINGS_FILE",
		"/var/lib/facets-device-sync/service-authority-bindings.json",
	)
	configuration, err := config.Load(config.DeviceSync)
	if err != nil {
		t.Fatal(err)
	}
	if configuration.DeploymentID != deploymentID ||
		configuration.DeploymentSigningKeyFile == "" ||
		configuration.ServiceAuthorityBindingsFile == "" {
		t.Fatalf("deployment authentication configuration=%+v", configuration)
	}
}

func TestUnsupportedServiceIsRejected(t *testing.T) {
	if _, err := config.Load(config.Service("other")); err == nil {
		t.Fatal("unsupported service accepted")
	}
}
