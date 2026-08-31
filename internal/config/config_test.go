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
	configureDeviceSyncDeployment(t)
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

func TestDeviceSyncRequiresAtLeastTwoDatabaseConnections(t *testing.T) {
	configureDeviceSyncDeployment(t)
	t.Setenv("FACETS_DEVICE_SYNC_DATABASE_URL", "postgres://example.invalid/facets")
	t.Setenv("FACETS_DEVICE_SYNC_DATABASE_CONNS", "1")
	if _, err := config.Load(config.DeviceSync); err == nil {
		t.Fatal("Device Sync accepted a self-deadlocking one-connection pool")
	}
	t.Setenv("FACETS_DEVICE_SYNC_DATABASE_CONNS", "2")
	configuration, err := config.Load(config.DeviceSync)
	if err != nil {
		t.Fatalf("two-connection Device Sync pool rejected: %v", err)
	}
	if configuration.DatabaseConns != 2 {
		t.Fatalf("Device Sync database connections=%d", configuration.DatabaseConns)
	}
}

func TestTrafficLimitDefaultsOverridesAndHardCaps(t *testing.T) {
	configureDeviceSyncDeployment(t)
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
	configureDeviceSyncDeployment(t)
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
	configureDeviceSyncDeployment(t)
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
	configureDeviceSyncDeployment(t)
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
	configureDeviceSyncDeployment(t)
	t.Setenv("FACETS_DEVICE_SYNC_DATABASE_URL", "postgres://example.invalid/device_sync")
	t.Setenv("FACETS_DEVICE_SYNC_LISTEN_ADDR", ":8081")
	t.Setenv("FACETS_SHARED_SPACES_DATABASE_URL", "postgres://example.invalid/shared_spaces")
	t.Setenv("FACETS_SHARED_SPACES_LISTEN_ADDR", ":8082")
	managedKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	computeSeed := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x43}, 32))
	t.Setenv("FACETS_SHARED_SPACES_MANAGED_KEY_ENCRYPTION_KEY", managedKey)
	t.Setenv("FACETS_SHARED_SPACES_COMPUTE_CAPABILITY_SIGNING_SEED", computeSeed)
	t.Setenv("FACETS_SHARED_SPACES_PUBLIC_URL", "https://shared-spaces.example")
	configureComputePool(t)
	t.Setenv("FACETS_COMPUTE_POOL_LISTEN_ADDR", ":8083")
	configureBackupCustody(t)
	t.Setenv("FACETS_BACKUP_CUSTODY_LISTEN_ADDR", ":8084")

	deviceSync, err := config.Load(config.DeviceSync)
	if err != nil {
		t.Fatal(err)
	}
	sharedSpaces, err := config.Load(config.SharedSpaces)
	if err != nil {
		t.Fatal(err)
	}
	computePool, err := config.Load(config.ComputePool)
	if err != nil {
		t.Fatal(err)
	}
	backupCustody, err := config.Load(config.BackupCustody)
	if err != nil {
		t.Fatal(err)
	}
	if deviceSync.Service != config.DeviceSync || deviceSync.ListenAddress != ":8081" || deviceSync.BlobRoot != "/var/lib/facets-device-sync/blobs" {
		t.Fatalf("device sync configuration=%+v", deviceSync)
	}
	if sharedSpaces.Service != config.SharedSpaces || sharedSpaces.ListenAddress != ":8082" || sharedSpaces.BlobRoot != "/var/lib/facets-shared-spaces/blobs" {
		t.Fatalf("shared spaces configuration=%+v", sharedSpaces)
	}
	if computePool.Service != config.ComputePool || computePool.ListenAddress != ":8083" ||
		computePool.BlobRoot != "/var/lib/facets-compute-pool/blobs" {
		t.Fatalf("Compute Pool configuration=%+v", computePool)
	}
	if backupCustody.Service != config.BackupCustody || backupCustody.ListenAddress != ":8084" ||
		backupCustody.BlobRoot != "" || backupCustody.BackupCustodyRoot != "/var/lib/facets-backup-custody/custody" {
		t.Fatalf("Backup custody configuration=%+v", backupCustody)
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

func TestBackupCustodyRequiresIndependentAuthorityAndBoundedQuotas(t *testing.T) {
	t.Setenv("FACETS_BACKUP_CUSTODY_DATABASE_URL", "postgres://example.invalid/backup")
	if _, err := config.Load(config.BackupCustody); err == nil {
		t.Fatal("Backup custody without independent authority accepted")
	}
	configureBackupCustody(t)
	t.Setenv("FACETS_BACKUP_CUSTODY_CUSTODY_ROOT", "/srv/facets-backup/custody")
	t.Setenv("FACETS_BACKUP_CUSTODY_MAXIMUM_CHUNK_BYTES", "1048576")
	t.Setenv("FACETS_BACKUP_CUSTODY_MAXIMUM_GENERATION_BYTES", "4194304")
	t.Setenv("FACETS_BACKUP_CUSTODY_MAXIMUM_STAGING_BYTES", "8388608")
	t.Setenv("FACETS_BACKUP_CUSTODY_MAXIMUM_COMMITTED_BYTES", "16777216")
	t.Setenv("FACETS_BACKUP_CUSTODY_MAXIMUM_CHUNKS_PER_UPLOAD", "4")
	configuration, err := config.Load(config.BackupCustody)
	if err != nil {
		t.Fatal(err)
	}
	if configuration.BackupCustodyRoot != "/srv/facets-backup/custody" || configuration.BlobRoot != "" ||
		configuration.BackupMaximumChunkBytes != 1_048_576 || configuration.BackupMaximumGenerationBytes != 4_194_304 ||
		configuration.BackupMaximumChunksPerUpload != 4 {
		t.Fatalf("Backup limits=%+v", configuration)
	}
	for name, value := range map[string]string{
		"FACETS_BACKUP_CUSTODY_MAXIMUM_CHUNK_BYTES":       "0",
		"FACETS_BACKUP_CUSTODY_MAXIMUM_GENERATION_BYTES":  "9223372036854775808",
		"FACETS_BACKUP_CUSTODY_MAXIMUM_CHUNKS_PER_UPLOAD": "3",
	} {
		t.Run(name, func(t *testing.T) {
			configureBackupCustody(t)
			t.Setenv("FACETS_BACKUP_CUSTODY_MAXIMUM_CHUNK_BYTES", "1048576")
			t.Setenv("FACETS_BACKUP_CUSTODY_MAXIMUM_GENERATION_BYTES", "4194304")
			t.Setenv("FACETS_BACKUP_CUSTODY_MAXIMUM_STAGING_BYTES", "8388608")
			t.Setenv("FACETS_BACKUP_CUSTODY_MAXIMUM_COMMITTED_BYTES", "16777216")
			t.Setenv("FACETS_BACKUP_CUSTODY_MAXIMUM_CHUNKS_PER_UPLOAD", "4")
			t.Setenv(name, value)
			if _, err := config.Load(config.BackupCustody); err == nil {
				t.Fatalf("invalid %s=%s accepted", name, value)
			}
		})
	}
	for _, value := range []string{"67108864", "67108865"} {
		t.Run("chunk-hard-cap-"+value, func(t *testing.T) {
			configureBackupCustody(t)
			t.Setenv("FACETS_BACKUP_CUSTODY_MAXIMUM_CHUNK_BYTES", value)
			t.Setenv("FACETS_BACKUP_CUSTODY_MAXIMUM_GENERATION_BYTES", value)
			t.Setenv("FACETS_BACKUP_CUSTODY_MAXIMUM_STAGING_BYTES", value)
			t.Setenv("FACETS_BACKUP_CUSTODY_MAXIMUM_COMMITTED_BYTES", value)
			t.Setenv("FACETS_BACKUP_CUSTODY_MAXIMUM_CHUNKS_PER_UPLOAD", "1")
			_, err := config.Load(config.BackupCustody)
			if value == "67108864" && err != nil {
				t.Fatalf("64 MiB hard cap rejected: %v", err)
			}
			if value == "67108865" && err == nil {
				t.Fatal("chunk size above 64 MiB hard cap accepted")
			}
		})
	}
}

func TestComputePoolRequiresIndependentOperatorAndDeploymentAuthority(t *testing.T) {
	t.Setenv("FACETS_COMPUTE_POOL_DATABASE_URL", "postgres://example.invalid/compute_pool")
	if _, err := config.Load(config.ComputePool); err == nil {
		t.Fatal("Compute Pool without operator and deployment authority was accepted")
	}
	t.Setenv(
		"FACETS_COMPUTE_POOL_OPERATOR_TOKEN",
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x61}, 32)),
	)
	if _, err := config.Load(config.ComputePool); err == nil {
		t.Fatal("Compute Pool without deployment authority was accepted")
	}
	configureComputePool(t)
	configuration, err := config.Load(config.ComputePool)
	if err != nil {
		t.Fatal(err)
	}
	if configuration.DeploymentID == uuid.Nil || configuration.OperatorToken == "" {
		t.Fatalf("Compute Pool authority configuration=%+v", configuration)
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
	configureDeviceSyncDeployment(t)
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

func configureComputePool(t *testing.T) {
	t.Helper()
	t.Setenv("FACETS_COMPUTE_POOL_DATABASE_URL", "postgres://example.invalid/compute_pool")
	t.Setenv(
		"FACETS_COMPUTE_POOL_OPERATOR_TOKEN",
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x61}, 32)),
	)
	t.Setenv("FACETS_COMPUTE_POOL_DEPLOYMENT_ID", "87000000-0000-0000-0000-000000000001")
	t.Setenv(
		"FACETS_COMPUTE_POOL_DEPLOYMENT_SIGNING_KEY_FILE",
		"/var/lib/facets-compute-pool/deployment-signing-key",
	)
	t.Setenv(
		"FACETS_COMPUTE_POOL_DEPLOYMENT_ROUTE_POLICY_FILE",
		"/var/lib/facets-compute-pool/deployment-route-policy.json",
	)
	t.Setenv(
		"FACETS_COMPUTE_POOL_SERVICE_AUTHORITY_BINDINGS_FILE",
		"/var/lib/facets-compute-pool/service-authority-bindings.json",
	)
}

func configureDeviceSyncDeployment(t *testing.T) {
	t.Helper()
	t.Setenv("FACETS_DEVICE_SYNC_DEPLOYMENT_ID", "63000000-0000-0000-0000-000000000001")
	t.Setenv(
		"FACETS_DEVICE_SYNC_DEPLOYMENT_SIGNING_KEY_FILE",
		"/var/lib/facets-device-sync/deployment-signing-key",
	)
	t.Setenv(
		"FACETS_DEVICE_SYNC_DEPLOYMENT_ROUTE_POLICY_FILE",
		"/var/lib/facets-device-sync/deployment-route-policy.json",
	)
	t.Setenv(
		"FACETS_DEVICE_SYNC_SERVICE_AUTHORITY_BINDINGS_FILE",
		"/var/lib/facets-device-sync/service-authority-bindings.json",
	)
}

func configureBackupCustody(t *testing.T) {
	t.Helper()
	t.Setenv("FACETS_BACKUP_CUSTODY_DATABASE_URL", "postgres://example.invalid/backup_custody")
	t.Setenv("FACETS_BACKUP_CUSTODY_PUBLIC_URL", "https://backup.example")
	t.Setenv("FACETS_BACKUP_CUSTODY_DEPLOYMENT_ID", "89000000-0000-0000-0000-000000000001")
	t.Setenv("FACETS_BACKUP_CUSTODY_DEPLOYMENT_SIGNING_KEY_FILE", "/var/lib/facets-backup-custody/deployment-signing-key")
	t.Setenv("FACETS_BACKUP_CUSTODY_DEPLOYMENT_ROUTE_POLICY_FILE", "/var/lib/facets-backup-custody/deployment-route-policy.json")
	t.Setenv("FACETS_BACKUP_CUSTODY_SERVICE_AUTHORITY_BINDINGS_FILE", "/var/lib/facets-backup-custody/service-authority-bindings.json")
	t.Setenv("FACETS_BACKUP_CUSTODY_ACCOUNT_ADMISSION_KEY_FILE", "/var/lib/facets-backup-custody/account-admission-key")
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
		"FACETS_DEVICE_SYNC_DEPLOYMENT_ROUTE_POLICY_FILE",
		"/var/lib/facets-device-sync/deployment-route-policy.json",
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
		configuration.DeploymentRoutePolicyFile == "" ||
		configuration.ServiceAuthorityBindingsFile == "" {
		t.Fatalf("deployment authentication configuration=%+v", configuration)
	}
}

func TestDeviceSyncRequiresDeploymentAuthority(t *testing.T) {
	t.Setenv(
		"FACETS_DEVICE_SYNC_DATABASE_URL",
		"postgres://example.invalid/device_sync",
	)
	if _, err := config.Load(config.DeviceSync); err == nil {
		t.Fatal("Device Sync without deployment authority was accepted")
	}
}

func TestOnionIngressTokenIsOptionalStrictAndServiceScoped(t *testing.T) {
	configureDeviceSyncDeployment(t)
	t.Setenv("FACETS_DEVICE_SYNC_DATABASE_URL", "postgres://example.invalid/device_sync")
	token := bytes.Repeat([]byte{0x51}, 32)
	t.Setenv(
		"FACETS_DEVICE_SYNC_ONION_INGRESS_TOKEN",
		base64.RawURLEncoding.EncodeToString(token),
	)
	t.Setenv("FACETS_SHARED_SPACES_ONION_INGRESS_TOKEN", "invalid-other-service-value")
	configuration, err := config.Load(config.DeviceSync)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(configuration.OnionIngressToken, token) {
		t.Fatal("Device Sync onion ingress token was not decoded")
	}
	for _, value := range []string{
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x51}, 31)),
		base64.URLEncoding.EncodeToString(token),
		"not-base64url",
	} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("FACETS_DEVICE_SYNC_ONION_INGRESS_TOKEN", value)
			if _, err := config.Load(config.DeviceSync); err == nil {
				t.Fatal("invalid onion ingress token accepted")
			}
		})
	}
}

func TestUnsupportedServiceIsRejected(t *testing.T) {
	if _, err := config.Load(config.Service("other")); err == nil {
		t.Fatal("unsupported service accepted")
	}
}
