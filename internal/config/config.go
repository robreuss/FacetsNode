package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/traffic"
)

const maximumBackupCustodyChunkBytes int64 = 64 * 1024 * 1024

type Config struct {
	Service                         Service
	ListenAddress                   string
	DatabaseURL                     string
	ShutdownPeriod                  time.Duration
	CleanupPeriod                   time.Duration
	TransferPeriod                  time.Duration
	DatabaseConns                   int32
	OperatorToken                   string
	ManagedKeyEncryptionKey         []byte
	ComputeCapabilitySigningSeed    []byte
	PublicURL                       string
	FacetsBoxServiceEndpoints       map[string]string
	BlobRoot                        string
	BlobUploadTTL                   time.Duration
	BlobOrphanGrace                 time.Duration
	CheckpointFenceTTL              time.Duration
	BackupCustodyRoot               string
	BackupAccountAdmissionKeyFile   string
	BackupMaximumCredentialLifetime time.Duration
	BackupMaximumActiveUploads      int
	BackupMaximumTargets            int
	BackupMaximumGenerations        int
	BackupMaximumRequests           int
	BackupMaximumRetentionProofs    int
	BackupMaximumControlRecords     int
	BackupMaximumChunksPerUpload    int
	BackupMaximumChunkBytes         int64
	BackupMaximumGenerationBytes    int64
	BackupMaximumStagingBytes       int64
	BackupMaximumCommittedBytes     int64
	TrafficLimits                   traffic.Limits
	DeploymentID                    uuid.UUID
	DeploymentSigningKeyFile        string
	DeploymentRoutePolicyFile       string
	ServiceAuthorityBindingsFile    string
	OnionIngressToken               []byte
}

type Service string

const (
	DeviceSync    Service = "facets-device-sync-server"
	SharedSpaces  Service = "facets-shared-spaces-server"
	ComputePool   Service = "facets-compute-pool-server"
	BackupCustody Service = "facets-backup-custody-server"
)

func (service Service) EnvironmentPrefix() (string, error) {
	switch service {
	case DeviceSync:
		return "FACETS_DEVICE_SYNC", nil
	case SharedSpaces:
		return "FACETS_SHARED_SPACES", nil
	case ComputePool:
		return "FACETS_COMPUTE_POOL", nil
	case BackupCustody:
		return "FACETS_BACKUP_CUSTODY", nil
	default:
		return "", fmt.Errorf("unsupported Facets server service %q", service)
	}
}

func (service Service) BlobRoot() (string, error) {
	switch service {
	case DeviceSync:
		return "/var/lib/facets-device-sync/blobs", nil
	case SharedSpaces:
		return "/var/lib/facets-shared-spaces/blobs", nil
	case ComputePool:
		return "/var/lib/facets-compute-pool/blobs", nil
	default:
		return "", fmt.Errorf("unsupported Facets server service %q", service)
	}
}

func Load(service Service) (Config, error) {
	prefix, err := service.EnvironmentPrefix()
	if err != nil {
		return Config{}, err
	}
	defaultBlobRoot := ""
	if service != BackupCustody {
		defaultBlobRoot, err = service.BlobRoot()
		if err != nil {
			return Config{}, err
		}
	}
	configuration := Config{
		Service:        service,
		ListenAddress:  environment(prefix+"_LISTEN_ADDR", ":8080"),
		DatabaseURL:    os.Getenv(prefix + "_DATABASE_URL"),
		ShutdownPeriod: 10 * time.Second,
		CleanupPeriod:  time.Minute,
		TransferPeriod: 10 * time.Minute,
		DatabaseConns:  10,
		OperatorToken:  os.Getenv(prefix + "_OPERATOR_TOKEN"),
		PublicURL:      os.Getenv(prefix + "_PUBLIC_URL"),
		FacetsBoxServiceEndpoints: map[string]string{
			"device-sync": strings.TrimSpace(
				os.Getenv("FACETS_BOX_DEVICE_SYNC_URL"),
			),
			"shared-spaces": strings.TrimSpace(
				os.Getenv("FACETS_BOX_SHARED_SPACES_URL"),
			),
			"backup":  strings.TrimSpace(os.Getenv("FACETS_BOX_BACKUP_URL")),
			"compute": strings.TrimSpace(os.Getenv("FACETS_BOX_COMPUTE_URL")),
		},
		BlobRoot:                        environment(prefix+"_BLOB_ROOT", defaultBlobRoot),
		BlobUploadTTL:                   7 * 24 * time.Hour,
		BlobOrphanGrace:                 24 * time.Hour,
		CheckpointFenceTTL:              2 * time.Hour,
		BackupMaximumCredentialLifetime: 90 * 24 * time.Hour,
		BackupMaximumActiveUploads:      4,
		BackupMaximumTargets:            32,
		BackupMaximumGenerations:        4_096,
		BackupMaximumRequests:           16_384,
		BackupMaximumRetentionProofs:    16_384,
		BackupMaximumControlRecords:     65_536,
		BackupMaximumChunksPerUpload:    262_144,
		BackupMaximumChunkBytes:         8 * 1_024 * 1_024,
		BackupMaximumGenerationBytes:    1 << 40,
		BackupMaximumStagingBytes:       2 << 40,
		BackupMaximumCommittedBytes:     20 << 40,
		TrafficLimits:                   traffic.DefaultLimits(),
	}
	if service == BackupCustody {
		configuration.BlobRoot = ""
		configuration.BackupCustodyRoot = environment(
			prefix+"_CUSTODY_ROOT",
			"/var/lib/facets-backup-custody/custody",
		)
		configuration.BackupAccountAdmissionKeyFile = strings.TrimSpace(
			os.Getenv(prefix + "_ACCOUNT_ADMISSION_KEY_FILE"),
		)
	}
	deploymentIDName := prefix + "_DEPLOYMENT_ID"
	deploymentKeyFileName := prefix + "_DEPLOYMENT_SIGNING_KEY_FILE"
	deploymentRoutePolicyFileName := prefix + "_DEPLOYMENT_ROUTE_POLICY_FILE"
	bindingFileName := prefix + "_SERVICE_AUTHORITY_BINDINGS_FILE"
	deploymentIDText := strings.TrimSpace(os.Getenv(deploymentIDName))
	configuration.DeploymentSigningKeyFile = strings.TrimSpace(
		os.Getenv(deploymentKeyFileName),
	)
	configuration.DeploymentRoutePolicyFile = strings.TrimSpace(
		os.Getenv(deploymentRoutePolicyFileName),
	)
	configuration.ServiceAuthorityBindingsFile = strings.TrimSpace(
		os.Getenv(bindingFileName),
	)
	configuredDeploymentValues := 0
	if deploymentIDText != "" {
		configuredDeploymentValues++
	}
	if configuration.DeploymentSigningKeyFile != "" {
		configuredDeploymentValues++
	}
	if configuration.DeploymentRoutePolicyFile != "" {
		configuredDeploymentValues++
	}
	if configuration.ServiceAuthorityBindingsFile != "" {
		configuredDeploymentValues++
	}
	if configuredDeploymentValues != 0 && configuredDeploymentValues != 4 {
		return Config{}, fmt.Errorf(
			"%s, %s, %s, and %s must be configured together",
			deploymentIDName,
			deploymentKeyFileName,
			deploymentRoutePolicyFileName,
			bindingFileName,
		)
	}
	if configuredDeploymentValues == 4 {
		configuration.DeploymentID, err = uuid.Parse(deploymentIDText)
		if err != nil || configuration.DeploymentID == uuid.Nil {
			return Config{}, fmt.Errorf("%s must be a nonzero UUID", deploymentIDName)
		}
	}
	onionIngressTokenName := prefix + "_ONION_INGRESS_TOKEN"
	if encoded := os.Getenv(onionIngressTokenName); encoded != "" {
		configuration.OnionIngressToken, err = decodeSecret32(
			onionIngressTokenName,
			encoded,
		)
		if err != nil {
			return Config{}, err
		}
	}
	if configuration.DatabaseURL == "" {
		return Config{}, fmt.Errorf("%s_DATABASE_URL is required", prefix)
	}
	if configuration.OperatorToken != "" {
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(
			configuration.OperatorToken,
		)
		if err != nil || len(decoded) != 32 ||
			base64.RawURLEncoding.EncodeToString(decoded) != configuration.OperatorToken {
			return Config{}, fmt.Errorf(
				"%s_OPERATOR_TOKEN must be 32-byte unpadded base64url", prefix,
			)
		}
	}
	if service == ComputePool && configuration.OperatorToken == "" {
		return Config{}, fmt.Errorf("%s_OPERATOR_TOKEN is required", prefix)
	}
	if service == ComputePool && configuredDeploymentValues != 4 {
		return Config{}, fmt.Errorf(
			"%s, %s, %s, and %s are required for the Compute Pool Service",
			deploymentIDName,
			deploymentKeyFileName,
			deploymentRoutePolicyFileName,
			bindingFileName,
		)
	}
	if service == BackupCustody && configuredDeploymentValues != 4 {
		return Config{}, fmt.Errorf(
			"%s, %s, %s, and %s are required for the Backup Custody Service",
			deploymentIDName,
			deploymentKeyFileName,
			deploymentRoutePolicyFileName,
			bindingFileName,
		)
	}
	if service == DeviceSync && configuredDeploymentValues != 4 {
		return Config{}, fmt.Errorf(
			"%s, %s, %s, and %s are required for the Device Sync Service",
			deploymentIDName,
			deploymentKeyFileName,
			deploymentRoutePolicyFileName,
			bindingFileName,
		)
	}
	if service == SharedSpaces {
		managedKeyName := prefix + "_MANAGED_KEY_ENCRYPTION_KEY"
		configuration.ManagedKeyEncryptionKey, err = decodeSecret32(
			managedKeyName, os.Getenv(managedKeyName),
		)
		if err != nil {
			return Config{}, err
		}
		computeSeedName := prefix + "_COMPUTE_CAPABILITY_SIGNING_SEED"
		configuration.ComputeCapabilitySigningSeed, err = decodeSecret32(
			computeSeedName, os.Getenv(computeSeedName),
		)
		if err != nil {
			return Config{}, err
		}
		configuration.PublicURL = strings.TrimSpace(configuration.PublicURL)
		if configuration.PublicURL == "" {
			return Config{}, fmt.Errorf("%s_PUBLIC_URL is required", prefix)
		}
	}
	if value := os.Getenv(prefix + "_SHUTDOWN_PERIOD"); value != "" {
		period, err := time.ParseDuration(value)
		if err != nil || period <= 0 {
			return Config{}, fmt.Errorf("%s_SHUTDOWN_PERIOD must be a positive duration", prefix)
		}
		configuration.ShutdownPeriod = period
	}
	if value := os.Getenv(prefix + "_CLEANUP_PERIOD"); value != "" {
		period, err := time.ParseDuration(value)
		if err != nil || period <= 0 {
			return Config{}, fmt.Errorf("%s_CLEANUP_PERIOD must be a positive duration", prefix)
		}
		configuration.CleanupPeriod = period
	}
	if value := os.Getenv(prefix + "_HTTP_TRANSFER_PERIOD"); value != "" {
		period, err := time.ParseDuration(value)
		if err != nil || period <= 0 || period > time.Hour {
			return Config{}, fmt.Errorf(
				"%s_HTTP_TRANSFER_PERIOD must be positive and no more than one hour", prefix,
			)
		}
		configuration.TransferPeriod = period
	}
	if value := os.Getenv(prefix + "_BLOB_UPLOAD_TTL"); value != "" {
		period, err := time.ParseDuration(value)
		if err != nil || period <= 0 {
			return Config{}, fmt.Errorf("%s_BLOB_UPLOAD_TTL must be a positive duration", prefix)
		}
		configuration.BlobUploadTTL = period
	}
	if value := os.Getenv(prefix + "_BLOB_ORPHAN_GRACE"); value != "" {
		period, err := time.ParseDuration(value)
		if err != nil || period <= 0 {
			return Config{}, fmt.Errorf("%s_BLOB_ORPHAN_GRACE must be a positive duration", prefix)
		}
		configuration.BlobOrphanGrace = period
	}
	if value := os.Getenv(prefix + "_CHECKPOINT_FENCE_TTL"); value != "" {
		period, err := time.ParseDuration(value)
		if err != nil || period < 5*time.Minute || period > 24*time.Hour {
			return Config{}, fmt.Errorf("%s_CHECKPOINT_FENCE_TTL must be between 5 minutes and 24 hours", prefix)
		}
		configuration.CheckpointFenceTTL = period
	}
	if value := os.Getenv(prefix + "_DATABASE_CONNS"); value != "" {
		count, err := strconv.ParseInt(value, 10, 32)
		minimum := int64(1)
		if service == DeviceSync {
			minimum = 2
		}
		if err != nil || count < minimum || count > 100 {
			return Config{}, fmt.Errorf(
				"%s_DATABASE_CONNS must be between %d and 100", prefix, minimum,
			)
		}
		configuration.DatabaseConns = int32(count)
	}
	if service == BackupCustody {
		configuration.PublicURL = strings.TrimSpace(configuration.PublicURL)
		if configuration.PublicURL == "" {
			return Config{}, fmt.Errorf("%s_PUBLIC_URL is required", prefix)
		}
		if configuration.BackupAccountAdmissionKeyFile == "" {
			return Config{}, fmt.Errorf("%s_ACCOUNT_ADMISSION_KEY_FILE is required", prefix)
		}
		if err := loadBackupCustodyLimits(&configuration, prefix); err != nil {
			return Config{}, err
		}
	}
	if err := loadTrafficLimits(&configuration, prefix); err != nil {
		return Config{}, err
	}
	return configuration, nil
}

func loadBackupCustodyLimits(configuration *Config, prefix string) error {
	integerValues := []struct {
		name        string
		destination *int
		minimum     int64
		maximum     int64
	}{
		{prefix + "_MAXIMUM_ACTIVE_UPLOADS", &configuration.BackupMaximumActiveUploads, 1, 1_024},
		{prefix + "_MAXIMUM_TARGETS", &configuration.BackupMaximumTargets, 1, 100_000},
		{prefix + "_MAXIMUM_GENERATIONS", &configuration.BackupMaximumGenerations, 1, 10_000_000},
		{prefix + "_MAXIMUM_REQUESTS", &configuration.BackupMaximumRequests, 1, 100_000_000},
		{prefix + "_MAXIMUM_RETENTION_PROOFS", &configuration.BackupMaximumRetentionProofs, 1, 100_000_000},
		{prefix + "_MAXIMUM_CONTROL_RECORDS", &configuration.BackupMaximumControlRecords, 1, 100_000_000},
		{prefix + "_MAXIMUM_CHUNKS_PER_UPLOAD", &configuration.BackupMaximumChunksPerUpload, 1, 10_000_000},
	}
	for _, value := range integerValues {
		raw := os.Getenv(value.name)
		if raw == "" {
			continue
		}
		parsed, err := strconv.ParseInt(raw, 10, 32)
		if err != nil || parsed < value.minimum || parsed > value.maximum {
			return fmt.Errorf("%s must be between %d and %d", value.name, value.minimum, value.maximum)
		}
		*value.destination = int(parsed)
	}
	byteValues := []struct {
		name        string
		destination *int64
	}{
		{prefix + "_MAXIMUM_CHUNK_BYTES", &configuration.BackupMaximumChunkBytes},
		{prefix + "_MAXIMUM_GENERATION_BYTES", &configuration.BackupMaximumGenerationBytes},
		{prefix + "_MAXIMUM_STAGING_BYTES", &configuration.BackupMaximumStagingBytes},
		{prefix + "_MAXIMUM_COMMITTED_BYTES", &configuration.BackupMaximumCommittedBytes},
	}
	for _, value := range byteValues {
		raw := os.Getenv(value.name)
		if raw == "" {
			continue
		}
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed <= 0 {
			return fmt.Errorf("%s must be a positive integer", value.name)
		}
		*value.destination = parsed
	}
	if value := os.Getenv(prefix + "_MAXIMUM_CREDENTIAL_LIFETIME"); value != "" {
		period, err := time.ParseDuration(value)
		if err != nil || period < time.Minute || period > 365*24*time.Hour {
			return fmt.Errorf("%s_MAXIMUM_CREDENTIAL_LIFETIME must be between one minute and 365 days", prefix)
		}
		configuration.BackupMaximumCredentialLifetime = period
	}
	requiredChunks := configuration.BackupMaximumGenerationBytes / configuration.BackupMaximumChunkBytes
	if configuration.BackupMaximumGenerationBytes%configuration.BackupMaximumChunkBytes != 0 {
		requiredChunks++
	}
	if configuration.BackupMaximumChunkBytes > configuration.BackupMaximumGenerationBytes ||
		configuration.BackupMaximumChunkBytes > maximumBackupCustodyChunkBytes ||
		configuration.BackupMaximumGenerationBytes > configuration.BackupMaximumStagingBytes ||
		configuration.BackupMaximumStagingBytes > configuration.BackupMaximumCommittedBytes ||
		int64(configuration.BackupMaximumChunksPerUpload) < requiredChunks {
		return fmt.Errorf("%s Backup custody byte limits are inconsistent", prefix)
	}
	return nil
}

var trafficSurfaceEnvironmentNames = map[traffic.Surface]string{
	traffic.SurfaceRendezvous:      "RENDEZVOUS",
	traffic.SurfaceRelayMessage:    "RELAY_MESSAGE",
	traffic.SurfaceStorage:         "STORAGE",
	traffic.SurfaceCheckpointAdmin: "CHECKPOINT_ADMIN",
	traffic.SurfaceManagement:      "MANAGEMENT",
}

func loadTrafficLimits(configuration *Config, servicePrefix string) error {
	for _, surface := range traffic.Surfaces() {
		prefix := servicePrefix + "_TRAFFIC_" + trafficSurfaceEnvironmentNames[surface]
		limit := configuration.TrafficLimits[surface]
		values := []struct {
			name        string
			destination *int
		}{
			{name: prefix + "_RATE_PER_MINUTE", destination: &limit.RequestsPerMinute},
			{name: prefix + "_BURST", destination: &limit.Burst},
			{name: prefix + "_CONNECTION_RATE_PER_MINUTE", destination: &limit.ConnectionRequestsPerMinute},
			{name: prefix + "_CONNECTION_BURST", destination: &limit.ConnectionBurst},
			{name: prefix + "_CONCURRENCY", destination: &limit.Concurrency},
		}
		for _, value := range values {
			raw := os.Getenv(value.name)
			if raw == "" {
				continue
			}
			parsed, err := strconv.Atoi(raw)
			if err != nil {
				return fmt.Errorf("%s must be an integer", value.name)
			}
			*value.destination = parsed
		}
		configuration.TrafficLimits[surface] = limit
	}
	if err := traffic.ValidateLimits(configuration.TrafficLimits); err != nil {
		return fmt.Errorf("traffic limits are invalid: %w", err)
	}
	return nil
}

func environment(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func decodeSecret32(name, encoded string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(decoded) != 32 ||
		base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		return nil, fmt.Errorf("%s must be 32-byte unpadded base64url", name)
	}
	return decoded, nil
}
