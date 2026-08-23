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

type Config struct {
	Service                      Service
	ListenAddress                string
	DatabaseURL                  string
	ShutdownPeriod               time.Duration
	CleanupPeriod                time.Duration
	TransferPeriod               time.Duration
	DatabaseConns                int32
	OperatorToken                string
	ManagedKeyEncryptionKey      []byte
	ComputeCapabilitySigningSeed []byte
	PublicURL                    string
	BlobRoot                     string
	BlobUploadTTL                time.Duration
	BlobOrphanGrace              time.Duration
	CheckpointFenceTTL           time.Duration
	TrafficLimits                traffic.Limits
	DeploymentID                 uuid.UUID
	DeploymentSigningKeyFile     string
	ServiceAuthorityBindingsFile string
}

type Service string

const (
	DeviceSync   Service = "facets-device-sync-server"
	SharedSpaces Service = "facets-shared-spaces-server"
)

func (service Service) EnvironmentPrefix() (string, error) {
	switch service {
	case DeviceSync:
		return "FACETS_DEVICE_SYNC", nil
	case SharedSpaces:
		return "FACETS_SHARED_SPACES", nil
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
	default:
		return "", fmt.Errorf("unsupported Facets server service %q", service)
	}
}

func Load(service Service) (Config, error) {
	prefix, err := service.EnvironmentPrefix()
	if err != nil {
		return Config{}, err
	}
	defaultBlobRoot, err := service.BlobRoot()
	if err != nil {
		return Config{}, err
	}
	configuration := Config{
		Service:            service,
		ListenAddress:      environment(prefix+"_LISTEN_ADDR", ":8080"),
		DatabaseURL:        os.Getenv(prefix + "_DATABASE_URL"),
		ShutdownPeriod:     10 * time.Second,
		CleanupPeriod:      time.Minute,
		TransferPeriod:     10 * time.Minute,
		DatabaseConns:      10,
		OperatorToken:      os.Getenv(prefix + "_OPERATOR_TOKEN"),
		PublicURL:          os.Getenv(prefix + "_PUBLIC_URL"),
		BlobRoot:           environment(prefix+"_BLOB_ROOT", defaultBlobRoot),
		BlobUploadTTL:      7 * 24 * time.Hour,
		BlobOrphanGrace:    24 * time.Hour,
		CheckpointFenceTTL: 2 * time.Hour,
		TrafficLimits:      traffic.DefaultLimits(),
	}
	deploymentIDName := prefix + "_DEPLOYMENT_ID"
	deploymentKeyFileName := prefix + "_DEPLOYMENT_SIGNING_KEY_FILE"
	bindingFileName := prefix + "_SERVICE_AUTHORITY_BINDINGS_FILE"
	deploymentIDText := strings.TrimSpace(os.Getenv(deploymentIDName))
	configuration.DeploymentSigningKeyFile = strings.TrimSpace(
		os.Getenv(deploymentKeyFileName),
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
	if configuration.ServiceAuthorityBindingsFile != "" {
		configuredDeploymentValues++
	}
	if configuredDeploymentValues != 0 && configuredDeploymentValues != 3 {
		return Config{}, fmt.Errorf(
			"%s, %s, and %s must be configured together",
			deploymentIDName,
			deploymentKeyFileName,
			bindingFileName,
		)
	}
	if configuredDeploymentValues == 3 {
		configuration.DeploymentID, err = uuid.Parse(deploymentIDText)
		if err != nil || configuration.DeploymentID == uuid.Nil {
			return Config{}, fmt.Errorf("%s must be a nonzero UUID", deploymentIDName)
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
		if err != nil || count <= 0 || count > 100 {
			return Config{}, fmt.Errorf("%s_DATABASE_CONNS must be between 1 and 100", prefix)
		}
		configuration.DatabaseConns = int32(count)
	}
	if err := loadTrafficLimits(&configuration, prefix); err != nil {
		return Config{}, err
	}
	return configuration, nil
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
