package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/robreuss/FacetsNode/internal/traffic"
)

type Config struct {
	ListenAddress      string
	DatabaseURL        string
	ShutdownPeriod     time.Duration
	CleanupPeriod      time.Duration
	TransferPeriod     time.Duration
	DatabaseConns      int32
	OperatorToken      string
	BlobRoot           string
	BlobUploadTTL      time.Duration
	BlobOrphanGrace    time.Duration
	CheckpointFenceTTL time.Duration
	TrafficLimits      traffic.Limits
}

func Load() (Config, error) {
	configuration := Config{
		ListenAddress:      environment("FACETS_NODE_LISTEN_ADDR", ":8080"),
		DatabaseURL:        os.Getenv("FACETS_NODE_DATABASE_URL"),
		ShutdownPeriod:     10 * time.Second,
		CleanupPeriod:      time.Minute,
		TransferPeriod:     10 * time.Minute,
		DatabaseConns:      10,
		OperatorToken:      os.Getenv("FACETS_NODE_OPERATOR_TOKEN"),
		BlobRoot:           environment("FACETS_NODE_BLOB_ROOT", "/var/lib/facets-node/blobs"),
		BlobUploadTTL:      7 * 24 * time.Hour,
		BlobOrphanGrace:    24 * time.Hour,
		CheckpointFenceTTL: 2 * time.Hour,
		TrafficLimits:      traffic.DefaultLimits(),
	}
	if configuration.DatabaseURL == "" {
		return Config{}, fmt.Errorf("FACETS_NODE_DATABASE_URL is required")
	}
	if configuration.OperatorToken != "" {
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(
			configuration.OperatorToken,
		)
		if err != nil || len(decoded) != 32 ||
			base64.RawURLEncoding.EncodeToString(decoded) != configuration.OperatorToken {
			return Config{}, fmt.Errorf(
				"FACETS_NODE_OPERATOR_TOKEN must be 32-byte unpadded base64url",
			)
		}
	}
	if value := os.Getenv("FACETS_NODE_SHUTDOWN_PERIOD"); value != "" {
		period, err := time.ParseDuration(value)
		if err != nil || period <= 0 {
			return Config{}, fmt.Errorf("FACETS_NODE_SHUTDOWN_PERIOD must be a positive duration")
		}
		configuration.ShutdownPeriod = period
	}
	if value := os.Getenv("FACETS_NODE_CLEANUP_PERIOD"); value != "" {
		period, err := time.ParseDuration(value)
		if err != nil || period <= 0 {
			return Config{}, fmt.Errorf("FACETS_NODE_CLEANUP_PERIOD must be a positive duration")
		}
		configuration.CleanupPeriod = period
	}
	if value := os.Getenv("FACETS_NODE_HTTP_TRANSFER_PERIOD"); value != "" {
		period, err := time.ParseDuration(value)
		if err != nil || period <= 0 || period > time.Hour {
			return Config{}, fmt.Errorf(
				"FACETS_NODE_HTTP_TRANSFER_PERIOD must be positive and no more than one hour",
			)
		}
		configuration.TransferPeriod = period
	}
	if value := os.Getenv("FACETS_NODE_BLOB_UPLOAD_TTL"); value != "" {
		period, err := time.ParseDuration(value)
		if err != nil || period <= 0 {
			return Config{}, fmt.Errorf("FACETS_NODE_BLOB_UPLOAD_TTL must be a positive duration")
		}
		configuration.BlobUploadTTL = period
	}
	if value := os.Getenv("FACETS_NODE_BLOB_ORPHAN_GRACE"); value != "" {
		period, err := time.ParseDuration(value)
		if err != nil || period <= 0 {
			return Config{}, fmt.Errorf("FACETS_NODE_BLOB_ORPHAN_GRACE must be a positive duration")
		}
		configuration.BlobOrphanGrace = period
	}
	if value := os.Getenv("FACETS_NODE_CHECKPOINT_FENCE_TTL"); value != "" {
		period, err := time.ParseDuration(value)
		if err != nil || period < 5*time.Minute || period > 24*time.Hour {
			return Config{}, fmt.Errorf("FACETS_NODE_CHECKPOINT_FENCE_TTL must be between 5 minutes and 24 hours")
		}
		configuration.CheckpointFenceTTL = period
	}
	if value := os.Getenv("FACETS_NODE_DATABASE_CONNS"); value != "" {
		count, err := strconv.ParseInt(value, 10, 32)
		if err != nil || count <= 0 || count > 100 {
			return Config{}, fmt.Errorf("FACETS_NODE_DATABASE_CONNS must be between 1 and 100")
		}
		configuration.DatabaseConns = int32(count)
	}
	if err := loadTrafficLimits(&configuration); err != nil {
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

func loadTrafficLimits(configuration *Config) error {
	for _, surface := range traffic.Surfaces() {
		prefix := "FACETS_NODE_TRAFFIC_" + trafficSurfaceEnvironmentNames[surface]
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
