package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	ListenAddress  string
	DatabaseURL    string
	ShutdownPeriod time.Duration
	CleanupPeriod  time.Duration
	DatabaseConns  int32
}

func Load() (Config, error) {
	configuration := Config{
		ListenAddress:  environment("FACETS_NODE_LISTEN_ADDR", ":8080"),
		DatabaseURL:    os.Getenv("FACETS_NODE_DATABASE_URL"),
		ShutdownPeriod: 10 * time.Second,
		CleanupPeriod:  time.Minute,
		DatabaseConns:  10,
	}
	if configuration.DatabaseURL == "" {
		return Config{}, fmt.Errorf("FACETS_NODE_DATABASE_URL is required")
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
	if value := os.Getenv("FACETS_NODE_DATABASE_CONNS"); value != "" {
		count, err := strconv.ParseInt(value, 10, 32)
		if err != nil || count <= 0 || count > 100 {
			return Config{}, fmt.Errorf("FACETS_NODE_DATABASE_CONNS must be between 1 and 100")
		}
		configuration.DatabaseConns = int32(count)
	}
	return configuration, nil
}

func environment(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
