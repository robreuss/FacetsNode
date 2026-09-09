package config_test

import (
	"encoding/base64"
	"testing"

	"github.com/robreuss/FacetsNode/internal/config"
)

func TestCandidateMaintenanceIsExplicitAndServiceScoped(t *testing.T) {
	configureDeviceSyncDeployment(t)
	t.Setenv("FACETS_DEVICE_SYNC_DATABASE_URL", "postgres://example.invalid/device")
	t.Setenv("FACETS_SHARED_SPACES_DATABASE_URL", "postgres://example.invalid/group")
	t.Setenv("FACETS_SHARED_SPACES_MANAGED_KEY_ENCRYPTION_KEY", base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("FACETS_SHARED_SPACES_COMPUTE_CAPABILITY_SIGNING_SEED", base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("FACETS_SHARED_SPACES_PUBLIC_URL", "https://group.example.invalid")
	for _, service := range []config.Service{config.DeviceSync, config.SharedSpaces} {
		t.Run(string(service), func(t *testing.T) {
			prefix, _ := service.EnvironmentPrefix()
			for _, value := range []string{"", "false", "true", "invalid"} {
				t.Setenv(prefix+"_CANDIDATE_MAINTENANCE", value)
				c, err := config.Load(service)
				if value == "invalid" {
					if err == nil {
						t.Fatal("invalid candidate mode accepted")
					}
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				if c.CandidateMaintenance != (value == "true") {
					t.Fatalf("unexpected mode for %q", value)
				}
			}
		})
	}
	t.Setenv("FACETS_DEVICE_SYNC_CANDIDATE_MAINTENANCE", "true")
	t.Setenv("FACETS_SHARED_SPACES_CANDIDATE_MAINTENANCE", "")
	c, err := config.Load(config.SharedSpaces)
	if err != nil || c.CandidateMaintenance {
		t.Fatal("Device Sync mode leaked into Group Spaces")
	}
}
