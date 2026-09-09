package main

import (
	"strings"
	"testing"
)

func TestServiceEnvironmentKeepsDeploymentsIndependent(t *testing.T) {
	identity, err := initializeApplianceIdentity(t.TempDir(), "installation", strings.Repeat("a", 56)+".onion", strings.Repeat("b", 56)+".onion")
	if err != nil {
		t.Fatal(err)
	}
	images := map[string]string{}
	for _, name := range imageNames {
		images[name] = "sha256:" + strings.Repeat("a", 64)
	}
	d, g, err := serviceEnvironment("/srv/facets-box-data", "/opt/fbd/service-kit", identity, images, true)
	if err != nil {
		t.Fatal(err)
	}
	if d["FACETS_DEVICE_SYNC_POSTGRES_PASSWORD"] == g["FACETS_SHARED_SPACES_POSTGRES_PASSWORD"] || d["FACETS_DEVICE_SYNC_DEPLOYMENT_ID"] == g["FACETS_SHARED_SPACES_DEPLOYMENT_ID"] || d["FBD_CLEANUP_PERIOD"] != "24h" {
		t.Fatal("deployment isolation or candidate setting lost")
	}
	if d["FACETS_BOX_DEVICE_SYNC_URL"] != identity.DeviceSync.Endpoint {
		t.Fatal("Box service catalog endpoint changed")
	}
	for _, env := range []map[string]string{d, g} {
		if _, err := encodeEnvironment(env); err != nil {
			t.Fatal(err)
		}
	}
	if _, exists := g["FACETS_DEVICE_SYNC_BOX_CONTROLLER_TOKEN"]; exists {
		t.Fatal("controller authority leaked into Group Spaces")
	}
	images["tor"] = "tor:latest"
	if _, _, err := serviceEnvironment("/srv", "/opt", identity, images, false); err == nil {
		t.Fatal("accepted mutable image tag")
	}
}

func TestEnvironmentRejectsInterpolationAndNewline(t *testing.T) {
	for _, value := range []string{"a\nSECRET=bad", "${SECRET}", "'quoted'", ""} {
		if _, err := encodeEnvironment(map[string]string{"VALUE": value}); err == nil {
			t.Fatal("unsafe .env value accepted")
		}
	}
}
