package deploy

import (
	"os"
	"strings"
	"testing"
)

func TestServiceApplicationsHaveIndependentOperationalNamespaces(t *testing.T) {
	deviceSync := readDeploymentFile(t, "../compose.yaml")
	sharedSpaces := readDeploymentFile(t, "shared-spaces/compose.yaml")

	assertContainsAll(t, "Device Sync Compose", deviceSync, []string{
		"name: facets-device-sync",
		"target: device-sync",
		"FACETS_DEVICE_SYNC_DATABASE_URL:",
		"facets-device-sync-postgres:",
		"facets-device-sync-blobs:",
		`["CMD", "/facets-device-sync-server"`,
	})
	assertContainsAll(t, "Shared Spaces Compose", sharedSpaces, []string{
		"name: facets-shared-spaces",
		"target: shared-spaces",
		"FACETS_SHARED_SPACES_DATABASE_URL:",
		"facets-shared-spaces-postgres:",
		"facets-shared-spaces-blobs:",
		`["CMD", "/facets-shared-spaces-server"`,
	})

	if strings.Contains(deviceSync, "FACETS_SHARED_SPACES_") {
		t.Fatal("Device Sync Compose consumes Shared Spaces configuration")
	}
	if strings.Contains(sharedSpaces, "FACETS_DEVICE_SYNC_") {
		t.Fatal("Shared Spaces Compose consumes Device Sync configuration")
	}
}

func TestDockerfilePublishesBothServiceImages(t *testing.T) {
	dockerfile := readDeploymentFile(t, "../Dockerfile")
	assertContainsAll(t, "Dockerfile", dockerfile, []string{
		"FROM scratch AS device-sync",
		"ENTRYPOINT [\"/facets-device-sync-server\"]",
		"FROM scratch AS shared-spaces",
		"ENTRYPOINT [\"/facets-shared-spaces-server\"]",
	})
}

func readDeploymentFile(t *testing.T, path string) string {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(contents)
}

func assertContainsAll(t *testing.T, subject, contents string, expected []string) {
	t.Helper()
	for _, value := range expected {
		if !strings.Contains(contents, value) {
			t.Errorf("%s is missing %q", subject, value)
		}
	}
}
