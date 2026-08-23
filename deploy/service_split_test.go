package deploy

import (
	"os"
	"os/exec"
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
		"FACETS_SHARED_SPACES_MANAGED_KEY_ENCRYPTION_KEY:",
		"FACETS_SHARED_SPACES_COMPUTE_CAPABILITY_SIGNING_SEED:",
		"FACETS_SHARED_SPACES_PUBLIC_URL:",
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

func TestSharedSpacesOperationsUseOnlySharedSpacesAuthority(t *testing.T) {
	backupCompose := readDeploymentFile(t, "shared-spaces/compose.backup.yaml")
	backupScript := readDeploymentFile(t, "shared-spaces/scripts/backup-checkpoint.sh")
	restoreScript := readDeploymentFile(t, "shared-spaces/scripts/restore-checkpoint.sh")

	assertContainsAll(t, "Shared Spaces backup Compose", backupCompose, []string{
		"--username=facets_shared_spaces",
		"--dbname=facets_shared_spaces",
		"FACETS_SHARED_SPACES_POSTGRES_PASSWORD:",
		"FACETS_SHARED_SPACES_CHECKPOINT_REVISION:",
		"facets-shared-spaces-blobs:/blobs:ro",
		"FACETS_SHARED_SPACES_RUNTIME_UID:",
		"if test -s /restore/checkpoint/blob-digests.sha256; then",
	})
	assertContainsAll(t, "Shared Spaces backup script", backupScript, []string{
		"facets_shared_spaces_resolve_checkpoint_revision",
		"--host facets-shared-spaces",
		"--tag facets-shared-spaces-checkpoint",
		"source Facets Shared Spaces Server did not become ready after checkpoint",
	})
	assertContainsAll(t, "Shared Spaces restore script", restoreScript, []string{
		"target_project != facets-shared-spaces",
		"${target_project}_facets-shared-spaces-${volume_name}",
		"pg_isready -U facets_shared_spaces -d facets_shared_spaces",
		"restored Facets Shared Spaces Server did not become ready",
	})

	for name, contents := range map[string]string{
		"backup Compose": backupCompose,
		"backup script":  backupScript,
		"restore script": restoreScript,
	} {
		if strings.Contains(contents, "FACETS_DEVICE_SYNC_") ||
			strings.Contains(contents, "facets-device-sync") {
			t.Errorf("Shared Spaces %s references Device Sync deployment authority", name)
		}
	}
}

func TestDeviceSyncOperationsUseOnlyDeviceSyncAuthority(t *testing.T) {
	backupCompose := readDeploymentFile(t, "../compose.backup.yaml")
	backupScript := readDeploymentFile(t, "../scripts/backup-checkpoint.sh")
	restoreScript := readDeploymentFile(t, "../scripts/restore-checkpoint.sh")

	assertContainsAll(t, "Device Sync backup Compose", backupCompose, []string{
		"--username=facets_device_sync",
		"--dbname=facets_device_sync",
		"FACETS_DEVICE_SYNC_POSTGRES_PASSWORD:",
		"FACETS_DEVICE_SYNC_CHECKPOINT_REVISION:",
		"facets-device-sync-blobs:/blobs:ro",
		"FACETS_DEVICE_SYNC_RUNTIME_UID:",
		"if test -s /restore/checkpoint/blob-digests.sha256; then",
	})
	assertContainsAll(t, "Device Sync backup script", backupScript, []string{
		"deployment_directory=$(cd -- \"$script_directory/..\" && pwd)",
		"cd -- \"$deployment_directory\"",
		"facets_device_sync_resolve_checkpoint_revision",
		"--host facets-device-sync",
		"--tag facets-device-sync-checkpoint",
		"source Facets Device Sync Server did not become ready after checkpoint",
	})
	assertContainsAll(t, "Device Sync restore script", restoreScript, []string{
		"deployment_directory=$(cd -- \"$script_directory/..\" && pwd)",
		"cd -- \"$deployment_directory\"",
		"target_project != facets-device-sync",
		"${target_project}_facets-device-sync-${volume_name}",
		"pg_isready -U facets_device_sync -d facets_device_sync",
		"restored Facets Device Sync Server did not become ready",
	})

	for name, contents := range map[string]string{
		"backup Compose": backupCompose,
		"backup script":  backupScript,
		"restore script": restoreScript,
	} {
		if strings.Contains(contents, "FACETS_SHARED_SPACES_") ||
			strings.Contains(contents, "facets-shared-spaces") {
			t.Errorf("Device Sync %s references Shared Spaces deployment authority", name)
		}
	}
}

func TestSharedSpacesOperationsScriptsParse(t *testing.T) {
	for _, path := range []string{
		"../scripts/revision-attestation.sh",
		"../scripts/backup-checkpoint.sh",
		"../scripts/restore-checkpoint.sh",
		"shared-spaces/scripts/revision-attestation.sh",
		"shared-spaces/scripts/backup-checkpoint.sh",
		"shared-spaces/scripts/restore-checkpoint.sh",
	} {
		command := exec.Command("bash", "-n", path)
		if output, err := command.CombinedOutput(); err != nil {
			t.Errorf("bash -n %s: %v\n%s", path, err, output)
		}
	}
}

func TestDockerfilePublishesAllServiceImages(t *testing.T) {
	dockerfile := readDeploymentFile(t, "../Dockerfile")
	assertContainsAll(t, "Dockerfile", dockerfile, []string{
		"FROM scratch AS device-sync",
		"ENTRYPOINT [\"/facets-device-sync-server\"]",
		"FROM scratch AS shared-spaces",
		"ENTRYPOINT [\"/facets-shared-spaces-server\"]",
		"FROM scratch AS compute-pool",
		"ENTRYPOINT [\"/facets-compute-pool-server\"]",
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
