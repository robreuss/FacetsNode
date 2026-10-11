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
	jobCustody := readDeploymentFile(t, "job-custody/compose.yaml")
	storageCapacity := readDeploymentFile(t, "storage-capacity/compose.yaml")

	assertContainsAll(t, "Device Sync Compose", deviceSync, []string{
		"name: facets-device-sync",
		"target: device-sync",
		"FACETS_DEVICE_SYNC_DATABASE_URL:",
		"FACETS_DEVICE_SYNC_DEPLOYMENT_ID:",
		"FACETS_DEVICE_SYNC_DEPLOYMENT_SIGNING_KEY_FILE:",
		"FACETS_DEVICE_SYNC_DEPLOYMENT_ROUTE_POLICY_FILE:",
		"FACETS_DEVICE_SYNC_SERVICE_AUTHORITY_BINDINGS_FILE:",
		"FACETS_DEVICE_SYNC_AUTHORITY_KEY_DIRECTORY",
		"FACETS_DEVICE_SYNC_AUTHORITY_POLICY_DIRECTORY",
		"FACETS_DEVICE_SYNC_AUTHORITY_STATE_DIRECTORY",
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
	assertContainsAll(t, "Job Custody Compose", jobCustody, []string{
		"name: facets-job-custody",
		"target: job-custody",
		"FACETS_JOB_CUSTODY_DATABASE_URL:",
		"FACETS_JOB_CUSTODY_DEPLOYMENT_ID:",
		"FACETS_JOB_CUSTODY_STORAGE_CAPACITY_AUTHORITY_URL: https://storage-capacity:8443",
		"facets-job-custody-postgres:",
		"/job-custody/content:/var/lib/facets-job-custody/custody",
		`["CMD", "/facets-job-custody-server"`,
		"external: true",
		"name: facets-box-service-control",
		"name: facets-box-storage-capacity-client",
	})
	assertContainsAll(t, "Storage Capacity Compose", storageCapacity, []string{
		"name: facets-storage-capacity",
		"target: storage-capacity-authority",
		"FACETS_STORAGE_CAPACITY_AUTHORITY_DATABASE_URL:",
		"FACETS_STORAGE_CAPACITY_AUTHORITY_POOL_ID:",
		"FACETS_STORAGE_CAPACITY_AUTHORITY_POOL_ROOT:",
		"facets-storage-capacity-postgres:",
		`["CMD", "/facets-storage-capacity-authority"`,
		"name: facets-box-storage-capacity-client",
	})

	if strings.Contains(deviceSync, "FACETS_SHARED_SPACES_") {
		t.Fatal("Device Sync Compose consumes Shared Spaces configuration")
	}
	if strings.Contains(sharedSpaces, "FACETS_DEVICE_SYNC_") {
		t.Fatal("Shared Spaces Compose consumes Device Sync configuration")
	}
	for _, forbidden := range []string{
		"FACETS_DEVICE_SYNC_DATABASE_URL", "FACETS_SHARED_SPACES_DATABASE_URL",
		"FACETS_BOX_CONTROLLER_DATABASE_URL", "FACETS_STORAGE_CAPACITY_AUTHORITY_DATABASE_URL",
	} {
		if strings.Contains(jobCustody, forbidden) {
			t.Fatalf("Job Custody Compose consumes unrelated authority %q", forbidden)
		}
	}
	for _, forbidden := range []string{
		"FACETS_JOB_CUSTODY_DATABASE_URL", "FACETS_DEVICE_SYNC_DATABASE_URL",
		"FACETS_SHARED_SPACES_DATABASE_URL", "FACETS_BOX_CONTROLLER_DATABASE_URL",
	} {
		if strings.Contains(storageCapacity, forbidden) {
			t.Fatalf("Storage Capacity Compose consumes unrelated authority %q", forbidden)
		}
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
		"FROM scratch AS backup-custody",
		"COPY --from=build /out/facets-backup-custody-server /facets-backup-custody-server",
		"COPY --chown=65532:65532 --from=build /out/backup-custody /var/lib/facets-backup-custody",
		"ENTRYPOINT [\"/facets-backup-custody-server\"]",
		"FROM scratch AS job-custody",
		"COPY --from=build /out/facets-job-custody-server /facets-job-custody-server",
		"COPY --chown=65532:65532 --from=build /out/job-custody /var/lib/facets-job-custody",
		"ENTRYPOINT [\"/facets-job-custody-server\"]",
		"FROM scratch AS storage-capacity-authority",
		"COPY --from=build /out/facets-storage-capacity-authority /facets-storage-capacity-authority",
		"ENTRYPOINT [\"/facets-storage-capacity-authority\"]",
		"FROM scratch AS box-controller",
		"ENTRYPOINT [\"/facets-box-controller\"]",
		"FROM scratch AS box-discovery",
		"ENTRYPOINT [\"/facets-box-discovery\"]",
	})
}

func TestJobCustodyCapacityTLSAndPublicIngressStayNarrow(t *testing.T) {
	compose := readDeploymentFile(t, "job-custody/compose.yaml")
	capacityCompose := readDeploymentFile(t, "storage-capacity/compose.yaml")
	capacityCaddy := readDeploymentFile(t, "storage-capacity/Capacity.Caddyfile")
	boxCaddy := readDeploymentFile(t, "Caddyfile")

	assertContainsAll(t, "Job Custody capacity TLS", capacityCaddy, []string{
		"tls /etc/facets-capacity-tls/server.crt /etc/facets-capacity-tls/server.key",
		"reverse_proxy storage-capacity-authority:8080",
		"admin off",
		"auto_https off",
	})
	assertContainsAll(t, "Box Job Custody ingress", boxCaddy, []string{
		"@jobCustodyApplication path /facetsbox/job-custody/v1/job-custody/*",
		"uri strip_prefix /facetsbox/job-custody",
		"reverse_proxy job-custody:8080",
	})
	capacityStart := strings.Index(capacityCompose, "  storage-capacity:\n")
	if capacityStart < 0 {
		t.Fatal("Job Custody capacity TLS block is not bounded")
	}
	capacityBlock := capacityCompose[capacityStart:]
	if strings.Contains(capacityBlock, "ports:") || strings.Contains(capacityBlock, "service-control") {
		t.Fatal("Storage Capacity Authority TLS endpoint escaped the private capacity plane")
	}
	if strings.Contains(compose, "storage-capacity-authority:") ||
		strings.Contains(compose, "storage-capacity-postgres:") {
		t.Fatal("Job Custody Compose owns shared physical-capacity lifecycle")
	}
	if strings.Contains(boxCaddy, "/facetsbox/job-custody/readyz") ||
		strings.Contains(boxCaddy, "/facetsbox/job-custody/livez") ||
		strings.Contains(boxCaddy, "/facetsbox/job-custody/v1/readiness") {
		t.Fatal("Job Custody operational readiness was exposed through public ingress")
	}
}

func TestBoxControllerHasIndependentDatabaseAndNoServiceSigningAuthority(t *testing.T) {
	compose := readDeploymentFile(t, "../compose.yaml")
	start := strings.Index(compose, "  controller:\n")
	if start < 0 {
		t.Fatal("Box controller service block missing")
	}
	relativeEnd := strings.Index(compose[start+1:], "\n  discovery:\n")
	if relativeEnd < 0 {
		t.Fatal("Box controller service block is not bounded")
	}
	block := compose[start : start+1+relativeEnd]
	assertContainsAll(t, "Box controller", block, []string{
		"target: box-controller",
		"FACETS_BOX_CONTROLLER_DATABASE_URL:",
		"FACETS_BOX_IDENTITY_KEY_FILE:",
		"FACETS_DEVICE_SYNC_BOX_CONTROLLER_TOKEN:",
		"facets-box-controller-state:/var/lib/facets-box-controller",
		"- controller-private",
		"- service-control",
	})
	for _, forbidden := range []string{
		"FACETS_DEVICE_SYNC_DATABASE_URL",
		"DEPLOYMENT_SIGNING_KEY",
		"OPERATOR_TOKEN",
		"docker.sock",
		"BACKUP_CUSTODY_ROOT",
	} {
		if strings.Contains(block, forbidden) {
			t.Errorf("Box controller received forbidden authority %q", forbidden)
		}
	}
}

func TestBoxDiscoveryReceivesOnlyThePublicTLSCertificate(t *testing.T) {
	compose := readDeploymentFile(t, "../compose.yaml")
	start := strings.Index(compose, "  discovery:\n")
	if start < 0 {
		t.Fatal("Box discovery service block missing")
	}
	relativeEnd := strings.Index(compose[start+1:], "\n  ingress:\n")
	if relativeEnd < 0 {
		t.Fatal("Box discovery service block is not bounded")
	}
	block := compose[start : start+1+relativeEnd]
	assertContainsAll(t, "Box discovery", block, []string{
		"FACETS_BOX_DISCOVERY_CA_FILE: /etc/facets-box/tls/server.crt",
		"/server.crt:/etc/facets-box/tls/server.crt:ro",
	})
	if strings.Contains(block, ":/etc/facets-box/tls:ro") || strings.Contains(block, "server.key") {
		t.Fatal("Box discovery must not receive the ingress TLS private key or directory")
	}
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
