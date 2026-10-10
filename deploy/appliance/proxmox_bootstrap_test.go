package appliance

import (
	"os"
	"strings"
	"testing"
)

func TestProxmoxBootstrapPreservesStorageAndIdentityBoundaries(t *testing.T) {
	data, err := os.ReadFile("proxmox/bootstrap-runtime.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, required := range []string{
		"initialize-empty-data-disk",
		"$device_link == /dev/disk/by-id/*facets-data*",
		"wipefs --no-act --noheadings",
		"Refusing to initialize a disk that backs the root filesystem",
		"/srv/facets-box-data/installation-id",
		`"data-root":"/srv/facets-box-data/docker"`,
		"systemctl mask --runtime docker.service docker.socket containerd.service",
		"facets-appliance-profile",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("missing bootstrap boundary %q", required)
		}
	}
	for _, forbidden := range []string{"qm destroy", "VM 190", "device-sync.env", "shared-spaces.env"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("bootstrap contains retained/deployment authority %q", forbidden)
		}
	}
}

func TestProxmoxCloudImageIsPinned(t *testing.T) {
	data, err := os.ReadFile("proxmox/fetch-cloud-image.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, required := range []string{
		"release-20260905/ubuntu-24.04-minimal-cloudimg-amd64.img",
		"46b0dbaffa6950a7da5ff2dc5ed34c46084610b3b6d1fae8f1ec2d7e953984a3",
		"[[ ! -e $output && ! -e $output.download ]]",
		"sha256sum",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("missing pinned cloud-image boundary %q", required)
		}
	}
}
