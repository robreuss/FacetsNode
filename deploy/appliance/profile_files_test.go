package appliance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/robreuss/FacetsNode/internal/applianceprofile"
)

func TestCommittedApplianceProfiles(t *testing.T) {
	tests := []struct {
		name         string
		architecture string
		adapter      string
	}{
		{"fbd-arm64.json", "arm64", "fbd-virtualization-framework"},
		{"proxmox-development-amd64.json", "amd64", "proxmox-qemu"},
	}
	for _, test := range tests {
		profile, err := applianceprofile.Read(filepath.Join(".", test.name))
		if err != nil {
			t.Fatalf("%s: %v", test.name, err)
		}
		if profile.Architecture != test.architecture || profile.HostAdapter != test.adapter {
			t.Fatalf("%s: unexpected platform binding: %+v", test.name, profile)
		}
	}
}

func TestDesktopFoundationCarriesCommittedProfile(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "desktop", "build-foundation.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, required := range []string{"deploy/appliance/fbd-arm64.json", `"$output/appliance-profile.json"`} {
		if !strings.Contains(script, required) {
			t.Fatalf("desktop foundation does not carry profile boundary %q", required)
		}
	}
}

func TestServiceReleaseBindsSelectedProfile(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "desktop", "guest-build.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, required := range []string{
		"facets-box-desktop-arm64", "facets-box-proxmox-development-amd64",
		"applianceProfileID", "applianceProfileSHA256", "{version:2",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("service release does not bind profile field %q", required)
		}
	}
}
