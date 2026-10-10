package appliance

import (
	"path/filepath"
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
