package applianceprofile

import (
	"encoding/json"
	"testing"
)

func validProfile() Profile {
	return Profile{
		SchemaVersion: 1, ProfileID: "facets-box-test-arm64", Architecture: "arm64",
		HostAdapter: "fbd-virtualization-framework", ManagementTransport: "virtio-socket",
		Guest:     Guest{OS: "linux", Distribution: "ubuntu", Release: "24.04", AgentProtocol: 1},
		Resources: Resources{CPUCount: 4, MemoryMiB: 8192},
		Storage: Storage{
			System: Disk{MinimumGiB: 16, Disposition: "replaceable"},
			Data:   Disk{MinimumGiB: 64, Disposition: "retained-authority", MountPath: "/srv/facets-box-data"},
		},
		Runtime: ContainerRuntime{EngineVersion: "29.8.0", ComposeVersion: "5.5.1", ContainerdVersion: "2.3.5", DataRoot: "/srv/facets-box-data/docker"},
	}
}

func TestProfileValidationAcceptsSupportedAdapters(t *testing.T) {
	fbd := validProfile()
	if err := fbd.Validate(); err != nil {
		t.Fatal(err)
	}
	proxmox := fbd
	proxmox.ProfileID = "facets-box-proxmox-development-amd64"
	proxmox.Architecture = "amd64"
	proxmox.HostAdapter = "proxmox-qemu"
	proxmox.ManagementTransport = "private-ssh"
	if err := proxmox.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestProfileValidationRejectsBoundarySubstitution(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Profile)
	}{
		{"unknown architecture", func(profile *Profile) { profile.Architecture = "riscv64" }},
		{"host transport mismatch", func(profile *Profile) { profile.ManagementTransport = "private-ssh" }},
		{"mutable authority on system disk", func(profile *Profile) { profile.Storage.System.Disposition = "retained-authority" }},
		{"replaceable data disk", func(profile *Profile) { profile.Storage.Data.Disposition = "replaceable" }},
		{"data outside retained disk", func(profile *Profile) { profile.Runtime.DataRoot = "/var/lib/docker" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			profile := validProfile()
			test.mutate(&profile)
			if err := profile.Validate(); err == nil {
				t.Fatal("invalid profile accepted")
			}
		})
	}
}

func TestDecodeIsStrict(t *testing.T) {
	encoded, err := json.Marshal(validProfile())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Decode(encoded); err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err = json.Unmarshal(encoded, &object); err != nil {
		t.Fatal(err)
	}
	object["unexpected"] = true
	encoded, _ = json.Marshal(object)
	if _, err = Decode(encoded); err == nil {
		t.Fatal("profile with unknown field accepted")
	}
	if _, err = Decode(append(encoded, []byte("{}")...)); err == nil {
		t.Fatal("profile with trailing object accepted")
	}
}
