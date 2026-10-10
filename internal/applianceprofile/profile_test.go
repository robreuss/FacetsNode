package applianceprofile

import (
	"encoding/json"
	"os"
	"path/filepath"
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

func TestReadWithSHA256BindsExactProfileBytes(t *testing.T) {
	encoded, err := json.Marshal(validProfile())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "profile.json")
	if err = os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	profile, digest, err := ReadWithSHA256(path)
	if err != nil {
		t.Fatal(err)
	}
	if profile.ProfileID != validProfile().ProfileID || digest != "3761b29ff41157a464001dcac6a56f4576b16d50a7ee0bd306f665f1cfd25735" {
		t.Fatalf("unexpected profile binding: id=%s digest=%s", profile.ProfileID, digest)
	}
	if err = os.WriteFile(path, append(encoded, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	_, changed, err := ReadWithSHA256(path)
	if err != nil {
		t.Fatal(err)
	}
	if changed == digest {
		t.Fatal("profile byte change did not change digest")
	}
}
