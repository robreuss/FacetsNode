package proxmoxadapter

import (
	"strings"
	"testing"

	"github.com/robreuss/FacetsNode/internal/applianceprofile"
)

func proxmoxProfile() applianceprofile.Profile {
	return applianceprofile.Profile{
		SchemaVersion: 1, ProfileID: "facets-box-proxmox-development-amd64", Architecture: "amd64",
		HostAdapter: "proxmox-qemu", ManagementTransport: "private-ssh",
		Guest:     applianceprofile.Guest{OS: "linux", Distribution: "ubuntu", Release: "24.04", AgentProtocol: 1},
		Resources: applianceprofile.Resources{CPUCount: 4, MemoryMiB: 8192},
		Storage: applianceprofile.Storage{
			System: applianceprofile.Disk{MinimumGiB: 16, Disposition: "replaceable"},
			Data:   applianceprofile.Disk{MinimumGiB: 64, Disposition: "retained-authority", MountPath: "/srv/facets-box-data"},
		},
		Runtime: applianceprofile.ContainerRuntime{EngineVersion: "29.8.0", ComposeVersion: "5.5.1", ContainerdVersion: "2.3.5", DataRoot: "/srv/facets-box-data/docker"},
	}
}

func validPlan() Plan {
	profile := proxmoxProfile()
	return NewPlan(profile, "pve", 191, "facets-box-portable-dev", "local-zfs", "vmbr0", "facets-admin",
		FileEvidence{Path: "/var/lib/vz/template/iso/ubuntu.img", SHA256: strings.Repeat("a", 64)},
		FileEvidence{Path: "/root/facets-box.pub", SHA256: strings.Repeat("b", 64)})
}

func TestPlanBindsProfileAndRetainedDataDisk(t *testing.T) {
	plan := validPlan()
	if err := plan.Validate(proxmoxProfile()); err != nil {
		t.Fatal(err)
	}
	commands := QMCommands(plan)
	joined := ""
	for _, command := range commands {
		joined += strings.Join(command, " ") + "\n"
	}
	for _, required := range []string{
		"create 191", "--onboot 0", "--scsi0 local-zfs:0,import-from=/var/lib/vz/template/iso/ubuntu.img",
		"serial=facets-system", "resize 191 scsi0 16G", "--scsi1 local-zfs:64", "serial=facets-data", "--ide2 local-zfs:cloudinit",
		"--ciuser facets-admin", "--ipconfig0 ip=dhcp", "start 191",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("missing command boundary %q in:\n%s", required, joined)
		}
	}
	if strings.Contains(joined, " 190 ") || strings.Contains(joined, "\nclone ") {
		t.Fatalf("retained VM or cloning entered plan:\n%s", joined)
	}
}

func TestPlanRejectsRetainedVMsAndProfileDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Plan)
	}{
		{"retained old node", func(plan *Plan) { plan.VMID = 180 }},
		{"retained current box", func(plan *Plan) { plan.VMID = 190 }},
		{"resource drift", func(plan *Plan) { plan.MemoryMiB++ }},
		{"root management", func(plan *Plan) { plan.AdminUser = "root" }},
		{"relative image", func(plan *Plan) { plan.CloudImage.Path = "ubuntu.img" }},
		{"property injection path", func(plan *Plan) { plan.CloudImage.Path = "/protected/ubuntu.img,backup=0" }},
		{"disabled first boot", func(plan *Plan) { plan.StartAfterCreate = false }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan := validPlan()
			test.mutate(&plan)
			if err := plan.Validate(proxmoxProfile()); err == nil {
				t.Fatal("invalid plan accepted")
			}
		})
	}
}

func TestPlanDigestBindsExactReviewBytes(t *testing.T) {
	encoded, err := EncodePlan(validPlan())
	if err != nil {
		t.Fatal(err)
	}
	first := PlanDigest(encoded)
	encoded[len(encoded)-2] ^= 1
	if PlanDigest(encoded) == first {
		t.Fatal("mutated plan retained approval digest")
	}
}
