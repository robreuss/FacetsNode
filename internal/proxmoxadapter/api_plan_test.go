package proxmoxadapter

import (
	"strings"
	"testing"
)

func validAPIPlan() APIPlan {
	return NewAPIPlan(
		proxmoxProfile(),
		"https://192.0.2.10:8006",
		strings.Repeat("c", 64),
		"pve",
		200,
		"facets-box-portable-dev",
		"zfs-nvme",
		"local",
		"vmbr0",
		"facets-admin",
		FileEvidence{Path: "/protected/ubuntu.img", SHA256: PinnedUbuntuImageSHA256},
		FileEvidence{Path: "/protected/facets-admin.pub", SHA256: strings.Repeat("d", 64)},
	)
}

func TestAPIPlanBindsPinnedInputsAndNonDestructiveOperations(t *testing.T) {
	plan := validAPIPlan()
	if err := plan.Validate(proxmoxProfile()); err != nil {
		t.Fatal(err)
	}
	publicKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEJeodct0V0EeaDSJQAwgqpqW7rMaucm/Ag5B0QFGp3J"
	operations := APIOperations(plan, publicKey)
	if len(operations) != 7 {
		t.Fatalf("unexpected operation count: %d", len(operations))
	}
	encoded := ""
	for _, operation := range operations {
		encoded += operation.Method + " " + operation.Path + " "
		for key, value := range operation.Form {
			encoded += key + "=" + value + " "
		}
		encoded += operation.UploadFilename + "\n"
		if operation.Method == "DELETE" {
			t.Fatalf("destructive operation entered API plan: %+v", operation)
		}
	}
	for _, required := range []string{
		"content=import",
		"facets-box-ubuntu-24.04-minimal-20260905-vm200-46b0dbaf.qcow2",
		"zfs-nvme:0,import-from=local:import/",
		"serial=facets-system",
		"disk=scsi0",
		"size=16G",
		"zfs-nvme:64",
		"serial=facets-data",
		"ciuser=facets-admin",
		"ipconfig0=ip=dhcp",
		"/qemu/200/status/start",
	} {
		if !strings.Contains(encoded, required) {
			t.Fatalf("missing API operation boundary %q in:\n%s", required, encoded)
		}
	}
	if strings.Contains(encoded, "/qemu/180") || strings.Contains(encoded, "/qemu/190") {
		t.Fatalf("retained VM entered API operations:\n%s", encoded)
	}
	if got := operations[5].Form["sshkeys"]; got != "ssh-ed25519%20AAAAC3NzaC1lZDI1NTE5AAAAIEJeodct0V0EeaDSJQAwgqpqW7rMaucm%2FAg5B0QFGp3J" {
		t.Fatalf("public key is not encoded for Proxmox's urlencoded field: %q", got)
	}
}

func TestAPIPlanRejectsEndpointEvidenceAndIdentityDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*APIPlan)
	}{
		{"retained vm", func(plan *APIPlan) { plan.VMID = 190 }},
		{"vm filename mismatch", func(plan *APIPlan) { plan.ImageFilename = "ubuntu.img" }},
		{"image content mismatch", func(plan *APIPlan) { plan.ImageContent = "iso" }},
		{"unpinned image", func(plan *APIPlan) { plan.CloudImage.SHA256 = strings.Repeat("e", 64) }},
		{"http endpoint", func(plan *APIPlan) { plan.Endpoint = "http://192.0.2.10:8006" }},
		{"endpoint path", func(plan *APIPlan) { plan.Endpoint = "https://192.0.2.10:8006/api2/json" }},
		{"endpoint userinfo", func(plan *APIPlan) { plan.Endpoint = "https://user@192.0.2.10:8006" }},
		{"uppercase certificate", func(plan *APIPlan) { plan.TLSCertificateSHA256 = strings.Repeat("A", 64) }},
		{"root guest", func(plan *APIPlan) { plan.AdminUser = "root" }},
		{"resource drift", func(plan *APIPlan) { plan.DataDiskGiB++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan := validAPIPlan()
			test.mutate(&plan)
			if err := plan.Validate(proxmoxProfile()); err == nil {
				t.Fatal("invalid API plan accepted")
			}
		})
	}
}

func TestAPIPlanReviewDeclaresSafetyAndPartialFailurePolicy(t *testing.T) {
	review := ReviewAPIPlan(validAPIPlan())
	if review["imageSourceURL"] != PinnedUbuntuImageURL {
		t.Fatalf("missing pinned image source: %#v", review)
	}
	policy, _ := review["partialFailurePolicy"].(string)
	if !strings.Contains(policy, "never auto-delete") {
		t.Fatalf("unsafe partial failure policy: %#v", review)
	}
}
