package proxmoxadapter

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/robreuss/FacetsNode/internal/applianceprofile"
)

const (
	PinnedUbuntuImageURL    = "https://cloud-images.ubuntu.com/minimal/releases/noble/release-20260905/ubuntu-24.04-minimal-cloudimg-amd64.img"
	PinnedUbuntuImageSHA256 = "46b0dbaffa6950a7da5ff2dc5ed34c46084610b3b6d1fae8f1ec2d7e953984a3"
)

type APIPlan struct {
	SchemaVersion        int          `json:"schemaVersion"`
	ProfileID            string       `json:"profileID"`
	Architecture         string       `json:"architecture"`
	Endpoint             string       `json:"endpoint"`
	TLSCertificateSHA256 string       `json:"tlsCertificateSHA256"`
	Node                 string       `json:"node"`
	VMID                 int          `json:"vmID"`
	Name                 string       `json:"name"`
	Storage              string       `json:"storage"`
	ImageStorage         string       `json:"imageStorage"`
	ImageContent         string       `json:"imageContent"`
	ImageFilename        string       `json:"imageFilename"`
	Bridge               string       `json:"bridge"`
	AdminUser            string       `json:"adminUser"`
	CloudImage           FileEvidence `json:"cloudImage"`
	SSHPublicKey         FileEvidence `json:"sshPublicKey"`
	CPUCount             int          `json:"cpuCount"`
	MemoryMiB            int          `json:"memoryMiB"`
	SystemDiskGiB        uint64       `json:"systemDiskGiB"`
	DataDiskGiB          uint64       `json:"dataDiskGiB"`
	StartAfterCreate     bool         `json:"startAfterCreate"`
}

type APIOperation struct {
	Name           string            `json:"name"`
	Method         string            `json:"method"`
	Path           string            `json:"path"`
	Form           map[string]string `json:"form,omitempty"`
	UploadPath     string            `json:"uploadPath,omitempty"`
	UploadFilename string            `json:"uploadFilename,omitempty"`
}

func NewAPIPlan(profile applianceprofile.Profile, endpoint, tlsCertificateSHA256, node string, vmID int, name, storage, imageStorage, bridge, adminUser string, cloudImage, sshPublicKey FileEvidence) APIPlan {
	return APIPlan{
		SchemaVersion: 2, ProfileID: profile.ProfileID, Architecture: profile.Architecture,
		Endpoint: endpoint, TLSCertificateSHA256: tlsCertificateSHA256,
		Node: node, VMID: vmID, Name: name, Storage: storage, ImageStorage: imageStorage,
		ImageContent: "import", ImageFilename: apiImageFilename(vmID), Bridge: bridge, AdminUser: adminUser,
		CloudImage: cloudImage, SSHPublicKey: sshPublicKey,
		CPUCount: profile.Resources.CPUCount, MemoryMiB: profile.Resources.MemoryMiB,
		SystemDiskGiB: profile.Storage.System.MinimumGiB, DataDiskGiB: profile.Storage.Data.MinimumGiB,
		StartAfterCreate: true,
	}
}

func (plan APIPlan) Validate(profile applianceprofile.Profile) error {
	if err := profile.Validate(); err != nil {
		return err
	}
	if profile.HostAdapter != "proxmox-qemu" || profile.ManagementTransport != "private-ssh" || profile.Architecture != "amd64" {
		return errors.New("profile is not a supported Proxmox API adapter")
	}
	if plan.SchemaVersion != 2 || plan.ProfileID != profile.ProfileID || plan.Architecture != profile.Architecture {
		return errors.New("API plan does not match appliance profile")
	}
	if plan.VMID < 100 || plan.VMID > 999999 || plan.VMID == 180 || plan.VMID == 190 {
		return errors.New("invalid or retained Proxmox VM ID")
	}
	for _, value := range []string{plan.Node, plan.Name, plan.Storage, plan.ImageStorage, plan.Bridge} {
		if !identifierPattern.MatchString(value) {
			return errors.New("invalid Proxmox API identifier")
		}
	}
	if !userPattern.MatchString(plan.AdminUser) || plan.AdminUser == "root" {
		return errors.New("invalid appliance administrator")
	}
	endpoint, err := normalizeAPIEndpoint(plan.Endpoint)
	if err != nil || endpoint != plan.Endpoint {
		return errors.New("invalid or non-canonical Proxmox API endpoint")
	}
	if !validHex(plan.TLSCertificateSHA256, 64) {
		return errors.New("invalid Proxmox TLS certificate digest")
	}
	if plan.ImageContent != "import" || plan.ImageFilename != apiImageFilename(plan.VMID) || filepath.Base(plan.ImageFilename) != plan.ImageFilename {
		return errors.New("invalid Proxmox image filename")
	}
	if !validFileEvidence(plan.CloudImage) || plan.CloudImage.SHA256 != PinnedUbuntuImageSHA256 || !validFileEvidence(plan.SSHPublicKey) {
		return errors.New("invalid Proxmox API input evidence")
	}
	if plan.CPUCount != profile.Resources.CPUCount || plan.MemoryMiB != profile.Resources.MemoryMiB || plan.SystemDiskGiB != profile.Storage.System.MinimumGiB || plan.DataDiskGiB != profile.Storage.Data.MinimumGiB {
		return errors.New("API plan resources do not match appliance profile")
	}
	if !plan.StartAfterCreate {
		return errors.New("development appliance must complete first boot")
	}
	return nil
}

func normalizeAPIEndpoint(value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("Proxmox API endpoint must be an HTTPS origin")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", errors.New("Proxmox API endpoint must not contain a path")
	}
	parsed.Path = ""
	parsed.RawPath = ""
	return parsed.String(), nil
}

func apiImageFilename(vmID int) string {
	return "facets-box-ubuntu-24.04-minimal-20260905-vm" + strconv.Itoa(vmID) + "-46b0dbaf.qcow2"
}

func ReadAPIPlan(path string, profile applianceprofile.Profile) (APIPlan, error) {
	plan, _, err := readAPIPlan(path, profile)
	return plan, err
}

func ReadApprovedAPIPlan(path string, profile applianceprofile.Profile, approval string) (APIPlan, error) {
	plan, data, err := readAPIPlan(path, profile)
	if err != nil {
		return APIPlan{}, err
	}
	if !validHex(approval, 64) || PlanDigest(data) != approval {
		return APIPlan{}, errors.New("Proxmox API plan approval digest mismatch")
	}
	return plan, nil
}

func readAPIPlan(path string, profile applianceprofile.Profile) (APIPlan, []byte, error) {
	var plan APIPlan
	info, err := os.Lstat(path)
	if err != nil {
		return plan, nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > MaximumPlanBytes {
		return plan, nil, errors.New("invalid Proxmox API plan file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return plan, nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&plan); err != nil {
		return APIPlan{}, nil, fmt.Errorf("decode Proxmox API plan: %w", err)
	}
	if err = decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return APIPlan{}, nil, errors.New("trailing Proxmox API plan content")
	}
	if err = plan.Validate(profile); err != nil {
		return APIPlan{}, nil, err
	}
	return plan, data, nil
}

func EncodeAPIPlan(plan APIPlan) ([]byte, error) {
	data, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func APIOperations(plan APIPlan, publicKey string) []APIOperation {
	vmID := strconv.Itoa(plan.VMID)
	vmPath := "/nodes/" + plan.Node + "/qemu/" + vmID
	sourceVolume := plan.ImageStorage + ":" + plan.ImageContent + "/" + plan.ImageFilename
	return []APIOperation{
		{
			Name: "upload-cloud-image", Method: "POST", Path: "/nodes/" + plan.Node + "/storage/" + plan.ImageStorage + "/upload",
			Form:       map[string]string{"content": plan.ImageContent, "checksum": plan.CloudImage.SHA256, "checksum-algorithm": "sha256"},
			UploadPath: plan.CloudImage.Path, UploadFilename: plan.ImageFilename,
		},
		{
			Name: "create-vm", Method: "POST", Path: "/nodes/" + plan.Node + "/qemu",
			Form: map[string]string{
				"vmid": vmID, "name": plan.Name, "description": "Facets Box portable development appliance; profile=" + plan.ProfileID,
				"ostype": "l26", "cpu": "host", "cores": strconv.Itoa(plan.CPUCount), "memory": strconv.Itoa(plan.MemoryMiB),
				"balloon": "0", "scsihw": "virtio-scsi-single", "agent": "enabled=1,fstrim_cloned_disks=1",
				"net0": "virtio,bridge=" + plan.Bridge, "onboot": "0", "serial0": "socket", "vga": "serial0",
			},
		},
		{
			Name: "import-system-disk", Method: "PUT", Path: vmPath + "/config",
			Form: map[string]string{"scsi0": plan.Storage + ":0,import-from=" + sourceVolume + ",discard=on,ssd=1,iothread=1,serial=facets-system"},
		},
		{
			Name: "resize-system-disk", Method: "PUT", Path: vmPath + "/resize",
			Form: map[string]string{"disk": "scsi0", "size": strconv.FormatUint(plan.SystemDiskGiB, 10) + "G"},
		},
		{
			Name: "create-data-disk", Method: "PUT", Path: vmPath + "/config",
			Form: map[string]string{"scsi1": plan.Storage + ":" + strconv.FormatUint(plan.DataDiskGiB, 10) + ",discard=on,ssd=1,iothread=1,serial=facets-data"},
		},
		{
			Name: "configure-cloud-init", Method: "PUT", Path: vmPath + "/config",
			Form: map[string]string{
				"ide2": plan.Storage + ":cloudinit", "boot": "order=scsi0", "ciuser": plan.AdminUser,
				"sshkeys": publicKey, "ipconfig0": "ip=dhcp",
			},
		},
		{Name: "start-vm", Method: "POST", Path: vmPath + "/status/start"},
	}
}

func ReviewAPIPlan(plan APIPlan) map[string]any {
	return map[string]any{
		"endpoint": plan.Endpoint, "tlsCertificateSHA256": plan.TLSCertificateSHA256,
		"vmID": plan.VMID, "name": plan.Name, "node": plan.Node, "profileID": plan.ProfileID,
		"imageSourceURL": PinnedUbuntuImageURL, "imageContent": plan.ImageContent, "operations": APIOperations(plan, "<verified-ed25519-public-key>"),
		"retainedVMIDsExcluded": []int{180, 190},
		"hostSafetyGates":       []string{"no-active-backup", "bounded-load", "unused-vm-id-and-name", "active-capable-storage-and-bridge", "absent-upload-target"},
		"partialFailurePolicy":  "leave-upload-and-created-vm-for-explicit-review; never auto-delete",
	}
}

func canonicalPublicKey(data []byte) (string, error) {
	if !validSSHPublicKey(data) {
		return "", errors.New("invalid SSH public key")
	}
	fields := strings.Fields(strings.TrimSpace(string(data)))
	return fields[0] + " " + fields[1], nil
}
