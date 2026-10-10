package proxmoxadapter

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/robreuss/FacetsNode/internal/applianceprofile"
)

const MaximumPlanBytes = 64 * 1024

var (
	identifierPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$`)
	userPattern       = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
)

type FileEvidence struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type Plan struct {
	SchemaVersion    int          `json:"schemaVersion"`
	ProfileID        string       `json:"profileID"`
	Architecture     string       `json:"architecture"`
	Node             string       `json:"node"`
	VMID             int          `json:"vmID"`
	Name             string       `json:"name"`
	Storage          string       `json:"storage"`
	Bridge           string       `json:"bridge"`
	AdminUser        string       `json:"adminUser"`
	CloudImage       FileEvidence `json:"cloudImage"`
	SSHPublicKey     FileEvidence `json:"sshPublicKey"`
	CPUCount         int          `json:"cpuCount"`
	MemoryMiB        int          `json:"memoryMiB"`
	SystemDiskGiB    uint64       `json:"systemDiskGiB"`
	DataDiskGiB      uint64       `json:"dataDiskGiB"`
	StartAfterCreate bool         `json:"startAfterCreate"`
}

func NewPlan(profile applianceprofile.Profile, node string, vmID int, name, storage, bridge, adminUser string, cloudImage, sshPublicKey FileEvidence) Plan {
	return Plan{
		SchemaVersion: 1, ProfileID: profile.ProfileID, Architecture: profile.Architecture,
		Node: node, VMID: vmID, Name: name, Storage: storage, Bridge: bridge, AdminUser: adminUser,
		CloudImage: cloudImage, SSHPublicKey: sshPublicKey,
		CPUCount: profile.Resources.CPUCount, MemoryMiB: profile.Resources.MemoryMiB,
		SystemDiskGiB: profile.Storage.System.MinimumGiB, DataDiskGiB: profile.Storage.Data.MinimumGiB,
		StartAfterCreate: true,
	}
}

func (plan Plan) Validate(profile applianceprofile.Profile) error {
	if err := profile.Validate(); err != nil {
		return err
	}
	if profile.HostAdapter != "proxmox-qemu" || profile.ManagementTransport != "private-ssh" || profile.Architecture != "amd64" {
		return errors.New("profile is not a supported Proxmox adapter")
	}
	if plan.SchemaVersion != 1 || plan.ProfileID != profile.ProfileID || plan.Architecture != profile.Architecture {
		return errors.New("plan does not match appliance profile")
	}
	if plan.VMID < 100 || plan.VMID > 999999 || plan.VMID == 180 || plan.VMID == 190 {
		return errors.New("invalid or retained Proxmox VM ID")
	}
	for _, value := range []string{plan.Node, plan.Name, plan.Storage, plan.Bridge} {
		if !identifierPattern.MatchString(value) {
			return errors.New("invalid Proxmox identifier")
		}
	}
	if !userPattern.MatchString(plan.AdminUser) || plan.AdminUser == "root" {
		return errors.New("invalid appliance administrator")
	}
	if plan.CPUCount != profile.Resources.CPUCount || plan.MemoryMiB != profile.Resources.MemoryMiB || plan.SystemDiskGiB != profile.Storage.System.MinimumGiB || plan.DataDiskGiB != profile.Storage.Data.MinimumGiB {
		return errors.New("plan resources do not match appliance profile")
	}
	if !validFileEvidence(plan.CloudImage) || !validFileEvidence(plan.SSHPublicKey) {
		return errors.New("invalid Proxmox input evidence")
	}
	if !plan.StartAfterCreate {
		return errors.New("development appliance must complete first boot")
	}
	return nil
}

func validFileEvidence(evidence FileEvidence) bool {
	return len(evidence.Path) > 0 && len(evidence.Path) <= 4096 && filepath.IsAbs(evidence.Path) && filepath.Clean(evidence.Path) == evidence.Path &&
		!strings.ContainsAny(evidence.Path, ",\x00\r\n\t") && validHex(evidence.SHA256, 64)
}

func validHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value == string(bytes.ToLower([]byte(value)))
}

func ReadPlan(path string, profile applianceprofile.Profile) (Plan, error) {
	plan, _, err := readPlan(path, profile)
	return plan, err
}

func ReadApprovedPlan(path string, profile applianceprofile.Profile, approval string) (Plan, error) {
	plan, data, err := readPlan(path, profile)
	if err != nil {
		return Plan{}, err
	}
	if !validHex(approval, 64) || PlanDigest(data) != approval {
		return Plan{}, errors.New("Proxmox plan approval digest mismatch")
	}
	return plan, nil
}

func readPlan(path string, profile applianceprofile.Profile) (Plan, []byte, error) {
	var plan Plan
	info, err := os.Lstat(path)
	if err != nil {
		return plan, nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > MaximumPlanBytes {
		return plan, nil, errors.New("invalid Proxmox plan file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return plan, nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&plan); err != nil {
		return Plan{}, nil, fmt.Errorf("decode Proxmox plan: %w", err)
	}
	if err = decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Plan{}, nil, errors.New("trailing Proxmox plan content")
	}
	if err = plan.Validate(profile); err != nil {
		return Plan{}, nil, err
	}
	return plan, data, nil
}

func EncodePlan(plan Plan) ([]byte, error) {
	data, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func PlanDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func FileSHA256(path string, maximumBytes int64) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximumBytes {
		return "", errors.New("invalid plan input file")
	}
	if info.Mode().Perm()&0022 != 0 {
		return "", errors.New("plan input file is group/world writable")
	}
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0022 != 0 {
		return "", errors.New("plan input directory is group/world writable")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err = io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func QMCommands(plan Plan) [][]string {
	vmID := strconv.Itoa(plan.VMID)
	return [][]string{
		{"create", vmID, "--name", plan.Name, "--description", "Facets Box portable development appliance; profile=" + plan.ProfileID, "--ostype", "l26", "--cpu", "host", "--cores", strconv.Itoa(plan.CPUCount), "--memory", strconv.Itoa(plan.MemoryMiB), "--balloon", "0", "--scsihw", "virtio-scsi-single", "--agent", "enabled=1,fstrim_cloned_disks=1", "--net0", "virtio,bridge=" + plan.Bridge, "--onboot", "0", "--serial0", "socket", "--vga", "serial0"},
		{"set", vmID, "--scsi0", plan.Storage + ":0,import-from=" + plan.CloudImage.Path + ",discard=on,ssd=1,iothread=1,serial=facets-system"},
		{"resize", vmID, "scsi0", strconv.FormatUint(plan.SystemDiskGiB, 10) + "G"},
		{"set", vmID, "--scsi1", plan.Storage + ":" + strconv.FormatUint(plan.DataDiskGiB, 10) + ",discard=on,ssd=1,iothread=1,serial=facets-data"},
		{"set", vmID, "--ide2", plan.Storage + ":cloudinit", "--boot", "order=scsi0", "--ciuser", plan.AdminUser, "--sshkeys", plan.SSHPublicKey.Path, "--ipconfig0", "ip=dhcp"},
		{"start", vmID},
	}
}
