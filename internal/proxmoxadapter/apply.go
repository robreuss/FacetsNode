package proxmoxadapter

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

const gibibyte = uint64(1024 * 1024 * 1024)

type Runner interface {
	Output(context.Context, string, ...string) ([]byte, error)
	Run(context.Context, string, ...string) error
}

type ExecRunner struct{}

func (ExecRunner) Output(ctx context.Context, name string, arguments ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, arguments...)
	return command.Output()
}

func (ExecRunner) Run(ctx context.Context, name string, arguments ...string) error {
	command := exec.CommandContext(ctx, name, arguments...)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	return command.Run()
}

type clusterResource struct {
	VMID int    `json:"vmid"`
	Name string `json:"name"`
}

type storageStatus struct {
	Active  boolish `json:"active"`
	Enabled boolish `json:"enabled"`
	Avail   uint64  `json:"avail"`
	Content string  `json:"content"`
}

type boolish bool

func (value *boolish) UnmarshalJSON(data []byte) error {
	switch string(data) {
	case "true", "1":
		*value = true
	case "false", "0":
		*value = false
	default:
		return errors.New("invalid PVE boolean")
	}
	return nil
}

func Preflight(ctx context.Context, runner Runner, plan Plan) error {
	if os.Geteuid() != 0 {
		return errors.New("Proxmox adapter must run as root on the selected PVE node")
	}
	if runtime.GOARCH != plan.Architecture {
		return errors.New("Proxmox host architecture does not match plan")
	}
	version, err := runner.Output(ctx, "/usr/bin/pveversion")
	if err != nil || !strings.HasPrefix(strings.TrimSpace(string(version)), "pve-manager/") {
		return errors.New("PVE runtime unavailable")
	}
	node, err := runner.Output(ctx, "/bin/hostname", "-s")
	if err != nil || strings.TrimSpace(string(node)) != plan.Node {
		return errors.New("PVE node identity does not match plan")
	}
	if info, err := os.Stat(filepath.Join("/sys/class/net", plan.Bridge, "bridge")); err != nil || !info.IsDir() {
		return errors.New("planned PVE bridge is unavailable")
	}
	resources, err := runner.Output(ctx, "/usr/bin/pvesh", "get", "/cluster/resources", "--type", "vm", "--output-format", "json")
	if err != nil {
		return errors.New("PVE VM inventory unavailable")
	}
	var inventory []clusterResource
	if json.Unmarshal(resources, &inventory) != nil {
		return errors.New("invalid PVE VM inventory")
	}
	for _, resource := range inventory {
		if resource.VMID == plan.VMID || resource.Name == plan.Name {
			return errors.New("planned PVE VM identity is already in use")
		}
	}
	statusBytes, err := runner.Output(ctx, "/usr/bin/pvesh", "get", "/nodes/"+plan.Node+"/storage/"+plan.Storage+"/status", "--output-format", "json")
	if err != nil {
		return errors.New("planned PVE storage is unavailable")
	}
	var status storageStatus
	if json.Unmarshal(statusBytes, &status) != nil || !bool(status.Active) || !bool(status.Enabled) || !containsCSV(status.Content, "images") {
		return errors.New("planned PVE storage is inactive")
	}
	required := (plan.SystemDiskGiB + plan.DataDiskGiB + 8) * gibibyte
	if status.Avail < required {
		return errors.New("insufficient PVE storage for appliance plan")
	}
	if err = verifyEvidence(plan.CloudImage, int64(8*gibibyte)); err != nil {
		return fmt.Errorf("verify cloud image: %w", err)
	}
	if err = verifyEvidence(plan.SSHPublicKey, 16*1024); err != nil {
		return fmt.Errorf("verify SSH public key: %w", err)
	}
	key, err := os.ReadFile(plan.SSHPublicKey.Path)
	if err != nil || !validSSHPublicKey(key) {
		return errors.New("invalid SSH public key")
	}
	return nil
}

func verifyEvidence(evidence FileEvidence, maximumBytes int64) error {
	digest, err := FileSHA256(evidence.Path, maximumBytes)
	if err != nil {
		return err
	}
	if digest != evidence.SHA256 {
		return errors.New("file digest mismatch")
	}
	return nil
}

func validSSHPublicKey(data []byte) bool {
	fields := strings.Fields(strings.TrimSpace(string(data)))
	if len(fields) < 2 || len(fields) > 3 || fields[0] != "ssh-ed25519" {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil || len(decoded) != 4+len("ssh-ed25519")+4+32 {
		return false
	}
	algorithmLength := int(binary.BigEndian.Uint32(decoded[:4]))
	keyOffset := 4 + algorithmLength
	return algorithmLength == len("ssh-ed25519") && bytes.Equal(decoded[4:keyOffset], []byte("ssh-ed25519")) &&
		binary.BigEndian.Uint32(decoded[keyOffset:keyOffset+4]) == 32
}

func containsCSV(value, wanted string) bool {
	for _, entry := range strings.Split(value, ",") {
		if strings.TrimSpace(entry) == wanted {
			return true
		}
	}
	return false
}

func Apply(ctx context.Context, runner Runner, plan Plan) error {
	if err := Preflight(ctx, runner, plan); err != nil {
		return err
	}
	for index, arguments := range QMCommands(plan) {
		if err := runner.Run(ctx, "/usr/sbin/qm", arguments...); err != nil {
			return fmt.Errorf("PVE VM creation stopped at step %s (%d of %d): %w; the adapter did not destroy any partial VM", arguments[0], index+1, len(QMCommands(plan)), err)
		}
	}
	return nil
}

func Review(plan Plan) map[string]any {
	commands := make([]map[string]any, 0, len(QMCommands(plan)))
	for _, arguments := range QMCommands(plan) {
		commands = append(commands, map[string]any{"program": "/usr/sbin/qm", "arguments": arguments})
	}
	return map[string]any{
		"vmID": plan.VMID, "name": plan.Name, "node": plan.Node,
		"profileID": plan.ProfileID, "commands": commands,
		"retainedVMIDsExcluded": []int{180, 190},
		"partialFailurePolicy":  "leave-created-vm-stopped-or-partial-for-explicit-review",
	}
}

func AvailableVMID(ctx context.Context, runner Runner) (int, error) {
	output, err := runner.Output(ctx, "/usr/bin/pvesh", "get", "/cluster/nextid", "--output-format", "json")
	if err != nil {
		return 0, err
	}
	var value json.RawMessage
	if err = json.Unmarshal(output, &value); err != nil {
		return 0, err
	}
	var number int
	if len(value) > 0 && value[0] == '"' {
		var text string
		if json.Unmarshal(value, &text) != nil {
			return 0, errors.New("invalid PVE next VM ID")
		}
		number, err = strconv.Atoi(text)
	} else {
		err = json.Unmarshal(value, &number)
	}
	if err != nil || number < 100 || number > 999999 || number == 180 || number == 190 {
		return 0, errors.New("invalid PVE next VM ID")
	}
	return number, nil
}
