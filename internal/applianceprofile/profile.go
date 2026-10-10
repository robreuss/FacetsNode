package applianceprofile

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

const MaximumProfileBytes = 64 * 1024

var (
	profileIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,79}$`)
	versionPattern   = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){1,3}(?:[-+][a-z0-9.-]+)?$`)
)

type Profile struct {
	SchemaVersion       int              `json:"schemaVersion"`
	ProfileID           string           `json:"profileID"`
	Architecture        string           `json:"architecture"`
	HostAdapter         string           `json:"hostAdapter"`
	ManagementTransport string           `json:"managementTransport"`
	Guest               Guest            `json:"guest"`
	Resources           Resources        `json:"resources"`
	Storage             Storage          `json:"storage"`
	Runtime             ContainerRuntime `json:"runtime"`
}

type Guest struct {
	OS            string `json:"os"`
	Distribution  string `json:"distribution"`
	Release       string `json:"release"`
	AgentProtocol int    `json:"agentProtocol"`
}

type Resources struct {
	CPUCount  int `json:"cpuCount"`
	MemoryMiB int `json:"memoryMiB"`
}

type Storage struct {
	System Disk `json:"system"`
	Data   Disk `json:"data"`
}

type Disk struct {
	MinimumGiB  uint64 `json:"minimumGiB"`
	Disposition string `json:"disposition"`
	MountPath   string `json:"mountPath,omitempty"`
}

type ContainerRuntime struct {
	EngineVersion     string `json:"engineVersion"`
	ComposeVersion    string `json:"composeVersion"`
	ContainerdVersion string `json:"containerdVersion"`
	DataRoot          string `json:"dataRoot"`
}

func Read(path string) (Profile, error) {
	profile, _, err := ReadWithSHA256(path)
	return profile, err
}

// ReadWithSHA256 binds callers to the exact committed profile bytes in addition
// to the decoded policy. The digest is intentionally over the file, not a
// re-encoding, so signed host artifacts and guest service releases can compare
// one unambiguous value.
func ReadWithSHA256(path string) (Profile, string, error) {
	var profile Profile
	info, err := os.Lstat(path)
	if err != nil {
		return profile, "", err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > MaximumProfileBytes {
		return profile, "", errors.New("invalid appliance profile file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return profile, "", err
	}
	profile, err = Decode(data)
	if err != nil {
		return Profile{}, "", err
	}
	digest := sha256.Sum256(data)
	return profile, fmt.Sprintf("%x", digest), nil
}

func Decode(data []byte) (Profile, error) {
	var profile Profile
	if len(data) == 0 || len(data) > MaximumProfileBytes {
		return profile, errors.New("invalid appliance profile size")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&profile); err != nil {
		return Profile{}, fmt.Errorf("decode appliance profile: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Profile{}, errors.New("trailing appliance profile content")
	}
	if err := profile.Validate(); err != nil {
		return Profile{}, err
	}
	return profile, nil
}

func (profile Profile) Validate() error {
	if profile.SchemaVersion != 1 || !profileIDPattern.MatchString(profile.ProfileID) {
		return errors.New("invalid appliance profile identity")
	}
	if profile.Architecture != "arm64" && profile.Architecture != "amd64" {
		return errors.New("unsupported appliance architecture")
	}
	transports := map[string]string{
		"fbd-virtualization-framework": "virtio-socket",
		"proxmox-qemu":                 "private-ssh",
	}
	if transports[profile.HostAdapter] != profile.ManagementTransport {
		return errors.New("invalid appliance host adapter transport")
	}
	if profile.Guest.OS != "linux" || profile.Guest.Distribution != "ubuntu" || profile.Guest.Release != "24.04" || profile.Guest.AgentProtocol != 1 {
		return errors.New("unsupported appliance guest")
	}
	if profile.Resources.CPUCount < 1 || profile.Resources.CPUCount > 32 || profile.Resources.MemoryMiB < 2048 || profile.Resources.MemoryMiB > 65536 {
		return errors.New("invalid appliance resources")
	}
	if profile.Storage.System.MinimumGiB < 16 || profile.Storage.System.MinimumGiB > 256 || profile.Storage.System.Disposition != "replaceable" || profile.Storage.System.MountPath != "" {
		return errors.New("invalid appliance system storage")
	}
	if profile.Storage.Data.MinimumGiB < 64 || profile.Storage.Data.MinimumGiB > 16*1024 || profile.Storage.Data.Disposition != "retained-authority" || profile.Storage.Data.MountPath != "/srv/facets-box-data" {
		return errors.New("invalid appliance data storage")
	}
	for _, version := range []string{profile.Runtime.EngineVersion, profile.Runtime.ComposeVersion, profile.Runtime.ContainerdVersion} {
		if !versionPattern.MatchString(strings.ToLower(version)) {
			return errors.New("invalid appliance runtime version")
		}
	}
	if profile.Runtime.DataRoot != "/srv/facets-box-data/docker" {
		return errors.New("invalid appliance runtime data root")
	}
	return nil
}
