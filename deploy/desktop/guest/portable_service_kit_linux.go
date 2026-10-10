//go:build linux

package main

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/applianceprofile"
	"golang.org/x/sys/unix"
)

const (
	portableProfilePath        = "/etc/facets-box/profile.json"
	portableSourceArchive      = dataRoot + "/staging/source.tar"
	portableSourceMetadata     = dataRoot + "/staging/source.tar.json"
	portableServiceKitRoot     = dataRoot + "/appliance/service-kit"
	portableServiceKitRecord   = dataRoot + "/appliance/service-kit-installation.json"
	portableServiceBuildLog    = dataRoot + "/staging/service-kit-build.log"
	portableServiceProfileID   = "facets-box-proxmox-development-amd64"
	portableServiceHostAdapter = "proxmox-qemu"
)

type portableStorage struct {
	InstallationID string
	ProfileID      string
	Architecture   string
}

type portableServiceInstallation struct {
	Version              int               `json:"version"`
	InstalledAt          string            `json:"installedAt"`
	InstallationID       string            `json:"installationID"`
	ProfileID            string            `json:"profileID"`
	Architecture         string            `json:"architecture"`
	InstallerSHA256      string            `json:"installerSHA256"`
	SourceRevision       string            `json:"sourceRevision"`
	SourceTree           string            `json:"sourceTree"`
	SourceArchiveSHA256  string            `json:"sourceArchiveSHA256"`
	ServiceReleaseSHA256 string            `json:"serviceReleaseSHA256"`
	Images               map[string]string `json:"images"`
	Activation           string            `json:"activation"`
}

type portableServiceSummary struct {
	Version        int               `json:"version"`
	InstallationID string            `json:"installationID"`
	ProfileID      string            `json:"profileID"`
	Architecture   string            `json:"architecture"`
	SourceRevision string            `json:"sourceRevision,omitempty"`
	SourceTree     string            `json:"sourceTree,omitempty"`
	Images         map[string]string `json:"images,omitempty"`
	Activation     string            `json:"activation"`
}

func runPortableServiceKit(args []string) error {
	if os.Geteuid() != 0 {
		return errors.New("root appliance infrastructure is required")
	}
	if len(args) != 1 {
		return errors.New("usage: portable-service-kit check-storage|install|verify")
	}
	switch args[0] {
	case "check-storage":
		_, err := checkPortableStorage()
		return err
	case "install":
		summary, err := installPortableServiceKit()
		if err == nil {
			err = writePortableSummary(summary)
		}
		return err
	case "verify":
		summary, err := verifyPortableServiceKit()
		if err == nil {
			err = writePortableSummary(summary)
		}
		return err
	default:
		return errors.New("unknown portable service-kit operation")
	}
}

func writePortableSummary(summary portableServiceSummary) error {
	b, err := json.Marshal(summary)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(os.Stdout, string(b))
	return err
}

func checkPortableStorage() (portableStorage, error) {
	var result portableStorage
	profile, err := applianceprofile.Read(portableProfilePath)
	if err != nil || profile.ProfileID != portableServiceProfileID || profile.HostAdapter != portableServiceHostAdapter || profile.Architecture != "amd64" {
		return result, errors.New("portable appliance profile mismatch")
	}
	if runtime.GOARCH != "amd64" {
		return result, errors.New("portable appliance profile mismatch")
	}
	var stat unix.Statfs_t
	if err = unix.Statfs(dataRoot, &stat); err != nil || stat.Type != unix.EXT4_SUPER_MAGIC {
		return result, errors.New("retained data filesystem unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	b, err := privateOutput(ctx, "/usr/bin/findmnt", "--noheadings", "--output", "TARGET", "--target", dataRoot)
	if err != nil || strings.TrimSpace(string(b)) != dataRoot {
		return result, errors.New("retained data mount mismatch")
	}
	idBytes, err := boundedIdentityFile(dataRoot+"/installation-id", 128)
	id := strings.TrimSpace(string(idBytes))
	if err != nil {
		return result, errors.New("appliance installation identity unavailable")
	}
	if _, err = uuid.Parse(id); err != nil {
		return result, errors.New("invalid appliance installation identity")
	}
	b, err = privateOutput(ctx, "/usr/bin/docker", "info", "--format", "{{.DockerRootDir}}\t{{.ServerVersion}}")
	fields := strings.Split(strings.TrimSpace(string(b)), "\t")
	if err != nil || len(fields) != 2 || fields[0] != profile.Runtime.DataRoot || fields[1] != profile.Runtime.EngineVersion {
		return result, errors.New("container runtime profile mismatch")
	}
	b, err = privateOutput(ctx, "/usr/bin/docker", "compose", "version", "--short")
	if err != nil || strings.TrimSpace(string(b)) != profile.Runtime.ComposeVersion {
		return result, errors.New("Compose runtime profile mismatch")
	}
	return portableStorage{InstallationID: id, ProfileID: profile.ProfileID, Architecture: profile.Architecture}, nil
}

func readPortableSource() (transferArtifact, error) {
	var artifact transferArtifact
	b, err := boundedIdentityFile(portableSourceMetadata, 4096)
	if err != nil {
		return artifact, errors.New("source metadata unavailable")
	}
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&artifact); err != nil || decoder.Decode(&struct{}{}) != io.EOF || artifact.validateSource() != nil {
		return artifact, errors.New("invalid source metadata")
	}
	sum, size, err := fileHash(portableSourceArchive)
	if err != nil || sum != artifact.SHA256 || size != artifact.Size {
		return artifact, errors.New("source archive hash mismatch")
	}
	if err = verifySourceArchiveRevision(portableSourceArchive, artifact.Revision); err != nil {
		return artifact, err
	}
	return artifact, nil
}

func verifySourceArchiveRevision(path, expected string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	reader := tar.NewReader(f)
	seen := ""
	for {
		header, nextErr := reader.Next()
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil {
			return errors.New("source archive is unreadable")
		}
		if header.Typeflag == tar.TypeXGlobalHeader {
			value := header.PAXRecords["comment"]
			if seen != "" || !validHex(value, 20) {
				return errors.New("source archive commit metadata is invalid")
			}
			seen = value
		}
	}
	if seen != expected {
		return errors.New("source archive commit metadata mismatch")
	}
	return nil
}

func installPortableServiceKit() (portableServiceSummary, error) {
	var summary portableServiceSummary
	storage, err := checkPortableStorage()
	if err != nil {
		return summary, err
	}
	if _, err = os.Lstat(portableServiceKitRoot); !os.IsNotExist(err) {
		return summary, errors.New("a portable service kit is already installed")
	}
	if _, err = os.Lstat(portableServiceKitRecord); !os.IsNotExist(err) {
		return summary, errors.New("a portable service installation record already exists")
	}
	artifact, err := readPortableSource()
	if err != nil {
		return summary, err
	}
	if err = os.MkdirAll(filepath.Dir(portableServiceKitRoot), 0700); err != nil {
		return summary, err
	}
	work, err := os.MkdirTemp(dataRoot+"/staging", "build-")
	if err != nil {
		return summary, err
	}
	sourceRoot := filepath.Join(work, "source")
	f, err := os.Open(portableSourceArchive)
	if err == nil {
		err = extractSource(f, sourceRoot)
		f.Close()
	}
	if err != nil {
		return summary, errors.New("committed source staging failed")
	}
	buildScript := filepath.Join(sourceRoot, "deploy/desktop/guest-build.sh")
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()
	log, err := os.OpenFile(portableServiceBuildLog, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return summary, err
	}
	command := boundedCommand(ctx, "/bin/bash", buildScript, work, artifact.Revision, artifact.Tree)
	command.Env = append(os.Environ(), "FACETS_SERVICE_KIT_HOST_ADAPTER="+portableServiceHostAdapter)
	output := &boundedBuildLog{file: log, remaining: 16 * 1024 * 1024}
	command.Stdout, command.Stderr = output, output
	err = command.Run()
	log.Close()
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
	_ = boundedCommand(stopCtx, "/usr/bin/docker", "buildx", "stop", "fbd-builder").Run()
	stopCancel()
	if err != nil {
		return summary, errors.New("service-kit build failed; inspect the private build log")
	}
	kitRoot := filepath.Join(work, "kit")
	releaseBytes, err := boundedIdentityFile(filepath.Join(kitRoot, "service-release.json"), 65536)
	var release serviceRelease
	if err != nil || json.Unmarshal(releaseBytes, &release) != nil || release.SourceRevision != artifact.Revision || release.SourceTree != artifact.Tree || release.Architecture != storage.Architecture {
		return summary, errors.New("built service release evidence mismatch")
	}
	expected := serviceReleaseImages(release)
	if _, err = verifyServiceKit(kitRoot, expected, storage.Architecture); err != nil {
		return summary, err
	}
	if err = validateBuiltServiceKit(ctx, work, release); err != nil {
		return summary, fmt.Errorf("service-kit acceptance failed: %w", err)
	}
	if err = writePortableAcceptance(filepath.Join(kitRoot, "service-release.json"), releaseBytes); err != nil {
		return summary, err
	}
	releaseBytes, err = boundedIdentityFile(filepath.Join(kitRoot, "service-release.json"), 65536)
	if err != nil || json.Unmarshal(releaseBytes, &release) != nil || !portableAcceptanceComplete(release.Acceptance) {
		return summary, errors.New("accepted service release record unavailable")
	}
	if _, err = verifyServiceKit(kitRoot, expected, storage.Architecture); err != nil {
		return summary, err
	}
	if err = verifyPortableDormancy(ctx); err != nil {
		return summary, err
	}
	if err = os.Rename(kitRoot, portableServiceKitRoot); err != nil {
		return summary, err
	}
	if _, err = importServiceImagesAt(ctx, release, portableServiceKitRoot); err != nil {
		return summary, err
	}
	releaseHash, _, err := fileHash(filepath.Join(portableServiceKitRoot, "service-release.json"))
	if err != nil {
		return summary, err
	}
	executable, err := os.Executable()
	if err != nil {
		return summary, err
	}
	installerHash, _, err := fileHash(executable)
	if err != nil {
		return summary, err
	}
	record := portableServiceInstallation{
		Version: 1, InstalledAt: time.Now().UTC().Format(time.RFC3339), InstallationID: storage.InstallationID,
		ProfileID: storage.ProfileID, Architecture: storage.Architecture, InstallerSHA256: installerHash, SourceRevision: release.SourceRevision,
		SourceTree: release.SourceTree, SourceArchiveSHA256: artifact.SHA256, ServiceReleaseSHA256: releaseHash,
		Images: expected, Activation: "withheld",
	}
	if err = os.RemoveAll(work); err != nil {
		return summary, errors.New("accepted service-kit scratch cleanup failed")
	}
	if err = writeJSONFile(portableServiceKitRecord, record); err != nil {
		return summary, err
	}
	return portableSummary(storage, release), nil
}

func writePortableAcceptance(path string, original []byte) error {
	var record map[string]any
	if json.Unmarshal(original, &record) != nil {
		return errors.New("invalid service release record")
	}
	record["acceptance"] = map[string]string{
		"dockerfileTests": "passed", "ociVerification": "passed", "renderedComposeBoundary": "passed",
		"ingressConfiguration": "passed", "offlineOnionIdentity": "passed", "isolatedServiceRuntime": "passed",
		"isolatedControllerClaimHTTPS": "passed", "containerRecreationIdentity": "passed", "candidateMaintenance": "passed",
		"serviceRuntime": "not-installed", "spacesSync": "not-run",
	}
	return writeJSONFile(path, record)
}

func portableAcceptanceComplete(acceptance map[string]string) bool {
	for _, name := range []string{"dockerfileTests", "ociVerification", "renderedComposeBoundary", "ingressConfiguration", "offlineOnionIdentity", "isolatedServiceRuntime", "isolatedControllerClaimHTTPS", "containerRecreationIdentity", "candidateMaintenance"} {
		if acceptance[name] != "passed" {
			return false
		}
	}
	return acceptance["serviceRuntime"] == "not-installed" && acceptance["spacesSync"] == "not-run"
}

func serviceReleaseImages(release serviceRelease) map[string]string {
	images := make(map[string]string, len(release.Images))
	for name, image := range release.Images {
		images[name] = image.Digest
	}
	return images
}

func verifyPortableServiceKit() (portableServiceSummary, error) {
	var summary portableServiceSummary
	storage, err := checkPortableStorage()
	if err != nil {
		return summary, err
	}
	var record portableServiceInstallation
	b, err := boundedIdentityFile(portableServiceKitRecord, 65536)
	if err != nil {
		return summary, errors.New("portable service installation record unavailable")
	}
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&record); err != nil || decoder.Decode(&struct{}{}) != io.EOF || record.Version != 1 || record.InstallationID != storage.InstallationID || record.ProfileID != storage.ProfileID || record.Architecture != storage.Architecture || record.Activation != "withheld" || len(record.Images) != len(imageNames) || !validHex(record.InstallerSHA256, 32) || !validHex(record.SourceArchiveSHA256, 32) || !validHex(record.ServiceReleaseSHA256, 32) {
		return summary, errors.New("invalid portable service installation record")
	}
	executable, err := os.Executable()
	if err != nil {
		return summary, err
	}
	installerHash, _, err := fileHash(executable)
	if err != nil || installerHash != record.InstallerSHA256 {
		return summary, errors.New("portable service installer hash mismatch")
	}
	releaseHash, _, err := fileHash(filepath.Join(portableServiceKitRoot, "service-release.json"))
	if err != nil || releaseHash != record.ServiceReleaseSHA256 {
		return summary, errors.New("installed service release hash mismatch")
	}
	release, err := verifyServiceKit(portableServiceKitRoot, record.Images, storage.Architecture)
	if err != nil || release.SourceRevision != record.SourceRevision || release.SourceTree != record.SourceTree || !portableAcceptanceComplete(release.Acceptance) {
		return summary, errors.New("installed service release evidence mismatch")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for name, digest := range record.Images {
		image, inspectErr := privateOutput(ctx, "/usr/bin/docker", "image", "inspect", "--platform", "linux/"+storage.Architecture, "--format", "{{.Id}}", digest)
		if inspectErr != nil || strings.TrimSpace(string(image)) != digest {
			return summary, fmt.Errorf("installed %s image identity mismatch", name)
		}
	}
	if err = verifyPortableDormancy(ctx); err != nil {
		return summary, err
	}
	return portableSummary(storage, release), nil
}

func verifyPortableDormancy(ctx context.Context) error {
	for _, path := range []string{
		dataRoot + "/configuration", dataRoot + "/service-activation.json",
		dataRoot + "/fbd-device-sync-onion-identity.json", dataRoot + "/fbd-shared-spaces-onion-identity.json",
		"/opt/fbd/device-sync.env", "/opt/fbd/shared-spaces.env",
	} {
		if _, err := os.Lstat(path); err == nil || !os.IsNotExist(err) {
			return errors.New("durable service authority exists before activation")
		}
	}
	containers, err := privateOutput(ctx, "/usr/bin/docker", "container", "ls", "--all", "--format", "{{.Names}}")
	if err != nil {
		return err
	}
	for _, name := range strings.Fields(string(containers)) {
		if portableRuntimeFixture(name) {
			return errors.New("service or acceptance container remains installed")
		}
	}
	volumes, err := privateOutput(ctx, "/usr/bin/docker", "volume", "ls", "--format", "{{.Name}}")
	if err != nil {
		return err
	}
	for _, name := range strings.Fields(string(volumes)) {
		if portableRuntimeFixture(name) {
			return errors.New("service or acceptance volume remains installed")
		}
	}
	return nil
}

func portableRuntimeFixture(name string) bool {
	for _, prefix := range []string{deviceProject, sharedProject, "fbd-validation-", "fbd-build-onion-"} {
		if strings.HasSuffix(prefix, "-") && strings.HasPrefix(name, prefix) {
			return true
		}
		if name == prefix || strings.HasPrefix(name, prefix+"-") || strings.HasPrefix(name, prefix+"_") {
			return true
		}
	}
	return false
}

func portableSummary(storage portableStorage, release serviceRelease) portableServiceSummary {
	return portableServiceSummary{
		Version: 1, InstallationID: storage.InstallationID, ProfileID: storage.ProfileID,
		Architecture: storage.Architecture, SourceRevision: release.SourceRevision, SourceTree: release.SourceTree,
		Images: serviceReleaseImages(release), Activation: "withheld",
	}
}
