package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// imageNames is the exact portable release set. Job Custody and Storage
// Capacity are shipped as dormant images until their independent identities,
// retained state, and activation policy are provisioned.
var imageNames = []string{
	"device-sync", "box-controller", "shared-spaces", "job-custody",
	"storage-capacity-authority", "postgres", "caddy", "tor",
}

// runtimeImageNames is the already activated appliance surface. Keeping this
// separate prevents merely shipping a verified image from being reported as a
// running or accepted service.
var runtimeImageNames = []string{
	"device-sync", "box-controller", "shared-spaces", "postgres", "caddy", "tor",
}

type serviceImage struct {
	Digest    string `json:"digest"`
	Config    string `json:"config"`
	Reference string `json:"reference"`
}
type serviceRelease struct {
	Version                int                     `json:"version"`
	Architecture           string                  `json:"architecture"`
	ApplianceProfileID     string                  `json:"applianceProfileID"`
	ApplianceProfileSHA256 string                  `json:"applianceProfileSHA256"`
	SourceRevision         string                  `json:"sourceRevision"`
	SourceTree             string                  `json:"sourceTree"`
	Images                 map[string]serviceImage `json:"images"`
	Acceptance             map[string]string       `json:"acceptance,omitempty"`
}

type applianceReleaseBinding struct {
	Architecture  string
	ProfileID     string
	ProfileSHA256 string
}

func digestPath(root, digest string) (string, error) {
	if !strings.HasPrefix(digest, "sha256:") || !validHex(strings.TrimPrefix(digest, "sha256:"), 32) {
		return "", errors.New("invalid OCI digest")
	}
	return filepath.Join(root, "blobs", "sha256", digest[7:]), nil
}
func verifiedBlob(root, digest string, size int64) ([]byte, error) {
	path, e := digestPath(root, digest)
	if e != nil {
		return nil, e
	}
	stat, e := os.Lstat(path)
	if e != nil || !stat.Mode().IsRegular() || stat.Size() > size {
		return nil, errors.New("invalid OCI blob")
	}
	sum, _, e := fileHash(path)
	if e != nil || "sha256:"+sum != digest {
		return nil, errors.New("OCI digest mismatch")
	}
	return os.ReadFile(path)
}
func supportedServiceArchitecture(architecture string) bool {
	return architecture == "arm64" || architecture == "amd64"
}

func verifyServiceKit(root string, expected map[string]string, binding applianceReleaseBinding) (serviceRelease, error) {
	var release serviceRelease
	b, e := os.ReadFile(filepath.Join(root, "service-release.json"))
	if e != nil || len(b) > 65536 || json.Unmarshal(b, &release) != nil {
		return release, errors.New("invalid service release")
	}
	if !supportedServiceArchitecture(binding.Architecture) || release.Version != 2 || release.Architecture != binding.Architecture || release.ApplianceProfileID != binding.ProfileID || release.ApplianceProfileSHA256 != binding.ProfileSHA256 || binding.ProfileID == "" || !validHex(binding.ProfileSHA256, 32) || !validHex(release.SourceRevision, 20) || !validHex(release.SourceTree, 20) || len(release.Images) != len(imageNames) || len(expected) != len(imageNames) {
		return release, errors.New("incompatible service release")
	}
	for _, name := range imageNames {
		image, ok := release.Images[name]
		if !ok || expected[name] != image.Digest {
			return release, errors.New("service image mismatch")
		}
		imageRoot := filepath.Join(root, "images", name)
		raw, e := verifiedBlob(imageRoot, image.Digest, 4*1024*1024)
		if e != nil {
			return release, e
		}
		type descriptor struct {
			Digest string `json:"digest"`
			Size   int64  `json:"size"`
		}
		var manifest struct {
			SchemaVersion int          `json:"schemaVersion"`
			Config        descriptor   `json:"config"`
			Layers        []descriptor `json:"layers"`
		}
		if json.Unmarshal(raw, &manifest) != nil || manifest.SchemaVersion != 2 || manifest.Config.Digest != image.Config || len(manifest.Layers) > 128 {
			return release, errors.New("invalid OCI manifest")
		}
		config, e := verifiedBlob(imageRoot, image.Config, 4*1024*1024)
		if e != nil {
			return release, e
		}
		if int64(len(config)) != manifest.Config.Size {
			return release, errors.New("OCI config size mismatch")
		}
		var platform struct {
			OS           string `json:"os"`
			Architecture string `json:"architecture"`
			Config       struct {
				Labels map[string]string `json:"Labels"`
			} `json:"config"`
		}
		if json.Unmarshal(config, &platform) != nil || platform.OS != "linux" || platform.Architecture != release.Architecture {
			return release, errors.New("wrong OCI platform")
		}
		if name == "device-sync" || name == "box-controller" || name == "shared-spaces" ||
			name == "job-custody" || name == "storage-capacity-authority" {
			if platform.Config.Labels["org.opencontainers.image.revision"] != release.SourceRevision || platform.Config.Labels["org.opencontainers.image.source-tree"] != release.SourceTree {
				return release, errors.New("OCI source revision mismatch")
			}
		}
		for _, layer := range manifest.Layers {
			path, e := digestPath(imageRoot, layer.Digest)
			if e != nil {
				return release, e
			}
			stat, e := os.Lstat(path)
			if e != nil || !stat.Mode().IsRegular() || stat.Size() != layer.Size || layer.Size < 0 || layer.Size > 4*1024*1024*1024 {
				return release, errors.New("invalid OCI layer")
			}
			sum, _, e := fileHash(path)
			if e != nil || "sha256:"+sum != layer.Digest {
				return release, errors.New("OCI layer hash mismatch")
			}
		}
		// Skopeo imports the named index entry, so bind that reference to the very
		// manifest just checked rather than trusting an unrelated index.json.
		indexBytes, e := os.ReadFile(filepath.Join(imageRoot, "index.json"))
		var index struct {
			Manifests []struct {
				Digest      string            `json:"digest"`
				Annotations map[string]string `json:"annotations"`
			} `json:"manifests"`
		}
		if e != nil || len(indexBytes) > 65536 || json.Unmarshal(indexBytes, &index) != nil || len(index.Manifests) != 1 || index.Manifests[0].Digest != image.Digest || index.Manifests[0].Annotations["org.opencontainers.image.ref.name"] != "release" {
			return release, errors.New("OCI index mismatch")
		}
	}
	return release, nil
}
