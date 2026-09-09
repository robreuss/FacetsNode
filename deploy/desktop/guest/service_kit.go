package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

var imageNames = []string{"device-sync", "box-controller", "shared-spaces", "postgres", "caddy", "tor"}

type serviceImage struct {
	Digest    string `json:"digest"`
	Config    string `json:"config"`
	Reference string `json:"reference"`
}
type serviceRelease struct {
	Version        int                     `json:"version"`
	Architecture   string                  `json:"architecture"`
	SourceRevision string                  `json:"sourceRevision"`
	SourceTree     string                  `json:"sourceTree"`
	Images         map[string]serviceImage `json:"images"`
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
func verifyServiceKit(root string, expected map[string]string) (serviceRelease, error) {
	var release serviceRelease
	b, e := os.ReadFile(filepath.Join(root, "service-release.json"))
	if e != nil || len(b) > 65536 || json.Unmarshal(b, &release) != nil {
		return release, errors.New("invalid service release")
	}
	if release.Version != 1 || release.Architecture != "arm64" || !validHex(release.SourceRevision, 20) || !validHex(release.SourceTree, 20) || len(release.Images) != len(imageNames) || len(expected) != len(imageNames) {
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
		var platform struct {
			OS           string `json:"os"`
			Architecture string `json:"architecture"`
		}
		if json.Unmarshal(config, &platform) != nil || platform.OS != "linux" || platform.Architecture != "arm64" {
			return release, errors.New("wrong OCI platform")
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
