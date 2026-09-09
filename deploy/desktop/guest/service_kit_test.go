package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestServiceKitVerifiesManifestConfigLayersIndexAndArchitecture(t *testing.T) {
	root := t.TempDir()
	expected := map[string]string{}
	release := serviceRelease{Version: 1, Architecture: "arm64", SourceRevision: strings.Repeat("a", 40), SourceTree: strings.Repeat("b", 40), Images: map[string]serviceImage{}}
	for _, name := range imageNames {
		dir := filepath.Join(root, "images", name)
		if e := os.MkdirAll(filepath.Join(dir, "blobs/sha256"), 0700); e != nil {
			t.Fatal(e)
		}
		blob := func(b []byte) string {
			sum := sha256.Sum256(b)
			digest := fmt.Sprintf("sha256:%x", sum)
			path, _ := digestPath(dir, digest)
			if e := os.WriteFile(path, b, 0600); e != nil {
				t.Fatal(e)
			}
			return digest
		}
		configBytes := []byte(`{"os":"linux","architecture":"arm64"}`)
		config := blob(configBytes)
		layer := []byte("a compressed layer fixture")
		layerDigest := blob(layer)
		manifest, _ := json.Marshal(map[string]any{"schemaVersion": 2, "config": map[string]any{"digest": config, "size": len(configBytes)}, "layers": []map[string]any{{"digest": layerDigest, "size": len(layer)}}})
		digest := blob(manifest)
		expected[name] = digest
		release.Images[name] = serviceImage{Digest: digest, Config: config}
		index, _ := json.Marshal(map[string]any{"manifests": []map[string]any{{"digest": digest, "annotations": map[string]string{"org.opencontainers.image.ref.name": "release"}}}})
		if e := os.WriteFile(filepath.Join(dir, "index.json"), index, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e := writeJSONFile(filepath.Join(root, "service-release.json"), release); e != nil {
		t.Fatal(e)
	}
	if _, e := verifyServiceKit(root, expected); e != nil {
		t.Fatal(e)
	}
	expected["tor"] = release.Images["tor"].Config
	if _, e := verifyServiceKit(root, expected); e == nil {
		t.Fatal("accepted config ID as manifest digest")
	}
	expected["tor"] = release.Images["tor"].Digest
	release.Architecture = "amd64"
	_ = writeJSONFile(filepath.Join(root, "service-release.json"), release)
	if _, e := verifyServiceKit(root, expected); e == nil {
		t.Fatal("accepted wrong architecture")
	}
	release.Architecture = "arm64"
	_ = writeJSONFile(filepath.Join(root, "service-release.json"), release)
	path, _ := digestPath(filepath.Join(root, "images/tor"), release.Images["tor"].Digest)
	_ = os.WriteFile(path, []byte("changed"), 0600)
	if _, e := verifyServiceKit(root, expected); e == nil {
		t.Fatal("accepted mutated manifest")
	}
}
