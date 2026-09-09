package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRuntimeImportReferencesDoNotCollideOrChangeManifest(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	raw := []byte(`{"schemaVersion":2,"manifests":[{"digest":"` + digest + `","size":123,"mediaType":"application/vnd.oci.image.manifest.v1+json","annotations":{"org.opencontainers.image.ref.name":"release"}}]}`)
	names := map[string]bool{}
	for _, image := range imageNames {
		b, err := runtimeImportIndex(raw, image, digest)
		if err != nil {
			t.Fatal(err)
		}
		var value struct {
			Manifests []struct {
				Digest      string
				Size        int
				Annotations map[string]string
			}
		}
		if json.Unmarshal(b, &value) != nil || value.Manifests[0].Digest != digest || value.Manifests[0].Size != 123 {
			t.Fatal("changed manifest descriptor")
		}
		name := value.Manifests[0].Annotations["org.opencontainers.image.ref.name"]
		if names[name] {
			t.Fatal("colliding import reference")
		}
		names[name] = true
	}
	if _, err := runtimeImportIndex(raw, "postgres", "sha256:"+strings.Repeat("b", 64)); err == nil {
		t.Fatal("accepted wrong digest")
	}
	if _, err := runtimeImportIndex(raw, "unreviewed", digest); err == nil {
		t.Fatal("accepted unknown image")
	}
}
