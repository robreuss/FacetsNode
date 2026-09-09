package main

import (
	"encoding/json"
	"errors"
	"strings"
)

// Portable layouts use the neutral reference "release". Importing all of them
// with that name replaces the previous image root. Assign distinct local roots
// without altering any signed manifest/configuration/layer blob or launch digest.
func runtimeImportIndex(raw []byte, name, digest string) ([]byte, error) {
	known := false
	for _, expected := range imageNames {
		if name == expected {
			known = true
		}
	}
	if !known || !strings.HasPrefix(digest, "sha256:") || !validHex(strings.TrimPrefix(digest, "sha256:"), 32) || len(raw) > 64*1024 {
		return nil, errors.New("invalid image import identity")
	}
	var index struct {
		SchemaVersion int                          `json:"schemaVersion"`
		Manifests     []map[string]json.RawMessage `json:"manifests"`
	}
	if json.Unmarshal(raw, &index) != nil || index.SchemaVersion != 2 || len(index.Manifests) != 1 {
		return nil, errors.New("invalid image import index")
	}
	var selected string
	if json.Unmarshal(index.Manifests[0]["digest"], &selected) != nil || selected != digest {
		return nil, errors.New("image import digest mismatch")
	}
	annotations, _ := json.Marshal(map[string]string{"org.opencontainers.image.ref.name": "fbd-release/" + name + ":" + strings.TrimPrefix(digest, "sha256:")})
	index.Manifests[0]["annotations"] = annotations
	return json.Marshal(index)
}
