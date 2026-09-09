package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
)

type fixtureVolumes struct {
	root         string
	volumes      map[string]managedVolume
	created      int
	failCreation bool
}

func (f *fixtureVolumes) inspect(name string) (managedVolume, bool, error) {
	v, ok := f.volumes[name]
	return v, ok, nil
}
func (f *fixtureVolumes) create(name, project, installation, identity string) error {
	f.created++
	f.volumes[name] = managedVolume{Name: name, Mountpoint: filepath.Join(f.root, "docker/volumes", name, "_data"), Driver: "local", Scope: "local", Labels: map[string]string{installationLabel: installation, volumeIdentityLabel: identity, "com.docker.compose.project": project, "com.docker.compose.volume": name[len(project)+1:]}}
	if f.failCreation {
		return errors.New("interrupted after runtime creation")
	}
	return nil
}

func TestVolumeInventoryPreservesIdentityAndRejectsMissingOrReplacedStorage(t *testing.T) {
	for _, mutation := range []string{"none", "missing", "replacement", "foreign", "location", "remote"} {
		t.Run(mutation, func(t *testing.T) {
			root, installation := t.TempDir(), uuid.NewString()
			backend := &fixtureVolumes{root: root, volumes: map[string]managedVolume{}}
			if err := ensureVolumeInventory(root, installation, backend); err != nil {
				t.Fatal(err)
			}
			if backend.created != 10 {
				t.Fatal("incomplete persistent inventory")
			}
			name := deviceProject + "_facets-device-sync-postgres"
			v := backend.volumes[name]
			switch mutation {
			case "missing":
				delete(backend.volumes, name)
			case "replacement":
				v.Labels[volumeIdentityLabel] = uuid.NewString()
			case "foreign":
				v.Labels[installationLabel] = uuid.NewString()
			case "location":
				v.Mountpoint = "/an/empty/system/disk"
			case "remote":
				v.Options = map[string]string{"type": "nfs"}
			}
			if mutation != "missing" {
				backend.volumes[name] = v
			}
			err := ensureVolumeInventory(root, installation, backend)
			if (err == nil) != (mutation == "none") || backend.created != 10 {
				t.Fatal("missing/replaced volume accepted or silently recreated")
			}
		})
	}
}

func TestVolumeCreationResumesOnlyOwnedUnrecordedVolume(t *testing.T) {
	root, installation := t.TempDir(), uuid.NewString()
	backend := &fixtureVolumes{root: root, volumes: map[string]managedVolume{}, failCreation: true}
	if ensureVolumeInventory(root, installation, backend) == nil {
		t.Fatal("interruption hidden")
	}
	backend.failCreation = false
	if err := ensureVolumeInventory(root, installation, backend); err != nil {
		t.Fatal(err)
	}
	if backend.created != 10 {
		t.Fatal("replaced a volume after interrupted creation")
	}
	b, err := os.ReadFile(filepath.Join(root, "volumes.json"))
	var record volumeInventory
	if err != nil || json.Unmarshal(b, &record) != nil || len(record.Volumes) != 10 {
		t.Fatal("inventory incomplete")
	}
	if ensureVolumeInventory(root, uuid.NewString(), backend) == nil {
		t.Fatal("foreign inventory accepted")
	}
	other := t.TempDir()
	if err := os.Mkdir(filepath.Join(other, "configuration"), 0700); err != nil {
		t.Fatal(err)
	}
	if ensureVolumeInventory(other, installation, backend) == nil {
		t.Fatal("existing configuration admitted without inventory")
	}
}
