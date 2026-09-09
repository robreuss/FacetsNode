package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"

	"github.com/google/uuid"
)

const volumeIdentityLabel = "net.simplyformed.facets.box.volume-id"
const installationLabel = "net.simplyformed.facets.box.installation"

// Socket volumes are included: losing any managed volume is a diagnosable
// inconsistency, never permission for Compose to silently create an empty one.
func persistentVolumes() map[string]string {
	out := map[string]string{}
	for project, volumes := range map[string][]string{
		deviceProject: {"facets-device-sync-postgres", "facets-device-sync-blobs", "facets-box-controller-postgres", "facets-box-controller-state", "facets-device-sync-onion", "facets-device-sync-onion-socket"},
		sharedProject: {"facets-shared-spaces-postgres", "facets-shared-spaces-blobs", "facets-shared-spaces-onion", "facets-shared-spaces-onion-socket"},
	} {
		for _, volume := range volumes {
			out[project+"_"+volume] = project
		}
	}
	return out
}

type volumeInventory struct {
	Version        int               `json:"version"`
	InstallationID string            `json:"installationID"`
	Volumes        map[string]string `json:"volumes"`
}

type managedVolume struct {
	Name, Mountpoint, Driver, Scope string
	Labels                          map[string]string
	Options                         map[string]string
}

type volumeBackend interface {
	inspect(name string) (managedVolume, bool, error)
	create(name, project, installation, identity string) error
}

// The inventory is on the persistent disk, separate from runtime metadata. Each
// volume has a random durable label. Record it before any service can write, then
// require that exact volume on every subsequent boot/system replacement. A
// creation interrupted between Docker and our record can resume only if the
// existing volume already carries this installation's valid ownership labels.
func ensureVolumeInventory(root, installation string, backend volumeBackend) error {
	path := filepath.Join(root, "volumes.json")
	expected := persistentVolumes()
	record := volumeInventory{Version: 1, InstallationID: installation, Volumes: map[string]string{}}
	_, err := os.Lstat(path)
	if err == nil {
		b, err := boundedIdentityFile(path, 16384)
		if err != nil {
			return err
		}
		if json.Unmarshal(b, &record) != nil || record.Version != 1 || record.InstallationID != installation || record.Volumes == nil {
			return errors.New("persistent volume inventory inconsistent")
		}
	} else if os.IsNotExist(err) {
		if _, e := os.Lstat(filepath.Join(root, "configuration")); !os.IsNotExist(e) {
			return errors.New("existing service configuration lacks its volume inventory")
		}
		if err = writeJSONFile(path, record); err != nil {
			return err
		}
	} else {
		return err
	}
	for name, identity := range record.Volumes {
		if expected[name] == "" || !validVolumeIdentity(identity) {
			return errors.New("invalid retained volume entry")
		}
	}
	names := make([]string, 0, len(expected))
	for name := range expected {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		project := expected[name]
		volume, exists, err := backend.inspect(name)
		if err != nil {
			return err
		}
		retained := record.Volumes[name]
		if !exists {
			if retained != "" {
				return errors.New("retained service volume unavailable; no replacement created")
			}
			if err = backend.create(name, project, installation, uuid.NewString()); err != nil {
				return err
			}
			volume, exists, err = backend.inspect(name)
			if err != nil || !exists {
				return errors.New("new volume could not be verified")
			}
		}
		identity := volume.Labels[volumeIdentityLabel]
		if volume.Name != name || volume.Driver != "local" || volume.Scope != "local" || len(volume.Options) != 0 ||
			volume.Mountpoint != filepath.Join(root, "docker/volumes", name, "_data") ||
			volume.Labels[installationLabel] != installation || volume.Labels["com.docker.compose.project"] != project ||
			volume.Labels["com.docker.compose.volume"] != name[len(project)+1:] || !validVolumeIdentity(identity) ||
			(retained != "" && retained != identity) {
			return errors.New("service volume identity or location changed")
		}
		if retained == "" {
			record.Volumes[name] = identity
			if err = writeJSONFile(path, record); err != nil {
				return err
			}
		}
	}
	return nil
}

func validVolumeIdentity(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value
}
