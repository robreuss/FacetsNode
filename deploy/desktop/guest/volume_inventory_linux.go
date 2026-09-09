//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
)

type dockerVolumes struct{ context context.Context }

func (d dockerVolumes) inspect(name string) (managedVolume, bool, error) {
	var out managedVolume
	b, err := privateOutput(d.context, "/usr/bin/docker", "volume", "ls", "--format", "{{.Name}}")
	if err != nil {
		return out, false, err
	}
	found := false
	for _, entry := range strings.Fields(string(b)) {
		if entry == name {
			found = true
		}
	}
	if !found {
		return out, false, nil
	}
	b, err = privateOutput(d.context, "/usr/bin/docker", "volume", "inspect", name)
	var volumes []managedVolume
	if err != nil || json.Unmarshal(b, &volumes) != nil || len(volumes) != 1 {
		return out, false, errors.New("volume inspection unavailable")
	}
	return volumes[0], true, nil
}

func (d dockerVolumes) create(name, project, installation, identity string) error {
	_, err := privateOutput(d.context, "/usr/bin/docker", "volume", "create", "--driver", "local",
		"--label", installationLabel+"="+installation, "--label", volumeIdentityLabel+"="+identity,
		"--label", "com.docker.compose.project="+project,
		"--label", "com.docker.compose.volume="+name[len(project)+1:], name)
	return err
}
