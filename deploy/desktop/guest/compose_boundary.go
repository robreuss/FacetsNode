package main

import (
	"encoding/json"
	"errors"
	"strings"
)

// Inspect the fully rendered (but never logged) Compose document, not just the
// overlay text. Secret-bearing environment values stay in private memory/files.
func validateComposeBoundary(raw []byte, project string, images map[string]string) error {
	if len(raw) > 1024*1024 {
		return errors.New("rendered deployment too large")
	}
	type volume struct {
		Type, Source, Target string
		ReadOnly             bool `json:"read_only"`
	}
	var rendered struct {
		Name     string
		Services map[string]struct {
			Image       string
			Build       json.RawMessage
			Ports       []json.RawMessage
			Profiles    []string
			Privileged  bool
			NetworkMode string `json:"network_mode"`
			PID         string `json:"pid"`
			Devices     []json.RawMessage
			Volumes     []volume
			Networks    map[string]json.RawMessage
			Restart     string
			PullPolicy  string `json:"pull_policy"`
		}
		Networks map[string]struct{ Internal bool }
	}
	if json.Unmarshal(raw, &rendered) != nil || rendered.Name != project {
		return errors.New("unexpected Compose project")
	}
	expected := map[string]string{"postgres": "postgres", "server": "shared-spaces", "onion-ingress": "caddy", "tor": "tor"}
	if project == deviceProject {
		expected["server"], expected["controller"], expected["box-postgres"] = "device-sync", "box-controller", "postgres"
	} else if project != sharedProject {
		return errors.New("unknown deployment")
	}
	active := 0
	for name, service := range rendered.Services {
		if len(service.Profiles) != 0 {
			if name != "discovery" && name != "ingress" {
				return errors.New("unexpected optional workload")
			}
			continue
		}
		active++
		kind, ok := expected[name]
		if !ok || service.Image != images[kind] || service.PullPolicy != "never" || service.Restart != "no" || len(service.Ports) != 0 || (len(service.Build) != 0 && string(service.Build) != "null") || service.Privileged || service.NetworkMode != "" || service.PID != "" || len(service.Devices) != 0 {
			return errors.New("unsafe rendered service")
		}
		if len(service.Networks) == 0 {
			return errors.New("implicit workload network")
		}
		for network := range service.Networks {
			configuration, found := rendered.Networks[network]
			if !found || (!configuration.Internal && (name != "tor" || network != "tor-egress")) {
				return errors.New("workload has external network access")
			}
		}
		for _, mount := range service.Volumes {
			if mount.Type != "volume" && mount.Type != "bind" {
				return errors.New("unexpected workload mount")
			}
			if strings.Contains(mount.Source, "docker.sock") || strings.Contains(mount.Target, "docker.sock") || mount.Target == "/" || mount.Source == "/" {
				return errors.New("runtime authority exposed to workload")
			}
			if mount.Type == "bind" && !strings.HasPrefix(mount.Source, "/srv/facets-box-data/configuration/") && !strings.HasPrefix(mount.Source, "/opt/fbd/service-kit/recipes/") && mount.Source != "/srv/facets-box-data/management" {
				return errors.New("unapproved host bind mount")
			}
		}
	}
	if active != len(expected) {
		return errors.New("missing existing workload")
	}
	return nil
}
