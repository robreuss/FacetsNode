package main

import (
	"encoding/json"
	"errors"

	"strings"
)

type serviceContainer struct {
	ID     string `json:"Id"`
	Config struct {
		Image  string
		Labels map[string]string
	}
	State struct {
		Running bool
		Health  *struct{ Status string }
	}
}

func expectedContainerImages(project string) map[string]string {
	if project == deviceProject {
		return map[string]string{"postgres": "postgres", "box-postgres": "postgres", "server": "device-sync", "controller": "box-controller", "onion-ingress": "caddy", "tor": "tor"}
	}
	if project == sharedProject {
		return map[string]string{"postgres": "postgres", "server": "shared-spaces", "onion-ingress": "caddy", "tor": "tor"}
	}
	return nil
}

func decodeServiceContainers(raw []byte, project string) ([]serviceContainer, error) {
	var containers []serviceContainer
	if len(raw) > 1024*1024 || json.Unmarshal(raw, &containers) != nil || expectedContainerImages(project) == nil {
		return nil, errors.New("invalid appliance container inventory")
	}
	seen := map[string]bool{}
	for _, c := range containers {
		name := c.Config.Labels["com.docker.compose.service"]
		if !validHex(c.ID, 32) || c.Config.Labels["com.docker.compose.project"] != project || expectedContainerImages(project)[name] == "" || seen[name] {
			return nil, errors.New("unexpected appliance container ownership")
		}
		seen[name] = true
	}
	return containers, nil
}

func aggregateServiceHealth(device, group []serviceContainer, images map[string]string, candidate bool) (map[string]string, error) {
	states := map[string]string{}
	for _, name := range imageNames {
		states[name] = "ready"
	}
	if candidate {
		states["tor"] = "withheld"
	}
	for index, project := range []string{deviceProject, sharedProject} {
		containers := device
		if index == 1 {
			containers = group
		}
		seen := map[string]bool{}
		for _, c := range containers {
			name := c.Config.Labels["com.docker.compose.service"]
			kind := expectedContainerImages(project)[name]
			seen[name] = true
			if candidate && name == "tor" {
				if c.State.Running {
					return nil, errors.New("candidate ingress was not withheld")
				}
				continue
			}
			if kind == "" || c.Config.Image != images[kind] || !strings.HasPrefix(c.Config.Image, "sha256:") {
				return nil, errors.New("running service image differs from release")
			}
			if !c.State.Running || (name != "onion-ingress" && (c.State.Health == nil || c.State.Health.Status != "healthy")) {
				states[kind] = "unavailable"
			}
		}
		for name, kind := range expectedContainerImages(project) {
			if !seen[name] && !(candidate && name == "tor") {
				states[kind] = "unavailable"
			}
		}
	}
	return states, nil
}
