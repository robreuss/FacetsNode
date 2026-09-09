//go:build linux

package main

import (
	"context"
	"errors"
	"strings"
)

func inspectServiceContainers(ctx context.Context, project string) ([]serviceContainer, error) {
	if expectedContainerImages(project) == nil {
		return nil, errors.New("unknown appliance project")
	}
	b, err := privateOutput(ctx, "/usr/bin/docker", "container", "ls", "--all", "--filter", "label=com.docker.compose.project="+project, "--format", "{{.ID}}", "--no-trunc")
	if err != nil {
		return nil, err
	}
	ids := strings.Fields(string(b))
	if len(ids) == 0 {
		return nil, nil
	}
	if len(ids) > len(expectedContainerImages(project)) {
		return nil, errors.New("unexpected appliance container count")
	}
	for _, id := range ids {
		if !validHex(id, 32) {
			return nil, errors.New("invalid container identifier")
		}
	}
	b, err = privateOutput(ctx, "/usr/bin/docker", append([]string{"container", "inspect"}, ids...)...)
	if err != nil {
		return nil, err
	}
	return decodeServiceContainers(b, project)
}

// Tor first, application/management second, databases last. Only exact IDs
// resolved from the two owned projects can be stopped; no global Docker stop.
func stopServiceContainers(ctx context.Context) error {
	var all []serviceContainer
	for _, project := range []string{deviceProject, sharedProject} {
		containers, err := inspectServiceContainers(ctx, project)
		if err != nil {
			return err
		}
		all = append(all, containers...)
	}
	for _, phase := range []int{0, 1, 2} {
		var ids []string
		for _, c := range all {
			name := c.Config.Labels["com.docker.compose.service"]
			order := 1
			if name == "tor" {
				order = 0
			}
			if name == "postgres" || name == "box-postgres" {
				order = 2
			}
			if order == phase && c.State.Running {
				ids = append(ids, c.ID)
			}
		}
		if len(ids) != 0 {
			if _, err := privateOutput(ctx, "/usr/bin/docker", append([]string{"stop", "--time", "20"}, ids...)...); err != nil {
				return err
			}
		}
	}
	return nil
}

func currentServiceHealth(ctx context.Context, images map[string]string, candidate bool) (map[string]string, error) {
	d, err := inspectServiceContainers(ctx, deviceProject)
	if err != nil {
		return nil, err
	}
	g, err := inspectServiceContainers(ctx, sharedProject)
	if err != nil {
		return nil, err
	}
	return aggregateServiceHealth(d, g, images, candidate)
}
