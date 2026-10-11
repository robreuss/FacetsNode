package main

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"strings"
)

// validateDormantComposeBoundary audits packaged-but-inactive Compute Queue
// services. Rendering proves the portable recipe boundary; it is deliberately
// not runtime or activation evidence.
func validateDormantComposeBoundary(raw []byte, kind, project string, images map[string]string, root, kit string) error {
	if len(raw) > 1024*1024 {
		return errors.New("rendered dormant deployment too large")
	}
	type volume struct {
		Type, Source, Target string
		ReadOnly             bool `json:"read_only"`
	}
	type service struct {
		Image       string
		Build       json.RawMessage
		Ports       []json.RawMessage
		Profiles    []string
		Privileged  bool
		ReadOnly    bool   `json:"read_only"`
		NetworkMode string `json:"network_mode"`
		PID         string `json:"pid"`
		Devices     []json.RawMessage
		CapDrop     []string `json:"cap_drop"`
		SecurityOpt []string `json:"security_opt"`
		Volumes     []volume
		Networks    map[string]json.RawMessage
		Restart     string
		PullPolicy  string `json:"pull_policy"`
	}
	var rendered struct {
		Name     string
		Services map[string]service
		Networks map[string]struct {
			Internal bool
			Name     string
			External bool
		}
		Volumes map[string]struct {
			Name     string
			External bool
		}
	}
	if json.Unmarshal(raw, &rendered) != nil || rendered.Name != project {
		return errors.New("unexpected dormant Compose project")
	}

	type expectedService struct {
		Image, Profile string
		Networks       []string
		Hardened       bool
	}
	expectedServices := map[string]expectedService{}
	expectedNetworks := map[string]struct {
		Name               string
		Internal, External bool
	}{}
	allowedBinds := map[string]bool{}
	switch kind {
	case jobCustodyProject:
		expectedServices = map[string]expectedService{
			"job-custody-postgres": {Image: images["postgres"], Networks: []string{"job-custody-database"}},
			"job-custody":          {Image: images["job-custody"], Networks: []string{"job-custody-database", "service-control", "storage-capacity-client"}, Hardened: true},
		}
		expectedNetworks = map[string]struct {
			Name               string
			Internal, External bool
		}{
			"job-custody-database":    {Name: project + "_job-custody-database", Internal: true},
			"service-control":         {Name: "facets-box-service-control", External: true},
			"storage-capacity-client": {Name: "facets-box-storage-capacity-client", External: true},
		}
		for _, path := range []string{
			filepath.Join(root, "job-custody/content"),
			filepath.Join(root, "configuration/job-custody/keys"),
			filepath.Join(root, "configuration/job-custody/policy"),
			filepath.Join(root, "configuration/job-custody/state"),
			filepath.Join(root, "configuration/job-custody/admission"),
			filepath.Join(root, "configuration/storage-capacity/tls/server.crt"),
		} {
			allowedBinds[path] = true
		}
	case storageCapacityProject:
		expectedServices = map[string]expectedService{
			"postgres":                   {Image: images["postgres"], Networks: []string{"database"}},
			"storage-capacity-authority": {Image: images["storage-capacity-authority"], Networks: []string{"backend", "database"}, Hardened: true},
			"initialize":                 {Image: images["storage-capacity-authority"], Profile: "initialize", Networks: []string{"database"}, Hardened: true},
			"storage-capacity":           {Image: images["caddy"], Networks: []string{"backend", "client"}, Hardened: true},
		}
		expectedNetworks = map[string]struct {
			Name               string
			Internal, External bool
		}{
			"database": {Name: project + "_database", Internal: true},
			"backend":  {Name: project + "_backend", Internal: true},
			"client":   {Name: "facets-box-storage-capacity-client", Internal: true},
		}
		for _, path := range []string{
			filepath.Join(root, "capacity-pool"),
			filepath.Join(root, "configuration/storage-capacity/peers.json"),
			filepath.Join(root, "configuration/storage-capacity/tls"),
			filepath.Join(kit, "recipes/Capacity.Caddyfile"),
		} {
			allowedBinds[path] = true
		}
	default:
		return errors.New("unknown dormant deployment")
	}

	if len(rendered.Networks) != len(expectedNetworks) {
		return errors.New("unexpected dormant deployment network count")
	}
	for name, expected := range expectedNetworks {
		network, ok := rendered.Networks[name]
		if !ok || network.Name != expected.Name || network.Internal != expected.Internal || network.External != expected.External {
			return errors.New("dormant deployment network boundary mismatch")
		}
	}
	ownedVolumes := map[string]bool{}
	for key, volume := range rendered.Volumes {
		if volume.External || !strings.HasPrefix(volume.Name, project+"_") {
			return errors.New("dormant deployment volume escapes project ownership")
		}
		// Compose versions have emitted either the logical top-level key or the
		// project-qualified name as a normalized service-mount source. Both are
		// bound here to the same already-verified owned volume.
		ownedVolumes[key] = true
		ownedVolumes[volume.Name] = true
	}
	if len(rendered.Services) != len(expectedServices) {
		return errors.New("unexpected dormant workload count")
	}
	for name, expected := range expectedServices {
		actual, ok := rendered.Services[name]
		if !ok || actual.Image != expected.Image || actual.PullPolicy != "never" || actual.Restart != "no" || len(actual.Ports) != 0 || (len(actual.Build) != 0 && string(actual.Build) != "null") || actual.Privileged || actual.NetworkMode != "" || actual.PID != "" || len(actual.Devices) != 0 {
			return errors.New("unsafe dormant workload")
		}
		if expected.Profile == "" {
			if len(actual.Profiles) != 0 {
				return errors.New("unexpected dormant workload profile")
			}
		} else if len(actual.Profiles) != 1 || actual.Profiles[0] != expected.Profile {
			return errors.New("dormant initialization profile mismatch")
		}
		actualNetworks := make([]string, 0, len(actual.Networks))
		for network := range actual.Networks {
			actualNetworks = append(actualNetworks, network)
		}
		slices.Sort(actualNetworks)
		expectedNetworkNames := slices.Clone(expected.Networks)
		slices.Sort(expectedNetworkNames)
		if !slices.Equal(actualNetworks, expectedNetworkNames) {
			return errors.New("dormant workload network membership mismatch")
		}
		if expected.Hardened && (!actual.ReadOnly || !slices.Contains(actual.CapDrop, "ALL") || !slices.Contains(actual.SecurityOpt, "no-new-privileges=true")) {
			return errors.New("dormant workload hardening unavailable")
		}
		for _, mount := range actual.Volumes {
			if mount.Type == "volume" {
				if !ownedVolumes[mount.Source] {
					return errors.New("dormant workload uses unowned volume")
				}
			} else if mount.Type == "bind" {
				if !allowedBinds[mount.Source] {
					return errors.New("dormant workload uses unapproved host bind mount")
				}
			} else {
				return errors.New("dormant workload uses unexpected mount")
			}
			if strings.Contains(mount.Source, "docker.sock") || strings.Contains(mount.Target, "docker.sock") || mount.Source == "/" || mount.Target == "/" {
				return errors.New("runtime authority exposed to dormant workload")
			}
		}
	}
	return nil
}
