package main

import (
	"errors"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// These names are appliance infrastructure constants, not host-selected Compose
// projects or paths. Each existing deployment retains its own named volumes.
const deviceProject = "fbd-device-sync"
const sharedProject = "fbd-shared-spaces"

func serviceEnvironment(root, kit string, identity applianceIdentity, images map[string]string, candidate bool) (map[string]string, map[string]string, error) {
	common := map[string]string{"FBD_RECIPE_DIRECTORY": filepath.Join(kit, "recipes"), "FBD_CANDIDATE_MAINTENANCE": strconv.FormatBool(candidate)}
	for _, name := range imageNames {
		image := images[name]
		if !strings.HasPrefix(image, "sha256:") || !validHex(strings.TrimPrefix(image, "sha256:"), 32) {
			return nil, nil, errors.New("unverified runtime image")
		}
		common["FBD_"+strings.ToUpper(strings.ReplaceAll(name, "-", "_"))+"_IMAGE"] = image
	}
	device, shared := map[string]string{}, map[string]string{}
	for k, v := range common {
		device[k], shared[k] = v, v
	}
	configuration := filepath.Join(root, "configuration")
	device["FBD_ADMIN_SOCKET_DIRECTORY"] = filepath.Join(root, "management")
	device["FACETS_DEVICE_SYNC_POSTGRES_PASSWORD"] = identity.Secrets["device-sync-db"]
	device["FACETS_BOX_CONTROLLER_POSTGRES_PASSWORD"] = identity.Secrets["controller-db"]
	device["FACETS_DEVICE_SYNC_OPERATOR_TOKEN"] = identity.Secrets["device-sync-operator"]
	device["FACETS_DEVICE_SYNC_BOX_CONTROLLER_TOKEN"] = identity.Secrets["box-controller"]
	device["FACETS_DEVICE_SYNC_ONION_INGRESS_TOKEN"] = identity.Secrets["device-sync-onion"]
	device["FACETS_DEVICE_SYNC_PUBLIC_URL"] = identity.DeviceSync.Endpoint
	device["FACETS_BOX_DEVICE_SYNC_URL"] = identity.DeviceSync.Endpoint
	device["FACETS_BOX_PUBLIC_URL"] = "https://" + identity.DeviceSync.Onion + "/facetsbox"
	device["FACETS_BOX_DISPLAY_NAME"] = "Desktop Facets Box"
	shared["FACETS_SHARED_SPACES_POSTGRES_PASSWORD"] = identity.Secrets["shared-spaces-db"]
	shared["FACETS_SHARED_SPACES_OPERATOR_TOKEN"] = identity.Secrets["shared-spaces-operator"]
	shared["FACETS_SHARED_SPACES_ONION_INGRESS_TOKEN"] = identity.Secrets["shared-spaces-onion"]
	shared["FACETS_SHARED_SPACES_MANAGED_KEY_ENCRYPTION_KEY"] = identity.Secrets["shared-spaces-key"]
	shared["FACETS_SHARED_SPACES_COMPUTE_CAPABILITY_SIGNING_SEED"] = identity.Secrets["shared-spaces-compute-seed"]
	shared["FACETS_SHARED_SPACES_PUBLIC_URL"] = identity.SharedSpaces.Endpoint
	for _, entry := range []struct {
		env               map[string]string
		prefix, directory string
		id                serviceIdentity
	}{
		{device, "FACETS_DEVICE_SYNC_", "device-sync", identity.DeviceSync},
		{shared, "FACETS_SHARED_SPACES_", "shared-spaces", identity.SharedSpaces},
	} {
		entry.env[entry.prefix+"DEPLOYMENT_ID"] = entry.id.DeploymentID
		for key, child := range map[string]string{"AUTHORITY_KEY_DIRECTORY": "keys", "AUTHORITY_POLICY_DIRECTORY": "policy", "AUTHORITY_STATE_DIRECTORY": "state", "TLS_DIRECTORY": "tls"} {
			entry.env[entry.prefix+key] = filepath.Join(configuration, entry.directory, child)
		}
	}
	return device, shared, nil
}

func encodeEnvironment(values map[string]string) ([]byte, error) {
	keys := make([]string, 0, len(values))
	for key, value := range values {
		// Compose's .env parser interprets shell-like syntax. Generated credentials
		// and appliance paths need none of it; reject rather than escape guesses.
		if key == "" || strings.Trim(key, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") != "" || value == "" || strings.ContainsAny(value, "\r\n\x00$'\"\\") {
			return nil, errors.New("unsafe deployment environment")
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var out strings.Builder
	for _, key := range keys {
		out.WriteString(key + "=" + values[key] + "\n")
	}
	return []byte(out.String()), nil
}
