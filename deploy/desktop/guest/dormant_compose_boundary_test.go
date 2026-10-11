package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func dormantFixtureImages() map[string]string {
	images := map[string]string{}
	for _, name := range imageNames {
		images[name] = "sha256:" + strings.Repeat("a", 64)
	}
	return images
}

func TestDormantJobCustodyComposeBoundary(t *testing.T) {
	images := dormantFixtureImages()
	project, root, kit := "validation-job", "/validation", "/kit"
	volumeName := project + "_facets-job-custody-postgres"
	document := map[string]any{
		"name": project,
		"networks": map[string]any{
			"job-custody-database":    map[string]any{"name": project + "_job-custody-database", "internal": true},
			"service-control":         map[string]any{"name": "facets-box-service-control", "external": true},
			"storage-capacity-client": map[string]any{"name": "facets-box-storage-capacity-client", "external": true},
		},
		"volumes": map[string]any{"facets-job-custody-postgres": map[string]any{"name": volumeName}},
		"services": map[string]any{
			"job-custody-postgres": map[string]any{
				"image": images["postgres"], "pull_policy": "never", "restart": "no",
				"networks": map[string]any{"job-custody-database": nil},
				"volumes":  []map[string]any{{"type": "volume", "source": volumeName, "target": "/var/lib/postgresql/data"}},
			},
			"job-custody": map[string]any{
				"image": images["job-custody"], "pull_policy": "never", "restart": "no", "read_only": true,
				"cap_drop": []string{"ALL"}, "security_opt": []string{"no-new-privileges=true"},
				"networks": map[string]any{"job-custody-database": nil, "service-control": nil, "storage-capacity-client": nil},
				"volumes":  []map[string]any{{"type": "bind", "source": root + "/job-custody/content", "target": "/var/lib/facets-job-custody/custody"}},
			},
		},
	}
	check := func() error {
		raw, _ := json.Marshal(document)
		return validateDormantComposeBoundary(raw, jobCustodyProject, project, images, root, kit)
	}
	if err := check(); err != nil {
		t.Fatal(err)
	}
	document["networks"].(map[string]any)["service-control"].(map[string]any)["name"] = "foreign-control"
	if check() == nil {
		t.Fatal("accepted foreign service-control network")
	}
	document["networks"].(map[string]any)["service-control"].(map[string]any)["name"] = "facets-box-service-control"
	document["services"].(map[string]any)["job-custody"].(map[string]any)["volumes"] = []map[string]any{{"type": "bind", "source": "/run/docker.sock", "target": "/run/docker.sock"}}
	if check() == nil {
		t.Fatal("accepted runtime authority mount")
	}
}

func TestDormantStorageCapacityComposeBoundary(t *testing.T) {
	images := dormantFixtureImages()
	project, root, kit := "validation-capacity", "/validation", "/kit"
	volumeName := project + "_facets-storage-capacity-postgres"
	hardened := func(image string, networks map[string]any) map[string]any {
		return map[string]any{
			"image": image, "pull_policy": "never", "restart": "no", "read_only": true,
			"cap_drop": []string{"ALL"}, "security_opt": []string{"no-new-privileges=true"}, "networks": networks,
		}
	}
	authority := hardened(images["storage-capacity-authority"], map[string]any{"backend": nil, "database": nil})
	authority["volumes"] = []map[string]any{{"type": "bind", "source": root + "/capacity-pool", "target": "/srv/facets-capacity-pool"}}
	initialize := hardened(images["storage-capacity-authority"], map[string]any{"database": nil})
	initialize["profiles"] = []string{"initialize"}
	initialize["volumes"] = []map[string]any{{"type": "bind", "source": root + "/configuration/storage-capacity/peers.json", "target": "/etc/facets-storage-capacity-authority/peers.json", "read_only": true}}
	caddy := hardened(images["caddy"], map[string]any{"backend": nil, "client": nil})
	caddy["volumes"] = []map[string]any{{"type": "bind", "source": kit + "/recipes/Capacity.Caddyfile", "target": "/etc/caddy/Caddyfile", "read_only": true}}
	document := map[string]any{
		"name": project,
		"networks": map[string]any{
			"database": map[string]any{"name": project + "_database", "internal": true},
			"backend":  map[string]any{"name": project + "_backend", "internal": true},
			"client":   map[string]any{"name": "facets-box-storage-capacity-client", "internal": true},
		},
		"volumes": map[string]any{"facets-storage-capacity-postgres": map[string]any{"name": volumeName}},
		"services": map[string]any{
			"postgres": map[string]any{
				"image": images["postgres"], "pull_policy": "never", "restart": "no",
				"networks": map[string]any{"database": nil},
				"volumes":  []map[string]any{{"type": "volume", "source": volumeName, "target": "/var/lib/postgresql/data"}},
			},
			"storage-capacity-authority": authority,
			"initialize":                 initialize,
			"storage-capacity":           caddy,
		},
	}
	check := func() error {
		raw, _ := json.Marshal(document)
		return validateDormantComposeBoundary(raw, storageCapacityProject, project, images, root, kit)
	}
	if err := check(); err != nil {
		t.Fatal(err)
	}
	initialize["profiles"] = []string{"ordinary-startup"}
	if check() == nil {
		t.Fatal("accepted initialization outside its explicit profile")
	}
	initialize["profiles"] = []string{"initialize"}
	caddy["restart"] = "unless-stopped"
	if check() == nil {
		t.Fatal("accepted autonomously restarting dormant service")
	}
}
