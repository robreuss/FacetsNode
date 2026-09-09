package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRenderedComposeBoundary(t *testing.T) {
	images := map[string]string{}
	for _, name := range imageNames {
		images[name] = "sha256:" + strings.Repeat("a", 64)
	}
	services := map[string]any{}
	for name, kind := range map[string]string{"postgres": "postgres", "server": "device-sync", "box-postgres": "postgres", "controller": "box-controller", "onion-ingress": "caddy", "tor": "tor"} {
		network := "private"
		if name == "tor" {
			network = "tor-egress"
		}
		services[name] = map[string]any{"image": images[kind], "pull_policy": "never", "restart": "no", "networks": map[string]any{network: nil}}
	}
	document := map[string]any{"name": deviceProject, "services": services, "networks": map[string]any{"private": map[string]bool{"internal": true}, "tor-egress": map[string]bool{}}}
	check := func() error { b, _ := json.Marshal(document); return validateComposeBoundary(b, deviceProject, images) }
	if e := check(); e != nil {
		t.Fatal(e)
	}
	server := services["server"].(map[string]any)
	server["ports"] = []string{"8080:8080"}
	if check() == nil {
		t.Fatal("accepted host listener")
	}
	delete(server, "ports")
	server["networks"] = map[string]any{"tor-egress": nil}
	if check() == nil {
		t.Fatal("accepted service egress")
	}
	server["networks"] = map[string]any{"private": nil}
	server["volumes"] = []map[string]string{{"type": "bind", "source": "/run/docker.sock", "target": "/run/docker.sock"}}
	if check() == nil {
		t.Fatal("accepted Docker authority")
	}
	delete(server, "volumes")
	server["restart"] = "always"
	if check() == nil {
		t.Fatal("accepted autonomous restart")
	}
}
