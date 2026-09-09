package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestServiceHealthRequiresEveryIndependentRuntimeAndWithholdsCandidateTor(t *testing.T) {
	images := map[string]string{}
	for _, name := range imageNames {
		images[name] = "sha256:" + strings.Repeat("a", 64)
	}
	fixture := func(project string, candidate bool) []serviceContainer {
		var containers []serviceContainer
		for name, kind := range expectedContainerImages(project) {
			if candidate && name == "tor" {
				continue
			}
			var c serviceContainer
			c.ID = strings.Repeat("b", 64)
			c.Config.Image = images[kind]
			c.Config.Labels = map[string]string{"com.docker.compose.project": project, "com.docker.compose.service": name}
			c.State.Running = true
			c.State.Health = &struct{ Status string }{Status: "healthy"}
			containers = append(containers, c)
		}
		return containers
	}
	for _, candidate := range []bool{false, true} {
		d, g := fixture(deviceProject, candidate), fixture(sharedProject, candidate)
		states, err := aggregateServiceHealth(d, g, images, candidate)
		if err != nil {
			t.Fatal(err)
		}
		if candidateServicesReady(states) != candidate {
			t.Fatal("candidate acceptance did not require explicit withheld ingress")
		}
		for kind, state := range states {
			if state != "ready" && !(candidate && kind == "tor" && state == "withheld") {
				t.Fatal("healthy independent services were not recognized")
			}
		}
		d[0].State.Running = false
		states, err = aggregateServiceHealth(d, g, images, candidate)
		kind := expectedContainerImages(deviceProject)[d[0].Config.Labels["com.docker.compose.service"]]
		if err != nil || states[kind] != "unavailable" {
			t.Fatal("one deployment masked another's failure")
		}
		if candidateServicesReady(states) {
			t.Fatal("incomplete candidate was eligible for activation")
		}
	}
	d, g := fixture(deviceProject, false), fixture(sharedProject, false)
	for i := range d {
		if d[i].Config.Labels["com.docker.compose.service"] == "tor" {
			d[i].State.Health.Status = "starting"
		}
	}
	states, err := aggregateServiceHealth(d, g, images, false)
	if err != nil || states["tor"] != "starting" {
		t.Fatal("Tor bootstrap was not distinguished from failure")
	}
	for i := range g {
		if g[i].Config.Labels["com.docker.compose.service"] == "tor" {
			g[i].State.Health.Status = "unhealthy"
		}
	}
	states, err = aggregateServiceHealth(d, g, images, false)
	if err != nil || states["tor"] != "unavailable" {
		t.Fatal("starting Tor masked a failed peer")
	}
	if _, err := aggregateServiceHealth(d, g, images, true); err == nil {
		t.Fatal("running Tor accepted for candidate")
	}
	d[0].Config.Image = "mutable:latest"
	if _, err := aggregateServiceHealth(d, g, images, false); err == nil {
		t.Fatal("unverified image accepted")
	}
	d = fixture(deviceProject, false)
	d[0].Config.Labels["com.docker.compose.project"] = "another-box"
	b, _ := json.Marshal(d)
	if _, err := decodeServiceContainers(b, deviceProject); err == nil {
		t.Fatal("foreign project admitted for stopping")
	}
}
