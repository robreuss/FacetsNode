package main

import (
	"os"
	"strings"
	"testing"
)

func TestStorageGatesDaemonsWithoutOrderingEarlySocketAfterBasicTarget(t *testing.T) {
	b, err := os.ReadFile("../guest-bootstrap.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(b)
	for _, line := range strings.Split(script, "\n") {
		if (strings.HasPrefix(line, "Before=") || strings.HasPrefix(line, "for unit in ")) && strings.Contains(line, "docker.socket") {
			t.Fatal("early Docker activation socket must not depend on ordinary storage service startup")
		}
	}
	for _, required := range []string{
		"Before=fbd-guest.service docker.service containerd.service",
		"for unit in docker.service containerd.service; do",
		"Requires=fbd-data.service", "BindsTo=fbd-data.service", "After=fbd-data.service",
		"ExecStartPre=/opt/fbd/guest-agent check-storage",
		"ExecStop=/usr/bin/umount /srv/facets-box-data",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("missing durable storage gate: %s", required)
		}
	}
	runtime, err := os.ReadFile("../guest-runtime.sh")
	if err != nil {
		t.Fatal(err)
	}
	verify := strings.Index(string(runtime), "systemd-analyze --man=no verify fbd-data.service fbd-guest.service docker.service docker.socket containerd.service")
	start := strings.Index(string(runtime), "systemctl enable --now containerd.service docker.service")
	if verify < 0 || start <= verify {
		t.Fatal("runtime preparation must verify the installed unit graph before starting daemons")
	}
}
