package deploy

import (
	"os"
	"strings"
	"testing"
)

func TestOnionIngressUsesTheReviewedApplicationAllowlist(t *testing.T) {
	direct := readDeploymentFile(t, "Caddyfile")
	onion := readDeploymentFile(t, "onion/Caddyfile")
	directPatterns := caddyPathMatcherPatterns(t, direct, "@application")
	onionPatterns := caddyPathMatcherPatterns(t, onion, "@application")
	if strings.Join(directPatterns, "\n") != strings.Join(onionPatterns, "\n") {
		t.Fatalf("onion allowlist differs from direct ingress\ndirect=%v\nonion=%v", directPatterns, onionPatterns)
	}
	for _, forbidden := range []string{"/livez", "/readyz", "/metrics", "/debug/pprof/"} {
		if matchesAnyCaddyPathPattern(forbidden, onionPatterns) {
			t.Fatalf("private path %q is published through onion ingress", forbidden)
		}
	}
	assertContainsAll(t, "onion Caddy ingress", onion, []string{
		"bind unix//run/facets-onion/ingress.sock|0222",
		"header_up -Forwarded",
		"header_up -X-Forwarded-For",
		"header_up -X-Real-IP",
		"header_up X-Facets-Ingress-Transport tor-onion",
		"header_up X-Facets-Onion-Ingress-Token {$FACETS_ONION_INGRESS_TOKEN}",
		"respond 404",
	})
}

func TestOnionProfilesPublishNoHostPortAndIsolateNetworks(t *testing.T) {
	for _, item := range []struct {
		name string
		path string
	}{
		{name: "Device Sync", path: "onion/device-sync.compose.yaml"},
		{name: "Shared Spaces", path: "onion/shared-spaces.compose.yaml"},
	} {
		t.Run(item.name, func(t *testing.T) {
			contents := readDeploymentFile(t, item.path)
			assertContainsAll(t, item.name+" onion profile", contents, []string{
				"ports: !reset []",
				"networks: !override",
				"direct-disabled-in-onion-mode",
				"onion-application:\n    internal: true",
				"onion-socket:/run/facets-onion",
				"tor-egress:",
				"no-new-privileges=true",
				"cap_drop:\n      - ALL",
				"cap_add:\n      - NET_BIND_SERVICE\n      - DAC_READ_SEARCH",
			})
			if strings.Contains(contents, "127.0.0.1:") ||
				strings.Contains(contents, "8443:8443") ||
				strings.Contains(contents, "9443:8443") {
				t.Fatal("onion profile contains a host-published listener")
			}
		})
	}
}

func TestTorImageHasNoClientProxyOrPublishedListener(t *testing.T) {
	torrc := readDeploymentFile(t, "onion/torrc")
	assertContainsAll(t, "Tor configuration", torrc, []string{
		"SocksPort 0",
		"ControlPort 0",
		"ExitPolicy reject *:*",
		"SafeLogging 1",
		"HiddenServiceVersion 3",
		"HiddenServicePort 443 unix:/run/facets-onion/ingress.sock",
	})
	dockerfile := readDeploymentFile(t, "onion/Dockerfile")
	assertContainsAll(t, "Tor image", dockerfile, []string{
		"apt-get install --no-install-recommends -y ca-certificates tor",
		"install -d -m 0700 -o debian-tor -g debian-tor",
		"USER debian-tor",
	})
	if strings.Contains(dockerfile, "EXPOSE") {
		t.Fatal("Tor image declares an inbound container listener")
	}
}

func TestDockerBuildContextExcludesNestedEnvironmentFiles(t *testing.T) {
	contents, err := os.ReadFile("../.dockerignore")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(contents), "**/.env") {
		t.Fatal("nested service environment files are not excluded from Docker builds")
	}
}
