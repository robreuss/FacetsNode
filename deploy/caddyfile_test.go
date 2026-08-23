package deploy

import (
	"os"
	"strings"
	"testing"
)

func TestPublicIngressRoutesOnlyApplicationProtocolFamilies(t *testing.T) {
	contents, err := os.ReadFile("Caddyfile")
	if err != nil {
		t.Fatal(err)
	}
	patterns := caddyPathMatcherPatterns(t, string(contents), "@application")

	for _, requestPath := range []string{
		"/v1/service-deployment/proof",
		"/v1/pairing/routes",
		"/v1/pairing/routes/11111111-1111-4111-8111-111111111111/messages",
		"/v1/relay/tenants/11111111-1111-4111-8111-111111111111/domains/22222222-2222-4222-8222-222222222222/messages",
		"/v1/device-sync/account-admissions/11111111-1111-4111-8111-111111111111/claim",
		"/v1/device-sync/join-requests",
		"/v1/device-sync/join-requests/11111111-1111-4111-8111-111111111111/bootstrap",
		"/v1/device-sync/principals/11111111-1111-4111-8111-111111111111/status",
		"/v1/shared-spaces/11111111-1111-4111-8111-111111111111/domains/22222222-2222-4222-8222-222222222222/status",
		"/v1/shared-spaces/11111111-1111-4111-8111-111111111111/domains/22222222-2222-4222-8222-222222222222/invitations/33333333-3333-4333-8333-333333333333/claim",
	} {
		if !matchesAnyCaddyPathPattern(requestPath, patterns) {
			t.Errorf("public application path %q is not routed", requestPath)
		}
	}
	for _, requestPath := range []string{
		"/v1/relay/tenants",
		"/v1/device-sync/account-admissions",
		"/v1/shared-spaces",
		"/livez",
		"/readyz",
		"/metrics",
		"/debug/pprof/",
	} {
		if matchesAnyCaddyPathPattern(requestPath, patterns) {
			t.Errorf("private management path %q is publicly routed", requestPath)
		}
	}

	if !strings.Contains(string(contents), "reverse_proxy @application server:8080") {
		t.Fatal("public reverse proxy is not bound to the application matcher")
	}
	if !strings.Contains(string(contents), "\troute {\n") {
		t.Fatal("public allowlist and fallback must retain declaration order")
	}
}

func TestDockerBuildContextExcludesDeploymentSecrets(t *testing.T) {
	contents, err := os.ReadFile("../.dockerignore")
	if err != nil {
		t.Fatal(err)
	}
	exclusions := make(map[string]bool)
	for _, line := range strings.Split(string(contents), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			exclusions[line] = true
		}
	}
	for _, secretPath := range []string{
		".env",
		".swift-relay-test-access.json",
		"deploy/tls",
	} {
		if !exclusions[secretPath] {
			t.Errorf("Docker build context does not exclude %q", secretPath)
		}
	}
}

func caddyPathMatcherPatterns(t *testing.T, contents, matcher string) []string {
	t.Helper()
	for _, line := range strings.Split(contents, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == matcher && fields[1] == "path" {
			return fields[2:]
		}
	}
	t.Fatalf("Caddy path matcher %s was not found", matcher)
	return nil
}

func matchesAnyCaddyPathPattern(requestPath string, patterns []string) bool {
	for _, pattern := range patterns {
		if strings.HasSuffix(pattern, "*") &&
			strings.HasPrefix(requestPath, strings.TrimSuffix(pattern, "*")) {
			return true
		}
		if requestPath == pattern {
			return true
		}
	}
	return false
}
