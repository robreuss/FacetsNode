package devicesync_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/robreuss/FacetsNode/internal/devicesync"
	"github.com/robreuss/FacetsNode/internal/relay"
)

func TestIssueAccountBootstrapCreatesOneTimeCredentialAndSetupURL(t *testing.T) {
	store := devicesync.NewMemoryStore(relay.NewMemoryStore())
	random := bytes.NewReader(bytes.Repeat([]byte{0x5a}, 64))
	now := time.UnixMilli(1_900_000_000_000)

	issued, err := devicesync.IssueAccountBootstrap(
		context.Background(), store, "https://sync.example.test/", 15*time.Minute, now, random,
	)
	if err != nil {
		t.Fatal(err)
	}
	if issued.Bootstrap.ServiceEndpoint != "https://sync.example.test" ||
		issued.Bootstrap.ExpiresAtMilliseconds != now.Add(15*time.Minute).UnixMilli() {
		t.Fatalf("bootstrap=%+v", issued.Bootstrap)
	}
	if !strings.HasPrefix(issued.SetupURL, "facets://device-sync/bootstrap#") {
		t.Fatalf("setup URL=%q", issued.SetupURL)
	}
	encoded := strings.TrimPrefix(issued.SetupURL, "facets://device-sync/bootstrap#")
	payload, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	var decoded devicesync.AccountBootstrap
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded != issued.Bootstrap {
		t.Fatalf("decoded=%+v issued=%+v", decoded, issued.Bootstrap)
	}
}

func TestIssueAccountBootstrapRejectsUnsafeEndpointAndLifetime(t *testing.T) {
	store := devicesync.NewMemoryStore(relay.NewMemoryStore())
	now := time.UnixMilli(1_900_000_000_000)
	for _, testCase := range []struct {
		endpoint string
		lifetime time.Duration
	}{
		{endpoint: "http://sync.example.test", lifetime: 15 * time.Minute},
		{endpoint: "https://sync.example.test/path", lifetime: 15 * time.Minute},
		{endpoint: "https://sync.example.test", lifetime: time.Minute},
	} {
		if _, err := devicesync.IssueAccountBootstrap(
			context.Background(), store, testCase.endpoint, testCase.lifetime,
			now, bytes.NewReader(bytes.Repeat([]byte{0x6b}, 64)),
		); err == nil {
			t.Fatalf("endpoint=%q lifetime=%s was accepted", testCase.endpoint, testCase.lifetime)
		}
	}
}

func TestIssueAccountBootstrapAllowsLoopbackHTTP(t *testing.T) {
	store := devicesync.NewMemoryStore(relay.NewMemoryStore())
	issued, err := devicesync.IssueAccountBootstrap(
		context.Background(), store, "http://127.0.0.1:18080/", 15*time.Minute,
		time.UnixMilli(1_900_000_000_000), bytes.NewReader(bytes.Repeat([]byte{0x4c}, 64)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if issued.Bootstrap.ServiceEndpoint != "http://127.0.0.1:18080" {
		t.Fatalf("endpoint=%q", issued.Bootstrap.ServiceEndpoint)
	}
}
