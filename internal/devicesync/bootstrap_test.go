package devicesync_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/devicesync"
	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

func TestIssueAccountBootstrapCreatesOneTimeCredentialAndSetupURL(t *testing.T) {
	store := devicesync.NewMemoryStore(relay.NewMemoryStore())
	random := bytes.NewReader(bytes.Repeat([]byte{0x5a}, 64))
	now := time.UnixMilli(1_900_000_000_000)

	issued, err := devicesync.IssueAccountBootstrap(
		context.Background(), store, "https://sync.example.test/",
		testDeploymentOffer(t, "https://sync.example.test", now, 15*time.Minute),
		15*time.Minute, now, random,
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
	if !reflect.DeepEqual(decoded, issued.Bootstrap) {
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
			context.Background(), store, testCase.endpoint,
			testDeploymentOffer(t, "https://sync.example.test", now, 15*time.Minute),
			testCase.lifetime,
			now, bytes.NewReader(bytes.Repeat([]byte{0x6b}, 64)),
		); err == nil {
			t.Fatalf("endpoint=%q lifetime=%s was accepted", testCase.endpoint, testCase.lifetime)
		}
	}
}

func TestIssueAccountBootstrapRejectsEndpointOutsideSignedRoutes(t *testing.T) {
	store := devicesync.NewMemoryStore(relay.NewMemoryStore())
	now := time.UnixMilli(1_900_000_000_000)
	_, err := devicesync.IssueAccountBootstrap(
		context.Background(), store, "https://other.example.test",
		testDeploymentOffer(t, "https://sync.example.test", now, 15*time.Minute),
		15*time.Minute, now, bytes.NewReader(bytes.Repeat([]byte{0x4c}, 64)),
	)
	if err == nil {
		t.Fatal("endpoint outside signed control routes accepted")
	}
}

func testDeploymentOffer(
	t *testing.T,
	endpoint string,
	now time.Time,
	lifetime time.Duration,
) serviceauthority.DeploymentOffer {
	t.Helper()
	deploymentID := uuid.MustParse("63000000-0000-0000-0000-000000000001")
	seed := make([]byte, 32)
	seed[31] = 2
	signer, err := serviceauthority.NewDeploymentSigner(deploymentID, seed)
	if err != nil {
		t.Fatal(err)
	}
	routeID := uuid.MustParse("62000000-0000-0000-0000-000000000001")
	template := serviceauthority.DeploymentOfferTemplate{
		Deployment: serviceauthority.DeploymentDescriptor{
			CreatedAtMilliseconds: now.Add(-time.Hour).UnixMilli(),
			DeploymentID:          deploymentID,
			PublicSigningKeyX963:  signer.PublicSigningKeyX963(),
			Routes: []serviceauthority.TransportRoute{{
				Endpoint:     endpoint,
				Kind:         serviceauthority.RouteDirectHTTPS,
				NetworkScope: serviceauthority.NetworkPublic,
				RouteID:      routeID,
				ServerAuthentication: serviceauthority.ServerAuthentication{
					Kind: "web_pki",
				},
			}},
			SigningKeyFingerprint: signer.SigningKeyFingerprint(),
			Version:               serviceauthority.SchemaVersion,
		},
		TransportPolicy: serviceauthority.TransportPolicy{
			AllowsPublicDirectBulkTransfer: true,
			BulkRouteIDs:                   []uuid.UUID{routeID},
			ControlRouteIDs:                []uuid.UUID{routeID},
			MessageRouteIDs:                []uuid.UUID{routeID},
			Version:                        serviceauthority.SchemaVersion,
		},
		Version: serviceauthority.SchemaVersion,
	}
	offer, err := template.SignOffer(signer, now, now.Add(lifetime))
	if err != nil {
		t.Fatal(err)
	}
	return offer
}
