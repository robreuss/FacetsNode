package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

func TestLANRoutesAreStablePinnedAndPreferredWithoutChangingTorIdentity(t *testing.T) {
	root := t.TempDir()
	box := strings.Repeat("a", 56) + ".onion"
	group := strings.Repeat("b", 56) + ".onion"
	identity, err := initializeApplianceIdentity(root, "installation", box, group)
	if err != nil {
		t.Fatal(err)
	}
	host := applianceLANHost("installation")
	if host != "facets-box-18eec647da36972c98009e1848c39fb9.local" || host == applianceLANHost("other") {
		t.Fatal("unstable LAN identity")
	}
	if identity.DeviceSync.LANEndpoint != "https://"+host+":9243/facetsbox/device-sync" || identity.SharedSpaces.LANEndpoint != "https://"+host+":9244" {
		t.Fatal("incorrect local endpoints")
	}
	for _, name := range []string{"device-sync", "shared-spaces"} {
		path := filepath.Join(root, "configuration", name, "policy/deployment-routes.json")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var offer serviceauthority.DeploymentOfferTemplate
		if err := json.Unmarshal(data, &offer); err != nil {
			t.Fatal(err)
		}
		if len(offer.Deployment.Routes) != 2 {
			t.Fatal("missing route")
		}
		for _, route := range offer.Deployment.Routes {
			if route.Kind == serviceauthority.RouteDirectHTTPS && (route.NetworkScope != serviceauthority.NetworkTrustedLAN || route.RouteID != offer.TransportPolicy.ControlRouteIDs[0] || route.RouteID != offer.TransportPolicy.BulkRouteIDs[0]) {
				t.Fatal("LAN not preferred")
			}
		}
		// A changed route cannot be silently repaired or used with old pins.
		offer.Deployment.Routes[0].Endpoint = "https://wrong.local:9243"
		changed, _ := json.Marshal(offer)
		if err := os.WriteFile(path, changed, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := initializeApplianceIdentity(root, "installation", box, group); err == nil {
			t.Fatal("accepted changed route")
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestApplianceIdentityIsIndependentPersistentAndFailsClosed(t *testing.T) {
	root := t.TempDir()
	box := strings.Repeat("a", 56) + ".onion"
	group := strings.Repeat("b", 56) + ".onion"
	first, e := initializeApplianceIdentity(root, "installation", box, group)
	if e != nil {
		t.Fatal(e)
	}
	second, e := initializeApplianceIdentity(root, "installation", box, group)
	if e != nil {
		t.Fatal(e)
	}
	if first.DeviceSync != second.DeviceSync || first.Secrets["activation"] != second.Secrets["activation"] {
		t.Fatal("regenerated identity")
	}
	format := regexp.MustCompile(`^[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}(-[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}){2}$`)
	if !format.MatchString(first.Secrets["activation"]) {
		t.Fatal("Desktop activation must use the shared human-readable Box code format")
	}
	for name, secret := range first.Secrets {
		if name == "activation" {
			continue
		}
		decoded, err := base64.RawURLEncoding.DecodeString(secret)
		if err != nil || len(decoded) != 32 {
			t.Fatalf("machine credential %s must retain 32 random bytes", name)
		}
	}
	if first.DeviceSync.DeploymentID == first.SharedSpaces.DeploymentID || first.Secrets["device-sync-db"] == first.Secrets["shared-spaces-db"] {
		t.Fatal("shared authority or credentials")
	}
	if _, e = initializeApplianceIdentity(root, "different", box, group); e == nil {
		t.Fatal("accepted wrong installation")
	}
	if e = os.WriteFile(filepath.Join(root, "configuration/identity.json"), []byte("invalid"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = initializeApplianceIdentity(root, "installation", box, group); e == nil {
		t.Fatal("replaced corrupt configuration")
	}
}

func TestMissingDeploymentKeyIsNeverRegenerated(t *testing.T) {
	root := t.TempDir()
	box := strings.Repeat("a", 56) + ".onion"
	group := strings.Repeat("b", 56) + ".onion"
	if _, e := initializeApplianceIdentity(root, "installation", box, group); e != nil {
		t.Fatal(e)
	}
	key := filepath.Join(root, "configuration/device-sync/keys/deployment-signing-key")
	if e := os.Remove(key); e != nil {
		t.Fatal(e)
	}
	if _, e := initializeApplianceIdentity(root, "installation", box, group); e == nil {
		t.Fatal("accepted missing key")
	}
	if _, e := os.Stat(key); !os.IsNotExist(e) {
		t.Fatal("regenerated missing identity")
	}
}
