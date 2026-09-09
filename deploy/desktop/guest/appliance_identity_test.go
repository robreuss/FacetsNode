package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
