package main

import "testing"

func TestServiceContinuityFingerprintBindsAuthoritiesWithoutSetupSecrets(t *testing.T) {
	id := applianceIdentity{InstallationID: "installation", DeviceSync: serviceIdentity{DeploymentID: "device", Onion: "device.onion", TLSSPKI: "pin"}, SharedSpaces: serviceIdentity{DeploymentID: "group"}, Secrets: map[string]string{"activation": "secret"}}
	controller := controllerIdentity{BoxID: "box", PublicKey: "public"}
	first := serviceIdentityFingerprint(id, controller)
	id.Secrets["activation"] = "not-an-authority-change"
	if first != serviceIdentityFingerprint(id, controller) || !validHex(first, 32) {
		t.Fatal("setup secret entered public continuity evidence")
	}
	controller.BoxID = "replacement"
	if first == serviceIdentityFingerprint(id, controller) {
		t.Fatal("controller replacement was invisible")
	}
	controller.BoxID = "box"
	id.DeviceSync.Onion = "changed.onion"
	if first == serviceIdentityFingerprint(id, controller) {
		t.Fatal("onion replacement was invisible")
	}
}
