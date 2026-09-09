package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// A continuity fingerprint is safe for redacted host health; onion addresses,
// private keys and setup credentials are not part of that health document.
func serviceIdentityFingerprint(identity applianceIdentity, controller controllerIdentity) string {
	b, _ := json.Marshal(struct {
		Installation            string
		DeviceSync, GroupSpaces serviceIdentity
		Controller              controllerIdentity
	}{identity.InstallationID, identity.DeviceSync, identity.SharedSpaces, controller})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
