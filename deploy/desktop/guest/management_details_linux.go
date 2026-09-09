//go:build linux

package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"time"
)

func readManagementDetails(c configuration, includeSetupCode bool) (*managementDetails, string, error) {
	if c.ActivationPending {
		return nil, "", errors.New("candidate management withheld")
	}
	applianceServices.Lock()
	mode, fingerprint := applianceServices.mode, applianceServices.identity
	applianceServices.Unlock()
	if mode != "active" || !validHex(fingerprint, 32) {
		return nil, "", errors.New("management unavailable")
	}
	// Apply the same active-release and fixed controller-socket gate as streams.
	connection, err := openManagement(c)
	if err != nil {
		return nil, "", err
	}
	connection.Close()
	var identity applianceIdentity
	b, err := boundedIdentityFile(dataRoot+"/configuration/identity.json", 65536)
	if err != nil || json.Unmarshal(b, &identity) != nil || identity.InstallationID != c.InstallationID {
		return nil, "", errors.New("management identity unavailable")
	}
	var controller controllerIdentity
	b, err = boundedIdentityFile(dataRoot+"/configuration/controller-identity.json", 4096)
	if err != nil || json.Unmarshal(b, &controller) != nil || serviceIdentityFingerprint(identity, controller) != fingerprint {
		return nil, "", errors.New("management identity changed")
	}
	cert, err := boundedIdentityFile(dataRoot+"/configuration/device-sync/tls/server.crt", 16384)
	if err != nil {
		return nil, "", err
	}
	block, rest := pem.Decode(cert)
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		return nil, "", errors.New("controller certificate unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	state, err := controllerQuery(ctx, "SELECT json_build_object('boxID', box_id::text, 'claimed', owner_verifier <> '')::text FROM box_state WHERE id = true")
	var box struct {
		BoxID   string
		Claimed bool
	}
	if err != nil || json.Unmarshal([]byte(state), &box) != nil || box.BoxID != controller.BoxID {
		return nil, "", errors.New("controller claim state unavailable")
	}
	details := &managementDetails{Onion: identity.DeviceSync.Onion, CertificateDER: block.Bytes, SPKISHA256: identity.DeviceSync.TLSSPKI, ServiceIdentity: fingerprint, BoxID: controller.BoxID, SetupRequired: !box.Claimed}
	code := ""
	if includeSetupCode {
		if box.Claimed {
			return nil, "", errors.New("Box already claimed")
		}
		code = identity.Secrets["activation"]
		if len(code) < 12 || len(code) > 128 {
			return nil, "", errors.New("setup code unavailable")
		}
	}
	return details, code, nil
}
