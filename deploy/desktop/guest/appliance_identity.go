package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

type serviceIdentity struct {
	DeploymentID string `json:"deploymentID"`
	Onion        string `json:"onion"`
	Endpoint     string `json:"endpoint"`
	TLSSPKI      string `json:"tlsSPKI"`
}
type applianceIdentity struct {
	Version        int               `json:"version"`
	InstallationID string            `json:"installationID"`
	DeviceSync     serviceIdentity   `json:"deviceSync"`
	SharedSpaces   serviceIdentity   `json:"sharedSpaces"`
	Secrets        map[string]string `json:"secrets"`
}

func randomSecret() (string, error) {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func privateWrite(path string, b []byte) error {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	if _, e = f.Write(b); e != nil {
		return e
	}
	return f.Sync()
}
func makeServiceIdentity(directory, onion, path string) (serviceIdentity, error) {
	var out serviceIdentity
	if len(onion) != 62 || !strings.HasSuffix(onion, ".onion") || strings.Trim(onion[:56], "abcdefghijklmnopqrstuvwxyz234567") != "" {
		return out, errors.New("invalid onion identity")
	}
	for _, child := range []string{"keys", "policy", "state", "tls"} {
		if e := os.MkdirAll(filepath.Join(directory, child), 0700); e != nil {
			return out, e
		}
	}
	deploymentKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return out, e
	}
	id := uuid.New()
	signer, e := serviceauthority.NewDeploymentSigner(id, deploymentKey.D.FillBytes(make([]byte, 32)))
	if e != nil {
		return out, e
	}
	if e = privateWrite(filepath.Join(directory, "keys/deployment-signing-key"), []byte(base64.RawURLEncoding.EncodeToString(deploymentKey.D.FillBytes(make([]byte, 32))))); e != nil {
		return out, e
	}
	tlsKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return out, e
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return out, e
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: onion}, DNSNames: []string{onion}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &tlsKey.PublicKey, tlsKey)
	if e != nil {
		return out, e
	}
	keyDER, e := x509.MarshalPKCS8PrivateKey(tlsKey)
	if e != nil {
		return out, e
	}
	if e = privateWrite(filepath.Join(directory, "tls/server.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); e != nil {
		return out, e
	}
	if e = privateWrite(filepath.Join(directory, "tls/server.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})); e != nil {
		return out, e
	}
	spki, e := x509.MarshalPKIXPublicKey(&tlsKey.PublicKey)
	if e != nil {
		return out, e
	}
	sum := sha256.Sum256(spki)
	pin := hex.EncodeToString(sum[:])
	routeID := uuid.New()
	onionID := onion[:56]
	portability := "dedicated_portable"
	endpoint := "https://" + onion + path
	descriptor := serviceauthority.DeploymentDescriptor{Version: 1, CreatedAtMilliseconds: time.Now().UnixMilli(), DeploymentID: id, PublicSigningKeyX963: signer.PublicSigningKeyX963(), SigningKeyFingerprint: signer.SigningKeyFingerprint(), Routes: []serviceauthority.TransportRoute{{Endpoint: endpoint, Kind: serviceauthority.RouteTorOnion, NetworkScope: serviceauthority.NetworkTor, OnionServiceID: &onionID, OnionPortability: &portability, RouteID: routeID, ServerAuthentication: serviceauthority.ServerAuthentication{Kind: "pinned_spki_sha256", PinnedSPKISHA256: &pin}}}}
	policy := serviceauthority.TransportPolicy{Version: 1, ControlRouteIDs: []uuid.UUID{routeID}, MessageRouteIDs: []uuid.UUID{routeID}, BulkRouteIDs: []uuid.UUID{routeID}}
	if descriptor.Validate() != nil || policy.Validate(descriptor) != nil {
		return out, errors.New("invalid generated route policy")
	}
	b, e := json.Marshal(serviceauthority.DeploymentOfferTemplate{Version: 1, Deployment: descriptor, TransportPolicy: policy})
	if e != nil {
		return out, e
	}
	if e = privateWrite(filepath.Join(directory, "policy/deployment-routes.json"), b); e != nil {
		return out, e
	}
	if e = privateWrite(filepath.Join(directory, "state/bindings.json"), []byte(`{"bindings":[],"version":1}`)); e != nil {
		return out, e
	}
	return serviceIdentity{DeploymentID: id.String(), Onion: onion, Endpoint: endpoint, TLSSPKI: pin}, nil
}

// The complete first-boot configuration is published atomically. An existing
// inconsistent identity never authorizes generation of a replacement identity.
func initializeApplianceIdentity(root, installationID, boxOnion, groupOnion string) (applianceIdentity, error) {
	var out applianceIdentity
	final := filepath.Join(root, "configuration")
	if _, e := os.Stat(final); e == nil {
		b, e := os.ReadFile(filepath.Join(final, "identity.json"))
		if e != nil || json.Unmarshal(b, &out) != nil || out.Version != 1 || out.InstallationID != installationID || out.DeviceSync.Onion != boxOnion || out.SharedSpaces.Onion != groupOnion {
			return out, errors.New("existing configuration identity inconsistent")
		}
		return out, nil
	} else if !os.IsNotExist(e) {
		return out, e
	}
	staging, e := os.MkdirTemp(root, "configuration-")
	if e != nil {
		return out, e
	}
	out = applianceIdentity{Version: 1, InstallationID: installationID, Secrets: map[string]string{}}
	out.DeviceSync, e = makeServiceIdentity(filepath.Join(staging, "device-sync"), boxOnion, "/facetsbox/device-sync")
	if e != nil {
		return out, e
	}
	out.SharedSpaces, e = makeServiceIdentity(filepath.Join(staging, "shared-spaces"), groupOnion, "")
	if e != nil {
		return out, e
	}
	for _, name := range []string{"device-sync-db", "controller-db", "shared-spaces-db", "device-sync-operator", "shared-spaces-operator", "box-controller", "device-sync-onion", "shared-spaces-onion", "shared-spaces-key", "shared-spaces-compute-seed", "activation"} {
		out.Secrets[name], e = randomSecret()
		if e != nil {
			return out, e
		}
	}
	if e = writeJSONFile(filepath.Join(staging, "identity.json"), out); e != nil {
		return out, e
	}
	if e = os.Rename(staging, final); e != nil {
		return out, e
	}
	d, e := os.Open(root)
	if e != nil {
		return out, e
	}
	defer d.Close()
	return out, d.Sync()
}
