package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
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
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

type serviceIdentity struct {
	DeploymentID          string `json:"deploymentID"`
	Onion                 string `json:"onion"`
	Endpoint              string `json:"endpoint"`
	LANEndpoint           string `json:"lanEndpoint"`
	TLSSPKI               string `json:"tlsSPKI"`
	SigningKeyFingerprint string `json:"signingKeyFingerprint"`
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

// Stable installation-scoped mDNS name, independent of DHCP and host renames.
func applianceLANHost(installationID string) string {
	digest := sha256.Sum256([]byte("facets-box-lan-v1\x00" + installationID))
	return "facets-box-" + hex.EncodeToString(digest[:16]) + ".local"
}

func makeServiceIdentity(directory, onion, path, lanHost, lanPort string) (serviceIdentity, error) {
	var out serviceIdentity
	if len(onion) != 62 || !strings.HasSuffix(onion, ".onion") || strings.Trim(onion[:56], "abcdefghijklmnopqrstuvwxyz234567") != "" {
		return out, errors.New("invalid onion identity")
	}
	if !strings.HasPrefix(lanHost, "facets-box-") || !strings.HasSuffix(lanHost, ".local") || len(lanHost) != 49 || strings.Trim(lanHost[11:43], "0123456789abcdef") != "" || (lanPort != "9243" && lanPort != "9244") {
		return out, errors.New("invalid LAN identity")
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
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: onion}, DNSNames: []string{onion, lanHost}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
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
	lanEndpoint := "https://" + lanHost + ":" + lanPort + path
	descriptor := serviceauthority.DeploymentDescriptor{Version: 1, CreatedAtMilliseconds: time.Now().UnixMilli(), DeploymentID: id, PublicSigningKeyX963: signer.PublicSigningKeyX963(), SigningKeyFingerprint: signer.SigningKeyFingerprint(), Routes: []serviceauthority.TransportRoute{{Endpoint: endpoint, Kind: serviceauthority.RouteTorOnion, NetworkScope: serviceauthority.NetworkTor, OnionServiceID: &onionID, OnionPortability: &portability, RouteID: routeID, ServerAuthentication: serviceauthority.ServerAuthentication{Kind: "pinned_spki_sha256", PinnedSPKISHA256: &pin}}}}
	lanRouteID := uuid.New()
	descriptor.Routes = append(descriptor.Routes, serviceauthority.TransportRoute{Endpoint: lanEndpoint, Kind: serviceauthority.RouteDirectHTTPS, NetworkScope: serviceauthority.NetworkTrustedLAN, RouteID: lanRouteID, ServerAuthentication: serviceauthority.ServerAuthentication{Kind: "pinned_spki_sha256", PinnedSPKISHA256: &pin}})
	sort.Slice(descriptor.Routes, func(i, j int) bool {
		return descriptor.Routes[i].RouteID.String() < descriptor.Routes[j].RouteID.String()
	})
	policy := serviceauthority.TransportPolicy{Version: 1, ControlRouteIDs: []uuid.UUID{lanRouteID, routeID}, MessageRouteIDs: []uuid.UUID{lanRouteID, routeID}, BulkRouteIDs: []uuid.UUID{lanRouteID, routeID}}
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
	return serviceIdentity{DeploymentID: id.String(), Onion: onion, Endpoint: endpoint, LANEndpoint: lanEndpoint, TLSSPKI: pin, SigningKeyFingerprint: signer.SigningKeyFingerprint()}, nil
}

func validateServiceIdentity(directory string, identity serviceIdentity) error {
	id, e := uuid.Parse(identity.DeploymentID)
	if e != nil {
		return e
	}
	signer, e := serviceauthority.LoadDeploymentSigner(id, filepath.Join(directory, "keys/deployment-signing-key"))
	if e != nil {
		return e
	}
	if signer.SigningKeyFingerprint() != identity.SigningKeyFingerprint {
		return errors.New("deployment key changed")
	}
	policy, e := serviceauthority.LoadDeploymentOfferTemplate(filepath.Join(directory, "policy/deployment-routes.json"), signer)
	if e != nil || len(policy.Deployment.Routes) != 2 || identity.LANEndpoint == "" {
		return errors.New("deployment route changed")
	}
	var lan, onion *serviceauthority.TransportRoute
	for i := range policy.Deployment.Routes {
		route := &policy.Deployment.Routes[i]
		pin := route.ServerAuthentication.PinnedSPKISHA256
		if pin == nil || *pin != identity.TLSSPKI {
			return errors.New("TLS route pin changed")
		}
		if route.Kind == serviceauthority.RouteDirectHTTPS && route.NetworkScope == serviceauthority.NetworkTrustedLAN && route.Endpoint == identity.LANEndpoint {
			lan = route
		}
		if route.Kind == serviceauthority.RouteTorOnion && route.Endpoint == identity.Endpoint {
			onion = route
		}
	}
	if lan == nil || onion == nil {
		return errors.New("deployment route changed")
	}
	for _, ids := range [][]uuid.UUID{policy.TransportPolicy.ControlRouteIDs, policy.TransportPolicy.MessageRouteIDs, policy.TransportPolicy.BulkRouteIDs} {
		if len(ids) != 2 || ids[0] != lan.RouteID || ids[1] != onion.RouteID {
			return errors.New("deployment route order changed")
		}
	}
	cert, e := tls.LoadX509KeyPair(filepath.Join(directory, "tls/server.crt"), filepath.Join(directory, "tls/server.key"))
	if e != nil {
		return e
	}
	leaf, e := x509.ParseCertificate(cert.Certificate[0])
	lanHost := strings.Split(strings.TrimPrefix(identity.LANEndpoint, "https://"), ":")[0]
	if e != nil || leaf.VerifyHostname(identity.Onion) != nil || leaf.VerifyHostname(lanHost) != nil {
		return errors.New("TLS identity changed")
	}
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	if hex.EncodeToString(sum[:]) != identity.TLSSPKI {
		return errors.New("TLS key changed")
	}
	bindingsPath := filepath.Join(directory, "state/bindings.json")
	info, e := os.Lstat(bindingsPath)
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return errors.New("authority state unavailable")
	}
	return nil
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
		if e = validateServiceIdentity(filepath.Join(final, "device-sync"), out.DeviceSync); e != nil {
			return out, e
		}
		if e = validateServiceIdentity(filepath.Join(final, "shared-spaces"), out.SharedSpaces); e != nil {
			return out, e
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
	out.DeviceSync, e = makeServiceIdentity(filepath.Join(staging, "device-sync"), boxOnion, "/facetsbox/device-sync", applianceLANHost(installationID), "9243")
	if e != nil {
		return out, e
	}
	out.SharedSpaces, e = makeServiceIdentity(filepath.Join(staging, "shared-spaces"), groupOnion, "", applianceLANHost(installationID), "9244")
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
