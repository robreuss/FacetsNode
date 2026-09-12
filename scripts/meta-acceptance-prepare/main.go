// Creates fresh, private configuration for an isolated LAN acceptance Box.
// It neither starts services nor reads/copies another deployment's identity.
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
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

func main() {
	directory := flag.String("directory", "", "new absolute private configuration directory")
	address := flag.String("address", "", "explicit LAN IP of the acceptance VM")
	httpsPort := flag.Int("https-port", 10443, "unoccupied public HTTPS port")
	managementPort := flag.Int("management-port", 18080, "unoccupied loopback-only management port")
	flag.Parse()
	if err := prepare(*directory, *address, *httpsPort, *managementPort); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("Fresh acceptance configuration created. No services started; no credentials printed.")
}

func prepare(directory, address string, httpsPort, managementPort int) error {
	ip := net.ParseIP(address)
	if ip == nil || (!ip.IsPrivate() && !ip.IsLoopback()) ||
		!filepath.IsAbs(directory) || filepath.Clean(directory) != directory ||
		len(strings.Split(directory, string(filepath.Separator))) < 4 ||
		strings.ContainsAny(directory, "\n\r\x00'\"$#") ||
		httpsPort < 1024 || httpsPort > 65535 || managementPort < 1024 || managementPort > 65535 ||
		httpsPort == managementPort {
		return errors.New("require a new dedicated absolute directory, LAN IP, and distinct unprivileged ports")
	}
	if err := os.Mkdir(directory, 0700); err != nil {
		return fmt.Errorf("create new acceptance directory (existing directories are never overwritten): %w", err)
	}
	for _, child := range []string{"keys", "policy", "state", "tls"} {
		if err := os.Mkdir(filepath.Join(directory, child), 0700); err != nil {
			return err
		}
	}
	write := func(name string, data []byte) error {
		file, err := os.OpenFile(filepath.Join(directory, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		defer file.Close()
		if _, err = file.Write(data); err != nil {
			return err
		}
		return file.Sync()
	}
	deploymentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	deploymentID := uuid.New()
	keyBytes := deploymentKey.D.FillBytes(make([]byte, 32))
	signer, err := serviceauthority.NewDeploymentSigner(deploymentID, keyBytes)
	if err != nil {
		return err
	}
	if err := write("keys/deployment-signing-key", []byte(base64.RawURLEncoding.EncodeToString(keyBytes))); err != nil {
		return err
	}
	tlsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	certificate := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: address},
		IPAddresses: []net.IP{ip}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &tlsKey.PublicKey, tlsKey)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(tlsKey)
	if err != nil {
		return err
	}
	if err := write("tls/server.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err != nil {
		return err
	}
	if err := write("tls/server.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})); err != nil {
		return err
	}
	spki, err := x509.MarshalPKIXPublicKey(&tlsKey.PublicKey)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(spki)
	pin := hex.EncodeToString(digest[:])
	baseURL := "https://" + net.JoinHostPort(address, fmt.Sprint(httpsPort)) + "/facetsbox"
	endpoint := baseURL + "/device-sync"
	routeID := uuid.New()
	descriptor := serviceauthority.DeploymentDescriptor{Version: 1, CreatedAtMilliseconds: time.Now().UnixMilli(),
		DeploymentID: deploymentID, PublicSigningKeyX963: signer.PublicSigningKeyX963(),
		SigningKeyFingerprint: signer.SigningKeyFingerprint(), Routes: []serviceauthority.TransportRoute{{
			Endpoint: endpoint, Kind: serviceauthority.RouteDirectHTTPS, NetworkScope: serviceauthority.NetworkTrustedLAN,
			RouteID: routeID, ServerAuthentication: serviceauthority.ServerAuthentication{Kind: "pinned_spki_sha256", PinnedSPKISHA256: &pin}}}}
	policy := serviceauthority.TransportPolicy{Version: 1, ControlRouteIDs: []uuid.UUID{routeID},
		MessageRouteIDs: []uuid.UUID{routeID}, BulkRouteIDs: []uuid.UUID{routeID}}
	if err := descriptor.Validate(); err != nil {
		return err
	}
	if err := policy.Validate(descriptor); err != nil {
		return err
	}
	encoded, err := json.Marshal(serviceauthority.DeploymentOfferTemplate{Version: 1, Deployment: descriptor, TransportPolicy: policy})
	if err != nil {
		return err
	}
	if err := write("policy/deployment-routes.json", encoded); err != nil {
		return err
	}
	if err := write("state/bindings.json", []byte(`{"bindings":[],"version":1}`)); err != nil {
		return err
	}
	values := []string{
		"FACETS_DEVICE_SYNC_PUBLIC_URL=" + endpoint,
		"FACETS_BOX_PUBLIC_URL=" + baseURL,
		"FACETS_BOX_DEVICE_SYNC_URL=" + endpoint,
		"FACETS_BOX_DISPLAY_NAME=Meta Acceptance Box",
		"FACETS_DEVICE_SYNC_HTTPS_PORT=" + fmt.Sprint(httpsPort),
		"FACETS_DEVICE_SYNC_MANAGEMENT_PORT=" + fmt.Sprint(managementPort),
		"FACETS_DEVICE_SYNC_DEPLOYMENT_ID=" + deploymentID.String(),
		"FACETS_DEVICE_SYNC_TLS_DIRECTORY=" + filepath.Join(directory, "tls"),
		"FACETS_DEVICE_SYNC_AUTHORITY_KEY_DIRECTORY=" + filepath.Join(directory, "keys"),
		"FACETS_DEVICE_SYNC_AUTHORITY_POLICY_DIRECTORY=" + filepath.Join(directory, "policy"),
		"FACETS_DEVICE_SYNC_AUTHORITY_STATE_DIRECTORY=" + filepath.Join(directory, "state"),
	}
	for _, name := range []string{"FACETS_DEVICE_SYNC_POSTGRES_PASSWORD", "FACETS_BOX_CONTROLLER_POSTGRES_PASSWORD",
		"FACETS_DEVICE_SYNC_OPERATOR_TOKEN", "FACETS_DEVICE_SYNC_BOX_CONTROLLER_TOKEN"} {
		value := make([]byte, 32)
		if _, err := rand.Read(value); err != nil {
			return err
		}
		values = append(values, name+"="+base64.RawURLEncoding.EncodeToString(value))
	}
	return write(".env", []byte(strings.Join(values, "\n")+"\n"))
}
