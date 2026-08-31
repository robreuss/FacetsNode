package serverapp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/backupcustody"
	"github.com/robreuss/FacetsNode/internal/config"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

func TestBackupAccountBootstrapUsesDeploymentOfferBoundDerivedBearer(t *testing.T) {
	root := t.TempDir()
	deploymentID := uuid.MustParse("89000000-0000-0000-0000-000000000001")
	accountID := uuid.MustParse("89000000-0000-0000-0000-000000000002")
	endpoint := "https://backup.example"
	seed := bytes.Repeat([]byte{0}, 32)
	seed[31] = 7
	signer, err := serviceauthority.NewDeploymentSigner(deploymentID, seed)
	if err != nil {
		t.Fatal(err)
	}
	routeID := uuid.MustParse("89000000-0000-0000-0000-000000000003")
	route := serviceauthority.TransportRoute{
		Endpoint:             endpoint,
		Kind:                 serviceauthority.RouteDirectHTTPS,
		NetworkScope:         serviceauthority.NetworkPublic,
		RouteID:              routeID,
		ServerAuthentication: serviceauthority.ServerAuthentication{Kind: "web_pki"},
	}
	descriptor := serviceauthority.DeploymentDescriptor{
		Version:               serviceauthority.SchemaVersion,
		DeploymentID:          deploymentID,
		CreatedAtMilliseconds: 900,
		PublicSigningKeyX963:  signer.PublicSigningKeyX963(),
		SigningKeyFingerprint: signer.SigningKeyFingerprint(),
		Routes:                []serviceauthority.TransportRoute{route},
	}
	policy := serviceauthority.TransportPolicy{
		Version:                        serviceauthority.SchemaVersion,
		AllowsPublicDirectBulkTransfer: true,
		ControlRouteIDs:                []uuid.UUID{routeID},
		MessageRouteIDs:                []uuid.UUID{routeID},
		BulkRouteIDs:                   []uuid.UUID{routeID},
	}
	template := serviceauthority.DeploymentOfferTemplate{
		Version:         serviceauthority.SchemaVersion,
		Deployment:      descriptor,
		TransportPolicy: policy,
	}
	keyPath := filepath.Join(root, "admission.key")
	signingPath := filepath.Join(root, "deployment.key")
	policyPath := filepath.Join(root, "routes.json")
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{0x4a}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(signingPath, []byte(base64.RawURLEncoding.EncodeToString(seed)), 0o600); err != nil {
		t.Fatal(err)
	}
	templateBytes, _ := json.Marshal(template)
	if err := os.WriteFile(policyPath, templateBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FACETS_BACKUP_CUSTODY_DATABASE_URL", "postgres://unused")
	t.Setenv("FACETS_BACKUP_CUSTODY_PUBLIC_URL", endpoint)
	t.Setenv("FACETS_BACKUP_CUSTODY_DEPLOYMENT_ID", deploymentID.String())
	t.Setenv("FACETS_BACKUP_CUSTODY_DEPLOYMENT_SIGNING_KEY_FILE", signingPath)
	t.Setenv("FACETS_BACKUP_CUSTODY_DEPLOYMENT_ROUTE_POLICY_FILE", policyPath)
	t.Setenv("FACETS_BACKUP_CUSTODY_SERVICE_AUTHORITY_BINDINGS_FILE", filepath.Join(root, "bindings.json"))
	t.Setenv("FACETS_BACKUP_CUSTODY_ACCOUNT_ADMISSION_KEY_FILE", keyPath)

	var output bytes.Buffer
	now := time.UnixMilli(1_000)
	if err := issueBackupAccountAdmission(
		config.BackupCustody,
		[]string{"--account-id", accountID.String(), "--lifetime", "10m"},
		&output,
		func() time.Time { return now },
	); err != nil {
		t.Fatal(err)
	}
	var bootstrap backupAccountBootstrap
	if err := json.Unmarshal(output.Bytes(), &bootstrap); err != nil {
		t.Fatal(err)
	}
	if bootstrap.Version != backupcustody.Version || bootstrap.Endpoint != endpoint ||
		bootstrap.AccountAdmission.AccountID != accountID || bootstrap.AuthorizationToken == "" {
		t.Fatalf("bootstrap=%+v", bootstrap)
	}
	authority, err := loadBackupAccountAdmissionAuthority(keyPath, deploymentID)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := authority.credential(bootstrap.AccountAdmission, deploymentID, bootstrap.DeploymentOffer)
	if err != nil || expected.TransportBearer() != bootstrap.AuthorizationToken {
		t.Fatal("bootstrap bearer was not derived from exact deployment offer")
	}
	changedOffer, err := template.SignOffer(signer, now.Add(time.Second), now.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := authority.credential(bootstrap.AccountAdmission, deploymentID, changedOffer); err == nil &&
		changed.TransportBearer() == bootstrap.AuthorizationToken {
		t.Fatal("admission bearer was reusable with another signed offer")
	}
	if strings.Contains(bootstrap.String(), bootstrap.AuthorizationToken) ||
		strings.Contains(bootstrap.GoString(), bootstrap.AuthorizationToken) {
		t.Fatal("bootstrap diagnostics exposed bearer")
	}
	if _, err := json.Marshal(bootstrap); err == nil {
		t.Fatal("secret-bearing bootstrap allowed generic JSON formatting")
	}
	keyBytes := bytes.Repeat([]byte{0x4a}, 32)
	keyHex := fmt.Sprintf("%x", keyBytes)
	keyBase64 := base64.RawURLEncoding.EncodeToString(keyBytes)
	for _, formatted := range []string{
		fmt.Sprintf("%v", authority),
		fmt.Sprintf("%+v", authority),
		fmt.Sprintf("%#v", authority),
	} {
		if strings.Contains(formatted, keyHex) || strings.Contains(formatted, keyBase64) ||
			strings.Contains(formatted, "74 74 74 74") {
			t.Fatalf("admission authority diagnostics exposed key: %s", formatted)
		}
	}
}

func TestBackupAccountAdmissionKeyRequiresExactOwnerPrivateFile(t *testing.T) {
	root := t.TempDir()
	deploymentID := uuid.New()
	path := filepath.Join(root, "key")
	if err := os.WriteFile(path, bytes.Repeat([]byte{1}, 32), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadBackupAccountAdmissionAuthority(path, deploymentID); err == nil {
		t.Fatal("group/world-readable admission key accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadBackupAccountAdmissionAuthority(path, deploymentID); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := loadBackupAccountAdmissionAuthority(link, deploymentID); err == nil {
		t.Fatal("symlink admission key accepted")
	}
}

func TestBackupCustodyStartupRequiresPublicURLOnSignedControlRoute(t *testing.T) {
	root := t.TempDir()
	deploymentID := uuid.New()
	seed := bytes.Repeat([]byte{0x31}, 32)
	signer, err := serviceauthority.NewDeploymentSigner(deploymentID, seed)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "https://backup.example"
	routeID := uuid.New()
	template := serviceauthority.DeploymentOfferTemplate{
		Version: serviceauthority.SchemaVersion,
		Deployment: serviceauthority.DeploymentDescriptor{
			Version:               serviceauthority.SchemaVersion,
			DeploymentID:          deploymentID,
			CreatedAtMilliseconds: 1_000,
			PublicSigningKeyX963:  signer.PublicSigningKeyX963(),
			SigningKeyFingerprint: signer.SigningKeyFingerprint(),
			Routes: []serviceauthority.TransportRoute{{
				Endpoint:             endpoint,
				Kind:                 serviceauthority.RouteDirectHTTPS,
				NetworkScope:         serviceauthority.NetworkPublic,
				RouteID:              routeID,
				ServerAuthentication: serviceauthority.ServerAuthentication{Kind: "web_pki"},
			}},
		},
		TransportPolicy: serviceauthority.TransportPolicy{
			Version:                        serviceauthority.SchemaVersion,
			AllowsPublicDirectBulkTransfer: true,
			BulkRouteIDs:                   []uuid.UUID{routeID},
			MessageRouteIDs:                []uuid.UUID{routeID},
		},
	}
	signingPath := filepath.Join(root, "deployment.key")
	policyPath := filepath.Join(root, "routes.json")
	if err := os.WriteFile(signingPath, []byte(base64.RawURLEncoding.EncodeToString(seed)), 0o600); err != nil {
		t.Fatal(err)
	}
	templateBytes, _ := json.Marshal(template)
	if err := os.WriteFile(policyPath, templateBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	configuration := config.Config{
		DeploymentID:              deploymentID,
		DeploymentSigningKeyFile:  signingPath,
		DeploymentRoutePolicyFile: policyPath,
		PublicURL:                 endpoint,
	}
	if _, err := loadBackupCustodyDeploymentAuthority(configuration); err == nil {
		t.Fatal("public Backup URL on a bulk-only route was accepted")
	}
	template.TransportPolicy.ControlRouteIDs = []uuid.UUID{routeID}
	templateBytes, _ = json.Marshal(template)
	if err := os.WriteFile(policyPath, templateBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	configuration.PublicURL = "https://other.example"
	if _, err := loadBackupCustodyDeploymentAuthority(configuration); err == nil {
		t.Fatal("public Backup URL absent from the signed route policy was accepted")
	}
	configuration.PublicURL = endpoint
	if _, err := loadBackupCustodyDeploymentAuthority(configuration); err != nil {
		t.Fatal(err)
	}
}
