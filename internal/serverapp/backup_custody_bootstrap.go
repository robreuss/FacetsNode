package serverapp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/backupcustody"
	"github.com/robreuss/FacetsNode/internal/config"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

const backupAccountAdmissionDomain = "Facets Backup custody account admission bearer v1\x00"

type backupAccountAdmissionAuthority struct {
	key          [32]byte
	deploymentID uuid.UUID
}

func (authority backupAccountAdmissionAuthority) String() string {
	return "backup-account-admission-authority(key-redacted)"
}

func (authority backupAccountAdmissionAuthority) GoString() string { return authority.String() }

type backupAccountBootstrap struct {
	AccountAdmission   backupcustody.AccountAdmissionReference `json:"accountAdmission"`
	AuthorizationToken string                                  `json:"authorizationToken"`
	DeploymentOffer    serviceauthority.DeploymentOffer        `json:"deploymentOffer"`
	Endpoint           string                                  `json:"endpoint"`
	Version            int                                     `json:"version"`
}

type backupAccountBootstrapCLIWire backupAccountBootstrap

func loadBackupAccountAdmissionAuthority(path string, deploymentID uuid.UUID) (*backupAccountAdmissionAuthority, error) {
	resolved, err := filepath.Abs(path)
	if err != nil || filepath.Clean(resolved) != resolved || deploymentID == uuid.Nil {
		return nil, serviceauthority.ErrInvalid
	}
	info, err := os.Lstat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, serviceauthority.ErrInvalid
	}
	file, err := os.Open(resolved)
	if err != nil {
		return nil, serviceauthority.ErrInvalid
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, serviceauthority.ErrInvalid
	}
	key, err := io.ReadAll(io.LimitReader(file, 33))
	if err != nil || len(key) != 32 {
		return nil, serviceauthority.ErrInvalid
	}
	authority := &backupAccountAdmissionAuthority{}
	copy(authority.key[:], key)
	authority.deploymentID = deploymentID
	return authority, nil
}

func (authority *backupAccountAdmissionAuthority) credential(
	reference backupcustody.AccountAdmissionReference,
	deploymentID uuid.UUID,
	offer serviceauthority.DeploymentOffer,
) (backupcustody.AccountAdmissionCredential, error) {
	offerPayload, offerErr := offer.VerifiedPayload(nil)
	offerReference, referenceErr := offer.ReferenceDigest()
	if authority == nil || reference.Validate() != nil || deploymentID == uuid.Nil ||
		offerErr != nil || referenceErr != nil || offerPayload.Deployment.DeploymentID != deploymentID ||
		reference.ExpiresAtMilliseconds <= offerPayload.IssuedAtMilliseconds ||
		reference.ExpiresAtMilliseconds > offerPayload.ExpiresAtMilliseconds {
		return backupcustody.AccountAdmissionCredential{}, serviceauthority.ErrInvalid
	}
	encoded, err := json.Marshal(reference)
	if err != nil {
		return backupcustody.AccountAdmissionCredential{}, serviceauthority.ErrInvalid
	}
	mac := hmac.New(sha256.New, authority.key[:])
	_, _ = mac.Write([]byte(backupAccountAdmissionDomain))
	_, _ = mac.Write(deploymentID[:])
	_, _ = mac.Write(encoded)
	_, _ = mac.Write([]byte(offerReference))
	bearer := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return backupcustody.ParseAccountAdmissionCredential(reference, bearer)
}

func (authority *backupAccountAdmissionAuthority) verify(
	credential backupcustody.AccountAdmissionCredential,
	deploymentID uuid.UUID,
	enrollment serviceauthority.InitialEnrollment,
) bool {
	if authority == nil {
		return false
	}
	expected, err := authority.credential(
		credential.Reference,
		deploymentID,
		enrollment.DeploymentOffer,
	)
	if err != nil {
		return false
	}
	return hmac.Equal(
		[]byte(expected.TransportBearer()),
		[]byte(credential.TransportBearer()),
	)
}

func (authority *backupAccountAdmissionAuthority) VerifyAccountAdmission(
	credential backupcustody.AccountAdmissionCredential,
	enrollment serviceauthority.InitialEnrollment,
) bool {
	scope := serviceauthority.Scope{
		Kind:    serviceauthority.ScopeBackupCustody,
		ScopeID: credential.Reference.AccountID,
	}
	if _, err := enrollment.ValidateForAdmissionClaim(scope); err != nil {
		return false
	}
	return authority.verify(credential, authority.deploymentID, enrollment)
}

func (bootstrap backupAccountBootstrap) String() string {
	return "backup-account-bootstrap(authorization-token-redacted)"
}

func (bootstrap backupAccountBootstrap) GoString() string { return bootstrap.String() }

func (bootstrap backupAccountBootstrap) MarshalJSON() ([]byte, error) {
	return nil, serviceauthority.ErrInvalid
}

func issueBackupAccountAdmission(
	service config.Service,
	arguments []string,
	output io.Writer,
	now func() time.Time,
) error {
	if service != config.BackupCustody {
		return fmt.Errorf("account admissions are available only for Facets Backup Custody Service")
	}
	configuration, err := config.Load(service)
	if err != nil {
		return err
	}
	flags := flag.NewFlagSet("issue-backup-account-admission", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	endpoint := flags.String("endpoint", configuration.PublicURL, "client-visible Backup Custody HTTPS endpoint")
	lifetime := flags.Duration("lifetime", 15*time.Minute, "one-time credential lifetime")
	accountText := flags.String("account-id", "", "optional fixed Backup account UUID")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *endpoint == "" || *lifetime <= 0 || *lifetime > time.Hour {
		return serviceauthority.ErrInvalid
	}
	accountID := uuid.New()
	if *accountText != "" {
		accountID, err = uuid.Parse(*accountText)
		if err != nil || accountID == uuid.Nil {
			return serviceauthority.ErrInvalid
		}
	}
	authority, err := loadBackupAccountAdmissionAuthority(
		configuration.BackupAccountAdmissionKeyFile,
		configuration.DeploymentID,
	)
	if err != nil {
		return fmt.Errorf("Backup account admission authority rejected: %w", err)
	}
	signer, err := serviceauthority.LoadDeploymentSigner(
		configuration.DeploymentID,
		configuration.DeploymentSigningKeyFile,
	)
	if err != nil {
		return fmt.Errorf("deployment signing custody rejected: %w", err)
	}
	template, err := serviceauthority.LoadDeploymentOfferTemplate(
		configuration.DeploymentRoutePolicyFile,
		signer,
	)
	if err != nil || !template.ContainsControlEndpoint(*endpoint) {
		return fmt.Errorf("deployment route policy rejected: %w", serviceauthority.ErrInvalid)
	}
	issuedAt := now()
	expiresAt := issuedAt.Add(*lifetime)
	offer, err := template.SignOffer(signer, issuedAt, expiresAt)
	if err != nil {
		return fmt.Errorf("sign deployment offer: %w", err)
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	reference := backupcustody.AccountAdmissionReference{
		Version:               backupcustody.Version,
		AccountID:             accountID,
		AdmissionID:           uuid.New(),
		ExpiresAtMilliseconds: expiresAt.UnixMilli(),
		RequestNonce:          base64.RawURLEncoding.EncodeToString(nonce),
	}
	credential, err := authority.credential(reference, configuration.DeploymentID, offer)
	if err != nil {
		return err
	}
	bootstrap := backupAccountBootstrap{
		Version:            backupcustody.Version,
		Endpoint:           *endpoint,
		AccountAdmission:   reference,
		AuthorizationToken: credential.TransportBearer(),
		DeploymentOffer:    offer,
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	// The secret-bearing representation is released only through this explicit
	// local CLI seam. Generic JSON formatting of backupAccountBootstrap fails.
	return encoder.Encode(backupAccountBootstrapCLIWire(bootstrap))
}
