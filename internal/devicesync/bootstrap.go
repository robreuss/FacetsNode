package devicesync

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

const accountBootstrapURLPrefix = "facets://device-sync/bootstrap#"

// AccountBootstrap is the one-time, short-lived material a self-hosted
// operator transfers to Facets. It authorizes creation of one Device Sync
// principal; it does not contain content keys or grant content authority.
type AccountBootstrap struct {
	Version               int                              `json:"version"`
	ServiceEndpoint       string                           `json:"serviceEndpoint"`
	AdmissionID           uuid.UUID                        `json:"admissionID"`
	AuthorizationToken    string                           `json:"authorizationToken"`
	DeploymentOffer       serviceauthority.DeploymentOffer `json:"deploymentOffer"`
	ExpiresAtMilliseconds int64                            `json:"expiresAtMilliseconds"`
}

func (bootstrap AccountBootstrap) Validate() error {
	if bootstrap.Version != SchemaVersion || bootstrap.AdmissionID == uuid.Nil ||
		bootstrap.ExpiresAtMilliseconds < 0 {
		return fmt.Errorf("Device Sync bootstrap fields are invalid")
	}
	if _, err := AdmissionAuthorizationDigest(AdmissionCredential{
		AdmissionID: bootstrap.AdmissionID,
		Token:       bootstrap.AuthorizationToken,
	}); err != nil {
		return err
	}
	endpoint, err := normalizeServiceEndpoint(bootstrap.ServiceEndpoint)
	if err != nil {
		return err
	}
	if endpoint != bootstrap.ServiceEndpoint {
		return fmt.Errorf("Device Sync service endpoint is not canonical")
	}
	offer, err := bootstrap.DeploymentOffer.VerifiedPayload(nil)
	if err != nil || offer.ExpiresAtMilliseconds != bootstrap.ExpiresAtMilliseconds {
		return fmt.Errorf("Device Sync deployment offer is invalid")
	}
	template := serviceauthority.DeploymentOfferTemplate{
		Deployment:      offer.Deployment,
		TransportPolicy: offer.TransportPolicy,
		Version:         serviceauthority.SchemaVersion,
	}
	if !template.ContainsControlEndpoint(bootstrap.ServiceEndpoint) {
		return fmt.Errorf("Device Sync service endpoint is not an offered control route")
	}
	return nil
}

func (bootstrap AccountBootstrap) SetupURL() (string, error) {
	if err := bootstrap.Validate(); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(bootstrap)
	if err != nil {
		return "", fmt.Errorf("encode Device Sync bootstrap: %w", err)
	}
	return accountBootstrapURLPrefix + base64.RawURLEncoding.EncodeToString(encoded), nil
}

type IssuedAccountBootstrap struct {
	Bootstrap AccountBootstrap `json:"bootstrap"`
	SetupURL  string           `json:"setupURL"`
}

type AccountAdmissionIssuer interface {
	CreateAccountAdmission(context.Context, AccountAdmission, int64) (AdmissionCreateResult, error)
}

func IssueAccountBootstrap(
	ctx context.Context,
	store AccountAdmissionIssuer,
	serviceEndpoint string,
	deploymentOffer serviceauthority.DeploymentOffer,
	lifetime time.Duration,
	now time.Time,
	random io.Reader,
) (IssuedAccountBootstrap, error) {
	endpoint, err := normalizeServiceEndpoint(serviceEndpoint)
	if err != nil {
		return IssuedAccountBootstrap{}, err
	}
	offer, err := deploymentOffer.VerifiedPayload(nil)
	if err != nil {
		return IssuedAccountBootstrap{}, fmt.Errorf("deployment offer rejected: %w", err)
	}
	template := serviceauthority.DeploymentOfferTemplate{
		Deployment:      offer.Deployment,
		TransportPolicy: offer.TransportPolicy,
		Version:         serviceauthority.SchemaVersion,
	}
	if !template.ContainsControlEndpoint(endpoint) {
		return IssuedAccountBootstrap{}, fmt.Errorf("service endpoint is not an offered control route")
	}
	lifetimeMilliseconds := lifetime.Milliseconds()
	if lifetimeMilliseconds < MinimumAdmissionLifetimeMilliseconds ||
		lifetimeMilliseconds > MaximumAdmissionLifetimeMilliseconds {
		return IssuedAccountBootstrap{}, fmt.Errorf("account admission lifetime must be between five minutes and seven days")
	}
	if random == nil {
		random = rand.Reader
	}
	retryID, err := uuid.NewRandomFromReader(random)
	if err != nil {
		return IssuedAccountBootstrap{}, fmt.Errorf("generate account admission retry ID: %w", err)
	}
	admissionID, err := uuid.NewRandomFromReader(random)
	if err != nil {
		return IssuedAccountBootstrap{}, fmt.Errorf("generate account admission ID: %w", err)
	}
	tokenBytes := make([]byte, 32)
	if _, err := io.ReadFull(random, tokenBytes); err != nil {
		return IssuedAccountBootstrap{}, fmt.Errorf("generate account admission token: %w", err)
	}
	credential := AdmissionCredential{
		AdmissionID: admissionID,
		Token:       base64.RawURLEncoding.EncodeToString(tokenBytes),
	}
	digest, err := AdmissionAuthorizationDigest(credential)
	if err != nil {
		return IssuedAccountBootstrap{}, err
	}
	nowMilliseconds := now.UnixMilli()
	if offer.IssuedAtMilliseconds != nowMilliseconds ||
		offer.ExpiresAtMilliseconds != nowMilliseconds+lifetimeMilliseconds {
		return IssuedAccountBootstrap{}, fmt.Errorf("deployment offer lifetime does not match account admission")
	}
	admission := AccountAdmission{
		Version: SchemaVersion, RetryID: retryID, AdmissionID: admissionID,
		AuthorizationDigest: digest, CreatedAtMilliseconds: nowMilliseconds,
		ExpiresAtMilliseconds: nowMilliseconds + lifetimeMilliseconds,
	}
	if _, err := store.CreateAccountAdmission(ctx, admission, nowMilliseconds); err != nil {
		return IssuedAccountBootstrap{}, fmt.Errorf("persist account admission: %w", err)
	}
	bootstrap := AccountBootstrap{
		Version: SchemaVersion, ServiceEndpoint: endpoint,
		AdmissionID: admissionID, AuthorizationToken: credential.Token,
		DeploymentOffer:       deploymentOffer,
		ExpiresAtMilliseconds: admission.ExpiresAtMilliseconds,
	}
	setupURL, err := bootstrap.SetupURL()
	if err != nil {
		return IssuedAccountBootstrap{}, err
	}
	return IssuedAccountBootstrap{Bootstrap: bootstrap, SetupURL: setupURL}, nil
}

func normalizeServiceEndpoint(raw string) (string, error) {
	endpoint, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || endpoint.Host == "" || endpoint.User != nil ||
		endpoint.RawQuery != "" || endpoint.Fragment != "" ||
		(endpoint.Path != "" && endpoint.Path != "/") {
		return "", fmt.Errorf("Device Sync service endpoint is invalid")
	}
	if endpoint.Scheme != "https" {
		host := endpoint.Hostname()
		ip := net.ParseIP(host)
		if endpoint.Scheme != "http" ||
			!(strings.EqualFold(host, "localhost") || (ip != nil && ip.IsLoopback())) {
			return "", fmt.Errorf("Device Sync service endpoint must use HTTPS except on loopback")
		}
	}
	endpoint.Path = ""
	return strings.TrimSuffix(endpoint.String(), "/"), nil
}
