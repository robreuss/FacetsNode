package sharedspaces

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

const provisioningBootstrapURLPrefix = "facets://shared-spaces/bootstrap#"

// ProvisioningBootstrap is the short-lived material an operator transfers to
// Facets so the client can create exactly one Shared Space. It contains no
// global operator credential, Space content key, or participant private key.
type ProvisioningBootstrap struct {
	Version                         int    `json:"version"`
	ServiceEndpoint                 string `json:"serviceEndpoint"`
	ProvisioningAdmissionCredential struct {
		AdmissionID        uuid.UUID `json:"admissionID"`
		AuthorizationToken string    `json:"authorizationToken"`
	} `json:"provisioningAdmissionCredential"`
	DeploymentOffer       serviceauthority.DeploymentOffer `json:"deploymentOffer"`
	ExpiresAtMilliseconds int64                            `json:"expiresAtMilliseconds"`
}

func (bootstrap ProvisioningBootstrap) Validate() error {
	credential := ProvisioningAdmissionCredential{
		AdmissionID: bootstrap.ProvisioningAdmissionCredential.AdmissionID,
		Token:       bootstrap.ProvisioningAdmissionCredential.AuthorizationToken,
	}
	if bootstrap.Version != SchemaVersion ||
		bootstrap.ExpiresAtMilliseconds < 0 {
		return fmt.Errorf("Shared Space provisioning bootstrap fields are invalid")
	}
	if _, err := ProvisioningAdmissionAuthorizationDigest(credential); err != nil {
		return err
	}
	endpoint, err := normalizeProvisioningServiceEndpoint(
		bootstrap.ServiceEndpoint,
	)
	if err != nil {
		return err
	}
	if endpoint != bootstrap.ServiceEndpoint {
		return fmt.Errorf("Shared Space service endpoint is not canonical")
	}
	offer, err := bootstrap.DeploymentOffer.VerifiedPayload(nil)
	if err != nil || offer.ExpiresAtMilliseconds != bootstrap.ExpiresAtMilliseconds {
		return fmt.Errorf("Shared Space deployment offer is invalid")
	}
	template := serviceauthority.DeploymentOfferTemplate{
		Deployment: offer.Deployment, TransportPolicy: offer.TransportPolicy,
		Version: serviceauthority.SchemaVersion,
	}
	if !template.ContainsControlEndpoint(bootstrap.ServiceEndpoint) {
		return fmt.Errorf("Shared Space service endpoint is not an offered control route")
	}
	return nil
}

func (bootstrap ProvisioningBootstrap) SetupURL() (string, error) {
	if err := bootstrap.Validate(); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(bootstrap)
	if err != nil {
		return "", fmt.Errorf("encode Shared Space provisioning bootstrap: %w", err)
	}
	return provisioningBootstrapURLPrefix +
		base64.RawURLEncoding.EncodeToString(encoded), nil
}

type IssuedProvisioningBootstrap struct {
	Bootstrap ProvisioningBootstrap `json:"bootstrap"`
	SetupURL  string                `json:"setupURL"`
}

type ProvisioningAdmissionIssuer interface {
	CreateProvisioningAdmission(
		context.Context,
		ProvisioningAdmission,
		int64,
	) (ProvisioningAdmissionCreateResult, error)
}

func IssueProvisioningBootstrap(
	ctx context.Context,
	store ProvisioningAdmissionIssuer,
	serviceEndpoint string,
	deploymentOffer serviceauthority.DeploymentOffer,
	lifetime time.Duration,
	now time.Time,
	random io.Reader,
) (IssuedProvisioningBootstrap, error) {
	endpoint, err := normalizeProvisioningServiceEndpoint(serviceEndpoint)
	if err != nil {
		return IssuedProvisioningBootstrap{}, err
	}
	offer, err := deploymentOffer.VerifiedPayload(nil)
	if err != nil {
		return IssuedProvisioningBootstrap{}, fmt.Errorf("deployment offer rejected: %w", err)
	}
	template := serviceauthority.DeploymentOfferTemplate{
		Deployment: offer.Deployment, TransportPolicy: offer.TransportPolicy,
		Version: serviceauthority.SchemaVersion,
	}
	if !template.ContainsControlEndpoint(endpoint) {
		return IssuedProvisioningBootstrap{}, fmt.Errorf("service endpoint is not an offered control route")
	}
	lifetimeMilliseconds := lifetime.Milliseconds()
	if lifetimeMilliseconds < MinimumProvisioningAdmissionLifetimeMilliseconds ||
		lifetimeMilliseconds > MaximumProvisioningAdmissionLifetimeMilliseconds {
		return IssuedProvisioningBootstrap{}, fmt.Errorf(
			"Shared Space provisioning admission lifetime must be between five minutes and seven days",
		)
	}
	if random == nil {
		random = rand.Reader
	}
	retryID, err := uuid.NewRandomFromReader(random)
	if err != nil {
		return IssuedProvisioningBootstrap{}, fmt.Errorf("generate provisioning admission retry ID: %w", err)
	}
	admissionID, err := uuid.NewRandomFromReader(random)
	if err != nil {
		return IssuedProvisioningBootstrap{}, fmt.Errorf("generate provisioning admission ID: %w", err)
	}
	tokenBytes := make([]byte, 32)
	if _, err := io.ReadFull(random, tokenBytes); err != nil {
		return IssuedProvisioningBootstrap{}, fmt.Errorf("generate provisioning admission token: %w", err)
	}
	credential := ProvisioningAdmissionCredential{
		AdmissionID: admissionID,
		Token:       base64.RawURLEncoding.EncodeToString(tokenBytes),
	}
	authorizationDigest, err := ProvisioningAdmissionAuthorizationDigest(
		credential,
	)
	if err != nil {
		return IssuedProvisioningBootstrap{}, err
	}
	nowMilliseconds := now.UnixMilli()
	if offer.IssuedAtMilliseconds != nowMilliseconds ||
		offer.ExpiresAtMilliseconds != nowMilliseconds+lifetimeMilliseconds {
		return IssuedProvisioningBootstrap{}, fmt.Errorf(
			"deployment offer lifetime does not match provisioning admission",
		)
	}
	admission := ProvisioningAdmission{
		Version: SchemaVersion, RetryID: retryID, AdmissionID: admissionID,
		AuthorizationDigest:   authorizationDigest,
		CreatedAtMilliseconds: nowMilliseconds,
		ExpiresAtMilliseconds: nowMilliseconds + lifetimeMilliseconds,
	}
	if _, err := store.CreateProvisioningAdmission(
		ctx, admission, nowMilliseconds,
	); err != nil {
		return IssuedProvisioningBootstrap{}, fmt.Errorf("persist provisioning admission: %w", err)
	}
	bootstrap := ProvisioningBootstrap{
		Version: SchemaVersion, ServiceEndpoint: endpoint,
		DeploymentOffer:       deploymentOffer,
		ExpiresAtMilliseconds: admission.ExpiresAtMilliseconds,
	}
	bootstrap.ProvisioningAdmissionCredential.AdmissionID = admissionID
	bootstrap.ProvisioningAdmissionCredential.AuthorizationToken = credential.Token
	setupURL, err := bootstrap.SetupURL()
	if err != nil {
		return IssuedProvisioningBootstrap{}, err
	}
	return IssuedProvisioningBootstrap{
		Bootstrap: bootstrap, SetupURL: setupURL,
	}, nil
}

func normalizeProvisioningServiceEndpoint(raw string) (string, error) {
	endpoint, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || endpoint.Host == "" || endpoint.User != nil ||
		endpoint.RawQuery != "" || endpoint.Fragment != "" ||
		(endpoint.Path != "" && endpoint.Path != "/") {
		return "", fmt.Errorf("Shared Space service endpoint is invalid")
	}
	if endpoint.Scheme != "https" {
		host := endpoint.Hostname()
		ip := net.ParseIP(host)
		if endpoint.Scheme != "http" ||
			!(strings.EqualFold(host, "localhost") ||
				(ip != nil && ip.IsLoopback())) {
			return "", fmt.Errorf(
				"Shared Space service endpoint must use HTTPS except on loopback",
			)
		}
	}
	endpoint.Path = ""
	return strings.TrimSuffix(endpoint.String(), "/"), nil
}
