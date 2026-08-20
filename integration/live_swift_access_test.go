package integration_test

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/devicesync"
	"github.com/robreuss/FacetsNode/internal/relay"
)

type swiftRelayMemberAccess struct {
	Version                  int       `json:"version"`
	TenantID                 uuid.UUID `json:"tenantID"`
	DomainID                 uuid.UUID `json:"domainID"`
	MemberID                 uuid.UUID `json:"memberID"`
	RouterAuthorizationToken string    `json:"routerAuthorizationToken"`
	KeyEpoch                 int       `json:"keyEpoch"`
	EncryptionKeyMaterial    string    `json:"encryptionKeyMaterial"`
}

type swiftRelayLiveAccess struct {
	AdministrationCredential liveRelayAdministrationCredential `json:"administrationCredential"`
	PublisherSubscriptionID  uuid.UUID                         `json:"publisherSubscriptionID"`
	PublisherAccess          swiftRelayMemberAccess            `json:"publisherAccess"`
	RecipientSubscriptionID  uuid.UUID                         `json:"recipientSubscriptionID"`
	RecipientAccess          swiftRelayMemberAccess            `json:"recipientAccess"`
}

// swiftDeviceSyncEnrollmentLiveAccess is intentionally restricted to the
// transport authority held by an already-enrolled sponsor device. It carries
// neither an account-admission credential nor any candidate private key. The
// Swift opt-in live test uses it to exercise the public PIN mailbox and the
// subsequent device-admission claim against a real service.
type swiftDeviceSyncEnrollmentLiveAccess struct {
	ServiceEndpoint                 string                            `json:"serviceEndpoint"`
	PrincipalID                     uuid.UUID                         `json:"principalID"`
	PrincipalAuthorizationToken     string                            `json:"principalAuthorizationToken"`
	SponsorDeviceID                 uuid.UUID                         `json:"sponsorDeviceID"`
	ControlAdministrationCredential liveRelayAdministrationCredential `json:"controlAdministrationCredential"`
	ControlSubscriptionID           uuid.UUID                         `json:"controlSubscriptionID"`
	ControlMemberAccess             swiftRelayMemberAccess            `json:"controlMemberAccess"`
	ControlEncryptionKeyMaterial    string                            `json:"controlEncryptionKeyMaterial"`
	CreatedAtMilliseconds           int64                             `json:"createdAtMilliseconds"`
}

// TestLiveProvisionSwiftRelayAccess creates a fresh two-subscription domain and
// writes the bearer/key material only to an explicitly requested, mode-0600
// path outside the source tree. It is an operations gate for the Swift live
// contract test, not part of the ordinary integration suite.
func TestLiveProvisionSwiftRelayAccess(t *testing.T) {
	baseURL := strings.TrimRight(os.Getenv("FACETS_SERVER_TEST_BASE_URL"), "/")
	operatorToken := os.Getenv("FACETS_SERVER_TEST_OPERATOR_TOKEN")
	outputPath := os.Getenv("FACETS_SERVER_TEST_SWIFT_ACCESS_OUTPUT_PATH")
	if baseURL == "" || operatorToken == "" || outputPath == "" {
		t.Skip("FACETS_SERVER_TEST_BASE_URL, FACETS_SERVER_TEST_OPERATOR_TOKEN, and FACETS_SERVER_TEST_SWIFT_ACCESS_OUTPUT_PATH are required")
	}
	validateHighVolumeStatePath(t, outputPath)
	client := &http.Client{Timeout: 15 * time.Second}
	domain := provisionLiveRelayDomain(t, client, baseURL, operatorToken)
	basePath := fmt.Sprintf(
		"%s/v1/relay/tenants/%s/domains/%s",
		baseURL, domain.Domain.TenantID, domain.Domain.DomainID,
	)
	recipient := admitLiveRelayRecipient(t, client, basePath, domain, 48, 80)
	keyMaterial := randomLiveAccessMaterial(t)
	access := swiftRelayLiveAccess{
		AdministrationCredential: liveRelayAdministrationCredential{
			TenantID:           domain.Domain.TenantID,
			DomainID:           domain.Domain.DomainID,
			AuthorizationToken: domain.AdministrationCredential.AuthorizationToken,
		},
		PublisherSubscriptionID: domain.SubscriptionID,
		PublisherAccess: swiftRelayMemberAccess{
			Version:                  relay.SchemaVersion,
			TenantID:                 domain.Domain.TenantID,
			DomainID:                 domain.Domain.DomainID,
			MemberID:                 domain.Member.MemberID,
			RouterAuthorizationToken: domain.MemberCredential.AuthorizationToken,
			KeyEpoch:                 1,
			EncryptionKeyMaterial:    keyMaterial,
		},
		RecipientSubscriptionID: recipient.SubscriptionID,
		RecipientAccess: swiftRelayMemberAccess{
			Version:                  relay.SchemaVersion,
			TenantID:                 domain.Domain.TenantID,
			DomainID:                 domain.Domain.DomainID,
			MemberID:                 recipient.Credential.MemberID,
			RouterAuthorizationToken: recipient.Credential.Token,
			KeyEpoch:                 1,
			EncryptionKeyMaterial:    keyMaterial,
		},
	}
	writeSwiftLiveAccess(t, outputPath, access)
}

// TestLiveProvisionSwiftDeviceSyncEnrollmentAccess creates one new Device
// Sync principal through the public service API and writes just enough
// sponsor-device authority for Swift to exercise its real enrollment
// mailbox/device-admission client. It is explicitly opt-in because the
// descriptor contains bearer credentials and is removed by the Swift test
// after it has been decoded.
func TestLiveProvisionSwiftDeviceSyncEnrollmentAccess(t *testing.T) {
	baseURL := strings.TrimRight(os.Getenv("FACETS_SERVER_TEST_BASE_URL"), "/")
	operatorToken := os.Getenv("FACETS_SERVER_TEST_OPERATOR_TOKEN")
	outputPath := os.Getenv("FACETS_SERVER_TEST_SWIFT_ENROLLMENT_ACCESS_OUTPUT_PATH")
	if baseURL == "" || operatorToken == "" || outputPath == "" {
		t.Skip("FACETS_SERVER_TEST_BASE_URL, FACETS_SERVER_TEST_OPERATOR_TOKEN, and FACETS_SERVER_TEST_SWIFT_ENROLLMENT_ACCESS_OUTPUT_PATH are required")
	}
	validateHighVolumeStatePath(t, outputPath)

	client := &http.Client{Timeout: 15 * time.Second}
	now := time.Now().UnixMilli()
	expiresAt := now + int64(time.Hour/time.Millisecond)
	accountAdmission := liveDeviceSyncAdmissionCredential{
		AdmissionID: uuid.New(), AuthorizationToken: encodedBytes(208),
	}
	requireStatusAndClose(t, requestRelayJSON(
		t, client, http.MethodPost, baseURL+"/v1/device-sync/account-admissions",
		liveDeviceSyncAdmissionCreateInput{
			Version: devicesync.SchemaVersion, RetryID: uuid.New(),
			AdmissionCredential: accountAdmission, ExpiresAtMilliseconds: expiresAt,
		},
		operatorToken, uuid.Nil,
	), http.StatusCreated)

	controlDomain := newLiveRelayDomainProvisioningRequest(now)
	principalID := controlDomain.AdministrationCredential.TenantID
	sponsorDeviceID := controlDomain.MemberCredential.MemberID
	principalAuthorizationToken := encodedBytes(216)
	principalResultResponse := requestRelayJSON(
		t, client, http.MethodPost,
		baseURL+"/v1/device-sync/account-admissions/"+
			accountAdmission.AdmissionID.String()+"/claim",
		liveDeviceSyncPrincipalClaimInput{
			Version: devicesync.SchemaVersion, RetryID: uuid.New(),
			PrincipalID: principalID, InitialDeviceID: sponsorDeviceID,
			TenantProvisioning: liveRelayTenantProvisioningRequest{
				Version: relay.SchemaVersion, RetryID: uuid.New(),
				TenantProvisioningCredential: liveRelayTenantCredential{
					TenantID: principalID, AuthorizationToken: principalAuthorizationToken,
				},
				InitialDomain: controlDomain,
			},
		},
		accountAdmission.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, principalResultResponse, http.StatusCreated)
	var principalResult devicesync.PrincipalProvisioningResult
	decodeLiveJSON(t, principalResultResponse, &principalResult)
	if principalResult.PrincipalID != principalID || principalResult.DeviceID != sponsorDeviceID {
		t.Fatalf("unexpected Swift enrollment principal result: %+v", principalResult)
	}

	access := swiftDeviceSyncEnrollmentLiveAccess{
		ServiceEndpoint:             baseURL,
		PrincipalID:                 principalID,
		PrincipalAuthorizationToken: principalAuthorizationToken,
		SponsorDeviceID:             sponsorDeviceID,
		ControlAdministrationCredential: liveRelayAdministrationCredential{
			TenantID: principalID, DomainID: controlDomain.AdministrationCredential.DomainID,
			AuthorizationToken: controlDomain.AdministrationCredential.AuthorizationToken,
		},
		ControlSubscriptionID: controlDomain.SubscriptionID,
		ControlMemberAccess: swiftRelayMemberAccess{
			Version:                  relay.SchemaVersion,
			TenantID:                 principalID,
			DomainID:                 controlDomain.AdministrationCredential.DomainID,
			MemberID:                 sponsorDeviceID,
			RouterAuthorizationToken: controlDomain.MemberCredential.AuthorizationToken,
			KeyEpoch:                 1,
			EncryptionKeyMaterial:    randomLiveAccessMaterial(t),
		},
		ControlEncryptionKeyMaterial: randomLiveAccessMaterial(t),
		CreatedAtMilliseconds:        now,
	}
	writeSwiftLiveAccess(t, outputPath, access)
}

func randomLiveAccessMaterial(t *testing.T) string {
	t.Helper()
	material := make([]byte, 32)
	if _, err := rand.Read(material); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(material)
}

func writeSwiftLiveAccess(t *testing.T, path string, access any) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatalf("create Swift live access without overwriting an existing file: %v", err)
	}
	succeeded := false
	defer func() {
		_ = file.Close()
		if !succeeded {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		t.Fatal(err)
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(access); err != nil {
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	succeeded = true
}
