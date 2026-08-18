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
	PublisherAccess          swiftRelayMemberAccess            `json:"publisherAccess"`
	RecipientAccess          swiftRelayMemberAccess            `json:"recipientAccess"`
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
		PublisherAccess: swiftRelayMemberAccess{
			Version:                  relay.SchemaVersion,
			TenantID:                 domain.Domain.TenantID,
			DomainID:                 domain.Domain.DomainID,
			MemberID:                 domain.Member.MemberID,
			RouterAuthorizationToken: domain.MemberCredential.AuthorizationToken,
			KeyEpoch:                 1,
			EncryptionKeyMaterial:    keyMaterial,
		},
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
	writeSwiftRelayLiveAccess(t, outputPath, access)
}

func randomLiveAccessMaterial(t *testing.T) string {
	t.Helper()
	material := make([]byte, 32)
	if _, err := rand.Read(material); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(material)
}

func writeSwiftRelayLiveAccess(t *testing.T, path string, access swiftRelayLiveAccess) {
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
