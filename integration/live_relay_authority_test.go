package integration_test

import (
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

// TestLiveReplicaRelayAuthorityLifecycle crosses the real HTTP and PostgreSQL
// boundaries while proving that credential replacement is atomic and safely
// retryable after response loss. The relay only receives authorization digests;
// client tokens remain client-side bearer material.
func TestLiveReplicaRelayAuthorityLifecycle(t *testing.T) {
	baseURL := strings.TrimRight(os.Getenv("FACETS_SERVER_TEST_BASE_URL"), "/")
	operatorToken := os.Getenv("FACETS_SERVER_TEST_OPERATOR_TOKEN")
	if baseURL == "" || operatorToken == "" {
		t.Skip("FACETS_SERVER_TEST_BASE_URL and FACETS_SERVER_TEST_OPERATOR_TOKEN are required")
	}
	client := &http.Client{Timeout: 15 * time.Second}
	domain := provisionLiveRelayDomain(t, client, baseURL, operatorToken)
	basePath := fmt.Sprintf(
		"%s/v1/relay/tenants/%s/domains/%s",
		baseURL,
		domain.Domain.TenantID,
		domain.Domain.DomainID,
	)

	oldAdminToken := domain.AdministrationCredential.AuthorizationToken
	newAdmin := relay.AdministrationCredential{
		TenantID: domain.Domain.TenantID,
		DomainID: domain.Domain.DomainID,
		Token:    encodedBytes(176),
	}
	newAdminDigest, err := relay.AdministrationDigest(newAdmin)
	if err != nil {
		t.Fatal(err)
	}
	adminRotationID := uuid.New()
	adminRotationURL := basePath + "/administration/credential-rotations/" +
		adminRotationID.String()
	adminRotationBody := map[string]string{"authorizationDigest": newAdminDigest}
	adminRotation := requestRelayJSON(
		t, client, http.MethodPost, adminRotationURL, adminRotationBody,
		oldAdminToken, uuid.Nil,
	)
	requireStatus(t, adminRotation, http.StatusCreated)
	var adminResult relay.CredentialRotationResult
	if err := json.NewDecoder(adminRotation.Body).Decode(&adminResult); err != nil {
		t.Fatal(err)
	}
	_ = adminRotation.Body.Close()
	if adminResult.Acceptance != relay.AcceptanceAccepted ||
		adminResult.RotationID != adminRotationID {
		t.Fatalf("live admin rotation=%+v", adminResult)
	}
	for _, token := range []string{oldAdminToken, newAdmin.Token} {
		retry := requestRelayJSON(
			t, client, http.MethodPost, adminRotationURL, adminRotationBody,
			token, uuid.Nil,
		)
		requireStatus(t, retry, http.StatusOK)
		var result relay.CredentialRotationResult
		if err := json.NewDecoder(retry.Body).Decode(&result); err != nil {
			t.Fatal(err)
		}
		_ = retry.Body.Close()
		if result.Acceptance != relay.AcceptanceDuplicate ||
			result.RotatedAtMilliseconds != adminResult.RotatedAtMilliseconds {
			t.Fatalf("live admin rotation retry=%+v", result)
		}
	}
	requireStatusAndClose(t, requestRelayJSON(
		t, client, http.MethodPost, basePath+"/admissions/collection", nil,
		oldAdminToken, uuid.Nil,
	), http.StatusUnauthorized)
	collection := requestRelayJSON(
		t, client, http.MethodPost, basePath+"/admissions/collection", nil,
		newAdmin.Token, uuid.Nil,
	)
	requireStatus(t, collection, http.StatusOK)
	var collectionResult relay.AdmissionCollectionResult
	if err := json.NewDecoder(collection.Body).Decode(&collectionResult); err != nil {
		t.Fatal(err)
	}
	_ = collection.Body.Close()
	if collectionResult.CollectedCount != 0 || collectionResult.HasMore {
		t.Fatalf("new live domain collected admissions: %+v", collectionResult)
	}

	oldMember := relay.Credential{
		TenantID: domain.Domain.TenantID,
		DomainID: domain.Domain.DomainID,
		MemberID: domain.Member.MemberID,
		Token:    domain.MemberCredential.AuthorizationToken,
	}
	newMember := oldMember
	newMember.Token = encodedBytes(208)
	newMemberDigest, err := relay.AuthorizationDigest(newMember)
	if err != nil {
		t.Fatal(err)
	}
	memberRotationID := uuid.New()
	memberRotationURL := basePath + "/members/" + oldMember.MemberID.String() +
		"/credential-rotations/" + memberRotationID.String()
	memberRotationBody := map[string]string{"authorizationDigest": newMemberDigest}
	memberRotation := requestRelayJSON(
		t, client, http.MethodPost, memberRotationURL, memberRotationBody,
		oldMember.Token, oldMember.MemberID,
	)
	requireStatus(t, memberRotation, http.StatusCreated)
	var memberResult relay.CredentialRotationResult
	if err := json.NewDecoder(memberRotation.Body).Decode(&memberResult); err != nil {
		t.Fatal(err)
	}
	_ = memberRotation.Body.Close()
	if memberResult.Acceptance != relay.AcceptanceAccepted ||
		memberResult.RotationID != memberRotationID {
		t.Fatalf("live member rotation=%+v", memberResult)
	}
	for _, credential := range []relay.Credential{oldMember, newMember} {
		retry := requestRelayJSON(
			t, client, http.MethodPost, memberRotationURL, memberRotationBody,
			credential.Token, credential.MemberID,
		)
		requireStatus(t, retry, http.StatusOK)
		var result relay.CredentialRotationResult
		if err := json.NewDecoder(retry.Body).Decode(&result); err != nil {
			t.Fatal(err)
		}
		_ = retry.Body.Close()
		if result.Acceptance != relay.AcceptanceDuplicate ||
			result.RotatedAtMilliseconds != memberResult.RotatedAtMilliseconds {
			t.Fatalf("live member rotation retry=%+v", result)
		}
	}
	requireStatusAndClose(t, requestRelayJSON(
		t, client, http.MethodGet, basePath+"/messages", nil,
		oldMember.Token, oldMember.MemberID,
	), http.StatusUnauthorized)
	requireStatusAndClose(t, requestRelayJSON(
		t, client, http.MethodGet, basePath+"/messages", nil,
		newMember.Token, newMember.MemberID,
	), http.StatusOK)

	oldAdmin := relay.AdministrationCredential{
		TenantID: domain.Domain.TenantID,
		DomainID: domain.Domain.DomainID,
		Token:    oldAdminToken,
	}
	oldAdminDigest, err := relay.AdministrationDigest(oldAdmin)
	if err != nil {
		t.Fatal(err)
	}
	requireStatusAndClose(t, requestRelayJSON(
		t,
		client,
		http.MethodPost,
		basePath+"/administration/credential-rotations/"+uuid.New().String(),
		map[string]string{"authorizationDigest": oldAdminDigest},
		newAdmin.Token,
		uuid.Nil,
	), http.StatusConflict)
}
