package httpapi

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/rendezvous"
)

func TestRelayAuthorityRotationAndAdmissionCollection(t *testing.T) {
	operatorToken := relayTestToken(220)
	server, err := NewWithRelay(
		rendezvous.NewMemoryStore(),
		relay.NewMemoryStore(),
		nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		operatorToken,
	)
	if err != nil {
		t.Fatal(err)
	}
	nowMilliseconds := int64(1_000)
	server.now = func() time.Time { return time.UnixMilli(nowMilliseconds) }
	handler := server.Handler()

	created := provisionRelayTestAuthority(
		t, handler, operatorToken, nowMilliseconds, 40, 80,
	)
	basePath := "/v1/relay/tenants/" + created.Domain.TenantID.String() +
		"/domains/" + created.Domain.DomainID.String()

	newAdminToken := relayTestToken(221)
	newAdmin := relay.AdministrationCredential{
		TenantID: created.Domain.TenantID,
		DomainID: created.Domain.DomainID,
		Token:    newAdminToken,
	}
	newAdminDigest, err := relay.AdministrationDigest(newAdmin)
	if err != nil {
		t.Fatal(err)
	}
	adminRotationID := uuid.New()
	adminRotationPath := basePath + "/administration/credential-rotations/" +
		adminRotationID.String()
	adminRotationBody := map[string]string{"authorizationDigest": newAdminDigest}
	rotateAdmin := performRelayJSON(
		t,
		handler,
		http.MethodPost,
		adminRotationPath,
		adminRotationBody,
		created.AdministrationCredential.AuthorizationToken,
		uuid.Nil,
	)
	requireStatus(t, rotateAdmin, http.StatusCreated)
	var rotatedAdmin relay.CredentialRotationResult
	if err := json.NewDecoder(rotateAdmin.Body).Decode(&rotatedAdmin); err != nil {
		t.Fatal(err)
	}
	_ = rotateAdmin.Body.Close()
	if rotatedAdmin.Acceptance != relay.AcceptanceAccepted ||
		rotatedAdmin.RotationID != adminRotationID {
		t.Fatalf("unexpected admin rotation: %+v", rotatedAdmin)
	}
	for _, token := range []string{
		created.AdministrationCredential.AuthorizationToken,
		newAdminToken,
	} {
		retry := performRelayJSON(
			t,
			handler,
			http.MethodPost,
			adminRotationPath,
			adminRotationBody,
			token,
			uuid.Nil,
		)
		requireStatus(t, retry, http.StatusOK)
	}
	oldAdminBlocked := performRelayJSON(
		t,
		handler,
		http.MethodPost,
		basePath+"/admissions/collection",
		nil,
		created.AdministrationCredential.AuthorizationToken,
		uuid.Nil,
	)
	requireStatus(t, oldAdminBlocked, http.StatusUnauthorized)

	newMemberToken := relayTestToken(222)
	newMember := relay.Credential{
		TenantID: created.Domain.TenantID,
		DomainID: created.Domain.DomainID,
		MemberID: created.Member.MemberID,
		Token:    newMemberToken,
	}
	newMemberDigest, err := relay.AuthorizationDigest(newMember)
	if err != nil {
		t.Fatal(err)
	}
	memberRotationID := uuid.New()
	memberRotationPath := basePath + "/members/" + created.Member.MemberID.String() +
		"/credential-rotations/" + memberRotationID.String()
	memberRotationBody := map[string]string{"authorizationDigest": newMemberDigest}
	rotateMember := performRelayJSON(
		t,
		handler,
		http.MethodPost,
		memberRotationPath,
		memberRotationBody,
		created.MemberCredential.AuthorizationToken,
		created.Member.MemberID,
	)
	requireStatus(t, rotateMember, http.StatusCreated)
	for _, token := range []string{
		created.MemberCredential.AuthorizationToken,
		newMemberToken,
	} {
		retry := performRelayJSON(
			t,
			handler,
			http.MethodPost,
			memberRotationPath,
			memberRotationBody,
			token,
			created.Member.MemberID,
		)
		requireStatus(t, retry, http.StatusOK)
	}
	oldMemberBlocked := performRelayJSON(
		t,
		handler,
		http.MethodGet,
		basePath+"/messages",
		nil,
		created.MemberCredential.AuthorizationToken,
		created.Member.MemberID,
	)
	requireStatus(t, oldMemberBlocked, http.StatusUnauthorized)
	newMemberAuthorized := performRelayJSON(
		t,
		handler,
		http.MethodGet,
		basePath+"/messages",
		nil,
		newMemberToken,
		created.Member.MemberID,
	)
	requireStatus(t, newMemberAuthorized, http.StatusOK)

	reuseOldAdmin := relay.AdministrationCredential{
		TenantID: created.Domain.TenantID,
		DomainID: created.Domain.DomainID,
		Token:    created.AdministrationCredential.AuthorizationToken,
	}
	oldAdminDigest, err := relay.AdministrationDigest(reuseOldAdmin)
	if err != nil {
		t.Fatal(err)
	}
	reuse := performRelayJSON(
		t,
		handler,
		http.MethodPost,
		basePath+"/administration/credential-rotations/"+uuid.New().String(),
		map[string]string{"authorizationDigest": oldAdminDigest},
		newAdminToken,
		uuid.Nil,
	)
	requireStatus(t, reuse, http.StatusConflict)

	nowMilliseconds = 2_000
	admissionCredential := relay.AdmissionCredential{
		TenantID:    created.Domain.TenantID,
		DomainID:    created.Domain.DomainID,
		AdmissionID: uuid.New(),
		Token:       relayTestToken(223),
	}
	admissionDigest, err := relay.AdmissionAuthorizationDigest(admissionCredential)
	if err != nil {
		t.Fatal(err)
	}
	createAdmission := performRelayJSON(
		t,
		handler,
		http.MethodPost,
		basePath+"/admissions",
		map[string]any{
			"subscriptionID":        created.SubscriptionID,
			"admissionID":           admissionCredential.AdmissionID,
			"authorizationDigest":   admissionDigest,
			"capabilities":          []string{string(relay.CapabilityFetchMessage)},
			"expiresAtMilliseconds": int64(3_000),
		},
		newAdminToken,
		uuid.Nil,
	)
	requireStatus(t, createAdmission, http.StatusCreated)
	nowMilliseconds = 2_100
	revokeAdmission := performRelayJSON(
		t,
		handler,
		http.MethodPost,
		basePath+"/admissions/"+admissionCredential.AdmissionID.String()+"/revocation",
		nil,
		newAdminToken,
		uuid.Nil,
	)
	requireStatus(t, revokeAdmission, http.StatusOK)
	nowMilliseconds = 2_100 + relay.AdmissionRecoveryWindowMilliseconds - 1
	earlyCollection := performRelayJSON(
		t,
		handler,
		http.MethodPost,
		basePath+"/admissions/collection",
		nil,
		newAdminToken,
		uuid.Nil,
	)
	requireStatus(t, earlyCollection, http.StatusOK)
	var early relay.AdmissionCollectionResult
	if err := json.NewDecoder(earlyCollection.Body).Decode(&early); err != nil {
		t.Fatal(err)
	}
	_ = earlyCollection.Body.Close()
	if early.CollectedCount != 0 {
		t.Fatalf("admission collected before retry window elapsed: %+v", early)
	}
	nowMilliseconds++
	collection := performRelayJSON(
		t,
		handler,
		http.MethodPost,
		basePath+"/admissions/collection",
		nil,
		newAdminToken,
		uuid.Nil,
	)
	requireStatus(t, collection, http.StatusOK)
	var collected relay.AdmissionCollectionResult
	if err := json.NewDecoder(collection.Body).Decode(&collected); err != nil {
		t.Fatal(err)
	}
	_ = collection.Body.Close()
	if collected.CollectedCount != 1 || collected.HasMore {
		t.Fatalf("unexpected admission collection: %+v", collected)
	}
}
