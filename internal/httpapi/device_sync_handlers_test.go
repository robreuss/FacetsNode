package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/devicesync"
	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/rendezvous"
)

func TestDeviceSyncAccountAdmissionClaimsPrincipalExactlyOnce(t *testing.T) {
	operatorToken := relayTestToken(201)
	relayStore := relay.NewMemoryStore()
	server := newDeviceSyncTestServer(t, relayStore, operatorToken, 1_000)
	handler := server.Handler()

	credential := deviceSyncAdmissionCredential{
		AdmissionID:        uuid.New(),
		AuthorizationToken: relayTestToken(202),
	}
	admission := deviceSyncAdmissionCreateInput{
		Version:               devicesync.SchemaVersion,
		RetryID:               uuid.New(),
		AdmissionCredential:   credential,
		ExpiresAtMilliseconds: 1_000 + devicesync.MinimumAdmissionLifetimeMilliseconds,
	}
	wrongOperator := performRelayJSON(
		t, handler, http.MethodPost, "/v1/device-sync/account-admissions",
		admission, relayTestToken(203), uuid.Nil,
	)
	requireStatus(t, wrongOperator, http.StatusUnauthorized)
	_ = wrongOperator.Body.Close()

	created := performRelayJSON(
		t, handler, http.MethodPost, "/v1/device-sync/account-admissions",
		admission, operatorToken, uuid.Nil,
	)
	requireStatus(t, created, http.StatusCreated)
	var createdResult devicesync.AdmissionCreateResult
	if err := json.NewDecoder(created.Body).Decode(&createdResult); err != nil {
		t.Fatal(err)
	}
	_ = created.Body.Close()
	if createdResult.Acceptance != relay.AcceptanceAccepted ||
		createdResult.Admission.AdmissionID != credential.AdmissionID ||
		createdResult.Admission.AuthorizationDigest == "" {
		t.Fatalf("unexpected admission result: %+v", createdResult)
	}

	retry := performRelayJSON(
		t, handler, http.MethodPost, "/v1/device-sync/account-admissions",
		admission, operatorToken, uuid.Nil,
	)
	requireStatus(t, retry, http.StatusOK)
	var retryResult devicesync.AdmissionCreateResult
	if err := json.NewDecoder(retry.Body).Decode(&retryResult); err != nil {
		t.Fatal(err)
	}
	_ = retry.Body.Close()
	if retryResult.Acceptance != relay.AcceptanceDuplicate ||
		retryResult.Admission.AuthorizationDigest != createdResult.Admission.AuthorizationDigest {
		t.Fatalf("admission retry changed authority: %+v", retryResult)
	}

	controlDomain := newRelayDomainProvisioningRequest(1_000, 204, 205)
	claim := deviceSyncPrincipalClaimInput{
		Version:         devicesync.SchemaVersion,
		RetryID:         uuid.New(),
		PrincipalID:     controlDomain.AdministrationCredential.TenantID,
		InitialDeviceID: controlDomain.MemberCredential.MemberID,
		TenantProvisioning: newRelayTenantProvisioningRequest(
			controlDomain, relayTestToken(206),
		),
	}
	claimPath := "/v1/device-sync/account-admissions/" + credential.AdmissionID.String() + "/claim"
	claimed := performRelayJSON(
		t, handler, http.MethodPost, claimPath, claim,
		credential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, claimed, http.StatusCreated)
	var claimedResult devicesync.PrincipalProvisioningResult
	if err := json.NewDecoder(claimed.Body).Decode(&claimedResult); err != nil {
		t.Fatal(err)
	}
	_ = claimed.Body.Close()
	if claimedResult.Acceptance != relay.AcceptanceAccepted ||
		claimedResult.PrincipalID != claim.PrincipalID ||
		claimedResult.DeviceID != claim.InitialDeviceID ||
		claimedResult.Relay.InitialDomain.DomainID != controlDomain.AdministrationCredential.DomainID {
		t.Fatalf("unexpected principal claim: %+v", claimedResult)
	}

	claimRetry := performRelayJSON(
		t, handler, http.MethodPost, claimPath, claim,
		credential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, claimRetry, http.StatusOK)
	var claimRetryResult devicesync.PrincipalProvisioningResult
	if err := json.NewDecoder(claimRetry.Body).Decode(&claimRetryResult); err != nil {
		t.Fatal(err)
	}
	_ = claimRetry.Body.Close()
	if claimRetryResult.Acceptance != relay.AcceptanceDuplicate ||
		claimRetryResult.Relay.InitialDomain.DomainID != claimedResult.Relay.InitialDomain.DomainID {
		t.Fatalf("claim retry changed authority: %+v", claimRetryResult)
	}

	changedClaim := claim
	changedClaim.RetryID = uuid.New()
	changed := performRelayJSON(
		t, handler, http.MethodPost, claimPath, changedClaim,
		credential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, changed, http.StatusConflict)
	_ = changed.Body.Close()
}

func TestDeviceSyncAccountClaimRejectsWrongAdmissionCredential(t *testing.T) {
	operatorToken := relayTestToken(211)
	relayStore := relay.NewMemoryStore()
	server := newDeviceSyncTestServer(t, relayStore, operatorToken, 2_000)
	handler := server.Handler()
	credential := deviceSyncAdmissionCredential{
		AdmissionID:        uuid.New(),
		AuthorizationToken: relayTestToken(212),
	}
	admission := deviceSyncAdmissionCreateInput{
		Version:               devicesync.SchemaVersion,
		RetryID:               uuid.New(),
		AdmissionCredential:   credential,
		ExpiresAtMilliseconds: 2_000 + devicesync.MinimumAdmissionLifetimeMilliseconds,
	}
	created := performRelayJSON(
		t, handler, http.MethodPost, "/v1/device-sync/account-admissions",
		admission, operatorToken, uuid.Nil,
	)
	requireStatus(t, created, http.StatusCreated)
	_ = created.Body.Close()

	domain := newRelayDomainProvisioningRequest(2_000, 213, 214)
	claim := deviceSyncPrincipalClaimInput{
		Version:         devicesync.SchemaVersion,
		RetryID:         uuid.New(),
		PrincipalID:     domain.AdministrationCredential.TenantID,
		InitialDeviceID: domain.MemberCredential.MemberID,
		TenantProvisioning: newRelayTenantProvisioningRequest(
			domain, relayTestToken(215),
		),
	}
	response := performRelayJSON(
		t, handler, http.MethodPost,
		"/v1/device-sync/account-admissions/"+credential.AdmissionID.String()+"/claim",
		claim, relayTestToken(216), uuid.Nil,
	)
	requireStatus(t, response, http.StatusUnauthorized)
	_ = response.Body.Close()
}

func TestDeviceSyncPrincipalAdmitsAdditionalDeviceTransportExactlyOnce(t *testing.T) {
	const now = int64(3_000)
	relayStore := relay.NewMemoryStore()
	deviceSyncStore := devicesync.NewMemoryStore(relayStore)
	domainInput := newRelayDomainProvisioningRequest(now, 231, 232)
	principalID := domainInput.AdministrationCredential.TenantID
	bootstrapDeviceSyncPrincipal(t, deviceSyncStore, domainInput, 233)
	server := newRelayTestServer(t, relayStore, relayTestToken(234))
	server.SetDeviceSyncStore(deviceSyncStore)
	server.now = func() time.Time { return time.UnixMilli(now) }
	handler := server.Handler()

	deviceID := uuid.New()
	admissionCredential := deviceSyncAdmissionCredential{
		AdmissionID: uuid.New(), AuthorizationToken: relayTestToken(235),
	}
	createInput := deviceSyncDeviceAdmissionCreateInput{
		Version: devicesync.SchemaVersion, RetryID: uuid.New(), DeviceID: deviceID,
		SubscriptionID:        domainInput.SubscriptionID,
		AdmissionCredential:   admissionCredential,
		ExpiresAtMilliseconds: now + devicesync.MinimumAdmissionLifetimeMilliseconds,
	}
	createPath := "/v1/device-sync/principals/" + principalID.String() +
		"/control-domains/" + domainInput.AdministrationCredential.DomainID.String() +
		"/device-admissions"
	wrongAdministrator := performRelayJSON(
		t, handler, http.MethodPost, createPath, createInput, relayTestToken(236), uuid.Nil,
	)
	requireStatus(t, wrongAdministrator, http.StatusUnauthorized)
	_ = wrongAdministrator.Body.Close()

	created := performRelayJSON(
		t, handler, http.MethodPost, createPath, createInput,
		domainInput.AdministrationCredential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, created, http.StatusCreated)
	var createdResult devicesync.DeviceAdmissionCreateResult
	if err := json.NewDecoder(created.Body).Decode(&createdResult); err != nil {
		t.Fatal(err)
	}
	_ = created.Body.Close()
	if createdResult.Acceptance != relay.AcceptanceAccepted ||
		createdResult.Admission.DeviceID != deviceID ||
		len(createdResult.Admission.RelayAdmission.Capabilities) != len(allRelayCapabilities) {
		t.Fatalf("unexpected device admission: %+v", createdResult)
	}

	retry := performRelayJSON(
		t, handler, http.MethodPost, createPath, createInput,
		domainInput.AdministrationCredential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, retry, http.StatusOK)
	_ = retry.Body.Close()

	memberCredential := relay.Credential{
		TenantID: principalID, DomainID: domainInput.AdministrationCredential.DomainID,
		MemberID: deviceID, Token: relayTestToken(237),
	}
	memberDigest, err := relay.AuthorizationDigest(memberCredential)
	if err != nil {
		t.Fatal(err)
	}
	claimInput := deviceSyncDeviceAdmissionClaimInput{
		Version: devicesync.SchemaVersion, DeviceID: deviceID,
		AuthorizationDigest: memberDigest,
	}
	claimPath := "/v1/device-sync/principals/" + principalID.String() +
		"/device-admissions/" + admissionCredential.AdmissionID.String() + "/claim"
	claimed := performRelayJSON(
		t, handler, http.MethodPost, claimPath, claimInput,
		admissionCredential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, claimed, http.StatusCreated)
	var claimedResult devicesync.DeviceAdmissionClaimResult
	if err := json.NewDecoder(claimed.Body).Decode(&claimedResult); err != nil {
		t.Fatal(err)
	}
	_ = claimed.Body.Close()
	if claimedResult.Acceptance != relay.AcceptanceAccepted ||
		claimedResult.DeviceID != deviceID ||
		claimedResult.Member.MemberRegistration.MemberID != deviceID {
		t.Fatalf("unexpected device claim: %+v", claimedResult)
	}

	claimRetry := performRelayJSON(
		t, handler, http.MethodPost, claimPath, claimInput,
		admissionCredential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, claimRetry, http.StatusOK)
	_ = claimRetry.Body.Close()
}

func TestDeviceSyncRoutesAreAbsentFromSharedSpacesSurface(t *testing.T) {
	operatorToken := relayTestToken(221)
	relayStore := relay.NewMemoryStore()
	server := newRelayTestServer(t, relayStore, operatorToken)
	response := performRelayJSON(
		t, server.Handler(), http.MethodPost, "/v1/device-sync/account-admissions",
		map[string]any{}, operatorToken, uuid.Nil,
	)
	requireStatus(t, response, http.StatusNotFound)
	_ = response.Body.Close()
	deviceResponse := performRelayJSON(
		t, server.Handler(), http.MethodPost,
		"/v1/device-sync/principals/"+uuid.NewString()+"/control-domains/"+uuid.NewString()+"/device-admissions",
		map[string]any{}, operatorToken, uuid.Nil,
	)
	requireStatus(t, deviceResponse, http.StatusNotFound)
	_ = deviceResponse.Body.Close()
}

func bootstrapDeviceSyncPrincipal(
	t *testing.T,
	store *devicesync.MemoryStore,
	domainInput relayDomainProvisioningRequest,
	seed byte,
) {
	t.Helper()
	tenant, controlDomain, err := relayTenantAndDomainProvisioning(
		newRelayTenantProvisioningRequest(domainInput, relayTestToken(seed)),
	)
	if err != nil {
		t.Fatal(err)
	}
	admissionCredential := devicesync.AdmissionCredential{
		AdmissionID: uuid.New(), Token: relayTestToken(seed + 1),
	}
	admissionDigest, err := devicesync.AdmissionAuthorizationDigest(admissionCredential)
	if err != nil {
		t.Fatal(err)
	}
	now := domainInput.CreatedAtMilliseconds
	admission := devicesync.AccountAdmission{
		Version: devicesync.SchemaVersion, RetryID: uuid.New(),
		AdmissionID:           admissionCredential.AdmissionID,
		AuthorizationDigest:   admissionDigest,
		CreatedAtMilliseconds: now,
		ExpiresAtMilliseconds: now + devicesync.MinimumAdmissionLifetimeMilliseconds,
	}
	if _, err := store.CreateAccountAdmission(context.Background(), admission, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimAccountAdmission(
		context.Background(), admissionCredential,
		devicesync.PrincipalProvisioning{
			Version: devicesync.SchemaVersion, RetryID: uuid.New(),
			PrincipalID: tenant.TenantID, InitialDeviceID: controlDomain.InitialMember.MemberID,
			Tenant: tenant, ControlDomain: controlDomain, CreatedAtMilliseconds: now,
		},
		now,
	); err != nil {
		t.Fatal(err)
	}
}

func newDeviceSyncTestServer(
	t *testing.T,
	relayStore relay.Store,
	operatorToken string,
	nowMilliseconds int64,
) *Server {
	t.Helper()
	server := newRelayTestServer(t, relayStore, operatorToken)
	server.SetDeviceSyncStore(devicesync.NewMemoryStore(relayStore))
	server.now = func() time.Time { return time.UnixMilli(nowMilliseconds) }
	return server
}

func newRelayTestServer(t *testing.T, relayStore relay.Store, operatorToken string) *Server {
	t.Helper()
	blobRoot := t.TempDir()
	blobStore, err := relay.NewFileBlobContentStore(blobRoot)
	if err != nil {
		t.Fatal(err)
	}
	uploadStore, err := relay.NewFileBlobUploadContentStore(blobRoot, blobStore)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewWithRelay(
		rendezvous.NewMemoryStore(), relayStore, blobStore,
		slog.New(slog.NewTextHandler(io.Discard, nil)), operatorToken, uploadStore,
	)
	if err != nil {
		t.Fatal(err)
	}
	return server
}
