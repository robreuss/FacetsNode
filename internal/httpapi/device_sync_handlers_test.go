package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/devicesync"
	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/rendezvous"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
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

func TestDeviceSyncAccountClaimActivatesClientSignedInitialAuthorityBinding(t *testing.T) {
	now := int64(1_100)
	operatorToken := relayTestToken(221)
	relayStore := relay.NewMemoryStore()
	server := newDeviceSyncTestServer(t, relayStore, operatorToken, now)
	credential := deviceSyncAdmissionCredential{
		AdmissionID:        uuid.New(),
		AuthorizationToken: relayTestToken(222),
	}
	admission := deviceSyncAdmissionCreateInput{
		Version:               devicesync.SchemaVersion,
		RetryID:               uuid.New(),
		AdmissionCredential:   credential,
		ExpiresAtMilliseconds: now + devicesync.MinimumAdmissionLifetimeMilliseconds,
	}
	created := performRelayJSON(
		t,
		server.Handler(),
		http.MethodPost,
		"/v1/device-sync/account-admissions",
		admission,
		operatorToken,
		uuid.Nil,
	)
	requireStatus(t, created, http.StatusCreated)
	_ = created.Body.Close()

	deploymentID := uuid.MustParse("63000000-0000-0000-0000-000000000001")
	routeID := uuid.MustParse("62000000-0000-0000-0000-000000000001")
	seed := make([]byte, 32)
	seed[31] = 2
	signer, err := serviceauthority.NewDeploymentSigner(deploymentID, seed)
	if err != nil {
		t.Fatal(err)
	}
	bindingDirectory := t.TempDir()
	bindingPath := filepath.Join(bindingDirectory, "bindings.json")
	emptyBindings, err := json.Marshal(serviceauthority.BindingFile{
		Bindings: []serviceauthority.BindingFileEntry{},
		Version:  serviceauthority.SchemaVersion,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bindingPath, emptyBindings, 0o600); err != nil {
		t.Fatal(err)
	}
	bindings, err := serviceauthority.LoadBindingRegistry(bindingPath, deploymentID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bindings.Close() })
	server.SetServiceAuthorityDeployment(
		signer,
		bindings,
		serviceauthority.ScopeDeviceSync,
	)
	handler := server.Handler()
	controlDomain := newRelayDomainProvisioningRequest(now, 223, 224)
	scope := serviceauthority.Scope{
		Kind:    serviceauthority.ScopeDeviceSync,
		ScopeID: controlDomain.AdministrationCredential.TenantID,
	}
	enrollment := testInitialServiceAuthorityEnrollment(
		t,
		signer,
		scope,
		routeID,
	)
	claim := deviceSyncPrincipalClaimInput{
		Version:                    devicesync.SchemaVersion,
		RetryID:                    uuid.New(),
		PrincipalID:                scope.ScopeID,
		InitialDeviceID:            controlDomain.MemberCredential.MemberID,
		ServiceAuthorityEnrollment: &enrollment,
		TenantProvisioning: newRelayTenantProvisioningRequest(
			controlDomain,
			relayTestToken(225),
		),
	}
	claimPath := "/v1/device-sync/account-admissions/" +
		credential.AdmissionID.String() + "/claim"

	missing := claim
	missing.ServiceAuthorityEnrollment = nil
	response := performRelayJSON(
		t,
		handler,
		http.MethodPost,
		claimPath,
		missing,
		credential.AuthorizationToken,
		uuid.Nil,
	)
	requireStatus(t, response, http.StatusBadRequest)
	_ = response.Body.Close()

	// Force the public-binding write to fail after the Device Sync store has
	// committed. The handler must withhold success, then allow an exact retry
	// to repair and durably activate the binding.
	if err := os.Remove(bindingPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(bindingPath, 0o700); err != nil {
		t.Fatal(err)
	}
	response = performRelayJSON(
		t,
		handler,
		http.MethodPost,
		claimPath,
		claim,
		credential.AuthorizationToken,
		uuid.Nil,
	)
	requireStatus(t, response, http.StatusConflict)
	_ = response.Body.Close()
	if err := os.Remove(bindingPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bindingPath, emptyBindings, 0o600); err != nil {
		t.Fatal(err)
	}
	response = performRelayJSON(
		t,
		handler,
		http.MethodPost,
		claimPath,
		claim,
		credential.AuthorizationToken,
		uuid.Nil,
	)
	requireStatus(t, response, http.StatusOK)
	_ = response.Body.Close()
	manifestDigest, err := enrollment.Manifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	if err := bindings.Authorize(serviceauthority.RequestBinding{
		Scope:             scope,
		AuthorityRevision: 1,
		AuthorityDigest:   manifestDigest,
		DeploymentID:      deploymentID,
		RouteID:           routeID,
		TrafficClass:      serviceauthority.TrafficControl,
	}); err != nil {
		t.Fatalf("claimed initial authority binding was not activated: %v", err)
	}

	// The setup offer expires at 2,000. Once the store has committed this exact
	// claim, expiry must not turn a lost-response retry into a false failure.
	now = 2_100
	server.now = func() time.Time { return time.UnixMilli(now) }
	response = performRelayJSON(
		t,
		handler,
		http.MethodPost,
		claimPath,
		claim,
		credential.AuthorizationToken,
		uuid.Nil,
	)
	requireStatus(t, response, http.StatusOK)
	_ = response.Body.Close()
}

func TestDeviceSyncAccountAdmissionAppliesOperatorEntitlement(t *testing.T) {
	const now = int64(1_250)
	operatorToken := relayTestToken(207)
	relayStore := relay.NewMemoryStore()
	server := newDeviceSyncTestServer(t, relayStore, operatorToken, now)
	handler := server.Handler()

	credential := deviceSyncAdmissionCredential{
		AdmissionID:        uuid.New(),
		AuthorizationToken: relayTestToken(208),
	}
	entitlement := devicesync.ServiceEntitlement{
		Version: devicesync.SchemaVersion,
		PlanID:  "hosted-starter",
		TenantQuota: relay.TenantQuota{
			MaximumDomainCount:               3,
			MaximumAggregateMessageCount:     40,
			MaximumAggregateMessageByteCount: 4_000,
			MaximumAggregateBlobCount:        5,
			MaximumAggregateBlobByteCount:    5_000,
		},
	}
	admission := deviceSyncAdmissionCreateInput{
		Version:               devicesync.SchemaVersion,
		RetryID:               uuid.New(),
		AdmissionCredential:   credential,
		ExpiresAtMilliseconds: now + devicesync.MinimumAdmissionLifetimeMilliseconds,
		Entitlement:           &entitlement,
	}
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
	if createdResult.Admission.Entitlement != entitlement {
		t.Fatalf("created entitlement=%+v want=%+v", createdResult.Admission.Entitlement, entitlement)
	}

	controlDomain := newRelayDomainProvisioningRequest(now, 209, 210)
	claim := deviceSyncPrincipalClaimInput{
		Version:         devicesync.SchemaVersion,
		RetryID:         uuid.New(),
		PrincipalID:     controlDomain.AdministrationCredential.TenantID,
		InitialDeviceID: controlDomain.MemberCredential.MemberID,
		TenantProvisioning: newRelayTenantProvisioningRequest(
			controlDomain, relayTestToken(211),
		),
	}
	claimed := performRelayJSON(
		t, handler, http.MethodPost,
		"/v1/device-sync/account-admissions/"+credential.AdmissionID.String()+"/claim",
		claim, credential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, claimed, http.StatusCreated)
	_ = claimed.Body.Close()

	status, err := relayStore.GetTenantStatus(context.Background(), relay.TenantCredential{
		TenantID: claim.PrincipalID,
		Token:    claim.TenantProvisioning.TenantProvisioningCredential.AuthorizationToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	if status.Quota != entitlement.TenantQuota {
		t.Fatalf("tenant quota=%+v want=%+v", status.Quota, entitlement.TenantQuota)
	}
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
		SubscriptionID:        uuid.New(),
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

	messageID := uuid.New()
	publisherCredential := relay.Credential{
		TenantID: principalID, DomainID: domainInput.AdministrationCredential.DomainID,
		MemberID: domainInput.MemberCredential.MemberID,
		Token:    domainInput.MemberCredential.AuthorizationToken,
	}
	envelope := relay.Envelope{
		Version: relay.SchemaVersion, Algorithm: relay.EnvelopeAlgorithm,
		TenantID: principalID, DomainID: domainInput.AdministrationCredential.DomainID,
		MessageID: messageID, PublisherMemberID: publisherCredential.MemberID,
		KeyEpoch: 1, CreatedAtMilliseconds: now,
		Nonce:             base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xa1}, 12)),
		Ciphertext:        base64.RawURLEncoding.EncodeToString([]byte("opaque-control-message")),
		AuthenticationTag: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xb2}, 16)),
	}
	if _, err := relayStore.Publish(context.Background(), publisherCredential, envelope, now); err != nil {
		t.Fatal(err)
	}
	fetched, err := relayStore.Fetch(context.Background(), memberCredential, 0, 10, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(fetched.Messages) != 1 || fetched.Messages[0].Envelope.MessageID != messageID {
		t.Fatalf("new device did not receive opaque control message: %+v", fetched)
	}

	claimRetry := performRelayJSON(
		t, handler, http.MethodPost, claimPath, claimInput,
		admissionCredential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, claimRetry, http.StatusOK)
	_ = claimRetry.Body.Close()
}

func TestDeviceSyncPrincipalProvisionsOpaqueSpaceDomainExactlyOnce(t *testing.T) {
	const now = int64(4_000)
	const tenantSeed = byte(243)
	relayStore := relay.NewMemoryStore()
	deviceSyncStore := devicesync.NewMemoryStore(relayStore)
	controlDomain := newRelayDomainProvisioningRequest(now, 241, 242)
	principalID := controlDomain.AdministrationCredential.TenantID
	initialDeviceID := controlDomain.MemberCredential.MemberID
	bootstrapDeviceSyncPrincipal(t, deviceSyncStore, controlDomain, tenantSeed)
	server := newRelayTestServer(t, relayStore, relayTestToken(244))
	server.SetDeviceSyncStore(deviceSyncStore)
	server.now = func() time.Time { return time.UnixMilli(now) }
	handler := server.Handler()

	spaceID := uuid.New()
	spaceDomain := newRelayDomainProvisioningRequest(now, 245, 246)
	spaceDomain.AdministrationCredential.TenantID = principalID
	spaceDomain.MemberCredential.TenantID = principalID
	spaceDomain.MemberCredential.MemberID = initialDeviceID
	spaceDomain.MemberCapabilities = nil
	spaceDomain.Quota = &relay.DomainQuota{
		MaximumMessageCount: 1, MaximumMessageByteCount: 1,
		MaximumBlobCount: 1, MaximumBlobByteCount: 1,
	}
	input := deviceSyncSpaceProvisioningInput{
		Version: devicesync.SchemaVersion, RetryID: uuid.New(),
		InitialDeviceID: initialDeviceID, Domain: relayDomainInput(spaceDomain),
	}
	path := "/v1/device-sync/principals/" + principalID.String() +
		"/spaces/" + spaceID.String()

	wrongCredential := performRelayJSON(
		t, handler, http.MethodPost, path, input, relayTestToken(247), uuid.Nil,
	)
	requireStatus(t, wrongCredential, http.StatusUnauthorized)
	_ = wrongCredential.Body.Close()

	created := performRelayJSON(
		t, handler, http.MethodPost, path, input, relayTestToken(tenantSeed), uuid.Nil,
	)
	requireStatus(t, created, http.StatusCreated)
	var createdResult devicesync.SpaceProvisioningResult
	if err := json.NewDecoder(created.Body).Decode(&createdResult); err != nil {
		t.Fatal(err)
	}
	_ = created.Body.Close()
	if createdResult.Acceptance != relay.AcceptanceAccepted ||
		createdResult.PrincipalID != principalID || createdResult.SpaceID != spaceID ||
		createdResult.Domain.DomainID != spaceDomain.AdministrationCredential.DomainID {
		t.Fatalf("unexpected Space provisioning: %+v", createdResult)
	}

	retry := performRelayJSON(
		t, handler, http.MethodPost, path, input, relayTestToken(tenantSeed), uuid.Nil,
	)
	requireStatus(t, retry, http.StatusOK)
	var retryResult devicesync.SpaceProvisioningResult
	if err := json.NewDecoder(retry.Body).Decode(&retryResult); err != nil {
		t.Fatal(err)
	}
	_ = retry.Body.Close()
	if retryResult.Acceptance != relay.AcceptanceDuplicate ||
		retryResult.Domain.DomainID != createdResult.Domain.DomainID {
		t.Fatalf("Space retry changed authority: %+v", retryResult)
	}

	changedPath := "/v1/device-sync/principals/" + principalID.String() +
		"/spaces/" + uuid.NewString()
	changed := performRelayJSON(
		t, handler, http.MethodPost, changedPath, input, relayTestToken(tenantSeed), uuid.Nil,
	)
	requireStatus(t, changed, http.StatusConflict)
	_ = changed.Body.Close()
}

func TestDeviceSyncPrincipalStatusIsAuthenticatedAndContentBlind(t *testing.T) {
	const now = int64(4_500)
	const tenantSeed = byte(7)
	relayStore := relay.NewMemoryStore()
	deviceSyncStore := devicesync.NewMemoryStore(relayStore)
	controlDomain := newRelayDomainProvisioningRequest(now, 8, 9)
	principalID := controlDomain.AdministrationCredential.TenantID
	bootstrapDeviceSyncPrincipal(t, deviceSyncStore, controlDomain, tenantSeed)
	server := newRelayTestServer(t, relayStore, relayTestToken(10))
	server.SetDeviceSyncStore(deviceSyncStore)
	handler := server.Handler()
	path := "/v1/device-sync/principals/" + principalID.String() + "/status"

	response := performRelayJSON(
		t, handler, http.MethodGet, path, nil, relayTestToken(tenantSeed), uuid.Nil,
	)
	requireStatus(t, response, http.StatusOK)
	var status devicesync.PrincipalStatus
	if err := json.NewDecoder(response.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if status.Version != devicesync.SchemaVersion || status.PrincipalID != principalID ||
		status.ControlDomainID != controlDomain.AdministrationCredential.DomainID ||
		len(status.Devices) != 1 || len(status.Spaces) != 0 {
		t.Fatalf("unexpected principal status: %+v", status)
	}
	if status.Devices[0].DeviceID != controlDomain.MemberCredential.MemberID ||
		status.Devices[0].ControlSubscriptionID != controlDomain.SubscriptionID {
		t.Fatalf("unexpected device status: %+v", status.Devices[0])
	}

	wrong := performRelayJSON(
		t, handler, http.MethodGet, path, nil, relayTestToken(11), uuid.Nil,
	)
	requireStatus(t, wrong, http.StatusUnauthorized)
	_ = wrong.Body.Close()
}

func TestDeviceSyncSpaceProvisioningRejectsUnenrolledInitialDevice(t *testing.T) {
	const now = int64(5_000)
	const tenantSeed = byte(253)
	relayStore := relay.NewMemoryStore()
	deviceSyncStore := devicesync.NewMemoryStore(relayStore)
	controlDomain := newRelayDomainProvisioningRequest(now, 251, 252)
	principalID := controlDomain.AdministrationCredential.TenantID
	bootstrapDeviceSyncPrincipal(t, deviceSyncStore, controlDomain, tenantSeed)
	server := newRelayTestServer(t, relayStore, relayTestToken(254))
	server.SetDeviceSyncStore(deviceSyncStore)
	server.now = func() time.Time { return time.UnixMilli(now) }

	unknownDeviceID := uuid.New()
	spaceDomain := newRelayDomainProvisioningRequest(now, 1, 2)
	spaceDomain.AdministrationCredential.TenantID = principalID
	spaceDomain.MemberCredential.TenantID = principalID
	spaceDomain.MemberCredential.MemberID = unknownDeviceID
	input := deviceSyncSpaceProvisioningInput{
		Version: devicesync.SchemaVersion, RetryID: uuid.New(),
		InitialDeviceID: unknownDeviceID, Domain: relayDomainInput(spaceDomain),
	}
	response := performRelayJSON(
		t, server.Handler(), http.MethodPost,
		"/v1/device-sync/principals/"+principalID.String()+"/spaces/"+uuid.NewString(),
		input, relayTestToken(tenantSeed), uuid.Nil,
	)
	requireStatus(t, response, http.StatusUnauthorized)
	_ = response.Body.Close()
}

func TestDeviceSyncSpaceAdmitsEnrolledDeviceTransportExactlyOnce(t *testing.T) {
	const now = int64(5_500)
	const tenantSeed = byte(41)
	relayStore := relay.NewMemoryStore()
	deviceSyncStore := devicesync.NewMemoryStore(relayStore)
	controlDomain := newRelayDomainProvisioningRequest(now, 42, 43)
	principalID := controlDomain.AdministrationCredential.TenantID
	initialDeviceID := controlDomain.MemberCredential.MemberID
	bootstrapDeviceSyncPrincipal(t, deviceSyncStore, controlDomain, tenantSeed)
	deviceID := uuid.New()
	enrollDeviceSyncTestDevice(t, deviceSyncStore, controlDomain, deviceID, now, 44, 45)

	spaceID := uuid.New()
	spaceDomainInput := newRelayDomainProvisioningRequest(now, 46, 47)
	spaceDomainInput.AdministrationCredential.TenantID = principalID
	spaceDomainInput.MemberCredential.TenantID = principalID
	spaceDomainInput.MemberCredential.MemberID = initialDeviceID
	_, spaceDomain, err := relayTenantAndDomainProvisioning(
		newRelayTenantProvisioningRequest(spaceDomainInput, relayTestToken(48)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deviceSyncStore.ProvisionSpace(
		context.Background(), relay.TenantCredential{TenantID: principalID, Token: relayTestToken(tenantSeed)},
		devicesync.SpaceProvisioning{
			Version: devicesync.SchemaVersion, RetryID: uuid.New(), PrincipalID: principalID,
			SpaceID: spaceID, InitialDeviceID: initialDeviceID, Domain: spaceDomain,
			CreatedAtMilliseconds: now,
		}, now,
	); err != nil {
		t.Fatal(err)
	}

	server := newRelayTestServer(t, relayStore, relayTestToken(49))
	server.SetDeviceSyncStore(deviceSyncStore)
	server.now = func() time.Time { return time.UnixMilli(now) }
	handler := server.Handler()
	admissionCredential := deviceSyncAdmissionCredential{
		AdmissionID: uuid.New(), AuthorizationToken: relayTestToken(50),
	}
	createInput := deviceSyncDeviceAdmissionCreateInput{
		Version: devicesync.SchemaVersion, RetryID: uuid.New(), DeviceID: deviceID,
		SubscriptionID:        uuid.New(),
		AdmissionCredential:   admissionCredential,
		ExpiresAtMilliseconds: now + devicesync.MinimumAdmissionLifetimeMilliseconds,
	}
	createPath := "/v1/device-sync/principals/" + principalID.String() +
		"/spaces/" + spaceID.String() + "/domains/" +
		spaceDomainInput.AdministrationCredential.DomainID.String() + "/device-admissions"
	created := performRelayJSON(
		t, handler, http.MethodPost, createPath, createInput,
		spaceDomainInput.AdministrationCredential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, created, http.StatusCreated)
	var createdResult devicesync.SpaceDeviceAdmissionCreateResult
	if err := json.NewDecoder(created.Body).Decode(&createdResult); err != nil {
		t.Fatal(err)
	}
	_ = created.Body.Close()
	if createdResult.Acceptance != relay.AcceptanceAccepted ||
		createdResult.Admission.SpaceID != spaceID ||
		createdResult.Admission.DeviceID != deviceID ||
		len(createdResult.Admission.RelayAdmission.Capabilities) != len(allRelayCapabilities) {
		t.Fatalf("unexpected Space device admission: %+v", createdResult)
	}
	retry := performRelayJSON(
		t, handler, http.MethodPost, createPath, createInput,
		spaceDomainInput.AdministrationCredential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, retry, http.StatusOK)
	_ = retry.Body.Close()

	memberCredential := relay.Credential{
		TenantID: principalID, DomainID: spaceDomainInput.AdministrationCredential.DomainID,
		MemberID: deviceID, Token: relayTestToken(51),
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
		"/spaces/" + spaceID.String() + "/device-admissions/" +
		admissionCredential.AdmissionID.String() + "/claim"
	claimed := performRelayJSON(
		t, handler, http.MethodPost, claimPath, claimInput,
		admissionCredential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, claimed, http.StatusCreated)
	var claimedResult devicesync.SpaceDeviceAdmissionClaimResult
	if err := json.NewDecoder(claimed.Body).Decode(&claimedResult); err != nil {
		t.Fatal(err)
	}
	_ = claimed.Body.Close()
	if claimedResult.Acceptance != relay.AcceptanceAccepted ||
		claimedResult.SpaceID != spaceID || claimedResult.DeviceID != deviceID {
		t.Fatalf("unexpected Space device claim: %+v", claimedResult)
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
	joinRequestResponse := performRelayJSON(
		t, server.Handler(), http.MethodPost, "/v1/device-sync/join-requests",
		map[string]any{}, operatorToken, uuid.Nil,
	)
	requireStatus(t, joinRequestResponse, http.StatusNotFound)
	_ = joinRequestResponse.Body.Close()
	joinBootstrapResponse := performRelayJSON(
		t, server.Handler(), http.MethodGet,
		"/v1/device-sync/join-requests/"+uuid.NewString()+"/bootstrap",
		nil, operatorToken, uuid.Nil,
	)
	requireStatus(t, joinBootstrapResponse, http.StatusNotFound)
	_ = joinBootstrapResponse.Body.Close()
	joinLookupResponse := performRelayJSON(
		t, server.Handler(), http.MethodGet,
		"/v1/device-sync/principals/"+uuid.NewString()+"/control-domains/"+uuid.NewString()+"/join-requests/123456",
		nil, operatorToken, uuid.Nil,
	)
	requireStatus(t, joinLookupResponse, http.StatusNotFound)
	_ = joinLookupResponse.Body.Close()
	statusResponse := performRelayJSON(
		t, server.Handler(), http.MethodGet,
		"/v1/device-sync/principals/"+uuid.NewString()+"/status",
		nil, operatorToken, uuid.Nil,
	)
	requireStatus(t, statusResponse, http.StatusNotFound)
	_ = statusResponse.Body.Close()
	deviceResponse := performRelayJSON(
		t, server.Handler(), http.MethodPost,
		"/v1/device-sync/principals/"+uuid.NewString()+"/control-domains/"+uuid.NewString()+"/device-admissions",
		map[string]any{}, operatorToken, uuid.Nil,
	)
	requireStatus(t, deviceResponse, http.StatusNotFound)
	_ = deviceResponse.Body.Close()
	spaceResponse := performRelayJSON(
		t, server.Handler(), http.MethodPost,
		"/v1/device-sync/principals/"+uuid.NewString()+"/spaces/"+uuid.NewString(),
		map[string]any{}, operatorToken, uuid.Nil,
	)
	requireStatus(t, spaceResponse, http.StatusNotFound)
	_ = spaceResponse.Body.Close()
	spaceAdmissionResponse := performRelayJSON(
		t, server.Handler(), http.MethodPost,
		"/v1/device-sync/principals/"+uuid.NewString()+"/spaces/"+uuid.NewString()+
			"/domains/"+uuid.NewString()+"/device-admissions",
		map[string]any{}, operatorToken, uuid.Nil,
	)
	requireStatus(t, spaceAdmissionResponse, http.StatusNotFound)
	_ = spaceAdmissionResponse.Body.Close()
	spaceAdmissionClaimResponse := performRelayJSON(
		t, server.Handler(), http.MethodPost,
		"/v1/device-sync/principals/"+uuid.NewString()+"/spaces/"+uuid.NewString()+
			"/device-admissions/"+uuid.NewString()+"/claim",
		map[string]any{}, operatorToken, uuid.Nil,
	)
	requireStatus(t, spaceAdmissionClaimResponse, http.StatusNotFound)
	_ = spaceAdmissionClaimResponse.Body.Close()
}

func enrollDeviceSyncTestDevice(
	t *testing.T,
	store *devicesync.MemoryStore,
	controlDomain relayDomainProvisioningRequest,
	deviceID uuid.UUID,
	now int64,
	admissionSeed byte,
	memberSeed byte,
) {
	t.Helper()
	credential := relay.AdmissionCredential{
		TenantID:    controlDomain.AdministrationCredential.TenantID,
		DomainID:    controlDomain.AdministrationCredential.DomainID,
		AdmissionID: uuid.New(), Token: relayTestToken(admissionSeed),
	}
	digest, err := relay.AdmissionAuthorizationDigest(credential)
	if err != nil {
		t.Fatal(err)
	}
	admission := devicesync.DeviceAdmission{
		Version: devicesync.SchemaVersion, RetryID: uuid.New(),
		PrincipalID: credential.TenantID, DeviceID: deviceID,
		SubscriptionID: uuid.New(),
		RelayAdmission: relay.MemberAdmission{
			Version: relay.SchemaVersion, TenantID: credential.TenantID,
			DomainID: credential.DomainID, AdmissionID: credential.AdmissionID,
			AuthorizationDigest:   digest,
			Capabilities:          append([]relay.Capability(nil), allRelayCapabilities...),
			CreatedAtMilliseconds: now,
			ExpiresAtMilliseconds: now + devicesync.MinimumAdmissionLifetimeMilliseconds,
		},
		CreatedAtMilliseconds: now,
	}
	if _, err := store.CreateDeviceAdmission(
		context.Background(), relay.AdministrationCredential{
			TenantID: controlDomain.AdministrationCredential.TenantID,
			DomainID: controlDomain.AdministrationCredential.DomainID,
			Token:    controlDomain.AdministrationCredential.AuthorizationToken,
		}, admission, now,
	); err != nil {
		t.Fatal(err)
	}
	memberCredential := relay.Credential{
		TenantID: credential.TenantID, DomainID: credential.DomainID,
		MemberID: deviceID, Token: relayTestToken(memberSeed),
	}
	memberDigest, err := relay.AuthorizationDigest(memberCredential)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimDeviceAdmission(
		context.Background(),
		devicesync.DeviceAdmissionCredential{
			PrincipalID: credential.TenantID, AdmissionID: credential.AdmissionID,
			Token: credential.Token,
		},
		devicesync.DeviceAdmissionClaim{
			Version: devicesync.SchemaVersion, PrincipalID: credential.TenantID,
			DeviceID: deviceID,
			RelayClaim: relay.MemberAdmissionClaim{
				MemberID: deviceID, AuthorizationDigest: memberDigest,
			},
			ClaimedAtMilliseconds: now,
		},
		now,
	); err != nil {
		t.Fatal(err)
	}
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

func relayDomainInput(request relayDomainProvisioningRequest) relayDomainProvisioningInput {
	return relayDomainProvisioningInput{
		Version: request.Version, RetryID: request.RetryID,
		AdministrationCredential: request.AdministrationCredential,
		SubscriptionID:           request.SubscriptionID,
		MemberCredential:         request.MemberCredential,
		MemberCapabilities:       request.MemberCapabilities,
		Quota:                    request.Quota,
		CreatedAtMilliseconds:    request.CreatedAtMilliseconds,
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
