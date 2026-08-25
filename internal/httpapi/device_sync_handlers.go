package httpapi

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/devicesync"
	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
	"github.com/robreuss/FacetsNode/internal/traffic"
)

type deviceSyncAdmissionCredential struct {
	AdmissionID        uuid.UUID `json:"admissionID"`
	AuthorizationToken string    `json:"authorizationToken"`
}

type deviceSyncAdmissionCreateInput struct {
	Version               int                            `json:"version"`
	RetryID               uuid.UUID                      `json:"retryID"`
	AdmissionCredential   deviceSyncAdmissionCredential  `json:"admissionCredential"`
	ExpiresAtMilliseconds int64                          `json:"expiresAtMilliseconds"`
	Entitlement           *devicesync.ServiceEntitlement `json:"entitlement,omitempty"`
}

type deviceSyncPrincipalClaimInput struct {
	Version                    int                                 `json:"version"`
	RetryID                    uuid.UUID                           `json:"retryID"`
	PrincipalID                uuid.UUID                           `json:"principalID"`
	InitialDeviceID            uuid.UUID                           `json:"initialDeviceID"`
	ServiceAuthorityEnrollment *serviceauthority.InitialEnrollment `json:"serviceAuthorityEnrollment,omitempty"`
	TenantProvisioning         relayTenantProvisioningInput        `json:"tenantProvisioning"`
}

type deviceSyncDeviceAdmissionCreateInput struct {
	Version                     int                           `json:"version"`
	RetryID                     uuid.UUID                     `json:"retryID"`
	DeviceID                    uuid.UUID                     `json:"deviceID"`
	SubscriptionID              uuid.UUID                     `json:"subscriptionID"`
	AdmissionCredential         deviceSyncAdmissionCredential `json:"admissionCredential"`
	ExpiresAtMilliseconds       int64                         `json:"expiresAtMilliseconds"`
	MemberExpiresAtMilliseconds *int64                        `json:"memberExpiresAtMilliseconds,omitempty"`
}

type deviceSyncDeviceAdmissionClaimInput struct {
	Version             int       `json:"version"`
	DeviceID            uuid.UUID `json:"deviceID"`
	AuthorizationDigest string    `json:"authorizationDigest"`
}

type deviceSyncSpaceProvisioningInput struct {
	Version         int                          `json:"version"`
	RetryID         uuid.UUID                    `json:"retryID"`
	InitialDeviceID uuid.UUID                    `json:"initialDeviceID"`
	Domain          relayDomainProvisioningInput `json:"domain"`
}

// deviceSyncJoinRequestCreateInput intentionally contains the raw candidate
// polling credential and displayed PIN only at ingress. The handler derives
// and persists digests; neither value is returned or stored in plaintext.
type deviceSyncJoinRequestCreateInput struct {
	Version                     int       `json:"version"`
	RetryID                     uuid.UUID `json:"retryID"`
	RequestID                   uuid.UUID `json:"requestID"`
	CandidateDeviceID           uuid.UUID `json:"candidateDeviceID"`
	CandidateBootstrapPublicKey string    `json:"candidateBootstrapPublicKey"`
	PollingAuthorizationToken   string    `json:"pollingAuthorizationToken"`
	PIN                         string    `json:"pin"`
	ExpiresAtMilliseconds       int64     `json:"expiresAtMilliseconds"`
}

type deviceSyncJoinBootstrapInput struct {
	devicesync.JoinBootstrapEnvelope
}

func (s *Server) handleCreateDeviceSyncJoinRequest(writer http.ResponseWriter, request *http.Request) {
	var input deviceSyncJoinRequestCreateInput
	if err := readRelayJSON(writer, request, &input, maximumRequestByteCount); err != nil {
		s.writeError(writer, err)
		return
	}
	if input.Version != devicesync.SchemaVersion {
		s.writeError(writer, devicesync.NewProtocolError(
			devicesync.CodeInvalidJoinRequest, "join request version is invalid",
		))
		return
	}
	pollingDigest, err := devicesync.JoinRequestPollingAuthorizationDigest(devicesync.JoinRequestCredential{
		RequestID: input.RequestID, Token: input.PollingAuthorizationToken,
	})
	if err != nil {
		s.writeError(writer, devicesync.NewProtocolError(devicesync.CodeInvalidJoinRequest, err.Error()))
		return
	}
	pinDigest, err := devicesync.JoinRequestPINAuthorizationDigest(input.PIN)
	if err != nil {
		s.writeError(writer, devicesync.NewProtocolError(devicesync.CodeInvalidJoinRequest, err.Error()))
		return
	}
	now := s.nowMilliseconds()
	result, err := s.deviceSyncStore.CreateJoinRequest(request.Context(), devicesync.JoinRequest{
		Version:                     devicesync.SchemaVersion,
		RetryID:                     input.RetryID,
		RequestID:                   input.RequestID,
		CandidateDeviceID:           input.CandidateDeviceID,
		CandidateBootstrapPublicKey: input.CandidateBootstrapPublicKey,
		PollingAuthorizationDigest:  pollingDigest,
		PINAuthorizationDigest:      pinDigest,
		CreatedAtMilliseconds:       now,
		ExpiresAtMilliseconds:       input.ExpiresAtMilliseconds,
	}, now)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(traffic.SurfaceRendezvous, string(result.Acceptance))
	writeJSON(writer, relayAcceptanceStatus(result.Acceptance), result)
}

func (s *Server) handleLookupDeviceSyncJoinRequest(writer http.ResponseWriter, request *http.Request) {
	credential, err := deviceSyncControlCredentialFromRequest(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	presentation, err := s.deviceSyncStore.LookupJoinRequest(
		request.Context(), credential, request.PathValue("pin"), s.nowMilliseconds(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, presentation)
}

func (s *Server) handleStoreDeviceSyncJoinBootstrap(writer http.ResponseWriter, request *http.Request) {
	credential, err := deviceSyncControlCredentialFromRequest(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	requestID, err := parseUUID(request.PathValue("requestID"))
	if err != nil {
		s.writeError(writer, devicesync.NewProtocolError(devicesync.CodeInvalidJoinRequest, err.Error()))
		return
	}
	var input deviceSyncJoinBootstrapInput
	if err := readRelayJSON(writer, request, &input, maximumRequestByteCount); err != nil {
		s.writeError(writer, err)
		return
	}
	if input.RequestID != requestID {
		s.writeError(writer, devicesync.NewProtocolError(
			devicesync.CodeWrongScope, "join bootstrap path and body differ",
		))
		return
	}
	acceptance, err := s.deviceSyncStore.StoreJoinRequestBootstrap(
		request.Context(), credential, input.JoinBootstrapEnvelope, s.nowMilliseconds(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(traffic.SurfaceManagement, string(acceptance))
	writeJSON(writer, relayAcceptanceStatus(acceptance), struct {
		Acceptance relay.Acceptance `json:"acceptance"`
	}{Acceptance: acceptance})
}

func (s *Server) handleFetchDeviceSyncJoinBootstrap(writer http.ResponseWriter, request *http.Request) {
	requestID, err := parseUUID(request.PathValue("requestID"))
	if err != nil {
		s.writeError(writer, devicesync.NewProtocolError(devicesync.CodeInvalidJoinRequest, err.Error()))
		return
	}
	token, err := bearerToken(request)
	if err != nil {
		s.writeError(writer, devicesync.NewProtocolError(
			devicesync.CodeUnauthorized, "join request polling credential is missing",
		))
		return
	}
	bootstrap, err := s.deviceSyncStore.FetchJoinRequestBootstrap(
		request.Context(), devicesync.JoinRequestCredential{RequestID: requestID, Token: token}, s.nowMilliseconds(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, bootstrap)
}

func deviceSyncControlCredentialFromRequest(request *http.Request) (relay.AdministrationCredential, error) {
	principalID, err := parseUUID(request.PathValue("principalID"))
	if err != nil {
		return relay.AdministrationCredential{}, devicesync.NewProtocolError(devicesync.CodeInvalidPrincipal, err.Error())
	}
	domainID, err := parseUUID(request.PathValue("domainID"))
	if err != nil {
		return relay.AdministrationCredential{}, devicesync.NewProtocolError(devicesync.CodeInvalidJoinRequest, err.Error())
	}
	token, err := bearerToken(request)
	if err != nil {
		return relay.AdministrationCredential{}, devicesync.NewProtocolError(
			devicesync.CodeUnauthorized, "Device Sync control-domain credential is missing",
		)
	}
	return relay.AdministrationCredential{TenantID: principalID, DomainID: domainID, Token: token}, nil
}

func (s *Server) handleGetDeviceSyncPrincipalStatus(writer http.ResponseWriter, request *http.Request) {
	principalID, err := parseUUID(request.PathValue("principalID"))
	if err != nil {
		s.writeError(writer, devicesync.NewProtocolError(devicesync.CodeInvalidPrincipal, err.Error()))
		return
	}
	token, err := bearerToken(request)
	if err != nil {
		s.writeError(writer, devicesync.NewProtocolError(
			devicesync.CodeUnauthorized, "Device Sync principal credential is missing",
		))
		return
	}
	status, err := s.deviceSyncStore.GetPrincipalStatus(
		request.Context(),
		relay.TenantCredential{TenantID: principalID, Token: token},
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, status)
}

func (s *Server) handleRevokeDeviceSyncDevice(writer http.ResponseWriter, request *http.Request) {
	principalID, err := parseUUID(request.PathValue("principalID"))
	if err != nil {
		s.writeError(writer, devicesync.NewProtocolError(devicesync.CodeInvalidPrincipal, err.Error()))
		return
	}
	deviceID, err := parseUUID(request.PathValue("deviceID"))
	if err != nil {
		s.writeError(writer, devicesync.NewProtocolError(devicesync.CodeInvalidPrincipal, err.Error()))
		return
	}
	token, err := bearerToken(request)
	if err != nil {
		s.writeError(writer, devicesync.NewProtocolError(
			devicesync.CodeUnauthorized, "Device Sync principal credential is missing",
		))
		return
	}
	var revocation devicesync.DeviceRevocation
	if err := readRelayJSON(writer, request, &revocation, maximumRequestByteCount); err != nil {
		s.writeError(writer, err)
		return
	}
	if revocation.PrincipalID != principalID || revocation.DeviceID != deviceID {
		s.writeError(writer, devicesync.NewProtocolError(
			devicesync.CodeWrongScope, "device revocation path and body differ",
		))
		return
	}
	result, err := s.deviceSyncStore.RevokeDevice(
		request.Context(),
		relay.TenantCredential{TenantID: principalID, Token: token},
		revocation,
		s.nowMilliseconds(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(traffic.SurfaceManagement, string(result.Acceptance))
	writeJSON(writer, relayAcceptanceStatus(result.Acceptance), result)
}

func (s *Server) handleCreateDeviceSyncAccountAdmission(writer http.ResponseWriter, request *http.Request) {
	if err := s.authorizeOperator(request); err != nil {
		s.writeError(writer, err)
		return
	}
	var input deviceSyncAdmissionCreateInput
	if err := readRelayJSON(writer, request, &input, maximumRequestByteCount); err != nil {
		s.writeError(writer, err)
		return
	}
	credential := devicesync.AdmissionCredential{
		AdmissionID: input.AdmissionCredential.AdmissionID,
		Token:       input.AdmissionCredential.AuthorizationToken,
	}
	digest, err := devicesync.AdmissionAuthorizationDigest(credential)
	if err != nil {
		s.writeError(writer, devicesync.NewProtocolError(devicesync.CodeInvalidAdmission, err.Error()))
		return
	}
	now := s.nowMilliseconds()
	entitlement := devicesync.DefaultServiceEntitlement()
	if input.Entitlement != nil {
		entitlement = *input.Entitlement
	}
	admission := devicesync.AccountAdmission{
		Version: devicesync.SchemaVersion, RetryID: input.RetryID,
		AdmissionID: credential.AdmissionID, AuthorizationDigest: digest,
		CreatedAtMilliseconds: now, ExpiresAtMilliseconds: input.ExpiresAtMilliseconds,
		Entitlement: entitlement,
	}
	if input.Version != devicesync.SchemaVersion {
		s.writeError(writer, devicesync.NewProtocolError(
			devicesync.CodeInvalidAdmission, "account admission version is invalid",
		))
		return
	}
	result, err := s.deviceSyncStore.CreateAccountAdmission(request.Context(), admission, now)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(traffic.SurfaceManagement, string(result.Acceptance))
	writeJSON(writer, relayAcceptanceStatus(result.Acceptance), result)
}

func (s *Server) handleClaimDeviceSyncAccountAdmission(writer http.ResponseWriter, request *http.Request) {
	admissionID, err := parseUUID(request.PathValue("admissionID"))
	if err != nil {
		s.writeError(writer, devicesync.NewProtocolError(devicesync.CodeInvalidAdmission, err.Error()))
		return
	}
	token, err := bearerToken(request)
	if err != nil {
		s.writeError(writer, devicesync.NewProtocolError(devicesync.CodeUnauthorized, "account admission credential is missing"))
		return
	}
	var input deviceSyncPrincipalClaimInput
	if err := readRelayJSON(writer, request, &input, maximumRequestByteCount); err != nil {
		s.writeError(writer, err)
		return
	}
	tenant, controlDomain, err := relayTenantAndDomainProvisioning(input.TenantProvisioning)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	provisioning := devicesync.PrincipalProvisioning{
		Version: devicesync.SchemaVersion, RetryID: input.RetryID,
		PrincipalID: input.PrincipalID, InitialDeviceID: input.InitialDeviceID,
		Tenant: tenant, ControlDomain: controlDomain,
		CreatedAtMilliseconds: tenant.CreatedAtMilliseconds,
	}
	if input.Version != devicesync.SchemaVersion {
		s.writeError(writer, devicesync.NewProtocolError(
			devicesync.CodeInvalidPrincipal, "principal provisioning version is invalid",
		))
		return
	}
	now := s.nowMilliseconds()
	var authorityBinding *serviceauthority.CurrentBinding
	if s.deploymentSigner != nil && s.serviceAuthorityBindings != nil {
		if input.ServiceAuthorityEnrollment == nil {
			s.writeError(writer, devicesync.NewProtocolError(
				devicesync.CodeInvalidPrincipal,
				"initial service authority enrollment is required",
			))
			return
		}
		scope := serviceauthority.Scope{
			Kind: serviceauthority.ScopeDeviceSync, ScopeID: input.PrincipalID,
		}
		manifest, enrollmentErr := input.ServiceAuthorityEnrollment.ValidateForAdmissionClaim(scope, now)
		digest, digestErr := input.ServiceAuthorityEnrollment.Manifest.ReferenceDigest()
		if enrollmentErr != nil || digestErr != nil ||
			manifest.ActiveDeployment.DeploymentID != s.deploymentSigner.DeploymentID() ||
			manifest.ActiveDeployment.PublicSigningKeyX963 !=
				s.deploymentSigner.PublicSigningKeyX963() ||
			manifest.ActiveDeployment.SigningKeyFingerprint !=
				s.deploymentSigner.SigningKeyFingerprint() {
			s.writeError(writer, devicesync.NewProtocolError(
				devicesync.CodeInvalidPrincipal,
				"initial service authority enrollment is invalid",
			))
			return
		}
		authorityBinding = &serviceauthority.CurrentBinding{
			Revision: manifest.Revision, Digest: digest,
			DeploymentID: manifest.ActiveDeployment.DeploymentID,
			Manifest:     &input.ServiceAuthorityEnrollment.Manifest,
		}
	}
	result, err := s.deviceSyncStore.ClaimAccountAdmission(
		request.Context(),
		devicesync.AdmissionCredential{AdmissionID: admissionID, Token: token},
		provisioning,
		now,
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	if authorityBinding != nil {
		if err := s.serviceAuthorityBindings.Activate(
			serviceauthority.Scope{
				Kind: serviceauthority.ScopeDeviceSync, ScopeID: input.PrincipalID,
			},
			*authorityBinding,
		); err != nil {
			writeServiceAuthorityError(writer, http.StatusConflict)
			return
		}
	}
	s.metrics.ObserveAcceptance(traffic.SurfaceManagement, string(result.Acceptance))
	writeJSON(writer, relayAcceptanceStatus(result.Acceptance), result)
}

func (s *Server) handleCreateDeviceSyncDeviceAdmission(writer http.ResponseWriter, request *http.Request) {
	principalID, err := parseUUID(request.PathValue("principalID"))
	if err != nil {
		s.writeError(writer, devicesync.NewProtocolError(devicesync.CodeInvalidPrincipal, err.Error()))
		return
	}
	controlDomainID, err := parseUUID(request.PathValue("domainID"))
	if err != nil {
		s.writeError(writer, devicesync.NewProtocolError(devicesync.CodeInvalidAdmission, err.Error()))
		return
	}
	token, err := bearerToken(request)
	if err != nil {
		s.writeError(writer, devicesync.NewProtocolError(devicesync.CodeUnauthorized, "control-domain administration credential is missing"))
		return
	}
	var input deviceSyncDeviceAdmissionCreateInput
	if err := readRelayJSON(writer, request, &input, maximumRequestByteCount); err != nil {
		s.writeError(writer, err)
		return
	}
	if input.Version != devicesync.SchemaVersion {
		s.writeError(writer, devicesync.NewProtocolError(devicesync.CodeInvalidAdmission, "device admission version is invalid"))
		return
	}
	admissionCredential := relay.AdmissionCredential{
		TenantID: principalID, DomainID: controlDomainID,
		AdmissionID: input.AdmissionCredential.AdmissionID,
		Token:       input.AdmissionCredential.AuthorizationToken,
	}
	authorizationDigest, err := relay.AdmissionAuthorizationDigest(admissionCredential)
	if err != nil {
		s.writeError(writer, devicesync.NewProtocolError(devicesync.CodeInvalidAdmission, err.Error()))
		return
	}
	now := s.nowMilliseconds()
	relayAdmission := relay.MemberAdmission{
		Version: relay.SchemaVersion, TenantID: principalID, DomainID: controlDomainID,
		AdmissionID:           input.AdmissionCredential.AdmissionID,
		AuthorizationDigest:   authorizationDigest,
		Capabilities:          append([]relay.Capability(nil), allRelayCapabilities...),
		CreatedAtMilliseconds: now, ExpiresAtMilliseconds: input.ExpiresAtMilliseconds,
		MemberExpiresAtMilliseconds: input.MemberExpiresAtMilliseconds,
	}
	result, err := s.deviceSyncStore.CreateDeviceAdmission(
		request.Context(),
		relay.AdministrationCredential{TenantID: principalID, DomainID: controlDomainID, Token: token},
		devicesync.DeviceAdmission{
			Version: devicesync.SchemaVersion, RetryID: input.RetryID,
			PrincipalID: principalID, DeviceID: input.DeviceID,
			SubscriptionID: input.SubscriptionID, RelayAdmission: relayAdmission,
			CreatedAtMilliseconds: now,
		},
		now,
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(traffic.SurfaceManagement, string(result.Acceptance))
	writeJSON(writer, relayAcceptanceStatus(result.Acceptance), result)
}

func (s *Server) handleClaimDeviceSyncDeviceAdmission(writer http.ResponseWriter, request *http.Request) {
	principalID, err := parseUUID(request.PathValue("principalID"))
	if err != nil {
		s.writeError(writer, devicesync.NewProtocolError(devicesync.CodeInvalidPrincipal, err.Error()))
		return
	}
	admissionID, err := parseUUID(request.PathValue("admissionID"))
	if err != nil {
		s.writeError(writer, devicesync.NewProtocolError(devicesync.CodeInvalidAdmission, err.Error()))
		return
	}
	token, err := bearerToken(request)
	if err != nil {
		s.writeError(writer, devicesync.NewProtocolError(devicesync.CodeUnauthorized, "device admission credential is missing"))
		return
	}
	var input deviceSyncDeviceAdmissionClaimInput
	if err := readRelayJSON(writer, request, &input, maximumRequestByteCount); err != nil {
		s.writeError(writer, err)
		return
	}
	if input.Version != devicesync.SchemaVersion {
		s.writeError(writer, devicesync.NewProtocolError(devicesync.CodeInvalidAdmission, "device admission claim version is invalid"))
		return
	}
	now := s.nowMilliseconds()
	result, err := s.deviceSyncStore.ClaimDeviceAdmission(
		request.Context(),
		devicesync.DeviceAdmissionCredential{PrincipalID: principalID, AdmissionID: admissionID, Token: token},
		devicesync.DeviceAdmissionClaim{
			Version: devicesync.SchemaVersion, PrincipalID: principalID, DeviceID: input.DeviceID,
			RelayClaim: relay.MemberAdmissionClaim{
				MemberID: input.DeviceID, AuthorizationDigest: input.AuthorizationDigest,
			},
			ClaimedAtMilliseconds: now,
		},
		now,
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(traffic.SurfaceManagement, string(result.Acceptance))
	writeJSON(writer, relayAcceptanceStatus(result.Acceptance), result)
}

func (s *Server) handleProvisionDeviceSyncSpace(writer http.ResponseWriter, request *http.Request) {
	principalID, err := parseUUID(request.PathValue("principalID"))
	if err != nil {
		s.writeError(writer, devicesync.NewProtocolError(devicesync.CodeInvalidPrincipal, err.Error()))
		return
	}
	spaceID, err := parseUUID(request.PathValue("spaceID"))
	if err != nil {
		s.writeError(writer, devicesync.NewProtocolError(devicesync.CodeInvalidSpace, err.Error()))
		return
	}
	token, err := bearerToken(request)
	if err != nil {
		s.writeError(writer, devicesync.NewProtocolError(devicesync.CodeUnauthorized, "Device Sync principal credential is missing"))
		return
	}
	var input deviceSyncSpaceProvisioningInput
	if err := readRelayJSON(writer, request, &input, maximumRequestByteCount); err != nil {
		s.writeError(writer, err)
		return
	}
	if input.Version != devicesync.SchemaVersion {
		s.writeError(writer, devicesync.NewProtocolError(devicesync.CodeInvalidSpace, "Space provisioning version is invalid"))
		return
	}
	// Device Sync owns its service policy. A caller may not enlarge relay quotas
	// or omit capabilities required for opaque checkpoint, tail, and blob custody.
	input.Domain.MemberCapabilities = append([]relay.Capability(nil), allRelayCapabilities...)
	input.Domain.Quota = nil
	domain, err := relayDomainProvisioning(input.Domain)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	result, err := s.deviceSyncStore.ProvisionSpace(
		request.Context(),
		relay.TenantCredential{TenantID: principalID, Token: token},
		devicesync.SpaceProvisioning{
			Version: devicesync.SchemaVersion, RetryID: input.RetryID,
			PrincipalID: principalID, SpaceID: spaceID,
			InitialDeviceID: input.InitialDeviceID, Domain: domain,
			CreatedAtMilliseconds: domain.Registration.CreatedAtMilliseconds,
		},
		s.nowMilliseconds(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(traffic.SurfaceManagement, string(result.Acceptance))
	writeJSON(writer, relayAcceptanceStatus(result.Acceptance), result)
}

func (s *Server) handleCreateDeviceSyncSpaceDeviceAdmission(writer http.ResponseWriter, request *http.Request) {
	principalID, err := parseUUID(request.PathValue("principalID"))
	if err != nil {
		s.writeError(writer, devicesync.NewProtocolError(devicesync.CodeInvalidPrincipal, err.Error()))
		return
	}
	spaceID, err := parseUUID(request.PathValue("spaceID"))
	if err != nil {
		s.writeError(writer, devicesync.NewProtocolError(devicesync.CodeInvalidSpace, err.Error()))
		return
	}
	domainID, err := parseUUID(request.PathValue("domainID"))
	if err != nil {
		s.writeError(writer, devicesync.NewProtocolError(devicesync.CodeInvalidAdmission, err.Error()))
		return
	}
	token, err := bearerToken(request)
	if err != nil {
		s.writeError(writer, devicesync.NewProtocolError(devicesync.CodeUnauthorized, "Space-domain administration credential is missing"))
		return
	}
	var input deviceSyncDeviceAdmissionCreateInput
	if err := readRelayJSON(writer, request, &input, maximumRequestByteCount); err != nil {
		s.writeError(writer, err)
		return
	}
	if input.Version != devicesync.SchemaVersion {
		s.writeError(writer, devicesync.NewProtocolError(devicesync.CodeInvalidAdmission, "Space device admission version is invalid"))
		return
	}
	admissionCredential := relay.AdmissionCredential{
		TenantID: principalID, DomainID: domainID,
		AdmissionID: input.AdmissionCredential.AdmissionID,
		Token:       input.AdmissionCredential.AuthorizationToken,
	}
	authorizationDigest, err := relay.AdmissionAuthorizationDigest(admissionCredential)
	if err != nil {
		s.writeError(writer, devicesync.NewProtocolError(devicesync.CodeInvalidAdmission, err.Error()))
		return
	}
	now := s.nowMilliseconds()
	result, err := s.deviceSyncStore.CreateSpaceDeviceAdmission(
		request.Context(),
		relay.AdministrationCredential{TenantID: principalID, DomainID: domainID, Token: token},
		devicesync.SpaceDeviceAdmission{
			Version: devicesync.SchemaVersion, RetryID: input.RetryID,
			PrincipalID: principalID, SpaceID: spaceID, DeviceID: input.DeviceID,
			SubscriptionID: input.SubscriptionID,
			RelayAdmission: relay.MemberAdmission{
				Version: relay.SchemaVersion, TenantID: principalID, DomainID: domainID,
				AdmissionID:           input.AdmissionCredential.AdmissionID,
				AuthorizationDigest:   authorizationDigest,
				Capabilities:          append([]relay.Capability(nil), allRelayCapabilities...),
				CreatedAtMilliseconds: now, ExpiresAtMilliseconds: input.ExpiresAtMilliseconds,
				MemberExpiresAtMilliseconds: input.MemberExpiresAtMilliseconds,
			},
			CreatedAtMilliseconds: now,
		},
		now,
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(traffic.SurfaceManagement, string(result.Acceptance))
	writeJSON(writer, relayAcceptanceStatus(result.Acceptance), result)
}

func (s *Server) handleClaimDeviceSyncSpaceDeviceAdmission(writer http.ResponseWriter, request *http.Request) {
	principalID, err := parseUUID(request.PathValue("principalID"))
	if err != nil {
		s.writeError(writer, devicesync.NewProtocolError(devicesync.CodeInvalidPrincipal, err.Error()))
		return
	}
	spaceID, err := parseUUID(request.PathValue("spaceID"))
	if err != nil {
		s.writeError(writer, devicesync.NewProtocolError(devicesync.CodeInvalidSpace, err.Error()))
		return
	}
	admissionID, err := parseUUID(request.PathValue("admissionID"))
	if err != nil {
		s.writeError(writer, devicesync.NewProtocolError(devicesync.CodeInvalidAdmission, err.Error()))
		return
	}
	token, err := bearerToken(request)
	if err != nil {
		s.writeError(writer, devicesync.NewProtocolError(devicesync.CodeUnauthorized, "Space device admission credential is missing"))
		return
	}
	var input deviceSyncDeviceAdmissionClaimInput
	if err := readRelayJSON(writer, request, &input, maximumRequestByteCount); err != nil {
		s.writeError(writer, err)
		return
	}
	if input.Version != devicesync.SchemaVersion {
		s.writeError(writer, devicesync.NewProtocolError(devicesync.CodeInvalidAdmission, "Space device admission claim version is invalid"))
		return
	}
	now := s.nowMilliseconds()
	result, err := s.deviceSyncStore.ClaimSpaceDeviceAdmission(
		request.Context(),
		devicesync.SpaceDeviceAdmissionCredential{
			PrincipalID: principalID, SpaceID: spaceID,
			AdmissionID: admissionID, Token: token,
		},
		devicesync.SpaceDeviceAdmissionClaim{
			Version: devicesync.SchemaVersion, PrincipalID: principalID,
			SpaceID: spaceID, DeviceID: input.DeviceID,
			RelayClaim: relay.MemberAdmissionClaim{
				MemberID: input.DeviceID, AuthorizationDigest: input.AuthorizationDigest,
			},
			ClaimedAtMilliseconds: now,
		},
		now,
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(traffic.SurfaceManagement, string(result.Acceptance))
	writeJSON(writer, relayAcceptanceStatus(result.Acceptance), result)
}
