package httpapi

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/devicesync"
	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/traffic"
)

type deviceSyncAdmissionCredential struct {
	AdmissionID        uuid.UUID `json:"admissionID"`
	AuthorizationToken string    `json:"authorizationToken"`
}

type deviceSyncAdmissionCreateInput struct {
	Version               int                           `json:"version"`
	RetryID               uuid.UUID                     `json:"retryID"`
	AdmissionCredential   deviceSyncAdmissionCredential `json:"admissionCredential"`
	ExpiresAtMilliseconds int64                         `json:"expiresAtMilliseconds"`
}

type deviceSyncPrincipalClaimInput struct {
	Version            int                          `json:"version"`
	RetryID            uuid.UUID                    `json:"retryID"`
	PrincipalID        uuid.UUID                    `json:"principalID"`
	InitialDeviceID    uuid.UUID                    `json:"initialDeviceID"`
	TenantProvisioning relayTenantProvisioningInput `json:"tenantProvisioning"`
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
	admission := devicesync.AccountAdmission{
		Version: devicesync.SchemaVersion, RetryID: input.RetryID,
		AdmissionID: credential.AdmissionID, AuthorizationDigest: digest,
		CreatedAtMilliseconds: now, ExpiresAtMilliseconds: input.ExpiresAtMilliseconds,
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
	result, err := s.deviceSyncStore.ClaimAccountAdmission(
		request.Context(),
		devicesync.AdmissionCredential{AdmissionID: admissionID, Token: token},
		provisioning,
		s.nowMilliseconds(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
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
