package httpapi

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/devicesync"
	"github.com/robreuss/FacetsNode/internal/relay"
)

func (s *Server) handleCancelDeviceSyncSpaceDeviceAdmission(writer http.ResponseWriter, request *http.Request) {
	ids := make(map[string]uuid.UUID)
	for _, name := range []string{"principalID", "spaceID", "domainID", "admissionID"} {
		id, err := parseUUID(request.PathValue(name))
		if err != nil {
			s.writeError(writer, devicesync.NewProtocolError(devicesync.CodeInvalidAdmission, "invalid cancellation scope"))
			return
		}
		ids[name] = id
	}
	token, err := bearerToken(request)
	if err != nil {
		s.writeError(writer, devicesync.NewProtocolError(devicesync.CodeUnauthorized, "Space administration credential is required"))
		return
	}
	var input struct {
		Version  int                          `json:"version"`
		RetryID  uuid.UUID                    `json:"retryID"`
		DeviceID uuid.UUID                    `json:"deviceID"`
		Sponsor  *deviceSyncSpaceSponsorInput `json:"sponsor"`
	}
	if err := readRelayJSON(writer, request, &input, maximumRequestByteCount); err != nil {
		s.writeError(writer, err)
		return
	}
	if input.Version != devicesync.SchemaVersion || input.Sponsor == nil {
		s.writeError(writer, devicesync.NewProtocolError(devicesync.CodeUnauthorized, "current sponsor credentials are required"))
		return
	}
	principalID, domainID := ids["principalID"], ids["domainID"]
	result, err := s.deviceSyncStore.CancelSpaceDeviceAdmission(request.Context(), devicesync.SpaceSponsorCredential{
		Administration: relay.AdministrationCredential{TenantID: principalID, DomainID: domainID, Token: token},
		Control:        relay.Credential{TenantID: principalID, DomainID: input.Sponsor.ControlDomainID, MemberID: input.Sponsor.DeviceID, Token: input.Sponsor.ControlAuthorizationToken},
		Space:          relay.Credential{TenantID: principalID, DomainID: domainID, MemberID: input.Sponsor.DeviceID, Token: input.Sponsor.SpaceAuthorizationToken},
	}, devicesync.SpaceDeviceAdmissionCancellation{PrincipalID: principalID, SpaceID: ids["spaceID"], AdmissionID: ids["admissionID"],
		DeviceID: input.DeviceID, RetryID: input.RetryID, SponsorDeviceID: input.Sponsor.DeviceID}, s.nowMilliseconds())
	if err != nil {
		s.writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, result)
}
