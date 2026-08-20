package httpapi

import (
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/sharedspaces"
	"github.com/robreuss/FacetsNode/internal/traffic"
)

type sharedSpaceProvisioningInput struct {
	Version                      int                                `json:"version"`
	RetryID                      uuid.UUID                          `json:"retryID"`
	SpaceID                      uuid.UUID                          `json:"spaceID"`
	SecurityMode                 sharedspaces.SecurityMode          `json:"securityMode"`
	InteractionMode              sharedspaces.InteractionMode       `json:"interactionMode"`
	InitialParticipantID         uuid.UUID                          `json:"initialParticipantID"`
	InitialParticipantKind       sharedspaces.ParticipantKind       `json:"initialParticipantKind"`
	InitialParticipantSigningKey sharedspaces.ParticipantSigningKey `json:"initialParticipantSigningKey"`
	TenantProvisioning           relayTenantProvisioningInput       `json:"tenantProvisioning"`
}

type sharedSpaceInvitationCredential struct {
	InvitationID       uuid.UUID `json:"invitationID"`
	AuthorizationToken string    `json:"authorizationToken"`
}

type sharedSpaceInvitationCreateInput struct {
	Version                     int                                `json:"version"`
	RetryID                     uuid.UUID                          `json:"retryID"`
	ParticipantID               uuid.UUID                          `json:"participantID"`
	SubscriptionID              uuid.UUID                          `json:"subscriptionID"`
	Kind                        sharedspaces.ParticipantKind       `json:"kind"`
	Role                        sharedspaces.Role                  `json:"role"`
	InteractionMode             sharedspaces.InteractionMode       `json:"interactionMode"`
	ParticipantSigningKey       sharedspaces.ParticipantSigningKey `json:"participantSigningKey"`
	KeyGrant                    *sharedspaces.ParticipantKeyGrant  `json:"keyGrant,omitempty"`
	InvitationCredential        sharedSpaceInvitationCredential    `json:"invitationCredential"`
	ExpiresAtMilliseconds       int64                              `json:"expiresAtMilliseconds"`
	MemberExpiresAtMilliseconds *int64                             `json:"memberExpiresAtMilliseconds,omitempty"`
	CreatedAtMilliseconds       int64                              `json:"createdAtMilliseconds"`
}

type sharedSpaceInvitationClaimInput struct {
	Version               int                   `json:"version"`
	ParticipantID         uuid.UUID             `json:"participantID"`
	MemberCredential      relayMemberCredential `json:"memberCredential"`
	ClaimedAtMilliseconds int64                 `json:"claimedAtMilliseconds"`
}

func (s *Server) handleProvisionSharedSpace(writer http.ResponseWriter, request *http.Request) {
	if err := s.authorizeOperator(request); err != nil {
		s.writeError(writer, err)
		return
	}
	var input sharedSpaceProvisioningInput
	if err := readSharedSpacesJSON(writer, request, &input); err != nil {
		s.writeError(writer, err)
		return
	}
	if input.Version != sharedspaces.SchemaVersion {
		s.writeError(writer, sharedspaces.NewProtocolError(
			sharedspaces.CodeInvalidSpace, "Shared Space provisioning version is invalid",
		))
		return
	}
	tenant, domain, err := relayTenantAndDomainProvisioning(input.TenantProvisioning)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	provisioning := sharedspaces.SpaceProvisioning{
		Version: sharedspaces.SchemaVersion, RetryID: input.RetryID,
		SpaceID: input.SpaceID, SecurityMode: input.SecurityMode,
		InteractionMode:              input.InteractionMode,
		InitialParticipantID:         input.InitialParticipantID,
		InitialParticipantKind:       input.InitialParticipantKind,
		InitialParticipantSigningKey: input.InitialParticipantSigningKey,
		Tenant:                       tenant, Domain: domain,
		CreatedAtMilliseconds: tenant.CreatedAtMilliseconds,
	}
	result, err := s.sharedSpacesStore.ProvisionSpace(
		request.Context(), provisioning, s.nowMilliseconds(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(traffic.SurfaceManagement, string(result.Acceptance))
	writeJSON(writer, relayAcceptanceStatus(result.Acceptance), result)
}

func (s *Server) handleGetSharedSpaceStatus(writer http.ResponseWriter, request *http.Request) {
	spaceID, domainID, err := sharedSpacesScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayAdministrationCredentialFromRequest(request, spaceID, domainID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	status, err := s.sharedSpacesStore.GetSpaceStatus(request.Context(), credential)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, status)
}

func (s *Server) handleListSharedSpaceAuthorityEvents(writer http.ResponseWriter, request *http.Request) {
	spaceID, domainID, err := sharedSpacesScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayAdministrationCredentialFromRequest(request, spaceID, domainID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	afterSequence := uint64(0)
	if raw := request.URL.Query().Get("afterSequence"); raw != "" {
		afterSequence, err = strconv.ParseUint(raw, 10, 64)
		if err != nil {
			s.writeError(writer, sharedspaces.NewProtocolError(
				sharedspaces.CodeInvalidAuthorityEvent,
				"Shared Space authority event cursor is invalid",
			))
			return
		}
	}
	limit := 50
	if raw := request.URL.Query().Get("limit"); raw != "" {
		limit, err = strconv.Atoi(raw)
		if err != nil {
			s.writeError(writer, sharedspaces.NewProtocolError(
				sharedspaces.CodeInvalidAuthorityEvent,
				"Shared Space authority event page size is invalid",
			))
			return
		}
	}
	page, err := s.sharedSpacesStore.ListAuthorityEvents(
		request.Context(), credential, afterSequence, limit,
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, page)
}

func (s *Server) handleChangeSharedSpaceComputePool(writer http.ResponseWriter, request *http.Request) {
	spaceID, domainID, err := sharedSpacesScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	poolID, err := parseSharedSpacesUUID(request.PathValue("poolID"))
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayAdministrationCredentialFromRequest(request, spaceID, domainID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	var change sharedspaces.ComputePoolChange
	if err := readSharedSpacesJSON(writer, request, &change); err != nil {
		s.writeError(writer, err)
		return
	}
	if change.SpaceID != spaceID || change.PoolID != poolID {
		s.writeError(writer, sharedspaces.NewProtocolError(
			sharedspaces.CodeWrongScope,
			"Shared Space compute pool body and path differ",
		))
		return
	}
	result, err := s.sharedSpacesStore.ChangeComputePool(
		request.Context(), credential, change, s.nowMilliseconds(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(traffic.SurfaceManagement, string(result.Acceptance))
	writeJSON(writer, relayAcceptanceStatus(result.Acceptance), result)
}

func (s *Server) handleGetSharedSpaceComputeCapabilityVerificationKey(
	writer http.ResponseWriter,
	_ *http.Request,
) {
	writeJSON(
		writer,
		http.StatusOK,
		s.sharedSpacesComputeCapabilitySigner.VerificationKey(),
	)
}

func (s *Server) handleIssueSharedSpaceComputeCapability(
	writer http.ResponseWriter,
	request *http.Request,
) {
	spaceID, domainID, err := sharedSpacesScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	participantID, err := parseSharedSpacesUUID(request.PathValue("participantID"))
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayCredentialFromRequest(request, spaceID, domainID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	if credential.MemberID != participantID {
		s.writeError(writer, sharedspaces.NewProtocolError(
			sharedspaces.CodeWrongScope,
			"Shared Space compute capability participant and credential differ",
		))
		return
	}
	var capabilityRequest sharedspaces.ComputeCapabilityRequest
	if err := readSharedSpacesJSON(writer, request, &capabilityRequest); err != nil {
		s.writeError(writer, err)
		return
	}
	if capabilityRequest.SpaceID != spaceID {
		s.writeError(writer, sharedspaces.NewProtocolError(
			sharedspaces.CodeWrongScope,
			"Shared Space compute capability body and path differ",
		))
		return
	}
	authorization, err := s.sharedSpacesStore.AuthorizeComputeCapability(
		request.Context(), credential, capabilityRequest, s.nowMilliseconds(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	capability, err := s.sharedSpacesComputeCapabilitySigner.Issue(authorization)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, capability)
}

func (s *Server) handleCreateSharedSpaceInvitation(writer http.ResponseWriter, request *http.Request) {
	spaceID, domainID, err := sharedSpacesScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayAdministrationCredentialFromRequest(request, spaceID, domainID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	var input sharedSpaceInvitationCreateInput
	if err := readSharedSpacesJSON(writer, request, &input); err != nil {
		s.writeError(writer, err)
		return
	}
	if input.Version != sharedspaces.SchemaVersion {
		s.writeError(writer, sharedspaces.NewProtocolError(
			sharedspaces.CodeInvalidInvitation, "Shared Space invitation version is invalid",
		))
		return
	}
	invitationCredential := relay.AdmissionCredential{
		TenantID: spaceID, DomainID: domainID,
		AdmissionID: input.InvitationCredential.InvitationID,
		Token:       input.InvitationCredential.AuthorizationToken,
	}
	authorizationDigest, err := relay.AdmissionAuthorizationDigest(invitationCredential)
	if err != nil {
		s.writeError(writer, sharedspaces.NewProtocolError(
			sharedspaces.CodeInvalidInvitation, err.Error(),
		))
		return
	}
	invitation := sharedspaces.Invitation{
		Version: sharedspaces.SchemaVersion, RetryID: input.RetryID,
		SpaceID: spaceID, InvitationID: invitationCredential.AdmissionID,
		ParticipantID: input.ParticipantID, SubscriptionID: input.SubscriptionID,
		Kind: input.Kind, Role: input.Role, InteractionMode: input.InteractionMode,
		ParticipantSigningKey: input.ParticipantSigningKey,
		KeyGrant:              input.KeyGrant,
		RelayAdmission: relay.MemberAdmission{
			Version: relay.SchemaVersion, TenantID: spaceID, DomainID: domainID,
			AdmissionID:                 invitationCredential.AdmissionID,
			AuthorizationDigest:         authorizationDigest,
			Capabilities:                input.Role.Capabilities(input.InteractionMode),
			CreatedAtMilliseconds:       input.CreatedAtMilliseconds,
			ExpiresAtMilliseconds:       input.ExpiresAtMilliseconds,
			MemberExpiresAtMilliseconds: input.MemberExpiresAtMilliseconds,
		},
		CreatedAtMilliseconds: input.CreatedAtMilliseconds,
	}
	result, err := s.sharedSpacesStore.CreateInvitation(
		request.Context(), credential, invitation, s.nowMilliseconds(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(traffic.SurfaceManagement, string(result.Acceptance))
	writeJSON(writer, relayAcceptanceStatus(result.Acceptance), result)
}

func (s *Server) handleListSharedSpaceInvitations(writer http.ResponseWriter, request *http.Request) {
	spaceID, domainID, err := sharedSpacesScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayAdministrationCredentialFromRequest(request, spaceID, domainID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	result, err := s.sharedSpacesStore.ListInvitations(
		request.Context(), credential, s.nowMilliseconds(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, result)
}

func (s *Server) handleClaimSharedSpaceInvitation(writer http.ResponseWriter, request *http.Request) {
	spaceID, domainID, err := sharedSpacesScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	invitationID, err := parseSharedSpacesUUID(request.PathValue("invitationID"))
	if err != nil {
		s.writeError(writer, err)
		return
	}
	invitationToken, err := bearerToken(request)
	if err != nil {
		s.writeError(writer, sharedspaces.NewProtocolError(
			sharedspaces.CodeUnauthorized, "Shared Space invitation credential is missing",
		))
		return
	}
	var input sharedSpaceInvitationClaimInput
	if err := readSharedSpacesJSON(writer, request, &input); err != nil {
		s.writeError(writer, err)
		return
	}
	if input.Version != sharedspaces.SchemaVersion || input.MemberCredential.TenantID != spaceID ||
		input.MemberCredential.DomainID != domainID || input.MemberCredential.MemberID != input.ParticipantID {
		s.writeError(writer, sharedspaces.NewProtocolError(
			sharedspaces.CodeWrongScope, "Shared Space invitation claim path and body differ",
		))
		return
	}
	memberCredential := relay.Credential{
		TenantID: spaceID, DomainID: domainID, MemberID: input.ParticipantID,
		Token: input.MemberCredential.AuthorizationToken,
	}
	memberDigest, err := relay.AuthorizationDigest(memberCredential)
	if err != nil {
		s.writeError(writer, sharedspaces.NewProtocolError(
			sharedspaces.CodeInvalidParticipant, err.Error(),
		))
		return
	}
	claim := sharedspaces.InvitationClaim{
		Version: sharedspaces.SchemaVersion, SpaceID: spaceID,
		ParticipantID: input.ParticipantID,
		RelayClaim: relay.MemberAdmissionClaim{
			MemberID: input.ParticipantID, AuthorizationDigest: memberDigest,
		},
		ClaimedAtMilliseconds: input.ClaimedAtMilliseconds,
	}
	result, err := s.sharedSpacesStore.ClaimInvitation(
		request.Context(),
		sharedspaces.InvitationCredential{
			SpaceID: spaceID, DomainID: domainID,
			InvitationID: invitationID, Token: invitationToken,
		},
		claim, s.nowMilliseconds(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(traffic.SurfaceManagement, string(result.Acceptance))
	writeJSON(writer, relayAcceptanceStatus(result.Acceptance), result)
}

func (s *Server) handleCancelSharedSpaceInvitation(writer http.ResponseWriter, request *http.Request) {
	spaceID, domainID, err := sharedSpacesScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	invitationID, err := parseSharedSpacesUUID(request.PathValue("invitationID"))
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayAdministrationCredentialFromRequest(request, spaceID, domainID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	var cancellation sharedspaces.InvitationCancellation
	if err := readSharedSpacesJSON(writer, request, &cancellation); err != nil {
		s.writeError(writer, err)
		return
	}
	if cancellation.SpaceID != spaceID || cancellation.InvitationID != invitationID {
		s.writeError(writer, sharedspaces.NewProtocolError(
			sharedspaces.CodeWrongScope, "Shared Space invitation cancellation path and body differ",
		))
		return
	}
	result, err := s.sharedSpacesStore.CancelInvitation(
		request.Context(), credential, cancellation, s.nowMilliseconds(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(traffic.SurfaceManagement, string(result.Acceptance))
	writeJSON(writer, relayAcceptanceStatus(result.Acceptance), result)
}

func (s *Server) handleChangeSharedSpaceParticipantRole(writer http.ResponseWriter, request *http.Request) {
	spaceID, domainID, err := sharedSpacesScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	participantID, err := parseSharedSpacesUUID(request.PathValue("participantID"))
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayAdministrationCredentialFromRequest(request, spaceID, domainID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	var change sharedspaces.ParticipantRoleChange
	if err := readSharedSpacesJSON(writer, request, &change); err != nil {
		s.writeError(writer, err)
		return
	}
	if change.SpaceID != spaceID || change.ParticipantID != participantID {
		s.writeError(writer, sharedspaces.NewProtocolError(
			sharedspaces.CodeWrongScope, "Shared Space participant role path and body differ",
		))
		return
	}
	result, err := s.sharedSpacesStore.ChangeParticipantRole(
		request.Context(), credential, change, s.nowMilliseconds(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(traffic.SurfaceManagement, string(result.Acceptance))
	writeJSON(writer, relayAcceptanceStatus(result.Acceptance), result)
}

func (s *Server) handleRevokeSharedSpaceParticipant(writer http.ResponseWriter, request *http.Request) {
	spaceID, domainID, err := sharedSpacesScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	participantID, err := parseSharedSpacesUUID(request.PathValue("participantID"))
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayAdministrationCredentialFromRequest(request, spaceID, domainID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	var revocation sharedspaces.ParticipantRevocation
	if err := readSharedSpacesJSON(writer, request, &revocation); err != nil {
		s.writeError(writer, err)
		return
	}
	if revocation.SpaceID != spaceID || revocation.ParticipantID != participantID {
		s.writeError(writer, sharedspaces.NewProtocolError(
			sharedspaces.CodeWrongScope, "Shared Space participant revocation path and body differ",
		))
		return
	}
	result, err := s.sharedSpacesStore.RevokeParticipant(
		request.Context(), credential, revocation, s.nowMilliseconds(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(traffic.SurfaceManagement, string(result.Acceptance))
	writeJSON(writer, relayAcceptanceStatus(result.Acceptance), result)
}

func (s *Server) handleGetSharedSpaceParticipantKeyGrant(writer http.ResponseWriter, request *http.Request) {
	spaceID, domainID, err := sharedSpacesScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	participantID, err := parseSharedSpacesUUID(request.PathValue("participantID"))
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayCredentialFromRequest(request, spaceID, domainID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	if credential.MemberID != participantID {
		s.writeError(writer, sharedspaces.NewProtocolError(
			sharedspaces.CodeWrongScope, "Shared Space participant key grant path and credential differ",
		))
		return
	}
	result, err := s.sharedSpacesStore.GetParticipantKeyGrant(
		request.Context(), credential, s.nowMilliseconds(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, result)
}

func (s *Server) handleGetSharedSpaceParticipantStatus(writer http.ResponseWriter, request *http.Request) {
	spaceID, domainID, err := sharedSpacesScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	participantID, err := parseSharedSpacesUUID(request.PathValue("participantID"))
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayCredentialFromRequest(request, spaceID, domainID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	if credential.MemberID != participantID {
		s.writeError(writer, sharedspaces.NewProtocolError(
			sharedspaces.CodeWrongScope, "Shared Space participant status path and credential differ",
		))
		return
	}
	result, err := s.sharedSpacesStore.GetParticipantStatus(
		request.Context(), credential, s.nowMilliseconds(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, result)
}

func (s *Server) handleGetSharedSpaceParticipantRoster(writer http.ResponseWriter, request *http.Request) {
	spaceID, domainID, err := sharedSpacesScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	participantID, err := parseSharedSpacesUUID(request.PathValue("participantID"))
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayCredentialFromRequest(request, spaceID, domainID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	if credential.MemberID != participantID {
		s.writeError(writer, sharedspaces.NewProtocolError(
			sharedspaces.CodeWrongScope, "Shared Space participant roster path and credential differ",
		))
		return
	}
	result, err := s.sharedSpacesStore.GetParticipantRoster(
		request.Context(), credential, s.nowMilliseconds(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, result)
}

func (s *Server) handleUpdateSharedSpaceParticipantPresentation(
	writer http.ResponseWriter,
	request *http.Request,
) {
	spaceID, domainID, err := sharedSpacesScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	participantID, err := parseSharedSpacesUUID(request.PathValue("participantID"))
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayCredentialFromRequest(request, spaceID, domainID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	if credential.MemberID != participantID {
		s.writeError(writer, sharedspaces.NewProtocolError(
			sharedspaces.CodeWrongScope,
			"Shared Space participant presentation path and credential differ",
		))
		return
	}
	var update sharedspaces.ParticipantPresentationUpdate
	if err := readSharedSpacesJSON(writer, request, &update); err != nil {
		s.writeError(writer, err)
		return
	}
	if update.SpaceID != spaceID || update.ParticipantID != participantID {
		s.writeError(writer, sharedspaces.NewProtocolError(
			sharedspaces.CodeWrongScope,
			"Shared Space participant presentation body and path differ",
		))
		return
	}
	result, err := s.sharedSpacesStore.UpdateParticipantPresentation(
		request.Context(), credential, update, s.nowMilliseconds(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(traffic.SurfaceManagement, string(result.Acceptance))
	writeJSON(writer, relayAcceptanceStatus(result.Acceptance), result)
}

func (s *Server) handleGetSharedSpaceParticipantBootstrap(writer http.ResponseWriter, request *http.Request) {
	spaceID, domainID, err := sharedSpacesScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	participantID, err := parseSharedSpacesUUID(request.PathValue("participantID"))
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayCredentialFromRequest(request, spaceID, domainID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	if credential.MemberID != participantID {
		s.writeError(writer, sharedspaces.NewProtocolError(
			sharedspaces.CodeWrongScope, "Shared Space participant bootstrap path and credential differ",
		))
		return
	}
	result, err := s.sharedSpacesStore.GetParticipantBootstrap(
		request.Context(), credential, s.nowMilliseconds(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, result)
}

func readSharedSpacesJSON(writer http.ResponseWriter, request *http.Request, destination any) error {
	return decodeJSONWithLimit(
		writer, request, destination, maximumRequestByteCount,
		func(message string) error {
			return sharedspaces.NewProtocolError(sharedspaces.CodeInvalidSpace, message)
		},
	)
}

func sharedSpacesScopeFromPath(request *http.Request) (uuid.UUID, uuid.UUID, error) {
	spaceID, err := parseSharedSpacesUUID(request.PathValue("spaceID"))
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	domainID, err := parseSharedSpacesUUID(request.PathValue("domainID"))
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	return spaceID, domainID, nil
}

func parseSharedSpacesUUID(value string) (uuid.UUID, error) {
	identifier, err := uuid.Parse(value)
	if err != nil || identifier == uuid.Nil {
		return uuid.Nil, sharedspaces.NewProtocolError(
			sharedspaces.CodeWrongScope, "Shared Space identifier is invalid",
		)
	}
	return identifier, nil
}
