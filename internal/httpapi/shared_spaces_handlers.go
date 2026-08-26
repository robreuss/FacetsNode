package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
	"github.com/robreuss/FacetsNode/internal/sharedspaces"
	"github.com/robreuss/FacetsNode/internal/traffic"
)

var sharedSpaceProvisioningClaimDigestDomain = []byte(
	"Facets Shared Space provisioning claim v1\x00",
)

type sharedSpaceProvisioningAdmissionCredentialInput struct {
	AdmissionID        uuid.UUID `json:"admissionID"`
	AuthorizationToken string    `json:"authorizationToken"`
}

type sharedSpaceProvisioningAdmissionCreateInput struct {
	Version               int                                             `json:"version"`
	RetryID               uuid.UUID                                       `json:"retryID"`
	AdmissionCredential   sharedSpaceProvisioningAdmissionCredentialInput `json:"admissionCredential"`
	ExpiresAtMilliseconds int64                                           `json:"expiresAtMilliseconds"`
}

type sharedSpaceProvisioningInput struct {
	Version                        int                                   `json:"version"`
	RetryID                        uuid.UUID                             `json:"retryID"`
	SpaceID                        uuid.UUID                             `json:"spaceID"`
	SecurityMode                   sharedspaces.SecurityMode             `json:"securityMode"`
	InteractionMode                sharedspaces.InteractionMode          `json:"interactionMode"`
	InitialParticipantID           uuid.UUID                             `json:"initialParticipantID"`
	InitialParticipantKind         sharedspaces.ParticipantKind          `json:"initialParticipantKind"`
	InitialParticipantSigningKey   sharedspaces.ParticipantSigningKey    `json:"initialParticipantSigningKey"`
	InitialParticipantDeviceKeys   []sharedspaces.ParticipantDeviceKey   `json:"initialParticipantDeviceKeys"`
	InitialSecureRosterAttestation *sharedspaces.SecureRosterAttestation `json:"initialSecureRosterAttestation,omitempty"`
	ServiceAuthorityEnrollment     *serviceauthority.InitialEnrollment   `json:"serviceAuthorityEnrollment,omitempty"`
	TenantProvisioning             relayTenantProvisioningInput          `json:"tenantProvisioning"`
}

type sharedSpaceInvitationCredential struct {
	InvitationID       uuid.UUID `json:"invitationID"`
	AuthorizationToken string    `json:"authorizationToken"`
}

type sharedSpaceInvitationCreateInput struct {
	Version                           int                                   `json:"version"`
	RetryID                           uuid.UUID                             `json:"retryID"`
	ParticipantID                     uuid.UUID                             `json:"participantID"`
	SubscriptionID                    uuid.UUID                             `json:"subscriptionID"`
	Kind                              sharedspaces.ParticipantKind          `json:"kind"`
	Role                              sharedspaces.Role                     `json:"role"`
	InteractionMode                   sharedspaces.InteractionMode          `json:"interactionMode"`
	ParticipantSigningKey             sharedspaces.ParticipantSigningKey    `json:"participantSigningKey"`
	ParticipantDeviceKeys             []sharedspaces.ParticipantDeviceKey   `json:"participantDeviceKeys"`
	KeyGrant                          *sharedspaces.ParticipantKeyGrant     `json:"keyGrant,omitempty"`
	ActivationSecureRosterAttestation *sharedspaces.SecureRosterAttestation `json:"activationSecureRosterAttestation,omitempty"`
	InvitationCredential              sharedSpaceInvitationCredential       `json:"invitationCredential"`
	ExpiresAtMilliseconds             int64                                 `json:"expiresAtMilliseconds"`
	MemberExpiresAtMilliseconds       *int64                                `json:"memberExpiresAtMilliseconds,omitempty"`
	CreatedAtMilliseconds             int64                                 `json:"createdAtMilliseconds"`
}

type sharedSpaceInvitationClaimInput struct {
	Version               int                   `json:"version"`
	ParticipantID         uuid.UUID             `json:"participantID"`
	MemberCredential      relayMemberCredential `json:"memberCredential"`
	ClaimedAtMilliseconds int64                 `json:"claimedAtMilliseconds"`
}

func (s *Server) handleCreateSharedSpaceProvisioningAdmission(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if err := s.authorizeOperator(request); err != nil {
		s.writeError(writer, err)
		return
	}
	var input sharedSpaceProvisioningAdmissionCreateInput
	if err := readSharedSpacesJSON(writer, request, &input); err != nil {
		s.writeError(writer, err)
		return
	}
	credential := sharedspaces.ProvisioningAdmissionCredential{
		AdmissionID: input.AdmissionCredential.AdmissionID,
		Token:       input.AdmissionCredential.AuthorizationToken,
	}
	digest, err := sharedspaces.ProvisioningAdmissionAuthorizationDigest(
		credential,
	)
	if err != nil || input.Version != sharedspaces.SchemaVersion {
		s.writeError(writer, sharedspaces.NewProtocolError(
			sharedspaces.CodeInvalidProvisioningAdmission,
			"Shared Space provisioning admission input is invalid",
		))
		return
	}
	now := s.nowMilliseconds()
	admission := sharedspaces.ProvisioningAdmission{
		Version: sharedspaces.SchemaVersion, RetryID: input.RetryID,
		AdmissionID: credential.AdmissionID, AuthorizationDigest: digest,
		CreatedAtMilliseconds: now,
		ExpiresAtMilliseconds: input.ExpiresAtMilliseconds,
	}
	result, err := s.sharedSpacesStore.CreateProvisioningAdmission(
		request.Context(), admission, now,
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(
		traffic.SurfaceManagement, string(result.Acceptance),
	)
	writeJSON(writer, relayAcceptanceStatus(result.Acceptance), result)
}

func (s *Server) handleClaimSharedSpaceProvisioningAdmission(
	writer http.ResponseWriter,
	request *http.Request,
) {
	admissionID, err := parseUUID(request.PathValue("admissionID"))
	if err != nil {
		s.writeError(writer, sharedspaces.NewProtocolError(
			sharedspaces.CodeInvalidProvisioningAdmission, err.Error(),
		))
		return
	}
	token, err := bearerToken(request)
	if err != nil {
		s.writeError(writer, sharedspaces.NewProtocolError(
			sharedspaces.CodeUnauthorized,
			"Shared Space provisioning admission credential is missing",
		))
		return
	}
	var input sharedSpaceProvisioningInput
	if err := readSharedSpacesJSON(writer, request, &input); err != nil {
		s.writeError(writer, err)
		return
	}
	now := s.nowMilliseconds()
	if err := s.validateSharedSpaceProvisioningInput(input, now); err != nil {
		if errors.Is(err, serviceauthority.ErrInvalid) {
			writeServiceAuthorityError(writer, http.StatusConflict)
		} else {
			s.writeError(writer, err)
		}
		return
	}
	requestDigest, err := sharedSpaceProvisioningClaimDigest(input)
	if err != nil {
		s.writeError(writer, sharedspaces.NewProtocolError(
			sharedspaces.CodeInvalidProvisioningAdmission,
			"Shared Space provisioning claim could not be canonicalized",
		))
		return
	}
	_, err = s.sharedSpacesStore.ClaimProvisioningAdmission(
		request.Context(),
		sharedspaces.ProvisioningAdmissionCredential{
			AdmissionID: admissionID, Token: token,
		},
		sharedspaces.ProvisioningAdmissionClaim{
			Version: sharedspaces.SchemaVersion, SpaceID: input.SpaceID,
			RequestDigest: requestDigest, ClaimedAtMilliseconds: now,
		},
		now,
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.provisionSharedSpace(writer, request, input, now)
}

func sharedSpaceProvisioningClaimDigest(
	input sharedSpaceProvisioningInput,
) (string, error) {
	canonical, err := json.Marshal(input)
	if err != nil {
		return "", err
	}
	digest := sha256.New()
	_, _ = digest.Write(sharedSpaceProvisioningClaimDigestDomain)
	_, _ = digest.Write(canonical)
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func (s *Server) validateSharedSpaceProvisioningInput(
	input sharedSpaceProvisioningInput,
	nowMilliseconds int64,
) error {
	if input.Version != sharedspaces.SchemaVersion {
		return sharedspaces.NewProtocolError(
			sharedspaces.CodeInvalidSpace,
			"Shared Space provisioning version is invalid",
		)
	}
	tenant, domain, err := relayTenantAndDomainProvisioning(
		input.TenantProvisioning,
	)
	if err != nil {
		return err
	}
	provisioning := sharedspaces.SpaceProvisioning{
		Version: sharedspaces.SchemaVersion, RetryID: input.RetryID,
		SpaceID: input.SpaceID, SecurityMode: input.SecurityMode,
		InteractionMode:                input.InteractionMode,
		InitialParticipantID:           input.InitialParticipantID,
		InitialParticipantKind:         input.InitialParticipantKind,
		InitialParticipantSigningKey:   input.InitialParticipantSigningKey,
		InitialParticipantDeviceKeys:   input.InitialParticipantDeviceKeys,
		InitialSecureRosterAttestation: input.InitialSecureRosterAttestation,
		Tenant:                         tenant, Domain: domain,
		CreatedAtMilliseconds: tenant.CreatedAtMilliseconds,
	}
	if err := provisioning.Validate(); err != nil {
		return err
	}
	if s.deploymentSigner != nil && s.serviceAuthorityBindings != nil {
		if input.ServiceAuthorityEnrollment == nil {
			return serviceauthority.ErrInvalid
		}
		scope := serviceauthority.Scope{
			Kind: serviceauthority.ScopeSharedSpace, ScopeID: input.SpaceID,
		}
		if _, err := sharedspaces.NewInitialServiceAuthorityBinding(
			*input.ServiceAuthorityEnrollment, s.deploymentSigner,
			scope, nowMilliseconds,
		); err != nil {
			return err
		}
		if _, ok := s.sharedSpacesStore.(sharedspaces.AuthorityBoundStore); !ok {
			return serviceauthority.ErrInvalid
		}
	} else if input.ServiceAuthorityEnrollment != nil {
		return serviceauthority.ErrInvalid
	}
	return nil
}

func (s *Server) provisionSharedSpace(
	writer http.ResponseWriter,
	request *http.Request,
	input sharedSpaceProvisioningInput,
	now int64,
) {
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
		InteractionMode:                input.InteractionMode,
		InitialParticipantID:           input.InitialParticipantID,
		InitialParticipantKind:         input.InitialParticipantKind,
		InitialParticipantSigningKey:   input.InitialParticipantSigningKey,
		InitialParticipantDeviceKeys:   input.InitialParticipantDeviceKeys,
		InitialSecureRosterAttestation: input.InitialSecureRosterAttestation,
		Tenant:                         tenant, Domain: domain,
		CreatedAtMilliseconds: tenant.CreatedAtMilliseconds,
	}
	var authorityBinding *serviceauthority.CurrentBinding
	var initialAuthority *sharedspaces.InitialServiceAuthorityBinding
	var authorityStore sharedspaces.AuthorityBoundStore
	if s.deploymentSigner != nil && s.serviceAuthorityBindings != nil {
		if input.ServiceAuthorityEnrollment == nil {
			writeServiceAuthorityError(writer, http.StatusConflict)
			return
		}
		scope := serviceauthority.Scope{
			Kind: serviceauthority.ScopeSharedSpace, ScopeID: input.SpaceID,
		}
		var bindingErr error
		initialAuthority, bindingErr = sharedspaces.NewInitialServiceAuthorityBinding(
			*input.ServiceAuthorityEnrollment, s.deploymentSigner, scope, now,
		)
		var storeSupportsAuthority bool
		authorityStore, storeSupportsAuthority =
			s.sharedSpacesStore.(sharedspaces.AuthorityBoundStore)
		if bindingErr != nil || !storeSupportsAuthority {
			writeServiceAuthorityError(writer, http.StatusConflict)
			return
		}
		manifest := initialAuthority.Manifest()
		authorityBinding = &serviceauthority.CurrentBinding{
			Revision:     initialAuthority.Revision(),
			Digest:       initialAuthority.ManifestDigest(),
			DeploymentID: initialAuthority.LocalDeploymentID(),
			Manifest:     &manifest,
		}
	} else if input.ServiceAuthorityEnrollment != nil {
		writeServiceAuthorityError(writer, http.StatusConflict)
		return
	}
	var result sharedspaces.SpaceProvisioningResult
	if initialAuthority == nil {
		result, err = s.sharedSpacesStore.ProvisionSpace(
			request.Context(), provisioning, now,
		)
	} else {
		result, err = authorityStore.ProvisionSpaceWithAuthority(
			request.Context(), provisioning, initialAuthority, now,
		)
	}
	if err != nil {
		s.writeError(writer, err)
		return
	}
	if authorityBinding != nil {
		scope := serviceauthority.Scope{
			Kind: serviceauthority.ScopeSharedSpace, ScopeID: input.SpaceID,
		}
		if err := s.serviceAuthorityBindings.Activate(scope, *authorityBinding); err != nil {
			writeSharedSpaceBindingActivationError(writer, err)
			return
		}
		if err := authorityStore.ActivateBoundSharedSpaceScope(
			request.Context(), input.SpaceID,
			initialAuthority.LocalDeploymentID(), initialAuthority.Revision(),
			initialAuthority.ManifestDigest(), now,
		); err != nil {
			if errors.Is(err, sharedspaces.ErrInitialServiceAuthorityConflict) ||
				errors.Is(err, serviceauthority.ErrInvalid) {
				writeServiceAuthorityError(writer, http.StatusConflict)
			} else {
				writeSharedSpaceAuthorityUnavailable(writer)
			}
			return
		}
	}
	s.metrics.ObserveAcceptance(traffic.SurfaceManagement, string(result.Acceptance))
	writeJSON(writer, relayAcceptanceStatus(result.Acceptance), result)
}

func writeSharedSpaceBindingActivationError(writer http.ResponseWriter, err error) {
	if errors.Is(err, serviceauthority.ErrBindingUnavailable) {
		writeSharedSpaceAuthorityUnavailable(writer)
	} else if errors.Is(err, serviceauthority.ErrBindingConflict) ||
		errors.Is(err, serviceauthority.ErrInvalid) {
		writeServiceAuthorityError(writer, http.StatusConflict)
	} else {
		writeSharedSpaceAuthorityUnavailable(writer)
	}
}

func writeSharedSpaceAuthorityUnavailable(writer http.ResponseWriter) {
	writeJSON(writer, http.StatusServiceUnavailable, map[string]string{
		"code":    "shared_space_authority_unavailable",
		"message": "Shared Space authority custody is temporarily unavailable.",
	})
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

func (s *Server) handleChangeSharedSpaceComputeBinding(writer http.ResponseWriter, request *http.Request) {
	spaceID, domainID, err := sharedSpacesScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	bindingID, err := parseSharedSpacesUUID(request.PathValue("bindingID"))
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayAdministrationCredentialFromRequest(request, spaceID, domainID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	var change sharedspaces.SpaceComputeBindingChange
	if err := readSharedSpacesJSON(writer, request, &change); err != nil {
		s.writeError(writer, err)
		return
	}
	if change.SpaceID != spaceID || change.BindingID != bindingID {
		s.writeError(writer, sharedspaces.NewProtocolError(
			sharedspaces.CodeWrongScope,
			"Shared Space compute binding body and path differ",
		))
		return
	}
	result, err := s.sharedSpacesStore.ChangeComputeBinding(
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
		ParticipantSigningKey:             input.ParticipantSigningKey,
		ParticipantDeviceKeys:             input.ParticipantDeviceKeys,
		KeyGrant:                          input.KeyGrant,
		ActivationSecureRosterAttestation: input.ActivationSecureRosterAttestation,
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

func (s *Server) handleEnrollSharedSpaceParticipantDevice(writer http.ResponseWriter, request *http.Request) {
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
	deviceID, err := parseSharedSpacesUUID(request.PathValue("deviceID"))
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayAdministrationCredentialFromRequest(request, spaceID, domainID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	var enrollment sharedspaces.ParticipantDeviceEnrollment
	if err := readSharedSpacesJSON(writer, request, &enrollment); err != nil {
		s.writeError(writer, err)
		return
	}
	if enrollment.SpaceID != spaceID || enrollment.ParticipantID != participantID ||
		enrollment.DeviceKey.DeviceID != deviceID {
		s.writeError(writer, sharedspaces.NewProtocolError(
			sharedspaces.CodeWrongScope, "Shared Space participant device enrollment path and body differ",
		))
		return
	}
	result, err := s.sharedSpacesStore.EnrollParticipantDevice(
		request.Context(), credential, enrollment, s.nowMilliseconds(),
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

func (s *Server) handleRevokeSharedSpaceParticipantDevice(writer http.ResponseWriter, request *http.Request) {
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
	deviceID, err := parseSharedSpacesUUID(request.PathValue("deviceID"))
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayAdministrationCredentialFromRequest(request, spaceID, domainID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	var revocation sharedspaces.ParticipantDeviceRevocation
	if err := readSharedSpacesJSON(writer, request, &revocation); err != nil {
		s.writeError(writer, err)
		return
	}
	if revocation.SpaceID != spaceID || revocation.ParticipantID != participantID ||
		revocation.DeviceID != deviceID {
		s.writeError(writer, sharedspaces.NewProtocolError(
			sharedspaces.CodeWrongScope, "Shared Space participant device revocation path and body differ",
		))
		return
	}
	result, err := s.sharedSpacesStore.RevokeParticipantDevice(
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
	recipientDeviceID, err := parseSharedSpacesUUID(request.URL.Query().Get("recipientDeviceID"))
	if err != nil {
		s.writeError(writer, err)
		return
	}
	result, err := s.sharedSpacesStore.GetParticipantKeyGrant(
		request.Context(), credential, recipientDeviceID, s.nowMilliseconds(),
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

func (s *Server) handleListSharedSpaceSecureRosterAttestations(
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
			"Shared Space roster authority path and credential differ",
		))
		return
	}
	afterRevision := uint64(0)
	if raw := request.URL.Query().Get("afterRevision"); raw != "" {
		afterRevision, err = strconv.ParseUint(raw, 10, 64)
		if err != nil {
			s.writeError(writer, sharedspaces.NewProtocolError(
				sharedspaces.CodeInvalidParticipant,
				"Secure Shared Space roster authority cursor is invalid",
			))
			return
		}
	}
	limit := 50
	if raw := request.URL.Query().Get("limit"); raw != "" {
		limit, err = strconv.Atoi(raw)
		if err != nil {
			s.writeError(writer, sharedspaces.NewProtocolError(
				sharedspaces.CodeInvalidParticipant,
				"Secure Shared Space roster authority page size is invalid",
			))
			return
		}
	}
	result, err := s.sharedSpacesStore.ListSecureRosterAttestations(
		request.Context(), credential, afterRevision, limit, s.nowMilliseconds(),
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
	recipientDeviceID, err := parseSharedSpacesUUID(request.URL.Query().Get("recipientDeviceID"))
	if err != nil {
		s.writeError(writer, err)
		return
	}
	result, err := s.sharedSpacesStore.GetParticipantBootstrap(
		request.Context(), credential, recipientDeviceID, s.nowMilliseconds(),
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
