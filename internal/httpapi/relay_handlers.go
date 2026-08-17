package httpapi

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"mime"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/traffic"
)

const maximumRelayRequestByteCount = ((relay.MaximumCiphertextByteCount + 2) / 3 * 4) + 32_768

const maximumRelayWakeWait = 25 * time.Second

var allRelayCapabilities = []relay.Capability{
	relay.CapabilityFetchBlob,
	relay.CapabilityPublishBlob,
	relay.CapabilityPublishCheckpoint,
	relay.CapabilityAcknowledgeMessage,
	relay.CapabilityFetchMessage,
	relay.CapabilityPublishMessage,
}

type relayAdministrationCredential struct {
	TenantID           uuid.UUID `json:"tenantID"`
	DomainID           uuid.UUID `json:"domainID"`
	AuthorizationToken string    `json:"authorizationToken"`
}

type relayMemberCredential struct {
	TenantID           uuid.UUID `json:"tenantID"`
	DomainID           uuid.UUID `json:"domainID"`
	MemberID           uuid.UUID `json:"memberID"`
	AuthorizationToken string    `json:"authorizationToken"`
}

type relayAdmissionCredential struct {
	TenantID           uuid.UUID `json:"tenantID"`
	DomainID           uuid.UUID `json:"domainID"`
	AdmissionID        uuid.UUID `json:"admissionID"`
	AuthorizationToken string    `json:"authorizationToken"`
}

type relayDomainProvisioningInput struct {
	Version                  int                           `json:"version"`
	RetryID                  uuid.UUID                     `json:"retryID"`
	AdministrationCredential relayAdministrationCredential `json:"administrationCredential"`
	SubscriptionID           uuid.UUID                     `json:"subscriptionID"`
	MemberCredential         relayMemberCredential         `json:"memberCredential"`
	MemberCapabilities       []relay.Capability            `json:"memberCapabilities"`
	CreatedAtMilliseconds    int64                         `json:"createdAtMilliseconds"`
}

type relayTenantCredential struct {
	TenantID           uuid.UUID `json:"tenantID"`
	AuthorizationToken string    `json:"authorizationToken"`
}

type relayTenantProvisioningInput struct {
	Version                      int                          `json:"version"`
	RetryID                      uuid.UUID                    `json:"retryID"`
	TenantProvisioningCredential relayTenantCredential        `json:"tenantProvisioningCredential"`
	InitialDomain                relayDomainProvisioningInput `json:"initialDomain"`
}

func (s *Server) handleProvisionRelayTenant(writer http.ResponseWriter, request *http.Request) {
	if err := s.authorizeOperator(request); err != nil {
		s.writeError(writer, err)
		return
	}
	var input relayTenantProvisioningInput
	if err := readRelayJSON(writer, request, &input, maximumRequestByteCount); err != nil {
		s.writeError(writer, err)
		return
	}
	tenantCredential := relay.TenantCredential{
		TenantID: input.TenantProvisioningCredential.TenantID,
		Token:    input.TenantProvisioningCredential.AuthorizationToken,
	}
	tenantDigest, err := relay.TenantAuthorizationDigest(tenantCredential)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	provisioning, err := relayDomainProvisioning(input.InitialDomain)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	if input.Version != relay.SchemaVersion || input.RetryID == uuid.Nil ||
		tenantCredential.TenantID != provisioning.Registration.TenantID {
		s.writeError(writer, relay.NewProtocolError(relay.CodeInvalidTenant, "tenant provisioning request is invalid"))
		return
	}
	tenant := relay.TenantRegistration{
		Version: relay.SchemaVersion, RetryID: input.RetryID,
		TenantID: tenantCredential.TenantID, AuthorizationDigest: tenantDigest,
		CreatedAtMilliseconds:            provisioning.Registration.CreatedAtMilliseconds,
		MaximumDomainCount:               relay.DefaultMaximumDomainCountPerTenant,
		MaximumAggregateMessageCount:     relay.DefaultMaximumMessageCountPerTenant,
		MaximumAggregateMessageByteCount: relay.DefaultMaximumMessageBytesPerTenant,
		MaximumAggregateBlobCount:        relay.DefaultMaximumBlobCountPerTenant,
		MaximumAggregateBlobByteCount:    relay.DefaultMaximumBlobBytesPerTenant,
	}
	result, err := s.relayStore.ProvisionTenant(request.Context(), tenant, provisioning)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(traffic.SurfaceManagement, string(result.Acceptance))
	writeJSON(writer, relayAcceptanceStatus(result.Acceptance), result)
}

func (s *Server) handleProvisionRelayDomain(writer http.ResponseWriter, request *http.Request) {
	tenantID, err := parseUUID(request.PathValue("tenantID"))
	if err != nil {
		s.writeError(writer, err)
		return
	}
	token, err := bearerToken(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	var input relayDomainProvisioningInput
	if err := readRelayJSON(writer, request, &input, maximumRequestByteCount); err != nil {
		s.writeError(writer, err)
		return
	}
	provisioning, err := relayDomainProvisioning(input)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	result, err := s.relayStore.ProvisionDomain(
		request.Context(), relay.TenantCredential{TenantID: tenantID, Token: token},
		provisioning, s.nowMilliseconds(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(traffic.SurfaceCheckpointAdmin, string(result.Acceptance))
	writeJSON(writer, relayAcceptanceStatus(result.Acceptance), result)
}

func relayDomainProvisioning(input relayDomainProvisioningInput) (relay.DomainProvisioning, error) {
	if input.AdministrationCredential.TenantID != input.MemberCredential.TenantID ||
		input.AdministrationCredential.DomainID != input.MemberCredential.DomainID {
		return relay.DomainProvisioning{}, relay.NewProtocolError(
			relay.CodeWrongScope,
			"initial member belongs to another domain",
		)
	}
	capabilities, err := normalizedCapabilities(input.MemberCapabilities)
	if err != nil {
		return relay.DomainProvisioning{}, err
	}
	administrationCredential := relay.AdministrationCredential{
		TenantID: input.AdministrationCredential.TenantID,
		DomainID: input.AdministrationCredential.DomainID,
		Token:    input.AdministrationCredential.AuthorizationToken,
	}
	administrationDigest, err := relay.AdministrationDigest(administrationCredential)
	if err != nil {
		return relay.DomainProvisioning{}, err
	}
	memberCredential := relay.Credential{
		TenantID: input.MemberCredential.TenantID,
		DomainID: input.MemberCredential.DomainID,
		MemberID: input.MemberCredential.MemberID,
		Token:    input.MemberCredential.AuthorizationToken,
	}
	memberDigest, err := relay.AuthorizationDigest(memberCredential)
	if err != nil {
		return relay.DomainProvisioning{}, err
	}
	domain := relay.DomainRegistration{
		Version:                 relay.SchemaVersion,
		TenantID:                administrationCredential.TenantID,
		DomainID:                administrationCredential.DomainID,
		AdministrationDigest:    administrationDigest,
		CreatedAtMilliseconds:   input.CreatedAtMilliseconds,
		MaximumMessageCount:     relay.DefaultMaximumMessageCount,
		MaximumMessageByteCount: relay.DefaultMaximumMessageByteCount,
		MaximumBlobCount:        relay.DefaultMaximumBlobCount,
		MaximumBlobByteCount:    relay.DefaultMaximumBlobByteCount,
	}
	member := relay.MemberRegistration{
		Version:               relay.SchemaVersion,
		TenantID:              memberCredential.TenantID,
		DomainID:              memberCredential.DomainID,
		MemberID:              memberCredential.MemberID,
		AuthorizationDigest:   memberDigest,
		Capabilities:          capabilities,
		CreatedAtMilliseconds: input.CreatedAtMilliseconds,
	}
	provisioning := relay.DomainProvisioning{
		Version: input.Version, RetryID: input.RetryID,
		Registration: domain,
		Subscription: relay.Subscription{
			Version: relay.SchemaVersion, TenantID: domain.TenantID,
			DomainID: domain.DomainID, SubscriptionID: input.SubscriptionID,
			Status:                relay.SubscriptionActive,
			CreatedAtMilliseconds: input.CreatedAtMilliseconds,
			UpdatedAtMilliseconds: input.CreatedAtMilliseconds,
		},
		InitialMember: member,
	}
	if err := provisioning.Validate(); err != nil {
		return relay.DomainProvisioning{}, err
	}
	return provisioning, nil
}

func (s *Server) handleRotateRelayTenantCredential(writer http.ResponseWriter, request *http.Request) {
	tenantID, err := parseUUID(request.PathValue("tenantID"))
	if err != nil {
		s.writeError(writer, err)
		return
	}
	rotationID, err := parseUUID(request.PathValue("rotationID"))
	if err != nil {
		s.writeError(writer, err)
		return
	}
	token, err := bearerToken(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	var rotation relay.TenantCredentialRotation
	if err := readRelayJSON(writer, request, &rotation, maximumRequestByteCount); err != nil {
		s.writeError(writer, err)
		return
	}
	if rotation.TenantID != tenantID || rotation.RotationID != rotationID {
		s.writeError(writer, relay.NewProtocolError(relay.CodeWrongScope, "tenant rotation path and body differ"))
		return
	}
	result, err := s.relayStore.RotateTenantCredential(
		request.Context(), relay.TenantCredential{TenantID: tenantID, Token: token}, rotation,
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(traffic.SurfaceCheckpointAdmin, string(result.Acceptance))
	writeJSON(writer, relayAcceptanceStatus(result.Acceptance), result)
}

func (s *Server) handleRelayTenantStatus(writer http.ResponseWriter, request *http.Request) {
	tenantID, err := parseUUID(request.PathValue("tenantID"))
	if err != nil {
		s.writeError(writer, err)
		return
	}
	token, err := bearerToken(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	status, err := s.relayStore.GetTenantStatus(
		request.Context(), relay.TenantCredential{TenantID: tenantID, Token: token},
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, status)
}

func (s *Server) handleCreateRelaySubscription(writer http.ResponseWriter, request *http.Request) {
	tenantID, domainID, err := relayScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayAdministrationCredentialFromRequest(request, tenantID, domainID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	var input relay.SubscriptionCreateRequest
	if err := readRelayJSON(writer, request, &input, maximumRequestByteCount); err != nil {
		s.writeError(writer, err)
		return
	}
	if input.CreatedAtMilliseconds > s.nowMilliseconds() {
		s.writeError(writer, relay.NewProtocolError(relay.CodeInvalidSubscription, "subscription creation is in the future"))
		return
	}
	result, err := s.relayStore.CreateSubscription(request.Context(), credential, input)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(traffic.SurfaceCheckpointAdmin, string(result.Acceptance))
	writeJSON(writer, relayAcceptanceStatus(result.Acceptance), result)
}

func (s *Server) handleGetRelaySubscription(writer http.ResponseWriter, request *http.Request) {
	tenantID, domainID, err := relayScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	subscriptionID, err := parseRelayUUID(request.PathValue("subscriptionID"))
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayAdministrationCredentialFromRequest(request, tenantID, domainID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	subscription, err := s.relayStore.GetSubscription(request.Context(), credential, subscriptionID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, subscription)
}

func (s *Server) handleChangeRelaySubscriptionStatus(writer http.ResponseWriter, request *http.Request) {
	tenantID, domainID, err := relayScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	subscriptionID, err := parseRelayUUID(request.PathValue("subscriptionID"))
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayAdministrationCredentialFromRequest(request, tenantID, domainID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	var input relay.SubscriptionStatusChangeRequest
	if err := readRelayJSON(writer, request, &input, maximumRequestByteCount); err != nil {
		s.writeError(writer, err)
		return
	}
	if input.ChangedAtMilliseconds > s.nowMilliseconds() {
		s.writeError(writer, relay.NewProtocolError(relay.CodeInvalidSubscription, "subscription status change is in the future"))
		return
	}
	result, err := s.relayStore.ChangeSubscriptionStatus(request.Context(), credential, subscriptionID, input)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(traffic.SurfaceCheckpointAdmin, string(result.Acceptance))
	writeJSON(writer, relayAcceptanceStatus(result.Acceptance), result)
}

func (s *Server) handleRelayDomainStatus(writer http.ResponseWriter, request *http.Request) {
	tenantID, domainID, err := relayScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayAdministrationCredentialFromRequest(request, tenantID, domainID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	status, err := s.relayStore.GetDomainStatus(request.Context(), credential)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, status)
}

func (s *Server) handleCreateRelayCheckpointFence(writer http.ResponseWriter, request *http.Request) {
	tenantID, domainID, err := relayScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayCredentialFromRequest(request, tenantID, domainID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	var input relay.CheckpointFenceRequest
	if err := readRelayJSON(writer, request, &input, maximumRequestByteCount); err != nil {
		s.writeError(writer, err)
		return
	}
	result, err := s.relayStore.CreateCheckpointFence(request.Context(), credential, input, s.nowMilliseconds())
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(traffic.SurfaceCheckpointAdmin, string(result.Acceptance))
	writeJSON(writer, relayAcceptanceStatus(result.Acceptance), result)
}

func (s *Server) handleGetRelayCheckpointFence(writer http.ResponseWriter, request *http.Request) {
	tenantID, domainID, err := relayScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	fenceID, err := parseRelayUUID(request.PathValue("fenceID"))
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayCredentialFromRequest(request, tenantID, domainID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	result, err := s.relayStore.GetCheckpointFence(request.Context(), credential, fenceID, s.nowMilliseconds())
	if err != nil {
		s.writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, result)
}

func (s *Server) handleAbortRelayCheckpointFence(writer http.ResponseWriter, request *http.Request) {
	tenantID, domainID, err := relayScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	fenceID, err := parseRelayUUID(request.PathValue("fenceID"))
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayCredentialFromRequest(request, tenantID, domainID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	var input relay.CheckpointFenceAbortRequest
	if err := readRelayJSON(writer, request, &input, maximumRequestByteCount); err != nil {
		s.writeError(writer, err)
		return
	}
	if input.FenceID != fenceID {
		s.writeError(writer, relay.NewProtocolError(relay.CodeWrongScope, "fence path and body differ"))
		return
	}
	result, err := s.relayStore.AbortCheckpointFence(request.Context(), credential, input, s.nowMilliseconds())
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(traffic.SurfaceCheckpointAdmin, string(result.Acceptance))
	writeJSON(writer, http.StatusOK, result)
}

func (s *Server) handleStageRelayCheckpoint(writer http.ResponseWriter, request *http.Request) {
	tenantID, domainID, err := relayScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayCredentialFromRequest(request, tenantID, domainID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	var candidate relay.CheckpointCandidate
	if err := readRelayJSON(writer, request, &candidate, maximumRelayRequestByteCount); err != nil {
		s.writeError(writer, err)
		return
	}
	if candidate.TenantID != tenantID || candidate.DomainID != domainID {
		s.writeError(writer, relay.NewProtocolError(relay.CodeWrongScope, "checkpoint path and body differ"))
		return
	}
	result, err := s.relayStore.StageCheckpoint(request.Context(), credential, candidate, s.nowMilliseconds())
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(traffic.SurfaceCheckpointAdmin, string(result.Acceptance))
	writeJSON(writer, relayAcceptanceStatus(result.Acceptance), result)
}

func (s *Server) handleActivateRelayCheckpoint(writer http.ResponseWriter, request *http.Request) {
	tenantID, domainID, checkpointID, credential, err := s.relayCheckpointAdministration(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	var input relay.CheckpointActivationRequest
	if err := readRelayJSON(writer, request, &input, maximumRequestByteCount); err != nil {
		s.writeError(writer, err)
		return
	}
	if input.CheckpointID != checkpointID {
		s.writeError(writer, relay.NewProtocolError(relay.CodeInvalidCheckpoint, "checkpoint activation path or time is invalid"))
		return
	}
	result, err := s.relayStore.ActivateCheckpoint(request.Context(), credential, input, s.nowMilliseconds())
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(traffic.SurfaceCheckpointAdmin, string(result.Acceptance))
	if result.Acceptance == relay.AcceptanceAccepted {
		s.notifyRelayWake(request.Context(), tenantID, domainID)
	}
	writeJSON(writer, relayAcceptanceStatus(result.Acceptance), result)
}

func (s *Server) handleDryRunRelayCheckpointCollection(writer http.ResponseWriter, request *http.Request) {
	_, _, checkpointID, credential, err := s.relayCheckpointAdministration(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	var input relay.CheckpointDryRunRequest
	if err := readRelayJSON(writer, request, &input, maximumRequestByteCount); err != nil {
		s.writeError(writer, err)
		return
	}
	if input.CheckpointID != checkpointID {
		s.writeError(writer, relay.NewProtocolError(relay.CodeWrongScope, "checkpoint path and body differ"))
		return
	}
	result, err := s.relayStore.DryRunCheckpointCollection(request.Context(), credential, input)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, result)
}

func (s *Server) handleCollectRelayCheckpoint(writer http.ResponseWriter, request *http.Request) {
	_, _, checkpointID, credential, err := s.relayCheckpointAdministration(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	var input relay.CheckpointCollectionRequest
	if err := readRelayJSON(writer, request, &input, maximumRequestByteCount); err != nil {
		s.writeError(writer, err)
		return
	}
	if input.CheckpointID != checkpointID || input.RequestedAtMilliseconds > s.nowMilliseconds() {
		s.writeError(writer, relay.NewProtocolError(relay.CodeInvalidCheckpoint, "checkpoint collection path or time is invalid"))
		return
	}
	result, err := s.relayStore.CollectCheckpoint(request.Context(), credential, input)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, result)
}

func (s *Server) relayCheckpointAdministration(request *http.Request) (uuid.UUID, uuid.UUID, uuid.UUID, relay.AdministrationCredential, error) {
	tenantID, domainID, err := relayScopeFromPath(request)
	if err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, relay.AdministrationCredential{}, err
	}
	checkpointID, err := parseRelayUUID(request.PathValue("checkpointID"))
	if err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, relay.AdministrationCredential{}, err
	}
	credential, err := relayAdministrationCredentialFromRequest(request, tenantID, domainID)
	return tenantID, domainID, checkpointID, credential, err
}

func (s *Server) handleCreateRelayMember(writer http.ResponseWriter, request *http.Request) {
	tenantID, domainID, err := relayScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayAdministrationCredentialFromRequest(
		request, tenantID, domainID,
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	var input struct {
		SubscriptionID        uuid.UUID          `json:"subscriptionID"`
		Capabilities          []relay.Capability `json:"capabilities"`
		ExpiresAtMilliseconds *int64             `json:"expiresAtMilliseconds,omitempty"`
	}
	if err := readRelayJSON(writer, request, &input, maximumRequestByteCount); err != nil {
		s.writeError(writer, err)
		return
	}
	capabilities, err := normalizedCapabilities(input.Capabilities)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	memberID := uuid.New()
	token, err := randomToken()
	if err != nil {
		s.writeError(writer, err)
		return
	}
	memberCredential := relay.Credential{
		TenantID: tenantID,
		DomainID: domainID,
		MemberID: memberID,
		Token:    token,
	}
	digest, err := relay.AuthorizationDigest(memberCredential)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	now := s.nowMilliseconds()
	registration := relay.MemberRegistration{
		Version:               relay.SchemaVersion,
		TenantID:              tenantID,
		DomainID:              domainID,
		MemberID:              memberID,
		AuthorizationDigest:   digest,
		Capabilities:          capabilities,
		CreatedAtMilliseconds: now,
		ExpiresAtMilliseconds: input.ExpiresAtMilliseconds,
	}
	acceptance, err := s.relayStore.CreateSubscriptionMember(
		request.Context(), credential, input.SubscriptionID, registration, now,
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(traffic.SurfaceCheckpointAdmin, string(acceptance))
	writeJSON(writer, http.StatusCreated, struct {
		Member     relay.SubscriptionMemberRegistration `json:"member"`
		Credential relayMemberCredential                `json:"credential"`
	}{
		Member: relay.SubscriptionMemberRegistration{
			SubscriptionID:     input.SubscriptionID,
			MemberRegistration: registration,
		},
		Credential: relayMemberCredential{
			TenantID:           tenantID,
			DomainID:           domainID,
			MemberID:           memberID,
			AuthorizationToken: token,
		},
	})
}

func (s *Server) handleRotateRelayAdministrationCredential(
	writer http.ResponseWriter,
	request *http.Request,
) {
	tenantID, domainID, err := relayScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	rotationID, err := parseRelayUUID(request.PathValue("rotationID"))
	if err != nil {
		s.writeError(writer, relay.NewProtocolError(
			relay.CodeInvalidCredentialRotation,
			"credential rotation identifier is invalid",
		))
		return
	}
	credential, err := relayAdministrationCredentialFromRequest(
		request, tenantID, domainID,
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	rotation, err := relayCredentialRotationFromRequest(writer, request, rotationID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	result, err := s.relayStore.RotateAdministrationCredential(
		request.Context(), credential, rotation, s.nowMilliseconds(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(traffic.SurfaceCheckpointAdmin, string(result.Acceptance))
	writeJSON(writer, relayAcceptanceStatus(result.Acceptance), result)
}

func (s *Server) handleRotateRelayMemberCredential(
	writer http.ResponseWriter,
	request *http.Request,
) {
	tenantID, domainID, err := relayScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	memberID, err := parseRelayUUID(request.PathValue("memberID"))
	if err != nil {
		s.writeError(writer, err)
		return
	}
	rotationID, err := parseRelayUUID(request.PathValue("rotationID"))
	if err != nil {
		s.writeError(writer, relay.NewProtocolError(
			relay.CodeInvalidCredentialRotation,
			"credential rotation identifier is invalid",
		))
		return
	}
	credential, err := relayCredentialFromRequest(request, tenantID, domainID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	if credential.MemberID != memberID {
		s.writeError(writer, relay.NewProtocolError(
			relay.CodeWrongScope,
			"member credential and path identifiers differ",
		))
		return
	}
	rotation, err := relayCredentialRotationFromRequest(writer, request, rotationID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	result, err := s.relayStore.RotateMemberCredential(
		request.Context(), credential, rotation, s.nowMilliseconds(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(traffic.SurfaceCheckpointAdmin, string(result.Acceptance))
	writeJSON(writer, relayAcceptanceStatus(result.Acceptance), result)
}

func relayCredentialRotationFromRequest(
	writer http.ResponseWriter,
	request *http.Request,
	rotationID uuid.UUID,
) (relay.CredentialRotation, error) {
	var input struct {
		AuthorizationDigest string `json:"authorizationDigest"`
	}
	if err := readRelayJSON(writer, request, &input, maximumRequestByteCount); err != nil {
		return relay.CredentialRotation{}, err
	}
	rotation := relay.CredentialRotation{
		RotationID:          rotationID,
		AuthorizationDigest: input.AuthorizationDigest,
	}
	if err := rotation.Validate(); err != nil {
		return relay.CredentialRotation{}, err
	}
	return rotation, nil
}

func relayAcceptanceStatus(acceptance relay.Acceptance) int {
	if acceptance == relay.AcceptanceDuplicate {
		return http.StatusOK
	}
	return http.StatusCreated
}

func (s *Server) handleCreateRelayAdmission(
	writer http.ResponseWriter,
	request *http.Request,
) {
	tenantID, domainID, err := relayScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayAdministrationCredentialFromRequest(
		request, tenantID, domainID,
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	var input struct {
		SubscriptionID              uuid.UUID          `json:"subscriptionID"`
		AdmissionID                 uuid.UUID          `json:"admissionID"`
		AuthorizationDigest         string             `json:"authorizationDigest"`
		Capabilities                []relay.Capability `json:"capabilities"`
		ExpiresAtMilliseconds       int64              `json:"expiresAtMilliseconds"`
		MemberExpiresAtMilliseconds *int64             `json:"memberExpiresAtMilliseconds,omitempty"`
	}
	if err := readRelayJSON(writer, request, &input, maximumRequestByteCount); err != nil {
		s.writeError(writer, err)
		return
	}
	capabilities, err := normalizedCapabilities(input.Capabilities)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	now := s.nowMilliseconds()
	registration := relay.MemberAdmission{
		Version:                     relay.SchemaVersion,
		TenantID:                    tenantID,
		DomainID:                    domainID,
		AdmissionID:                 input.AdmissionID,
		AuthorizationDigest:         input.AuthorizationDigest,
		Capabilities:                capabilities,
		CreatedAtMilliseconds:       now,
		ExpiresAtMilliseconds:       input.ExpiresAtMilliseconds,
		MemberExpiresAtMilliseconds: input.MemberExpiresAtMilliseconds,
	}
	result, err := s.relayStore.CreateSubscriptionAdmission(
		request.Context(), credential, input.SubscriptionID, registration, now,
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(traffic.SurfaceCheckpointAdmin, string(result.Acceptance))
	status := http.StatusCreated
	if result.Acceptance == relay.AcceptanceDuplicate {
		status = http.StatusOK
	}
	writeJSON(writer, status, result)
}

func (s *Server) handleWaitForRelayMessages(
	writer http.ResponseWriter,
	request *http.Request,
) {
	tenantID, domainID, err := relayScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayCredentialFromRequest(request, tenantID, domainID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	after, err := relay.DecodeCursor(request.URL.Query().Get("cursor"))
	if err != nil {
		s.writeError(writer, err)
		return
	}
	wait := maximumRelayWakeWait
	if rawWait := request.URL.Query().Get("waitMilliseconds"); rawWait != "" {
		waitMilliseconds, parseErr := strconv.Atoi(rawWait)
		if parseErr != nil || waitMilliseconds <= 0 ||
			time.Duration(waitMilliseconds)*time.Millisecond > maximumRelayWakeWait {
			s.writeError(writer, relay.NewProtocolError(
				relay.CodeInvalidCursor,
				"wake wait is invalid",
			))
			return
		}
		wait = time.Duration(waitMilliseconds) * time.Millisecond
	}

	// Subscribe before checking the durable store so publication cannot fall
	// into a gap between the check and the wait.
	wake := s.relayWakeBroker.subscribe(tenantID, domainID)
	hasChanges := func() (bool, error) {
		result, fetchErr := s.relayStore.Fetch(
			request.Context(), credential, after, 1, s.nowMilliseconds(),
		)
		return len(result.Messages) > 0, fetchErr
	}
	changed, err := hasChanges()
	if err != nil {
		s.writeError(writer, err)
		return
	}
	if changed {
		writeJSON(writer, http.StatusOK, map[string]bool{"changed": true})
		return
	}

	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-request.Context().Done():
		return
	case <-timer.C:
		writer.WriteHeader(http.StatusNoContent)
		return
	case <-wake:
	}

	changed, err = hasChanges()
	if err != nil {
		s.writeError(writer, err)
		return
	}
	if !changed {
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]bool{"changed": true})
}

func (s *Server) handleCollectRelayAdmissions(
	writer http.ResponseWriter,
	request *http.Request,
) {
	tenantID, domainID, err := relayScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayAdministrationCredentialFromRequest(
		request, tenantID, domainID,
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	result, err := s.relayStore.CollectAdmissions(
		request.Context(), credential, s.nowMilliseconds(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, result)
}

func (s *Server) handleClaimRelayAdmission(
	writer http.ResponseWriter,
	request *http.Request,
) {
	tenantID, domainID, err := relayScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	admissionID, err := parseRelayUUID(request.PathValue("admissionID"))
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayAdmissionCredentialFromRequest(
		request, tenantID, domainID, admissionID,
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	var claim relay.MemberAdmissionClaim
	if err := readRelayJSON(writer, request, &claim, maximumRequestByteCount); err != nil {
		s.writeError(writer, err)
		return
	}
	result, err := s.relayStore.ClaimSubscriptionAdmission(
		request.Context(), credential, claim, s.nowMilliseconds(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(traffic.SurfaceCheckpointAdmin, string(result.Acceptance))
	status := http.StatusCreated
	if result.Acceptance == relay.AcceptanceDuplicate {
		status = http.StatusOK
	}
	writeJSON(writer, status, result)
}

func (s *Server) handleRevokeRelayAdmission(
	writer http.ResponseWriter,
	request *http.Request,
) {
	tenantID, domainID, err := relayScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	admissionID, err := parseRelayUUID(request.PathValue("admissionID"))
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayAdministrationCredentialFromRequest(
		request, tenantID, domainID,
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	acceptance, err := s.relayStore.RevokeAdmission(
		request.Context(), credential, admissionID, s.nowMilliseconds(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(traffic.SurfaceCheckpointAdmin, string(acceptance))
	writeJSON(writer, http.StatusOK, map[string]string{
		"acceptance": string(acceptance),
	})
}

func (s *Server) handleRevokeRelayMember(writer http.ResponseWriter, request *http.Request) {
	tenantID, domainID, err := relayScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	memberID, err := parseRelayUUID(request.PathValue("memberID"))
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayAdministrationCredentialFromRequest(
		request, tenantID, domainID,
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	acceptance, err := s.relayStore.RevokeMember(
		request.Context(), credential, memberID, s.nowMilliseconds(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(traffic.SurfaceCheckpointAdmin, string(acceptance))
	writeJSON(writer, http.StatusOK, map[string]string{
		"acceptance": string(acceptance),
	})
}

func (s *Server) handlePublishRelayMessage(writer http.ResponseWriter, request *http.Request) {
	tenantID, domainID, err := relayScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	messageID, err := parseRelayUUID(request.PathValue("messageID"))
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayCredentialFromRequest(request, tenantID, domainID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	var envelope relay.Envelope
	if err := readRelayJSON(
		writer, request, &envelope, maximumRelayRequestByteCount,
	); err != nil {
		s.writeError(writer, err)
		return
	}
	if envelope.TenantID != tenantID || envelope.DomainID != domainID ||
		envelope.MessageID != messageID {
		s.writeError(writer, relay.NewProtocolError(
			relay.CodeWrongScope,
			"path and envelope identifiers differ",
		))
		return
	}
	result, err := s.relayStore.Publish(
		request.Context(), credential, envelope, s.nowMilliseconds(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(traffic.SurfaceRelayMessage, string(result.Acceptance))
	status := http.StatusCreated
	if result.Acceptance == relay.AcceptanceDuplicate {
		status = http.StatusOK
	} else if result.Acceptance == relay.AcceptanceAccepted {
		s.notifyRelayWake(request.Context(), tenantID, domainID)
	}
	writeJSON(writer, status, result)
}

func (s *Server) handleFetchRelayMessages(writer http.ResponseWriter, request *http.Request) {
	tenantID, domainID, err := relayScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayCredentialFromRequest(request, tenantID, domainID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	after, err := relay.DecodeCursor(request.URL.Query().Get("cursor"))
	if err != nil {
		s.writeError(writer, err)
		return
	}
	limit := relay.MaximumPageSize
	if rawLimit := request.URL.Query().Get("limit"); rawLimit != "" {
		limit, err = strconv.Atoi(rawLimit)
		if err != nil || limit <= 0 || limit > relay.MaximumPageSize {
			s.writeError(writer, relay.NewProtocolError(
				relay.CodeInvalidCursor,
				"page limit is invalid",
			))
			return
		}
	}
	result, err := s.relayStore.Fetch(
		request.Context(), credential, after, limit, s.nowMilliseconds(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, struct {
		Messages []relay.Message `json:"messages"`
		Cursor   string          `json:"cursor"`
	}{
		Messages: result.Messages,
		Cursor:   relay.EncodeCursor(result.NextSequence),
	})
}

func (s *Server) handleAcknowledgeRelayMessage(writer http.ResponseWriter, request *http.Request) {
	tenantID, domainID, err := relayScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	messageID, err := parseRelayUUID(request.PathValue("messageID"))
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayCredentialFromRequest(request, tenantID, domainID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	var input struct {
		Stage relay.AcknowledgmentStage `json:"stage"`
	}
	if err := readRelayJSON(writer, request, &input, maximumRequestByteCount); err != nil {
		s.writeError(writer, err)
		return
	}
	result, err := s.relayStore.Acknowledge(
		request.Context(), credential, messageID, input.Stage, s.nowMilliseconds(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(traffic.SurfaceRelayMessage, string(result.Acceptance))
	writeJSON(writer, http.StatusOK, result)
}

func (s *Server) handleCreateRelayBlobUpload(writer http.ResponseWriter, request *http.Request) {
	tenantID, domainID, err := relayScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayCredentialFromRequest(request, tenantID, domainID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	var input relay.BlobUploadRequest
	if err := readRelayJSON(writer, request, &input, 8_192); err != nil {
		s.writeError(writer, err)
		return
	}
	result, err := s.relayStore.CreateBlobUpload(request.Context(), credential, input, s.nowMilliseconds())
	if err != nil {
		s.writeError(writer, err)
		return
	}
	if !result.Status.Finalized {
		scope := relay.BlobScope{TenantID: tenantID, DomainID: domainID}
		if err := s.blobUploadContentStore.Initialize(request.Context(), scope, input.UploadID, result.Status.CommittedOffset); err != nil {
			s.writeError(writer, err)
			return
		}
	}
	s.metrics.ObserveAcceptance(traffic.SurfaceStorage, string(result.Acceptance))
	status := http.StatusCreated
	if result.Acceptance == relay.AcceptanceDuplicate {
		status = http.StatusOK
	}
	writeJSON(writer, status, result)
}

func (s *Server) handleGetRelayBlobUpload(writer http.ResponseWriter, request *http.Request) {
	tenantID, domainID, err := relayScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	uploadID, err := parseRelayUUID(request.PathValue("uploadID"))
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayCredentialFromRequest(request, tenantID, domainID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	status, err := s.relayStore.GetBlobUpload(request.Context(), credential, uploadID, s.nowMilliseconds())
	if err != nil {
		s.writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, status)
}

func (s *Server) handleAppendRelayBlobUpload(writer http.ResponseWriter, request *http.Request) {
	tenantID, domainID, err := relayScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	uploadID, err := parseRelayUUID(request.PathValue("uploadID"))
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayCredentialFromRequest(request, tenantID, domainID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	mediaType, _, mediaErr := mime.ParseMediaType(request.Header.Get("Content-Type"))
	offset, offsetErr := strconv.ParseInt(request.Header.Get("Upload-Offset"), 10, 64)
	if mediaErr != nil || mediaType != "application/octet-stream" || offsetErr != nil ||
		request.ContentLength <= 0 || request.ContentLength > relay.MaximumBlobByteCount {
		s.writeError(writer, relay.NewProtocolError(relay.CodeInvalidBlobUpload, "chunk headers are invalid"))
		return
	}
	chunk := relay.BlobUploadChunkRequest{
		UploadID: uploadID, Offset: offset, ByteCount: request.ContentLength,
		ChunkSHA256: request.Header.Get("X-Chunk-SHA256"),
	}
	request.Body = http.MaxBytesReader(writer, request.Body, request.ContentLength)
	scope := relay.BlobScope{TenantID: tenantID, DomainID: domainID}
	status, err := s.relayStore.AppendBlobUploadChunk(
		request.Context(), credential, chunk, s.nowMilliseconds(),
		func(durable relay.BlobUploadStatus) error {
			if err := s.blobUploadContentStore.Initialize(request.Context(), scope, uploadID, durable.CommittedOffset); err != nil {
				return err
			}
			return s.blobUploadContentStore.Append(request.Context(), scope, chunk, request.Body)
		},
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, status)
}

func (s *Server) handleFinalizeRelayBlobUpload(writer http.ResponseWriter, request *http.Request) {
	tenantID, domainID, err := relayScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	uploadID, err := parseRelayUUID(request.PathValue("uploadID"))
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayCredentialFromRequest(request, tenantID, domainID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	var input relay.BlobUploadFinalizationRequest
	if err := readRelayJSON(writer, request, &input, 8_192); err != nil {
		s.writeError(writer, err)
		return
	}
	if input.UploadID != uploadID {
		s.writeError(writer, relay.NewProtocolError(relay.CodeInvalidBlobUpload, "finalization upload ID does not match path"))
		return
	}
	scope := relay.BlobScope{TenantID: tenantID, DomainID: domainID}
	result, err := s.relayStore.FinalizeBlobUpload(
		request.Context(), credential, input, s.nowMilliseconds(),
		func(relay.BlobUploadStatus) error {
			_, publishErr := s.blobUploadContentStore.Publish(request.Context(), scope, uploadID, input.RelayBlobID, input.ByteCount)
			return publishErr
		},
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	_ = s.blobUploadContentStore.Delete(request.Context(), relay.BlobScope{TenantID: tenantID, DomainID: domainID}, uploadID)
	s.metrics.ObserveAcceptance(traffic.SurfaceStorage, string(result.Acceptance))
	statusCode := http.StatusCreated
	if result.Acceptance == relay.AcceptanceDuplicate {
		statusCode = http.StatusOK
	}
	writeJSON(writer, statusCode, result)
}

func (s *Server) handleFetchRelayBlob(writer http.ResponseWriter, request *http.Request) {
	tenantID, domainID, err := relayScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	blobID := request.PathValue("blobID")
	if err := relay.ValidateBlobID(blobID); err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayCredentialFromRequest(request, tenantID, domainID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	metadata, err := s.relayStore.GetBlobMetadata(
		request.Context(),
		credential,
		blobID,
		s.nowMilliseconds(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	content, err := s.blobContentStore.Open(
		request.Context(),
		relay.BlobScope{TenantID: tenantID, DomainID: domainID},
		blobID,
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	defer content.Reader.Close()
	if content.ByteCount != metadata.ByteCount {
		s.writeError(writer, fmt.Errorf("stored blob content length differs from metadata"))
		return
	}
	writer.Header().Set("Content-Type", "application/octet-stream")
	writer.Header().Set("ETag", `"`+blobID+`"`)
	http.ServeContent(writer, request, blobID, time.Time{}, content.Reader)
}

func (s *Server) authorizeOperator(request *http.Request) error {
	if !s.operatorProvisioningOn {
		return relay.NewProtocolError(relay.CodeUnauthorized, "operator provisioning is disabled")
	}
	token, err := bearerToken(request)
	if err != nil {
		return err
	}
	digest, err := operatorDigest(token)
	if err != nil || subtle.ConstantTimeCompare(
		digest[:], s.operatorTokenDigest[:],
	) != 1 {
		return relay.NewProtocolError(relay.CodeUnauthorized, "operator credential is invalid")
	}
	return nil
}

func operatorDigest(token string) ([32]byte, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(decoded) != 32 ||
		base64.RawURLEncoding.EncodeToString(decoded) != token {
		return [32]byte{}, fmt.Errorf("operator token must be 32-byte unpadded base64url")
	}
	return sha256.Sum256(decoded), nil
}

func randomToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate authorization token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func normalizedCapabilities(input []relay.Capability) ([]relay.Capability, error) {
	set := make(map[relay.Capability]struct{}, len(input))
	for _, capability := range input {
		if !capability.Valid() {
			return nil, relay.NewProtocolError(
				relay.CodeInvalidMember,
				"member capability is invalid",
			)
		}
		set[capability] = struct{}{}
	}
	if len(set) == 0 {
		return nil, relay.NewProtocolError(
			relay.CodeInvalidMember,
			"at least one member capability is required",
		)
	}
	result := make([]relay.Capability, 0, len(set))
	for capability := range set {
		result = append(result, capability)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result, nil
}

func readRelayJSON(
	writer http.ResponseWriter,
	request *http.Request,
	destination any,
	maximumByteCount int,
) error {
	return decodeJSONWithLimit(
		writer,
		request,
		destination,
		maximumByteCount,
		func(message string) error {
			return relay.NewProtocolError(relay.CodeInvalidEnvelope, message)
		},
	)
}

func relayScopeFromPath(request *http.Request) (uuid.UUID, uuid.UUID, error) {
	tenantID, err := parseRelayUUID(request.PathValue("tenantID"))
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	domainID, err := parseRelayUUID(request.PathValue("domainID"))
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	return tenantID, domainID, nil
}

func parseRelayUUID(value string) (uuid.UUID, error) {
	identifier, err := uuid.Parse(value)
	if err != nil || identifier == uuid.Nil {
		return uuid.Nil, relay.NewProtocolError(
			relay.CodeWrongScope,
			"identifier is invalid",
		)
	}
	return identifier, nil
}

func relayAdministrationCredentialFromRequest(
	request *http.Request,
	tenantID uuid.UUID,
	domainID uuid.UUID,
) (relay.AdministrationCredential, error) {
	token, err := bearerToken(request)
	if err != nil {
		return relay.AdministrationCredential{}, err
	}
	return relay.AdministrationCredential{
		TenantID: tenantID,
		DomainID: domainID,
		Token:    token,
	}, nil
}

func relayCredentialFromRequest(
	request *http.Request,
	tenantID uuid.UUID,
	domainID uuid.UUID,
) (relay.Credential, error) {
	token, err := bearerToken(request)
	if err != nil {
		return relay.Credential{}, err
	}
	memberID, err := parseRelayUUID(request.Header.Get("X-Facets-Member-ID"))
	if err != nil {
		return relay.Credential{}, relay.NewProtocolError(
			relay.CodeUnauthorized,
			"member identifier is required",
		)
	}
	return relay.Credential{
		TenantID: tenantID,
		DomainID: domainID,
		MemberID: memberID,
		Token:    token,
	}, nil
}

func relayAdmissionCredentialFromRequest(
	request *http.Request,
	tenantID uuid.UUID,
	domainID uuid.UUID,
	admissionID uuid.UUID,
) (relay.AdmissionCredential, error) {
	authorization := request.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, "Bearer ") ||
		strings.TrimPrefix(authorization, "Bearer ") == "" {
		return relay.AdmissionCredential{}, relay.NewProtocolError(
			relay.CodeUnauthorized,
			"admission credential is required",
		)
	}
	return relay.AdmissionCredential{
		TenantID:    tenantID,
		DomainID:    domainID,
		AdmissionID: admissionID,
		Token:       strings.TrimPrefix(authorization, "Bearer "),
	}, nil
}

func bearerToken(request *http.Request) (string, error) {
	authorization := request.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, "Bearer ") ||
		len(authorization) <= len("Bearer ") {
		return "", relay.NewProtocolError(
			relay.CodeUnauthorized,
			"bearer credential is required",
		)
	}
	return strings.TrimPrefix(authorization, "Bearer "), nil
}
