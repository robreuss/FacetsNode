package httpapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/devicesync"
	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/sharedspaces"
)

func TestSharedSpacesAPIProvisionsInvitesClaimsAndRevokesParticipant(t *testing.T) {
	const nowMilliseconds = int64(20_000)
	operatorToken := relayTestToken(0x11)
	relayStore := relay.NewMemoryStore()
	server := newRelayTestServer(t, relayStore, operatorToken)
	server.SetSharedSpacesStore(sharedspaces.NewMemoryStore(relayStore))
	server.now = func() time.Time { return time.UnixMilli(nowMilliseconds) }
	handler := server.Handler()

	domain := newRelayDomainProvisioningRequest(nowMilliseconds, 0x21, 0x31)
	spaceID := domain.AdministrationCredential.TenantID
	domainID := domain.AdministrationCredential.DomainID
	provisioning := sharedSpaceProvisioningInput{
		Version:                sharedspaces.SchemaVersion,
		RetryID:                uuid.New(),
		SpaceID:                spaceID,
		SecurityMode:           sharedspaces.SecurityModeE2EE,
		InteractionMode:        sharedspaces.InteractionModeCollaborative,
		InitialParticipantID:   domain.MemberCredential.MemberID,
		InitialParticipantKind: sharedspaces.ParticipantPerson,
		TenantProvisioning: newRelayTenantProvisioningRequest(
			domain,
			relayTestToken(0x41),
		),
	}
	created := performRelayJSON(
		t, handler, http.MethodPost, "/v1/shared-spaces",
		provisioning, operatorToken, uuid.Nil,
	)
	requireStatus(t, created, http.StatusCreated)
	var createdResult sharedspaces.SpaceProvisioningResult
	if err := json.NewDecoder(created.Body).Decode(&createdResult); err != nil {
		t.Fatal(err)
	}
	_ = created.Body.Close()
	if createdResult.Acceptance != relay.AcceptanceAccepted ||
		createdResult.InitialParticipant.Role != sharedspaces.RoleHost ||
		createdResult.InteractionMode != sharedspaces.InteractionModeCollaborative ||
		createdResult.CurrentKeyEpoch != sharedspaces.InitialKeyEpoch {
		t.Fatalf("created=%+v", createdResult)
	}
	retry := performRelayJSON(
		t, handler, http.MethodPost, "/v1/shared-spaces",
		provisioning, operatorToken, uuid.Nil,
	)
	requireStatus(t, retry, http.StatusOK)
	_ = retry.Body.Close()

	participantID := uuid.New()
	invitationID := uuid.New()
	subscriptionID := uuid.New()
	invitationToken := relayTestToken(0x51)
	invitation := sharedSpaceInvitationCreateInput{
		Version:         sharedspaces.SchemaVersion,
		RetryID:         uuid.New(),
		ParticipantID:   participantID,
		SubscriptionID:  subscriptionID,
		Kind:            sharedspaces.ParticipantPerson,
		Role:            sharedspaces.RoleReader,
		InteractionMode: provisioning.InteractionMode,
		InvitationCredential: sharedSpaceInvitationCredential{
			InvitationID:       invitationID,
			AuthorizationToken: invitationToken,
		},
		ExpiresAtMilliseconds: nowMilliseconds + 60_000,
		CreatedAtMilliseconds: nowMilliseconds,
	}
	invitation.KeyGrant = sharedSpaceParticipantKeyGrant(
		t, spaceID, participantID, provisioning.InitialParticipantID,
		sharedspaces.InitialKeyEpoch, nowMilliseconds,
	)
	spaceRoot := "/v1/shared-spaces/" + spaceID.String() + "/domains/" + domainID.String()
	blocked := performRelayJSON(
		t, handler, http.MethodPost, spaceRoot+"/invitations",
		invitation, domain.AdministrationCredential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, blocked, http.StatusConflict)
	_ = blocked.Body.Close()
	publishSharedSpaceBootstrapCheckpointHTTP(t, handler, domain, nowMilliseconds)
	cancelledParticipantID := uuid.New()
	cancelledInvitationID := uuid.New()
	cancelledToken := relayTestToken(0x52)
	cancelledInvitation := sharedSpaceInvitationCreateInput{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(),
		ParticipantID: cancelledParticipantID, SubscriptionID: uuid.New(),
		Kind: sharedspaces.ParticipantPerson, Role: sharedspaces.RoleReader,
		InteractionMode: provisioning.InteractionMode,
		InvitationCredential: sharedSpaceInvitationCredential{
			InvitationID: cancelledInvitationID, AuthorizationToken: cancelledToken,
		},
		ExpiresAtMilliseconds: nowMilliseconds + 60_000,
		CreatedAtMilliseconds: nowMilliseconds,
	}
	cancelledInvitation.KeyGrant = sharedSpaceParticipantKeyGrant(
		t, spaceID, cancelledParticipantID, provisioning.InitialParticipantID,
		sharedspaces.InitialKeyEpoch, nowMilliseconds,
	)
	cancelledIssue := performRelayJSON(
		t, handler, http.MethodPost, spaceRoot+"/invitations",
		cancelledInvitation, domain.AdministrationCredential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, cancelledIssue, http.StatusCreated)
	_ = cancelledIssue.Body.Close()
	cancellation := sharedspaces.InvitationCancellation{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(), SpaceID: spaceID,
		InvitationID: cancelledInvitationID, CancelledAtMilliseconds: nowMilliseconds,
	}
	cancellationPath := spaceRoot + "/invitations/" + cancelledInvitationID.String() + "/cancellation"
	cancelledResponse := performRelayJSON(
		t, handler, http.MethodPost, cancellationPath, cancellation,
		domain.AdministrationCredential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, cancelledResponse, http.StatusCreated)
	_ = cancelledResponse.Body.Close()
	cancelledRetry := performRelayJSON(
		t, handler, http.MethodPost, cancellationPath, cancellation,
		domain.AdministrationCredential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, cancelledRetry, http.StatusOK)
	_ = cancelledRetry.Body.Close()
	cancelledMemberToken := relayTestToken(0x62)
	cancelledClaim := sharedSpaceInvitationClaimInput{
		Version: sharedspaces.SchemaVersion, ParticipantID: cancelledParticipantID,
		MemberCredential: relayMemberCredential{
			TenantID: spaceID, DomainID: domainID, MemberID: cancelledParticipantID,
			AuthorizationToken: cancelledMemberToken,
		},
		ClaimedAtMilliseconds: nowMilliseconds,
	}
	cancelledClaimResponse := performRelayJSON(
		t, handler, http.MethodPost,
		spaceRoot+"/invitations/"+cancelledInvitationID.String()+"/claim",
		cancelledClaim, cancelledToken, uuid.Nil,
	)
	requireStatus(t, cancelledClaimResponse, http.StatusGone)
	_ = cancelledClaimResponse.Body.Close()

	issued := performRelayJSON(
		t, handler, http.MethodPost, spaceRoot+"/invitations",
		invitation, domain.AdministrationCredential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, issued, http.StatusCreated)
	var issuedResult sharedspaces.InvitationCreateResult
	if err := json.NewDecoder(issued.Body).Decode(&issuedResult); err != nil {
		t.Fatal(err)
	}
	_ = issued.Body.Close()
	if issuedResult.Invitation.Role != sharedspaces.RoleReader ||
		issuedResult.Invitation.InteractionMode != provisioning.InteractionMode ||
		len(issuedResult.Invitation.RelayAdmission.Capabilities) != len(sharedspaces.RoleReader.Capabilities(provisioning.InteractionMode)) {
		t.Fatalf("issued=%+v", issuedResult)
	}

	memberToken := relayTestToken(0x61)
	claim := sharedSpaceInvitationClaimInput{
		Version:       sharedspaces.SchemaVersion,
		ParticipantID: participantID,
		MemberCredential: relayMemberCredential{
			TenantID: spaceID, DomainID: domainID, MemberID: participantID,
			AuthorizationToken: memberToken,
		},
		ClaimedAtMilliseconds: nowMilliseconds,
	}
	claimPath := spaceRoot + "/invitations/" + invitationID.String() + "/claim"
	claimed := performRelayJSON(
		t, handler, http.MethodPost, claimPath, claim, invitationToken, uuid.Nil,
	)
	requireStatus(t, claimed, http.StatusCreated)
	var claimResult sharedspaces.InvitationClaimResult
	if err := json.NewDecoder(claimed.Body).Decode(&claimResult); err != nil {
		t.Fatal(err)
	}
	_ = claimed.Body.Close()
	if claimResult.CurrentKeyEpoch != sharedspaces.InitialKeyEpoch ||
		claimResult.Participant.Role != sharedspaces.RoleReader {
		t.Fatalf("claim=%+v", claimResult)
	}
	claimRetry := performRelayJSON(
		t, handler, http.MethodPost, claimPath, claim, invitationToken, uuid.Nil,
	)
	requireStatus(t, claimRetry, http.StatusOK)
	_ = claimRetry.Body.Close()
	keyGrantPath := spaceRoot + "/participants/" + participantID.String() + "/key-grant"
	currentMemberGrantResponse := performRelayJSON(
		t, handler, http.MethodGet, keyGrantPath, nil, memberToken, participantID,
	)
	requireStatus(t, currentMemberGrantResponse, http.StatusOK)
	var currentMemberGrant sharedspaces.ParticipantKeyGrantResult
	if err := json.NewDecoder(currentMemberGrantResponse.Body).Decode(&currentMemberGrant); err != nil {
		t.Fatal(err)
	}
	_ = currentMemberGrantResponse.Body.Close()
	if currentMemberGrant.KeyGrant.ParticipantID != participantID ||
		currentMemberGrant.KeyGrant.KeyEpoch != sharedspaces.InitialKeyEpoch {
		t.Fatalf("member key grant=%+v", currentMemberGrant)
	}
	wrongMemberGrantResponse := performRelayJSON(
		t, handler, http.MethodGet, keyGrantPath, nil,
		domain.MemberCredential.AuthorizationToken, provisioning.InitialParticipantID,
	)
	requireStatus(t, wrongMemberGrantResponse, http.StatusBadRequest)
	_ = wrongMemberGrantResponse.Body.Close()

	invitationListResponse := performRelayJSON(
		t, handler, http.MethodGet, spaceRoot+"/invitations", nil,
		domain.AdministrationCredential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, invitationListResponse, http.StatusOK)
	var invitationList sharedspaces.InvitationList
	if err := json.NewDecoder(invitationListResponse.Body).Decode(&invitationList); err != nil {
		t.Fatal(err)
	}
	_ = invitationListResponse.Body.Close()
	states := map[uuid.UUID]sharedspaces.InvitationStatus{}
	for _, status := range invitationList.Invitations {
		states[status.InvitationID] = status
	}
	if len(states) != 2 || states[invitationID].State != sharedspaces.InvitationClaimed ||
		states[invitationID].InteractionMode != provisioning.InteractionMode ||
		states[invitationID].ClaimedAtMilliseconds == nil ||
		states[cancelledInvitationID].State != sharedspaces.InvitationCancelled ||
		states[cancelledInvitationID].CancelledAtMilliseconds == nil {
		t.Fatalf("invitation list=%+v", invitationList)
	}
	unauthorizedList := performRelayJSON(
		t, handler, http.MethodGet, spaceRoot+"/invitations", nil,
		relayTestToken(0x7f), uuid.Nil,
	)
	requireStatus(t, unauthorizedList, http.StatusUnauthorized)
	_ = unauthorizedList.Body.Close()

	rolePath := spaceRoot + "/participants/" + participantID.String() + "/role"
	promotion := sharedspaces.ParticipantRoleChange{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(), SpaceID: spaceID,
		ParticipantID: participantID, PreviousRole: sharedspaces.RoleReader,
		NextRole: sharedspaces.RoleParticipant, ChangedAtMilliseconds: nowMilliseconds,
	}
	promoted := performRelayJSON(
		t, handler, http.MethodPost, rolePath, promotion,
		domain.AdministrationCredential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, promoted, http.StatusCreated)
	var promotedResult sharedspaces.ParticipantRoleChangeResult
	if err := json.NewDecoder(promoted.Body).Decode(&promotedResult); err != nil {
		t.Fatal(err)
	}
	_ = promoted.Body.Close()
	if promotedResult.CurrentRole != sharedspaces.RoleParticipant {
		t.Fatalf("promoted=%+v", promotedResult)
	}
	promotionRetry := performRelayJSON(
		t, handler, http.MethodPost, rolePath, promotion,
		domain.AdministrationCredential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, promotionRetry, http.StatusOK)
	_ = promotionRetry.Body.Close()
	demotion := sharedspaces.ParticipantRoleChange{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(), SpaceID: spaceID,
		ParticipantID: participantID, PreviousRole: sharedspaces.RoleParticipant,
		NextRole: sharedspaces.RoleReader, ChangedAtMilliseconds: nowMilliseconds,
	}
	demoted := performRelayJSON(
		t, handler, http.MethodPost, rolePath, demotion,
		domain.AdministrationCredential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, demoted, http.StatusCreated)
	_ = demoted.Body.Close()
	presentationPath := spaceRoot + "/participants/" + participantID.String() + "/presentation"
	presentationUpdate := sharedspaces.ParticipantPresentationUpdate{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(), SpaceID: spaceID,
		ParticipantID: participantID, PreviousRevision: 0, DisplayName: "Ada Lovelace",
		UpdatedAtMilliseconds: nowMilliseconds,
	}
	presentationResponse := performRelayJSON(
		t, handler, http.MethodPost, presentationPath, presentationUpdate,
		memberToken, participantID,
	)
	requireStatus(t, presentationResponse, http.StatusCreated)
	var presentationResult sharedspaces.ParticipantPresentationUpdateResult
	if err := json.NewDecoder(presentationResponse.Body).Decode(&presentationResult); err != nil {
		t.Fatal(err)
	}
	_ = presentationResponse.Body.Close()
	if presentationResult.Presentation.Revision != 1 ||
		presentationResult.Presentation.DisplayName != "Ada Lovelace" {
		t.Fatalf("presentation=%+v", presentationResult)
	}
	presentationRetry := performRelayJSON(
		t, handler, http.MethodPost, presentationPath, presentationUpdate,
		memberToken, participantID,
	)
	requireStatus(t, presentationRetry, http.StatusOK)
	_ = presentationRetry.Body.Close()
	presentationCollision := presentationUpdate
	presentationCollision.RetryID = uuid.New()
	presentationCollision.DisplayName = "Countess of Lovelace"
	presentationCollisionResponse := performRelayJSON(
		t, handler, http.MethodPost, presentationPath, presentationCollision,
		memberToken, participantID,
	)
	requireStatus(t, presentationCollisionResponse, http.StatusConflict)
	_ = presentationCollisionResponse.Body.Close()
	wrongParticipantPresentationResponse := performRelayJSON(
		t, handler, http.MethodPost, presentationPath, presentationUpdate,
		domain.MemberCredential.AuthorizationToken, provisioning.InitialParticipantID,
	)
	requireStatus(t, wrongParticipantPresentationResponse, http.StatusBadRequest)
	_ = wrongParticipantPresentationResponse.Body.Close()
	participantStatusPath := spaceRoot + "/participants/" + participantID.String() + "/status"
	participantStatusResponse := performRelayJSON(
		t, handler, http.MethodGet, participantStatusPath, nil, memberToken, participantID,
	)
	requireStatus(t, participantStatusResponse, http.StatusOK)
	var participantStatus sharedspaces.ParticipantStatus
	if err := json.NewDecoder(participantStatusResponse.Body).Decode(&participantStatus); err != nil {
		t.Fatal(err)
	}
	_ = participantStatusResponse.Body.Close()
	if participantStatus.SpaceID != spaceID || participantStatus.DomainID != domainID ||
		participantStatus.SecurityMode != sharedspaces.SecurityModeE2EE ||
		participantStatus.InteractionMode != provisioning.InteractionMode ||
		participantStatus.CurrentKeyEpoch != sharedspaces.InitialKeyEpoch ||
		!participantStatus.BootstrapReady || participantStatus.ActiveCheckpointEpoch == nil ||
		*participantStatus.ActiveCheckpointEpoch != sharedspaces.InitialKeyEpoch ||
		participantStatus.Participant.ParticipantID != participantID ||
		participantStatus.Participant.Role != sharedspaces.RoleReader ||
		participantStatus.Presentation == nil ||
		participantStatus.Presentation.DisplayName != "Ada Lovelace" ||
		!sameRelayCapabilities(
			participantStatus.Capabilities,
			sharedspaces.RoleReader.Capabilities(provisioning.InteractionMode),
		) {
		t.Fatalf("participant status=%+v", participantStatus)
	}
	participantBootstrapPath := spaceRoot + "/participants/" + participantID.String() + "/bootstrap"
	participantBootstrapResponse := performRelayJSON(
		t, handler, http.MethodGet, participantBootstrapPath, nil, memberToken, participantID,
	)
	requireStatus(t, participantBootstrapResponse, http.StatusOK)
	var participantBootstrap sharedspaces.ParticipantBootstrap
	if err := json.NewDecoder(participantBootstrapResponse.Body).Decode(&participantBootstrap); err != nil {
		t.Fatal(err)
	}
	_ = participantBootstrapResponse.Body.Close()
	if participantBootstrap.Status.Participant.ParticipantID != participantID ||
		participantBootstrap.Status.Participant.Role != sharedspaces.RoleReader ||
		participantBootstrap.Status.Presentation == nil ||
		participantBootstrap.Status.Presentation.DisplayName != "Ada Lovelace" ||
		participantBootstrap.KeyGrant == nil ||
		participantBootstrap.KeyGrant.ParticipantID != participantID ||
		participantBootstrap.KeyGrant.CurrentKeyEpoch != participantBootstrap.Status.CurrentKeyEpoch ||
		participantBootstrap.KeyGrant.KeyGrant.KeyEpoch != participantBootstrap.Status.CurrentKeyEpoch {
		t.Fatalf("participant bootstrap=%+v", participantBootstrap)
	}
	wrongParticipantStatusResponse := performRelayJSON(
		t, handler, http.MethodGet, participantStatusPath, nil,
		domain.MemberCredential.AuthorizationToken, provisioning.InitialParticipantID,
	)
	requireStatus(t, wrongParticipantStatusResponse, http.StatusBadRequest)
	_ = wrongParticipantStatusResponse.Body.Close()
	wrongParticipantBootstrapResponse := performRelayJSON(
		t, handler, http.MethodGet, participantBootstrapPath, nil,
		domain.MemberCredential.AuthorizationToken, provisioning.InitialParticipantID,
	)
	requireStatus(t, wrongParticipantBootstrapResponse, http.StatusBadRequest)
	_ = wrongParticipantBootstrapResponse.Body.Close()

	statusPath := spaceRoot + "/status"
	statusResponse := performRelayJSON(
		t, handler, http.MethodGet, statusPath, nil,
		domain.AdministrationCredential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, statusResponse, http.StatusOK)
	var status sharedspaces.SpaceStatus
	if err := json.NewDecoder(statusResponse.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	_ = statusResponse.Body.Close()
	participantRoles := map[uuid.UUID]sharedspaces.Role{}
	for _, participant := range status.Participants {
		participantRoles[participant.ParticipantID] = participant.Role
	}
	if len(status.Participants) != 2 || status.Relay.ActiveSubscriptionCount != 2 ||
		len(status.Presentations) != 1 ||
		status.Presentations[0].ParticipantID != participantID ||
		status.Presentations[0].DisplayName != "Ada Lovelace" ||
		status.InteractionMode != provisioning.InteractionMode ||
		status.CurrentKeyEpoch != sharedspaces.InitialKeyEpoch || !status.BootstrapReady ||
		status.ActiveCheckpointEpoch == nil || *status.ActiveCheckpointEpoch != sharedspaces.InitialKeyEpoch ||
		participantRoles[participantID] != sharedspaces.RoleReader ||
		participantRoles[provisioning.InitialParticipantID] != sharedspaces.RoleHost {
		t.Fatalf("status=%+v", status)
	}
	poolID := uuid.New()
	computePoolPath := spaceRoot + "/compute-pools/" + poolID.String()
	computeChange := sharedspaces.ComputePoolChange{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(), SpaceID: spaceID,
		PoolID: poolID, DisplayName: "Space batch workers", Enabled: true,
		AllowedOperations: []string{"facets.ai.classify", "facets.ai.embed"},
		ResourceCeiling: sharedspaces.ComputeResourceCeiling{
			MaximumInputBytes: 1 << 20, MaximumOutputBytes: 1 << 20,
			MaximumMemoryBytes: 1 << 30, MaximumWallTimeMilliseconds: 60_000,
		},
		PricingRevision: 1, DataSensitivityContract: "space-members-v1",
		ProcessingContract: "participant-device-v1", ChangedAtMilliseconds: nowMilliseconds,
	}
	computeResponse := performRelayJSON(
		t, handler, http.MethodPost, computePoolPath, computeChange,
		domain.AdministrationCredential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, computeResponse, http.StatusCreated)
	var computeResult sharedspaces.ComputePoolChangeResult
	if err := json.NewDecoder(computeResponse.Body).Decode(&computeResult); err != nil {
		t.Fatal(err)
	}
	_ = computeResponse.Body.Close()
	if computeResult.Pool.PoolID != poolID || computeResult.Binding.Revision != 1 {
		t.Fatalf("compute result=%+v", computeResult)
	}
	computeRetry := performRelayJSON(
		t, handler, http.MethodPost, computePoolPath, computeChange,
		domain.AdministrationCredential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, computeRetry, http.StatusOK)
	_ = computeRetry.Body.Close()
	computeStatusResponse := performRelayJSON(
		t, handler, http.MethodGet, statusPath, nil,
		domain.AdministrationCredential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, computeStatusResponse, http.StatusOK)
	var computeStatus sharedspaces.SpaceStatus
	if err := json.NewDecoder(computeStatusResponse.Body).Decode(&computeStatus); err != nil {
		t.Fatal(err)
	}
	_ = computeStatusResponse.Body.Close()
	if len(computeStatus.ComputePools) != 1 || len(computeStatus.ComputeBindings) != 1 ||
		computeStatus.ComputePools[0].PoolID != poolID ||
		computeStatus.ComputeBindings[0].PoolID != poolID {
		t.Fatalf("compute status=%+v", computeStatus)
	}
	wrongPoolPathResponse := performRelayJSON(
		t, handler, http.MethodPost, spaceRoot+"/compute-pools/"+uuid.New().String(),
		computeChange, domain.AdministrationCredential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, wrongPoolPathResponse, http.StatusBadRequest)
	_ = wrongPoolPathResponse.Body.Close()

	revocation := sharedspaces.ParticipantRevocation{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(),
		SpaceID: spaceID, ParticipantID: participantID,
		PreviousKeyEpoch: sharedspaces.InitialKeyEpoch, NextKeyEpoch: sharedspaces.InitialKeyEpoch + 1,
		KeyGrants: []sharedspaces.ParticipantKeyGrant{*sharedSpaceParticipantKeyGrant(
			t, spaceID, provisioning.InitialParticipantID, provisioning.InitialParticipantID,
			sharedspaces.InitialKeyEpoch+1, nowMilliseconds,
		)},
	}
	revoked := performRelayJSON(
		t, handler, http.MethodPost,
		spaceRoot+"/participants/"+participantID.String()+"/revocation",
		revocation, domain.AdministrationCredential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, revoked, http.StatusCreated)
	var revokedResult sharedspaces.ParticipantRevocationResult
	if err := json.NewDecoder(revoked.Body).Decode(&revokedResult); err != nil {
		t.Fatal(err)
	}
	_ = revoked.Body.Close()
	if revokedResult.PreviousKeyEpoch != sharedspaces.InitialKeyEpoch ||
		revokedResult.CurrentKeyEpoch != sharedspaces.InitialKeyEpoch+1 {
		t.Fatalf("revoked=%+v", revokedResult)
	}
	revokedParticipantStatusResponse := performRelayJSON(
		t, handler, http.MethodGet, participantStatusPath, nil, memberToken, participantID,
	)
	requireStatus(t, revokedParticipantStatusResponse, http.StatusConflict)
	_ = revokedParticipantStatusResponse.Body.Close()
	revokedParticipantBootstrapResponse := performRelayJSON(
		t, handler, http.MethodGet, participantBootstrapPath, nil, memberToken, participantID,
	)
	requireStatus(t, revokedParticipantBootstrapResponse, http.StatusConflict)
	_ = revokedParticipantBootstrapResponse.Body.Close()
	revokedParticipantPresentationResponse := performRelayJSON(
		t, handler, http.MethodPost, presentationPath, presentationUpdate,
		memberToken, participantID,
	)
	requireStatus(t, revokedParticipantPresentationResponse, http.StatusConflict)
	_ = revokedParticipantPresentationResponse.Body.Close()
	hostKeyGrantPath := spaceRoot + "/participants/" + provisioning.InitialParticipantID.String() + "/key-grant"
	currentHostGrantResponse := performRelayJSON(
		t, handler, http.MethodGet, hostKeyGrantPath, nil,
		domain.MemberCredential.AuthorizationToken, provisioning.InitialParticipantID,
	)
	requireStatus(t, currentHostGrantResponse, http.StatusOK)
	var currentHostGrant sharedspaces.ParticipantKeyGrantResult
	if err := json.NewDecoder(currentHostGrantResponse.Body).Decode(&currentHostGrant); err != nil {
		t.Fatal(err)
	}
	_ = currentHostGrantResponse.Body.Close()
	if currentHostGrant.KeyGrant.ParticipantID != provisioning.InitialParticipantID ||
		currentHostGrant.KeyGrant.KeyEpoch != sharedspaces.InitialKeyEpoch+1 {
		t.Fatalf("host key grant=%+v", currentHostGrant)
	}
	staleEnvelope := relay.Envelope{
		Version: relay.SchemaVersion, Algorithm: relay.EnvelopeAlgorithm,
		TenantID: spaceID, DomainID: domainID, MessageID: uuid.New(),
		PublisherMemberID: domain.MemberCredential.MemberID,
		KeyEpoch:          sharedspaces.InitialKeyEpoch, CreatedAtMilliseconds: nowMilliseconds,
		Nonce:             base64.RawURLEncoding.EncodeToString(make([]byte, 12)),
		Ciphertext:        base64.RawURLEncoding.EncodeToString([]byte("stale Shared Space payload")),
		AuthenticationTag: base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
	}
	relayRoot := "/v1/relay/tenants/" + spaceID.String() + "/domains/" + domainID.String()
	stalePublish := performRelayJSON(
		t, handler, http.MethodPut,
		relayRoot+"/messages/"+staleEnvelope.MessageID.String(), staleEnvelope,
		domain.MemberCredential.AuthorizationToken, domain.MemberCredential.MemberID,
	)
	requireStatus(t, stalePublish, http.StatusConflict)
	_ = stalePublish.Body.Close()
	currentEnvelope := staleEnvelope
	currentEnvelope.MessageID = uuid.New()
	currentEnvelope.KeyEpoch = sharedspaces.InitialKeyEpoch + 1
	currentPublish := performRelayJSON(
		t, handler, http.MethodPut,
		relayRoot+"/messages/"+currentEnvelope.MessageID.String(), currentEnvelope,
		domain.MemberCredential.AuthorizationToken, domain.MemberCredential.MemberID,
	)
	requireStatus(t, currentPublish, http.StatusCreated)
	_ = currentPublish.Body.Close()
	revokedMember := relay.Credential{
		TenantID: spaceID, DomainID: domainID, MemberID: participantID, Token: memberToken,
	}
	if _, err := relayStore.Fetch(t.Context(), revokedMember, 0, 1, nowMilliseconds+1); !relay.ErrorHasCode(err, relay.CodeMemberRevoked) {
		t.Fatalf("revoked member relay access err=%v", err)
	}

	authorityEventsPath := spaceRoot + "/authority-events"
	firstAuthorityPageResponse := performRelayJSON(
		t, handler, http.MethodGet, authorityEventsPath+"?limit=3", nil,
		domain.AdministrationCredential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, firstAuthorityPageResponse, http.StatusOK)
	var firstAuthorityPage sharedspaces.AuthorityEventPage
	if err := json.NewDecoder(firstAuthorityPageResponse.Body).Decode(&firstAuthorityPage); err != nil {
		t.Fatal(err)
	}
	_ = firstAuthorityPageResponse.Body.Close()
	if len(firstAuthorityPage.Events) != 3 || firstAuthorityPage.NextSequence != 3 ||
		firstAuthorityPage.Events[0].EventType != sharedspaces.AuthorityEventSpaceProvisioned ||
		firstAuthorityPage.Events[1].EventType != sharedspaces.AuthorityEventInvitationCreated ||
		firstAuthorityPage.Events[2].EventType != sharedspaces.AuthorityEventInvitationCancelled {
		t.Fatalf("first authority event page=%+v", firstAuthorityPage)
	}
	secondAuthorityPageResponse := performRelayJSON(
		t, handler, http.MethodGet,
		authorityEventsPath+"?afterSequence="+strconv.FormatUint(firstAuthorityPage.NextSequence, 10)+"&limit=10",
		nil, domain.AdministrationCredential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, secondAuthorityPageResponse, http.StatusOK)
	var secondAuthorityPage sharedspaces.AuthorityEventPage
	if err := json.NewDecoder(secondAuthorityPageResponse.Body).Decode(&secondAuthorityPage); err != nil {
		t.Fatal(err)
	}
	_ = secondAuthorityPageResponse.Body.Close()
	wantRemainingAuthorityEvents := []sharedspaces.AuthorityEventType{
		sharedspaces.AuthorityEventInvitationCreated,
		sharedspaces.AuthorityEventInvitationClaimed,
		sharedspaces.AuthorityEventParticipantRoleChanged,
		sharedspaces.AuthorityEventParticipantRoleChanged,
		sharedspaces.AuthorityEventSpaceComputeBindingChanged,
		sharedspaces.AuthorityEventParticipantRevoked,
	}
	if len(secondAuthorityPage.Events) != len(wantRemainingAuthorityEvents) || secondAuthorityPage.NextSequence != 9 {
		t.Fatalf("second authority event page=%+v", secondAuthorityPage)
	}
	for index, eventType := range wantRemainingAuthorityEvents {
		if secondAuthorityPage.Events[index].EventType != eventType {
			t.Fatalf("authority event %d type=%q want=%q", index, secondAuthorityPage.Events[index].EventType, eventType)
		}
	}
	unauthorizedAuthorityEvents := performRelayJSON(
		t, handler, http.MethodGet, authorityEventsPath, nil, relayTestToken(0x7f), uuid.Nil,
	)
	requireStatus(t, unauthorizedAuthorityEvents, http.StatusUnauthorized)
	_ = unauthorizedAuthorityEvents.Body.Close()
	invalidAuthorityEvents := performRelayJSON(
		t, handler, http.MethodGet, authorityEventsPath+"?limit=0", nil,
		domain.AdministrationCredential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, invalidAuthorityEvents, http.StatusBadRequest)
	_ = invalidAuthorityEvents.Body.Close()
}

func TestSharedSpacesAPIManagedBootstrapDistributesAndRotatesServiceKey(t *testing.T) {
	const nowMilliseconds = int64(30_000)
	operatorToken := relayTestToken(0x12)
	relayStore := relay.NewMemoryStore()
	server := newRelayTestServer(t, relayStore, operatorToken)
	server.SetSharedSpacesStore(sharedspaces.NewMemoryStore(relayStore))
	server.now = func() time.Time { return time.UnixMilli(nowMilliseconds) }
	handler := server.Handler()

	domain := newRelayDomainProvisioningRequest(nowMilliseconds, 0x22, 0x32)
	spaceID := domain.AdministrationCredential.TenantID
	domainID := domain.AdministrationCredential.DomainID
	provisioning := sharedSpaceProvisioningInput{
		Version:                sharedspaces.SchemaVersion,
		RetryID:                uuid.New(),
		SpaceID:                spaceID,
		SecurityMode:           sharedspaces.SecurityModeManaged,
		InteractionMode:        sharedspaces.InteractionModeCollaborative,
		InitialParticipantID:   domain.MemberCredential.MemberID,
		InitialParticipantKind: sharedspaces.ParticipantPerson,
		TenantProvisioning:     newRelayTenantProvisioningRequest(domain, relayTestToken(0x42)),
	}
	created := performRelayJSON(
		t, handler, http.MethodPost, "/v1/shared-spaces",
		provisioning, operatorToken, uuid.Nil,
	)
	requireStatus(t, created, http.StatusCreated)
	_ = created.Body.Close()
	publishSharedSpaceBootstrapCheckpointHTTP(t, handler, domain, nowMilliseconds)

	participantID := uuid.New()
	invitationID := uuid.New()
	invitationToken := relayTestToken(0x52)
	invitation := sharedSpaceInvitationCreateInput{
		Version:         sharedspaces.SchemaVersion,
		RetryID:         uuid.New(),
		ParticipantID:   participantID,
		SubscriptionID:  uuid.New(),
		Kind:            sharedspaces.ParticipantPerson,
		Role:            sharedspaces.RoleParticipant,
		InteractionMode: provisioning.InteractionMode,
		InvitationCredential: sharedSpaceInvitationCredential{
			InvitationID:       invitationID,
			AuthorizationToken: invitationToken,
		},
		ExpiresAtMilliseconds: nowMilliseconds + 60_000,
		CreatedAtMilliseconds: nowMilliseconds,
	}
	spaceRoot := "/v1/shared-spaces/" + spaceID.String() + "/domains/" + domainID.String()
	issued := performRelayJSON(
		t, handler, http.MethodPost, spaceRoot+"/invitations",
		invitation, domain.AdministrationCredential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, issued, http.StatusCreated)
	_ = issued.Body.Close()

	memberToken := relayTestToken(0x62)
	claim := sharedSpaceInvitationClaimInput{
		Version:       sharedspaces.SchemaVersion,
		ParticipantID: participantID,
		MemberCredential: relayMemberCredential{
			TenantID: spaceID, DomainID: domainID, MemberID: participantID,
			AuthorizationToken: memberToken,
		},
		ClaimedAtMilliseconds: nowMilliseconds,
	}
	claimPath := spaceRoot + "/invitations/" + invitationID.String() + "/claim"
	claimed := performRelayJSON(
		t, handler, http.MethodPost, claimPath, claim, invitationToken, uuid.Nil,
	)
	requireStatus(t, claimed, http.StatusCreated)
	var claimResult sharedspaces.InvitationClaimResult
	if err := json.NewDecoder(claimed.Body).Decode(&claimResult); err != nil {
		t.Fatal(err)
	}
	_ = claimed.Body.Close()
	if claimResult.KeyGrant != nil {
		t.Fatalf("managed claim unexpectedly exposed E2EE grant=%+v", claimResult.KeyGrant)
	}

	hostBootstrapPath := spaceRoot + "/participants/" + provisioning.InitialParticipantID.String() + "/bootstrap"
	memberBootstrapPath := spaceRoot + "/participants/" + participantID.String() + "/bootstrap"
	hostBootstrap := fetchSharedSpaceParticipantBootstrap(
		t, handler, hostBootstrapPath, domain.MemberCredential.AuthorizationToken,
		provisioning.InitialParticipantID,
	)
	memberBootstrap := fetchSharedSpaceParticipantBootstrap(
		t, handler, memberBootstrapPath, memberToken, participantID,
	)
	if hostBootstrap.KeyGrant != nil || memberBootstrap.KeyGrant != nil ||
		hostBootstrap.ManagedContentKey == nil || memberBootstrap.ManagedContentKey == nil ||
		hostBootstrap.ManagedContentKey.KeyMaterial != memberBootstrap.ManagedContentKey.KeyMaterial ||
		hostBootstrap.ManagedContentKey.KeyEpoch != sharedspaces.InitialKeyEpoch ||
		memberBootstrap.ManagedContentKey.KeyEpoch != sharedspaces.InitialKeyEpoch {
		t.Fatalf("managed bootstraps host=%+v member=%+v", hostBootstrap, memberBootstrap)
	}
	previousKeyMaterial := hostBootstrap.ManagedContentKey.KeyMaterial

	revocation := sharedspaces.ParticipantRevocation{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(),
		SpaceID: spaceID, ParticipantID: participantID,
		PreviousKeyEpoch: sharedspaces.InitialKeyEpoch,
		NextKeyEpoch:     sharedspaces.InitialKeyEpoch + 1,
	}
	revoked := performRelayJSON(
		t, handler, http.MethodPost,
		spaceRoot+"/participants/"+participantID.String()+"/revocation",
		revocation, domain.AdministrationCredential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, revoked, http.StatusCreated)
	_ = revoked.Body.Close()

	rotatedHostBootstrap := fetchSharedSpaceParticipantBootstrap(
		t, handler, hostBootstrapPath, domain.MemberCredential.AuthorizationToken,
		provisioning.InitialParticipantID,
	)
	if rotatedHostBootstrap.ManagedContentKey == nil ||
		rotatedHostBootstrap.ManagedContentKey.KeyEpoch != sharedspaces.InitialKeyEpoch+1 ||
		rotatedHostBootstrap.ManagedContentKey.KeyMaterial == previousKeyMaterial ||
		rotatedHostBootstrap.Status.BootstrapReady {
		t.Fatalf("rotated host bootstrap=%+v", rotatedHostBootstrap)
	}
	revokedMemberBootstrap := performRelayJSON(
		t, handler, http.MethodGet, memberBootstrapPath, nil, memberToken, participantID,
	)
	requireStatus(t, revokedMemberBootstrap, http.StatusConflict)
	_ = revokedMemberBootstrap.Body.Close()
}

func fetchSharedSpaceParticipantBootstrap(
	t *testing.T,
	handler http.Handler,
	path string,
	token string,
	participantID uuid.UUID,
) sharedspaces.ParticipantBootstrap {
	t.Helper()
	response := performRelayJSON(t, handler, http.MethodGet, path, nil, token, participantID)
	requireStatus(t, response, http.StatusOK)
	var bootstrap sharedspaces.ParticipantBootstrap
	if err := json.NewDecoder(response.Body).Decode(&bootstrap); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if err := bootstrap.Validate(); err != nil {
		t.Fatalf("invalid participant bootstrap: %v", err)
	}
	return bootstrap
}

func sharedSpaceParticipantKeyGrant(
	t *testing.T,
	spaceID uuid.UUID,
	participantID uuid.UUID,
	issuerParticipantID uuid.UUID,
	keyEpoch uint64,
	now int64,
) *sharedspaces.ParticipantKeyGrant {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := elliptic.Marshal(elliptic.P256(), privateKey.PublicKey.X, privateKey.PublicKey.Y)
	signingFingerprint := sha256.Sum256(publicKey)
	recipientFingerprint := sha256.Sum256([]byte("recipient agreement key"))
	grant := sharedspaces.ParticipantKeyGrant{
		Version: sharedspaces.SchemaVersion, SpaceID: spaceID,
		ParticipantID: participantID, IssuerParticipantID: issuerParticipantID,
		KeyEpoch: keyEpoch, Algorithm: sharedspaces.ParticipantKeyGrantAlgorithm,
		RecipientAgreementKeyFingerprint: hex.EncodeToString(recipientFingerprint[:]),
		EphemeralAgreementPublicKeyX963:  base64.RawURLEncoding.EncodeToString(publicKey),
		Nonce:                            base64.RawURLEncoding.EncodeToString(make([]byte, 12)),
		Ciphertext:                       base64.RawURLEncoding.EncodeToString([]byte("opaque wrapped content key")),
		AuthenticationTag:                base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
		CreatedAtMilliseconds:            now,
		Signature: sharedspaces.ParticipantKeyGrantSignature{
			Algorithm:             sharedspaces.ParticipantKeyGrantSignatureAlgorithm,
			PublicSigningKeyX963:  base64.RawURLEncoding.EncodeToString(publicKey),
			SigningKeyFingerprint: hex.EncodeToString(signingFingerprint[:]),
		},
	}
	payload, err := grant.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	grant.Signature.Signature = base64.RawURLEncoding.EncodeToString(signature)
	return &grant
}

func publishSharedSpaceBootstrapCheckpointHTTP(
	t *testing.T,
	handler http.Handler,
	domain relayDomainProvisioningRequest,
	nowMilliseconds int64,
) {
	t.Helper()
	domainRoot := "/v1/relay/tenants/" + domain.AdministrationCredential.TenantID.String() +
		"/domains/" + domain.AdministrationCredential.DomainID.String()
	fenceRequest := relay.CheckpointFenceRequest{
		RetryID: uuid.New(), FenceID: uuid.New(), RequestedAtMilliseconds: nowMilliseconds,
	}
	fenceResponse := performRelayJSON(
		t, handler, http.MethodPost, domainRoot+"/checkpoint-fences", fenceRequest,
		domain.MemberCredential.AuthorizationToken, domain.MemberCredential.MemberID,
	)
	requireStatus(t, fenceResponse, http.StatusCreated)
	var fence relay.CheckpointFenceResponse
	if err := json.NewDecoder(fenceResponse.Body).Decode(&fence); err != nil {
		t.Fatal(err)
	}
	_ = fenceResponse.Body.Close()
	candidate := relay.CheckpointCandidate{
		Version: relay.SchemaVersion, RetryID: uuid.New(), CheckpointID: uuid.New(),
		FenceID:                 fence.FenceID,
		TenantID:                domain.AdministrationCredential.TenantID,
		DomainID:                domain.AdministrationCredential.DomainID,
		PublisherSubscriptionID: domain.SubscriptionID,
		KeyEpoch:                sharedspaces.InitialKeyEpoch, CoveredThroughCursor: fence.BoundaryCursor,
		CreatedAtMilliseconds: nowMilliseconds,
	}
	staged := performRelayJSON(
		t, handler, http.MethodPost, domainRoot+"/checkpoints/candidates", candidate,
		domain.MemberCredential.AuthorizationToken, domain.MemberCredential.MemberID,
	)
	requireStatus(t, staged, http.StatusCreated)
	_ = staged.Body.Close()
	activation := relay.CheckpointActivationRequest{
		RetryID: uuid.New(), CheckpointID: candidate.CheckpointID,
		ActivatedAtMilliseconds: nowMilliseconds,
	}
	activated := performRelayJSON(
		t, handler, http.MethodPost,
		domainRoot+"/checkpoints/"+candidate.CheckpointID.String()+"/activation",
		activation, domain.AdministrationCredential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, activated, http.StatusCreated)
	_ = activated.Body.Close()
}

func sameRelayCapabilities(left, right []relay.Capability) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func TestProductAuthorityRoutesAreIsolatedByServiceConfiguration(t *testing.T) {
	operatorToken := relayTestToken(0x71)

	deviceRelay := relay.NewMemoryStore()
	deviceServer := newRelayTestServer(t, deviceRelay, operatorToken)
	deviceServer.SetDeviceSyncStore(devicesync.NewMemoryStore(deviceRelay))
	sharedOnDevice := performRelayJSON(
		t, deviceServer.Handler(), http.MethodPost, "/v1/shared-spaces",
		map[string]any{}, operatorToken, uuid.Nil,
	)
	requireStatus(t, sharedOnDevice, http.StatusNotFound)
	_ = sharedOnDevice.Body.Close()

	sharedRelay := relay.NewMemoryStore()
	sharedServer := newRelayTestServer(t, sharedRelay, operatorToken)
	sharedServer.SetSharedSpacesStore(sharedspaces.NewMemoryStore(sharedRelay))
	deviceOnShared := performRelayJSON(
		t, sharedServer.Handler(), http.MethodPost, "/v1/device-sync/accounts",
		map[string]any{}, operatorToken, uuid.Nil,
	)
	requireStatus(t, deviceOnShared, http.StatusNotFound)
	_ = deviceOnShared.Body.Close()
}
