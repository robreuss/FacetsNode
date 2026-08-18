package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
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
		Version:        sharedspaces.SchemaVersion,
		RetryID:        uuid.New(),
		ParticipantID:  participantID,
		SubscriptionID: subscriptionID,
		Kind:           sharedspaces.ParticipantPerson,
		Role:           sharedspaces.RoleReader,
		InvitationCredential: sharedSpaceInvitationCredential{
			InvitationID:       invitationID,
			AuthorizationToken: invitationToken,
		},
		ExpiresAtMilliseconds: nowMilliseconds + 60_000,
		CreatedAtMilliseconds: nowMilliseconds,
	}
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
		InvitationCredential: sharedSpaceInvitationCredential{
			InvitationID: cancelledInvitationID, AuthorizationToken: cancelledToken,
		},
		ExpiresAtMilliseconds: nowMilliseconds + 60_000,
		CreatedAtMilliseconds: nowMilliseconds,
	}
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
		len(issuedResult.Invitation.RelayAdmission.Capabilities) != len(sharedspaces.RoleReader.Capabilities()) {
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
	if len(status.Participants) != 2 || status.Relay.ActiveSubscriptionCount != 2 ||
		status.CurrentKeyEpoch != sharedspaces.InitialKeyEpoch || !status.BootstrapReady ||
		status.ActiveCheckpointEpoch == nil || *status.ActiveCheckpointEpoch != sharedspaces.InitialKeyEpoch ||
		status.Participants[1].Role != sharedspaces.RoleReader {
		t.Fatalf("status=%+v", status)
	}

	revocation := sharedspaces.ParticipantRevocation{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(),
		SpaceID: spaceID, ParticipantID: participantID,
		PreviousKeyEpoch: sharedspaces.InitialKeyEpoch, NextKeyEpoch: sharedspaces.InitialKeyEpoch + 1,
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
