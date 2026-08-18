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
	if claimResult.Participant.Role != sharedspaces.RoleReader {
		t.Fatalf("claim=%+v", claimResult)
	}
	claimRetry := performRelayJSON(
		t, handler, http.MethodPost, claimPath, claim, invitationToken, uuid.Nil,
	)
	requireStatus(t, claimRetry, http.StatusOK)
	_ = claimRetry.Body.Close()

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
		status.CurrentKeyEpoch != sharedspaces.InitialKeyEpoch {
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
