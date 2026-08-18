package integration_test

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/sharedspaces"
)

// TestLiveSharedSpacesVerticalSlice proves the first product authority
// lifecycle against a running PostgreSQL-backed Shared Spaces service. It does
// not seed authority or relay state directly: a Space and host are provisioned
// through the operator API, a reader is invited and claims membership, opaque
// content crosses the relay, and revocation removes that participant's access.
func TestLiveSharedSpacesVerticalSlice(t *testing.T) {
	baseURL := strings.TrimRight(os.Getenv("FACETS_SHARED_SPACES_TEST_BASE_URL"), "/")
	operatorToken := os.Getenv("FACETS_SHARED_SPACES_TEST_OPERATOR_TOKEN")
	if baseURL == "" || operatorToken == "" {
		t.Skip("FACETS_SHARED_SPACES_TEST_BASE_URL and FACETS_SHARED_SPACES_TEST_OPERATOR_TOKEN are required")
	}

	client := &http.Client{Timeout: 30 * time.Second}
	now := time.Now().UnixMilli()
	domain := newLiveRelayDomainProvisioningRequest(now)
	spaceID := domain.AdministrationCredential.TenantID
	domainID := domain.AdministrationCredential.DomainID
	hostID := domain.MemberCredential.MemberID
	provisioning := liveSharedSpaceProvisioningInput{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(),
		SpaceID: spaceID, SecurityMode: sharedspaces.SecurityModeE2EE,
		InitialParticipantID: hostID, InitialParticipantKind: sharedspaces.ParticipantPerson,
		TenantProvisioning: liveRelayTenantProvisioningRequest{
			Version: relay.SchemaVersion, RetryID: uuid.New(),
			TenantProvisioningCredential: liveRelayTenantCredential{
				TenantID: spaceID, AuthorizationToken: encodedBytes(8),
			},
			InitialDomain: domain,
		},
	}
	created := requestRelayJSON(
		t, client, http.MethodPost, baseURL+"/v1/shared-spaces",
		provisioning, operatorToken, uuid.Nil,
	)
	requireStatus(t, created, http.StatusCreated)
	var createdResult sharedspaces.SpaceProvisioningResult
	decodeLiveJSON(t, created, &createdResult)
	if createdResult.SpaceID != spaceID ||
		createdResult.InitialParticipant.ParticipantID != hostID ||
		createdResult.InitialParticipant.Role != sharedspaces.RoleHost ||
		createdResult.CurrentKeyEpoch != sharedspaces.InitialKeyEpoch {
		t.Fatalf("unexpected Shared Space provisioning: %+v", createdResult)
	}
	requireStatusAndClose(t, requestRelayJSON(
		t, client, http.MethodPost, baseURL+"/v1/shared-spaces",
		provisioning, operatorToken, uuid.Nil,
	), http.StatusOK)

	participantID := uuid.New()
	invitationID := uuid.New()
	invitationToken := encodedBytes(40)
	invitation := liveSharedSpaceInvitationCreateInput{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(),
		ParticipantID: participantID, SubscriptionID: uuid.New(),
		Kind: sharedspaces.ParticipantPerson, Role: sharedspaces.RoleReader,
		InvitationCredential: liveSharedSpaceInvitationCredential{
			InvitationID: invitationID, AuthorizationToken: invitationToken,
		},
		ExpiresAtMilliseconds: now + int64(time.Hour/time.Millisecond),
		CreatedAtMilliseconds: now,
	}
	spaceRoot := baseURL + "/v1/shared-spaces/" + spaceID.String() +
		"/domains/" + domainID.String()
	relayRoot := baseURL + "/v1/relay/tenants/" + spaceID.String() +
		"/domains/" + domainID.String()
	requireStatusAndClose(t, requestRelayJSON(
		t, client, http.MethodPost, spaceRoot+"/invitations", invitation,
		domain.AdministrationCredential.AuthorizationToken, uuid.Nil,
	), http.StatusConflict)
	publishLiveSharedSpaceBootstrapCheckpoint(t, client, relayRoot, domain, now)
	requireStatusAndClose(t, requestRelayJSON(
		t, client, http.MethodPost, spaceRoot+"/invitations", invitation,
		domain.AdministrationCredential.AuthorizationToken, uuid.Nil,
	), http.StatusCreated)

	participantToken := encodedBytes(72)
	claim := liveSharedSpaceInvitationClaimInput{
		Version: sharedspaces.SchemaVersion, ParticipantID: participantID,
		MemberCredential: liveRelayMemberCredential{
			TenantID: spaceID, DomainID: domainID, MemberID: participantID,
			AuthorizationToken: participantToken,
		},
		ClaimedAtMilliseconds: now,
	}
	claimPath := spaceRoot + "/invitations/" + invitationID.String() + "/claim"
	requireStatusAndClose(t, requestRelayJSON(
		t, client, http.MethodPost, claimPath, claim, invitationToken, uuid.Nil,
	), http.StatusCreated)
	requireStatusAndClose(t, requestRelayJSON(
		t, client, http.MethodPost, claimPath, claim, invitationToken, uuid.Nil,
	), http.StatusOK)

	statusResponse := requestRelayJSON(
		t, client, http.MethodGet, spaceRoot+"/status", nil,
		domain.AdministrationCredential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, statusResponse, http.StatusOK)
	var status sharedspaces.SpaceStatus
	decodeLiveJSON(t, statusResponse, &status)
	if status.SpaceID != spaceID || len(status.Participants) != 2 ||
		status.Relay.ActiveSubscriptionCount != 2 ||
		status.CurrentKeyEpoch != sharedspaces.InitialKeyEpoch {
		t.Fatalf("unexpected Shared Space status: %+v", status)
	}

	message := relay.Envelope{
		Version: relay.SchemaVersion, Algorithm: relay.EnvelopeAlgorithm,
		TenantID: spaceID, DomainID: domainID, MessageID: uuid.New(),
		PublisherMemberID: hostID, KeyEpoch: 1,
		CreatedAtMilliseconds: now,
		Nonce: base64.RawURLEncoding.EncodeToString(
			bytes.Repeat([]byte{0x68}, 12),
		),
		Ciphertext: encodedBytes(120),
		AuthenticationTag: base64.RawURLEncoding.EncodeToString(
			bytes.Repeat([]byte{0x98}, 16),
		),
	}
	requireStatusAndClose(t, requestRelayJSON(
		t, client, http.MethodPut, relayRoot+"/messages/"+message.MessageID.String(),
		message, domain.MemberCredential.AuthorizationToken, hostID,
	), http.StatusCreated)
	participantCredential := relay.Credential{
		TenantID: spaceID, DomainID: domainID, MemberID: participantID,
		Token: participantToken,
	}
	fetched := requestRelayJSON(
		t, client, http.MethodGet, relayRoot+"/messages?limit=10", nil,
		participantCredential.Token, participantID,
	)
	requireStatus(t, fetched, http.StatusOK)
	var delivery struct {
		Messages []relay.Message `json:"messages"`
		Cursor   string          `json:"cursor"`
	}
	decodeLiveJSON(t, fetched, &delivery)
	if len(delivery.Messages) != 1 || delivery.Messages[0].Envelope.MessageID != message.MessageID {
		t.Fatalf("unexpected Shared Space relay delivery: %+v", delivery)
	}

	revocation := sharedspaces.ParticipantRevocation{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(),
		SpaceID: spaceID, ParticipantID: participantID,
		PreviousKeyEpoch: sharedspaces.InitialKeyEpoch, NextKeyEpoch: sharedspaces.InitialKeyEpoch + 1,
	}
	revokedResponse := requestRelayJSON(
		t, client, http.MethodPost,
		spaceRoot+"/participants/"+participantID.String()+"/revocation",
		revocation, domain.AdministrationCredential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, revokedResponse, http.StatusCreated)
	var revokedResult sharedspaces.ParticipantRevocationResult
	decodeLiveJSON(t, revokedResponse, &revokedResult)
	if revokedResult.PreviousKeyEpoch != sharedspaces.InitialKeyEpoch ||
		revokedResult.CurrentKeyEpoch != sharedspaces.InitialKeyEpoch+1 {
		t.Fatalf("unexpected Shared Space revocation: %+v", revokedResult)
	}
	statusResponse = requestRelayJSON(
		t, client, http.MethodGet, spaceRoot+"/status", nil,
		domain.AdministrationCredential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, statusResponse, http.StatusOK)
	decodeLiveJSON(t, statusResponse, &status)
	if status.CurrentKeyEpoch != sharedspaces.InitialKeyEpoch+1 {
		t.Fatalf("Shared Space key epoch did not advance: %+v", status)
	}
	staleMessage := message
	staleMessage.MessageID = uuid.New()
	requireStatusAndClose(t, requestRelayJSON(
		t, client, http.MethodPut,
		relayRoot+"/messages/"+staleMessage.MessageID.String(), staleMessage,
		domain.MemberCredential.AuthorizationToken, hostID,
	), http.StatusConflict)
	currentMessage := message
	currentMessage.MessageID = uuid.New()
	currentMessage.KeyEpoch = sharedspaces.InitialKeyEpoch + 1
	requireStatusAndClose(t, requestRelayJSON(
		t, client, http.MethodPut,
		relayRoot+"/messages/"+currentMessage.MessageID.String(), currentMessage,
		domain.MemberCredential.AuthorizationToken, hostID,
	), http.StatusCreated)
	requireStatusAndClose(t, requestRelayJSON(
		t, client, http.MethodGet, relayRoot+"/messages?limit=1", nil,
		participantCredential.Token, participantID,
	), http.StatusForbidden)
}

func publishLiveSharedSpaceBootstrapCheckpoint(
	t *testing.T,
	client *http.Client,
	relayRoot string,
	domain liveRelayDomainProvisioningRequest,
	now int64,
) {
	t.Helper()
	fenceRequest := relay.CheckpointFenceRequest{
		RetryID: uuid.New(), FenceID: uuid.New(), RequestedAtMilliseconds: now,
	}
	fenceResponse := requestRelayJSON(
		t, client, http.MethodPost, relayRoot+"/checkpoint-fences", fenceRequest,
		domain.MemberCredential.AuthorizationToken, domain.MemberCredential.MemberID,
	)
	requireStatus(t, fenceResponse, http.StatusCreated)
	var fence relay.CheckpointFenceResponse
	decodeLiveJSON(t, fenceResponse, &fence)
	candidate := relay.CheckpointCandidate{
		Version: relay.SchemaVersion, RetryID: uuid.New(), CheckpointID: uuid.New(),
		FenceID:                 fence.FenceID,
		TenantID:                domain.AdministrationCredential.TenantID,
		DomainID:                domain.AdministrationCredential.DomainID,
		PublisherSubscriptionID: domain.SubscriptionID,
		KeyEpoch:                sharedspaces.InitialKeyEpoch, CoveredThroughCursor: fence.BoundaryCursor,
		CreatedAtMilliseconds: now,
	}
	requireStatusAndClose(t, requestRelayJSON(
		t, client, http.MethodPost, relayRoot+"/checkpoints/candidates", candidate,
		domain.MemberCredential.AuthorizationToken, domain.MemberCredential.MemberID,
	), http.StatusCreated)
	activation := relay.CheckpointActivationRequest{
		RetryID: uuid.New(), CheckpointID: candidate.CheckpointID,
		ActivatedAtMilliseconds: now,
	}
	requireStatusAndClose(t, requestRelayJSON(
		t, client, http.MethodPost,
		relayRoot+"/checkpoints/"+candidate.CheckpointID.String()+"/activation",
		activation, domain.AdministrationCredential.AuthorizationToken, uuid.Nil,
	), http.StatusCreated)
}

type liveSharedSpaceProvisioningInput struct {
	Version                int                                `json:"version"`
	RetryID                uuid.UUID                          `json:"retryID"`
	SpaceID                uuid.UUID                          `json:"spaceID"`
	SecurityMode           sharedspaces.SecurityMode          `json:"securityMode"`
	InitialParticipantID   uuid.UUID                          `json:"initialParticipantID"`
	InitialParticipantKind sharedspaces.ParticipantKind       `json:"initialParticipantKind"`
	TenantProvisioning     liveRelayTenantProvisioningRequest `json:"tenantProvisioning"`
}

type liveSharedSpaceInvitationCredential struct {
	InvitationID       uuid.UUID `json:"invitationID"`
	AuthorizationToken string    `json:"authorizationToken"`
}

type liveSharedSpaceInvitationCreateInput struct {
	Version                     int                                 `json:"version"`
	RetryID                     uuid.UUID                           `json:"retryID"`
	ParticipantID               uuid.UUID                           `json:"participantID"`
	SubscriptionID              uuid.UUID                           `json:"subscriptionID"`
	Kind                        sharedspaces.ParticipantKind        `json:"kind"`
	Role                        sharedspaces.Role                   `json:"role"`
	InvitationCredential        liveSharedSpaceInvitationCredential `json:"invitationCredential"`
	ExpiresAtMilliseconds       int64                               `json:"expiresAtMilliseconds"`
	MemberExpiresAtMilliseconds *int64                              `json:"memberExpiresAtMilliseconds,omitempty"`
	CreatedAtMilliseconds       int64                               `json:"createdAtMilliseconds"`
}

type liveSharedSpaceInvitationClaimInput struct {
	Version               int                       `json:"version"`
	ParticipantID         uuid.UUID                 `json:"participantID"`
	MemberCredential      liveRelayMemberCredential `json:"memberCredential"`
	ClaimedAtMilliseconds int64                     `json:"claimedAtMilliseconds"`
}
