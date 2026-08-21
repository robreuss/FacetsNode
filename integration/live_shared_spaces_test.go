package integration_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"net/http"
	"os"
	"sort"
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
		SpaceID: spaceID, SecurityMode: sharedspaces.SecurityModeSecure,
		InteractionMode:      sharedspaces.InteractionModeCollaborative,
		InitialParticipantID: hostID, InitialParticipantKind: sharedspaces.ParticipantPerson,
		TenantProvisioning: liveRelayTenantProvisioningRequest{
			Version: relay.SchemaVersion, RetryID: uuid.New(),
			TenantProvisioningCredential: liveRelayTenantCredential{
				TenantID: spaceID, AuthorizationToken: encodedBytes(8),
			},
			InitialDomain: domain,
		},
	}
	provisioning.InitialParticipantSigningKey = liveSharedSpaceParticipantSigningKey(t, hostID)
	provisioning.InitialParticipantDeviceKeys = []sharedspaces.ParticipantDeviceKey{
		liveSharedSpaceParticipantDeviceKey(t, spaceID, hostID, now),
	}
	provisioning.InitialSecureRosterAttestation = liveSharedSpaceInitialRosterAttestation(
		t, provisioning, domainID, now,
	)
	created := requestRelayJSON(
		t, client, http.MethodPost, baseURL+"/v1/shared-spaces",
		provisioning, operatorToken, uuid.Nil,
	)
	requireStatus(t, created, http.StatusCreated)
	var createdResult sharedspaces.SpaceProvisioningResult
	decodeLiveJSON(t, created, &createdResult)
	if createdResult.SpaceID != spaceID ||
		createdResult.InteractionMode != sharedspaces.InteractionModeCollaborative ||
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
		InteractionMode: sharedspaces.InteractionModeCollaborative,
		InvitationCredential: liveSharedSpaceInvitationCredential{
			InvitationID: invitationID, AuthorizationToken: invitationToken,
		},
		ExpiresAtMilliseconds: now + int64(time.Hour/time.Millisecond),
		CreatedAtMilliseconds: now,
	}
	invitation.ParticipantSigningKey = liveSharedSpaceParticipantSigningKey(t, participantID)
	invitation.ParticipantDeviceKeys = []sharedspaces.ParticipantDeviceKey{
		liveSharedSpaceParticipantDeviceKey(t, spaceID, participantID, now),
	}
	invitation.KeyGrant = liveSharedSpaceParticipantKeyGrant(
		t, spaceID, participantID, hostID, sharedspaces.InitialKeyEpoch, now,
	)
	invitation.ActivationSecureRosterAttestation = liveSharedSpaceInvitationRosterAttestation(
		t, provisioning, domainID, invitation, *provisioning.InitialSecureRosterAttestation,
	)
	spaceRoot := baseURL + "/v1/shared-spaces/" + spaceID.String() +
		"/domains/" + domainID.String()
	relayRoot := baseURL + "/v1/relay/tenants/" + spaceID.String() +
		"/domains/" + domainID.String()
	requireStatusAndClose(t, requestRelayJSON(
		t, client, http.MethodPost, spaceRoot+"/invitations", invitation,
		domain.AdministrationCredential.AuthorizationToken, uuid.Nil,
	), http.StatusConflict)
	publishLiveSharedSpaceBootstrapCheckpoint(
		t, client, relayRoot, domain, sharedspaces.InitialKeyEpoch, now,
	)
	secondaryHostDeviceID := liveSharedSpaceParticipantSecondaryDeviceID(hostID)
	secondaryHostDeviceKey := liveSharedSpaceParticipantDeviceKeyWithID(
		t, spaceID, hostID, secondaryHostDeviceID, now,
	)
	deviceEnrollment := sharedspaces.ParticipantDeviceEnrollment{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(), SpaceID: spaceID,
		ParticipantID: hostID, DeviceKey: secondaryHostDeviceKey,
		KeyGrant: liveSharedSpaceParticipantKeyGrantForDevice(
			t, spaceID, hostID, secondaryHostDeviceID, hostID,
			sharedspaces.InitialKeyEpoch, now,
		),
		EnrolledAtMilliseconds: now,
	}
	deviceEnrollment.SecureRosterAttestation = liveSharedSpaceDeviceEnrollmentRosterAttestation(
		t, provisioning, domainID, *provisioning.InitialSecureRosterAttestation,
		hostID, secondaryHostDeviceKey, now,
	)
	deviceEnrollmentPath := spaceRoot + "/participants/" + hostID.String() +
		"/devices/" + secondaryHostDeviceID.String()
	requireStatusAndClose(t, requestRelayJSON(
		t, client, http.MethodPost, deviceEnrollmentPath, deviceEnrollment,
		domain.AdministrationCredential.AuthorizationToken, uuid.Nil,
	), http.StatusCreated)
	requireStatusAndClose(t, requestRelayJSON(
		t, client, http.MethodPost, deviceEnrollmentPath, deviceEnrollment,
		domain.AdministrationCredential.AuthorizationToken, uuid.Nil,
	), http.StatusOK)
	secondaryGrantResponse := requestRelayJSON(
		t, client, http.MethodGet,
		spaceRoot+"/participants/"+hostID.String()+"/key-grant?recipientDeviceID="+
			secondaryHostDeviceID.String(), nil,
		domain.MemberCredential.AuthorizationToken, hostID,
	)
	requireStatus(t, secondaryGrantResponse, http.StatusOK)
	var secondaryGrant sharedspaces.ParticipantKeyGrantResult
	decodeLiveJSON(t, secondaryGrantResponse, &secondaryGrant)
	if secondaryGrant.KeyGrant.RecipientDeviceID != secondaryHostDeviceID {
		t.Fatalf("additional host device grant was not addressable: %+v", secondaryGrant)
	}
	invitation.ActivationSecureRosterAttestation = liveSharedSpaceInvitationRosterAttestation(
		t, provisioning, domainID, invitation, *deviceEnrollment.SecureRosterAttestation,
	)
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
	claimResponse := requestRelayJSON(
		t, client, http.MethodPost, claimPath, claim, invitationToken, uuid.Nil,
	)
	requireStatus(t, claimResponse, http.StatusCreated)
	var claimResult sharedspaces.InvitationClaimResult
	decodeLiveJSON(t, claimResponse, &claimResult)
	if claimResult.SecureRosterAttestation == nil ||
		claimResult.SecureRosterAttestation.Revision != 3 ||
		claimResult.SecureRosterAttestation.CurrentKeyEpoch != sharedspaces.InitialKeyEpoch {
		t.Fatalf("Secure claim did not return its signed roster authority: %+v", claimResult)
	}
	retryClaimResponse := requestRelayJSON(
		t, client, http.MethodPost, claimPath, claim, invitationToken, uuid.Nil,
	)
	requireStatus(t, retryClaimResponse, http.StatusOK)
	var retryClaimResult sharedspaces.InvitationClaimResult
	decodeLiveJSON(t, retryClaimResponse, &retryClaimResult)
	if retryClaimResult.SecureRosterAttestation == nil ||
		mustLiveSecureRosterDigest(t, *retryClaimResult.SecureRosterAttestation) != mustLiveSecureRosterDigest(t, *claimResult.SecureRosterAttestation) {
		t.Fatalf("Secure claim retry did not preserve roster authority: %+v", retryClaimResult)
	}
	bootstrapResponse := requestRelayJSON(
		t, client, http.MethodGet,
		spaceRoot+"/participants/"+participantID.String()+"/bootstrap?recipientDeviceID="+
			liveSharedSpaceParticipantDeviceID(participantID).String(), nil,
		participantToken, participantID,
	)
	requireStatus(t, bootstrapResponse, http.StatusOK)
	var bootstrap sharedspaces.ParticipantBootstrap
	decodeLiveJSON(t, bootstrapResponse, &bootstrap)
	if err := bootstrap.Validate(); err != nil || bootstrap.Roster == nil ||
		bootstrap.Roster.CurrentKeyEpoch != sharedspaces.InitialKeyEpoch ||
		len(bootstrap.Roster.Participants) != 2 ||
		mustLiveSecureRosterDigest(t, bootstrap.Roster.AuthorityAttestation) != mustLiveSecureRosterDigest(t, *claimResult.SecureRosterAttestation) {
		t.Fatalf("Secure participant bootstrap was not atomically bound to its roster: bootstrap=%+v error=%v", bootstrap, err)
	}

	rosterHistoryPath := spaceRoot + "/participants/" + participantID.String() + "/roster-attestations"
	historyResponse := requestRelayJSON(
		t, client, http.MethodGet, rosterHistoryPath+"?limit=1", nil,
		participantToken, participantID,
	)
	requireStatus(t, historyResponse, http.StatusOK)
	var initialRosterPage sharedspaces.SecureRosterAttestationPage
	decodeLiveJSON(t, historyResponse, &initialRosterPage)
	if err := initialRosterPage.Validate(); err != nil || len(initialRosterPage.Attestations) != 1 ||
		initialRosterPage.Attestations[0].Revision != 1 || initialRosterPage.NextRevision != 1 {
		t.Fatalf("unexpected initial Secure roster history: page=%+v error=%v", initialRosterPage, err)
	}
	historyResponse = requestRelayJSON(
		t, client, http.MethodGet, rosterHistoryPath+"?afterRevision=1&limit=1", nil,
		participantToken, participantID,
	)
	requireStatus(t, historyResponse, http.StatusOK)
	var enrollmentRosterPage sharedspaces.SecureRosterAttestationPage
	decodeLiveJSON(t, historyResponse, &enrollmentRosterPage)
	if err := enrollmentRosterPage.Validate(); err != nil || len(enrollmentRosterPage.Attestations) != 1 ||
		enrollmentRosterPage.Attestations[0].Revision != 2 ||
		mustLiveSecureRosterDigest(t, enrollmentRosterPage.Attestations[0]) != mustLiveSecureRosterDigest(t, *deviceEnrollment.SecureRosterAttestation) {
		t.Fatalf("unexpected device enrollment Secure roster history: page=%+v error=%v", enrollmentRosterPage, err)
	}
	historyResponse = requestRelayJSON(
		t, client, http.MethodGet, rosterHistoryPath+"?afterRevision=2", nil,
		participantToken, participantID,
	)
	requireStatus(t, historyResponse, http.StatusOK)
	var activationRosterPage sharedspaces.SecureRosterAttestationPage
	decodeLiveJSON(t, historyResponse, &activationRosterPage)
	if err := activationRosterPage.Validate(); err != nil || len(activationRosterPage.Attestations) != 1 ||
		activationRosterPage.Attestations[0].Revision != 3 ||
		mustLiveSecureRosterDigest(t, activationRosterPage.Attestations[0]) != mustLiveSecureRosterDigest(t, *claimResult.SecureRosterAttestation) {
		t.Fatalf("unexpected activation Secure roster history: page=%+v error=%v", activationRosterPage, err)
	}

	// A role change is both a data-plane authorization change and a Secure
	// membership-authority transition. Exercise it against the running service
	// before testing the participant's newly granted capability.
	promotion := sharedspaces.ParticipantRoleChange{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(), SpaceID: spaceID,
		ParticipantID: participantID, PreviousRole: sharedspaces.RoleReader,
		NextRole: sharedspaces.RoleParticipant, ChangedAtMilliseconds: now + 1,
	}
	promotion.SecureRosterAttestation = liveSharedSpaceRoleChangeRosterAttestation(
		t, provisioning, domainID, promotion, *claimResult.SecureRosterAttestation,
	)
	promotionResponse := requestRelayJSON(
		t, client, http.MethodPost,
		spaceRoot+"/participants/"+participantID.String()+"/role",
		promotion, domain.AdministrationCredential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, promotionResponse, http.StatusCreated)
	var promotionResult sharedspaces.ParticipantRoleChangeResult
	decodeLiveJSON(t, promotionResponse, &promotionResult)
	if promotionResult.CurrentRole != sharedspaces.RoleParticipant ||
		promotionResult.PreviousRole != sharedspaces.RoleReader {
		t.Fatalf("unexpected Secure participant promotion: %+v", promotionResult)
	}
	promotedBootstrapResponse := requestRelayJSON(
		t, client, http.MethodGet,
		spaceRoot+"/participants/"+participantID.String()+"/bootstrap?recipientDeviceID="+
			liveSharedSpaceParticipantDeviceID(participantID).String(), nil,
		participantToken, participantID,
	)
	requireStatus(t, promotedBootstrapResponse, http.StatusOK)
	var promotedBootstrap sharedspaces.ParticipantBootstrap
	decodeLiveJSON(t, promotedBootstrapResponse, &promotedBootstrap)
	if err := promotedBootstrap.Validate(); err != nil ||
		promotedBootstrap.Status.Participant.Role != sharedspaces.RoleParticipant ||
		promotedBootstrap.Roster == nil || promotedBootstrap.Roster.AuthorityAttestation.Revision != 4 {
		t.Fatalf("Secure promotion bootstrap did not converge: bootstrap=%+v error=%v", promotedBootstrap, err)
	}

	statusResponse := requestRelayJSON(
		t, client, http.MethodGet, spaceRoot+"/status", nil,
		domain.AdministrationCredential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, statusResponse, http.StatusOK)
	var status sharedspaces.SpaceStatus
	decodeLiveJSON(t, statusResponse, &status)
	if status.SpaceID != spaceID || len(status.Participants) != 2 ||
		status.InteractionMode != sharedspaces.InteractionModeCollaborative ||
		status.Relay.ActiveSubscriptionCount != 2 ||
		status.CurrentKeyEpoch != sharedspaces.InitialKeyEpoch || !status.BootstrapReady ||
		status.ActiveCheckpointEpoch == nil || *status.ActiveCheckpointEpoch != sharedspaces.InitialKeyEpoch {
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
	participantMessage := message
	participantMessage.MessageID = uuid.New()
	participantMessage.PublisherMemberID = participantID
	participantMessage.CreatedAtMilliseconds = now + 2
	requireStatusAndClose(t, requestRelayJSON(
		t, client, http.MethodPut, relayRoot+"/messages/"+participantMessage.MessageID.String(),
		participantMessage, participantToken, participantID,
	), http.StatusCreated)

	revocation := sharedspaces.ParticipantRevocation{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(),
		SpaceID: spaceID, ParticipantID: participantID,
		PreviousKeyEpoch: sharedspaces.InitialKeyEpoch, NextKeyEpoch: sharedspaces.InitialKeyEpoch + 1,
		KeyGrants: []sharedspaces.ParticipantKeyGrant{
			*liveSharedSpaceParticipantKeyGrant(
				t, spaceID, hostID, hostID, sharedspaces.InitialKeyEpoch+1, now,
			),
			*liveSharedSpaceParticipantKeyGrantForDevice(
				t, spaceID, hostID, secondaryHostDeviceID, hostID,
				sharedspaces.InitialKeyEpoch+1, now,
			),
		},
	}
	revocation.SecureRosterAttestation = liveSharedSpaceRevocationRosterAttestation(
		t, provisioning, domainID, revocation, *promotion.SecureRosterAttestation, now,
	)
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
	historyResponse = requestRelayJSON(
		t, client, http.MethodGet, rosterHistoryPath, nil,
		domain.MemberCredential.AuthorizationToken, hostID,
	)
	requireStatus(t, historyResponse, http.StatusOK)
	var hostRosterHistory sharedspaces.SecureRosterAttestationPage
	decodeLiveJSON(t, historyResponse, &hostRosterHistory)
	if err := hostRosterHistory.Validate(); err != nil || len(hostRosterHistory.Attestations) != 5 ||
		hostRosterHistory.Attestations[4].Revision != 5 ||
		hostRosterHistory.Attestations[4].CurrentKeyEpoch != sharedspaces.InitialKeyEpoch+1 {
		t.Fatalf("unexpected post-revocation Secure roster history: page=%+v error=%v", hostRosterHistory, err)
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
	deviceRevokedAt := time.Now().UnixMilli()
	publishLiveSharedSpaceBootstrapCheckpoint(
		t, client, relayRoot, domain, sharedspaces.InitialKeyEpoch+1, deviceRevokedAt,
	)
	revokedDeviceKey := liveSharedSpaceRevokedParticipantDeviceKey(
		t, secondaryHostDeviceKey, deviceRevokedAt,
	)
	deviceRevocation := sharedspaces.ParticipantDeviceRevocation{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(), SpaceID: spaceID,
		ParticipantID: hostID, DeviceID: secondaryHostDeviceID, DeviceKey: revokedDeviceKey,
		PreviousKeyEpoch: sharedspaces.InitialKeyEpoch + 1,
		NextKeyEpoch:     sharedspaces.InitialKeyEpoch + 2,
		KeyGrants: []sharedspaces.ParticipantKeyGrant{*liveSharedSpaceParticipantKeyGrant(
			t, spaceID, hostID, hostID, sharedspaces.InitialKeyEpoch+2, deviceRevokedAt,
		)},
	}
	deviceRevocation.SecureRosterAttestation = liveSharedSpaceDeviceRevocationRosterAttestation(
		t, provisioning, domainID, *revocation.SecureRosterAttestation,
		revokedDeviceKey, deviceRevocation.NextKeyEpoch, deviceRevokedAt,
	)
	deviceRevocationPath := spaceRoot + "/participants/" + hostID.String() +
		"/devices/" + secondaryHostDeviceID.String() + "/revocation"
	requireStatusAndClose(t, requestRelayJSON(
		t, client, http.MethodPost, deviceRevocationPath, deviceRevocation,
		domain.AdministrationCredential.AuthorizationToken, uuid.Nil,
	), http.StatusCreated)
	requireStatusAndClose(t, requestRelayJSON(
		t, client, http.MethodPost, deviceRevocationPath, deviceRevocation,
		domain.AdministrationCredential.AuthorizationToken, uuid.Nil,
	), http.StatusOK)
	requireStatusAndClose(t, requestRelayJSON(
		t, client, http.MethodGet,
		spaceRoot+"/participants/"+hostID.String()+"/key-grant?recipientDeviceID="+
			secondaryHostDeviceID.String(), nil,
		domain.MemberCredential.AuthorizationToken, hostID,
	), http.StatusNotFound)
	initialHostGrantResponse := requestRelayJSON(
		t, client, http.MethodGet,
		spaceRoot+"/participants/"+hostID.String()+"/key-grant?recipientDeviceID="+
			liveSharedSpaceParticipantDeviceID(hostID).String(), nil,
		domain.MemberCredential.AuthorizationToken, hostID,
	)
	requireStatus(t, initialHostGrantResponse, http.StatusOK)
	var initialHostGrant sharedspaces.ParticipantKeyGrantResult
	decodeLiveJSON(t, initialHostGrantResponse, &initialHostGrant)
	if initialHostGrant.CurrentKeyEpoch != sharedspaces.InitialKeyEpoch+2 {
		t.Fatalf("remaining host device did not receive the rotated grant: %+v", initialHostGrant)
	}
	requireStatusAndClose(t, requestRelayJSON(
		t, client, http.MethodGet, relayRoot+"/messages?limit=1", nil,
		participantCredential.Token, participantID,
	), http.StatusForbidden)
	requireStatusAndClose(t, requestRelayJSON(
		t, client, http.MethodGet, rosterHistoryPath, nil,
		participantCredential.Token, participantID,
	), http.StatusForbidden)
}

func publishLiveSharedSpaceBootstrapCheckpoint(
	t *testing.T,
	client *http.Client,
	relayRoot string,
	domain liveRelayDomainProvisioningRequest,
	keyEpoch uint64,
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
		KeyEpoch:                keyEpoch, CoveredThroughCursor: fence.BoundaryCursor,
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
	TenantProvisioning             liveRelayTenantProvisioningRequest    `json:"tenantProvisioning"`
}

type liveSharedSpaceInvitationCredential struct {
	InvitationID       uuid.UUID `json:"invitationID"`
	AuthorizationToken string    `json:"authorizationToken"`
}

type liveSharedSpaceInvitationCreateInput struct {
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
	InvitationCredential              liveSharedSpaceInvitationCredential   `json:"invitationCredential"`
	ExpiresAtMilliseconds             int64                                 `json:"expiresAtMilliseconds"`
	MemberExpiresAtMilliseconds       *int64                                `json:"memberExpiresAtMilliseconds,omitempty"`
	CreatedAtMilliseconds             int64                                 `json:"createdAtMilliseconds"`
}

func liveSharedSpaceParticipantKeyGrant(
	t *testing.T,
	spaceID uuid.UUID,
	participantID uuid.UUID,
	issuerParticipantID uuid.UUID,
	keyEpoch uint64,
	now int64,
) *sharedspaces.ParticipantKeyGrant {
	t.Helper()
	return liveSharedSpaceParticipantKeyGrantForDevice(
		t, spaceID, participantID, liveSharedSpaceParticipantDeviceID(participantID),
		issuerParticipantID, keyEpoch, now,
	)
}

func liveSharedSpaceParticipantKeyGrantForDevice(
	t *testing.T,
	spaceID uuid.UUID,
	participantID uuid.UUID,
	recipientDeviceID uuid.UUID,
	issuerParticipantID uuid.UUID,
	keyEpoch uint64,
	now int64,
) *sharedspaces.ParticipantKeyGrant {
	t.Helper()
	privateKey := liveSharedSpaceParticipantSigningPrivateKey(t, issuerParticipantID)
	publicKey := elliptic.Marshal(elliptic.P256(), privateKey.PublicKey.X, privateKey.PublicKey.Y)
	signingFingerprint := sha256.Sum256(publicKey)
	recipientDeviceKey := liveSharedSpaceParticipantDeviceKeyWithID(
		t, spaceID, participantID, recipientDeviceID, now,
	)
	grant := sharedspaces.ParticipantKeyGrant{
		Version: sharedspaces.SchemaVersion, SpaceID: spaceID,
		ParticipantID: participantID, RecipientDeviceID: recipientDeviceKey.DeviceID,
		IssuerParticipantID: issuerParticipantID,
		KeyEpoch:            keyEpoch, Algorithm: sharedspaces.ParticipantKeyGrantAlgorithm,
		RecipientAgreementKeyFingerprint: recipientDeviceKey.AgreementKeyFingerprint,
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

func liveSharedSpaceParticipantSigningPrivateKey(t *testing.T, participantID uuid.UUID) *ecdsa.PrivateKey {
	t.Helper()
	curve := elliptic.P256()
	digest := sha256.Sum256(participantID[:])
	maximum := new(big.Int).Sub(curve.Params().N, big.NewInt(1))
	privateScalar := new(big.Int).SetBytes(digest[:])
	privateScalar.Mod(privateScalar, maximum)
	privateScalar.Add(privateScalar, big.NewInt(1))
	x, y := curve.ScalarBaseMult(privateScalar.Bytes())
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y},
		D:         privateScalar,
	}
}

func liveSharedSpaceParticipantSigningKey(t *testing.T, participantID uuid.UUID) sharedspaces.ParticipantSigningKey {
	t.Helper()
	privateKey := liveSharedSpaceParticipantSigningPrivateKey(t, participantID)
	publicKey := elliptic.Marshal(elliptic.P256(), privateKey.PublicKey.X, privateKey.PublicKey.Y)
	fingerprint := sha256.Sum256(publicKey)
	return sharedspaces.ParticipantSigningKey{
		Algorithm:             sharedspaces.ParticipantKeyGrantSignatureAlgorithm,
		PublicKeyX963:         base64.RawURLEncoding.EncodeToString(publicKey),
		SigningKeyFingerprint: hex.EncodeToString(fingerprint[:]),
	}
}

func liveSharedSpaceParticipantDeviceID(participantID uuid.UUID) uuid.UUID {
	digest := sha256.Sum256(append([]byte("facets-shared-space-live-device:"), participantID[:]...))
	deviceID, err := uuid.FromBytes(digest[:16])
	if err != nil {
		panic(err)
	}
	return deviceID
}

func liveSharedSpaceParticipantSecondaryDeviceID(participantID uuid.UUID) uuid.UUID {
	digest := sha256.Sum256(append([]byte("facets-shared-space-live-secondary-device:"), participantID[:]...))
	deviceID, err := uuid.FromBytes(digest[:16])
	if err != nil {
		panic(err)
	}
	return deviceID
}

func liveSharedSpaceParticipantDeviceKey(
	t *testing.T,
	spaceID uuid.UUID,
	participantID uuid.UUID,
	createdAtMilliseconds int64,
) sharedspaces.ParticipantDeviceKey {
	t.Helper()
	return liveSharedSpaceParticipantDeviceKeyWithID(
		t, spaceID, participantID, liveSharedSpaceParticipantDeviceID(participantID),
		createdAtMilliseconds,
	)
}

func liveSharedSpaceParticipantDeviceKeyWithID(
	t *testing.T,
	spaceID uuid.UUID,
	participantID uuid.UUID,
	deviceID uuid.UUID,
	createdAtMilliseconds int64,
) sharedspaces.ParticipantDeviceKey {
	t.Helper()
	agreementPrivateKey := liveSharedSpaceParticipantSigningPrivateKey(t, deviceID)
	agreementPublicKey := elliptic.Marshal(
		elliptic.P256(), agreementPrivateKey.PublicKey.X, agreementPrivateKey.PublicKey.Y,
	)
	agreementFingerprint := sha256.Sum256(agreementPublicKey)
	signingPrivateKey := liveSharedSpaceParticipantSigningPrivateKey(t, participantID)
	signingPublicKey := elliptic.Marshal(
		elliptic.P256(), signingPrivateKey.PublicKey.X, signingPrivateKey.PublicKey.Y,
	)
	signingFingerprint := sha256.Sum256(signingPublicKey)
	key := sharedspaces.ParticipantDeviceKey{
		Version: sharedspaces.SchemaVersion, SpaceID: spaceID,
		ParticipantID: participantID, DeviceID: deviceID, Algorithm: "P256",
		AgreementPublicKeyX963:  base64.RawURLEncoding.EncodeToString(agreementPublicKey),
		AgreementKeyFingerprint: hex.EncodeToString(agreementFingerprint[:]),
		CreatedAtMilliseconds:   createdAtMilliseconds,
		Signature: sharedspaces.ParticipantKeyGrantSignature{
			Algorithm:             sharedspaces.ParticipantKeyGrantSignatureAlgorithm,
			PublicSigningKeyX963:  base64.RawURLEncoding.EncodeToString(signingPublicKey),
			SigningKeyFingerprint: hex.EncodeToString(signingFingerprint[:]),
		},
	}
	payload, err := key.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	r, s, err := ecdsa.Sign(rand.Reader, signingPrivateKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	key.Signature.Signature = base64.RawURLEncoding.EncodeToString(signature)
	return key
}

func liveSharedSpaceRevokedParticipantDeviceKey(
	t *testing.T,
	current sharedspaces.ParticipantDeviceKey,
	revokedAtMilliseconds int64,
) sharedspaces.ParticipantDeviceKey {
	t.Helper()
	key := current
	key.RevokedAtMilliseconds = &revokedAtMilliseconds
	privateKey := liveSharedSpaceParticipantSigningPrivateKey(t, key.ParticipantID)
	payload, err := key.SigningPayload()
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
	key.Signature.Signature = base64.RawURLEncoding.EncodeToString(signature)
	return key
}

func liveSharedSpaceInitialRosterAttestation(
	t *testing.T,
	provisioning liveSharedSpaceProvisioningInput,
	domainID uuid.UUID,
	nowMilliseconds int64,
) *sharedspaces.SecureRosterAttestation {
	t.Helper()
	host := sharedspaces.Participant{
		Version: sharedspaces.SchemaVersion, SpaceID: provisioning.SpaceID,
		ParticipantID:  provisioning.InitialParticipantID,
		SubscriptionID: provisioning.TenantProvisioning.InitialDomain.SubscriptionID,
		Kind:           provisioning.InitialParticipantKind, Role: sharedspaces.RoleHost,
		SigningKey:            provisioning.InitialParticipantSigningKey,
		DeviceKeys:            provisioning.InitialParticipantDeviceKeys,
		CreatedAtMilliseconds: nowMilliseconds,
	}
	return liveSharedSpaceSignedRosterAttestation(
		t, provisioning.SpaceID, domainID, 1, "", sharedspaces.InitialKeyEpoch,
		[]sharedspaces.Participant{host}, provisioning.InitialParticipantID, nowMilliseconds,
	)
}

func liveSharedSpaceInvitationRosterAttestation(
	t *testing.T,
	provisioning liveSharedSpaceProvisioningInput,
	domainID uuid.UUID,
	invitation liveSharedSpaceInvitationCreateInput,
	previous sharedspaces.SecureRosterAttestation,
) *sharedspaces.SecureRosterAttestation {
	t.Helper()
	participants := append([]sharedspaces.Participant(nil), previous.Participants...)
	member := sharedspaces.Participant{
		Version: sharedspaces.SchemaVersion, SpaceID: provisioning.SpaceID,
		ParticipantID: invitation.ParticipantID, SubscriptionID: invitation.SubscriptionID,
		Kind: invitation.Kind, Role: invitation.Role, SigningKey: invitation.ParticipantSigningKey,
		DeviceKeys:            invitation.ParticipantDeviceKeys,
		CreatedAtMilliseconds: invitation.CreatedAtMilliseconds,
	}
	participants = append(participants, member)
	return liveSharedSpaceSuccessorRosterAttestation(
		t, provisioning, domainID, previous, previous.CurrentKeyEpoch,
		participants, invitation.CreatedAtMilliseconds,
	)
}

func liveSharedSpaceDeviceEnrollmentRosterAttestation(
	t *testing.T,
	provisioning liveSharedSpaceProvisioningInput,
	domainID uuid.UUID,
	previous sharedspaces.SecureRosterAttestation,
	participantID uuid.UUID,
	deviceKey sharedspaces.ParticipantDeviceKey,
	enrolledAtMilliseconds int64,
) *sharedspaces.SecureRosterAttestation {
	t.Helper()
	participants := append([]sharedspaces.Participant(nil), previous.Participants...)
	for index := range participants {
		if participants[index].ParticipantID != participantID {
			continue
		}
		participants[index].DeviceKeys = append(
			[]sharedspaces.ParticipantDeviceKey(nil), participants[index].DeviceKeys...,
		)
		participants[index].DeviceKeys = append(participants[index].DeviceKeys, deviceKey)
		sort.Slice(participants[index].DeviceKeys, func(left, right int) bool {
			return participants[index].DeviceKeys[left].DeviceID.String() <
				participants[index].DeviceKeys[right].DeviceID.String()
		})
	}
	return liveSharedSpaceSuccessorRosterAttestation(
		t, provisioning, domainID, previous, previous.CurrentKeyEpoch,
		participants, enrolledAtMilliseconds,
	)
}

func liveSharedSpaceRevocationRosterAttestation(
	t *testing.T,
	provisioning liveSharedSpaceProvisioningInput,
	domainID uuid.UUID,
	revocation sharedspaces.ParticipantRevocation,
	previous sharedspaces.SecureRosterAttestation,
	createdAtMilliseconds int64,
) *sharedspaces.SecureRosterAttestation {
	t.Helper()
	participants := make([]sharedspaces.Participant, 0, len(previous.Participants)-1)
	for _, participant := range previous.Participants {
		if participant.ParticipantID != revocation.ParticipantID {
			participants = append(participants, participant)
		}
	}
	return liveSharedSpaceSuccessorRosterAttestation(
		t, provisioning, domainID, previous, revocation.NextKeyEpoch, participants,
		createdAtMilliseconds,
	)
}

func liveSharedSpaceDeviceRevocationRosterAttestation(
	t *testing.T,
	provisioning liveSharedSpaceProvisioningInput,
	domainID uuid.UUID,
	previous sharedspaces.SecureRosterAttestation,
	revokedDeviceKey sharedspaces.ParticipantDeviceKey,
	nextKeyEpoch uint64,
	createdAtMilliseconds int64,
) *sharedspaces.SecureRosterAttestation {
	t.Helper()
	participants := append([]sharedspaces.Participant(nil), previous.Participants...)
	for participantIndex := range participants {
		participants[participantIndex].DeviceKeys = append(
			[]sharedspaces.ParticipantDeviceKey(nil), participants[participantIndex].DeviceKeys...,
		)
		if participants[participantIndex].ParticipantID != revokedDeviceKey.ParticipantID {
			continue
		}
		for deviceIndex := range participants[participantIndex].DeviceKeys {
			if participants[participantIndex].DeviceKeys[deviceIndex].DeviceID == revokedDeviceKey.DeviceID {
				participants[participantIndex].DeviceKeys[deviceIndex] = revokedDeviceKey
			}
		}
	}
	return liveSharedSpaceSuccessorRosterAttestation(
		t, provisioning, domainID, previous, nextKeyEpoch, participants,
		createdAtMilliseconds,
	)
}

func liveSharedSpaceRoleChangeRosterAttestation(
	t *testing.T,
	provisioning liveSharedSpaceProvisioningInput,
	domainID uuid.UUID,
	change sharedspaces.ParticipantRoleChange,
	previous sharedspaces.SecureRosterAttestation,
) *sharedspaces.SecureRosterAttestation {
	t.Helper()
	participants := append([]sharedspaces.Participant(nil), previous.Participants...)
	for index := range participants {
		if participants[index].ParticipantID == change.ParticipantID {
			participants[index].Role = change.NextRole
			break
		}
	}
	return liveSharedSpaceSuccessorRosterAttestation(
		t, provisioning, domainID, previous, previous.CurrentKeyEpoch, participants,
		change.ChangedAtMilliseconds,
	)
}

func liveSharedSpaceSuccessorRosterAttestation(
	t *testing.T,
	provisioning liveSharedSpaceProvisioningInput,
	domainID uuid.UUID,
	previous sharedspaces.SecureRosterAttestation,
	keyEpoch uint64,
	participants []sharedspaces.Participant,
	createdAtMilliseconds int64,
) *sharedspaces.SecureRosterAttestation {
	t.Helper()
	return liveSharedSpaceSignedRosterAttestation(
		t, provisioning.SpaceID, domainID, previous.Revision+1,
		mustLiveSecureRosterDigest(t, previous), keyEpoch, participants,
		provisioning.InitialParticipantID, createdAtMilliseconds,
	)
}

func liveSharedSpaceSignedRosterAttestation(
	t *testing.T,
	spaceID uuid.UUID,
	domainID uuid.UUID,
	revision uint64,
	previousDigest string,
	keyEpoch uint64,
	participants []sharedspaces.Participant,
	issuerParticipantID uuid.UUID,
	createdAtMilliseconds int64,
) *sharedspaces.SecureRosterAttestation {
	t.Helper()
	sortedParticipants := append([]sharedspaces.Participant(nil), participants...)
	sort.Slice(sortedParticipants, func(left, right int) bool {
		return sortedParticipants[left].ParticipantID.String() < sortedParticipants[right].ParticipantID.String()
	})
	privateKey := liveSharedSpaceParticipantSigningPrivateKey(t, issuerParticipantID)
	publicKey := elliptic.Marshal(elliptic.P256(), privateKey.PublicKey.X, privateKey.PublicKey.Y)
	fingerprint := sha256.Sum256(publicKey)
	attestation := &sharedspaces.SecureRosterAttestation{
		Version: sharedspaces.SchemaVersion, SpaceID: spaceID, DomainID: domainID,
		Revision: revision, PreviousDigest: previousDigest, CurrentKeyEpoch: keyEpoch,
		Participants: sortedParticipants, IssuerParticipantID: issuerParticipantID,
		CreatedAtMilliseconds: createdAtMilliseconds,
		Signature: sharedspaces.ParticipantKeyGrantSignature{
			Algorithm:             sharedspaces.ParticipantKeyGrantSignatureAlgorithm,
			PublicSigningKeyX963:  base64.RawURLEncoding.EncodeToString(publicKey),
			SigningKeyFingerprint: hex.EncodeToString(fingerprint[:]),
		},
	}
	payload, err := attestation.SigningPayload()
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
	attestation.Signature.Signature = base64.RawURLEncoding.EncodeToString(signature)
	return attestation
}

func mustLiveSecureRosterDigest(t *testing.T, attestation sharedspaces.SecureRosterAttestation) string {
	t.Helper()
	digest, err := attestation.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

type liveSharedSpaceInvitationClaimInput struct {
	Version               int                       `json:"version"`
	ParticipantID         uuid.UUID                 `json:"participantID"`
	MemberCredential      liveRelayMemberCredential `json:"memberCredential"`
	ClaimedAtMilliseconds int64                     `json:"claimedAtMilliseconds"`
}
