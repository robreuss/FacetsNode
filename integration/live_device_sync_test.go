package integration_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/devicesync"
	"github.com/robreuss/FacetsNode/internal/protocol"
	"github.com/robreuss/FacetsNode/internal/relay"
)

// TestLiveDeviceSyncVerticalSlice is the product-level acceptance harness for
// the self-hosted Device Sync service. Unlike the in-memory data-plane tests,
// this test does not seed relay or Device Sync authority directly. It creates
// every principal, device, Space, and relay membership through the public HTTP
// contract, then proves opaque checkpoint, tail, blob, acknowledgement,
// status, and revocation behavior against the running PostgreSQL-backed
// service.
func TestLiveDeviceSyncVerticalSlice(t *testing.T) {
	baseURL := strings.TrimRight(os.Getenv("FACETS_SERVER_TEST_BASE_URL"), "/")
	operatorToken := os.Getenv("FACETS_SERVER_TEST_OPERATOR_TOKEN")
	if baseURL == "" || operatorToken == "" {
		t.Skip("FACETS_SERVER_TEST_BASE_URL and FACETS_SERVER_TEST_OPERATOR_TOKEN are required")
	}

	client := &http.Client{Timeout: 30 * time.Second}
	now := time.Now().UnixMilli()
	expiresAt := now + int64(time.Hour/time.Millisecond)

	accountAdmission := liveDeviceSyncAdmissionCredential{
		AdmissionID: uuid.New(), AuthorizationToken: encodedBytes(8),
	}
	accountAdmissionInput := liveDeviceSyncAdmissionCreateInput{
		Version: devicesync.SchemaVersion, RetryID: uuid.New(),
		AdmissionCredential:   accountAdmission,
		ExpiresAtMilliseconds: expiresAt,
	}
	requireStatusAndClose(t, requestRelayJSON(
		t, client, http.MethodPost, baseURL+"/v1/device-sync/account-admissions",
		accountAdmissionInput, operatorToken, uuid.Nil,
	), http.StatusCreated)

	controlDomain := newLiveRelayDomainProvisioningRequest(now)
	principalID := controlDomain.AdministrationCredential.TenantID
	initialDeviceID := controlDomain.MemberCredential.MemberID
	principalToken := encodedBytes(40)
	principalClaim := liveDeviceSyncPrincipalClaimInput{
		Version: devicesync.SchemaVersion, RetryID: uuid.New(),
		PrincipalID: principalID, InitialDeviceID: initialDeviceID,
		TenantProvisioning: liveRelayTenantProvisioningRequest{
			Version: relay.SchemaVersion, RetryID: uuid.New(),
			TenantProvisioningCredential: liveRelayTenantCredential{
				TenantID: principalID, AuthorizationToken: principalToken,
			},
			InitialDomain: controlDomain,
		},
	}
	principalResponse := requestRelayJSON(
		t, client, http.MethodPost,
		baseURL+"/v1/device-sync/account-admissions/"+
			accountAdmission.AdmissionID.String()+"/claim",
		principalClaim, accountAdmission.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, principalResponse, http.StatusCreated)
	var principalResult devicesync.PrincipalProvisioningResult
	decodeLiveJSON(t, principalResponse, &principalResult)
	if principalResult.PrincipalID != principalID ||
		principalResult.DeviceID != initialDeviceID {
		t.Fatalf("unexpected Device Sync principal result: %+v", principalResult)
	}

	secondDeviceID := uuid.New()
	secondControlCredential := liveDeviceSyncAdmitDevice(
		t, client, baseURL, principalID, secondDeviceID, controlDomain,
		uuid.Nil, expiresAt, encodedBytes(72), encodedBytes(104),
	)

	spaceID := uuid.New()
	spaceDomain := newLiveRelayDomainProvisioningRequest(now)
	spaceDomain.AdministrationCredential.TenantID = principalID
	spaceDomain.MemberCredential.TenantID = principalID
	spaceDomain.MemberCredential.MemberID = initialDeviceID
	spaceProvisioning := liveDeviceSyncSpaceProvisioningInput{
		Version: devicesync.SchemaVersion, RetryID: uuid.New(),
		InitialDeviceID: initialDeviceID, Domain: spaceDomain,
	}
	spaceResponse := requestRelayJSON(
		t, client, http.MethodPost,
		fmt.Sprintf("%s/v1/device-sync/principals/%s/spaces/%s", baseURL, principalID, spaceID),
		spaceProvisioning, principalToken, uuid.Nil,
	)
	requireStatus(t, spaceResponse, http.StatusCreated)
	var spaceResult devicesync.SpaceProvisioningResult
	decodeLiveJSON(t, spaceResponse, &spaceResult)
	if spaceResult.PrincipalID != principalID || spaceResult.SpaceID != spaceID ||
		spaceResult.Domain.DomainID != spaceDomain.AdministrationCredential.DomainID {
		t.Fatalf("unexpected Device Sync Space result: %+v", spaceResult)
	}

	secondSpaceCredential := liveDeviceSyncAdmitDevice(
		t, client, baseURL, principalID, secondDeviceID, spaceDomain,
		spaceID, expiresAt, encodedBytes(136), encodedBytes(168),
	)
	spaceBasePath := fmt.Sprintf(
		"%s/v1/relay/tenants/%s/domains/%s",
		baseURL, principalID, spaceDomain.AdministrationCredential.DomainID,
	)
	initialSpaceCredential := relay.Credential{
		TenantID: principalID,
		DomainID: spaceDomain.AdministrationCredential.DomainID,
		MemberID: initialDeviceID,
		Token:    spaceDomain.MemberCredential.AuthorizationToken,
	}

	checkpoint := liveDeviceSyncTransportEnvelope(
		t, protocol.PayloadFEFCheckpoint, now,
		[]byte(`{"fef":"opaque-live-checkpoint"}`), nil,
	)
	mutation := liveDeviceSyncTransportEnvelope(
		t, protocol.PayloadFEFMutationBatch, now+1,
		[]byte(`{"fef":"opaque-live-mutation"}`), []uuid.UUID{checkpoint.MessageID},
	)
	for _, transportEnvelope := range []protocol.TransportEnvelope{checkpoint, mutation} {
		relayEnvelope := liveDeviceSyncRelayEnvelope(t, transportEnvelope, initialSpaceCredential)
		requireStatusAndClose(t, requestRelayJSON(
			t, client, http.MethodPut,
			spaceBasePath+"/messages/"+transportEnvelope.MessageID.String(),
			relayEnvelope, initialSpaceCredential.Token, initialSpaceCredential.MemberID,
		), http.StatusCreated)
	}

	fetch := requestRelayJSON(
		t, client, http.MethodGet, spaceBasePath+"/messages?limit=10", nil,
		secondSpaceCredential.Token, secondDeviceID,
	)
	requireStatus(t, fetch, http.StatusOK)
	var fetched struct {
		Messages []relay.Message `json:"messages"`
		Cursor   string          `json:"cursor"`
	}
	decodeLiveJSON(t, fetch, &fetched)
	if len(fetched.Messages) != 2 || fetched.Cursor != relay.EncodeCursor(2) {
		t.Fatalf("unexpected live Device Sync fetch: %+v", fetched)
	}
	for index, expected := range []protocol.TransportEnvelope{checkpoint, mutation} {
		actual := liveDeviceSyncDecodeEnvelope(t, fetched.Messages[index].Envelope)
		if actual.MessageID != expected.MessageID || actual.Kind != expected.Kind ||
			actual.PayloadSHA256 != expected.PayloadSHA256 {
			t.Fatalf("transport envelope %d mismatch: got=%+v expected=%+v", index, actual, expected)
		}
		for _, stage := range []string{"accepted", "applied"} {
			requireStatusAndClose(t, requestRelayJSON(
				t, client, http.MethodPost,
				spaceBasePath+"/messages/"+expected.MessageID.String()+"/acknowledgments",
				map[string]string{"stage": stage},
				secondSpaceCredential.Token, secondDeviceID,
			), http.StatusOK)
		}
	}

	blobBytes := []byte("opaque live Device Sync encrypted blob")
	uploadLiveRelayBlob(t, client, spaceBasePath, initialSpaceCredential, blobBytes, true)
	blobResponse := requestRelayBlob(
		t, client, http.MethodGet,
		spaceBasePath+"/blobs/"+relay.BlobID(blobBytes), nil,
		secondSpaceCredential.Token, secondDeviceID, "",
	)
	requireStatus(t, blobResponse, http.StatusOK)
	downloaded, err := io.ReadAll(blobResponse.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = blobResponse.Body.Close()
	if !bytes.Equal(downloaded, blobBytes) {
		t.Fatalf("live Device Sync blob mismatch: got=%q expected=%q", downloaded, blobBytes)
	}

	statusPath := fmt.Sprintf("%s/v1/device-sync/principals/%s/status", baseURL, principalID)
	statusResponse := requestRelayJSON(
		t, client, http.MethodGet, statusPath, nil, principalToken, uuid.Nil,
	)
	requireStatus(t, statusResponse, http.StatusOK)
	var status devicesync.PrincipalStatus
	decodeLiveJSON(t, statusResponse, &status)
	if len(status.Devices) != 2 || len(status.Spaces) != 1 ||
		len(status.Spaces[0].Devices) != 2 {
		t.Fatalf("unexpected live Device Sync status: %+v", status)
	}

	revocation := devicesync.DeviceRevocation{
		Version: devicesync.SchemaVersion, RetryID: uuid.New(),
		PrincipalID: principalID, DeviceID: secondDeviceID,
	}
	revocationPath := fmt.Sprintf(
		"%s/v1/device-sync/principals/%s/devices/%s/revocation",
		baseURL, principalID, secondDeviceID,
	)
	requireStatusAndClose(t, requestRelayJSON(
		t, client, http.MethodPost, revocationPath, revocation,
		principalToken, uuid.Nil,
	), http.StatusCreated)
	requireStatusAndClose(t, requestRelayJSON(
		t, client, http.MethodGet, spaceBasePath+"/messages?limit=1", nil,
		secondSpaceCredential.Token, secondDeviceID,
	), http.StatusForbidden)
	requireStatusAndClose(t, requestRelayJSON(
		t, client, http.MethodGet,
		fmt.Sprintf("%s/v1/relay/tenants/%s/domains/%s/messages?limit=1",
			baseURL, principalID, controlDomain.AdministrationCredential.DomainID),
		nil, secondControlCredential.Token, secondDeviceID,
	), http.StatusForbidden)
}

type liveDeviceSyncAdmissionCredential struct {
	AdmissionID        uuid.UUID `json:"admissionID"`
	AuthorizationToken string    `json:"authorizationToken"`
}

type liveDeviceSyncAdmissionCreateInput struct {
	Version               int                               `json:"version"`
	RetryID               uuid.UUID                         `json:"retryID"`
	AdmissionCredential   liveDeviceSyncAdmissionCredential `json:"admissionCredential"`
	ExpiresAtMilliseconds int64                             `json:"expiresAtMilliseconds"`
}

type liveDeviceSyncPrincipalClaimInput struct {
	Version            int                                `json:"version"`
	RetryID            uuid.UUID                          `json:"retryID"`
	PrincipalID        uuid.UUID                          `json:"principalID"`
	InitialDeviceID    uuid.UUID                          `json:"initialDeviceID"`
	TenantProvisioning liveRelayTenantProvisioningRequest `json:"tenantProvisioning"`
}

type liveDeviceSyncDeviceAdmissionCreateInput struct {
	Version               int                               `json:"version"`
	RetryID               uuid.UUID                         `json:"retryID"`
	DeviceID              uuid.UUID                         `json:"deviceID"`
	SubscriptionID        uuid.UUID                         `json:"subscriptionID"`
	AdmissionCredential   liveDeviceSyncAdmissionCredential `json:"admissionCredential"`
	ExpiresAtMilliseconds int64                             `json:"expiresAtMilliseconds"`
}

type liveDeviceSyncDeviceAdmissionClaimInput struct {
	Version             int       `json:"version"`
	DeviceID            uuid.UUID `json:"deviceID"`
	AuthorizationDigest string    `json:"authorizationDigest"`
}

type liveDeviceSyncSpaceProvisioningInput struct {
	Version         int                                `json:"version"`
	RetryID         uuid.UUID                          `json:"retryID"`
	InitialDeviceID uuid.UUID                          `json:"initialDeviceID"`
	Domain          liveRelayDomainProvisioningRequest `json:"domain"`
}

func liveDeviceSyncAdmitDevice(
	t *testing.T,
	client *http.Client,
	baseURL string,
	principalID uuid.UUID,
	deviceID uuid.UUID,
	domain liveRelayDomainProvisioningRequest,
	spaceID uuid.UUID,
	expiresAtMilliseconds int64,
	admissionToken string,
	memberToken string,
) relay.Credential {
	t.Helper()
	admissionID := uuid.New()
	input := liveDeviceSyncDeviceAdmissionCreateInput{
		Version: devicesync.SchemaVersion, RetryID: uuid.New(),
		DeviceID: deviceID, SubscriptionID: uuid.New(),
		AdmissionCredential: liveDeviceSyncAdmissionCredential{
			AdmissionID: admissionID, AuthorizationToken: admissionToken,
		},
		ExpiresAtMilliseconds: expiresAtMilliseconds,
	}
	createPath := fmt.Sprintf(
		"%s/v1/device-sync/principals/%s/control-domains/%s/device-admissions",
		baseURL, principalID, domain.AdministrationCredential.DomainID,
	)
	claimPath := fmt.Sprintf(
		"%s/v1/device-sync/principals/%s/device-admissions/%s/claim",
		baseURL, principalID, admissionID,
	)
	if spaceID != uuid.Nil {
		createPath = fmt.Sprintf(
			"%s/v1/device-sync/principals/%s/spaces/%s/domains/%s/device-admissions",
			baseURL, principalID, spaceID, domain.AdministrationCredential.DomainID,
		)
		claimPath = fmt.Sprintf(
			"%s/v1/device-sync/principals/%s/spaces/%s/device-admissions/%s/claim",
			baseURL, principalID, spaceID, admissionID,
		)
	}
	requireStatusAndClose(t, requestRelayJSON(
		t, client, http.MethodPost, createPath, input,
		domain.AdministrationCredential.AuthorizationToken, uuid.Nil,
	), http.StatusCreated)

	credential := relay.Credential{
		TenantID: principalID, DomainID: domain.AdministrationCredential.DomainID,
		MemberID: deviceID, Token: memberToken,
	}
	digest, err := relay.AuthorizationDigest(credential)
	if err != nil {
		t.Fatal(err)
	}
	requireStatusAndClose(t, requestRelayJSON(
		t, client, http.MethodPost, claimPath,
		liveDeviceSyncDeviceAdmissionClaimInput{
			Version: devicesync.SchemaVersion, DeviceID: deviceID,
			AuthorizationDigest: digest,
		},
		admissionToken, uuid.Nil,
	), http.StatusCreated)
	return credential
}

func liveDeviceSyncTransportEnvelope(
	t *testing.T,
	kind protocol.PayloadKind,
	createdAtMilliseconds int64,
	payload []byte,
	dependencies []uuid.UUID,
) protocol.TransportEnvelope {
	t.Helper()
	envelope, err := protocol.NewTransportEnvelope(
		kind, uuid.New(), createdAtMilliseconds, "application/fef+json",
		payload, dependencies, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func liveDeviceSyncRelayEnvelope(
	t *testing.T,
	transportEnvelope protocol.TransportEnvelope,
	credential relay.Credential,
) relay.Envelope {
	t.Helper()
	encoded, err := transportEnvelope.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return relay.Envelope{
		Version: relay.SchemaVersion, Algorithm: relay.EnvelopeAlgorithm,
		TenantID: credential.TenantID, DomainID: credential.DomainID,
		MessageID: transportEnvelope.MessageID, PublisherMemberID: credential.MemberID,
		KeyEpoch: 1, CreatedAtMilliseconds: transportEnvelope.CreatedAtMilliseconds,
		Nonce:             base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xa1}, 12)),
		Ciphertext:        base64.RawURLEncoding.EncodeToString(encoded),
		AuthenticationTag: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xb2}, 16)),
	}
}

func liveDeviceSyncDecodeEnvelope(
	t *testing.T,
	envelope relay.Envelope,
) protocol.TransportEnvelope {
	t.Helper()
	encoded, err := base64.RawURLEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	var transportEnvelope protocol.TransportEnvelope
	if err := json.Unmarshal(encoded, &transportEnvelope); err != nil {
		t.Fatal(err)
	}
	if err := transportEnvelope.Validate(); err != nil {
		t.Fatal(err)
	}
	return transportEnvelope
}

func decodeLiveJSON(t *testing.T, response *http.Response, output any) {
	t.Helper()
	defer response.Body.Close()
	if err := json.NewDecoder(response.Body).Decode(output); err != nil {
		t.Fatal(err)
	}
}
