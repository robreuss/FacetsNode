package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/devicesync"
	"github.com/robreuss/FacetsNode/internal/protocol"
	"github.com/robreuss/FacetsNode/internal/relay"
)

func TestDeviceSyncSpaceDataPlaneCarriesOpaqueCheckpointTailAndBlob(t *testing.T) {
	const now = int64(8_000)
	const tenantSeed = byte(61)

	relayStore := relay.NewMemoryStore()
	deviceSyncStore := devicesync.NewMemoryStore(relayStore)
	controlDomain := newRelayDomainProvisioningRequest(now, 62, 63)
	principalID := controlDomain.AdministrationCredential.TenantID
	initialDeviceID := controlDomain.MemberCredential.MemberID
	bootstrapDeviceSyncPrincipal(t, deviceSyncStore, controlDomain, tenantSeed)

	secondDeviceID := uuid.New()
	enrollDeviceSyncTestDevice(
		t, deviceSyncStore, controlDomain, secondDeviceID, now, 64, 65,
	)

	spaceID := uuid.New()
	spaceDomainInput := newRelayDomainProvisioningRequest(now, 66, 67)
	spaceDomainInput.AdministrationCredential.TenantID = principalID
	spaceDomainInput.MemberCredential.TenantID = principalID
	spaceDomainInput.MemberCredential.MemberID = initialDeviceID
	_, spaceDomain, err := relayTenantAndDomainProvisioning(
		newRelayTenantProvisioningRequest(spaceDomainInput, relayTestToken(68)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deviceSyncStore.ProvisionSpace(
		context.Background(),
		relay.TenantCredential{TenantID: principalID, Token: relayTestToken(tenantSeed)},
		devicesync.SpaceProvisioning{
			Version: devicesync.SchemaVersion, RetryID: uuid.New(),
			PrincipalID: principalID, SpaceID: spaceID,
			InitialDeviceID: initialDeviceID, Domain: spaceDomain,
			CreatedAtMilliseconds: now,
		},
		now,
	); err != nil {
		t.Fatal(err)
	}

	server := newRelayTestServer(t, relayStore, relayTestToken(69))
	server.SetDeviceSyncStore(deviceSyncStore)
	server.now = func() time.Time { return time.UnixMilli(now) }
	handler := server.Handler()

	secondSpaceToken := relayTestToken(70)
	secondSpaceCredential := admitDeviceToTestSpace(
		t, handler, principalID, spaceID, secondDeviceID,
		spaceDomainInput, secondSpaceToken, now,
	)
	basePath := "/v1/relay/tenants/" + principalID.String() +
		"/domains/" + spaceDomainInput.AdministrationCredential.DomainID.String()

	blobBytes := []byte("opaque encrypted media bytes for one contained Space")
	blobID := relay.BlobID(blobBytes)
	blobDigest := sha256.Sum256(blobBytes)
	blobReference := protocol.BlobReference{
		BlobID: blobID, SHA256: hex.EncodeToString(blobDigest[:]),
		ByteCount: int64(len(blobBytes)), ContentType: "application/octet-stream",
	}
	checkpoint := newDeviceSyncTransportEnvelope(
		t, protocol.PayloadFEFCheckpoint, now,
		[]byte(`{"fef":"opaque-checkpoint"}`), nil, []protocol.BlobReference{blobReference},
	)
	mutation := newDeviceSyncTransportEnvelope(
		t, protocol.PayloadFEFMutationBatch, now+1,
		[]byte(`{"fef":"opaque-mutation"}`), []uuid.UUID{checkpoint.MessageID}, nil,
	)

	publisher := relay.Credential{
		TenantID: principalID,
		DomainID: spaceDomainInput.AdministrationCredential.DomainID,
		MemberID: initialDeviceID,
		Token:    spaceDomainInput.MemberCredential.AuthorizationToken,
	}
	for _, transportEnvelope := range []protocol.TransportEnvelope{checkpoint, mutation} {
		relayEnvelope := wrapTransportEnvelopeForRelay(
			t, transportEnvelope, principalID, publisher.DomainID, publisher.MemberID,
		)
		response := performRelayJSON(
			t, handler, http.MethodPut,
			basePath+"/messages/"+transportEnvelope.MessageID.String(),
			relayEnvelope, publisher.Token, publisher.MemberID,
		)
		requireStatus(t, response, http.StatusCreated)
		_ = response.Body.Close()
	}

	controlCredentialCannotReadSpace := performRelayJSON(
		t, handler, http.MethodGet, basePath+"/messages?limit=10", nil,
		controlDomain.MemberCredential.AuthorizationToken, initialDeviceID,
	)
	requireStatus(t, controlCredentialCannotReadSpace, http.StatusUnauthorized)
	_ = controlCredentialCannotReadSpace.Body.Close()

	fetch := performRelayJSON(
		t, handler, http.MethodGet, basePath+"/messages?limit=10", nil,
		secondSpaceCredential.Token, secondSpaceCredential.MemberID,
	)
	requireStatus(t, fetch, http.StatusOK)
	var fetched struct {
		Messages []relay.Message `json:"messages"`
		Cursor   string          `json:"cursor"`
	}
	if err := json.NewDecoder(fetch.Body).Decode(&fetched); err != nil {
		t.Fatal(err)
	}
	_ = fetch.Body.Close()
	if len(fetched.Messages) != 2 || fetched.Cursor != relay.EncodeCursor(2) {
		t.Fatalf("unexpected Device Sync Space fetch: %+v", fetched)
	}
	for index, expected := range []protocol.TransportEnvelope{checkpoint, mutation} {
		actual := unwrapTransportEnvelopeFromRelay(t, fetched.Messages[index].Envelope)
		if actual.MessageID != expected.MessageID || actual.Kind != expected.Kind ||
			actual.PayloadSHA256 != expected.PayloadSHA256 {
			t.Fatalf("transport envelope %d mismatch: got=%+v expected=%+v", index, actual, expected)
		}
		for _, stage := range []string{"accepted", "applied"} {
			response := performRelayJSON(
				t, handler, http.MethodPost,
				basePath+"/messages/"+expected.MessageID.String()+"/acknowledgments",
				map[string]string{"stage": stage},
				secondSpaceCredential.Token, secondSpaceCredential.MemberID,
			)
			requireStatus(t, response, http.StatusOK)
			_ = response.Body.Close()
		}
	}

	uploadID := uuid.New()
	uploadPath := basePath + "/blob-uploads/" + uploadID.String()
	upload := performRelayJSON(
		t, handler, http.MethodPost, basePath+"/blob-uploads",
		relay.BlobUploadRequest{
			RetryID: uuid.New(), UploadID: uploadID, RelayBlobID: blobID,
			ByteCount: int64(len(blobBytes)), CreatedAtMilliseconds: now,
		},
		publisher.Token, publisher.MemberID,
	)
	requireStatus(t, upload, http.StatusCreated)
	_ = upload.Body.Close()

	chunk := httptest.NewRequest(http.MethodPatch, uploadPath, bytes.NewReader(blobBytes))
	chunk.Header.Set("Authorization", "Bearer "+publisher.Token)
	chunk.Header.Set("X-Facets-Member-ID", publisher.MemberID.String())
	chunk.Header.Set("Content-Type", "application/octet-stream")
	chunk.Header.Set("Upload-Offset", "0")
	chunk.Header.Set("X-Chunk-SHA256", blobReference.SHA256)
	chunkRecorder := httptest.NewRecorder()
	handler.ServeHTTP(chunkRecorder, chunk)
	if chunkRecorder.Code != http.StatusOK {
		t.Fatalf("blob chunk status=%d body=%s", chunkRecorder.Code, chunkRecorder.Body.String())
	}

	finalization := performRelayJSON(
		t, handler, http.MethodPost, uploadPath+"/finalization",
		relay.BlobUploadFinalizationRequest{
			RetryID: uuid.New(), UploadID: uploadID, RelayBlobID: blobID,
			ByteCount: int64(len(blobBytes)), FinalizedAtMilliseconds: now,
		},
		publisher.Token, publisher.MemberID,
	)
	requireStatus(t, finalization, http.StatusCreated)
	_ = finalization.Body.Close()

	download := performRelayBlob(
		t, handler, http.MethodGet, basePath+"/blobs/"+blobID, nil,
		secondSpaceCredential.Token, secondSpaceCredential.MemberID, "",
	)
	requireStatus(t, download, http.StatusOK)
	downloaded, err := io.ReadAll(download.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = download.Body.Close()
	if !bytes.Equal(downloaded, blobBytes) {
		t.Fatalf("Device Sync blob mismatch: got=%q expected=%q", downloaded, blobBytes)
	}

	revocation := devicesync.DeviceRevocation{
		Version: devicesync.SchemaVersion, RetryID: uuid.New(),
		PrincipalID: principalID, DeviceID: secondDeviceID,
	}
	revocationPath := "/v1/device-sync/principals/" + principalID.String() +
		"/devices/" + secondDeviceID.String() + "/revocation"
	revoked := performRelayJSON(
		t, handler, http.MethodPost, revocationPath, revocation,
		relayTestToken(tenantSeed), uuid.Nil,
	)
	requireStatus(t, revoked, http.StatusCreated)
	var revokedResult devicesync.DeviceRevocationResult
	if err := json.NewDecoder(revoked.Body).Decode(&revokedResult); err != nil {
		t.Fatal(err)
	}
	_ = revoked.Body.Close()
	if revokedResult.Acceptance != relay.AcceptanceAccepted ||
		revokedResult.DeviceID != secondDeviceID || len(revokedResult.Memberships) != 2 {
		t.Fatalf("unexpected Device Sync revocation: %+v", revokedResult)
	}
	revocationRetry := performRelayJSON(
		t, handler, http.MethodPost, revocationPath, revocation,
		relayTestToken(tenantSeed), uuid.Nil,
	)
	requireStatus(t, revocationRetry, http.StatusOK)
	var retryResult devicesync.DeviceRevocationResult
	if err := json.NewDecoder(revocationRetry.Body).Decode(&retryResult); err != nil {
		t.Fatal(err)
	}
	_ = revocationRetry.Body.Close()
	if retryResult.Acceptance != relay.AcceptanceDuplicate ||
		!reflect.DeepEqual(retryResult.Memberships, revokedResult.Memberships) {
		t.Fatalf("revocation retry changed result: %+v", retryResult)
	}

	secondControlCredential := relay.Credential{
		TenantID: principalID,
		DomainID: controlDomain.AdministrationCredential.DomainID,
		MemberID: secondDeviceID,
		Token:    relayTestToken(65),
	}
	controlPath := "/v1/relay/tenants/" + principalID.String() +
		"/domains/" + controlDomain.AdministrationCredential.DomainID.String()
	for _, denied := range []*http.Response{
		performRelayJSON(
			t, handler, http.MethodGet, controlPath+"/messages?limit=1", nil,
			secondControlCredential.Token, secondControlCredential.MemberID,
		),
		performRelayJSON(
			t, handler, http.MethodGet, basePath+"/messages?limit=1", nil,
			secondSpaceCredential.Token, secondSpaceCredential.MemberID,
		),
		performRelayBlob(
			t, handler, http.MethodGet, basePath+"/blobs/"+blobID, nil,
			secondSpaceCredential.Token, secondSpaceCredential.MemberID, "",
		),
	} {
		requireStatus(t, denied, http.StatusForbidden)
		_ = denied.Body.Close()
	}
	initialStillActive := performRelayJSON(
		t, handler, http.MethodGet, basePath+"/messages?limit=1", nil,
		publisher.Token, publisher.MemberID,
	)
	requireStatus(t, initialStillActive, http.StatusOK)
	_ = initialStillActive.Body.Close()

	statusResponse := performRelayJSON(
		t, handler, http.MethodGet,
		"/v1/device-sync/principals/"+principalID.String()+"/status", nil,
		relayTestToken(tenantSeed), uuid.Nil,
	)
	requireStatus(t, statusResponse, http.StatusOK)
	var status devicesync.PrincipalStatus
	if err := json.NewDecoder(statusResponse.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	_ = statusResponse.Body.Close()
	if !principalDeviceIsRevoked(status, secondDeviceID) ||
		!spaceDeviceIsRevoked(status, spaceID, secondDeviceID) {
		t.Fatalf("revocation is missing from content-blind status: %+v", status)
	}

	revokedAgain := revocation
	revokedAgain.RetryID = uuid.New()
	collision := performRelayJSON(
		t, handler, http.MethodPost, revocationPath, revokedAgain,
		relayTestToken(tenantSeed), uuid.Nil,
	)
	requireStatus(t, collision, http.StatusConflict)
	_ = collision.Body.Close()
	lastDevice := devicesync.DeviceRevocation{
		Version: devicesync.SchemaVersion, RetryID: uuid.New(),
		PrincipalID: principalID, DeviceID: initialDeviceID,
	}
	lastDeviceResponse := performRelayJSON(
		t, handler, http.MethodPost,
		"/v1/device-sync/principals/"+principalID.String()+"/devices/"+
			initialDeviceID.String()+"/revocation",
		lastDevice, relayTestToken(tenantSeed), uuid.Nil,
	)
	requireStatus(t, lastDeviceResponse, http.StatusConflict)
	_ = lastDeviceResponse.Body.Close()
}

func principalDeviceIsRevoked(status devicesync.PrincipalStatus, deviceID uuid.UUID) bool {
	for _, device := range status.Devices {
		if device.DeviceID == deviceID {
			return device.RevokedAtMilliseconds != nil
		}
	}
	return false
}

func spaceDeviceIsRevoked(status devicesync.PrincipalStatus, spaceID, deviceID uuid.UUID) bool {
	for _, space := range status.Spaces {
		if space.SpaceID != spaceID {
			continue
		}
		for _, device := range space.Devices {
			if device.DeviceID == deviceID {
				return device.RevokedAtMilliseconds != nil
			}
		}
	}
	return false
}

func admitDeviceToTestSpace(
	t *testing.T,
	handler http.Handler,
	principalID uuid.UUID,
	spaceID uuid.UUID,
	deviceID uuid.UUID,
	spaceDomain relayDomainProvisioningRequest,
	memberToken string,
	now int64,
) relay.Credential {
	t.Helper()
	admissionCredential := deviceSyncAdmissionCredential{
		AdmissionID: uuid.New(), AuthorizationToken: relayTestToken(71),
	}
	createInput := deviceSyncDeviceAdmissionCreateInput{
		Version: devicesync.SchemaVersion, RetryID: uuid.New(), DeviceID: deviceID,
		SubscriptionID:        uuid.New(),
		AdmissionCredential:   admissionCredential,
		ExpiresAtMilliseconds: now + devicesync.MinimumAdmissionLifetimeMilliseconds,
	}
	createPath := "/v1/device-sync/principals/" + principalID.String() +
		"/spaces/" + spaceID.String() + "/domains/" +
		spaceDomain.AdministrationCredential.DomainID.String() + "/device-admissions"
	created := performRelayJSON(
		t, handler, http.MethodPost, createPath, createInput,
		spaceDomain.AdministrationCredential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, created, http.StatusCreated)
	_ = created.Body.Close()

	credential := relay.Credential{
		TenantID: principalID, DomainID: spaceDomain.AdministrationCredential.DomainID,
		MemberID: deviceID, Token: memberToken,
	}
	digest, err := relay.AuthorizationDigest(credential)
	if err != nil {
		t.Fatal(err)
	}
	claim := performRelayJSON(
		t, handler, http.MethodPost,
		"/v1/device-sync/principals/"+principalID.String()+
			"/spaces/"+spaceID.String()+"/device-admissions/"+
			admissionCredential.AdmissionID.String()+"/claim",
		deviceSyncDeviceAdmissionClaimInput{
			Version: devicesync.SchemaVersion, DeviceID: deviceID,
			AuthorizationDigest: digest,
		},
		admissionCredential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, claim, http.StatusCreated)
	_ = claim.Body.Close()
	return credential
}

func newDeviceSyncTransportEnvelope(
	t *testing.T,
	kind protocol.PayloadKind,
	createdAtMilliseconds int64,
	payload []byte,
	dependencies []uuid.UUID,
	blobReferences []protocol.BlobReference,
) protocol.TransportEnvelope {
	t.Helper()
	envelope, err := protocol.NewTransportEnvelope(
		kind, uuid.New(), createdAtMilliseconds, "application/fef+json",
		payload, dependencies, blobReferences,
	)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func wrapTransportEnvelopeForRelay(
	t *testing.T,
	transportEnvelope protocol.TransportEnvelope,
	tenantID uuid.UUID,
	domainID uuid.UUID,
	publisherMemberID uuid.UUID,
) relay.Envelope {
	t.Helper()
	encoded, err := transportEnvelope.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return relay.Envelope{
		Version: relay.SchemaVersion, Algorithm: relay.EnvelopeAlgorithm,
		TenantID: tenantID, DomainID: domainID,
		MessageID: transportEnvelope.MessageID, PublisherMemberID: publisherMemberID,
		KeyEpoch: 1, CreatedAtMilliseconds: transportEnvelope.CreatedAtMilliseconds,
		Nonce:             base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xa1}, 12)),
		Ciphertext:        base64.RawURLEncoding.EncodeToString(encoded),
		AuthenticationTag: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xb2}, 16)),
	}
}

func unwrapTransportEnvelopeFromRelay(
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
