package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/devicesync"
	"github.com/robreuss/FacetsNode/internal/relay"
)

func TestDeviceSyncJoinRequestDeliversOnlyCandidateEncryptedBootstrap(t *testing.T) {
	const now = int64(1_000)
	relayStore := relay.NewMemoryStore()
	deviceStore := devicesync.NewMemoryStore(relayStore)
	controlDomain := newRelayDomainProvisioningRequest(now, 111, 112)
	bootstrapDeviceSyncPrincipal(t, deviceStore, controlDomain, 113)
	server := newRelayTestServer(t, relayStore, relayTestToken(114))
	setUnboundDeviceSyncStoreForTesting(server, deviceStore)
	server.now = func() time.Time { return time.UnixMilli(now) }
	handler := server.Handler()

	requestID := uuid.New()
	pollingToken := relayTestToken(115)
	pin := "482501"
	createInput := deviceSyncJoinRequestCreateInput{
		Version:                     devicesync.SchemaVersion,
		RetryID:                     uuid.New(),
		RequestID:                   requestID,
		CandidateDeviceID:           uuid.New(),
		CandidateBootstrapPublicKey: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, 65)),
		PollingAuthorizationToken:   pollingToken,
		PIN:                         pin,
		ExpiresAtMilliseconds:       now + devicesync.MinimumJoinRequestLifetimeMilliseconds,
	}
	created := performRelayJSON(t, handler, http.MethodPost, "/v1/device-sync/join-requests", createInput, "", uuid.Nil)
	requireStatus(t, created, http.StatusCreated)
	var createResult devicesync.JoinRequestCreateResult
	if err := json.NewDecoder(created.Body).Decode(&createResult); err != nil {
		t.Fatal(err)
	}
	_ = created.Body.Close()
	if createResult.Acceptance != relay.AcceptanceAccepted || createResult.RequestID != requestID {
		t.Fatalf("unexpected create result: %+v", createResult)
	}

	// Neither the raw polling credential nor the displayed PIN can leak from
	// either the public create result or the administrator lookup presentation.
	retry := performRelayJSON(t, handler, http.MethodPost, "/v1/device-sync/join-requests", createInput, "", uuid.Nil)
	requireStatus(t, retry, http.StatusOK)
	retryBody, _ := io.ReadAll(retry.Body)
	_ = retry.Body.Close()
	if bytes.Contains(retryBody, []byte(pollingToken)) || bytes.Contains(retryBody, []byte(pin)) {
		t.Fatalf("join request retry leaked a credential: %s", retryBody)
	}

	principalID := controlDomain.AdministrationCredential.TenantID
	domainID := controlDomain.AdministrationCredential.DomainID
	lookupPath := "/v1/device-sync/principals/" + principalID.String() +
		"/control-domains/" + domainID.String() + "/join-requests/" + pin
	lookup := performRelayJSON(
		t, handler, http.MethodGet, lookupPath, nil,
		controlDomain.AdministrationCredential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, lookup, http.StatusOK)
	var presentation devicesync.JoinRequestSponsorPresentation
	if err := json.NewDecoder(lookup.Body).Decode(&presentation); err != nil {
		t.Fatal(err)
	}
	_ = lookup.Body.Close()
	if presentation.RequestID != requestID || presentation.CandidateDeviceID != createInput.CandidateDeviceID ||
		presentation.CandidateBootstrapPublicKey != createInput.CandidateBootstrapPublicKey {
		t.Fatalf("unexpected sponsor presentation: %+v", presentation)
	}

	fetchPath := "/v1/device-sync/join-requests/" + requestID.String() + "/bootstrap"
	beforeBootstrap := performRelayJSON(t, handler, http.MethodGet, fetchPath, nil, pollingToken, uuid.Nil)
	requireStatus(t, beforeBootstrap, http.StatusNotFound)
	_ = beforeBootstrap.Body.Close()

	envelope := devicesync.JoinBootstrapEnvelope{
		Version:               devicesync.SchemaVersion,
		RequestID:             requestID,
		Algorithm:             "P256+ChaCha20Poly1305",
		EphemeralPublicKey:    base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, 65)),
		Nonce:                 base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 12)),
		Ciphertext:            base64.RawURLEncoding.EncodeToString([]byte("opaque encrypted protected pairing handoff")),
		AuthenticationTag:     base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x43}, 16)),
		CreatedAtMilliseconds: now,
		ExpiresAtMilliseconds: now + devicesync.MinimumJoinRequestLifetimeMilliseconds,
	}
	storePath := "/v1/device-sync/principals/" + principalID.String() +
		"/control-domains/" + domainID.String() + "/join-requests/" + requestID.String() + "/bootstrap"
	stored := performRelayJSON(
		t, handler, http.MethodPut, storePath, deviceSyncJoinBootstrapInput{JoinBootstrapEnvelope: envelope},
		controlDomain.AdministrationCredential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, stored, http.StatusCreated)
	_ = stored.Body.Close()

	wrongCredential := performRelayJSON(t, handler, http.MethodGet, fetchPath, nil, relayTestToken(116), uuid.Nil)
	requireStatus(t, wrongCredential, http.StatusUnauthorized)
	_ = wrongCredential.Body.Close()
	fetched := performRelayJSON(t, handler, http.MethodGet, fetchPath, nil, pollingToken, uuid.Nil)
	requireStatus(t, fetched, http.StatusOK)
	var received devicesync.JoinBootstrapEnvelope
	if err := json.NewDecoder(fetched.Body).Decode(&received); err != nil {
		t.Fatal(err)
	}
	_ = fetched.Body.Close()
	if received != envelope {
		t.Fatalf("candidate received changed bootstrap: got=%+v want=%+v", received, envelope)
	}

	// The same encrypted handoff is safely retryable; a replacement handoff is
	// rejected so an existing administrator cannot silently redirect a candidate.
	storeRetry := performRelayJSON(
		t, handler, http.MethodPut, storePath, deviceSyncJoinBootstrapInput{JoinBootstrapEnvelope: envelope},
		controlDomain.AdministrationCredential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, storeRetry, http.StatusOK)
	_ = storeRetry.Body.Close()
	replacement := envelope
	replacement.Ciphertext = base64.RawURLEncoding.EncodeToString([]byte("different encrypted protected pairing handoff"))
	conflict := performRelayJSON(
		t, handler, http.MethodPut, storePath, deviceSyncJoinBootstrapInput{JoinBootstrapEnvelope: replacement},
		controlDomain.AdministrationCredential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, conflict, http.StatusConflict)
	_ = conflict.Body.Close()
}

func TestDeviceSyncJoinRequestMemoryStoreRejectsActivePINCollision(t *testing.T) {
	const now = int64(9_000)
	store := devicesync.NewMemoryStore(relay.NewMemoryStore())
	newRequest := func(requestID, retryID uuid.UUID) devicesync.JoinRequest {
		pollingDigest, err := devicesync.JoinRequestPollingAuthorizationDigest(devicesync.JoinRequestCredential{
			RequestID: requestID, Token: relayTestToken(119),
		})
		if err != nil {
			t.Fatal(err)
		}
		pinDigest, err := devicesync.JoinRequestPINAuthorizationDigest("123456")
		if err != nil {
			t.Fatal(err)
		}
		return devicesync.JoinRequest{
			Version: devicesync.SchemaVersion, RetryID: retryID, RequestID: requestID,
			CandidateDeviceID:           uuid.New(),
			CandidateBootstrapPublicKey: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x52}, 65)),
			PollingAuthorizationDigest:  pollingDigest, PINAuthorizationDigest: pinDigest,
			CreatedAtMilliseconds: now, ExpiresAtMilliseconds: now + devicesync.MinimumJoinRequestLifetimeMilliseconds,
		}
	}
	if _, err := store.CreateJoinRequest(context.Background(), newRequest(uuid.New(), uuid.New()), now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateJoinRequest(context.Background(), newRequest(uuid.New(), uuid.New()), now); !devicesync.ErrorHasCode(err, devicesync.CodeJoinRequestCollision) {
		t.Fatalf("active PIN collision error=%v", err)
	}
}
