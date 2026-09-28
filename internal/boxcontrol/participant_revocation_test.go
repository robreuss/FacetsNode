package boxcontrol

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func claimedParticipantStore(t *testing.T, fixture participantFixture) (*MemoryStore, BoxParticipantEnrollment) {
	t.Helper()
	ctx := context.Background()
	store := NewMemoryStore()
	if err := store.Initialize(ctx, State{BoxID: fixture.anchor.BoxID, ActivationVerifier: "activation"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Claim(ctx, "activation", "owner", "Box", time.Now()); err != nil {
		t.Fatal(err)
	}
	enrollment := BoxParticipantEnrollment{
		Anchor: fixture.anchor, Device: fixture.device,
		RootRecord: fixture.root, GrantRecord: fixture.grant,
	}
	if err := store.PinOwnerApprovedParticipant(ctx, enrollment, fixture.now); err != nil {
		t.Fatal(err)
	}
	return store, enrollment
}

func participantChallenge(fixture participantFixture) BoxParticipantChallenge {
	return BoxParticipantChallenge{
		BoxID: fixture.anchor.BoxID, ParticipantID: fixture.anchor.ParticipantID,
		DeviceID: fixture.device.DeviceID, ChallengeID: fixture.challengeID,
		IssuedAtMilliseconds: fixture.now, ExpiresAtMilliseconds: fixture.now + 30_000,
	}
}

func TestMemoryParticipantRevocationStopsOutstandingAndNewChallenges(t *testing.T) {
	for _, revokeDevice := range []bool{false, true} {
		fixture := newParticipantFixture(t)
		store, enrollment := claimedParticipantStore(t, fixture)
		ctx := context.Background()
		challenge := participantChallenge(fixture)
		if err := store.IssueParticipantChallenge(ctx, challenge, fixture.now); err != nil {
			t.Fatal(err)
		}
		if err := store.RevokePinnedParticipant(ctx, uuid.New(), fixture.anchor.ParticipantID, fixture.now+500); !errors.Is(err, ErrParticipantAuthority) {
			t.Fatalf("wrong Box revoked participant: %v", err)
		}
		if err := store.RevokePinnedParticipantDevice(ctx, fixture.anchor.BoxID, fixture.anchor.ParticipantID, uuid.New(), fixture.now+500); !errors.Is(err, ErrParticipantAuthority) {
			t.Fatalf("wrong device was revoked: %v", err)
		}
		if revokeDevice {
			if err := store.RevokePinnedParticipantDevice(ctx, fixture.anchor.BoxID, fixture.anchor.ParticipantID, fixture.device.DeviceID, fixture.now+500); err != nil {
				t.Fatal(err)
			}
			if err := store.RevokePinnedParticipantDevice(ctx, fixture.anchor.BoxID, fixture.anchor.ParticipantID, fixture.device.DeviceID, fixture.now+600); err != nil {
				t.Fatalf("exact device revocation retry: %v", err)
			}
		} else {
			if err := store.RevokePinnedParticipant(ctx, fixture.anchor.BoxID, fixture.anchor.ParticipantID, fixture.now+500); err != nil {
				t.Fatal(err)
			}
			if err := store.RevokePinnedParticipant(ctx, fixture.anchor.BoxID, fixture.anchor.ParticipantID, fixture.now+600); err != nil {
				t.Fatalf("exact participant revocation retry: %v", err)
			}
		}
		pinned, err := store.PinnedParticipant(ctx, fixture.anchor.BoxID, fixture.anchor.ParticipantID, fixture.device.DeviceID)
		if err != nil {
			t.Fatal(err)
		}
		if revokeDevice && pinned.Device.RevokedThroughGeneration != 1 {
			t.Fatal("device generation was not revoked")
		}
		if !revokeDevice && pinned.Anchor.RevokedAtMilliseconds != fixture.now+500 {
			t.Fatal("participant root was not revoked at first request")
		}
		consumed, err := store.ConsumeParticipantChallenge(ctx, challenge.BoxID,
			challenge.ParticipantID, challenge.DeviceID, challenge.ChallengeID, fixture.now+1_000)
		if err != nil || consumed {
			t.Fatal("outstanding challenge survived revocation", err)
		}
		challenge.ChallengeID = uuid.New()
		if err := store.IssueParticipantChallenge(ctx, challenge, fixture.now+1_000); !errors.Is(err, ErrParticipantAuthority) {
			t.Fatalf("revoked participant received challenge: %v", err)
		}
		if err := store.PinOwnerApprovedParticipant(ctx, enrollment, fixture.now+1_000); !errors.Is(err, ErrParticipantAuthority) {
			t.Fatalf("old enrollment repinned after revocation: %v", err)
		}
	}
}

func TestParticipantRevocationHTTPRequiresOwnerSessionAndCSRF(t *testing.T) {
	fixture := newParticipantFixture(t)
	store, _ := claimedParticipantStore(t, fixture)
	now := time.UnixMilli(fixture.now)
	service := makeTestService(t, store, &testDeviceSyncController{}, now)
	handler := service.Handler()
	ctx := context.Background()
	sessionToken, sessionDigest, err := RandomToken(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrf, csrfDigest, err := RandomToken(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateWebSession(ctx, WebSession{
		TokenDigest: sessionDigest, CSRFDigest: csrfDigest,
		CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	grantToken, grantDigest, err := RandomToken(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateGrant(ctx, ConnectionGrant{
		GrantID: uuid.New(), TokenDigest: grantDigest, DeviceName: "connected Facets",
		CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	devicePath := "/v1/owner/participants/" + fixture.anchor.ParticipantID.String() +
		"/devices/" + fixture.device.DeviceID.String() + "/revoke"
	post := func(path, formCSRF string, withSession bool, bearerToken string) *httptest.ResponseRecorder {
		t.Helper()
		form := url.Values{"csrf": {formCSRF}}
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if withSession {
			request.AddCookie(&http.Cookie{Name: "facets_box_session", Value: sessionToken})
			request.AddCookie(&http.Cookie{Name: "facets_box_csrf", Value: csrf})
		}
		if bearerToken != "" {
			request.Header.Set("Authorization", "Bearer "+bearerToken)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	if result := post(devicePath, csrf, false, grantToken); result.Code != http.StatusBadRequest {
		t.Fatalf("app grant revoked device: %d", result.Code)
	}
	if result := post(devicePath, "wrong", true, ""); result.Code != http.StatusBadRequest {
		t.Fatalf("wrong CSRF revoked device: %d", result.Code)
	}
	if result := post(strings.Replace(devicePath, fixture.device.DeviceID.String(), uuid.NewString(), 1), csrf, true, ""); result.Code != http.StatusNotFound {
		t.Fatalf("wrong device revoked grant: %d", result.Code)
	}
	challenge := participantChallenge(fixture)
	if err := store.IssueParticipantChallenge(ctx, challenge, fixture.now); err != nil {
		t.Fatal(err)
	}
	if result := post(devicePath, csrf, true, ""); result.Code != http.StatusNoContent {
		t.Fatalf("owner device revocation status %d: %s", result.Code, result.Body.String())
	}
	consumed, err := store.ConsumeParticipantChallenge(ctx, challenge.BoxID,
		challenge.ParticipantID, challenge.DeviceID, challenge.ChallengeID, fixture.now+1)
	if err != nil || consumed {
		t.Fatal("owner revocation left challenge usable", err)
	}
	rootPath := "/v1/owner/participants/" + fixture.anchor.ParticipantID.String() + "/revoke"
	if result := post(rootPath, csrf, true, ""); result.Code != http.StatusNoContent {
		t.Fatalf("owner root revocation status %d: %s", result.Code, result.Body.String())
	}
	pinned, err := store.PinnedParticipant(ctx, fixture.anchor.BoxID, fixture.anchor.ParticipantID, fixture.device.DeviceID)
	if err != nil || pinned.Anchor.RevokedAtMilliseconds != fixture.now {
		t.Fatal("owner root revocation was not persisted", err)
	}
}
