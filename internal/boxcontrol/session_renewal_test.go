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

func TestForegroundAdministrationRenewsWithoutAbsoluteInterruption(t *testing.T) {
	withFastArgon(t)
	now := time.Unix(1800000000, 0).UTC()
	store := initializedMemoryStore(t, "setup-only")
	service := makeTestService(t, store, &testDeviceSyncController{}, now)
	service.now = func() time.Time { return now }
	issued := httptest.NewRecorder()
	token, csrf, err := service.issueWebSession(issued, httptest.NewRequest("GET", "/", nil))
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := TokenDigest(token)
	original, _ := store.WebSession(context.Background(), digest, now)
	// Forty hours of active work, without changing either the session identity or
	// the CSRF token used by an unfinished form. No wall-clock sleep in this test.
	for range 240 {
		now = now.Add(10 * time.Minute)
		request := httptest.NewRequest("GET", "/", nil)
		request.AddCookie(&http.Cookie{Name: "facets_box_session", Value: token})
		request.AddCookie(&http.Cookie{Name: "facets_box_csrf", Value: csrf})
		response := httptest.NewRecorder()
		service.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("foreground renewal: %d", response.Code)
		}
		for _, name := range []string{"facets_box_session", "facets_box_csrf"} {
			cookie := cookieNamed(t, response.Result().Cookies(), name)
			if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.MaxAge != int(WebSessionRenewalLifetime.Seconds()) {
				t.Fatal("cookie protections changed")
			}
			if (name == "facets_box_session" && cookie.Value != token) || (name == "facets_box_csrf" && cookie.Value != csrf) {
				t.Fatal("renewal invalidated an unfinished form")
			}
		}
	}
	current, err := store.WebSession(context.Background(), digest, now)
	if err != nil || !current.CreatedAt.Equal(original.CreatedAt) || !current.ExpiresAt.Equal(now.Add(WebSessionRenewalLifetime)) {
		t.Fatal("active session did not renew")
	}
	if grants, _ := store.ListGrants(context.Background()); len(grants) != 0 {
		t.Fatal("read-only renewal created a grant")
	}
	if len(store.invitations) != 0 {
		t.Fatal("read-only renewal created an invitation")
	}
}

func TestExpiredRevokedAndSignedOutAdminCannotRenewButClientGrantSurvives(t *testing.T) {
	for _, scenario := range []string{"idle", "expired", "revoked", "logout", "wrong-csrf"} {
		t.Run(scenario, func(t *testing.T) {
			withFastArgon(t)
			now := time.Unix(1800000000, 0).UTC()
			store := initializedMemoryStore(t, "setup-only")
			service := makeTestService(t, store, &testDeviceSyncController{}, now)
			service.now = func() time.Time { return now }
			token, csrf, err := service.issueWebSession(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
			if err != nil {
				t.Fatal(err)
			}
			digest, _ := TokenDigest(token)
			grantToken, grantDigest, _ := RandomToken(rand.Reader)
			if err := store.CreateGrant(context.Background(), ConnectionGrant{GrantID: uuid.New(), TokenDigest: grantDigest, ExpiresAt: now.Add(ConnectionGrantLifetime)}); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "idle":
				now = now.Add(WebSessionIdleLifetime + time.Second)
			case "expired":
				session := store.sessions[digest]
				session.ExpiresAt = now
				store.sessions[digest] = session
			case "revoked":
				_ = store.RevokeAllWebSessions(context.Background())
			case "logout":
				request := httptest.NewRequest("POST", "/logout", strings.NewReader(url.Values{"csrf": {csrf}}.Encode()))
				request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				request.AddCookie(&http.Cookie{Name: "facets_box_session", Value: token})
				request.AddCookie(&http.Cookie{Name: "facets_box_csrf", Value: csrf})
				response := httptest.NewRecorder()
				service.Handler().ServeHTTP(response, request)
				if response.Code != http.StatusSeeOther {
					t.Fatalf("logout: %d", response.Code)
				}
			}
			if scenario != "wrong-csrf" && !errors.Is(store.TouchWebSession(context.Background(), digest, now), ErrInvalidCredential) {
				t.Fatal("renewal revived an expired/deleted login")
			}
			request := httptest.NewRequest("GET", "/", nil)
			request.AddCookie(&http.Cookie{Name: "facets_box_session", Value: token})
			if scenario == "wrong-csrf" {
				csrf, _, _ = RandomToken(rand.Reader)
			}
			request.AddCookie(&http.Cookie{Name: "facets_box_csrf", Value: csrf})
			response := httptest.NewRecorder()
			service.Handler().ServeHTTP(response, request)
			for _, cookie := range response.Result().Cookies() {
				if cookie.Name == "facets_box_session" && cookie.MaxAge > 0 {
					t.Fatal("unauthenticated request renewed a login")
				}
			}
			profile := httptest.NewRequest("GET", "/v1/profile", nil)
			profile.Header.Set("Authorization", "Bearer "+grantToken)
			profileResponse := httptest.NewRecorder()
			service.Handler().ServeHTTP(profileResponse, profile)
			if profileResponse.Code != http.StatusOK {
				t.Fatalf("admin expiry/signout affected client access: %d", profileResponse.Code)
			}
		})
	}
}
