package boxcontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestClaimRetryRetainsExactInstallation(t *testing.T) {
	withFastArgon(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	store := initializedMemoryStore(t, "RETRY-BOX-CODE")
	service := makeTestService(t, store, &testDeviceSyncController{}, now)
	handler := service.Handler()
	_, _, body := testConnectionRequest(t, now, "Claiming Mac")
	var input createConnectionRequestBody
	if err := json.Unmarshal(body, &input); err != nil {
		t.Fatal(err)
	}
	created := httptest.NewRecorder()
	handler.ServeHTTP(created, httptest.NewRequest(http.MethodPost, "/v1/claim-connection-requests", bytes.NewReader(body)))
	if created.Code != http.StatusCreated {
		t.Fatalf("create: %d", created.Code)
	}
	home := httptest.NewRecorder()
	handler.ServeHTTP(home, httptest.NewRequest(http.MethodGet, "/?claim_request_id="+input.RequestID.String(), nil))
	csrf := cookieNamed(t, home.Result().Cookies(), "facets_box_csrf")
	form := claimRetryForm(csrf.Value, input.RequestID.String())
	form.Set("activation_code", "WRONG-RETRY-CODE")
	rejected := postClaimRetry(handler, csrf, form)
	location, err := url.Parse(rejected.Header().Get("Location"))
	if err != nil || location.Query().Get("claim_request_id") != input.RequestID.String() {
		t.Fatalf("lost exact request: %v", location)
	}
	for _, secret := range []string{"WRONG-RETRY-CODE", form.Get("password"), csrf.Value} {
		if strings.Contains(location.String(), secret) {
			t.Fatal("claim redirect exposed form secrets")
		}
	}
	retryPage := httptest.NewRecorder()
	// The production ingress removes the public base path before routing.
	get := httptest.NewRequest(http.MethodGet, strings.TrimPrefix(location.String(), service.cookiePath), nil)
	get.AddCookie(csrf)
	handler.ServeHTTP(retryPage, get)
	if !strings.Contains(retryPage.Body.String(), `name="claim_request_id" value="`+input.RequestID.String()+`"`) || !strings.Contains(retryPage.Body.String(), "Claiming Mac") {
		t.Fatal("retry form lost the claiming installation")
	}
	form.Set("activation_code", "RETRY-BOX-CODE")
	accepted := postClaimRetry(handler, csrf, form)
	grants, err := store.ListGrants(context.Background())
	if accepted.Code != http.StatusSeeOther || err != nil || len(grants) != 1 || grants[0].DeviceName != "Claiming Mac" {
		t.Fatalf("retry failed to connect exact device: status=%d grants=%d err=%v", accepted.Code, len(grants), err)
	}
}

func TestUnavailableClaimContextNeverOffersStandaloneClaim(t *testing.T) {
	withFastArgon(t)
	for _, kind := range []string{"expired", "unknown", "malformed", "empty", "zero"} {
		t.Run(kind, func(t *testing.T) {
			now := time.Unix(1_800_000_000, 0).UTC()
			store := initializedMemoryStore(t, "RETRY-BOX-CODE")
			service := makeTestService(t, store, &testDeviceSyncController{}, now)
			handler := service.Handler()
			requestID := uuid.NewString()
			switch kind {
			case "expired":
				_, _, body := testConnectionRequest(t, now, "Expired Mac")
				var input createConnectionRequestBody
				if err := json.Unmarshal(body, &input); err != nil {
					t.Fatal(err)
				}
				requestID = input.RequestID.String()
				created := httptest.NewRecorder()
				handler.ServeHTTP(created, httptest.NewRequest(http.MethodPost, "/v1/claim-connection-requests", bytes.NewReader(body)))
				if created.Code != http.StatusCreated {
					t.Fatalf("create: %d", created.Code)
				}
				service.now = func() time.Time { return now.Add(11 * time.Minute) }
			case "malformed":
				requestID = "not-a-request"
			case "empty":
				requestID = ""
			case "zero":
				requestID = uuid.Nil.String()
			}
			home := httptest.NewRecorder()
			handler.ServeHTTP(home, httptest.NewRequest(http.MethodGet, "/?claim_request_id="+url.QueryEscape(requestID), nil))
			assertUnavailableClaimPage(t, home.Body.String())
			csrf := cookieNamed(t, home.Result().Cookies(), "facets_box_csrf")
			form := claimRetryForm(csrf.Value, requestID)
			for attempt := 0; attempt < 2; attempt++ {
				rejected := postClaimRetry(handler, csrf, form)
				location, err := url.Parse(rejected.Header().Get("Location"))
				if rejected.Code != http.StatusSeeOther || err != nil || !location.Query().Has("claim_request_id") {
					t.Fatal("failed claim dropped connection context")
				}
				page := httptest.NewRecorder()
				get := httptest.NewRequest(http.MethodGet, strings.TrimPrefix(location.String(), service.cookiePath), nil)
				get.AddCookie(csrf)
				handler.ServeHTTP(page, get)
				assertUnavailableClaimPage(t, page.Body.String())
			}
			state, err := store.State(context.Background())
			grants, grantErr := store.ListGrants(context.Background())
			if err != nil || state.Claimed() || !verifySecret(state.ActivationVerifier, "RETRY-BOX-CODE") || grantErr != nil || len(grants) != 0 {
				t.Fatal("invalid connection changed claim authority or issued a grant")
			}
		})
	}
}

func TestStandaloneClaimHasAccurateLabel(t *testing.T) {
	withFastArgon(t)
	service := makeTestService(t, initializedMemoryStore(t, "RETRY-BOX-CODE"), &testDeviceSyncController{}, time.Now())
	home := httptest.NewRecorder()
	service.Handler().ServeHTTP(home, httptest.NewRequest(http.MethodGet, "/", nil))
	if !strings.Contains(home.Body.String(), "<button>Claim Box</button>") || strings.Contains(home.Body.String(), "Claim and connect") {
		t.Fatal("standalone claim promises an app connection")
	}
}

func TestClaimOneHourWindowAndCodeReuseAfterExpiry(t *testing.T) {
	withFastArgon(t)
	for _, elapsed := range []time.Duration{59 * time.Minute, time.Hour, time.Hour + time.Second} {
		t.Run(elapsed.String(), func(t *testing.T) {
			now := time.Unix(1_800_000_000, 0).UTC()
			store := initializedMemoryStore(t, "RETRY-BOX-CODE")
			service := makeTestService(t, store, &testDeviceSyncController{}, now)
			handler := service.Handler()
			_, _, raw := testConnectionRequest(t, now, "Claiming Mac")
			var input createConnectionRequestBody
			if err := json.Unmarshal(raw, &input); err != nil {
				t.Fatal(err)
			}
			input.ExpiresAtMillis = now.Add(time.Hour).UnixMilli()
			raw, _ = json.Marshal(input)
			created := httptest.NewRecorder()
			handler.ServeHTTP(created, httptest.NewRequest(http.MethodPost, "/v1/claim-connection-requests", bytes.NewReader(raw)))
			if created.Code != http.StatusCreated {
				t.Fatal("create", created.Code)
			}
			service.now = func() time.Time { return now.Add(elapsed) }
			home := httptest.NewRecorder()
			handler.ServeHTTP(home, httptest.NewRequest(http.MethodGet, "/?claim_request_id="+input.RequestID.String(), nil))
			csrf := cookieNamed(t, home.Result().Cookies(), "facets_box_csrf")
			postClaimRetry(handler, csrf, claimRetryForm(csrf.Value, input.RequestID.String()))
			state, _ := store.State(context.Background())
			if elapsed < time.Hour {
				if !state.Claimed() {
					t.Fatal("claim failed before one hour")
				}
				return
			}
			assertUnavailableClaimPage(t, home.Body.String())
			if state.Claimed() || !verifySecret(state.ActivationVerifier, "RETRY-BOX-CODE") {
				t.Fatal("expired claim consumed code")
			}
			// A new app-bound request can use that same activation code.
			input.RequestID = uuid.New()
			input.ExpiresAtMillis = service.now().Add(time.Hour).UnixMilli()
			raw, _ = json.Marshal(input)
			fresh := httptest.NewRecorder()
			handler.ServeHTTP(fresh, httptest.NewRequest(http.MethodPost, "/v1/claim-connection-requests", bytes.NewReader(raw)))
			if fresh.Code != http.StatusCreated {
				t.Fatal("fresh create", fresh.Code)
			}
			postClaimRetry(handler, csrf, claimRetryForm(csrf.Value, input.RequestID.String()))
			state, _ = store.State(context.Background())
			if !state.Claimed() {
				t.Fatal("same activation code failed on fresh request")
			}
		})
	}
}

func TestOneHourClaimDoesNotExtendSixDigitRequests(t *testing.T) {
	now := time.Now().UTC()
	id := uuid.New()
	digest, _ := ApprovalCodeDigest("123456")
	request := ConnectionRequest{RequestID: id, ApprovalCodeDigest: digest, DeviceName: "Mac", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if request.Validate(now) == nil {
		t.Fatal("six-digit request accepted an hour")
	}
	request.ApprovalCodeDigest = claimRequestDigest(id)
	if err := request.Validate(now); err != nil {
		t.Fatal("claim rejected an hour", err)
	}
	request.ExpiresAt = now.Add(time.Hour + time.Nanosecond)
	if request.Validate(now) == nil {
		t.Fatal("claim exceeded one hour")
	}
	invitation := ConnectionInvitation{InvitationID: id, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if invitation.Validate(now) == nil {
		t.Fatal("six-digit invitation accepted an hour")
	}
}

func claimRetryForm(csrf, requestID string) url.Values {
	return url.Values{"csrf": {csrf}, "display_name": {"Retry Box"}, "activation_code": {"RETRY-BOX-CODE"}, "password": {"a memorable private facets owner phrase"}, "password_confirmation": {"a memorable private facets owner phrase"}, "claim_request_id": {requestID}}
}

func postClaimRetry(handler http.Handler, csrf *http.Cookie, form url.Values) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/claim", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(csrf)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func assertUnavailableClaimPage(t *testing.T, body string) {
	t.Helper()
	if strings.Contains(body, `action="claim"`) || !strings.Contains(body, "start Box setup again in Facets") {
		t.Fatal("unavailable connection offered an owner-only claim instead of restarting setup")
	}
	if strings.Contains(body, "credential rejected") || strings.Contains(body, `class="bad"`) ||
		!strings.Contains(body, "this attempt did not use up your activation code") {
		t.Fatal("unavailable setup misrepresented activation-code validity")
	}
}
