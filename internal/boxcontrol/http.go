package boxcontrol

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type Service struct {
	store         Store
	deviceSync    DeviceSyncController
	privateKey    ed25519.PrivateKey
	publicBaseURL string
	cookiePath    string
	displayName   string
	services      []ServiceDescriptor
	logger        *slog.Logger
	now           func() time.Time
	random        io.Reader
	approvalMu    sync.Mutex
}

func NewService(
	store Store,
	deviceSync DeviceSyncController,
	privateKey ed25519.PrivateKey,
	publicBaseURL string,
	displayName string,
	services []ServiceDescriptor,
	logger *slog.Logger,
) (*Service, error) {
	if store == nil || deviceSync == nil || len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("Box controller dependencies are invalid")
	}
	baseURL, err := ValidatePublicBaseURL(publicBaseURL)
	if err != nil {
		return nil, err
	}
	parsed, _ := url.Parse(baseURL)
	services, err = ValidateServices(services)
	if err != nil {
		return nil, err
	}
	displayName = normalizedDisplayName(displayName)
	if displayName == "" || len(displayName) > 128 {
		return nil, errors.New("Box display name is invalid")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		store: store, deviceSync: deviceSync, privateKey: privateKey,
		publicBaseURL: baseURL, cookiePath: parsed.Path, displayName: displayName,
		services: services, logger: logger, now: time.Now, random: rand.Reader,
	}, nil
}

func (service *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /livez", service.handleLive)
	mux.HandleFunc("GET /readyz", service.handleReady)
	mux.HandleFunc("GET /.well-known/facets-box", service.handleManifest)
	mux.HandleFunc("GET /", service.handleHome)
	mux.HandleFunc("POST /claim", service.handleClaim)
	mux.HandleFunc("POST /login", service.handleLogin)
	mux.HandleFunc("POST /logout", service.handleLogout)
	mux.HandleFunc("POST /password", service.handlePasswordChange)
	mux.HandleFunc("POST /grants/{grantID}/revoke", service.handleGrantRevocation)
	mux.HandleFunc("POST /v1/connection-requests", service.handleCreateConnectionRequest)
	mux.HandleFunc("GET /v1/connection-requests/{requestID}", service.handlePollConnectionRequest)
	mux.HandleFunc("GET /v1/profile", service.handleProfile)
	return securityHeaders(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.ContentLength > MaximumRequestBytes {
			http.Error(writer, "Request is too large.", http.StatusRequestEntityTooLarge)
			return
		}
		mux.ServeHTTP(writer, request)
	}))
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		writer.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(writer, request)
	})
}

func (service *Service) handleLive(writer http.ResponseWriter, _ *http.Request) {
	writer.WriteHeader(http.StatusOK)
}

func (service *Service) handleReady(writer http.ResponseWriter, request *http.Request) {
	if _, err := service.store.State(request.Context()); err != nil {
		http.Error(writer, "Not ready.", http.StatusServiceUnavailable)
		return
	}
	writer.WriteHeader(http.StatusOK)
}

func (service *Service) handleManifest(writer http.ResponseWriter, request *http.Request) {
	state, err := service.store.State(request.Context())
	if err != nil {
		http.Error(writer, "Facets Box is unavailable.", http.StatusServiceUnavailable)
		return
	}
	publicKey := service.privateKey.Public().(ed25519.PublicKey)
	manifest, err := signPublicManifest(service.privateKey, PublicManifestPayload{
		Version: SchemaVersion, BoxID: state.BoxID, DisplayName: service.displayName,
		PublicKey: base64.RawURLEncoding.EncodeToString(publicKey), Services: service.services,
	})
	if err != nil {
		service.internalError(writer, request, "manifest_signing", err)
		return
	}
	writeJSON(writer, http.StatusOK, manifest)
}

type pageModel struct {
	Claimed           bool
	Authenticated     bool
	CSRF              string
	ConnectionRequest string
	ConnectionIntent  string
	DeviceName        string
	GroupName         string
	Approved          bool
	Grants            []ConnectionGrant
	Audit             []AuditEvent
	DeviceSyncHealthy bool
	Error             string
}

var homeTemplate = template.Must(template.New("home").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Facets Box</title><style>
:root{color-scheme:dark light;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}body{max-width:760px;margin:0 auto;padding:32px 20px;background:#15191f;color:#edf2f7}section{background:#20262e;border:1px solid #38414d;border-radius:14px;padding:20px;margin:18px 0}input,button{font:inherit;padding:10px 12px;border-radius:9px;border:1px solid #596575}input{width:min(100%,520px);box-sizing:border-box;background:#11151a;color:inherit}button{background:#147efb;color:white;border:0;font-weight:650}.quiet{color:#aeb8c4}.good{color:#72d68b}.bad{color:#ff7979}code{word-break:break-all}</style></head><body>
<h1>Facets Box</h1><p class="quiet">One control plane for Device Sync and future Facets services. This interface never decrypts Space content.</p>
{{if .Error}}<p class="bad">{{.Error}}</p>{{end}}
{{if not .Claimed}}<section><h2>Claim this Facets Box</h2><p>Enter the one-time activation code shown by the Box console and choose the shared Box Owner password.</p><form method="post" action="claim"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="connection_request" value="{{.ConnectionRequest}}"><p><input name="activation_code" autocomplete="one-time-code" placeholder="One-time activation code" required></p><p><input type="password" name="password" autocomplete="new-password" minlength="15" maxlength="128" placeholder="New Box Owner password" required></p><button>Claim Facets Box</button></form></section>
{{else if not .Authenticated}}<section><h2>Box Owner</h2><p>Enter the Box Owner password to manage services or approve this Facets connection.</p><form method="post" action="login"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="connection_request" value="{{.ConnectionRequest}}"><p><input type="password" name="password" autocomplete="current-password" maxlength="128" required></p><button>Sign in</button></form></section>
{{else}}
{{if .Approved}}<section><h2 class="good">Facets connection approved</h2><p>Return to Facets. The app will finish setup without exposing an invitation or credential.</p></section>{{end}}
{{if and .ConnectionRequest (not .Approved)}}<section><h2>Approve Facets connection</h2><p>Device: <strong>{{.DeviceName}}</strong></p>{{if .GroupName}}<p>Create first Sync Group: <strong>{{.GroupName}}</strong></p>{{end}}<form method="post" action="login"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="connection_request" value="{{.ConnectionRequest}}"><input type="hidden" name="approve_existing_session" value="yes"><button>Approve connection</button></form></section>{{end}}
<section><h2>Services</h2><p>Device Sync: {{if .DeviceSyncHealthy}}<span class="good">available</span>{{else}}<span class="bad">unavailable</span>{{end}}</p><p class="quiet">Shared Spaces, Backup, Compute, Edge, and Post can register here later without reclaiming the Box.</p></section>
<section><h2>Connected Facets installations</h2>{{range .Grants}}<p>{{.DeviceName}} <span class="quiet">last seen {{.LastSeenAt.Format "2006-01-02 15:04 MST"}}</span> {{if .RevokedAt.IsZero}}<form style="display:inline" method="post" action="grants/{{.GrantID}}/revoke"><input type="hidden" name="csrf" value="{{$.CSRF}}"><button>Revoke</button></form>{{else}}<span class="quiet">revoked</span>{{end}}</p>{{else}}<p class="quiet">No app connections yet.</p>{{end}}</section>
<section><h2>Change Box Owner password</h2><form method="post" action="password"><input type="hidden" name="csrf" value="{{.CSRF}}"><p><input type="password" name="current_password" autocomplete="current-password" placeholder="Current password" required></p><p><input type="password" name="new_password" autocomplete="new-password" minlength="15" maxlength="128" placeholder="New password" required></p><button>Change and revoke all connections</button></form></section>
<section><h2>Recent activity</h2>{{range .Audit}}<p><code>{{.OccurredAt.Format "2006-01-02 15:04 MST"}}</code> {{.Kind}} — {{.Outcome}}</p>{{else}}<p class="quiet">No activity yet.</p>{{end}}</section>
<form method="post" action="logout"><input type="hidden" name="csrf" value="{{.CSRF}}"><button>Sign out</button></form>
{{end}}</body></html>`))

func (service *Service) handleHome(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path != "/" {
		http.NotFound(writer, request)
		return
	}
	state, err := service.store.State(request.Context())
	if err != nil {
		http.Error(writer, "Facets Box is unavailable.", http.StatusServiceUnavailable)
		return
	}
	csrf, session, authenticated := service.webContext(request)
	if csrf == "" && !authenticated {
		csrf = service.ensurePreauthCSRF(writer, request)
	}
	model := pageModel{Claimed: state.Claimed(), Authenticated: authenticated, CSRF: csrf}
	model.Error = request.URL.Query().Get("error")
	if requestID := request.URL.Query().Get("connection_request"); requestID != "" {
		if parsed, parseErr := uuid.Parse(requestID); parseErr == nil {
			if connection, connectionErr := service.store.ConnectionRequest(request.Context(), parsed); connectionErr == nil && connection.ExpiresAt.After(service.now()) {
				model.ConnectionRequest = parsed.String()
				model.ConnectionIntent = string(connection.Intent)
				model.DeviceName = connection.DeviceName
				model.GroupName = connection.GroupName
				model.Approved = len(connection.EncryptedResult) != 0
			}
		}
	}
	if authenticated {
		_ = service.store.TouchWebSession(request.Context(), session.TokenDigest, service.now())
		model.Grants, _ = service.store.ListGrants(request.Context())
		model.Audit, _ = service.store.RecentAudit(request.Context(), 20)
		healthContext, cancel := context.WithTimeout(request.Context(), 2*time.Second)
		defer cancel()
		model.DeviceSyncHealthy = service.deviceSync.Healthy(healthContext) == nil
	}
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := homeTemplate.Execute(writer, model); err != nil {
		service.logger.Error("render Box UI failed", "error_type", fmt.Sprintf("%T", err))
	}
}

func (service *Service) handleClaim(writer http.ResponseWriter, request *http.Request) {
	if !service.validateCSRF(request, nil) || request.ParseForm() != nil {
		http.Error(writer, "Request rejected.", http.StatusBadRequest)
		return
	}
	state, err := service.store.State(request.Context())
	if err != nil || state.Claimed() {
		http.Error(writer, "Facets Box is already claimed.", http.StatusConflict)
		return
	}
	activation := strings.TrimSpace(request.FormValue("activation_code"))
	password, err := normalizeOwnerPassword(request.FormValue("password"))
	if err != nil || !verifySecret(state.ActivationVerifier, activation) {
		service.audit(request.Context(), "box_claim", "rejected")
		service.renderRedirectError(writer, request, errOrCredential(err))
		return
	}
	verifier, err := hashSecret(password, service.random)
	if err != nil || service.store.Claim(request.Context(), state.ActivationVerifier, verifier, service.now()) != nil {
		service.internalError(writer, request, "box_claim", err)
		return
	}
	_, _, err = service.issueWebSession(writer, request)
	if err != nil {
		service.internalError(writer, request, "web_session", err)
		return
	}
	service.audit(request.Context(), "box_claim", "accepted")
	service.approveAndRedirect(writer, request)
}

func (service *Service) handleLogin(writer http.ResponseWriter, request *http.Request) {
	csrf, session, authenticated := service.webContext(request)
	if !service.validateCSRF(request, func() *WebSession {
		if authenticated {
			return &session
		}
		return nil
	}()) || request.ParseForm() != nil {
		http.Error(writer, "Request rejected.", http.StatusBadRequest)
		return
	}
	_ = csrf
	if authenticated && request.FormValue("approve_existing_session") == "yes" {
		service.approveAndRedirect(writer, request)
		return
	}
	key := service.loginKey(request)
	now := service.now()
	throttle, err := service.store.LoginThrottle(request.Context(), key)
	if err != nil || (!throttle.BlockedUntil.IsZero() && throttle.BlockedUntil.After(now)) {
		service.audit(request.Context(), "owner_login", "throttled")
		http.Error(writer, "Sign-in is temporarily unavailable.", http.StatusTooManyRequests)
		return
	}
	state, err := service.store.State(request.Context())
	password := normPasswordForVerification(request.FormValue("password"))
	if err != nil || !state.Claimed() || !verifySecret(state.OwnerVerifier, password) {
		service.recordLoginFailure(request.Context(), key, throttle, now)
		service.audit(request.Context(), "owner_login", "rejected")
		service.renderRedirectError(writer, request, ErrInvalidCredential)
		return
	}
	_ = service.store.ClearLoginFailures(request.Context(), key)
	if _, _, err := service.issueWebSession(writer, request); err != nil {
		service.internalError(writer, request, "web_session", err)
		return
	}
	service.audit(request.Context(), "owner_login", "accepted")
	service.approveAndRedirect(writer, request)
}

func (service *Service) handleLogout(writer http.ResponseWriter, request *http.Request) {
	_, session, authenticated := service.webContext(request)
	if !authenticated || !service.validateCSRF(request, &session) {
		http.Error(writer, "Request rejected.", http.StatusBadRequest)
		return
	}
	_ = service.store.DeleteWebSession(request.Context(), session.TokenDigest)
	service.clearSessionCookies(writer)
	http.Redirect(writer, request, service.cookiePath+"/", http.StatusSeeOther)
}

func (service *Service) handlePasswordChange(writer http.ResponseWriter, request *http.Request) {
	_, session, authenticated := service.webContext(request)
	if !authenticated || !service.validateCSRF(request, &session) || request.ParseForm() != nil {
		http.Error(writer, "Request rejected.", http.StatusBadRequest)
		return
	}
	state, err := service.store.State(request.Context())
	current := normPasswordForVerification(request.FormValue("current_password"))
	newPassword, policyErr := normalizeOwnerPassword(request.FormValue("new_password"))
	if err != nil || policyErr != nil || !verifySecret(state.OwnerVerifier, current) {
		service.audit(request.Context(), "owner_password_change", "rejected")
		service.renderRedirectError(writer, request, errOrCredential(policyErr))
		return
	}
	verifier, err := hashSecret(newPassword, service.random)
	if err != nil || service.store.ChangeOwnerPassword(request.Context(), verifier, service.now()) != nil {
		service.internalError(writer, request, "owner_password_change", err)
		return
	}
	service.clearSessionCookies(writer)
	service.audit(request.Context(), "owner_password_change", "accepted")
	http.Redirect(writer, request, service.cookiePath+"/", http.StatusSeeOther)
}

func (service *Service) handleGrantRevocation(writer http.ResponseWriter, request *http.Request) {
	_, session, authenticated := service.webContext(request)
	if !authenticated || !service.validateCSRF(request, &session) {
		http.Error(writer, "Request rejected.", http.StatusBadRequest)
		return
	}
	grantID, err := uuid.Parse(request.PathValue("grantID"))
	if err != nil || service.store.RevokeGrant(request.Context(), grantID, service.now()) != nil {
		http.Error(writer, "Grant not found.", http.StatusNotFound)
		return
	}
	service.audit(request.Context(), "connection_grant_revoke", "accepted")
	http.Redirect(writer, request, service.cookiePath+"/", http.StatusSeeOther)
}

type createConnectionRequestBody struct {
	Version         int              `json:"version"`
	RequestID       uuid.UUID        `json:"requestID"`
	PollTokenDigest string           `json:"pollTokenDigest"`
	ClientPublicKey string           `json:"clientPublicKey"`
	Intent          ConnectionIntent `json:"intent"`
	GroupName       string           `json:"groupName"`
	DeviceName      string           `json:"deviceName"`
	ExpiresAtMillis int64            `json:"expiresAtMilliseconds"`
}

func (service *Service) handleCreateConnectionRequest(writer http.ResponseWriter, request *http.Request) {
	var input createConnectionRequestBody
	if err := decodeJSON(request, &input); err != nil || input.Version != SchemaVersion {
		http.Error(writer, "Connection request is invalid.", http.StatusBadRequest)
		return
	}
	poll, err := base64.RawURLEncoding.Strict().DecodeString(input.PollTokenDigest)
	if err != nil || len(poll) != 32 || base64.RawURLEncoding.EncodeToString(poll) != input.PollTokenDigest {
		http.Error(writer, "Connection request is invalid.", http.StatusBadRequest)
		return
	}
	publicKey, err := base64.RawURLEncoding.Strict().DecodeString(input.ClientPublicKey)
	if err != nil || len(publicKey) != 32 || base64.RawURLEncoding.EncodeToString(publicKey) != input.ClientPublicKey {
		http.Error(writer, "Connection request is invalid.", http.StatusBadRequest)
		return
	}
	now := service.now()
	connection := ConnectionRequest{
		RequestID: input.RequestID, Intent: input.Intent,
		GroupName: normalizedDisplayName(input.GroupName), DeviceName: normalizedDisplayName(input.DeviceName),
		CreatedAt: now, ExpiresAt: time.UnixMilli(input.ExpiresAtMillis),
	}
	copy(connection.PollTokenDigest[:], poll)
	copy(connection.ClientPublicKey[:], publicKey)
	if err := connection.Validate(now); err != nil || service.store.CreateConnectionRequest(request.Context(), connection) != nil {
		http.Error(writer, "Connection request is invalid.", http.StatusBadRequest)
		return
	}
	service.audit(request.Context(), "connection_request", "created")
	writeJSON(writer, http.StatusCreated, struct {
		ApprovalURL string `json:"approvalURL"`
	}{ApprovalURL: service.publicBaseURL + "/?connection_request=" + connection.RequestID.String()})
}

func (service *Service) handlePollConnectionRequest(writer http.ResponseWriter, request *http.Request) {
	requestID, err := uuid.Parse(request.PathValue("requestID"))
	connection, storeErr := service.store.ConnectionRequest(request.Context(), requestID)
	if err != nil || storeErr != nil || !connection.ExpiresAt.After(service.now()) {
		http.NotFound(writer, request)
		return
	}
	token, tokenErr := bearer(request)
	digest, digestErr := TokenDigest(token)
	if tokenErr != nil || digestErr != nil || subtle.ConstantTimeCompare(digest[:], connection.PollTokenDigest[:]) != 1 {
		http.NotFound(writer, request)
		return
	}
	if len(connection.EncryptedResult) == 0 {
		writer.WriteHeader(http.StatusAccepted)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(connection.EncryptedResult)
}

func (service *Service) handleProfile(writer http.ResponseWriter, request *http.Request) {
	if _, err := service.authorizeGrant(request); err != nil {
		http.Error(writer, "Connection grant rejected.", http.StatusUnauthorized)
		return
	}
	profile, err := service.profile(request.Context())
	if err != nil {
		service.internalError(writer, request, "profile", err)
		return
	}
	writeJSON(writer, http.StatusOK, profile)
}

func (service *Service) approveAndRedirect(writer http.ResponseWriter, request *http.Request) {
	requestIDText := request.FormValue("connection_request")
	if requestIDText == "" {
		http.Redirect(writer, request, service.cookiePath+"/", http.StatusSeeOther)
		return
	}
	requestID, err := uuid.Parse(requestIDText)
	if err != nil || service.approveConnection(request.Context(), requestID) != nil {
		service.renderRedirectError(writer, request, errors.New("Facets connection approval failed"))
		return
	}
	http.Redirect(writer, request, service.cookiePath+"/?connection_request="+requestID.String(), http.StatusSeeOther)
}

func (service *Service) approveConnection(ctx context.Context, requestID uuid.UUID) error {
	service.approvalMu.Lock()
	defer service.approvalMu.Unlock()
	connection, err := service.store.ConnectionRequest(ctx, requestID)
	if err != nil {
		return err
	}
	if !connection.ExpiresAt.After(service.now()) {
		return ErrRequestExpired
	}
	if len(connection.EncryptedResult) != 0 {
		return nil
	}
	groups, err := service.deviceSync.Groups(ctx)
	if err != nil {
		return err
	}
	if connection.Intent == ConnectionIntentCreateFirstGroup && len(groups) != 0 {
		return errors.New("the first Device Sync group already exists")
	}
	grantToken, grantDigest, err := RandomToken(service.random)
	if err != nil {
		return err
	}
	now := service.now()
	grant := ConnectionGrant{
		GrantID: uuid.New(), TokenDigest: grantDigest, DeviceName: connection.DeviceName,
		CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(ConnectionGrantLifetime),
	}
	if err := service.store.CreateGrant(ctx, grant); err != nil {
		return err
	}
	profile, err := service.profile(ctx)
	if err != nil {
		_ = service.store.RevokeGrant(ctx, grant.GrantID, now)
		return err
	}
	payload := ConnectionResultPayload{Version: SchemaVersion, BoxID: profile.BoxID, GrantToken: grantToken, Profile: profile}
	if connection.Intent == ConnectionIntentCreateFirstGroup {
		payload.DeviceSyncBootstrap, err = service.deviceSync.IssueAccountBootstrap(ctx)
		if err != nil {
			_ = service.store.RevokeGrant(ctx, grant.GrantID, now)
			return err
		}
	}
	sealed, err := sealConnectionResult(requestID, connection.ClientPublicKey, payload, service.random)
	if err != nil || service.store.CompleteConnectionRequest(ctx, requestID, sealed) != nil {
		_ = service.store.RevokeGrant(ctx, grant.GrantID, now)
		return err
	}
	service.audit(ctx, "connection_request", "approved")
	return nil
}

func (service *Service) profile(ctx context.Context) (AuthenticatedProfile, error) {
	state, err := service.store.State(ctx)
	if err != nil {
		return AuthenticatedProfile{}, err
	}
	groups, err := service.deviceSync.Groups(ctx)
	if err != nil {
		return AuthenticatedProfile{}, err
	}
	return AuthenticatedProfile{
		Version: SchemaVersion, BoxID: state.BoxID, DisplayName: service.displayName,
		Services: service.services, DeviceSyncGroups: groups,
	}, nil
}

func (service *Service) issueWebSession(writer http.ResponseWriter, request *http.Request) (string, string, error) {
	token, tokenDigest, err := RandomToken(service.random)
	if err != nil {
		return "", "", err
	}
	csrf, csrfDigest, err := RandomToken(service.random)
	if err != nil {
		return "", "", err
	}
	now := service.now()
	if err := service.store.CreateWebSession(request.Context(), WebSession{
		TokenDigest: tokenDigest, CSRFDigest: csrfDigest, CreatedAt: now, LastSeenAt: now,
		ExpiresAt: now.Add(WebSessionMaximumLifetime),
	}); err != nil {
		return "", "", err
	}
	http.SetCookie(writer, &http.Cookie{Name: "facets_box_session", Value: token, Path: service.cookiePath, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: int(WebSessionMaximumLifetime.Seconds())})
	http.SetCookie(writer, &http.Cookie{Name: "facets_box_csrf", Value: csrf, Path: service.cookiePath, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: int(WebSessionMaximumLifetime.Seconds())})
	return token, csrf, nil
}

func (service *Service) webContext(request *http.Request) (string, WebSession, bool) {
	csrfCookie, csrfErr := request.Cookie("facets_box_csrf")
	csrf := ""
	if csrfErr == nil {
		csrf = csrfCookie.Value
	}
	sessionCookie, err := request.Cookie("facets_box_session")
	if err != nil {
		return csrf, WebSession{}, false
	}
	digest, err := TokenDigest(sessionCookie.Value)
	if err != nil {
		return csrf, WebSession{}, false
	}
	session, err := service.store.WebSession(request.Context(), digest, service.now())
	if err != nil {
		return csrf, WebSession{}, false
	}
	csrfDigest, err := TokenDigest(csrf)
	if err != nil || subtle.ConstantTimeCompare(csrfDigest[:], session.CSRFDigest[:]) != 1 {
		return csrf, WebSession{}, false
	}
	return csrf, session, true
}

func (service *Service) validateCSRF(request *http.Request, session *WebSession) bool {
	if err := request.ParseForm(); err != nil {
		return false
	}
	form := request.FormValue("csrf")
	cookie, err := request.Cookie("facets_box_csrf")
	if err != nil || form == "" || subtle.ConstantTimeCompare([]byte(form), []byte(cookie.Value)) != 1 {
		return false
	}
	if session != nil {
		digest, err := TokenDigest(form)
		return err == nil && subtle.ConstantTimeCompare(digest[:], session.CSRFDigest[:]) == 1
	}
	return true
}

func (service *Service) ensurePreauthCSRF(writer http.ResponseWriter, request *http.Request) string {
	if cookie, err := request.Cookie("facets_box_csrf"); err == nil {
		if _, digestErr := TokenDigest(cookie.Value); digestErr == nil {
			return cookie.Value
		}
	}
	token, _, err := RandomToken(service.random)
	if err != nil {
		return ""
	}
	http.SetCookie(writer, &http.Cookie{Name: "facets_box_csrf", Value: token, Path: service.cookiePath, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: int(WebSessionMaximumLifetime.Seconds())})
	return token
}

func (service *Service) authorizeGrant(request *http.Request) (ConnectionGrant, error) {
	token, err := bearer(request)
	if err != nil {
		return ConnectionGrant{}, err
	}
	digest, err := TokenDigest(token)
	if err != nil {
		return ConnectionGrant{}, err
	}
	return service.store.Grant(request.Context(), digest, service.now())
}

func bearer(request *http.Request) (string, error) {
	value := request.Header.Get("Authorization")
	if !strings.HasPrefix(value, "Bearer ") || len(value) <= len("Bearer ") {
		return "", ErrInvalidCredential
	}
	return strings.TrimPrefix(value, "Bearer "), nil
}

func (service *Service) loginKey(request *http.Request) string {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		host = request.RemoteAddr
	}
	digest := sha256.Sum256([]byte(strings.ToLower(host)))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func (service *Service) recordLoginFailure(ctx context.Context, key string, previous LoginThrottle, now time.Time) {
	if previous.WindowStart.IsZero() || now.Sub(previous.WindowStart) > 15*time.Minute {
		previous = LoginThrottle{WindowStart: now}
	}
	previous.Failures++
	if previous.Failures >= 5 {
		shift := min(previous.Failures-5, 8)
		delay := time.Duration(1<<shift) * time.Minute
		previous.BlockedUntil = now.Add(min(delay, 15*time.Minute))
	}
	_ = service.store.RecordLoginFailure(ctx, key, previous)
}

func (service *Service) audit(ctx context.Context, kind, outcome string) {
	_ = service.store.AppendAudit(ctx, AuditEvent{OccurredAt: service.now(), Kind: kind, Outcome: outcome})
}

func (service *Service) internalError(writer http.ResponseWriter, request *http.Request, operation string, err error) {
	service.logger.Error("Box controller request failed", "operation", operation, "error_type", fmt.Sprintf("%T", err))
	http.Error(writer, "Facets Box request failed.", http.StatusInternalServerError)
	service.audit(request.Context(), operation, "failed")
}

func (service *Service) renderRedirectError(writer http.ResponseWriter, request *http.Request, err error) {
	requestID := request.FormValue("connection_request")
	location := service.cookiePath + "/"
	if requestID != "" {
		location += "?connection_request=" + url.QueryEscape(requestID) + "&error=" + url.QueryEscape(err.Error())
	}
	http.Redirect(writer, request, location, http.StatusSeeOther)
}

func (service *Service) clearSessionCookies(writer http.ResponseWriter) {
	for _, name := range []string{"facets_box_session", "facets_box_csrf"} {
		http.SetCookie(writer, &http.Cookie{Name: name, Value: "", Path: service.cookiePath, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	}
}

func decodeJSON(request *http.Request, destination any) error {
	decoder := json.NewDecoder(io.LimitReader(request.Body, MaximumRequestBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("request must contain one JSON value")
	}
	return nil
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func errOrCredential(err error) error {
	if err != nil {
		return err
	}
	return ErrInvalidCredential
}

func normPasswordForVerification(value string) string {
	value, err := normalizeOwnerPassword(value)
	if err != nil {
		return ""
	}
	return value
}
