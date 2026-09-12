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

const (
	spacesSyncProductName  = "Spaces Sync"
	groupSpacesProductName = "Group Spaces"
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
	startedAt     time.Time
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
		startedAt: time.Now(),
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
	mux.HandleFunc("GET /authorize-device", service.handleAuthorizeDevice)
	mux.HandleFunc("POST /grants/{grantID}/revoke", service.handleGrantRevocation)
	mux.HandleFunc("POST /v1/claim-connection-requests", service.handleCreateClaimConnectionRequest)
	mux.HandleFunc("POST /v1/connection-invitations/redeem", service.handleRedeemConnectionInvitation)
	mux.HandleFunc("GET /v1/connection-requests/{requestID}", service.handlePollConnectionRequest)
	mux.HandleFunc("GET /v1/profile", service.handleProfile)
	mux.HandleFunc("GET /v1/services/device-sync/groups", service.handleDeviceSyncGroups)
	mux.HandleFunc("POST /v1/services/device-sync/account-admissions", service.handleDeviceSyncAccountAdmission)
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
	displayName := service.displayName
	if state.Claimed() && state.DisplayName != "" {
		displayName = state.DisplayName
	}
	manifest, err := signPublicManifest(service.privateKey, PublicManifestPayload{
		Version: SchemaVersion, BoxID: state.BoxID, DisplayName: displayName, Claimed: state.Claimed(),
		PublicKey: base64.RawURLEncoding.EncodeToString(publicKey), Services: service.services,
	})
	if err != nil {
		service.internalError(writer, request, "manifest_signing", err)
		return
	}
	writeJSON(writer, http.StatusOK, manifest)
}

type pageModel struct {
	Claimed                    bool
	Authenticated              bool
	CSRF                       string
	DisplayName                string
	BoxID                      string
	PublicURL                  string
	Uptime                     string
	Grants                     []ConnectionGrant
	Audit                      []AuditEvent
	DeviceSyncHealthy          bool
	Error                      string
	ReturnTo                   string
	ClaimRequestID             string
	ClaimDeviceName            string
	ClaimExpires               string
	ClaimConnectionUnavailable bool
	InvitationCode             string
	InvitationExpires          string
	SpacesSyncName             string
	GroupSpacesName            string
}

var homeTemplate = template.Must(template.New("home").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Facets Box Management</title><style>
:root{color-scheme:dark light;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}body{max-width:860px;margin:0 auto;padding:32px 20px;background:#15191f;color:#edf2f7}header{padding:8px 2px 14px}section{background:#20262e;border:1px solid #38414d;border-radius:14px;padding:20px;margin:18px 0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:14px}.card{margin:0}input,button,.button{font:inherit;padding:10px 12px;border-radius:9px;border:1px solid #596575}input{width:min(100%,520px);box-sizing:border-box;background:#11151a;color:inherit}button,.button{display:inline-block;background:#147efb;color:white;border:0;font-weight:650;text-decoration:none}.quiet{color:#aeb8c4}.good{color:#72d68b}.bad{color:#ff7979}.pin{font-size:2rem;font-weight:750;letter-spacing:.28em}code{word-break:break-all}.identity{font-size:.88rem}</style></head><body>
<header><h1>Facets Box Management</h1><p class="quiet">Configure this Box and its services. This interface never decrypts Space content.</p></header>
{{if and .Error (not .ClaimConnectionUnavailable)}}<p class="bad" role="alert">{{.Error}}</p>{{end}}
{{if not .Claimed}}<section><h2>Claim this Facets Box</h2>
{{if .ClaimConnectionUnavailable}}<h3>Reopen setup to continue</h3><p>This setup page has expired or is no longer available. The Box has not been claimed, and this attempt did not use up your activation code.</p><p><strong>Close this page and start Box setup again in Facets, then enter the same activation code.</strong> If you have requested a replacement code, use the newest one instead.</p>
{{else}}<p>Enter the one-time activation code shown by the Box console, name the Box, and choose the shared Box Owner password.</p>{{if .ClaimDeviceName}}<p class="quiet">This will also connect <strong>{{.ClaimDeviceName}}</strong> to the Box. Complete setup before {{.ClaimExpires}} (one hour after starting setup).</p>{{end}}<form method="post" action="claim"><input type="hidden" name="csrf" value="{{.CSRF}}">{{if .ClaimRequestID}}<input type="hidden" name="claim_request_id" value="{{.ClaimRequestID}}">{{end}}<p><input name="activation_code" autocomplete="one-time-code" placeholder="One-time activation code" required></p><p><input name="display_name" autocomplete="organization" maxlength="128" value="{{.DisplayName}}" placeholder="Box name, for example Home Box" required></p><p><input type="password" name="password" autocomplete="new-password" minlength="15" maxlength="128" placeholder="New Box Owner password" required></p><p><input type="password" name="password_confirmation" autocomplete="new-password" minlength="15" maxlength="128" placeholder="Confirm Box Owner password" required></p><button>{{if .ClaimRequestID}}Claim and connect{{else}}Claim Box{{end}}</button></form>{{end}}</section>
{{else if not .Authenticated}}<section><h2>{{.DisplayName}}</h2><p>Enter the Box Owner password to continue.</p><form method="post" action="login{{if .ReturnTo}}?return_to={{.ReturnTo}}{{end}}"><input type="hidden" name="csrf" value="{{.CSRF}}"><p><input type="password" name="password" autocomplete="current-password" maxlength="128" required></p><button>Sign in</button></form></section>
{{else}}
{{if .InvitationCode}}<section><h2>Authorize another device</h2><p class="pin">{{.InvitationCode}}</p><p>Use this code to add another Facets device. It expires {{.InvitationExpires}}.</p></section>{{end}}
<section><h2>{{.DisplayName}}</h2><p class="identity"><strong>Address:</strong> {{.PublicURL}}<br><strong>Box identity:</strong> <code>{{.BoxID}}</code><br><strong>Controller uptime:</strong> {{.Uptime}}</p></section>
<section><h2>Device access</h2><p>Create a time-limited code for another Facets installation. The code grants service discovery, not Box administration or membership in any service.</p><a class="button" href="authorize-device">Authorize another device</a></section>
<section><h2>Services</h2><div class="grid"><section class="card"><h3>{{.SpacesSyncName}}</h3>{{if .DeviceSyncHealthy}}<p class="good">Available</p>{{else}}<p class="bad">Unavailable</p>{{end}}</section><section class="card"><h3>{{.GroupSpacesName}}</h3><p class="quiet">Not configured</p></section><section class="card"><h3>Backup</h3><p class="quiet">Not configured</p></section><section class="card"><h3>Edge</h3><p class="quiet">Not configured</p></section><section class="card"><h3>Post</h3><p class="quiet">Not configured</p></section><section class="card"><h3>Compute</h3><p class="quiet">Not configured</p></section></div></section>
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
	displayName := service.displayName
	if state.DisplayName != "" {
		displayName = state.DisplayName
	}
	model := pageModel{
		Claimed: state.Claimed(), Authenticated: authenticated, CSRF: csrf,
		DisplayName: displayName, BoxID: state.BoxID.String(),
		PublicURL: service.publicBaseURL, Uptime: service.uptimeDescription(),
		SpacesSyncName: spacesSyncProductName, GroupSpacesName: groupSpacesProductName,
	}
	model.Error = request.URL.Query().Get("error")
	if !state.Claimed() && request.URL.Query().Has("claim_request_id") {
		// A failed or expired in-app setup must not become a standalone claim.
		model.ClaimConnectionUnavailable = true
		if requestID, parseErr := uuid.Parse(request.URL.Query().Get("claim_request_id")); parseErr == nil {
			if connection, requestErr := service.store.ConnectionRequest(request.Context(), requestID); requestErr == nil &&
				connection.ApprovalCodeDigest == claimRequestDigest(requestID) &&
				connection.ExpiresAt.After(service.now()) && len(connection.EncryptedResult) == 0 {
				model.ClaimRequestID = requestID.String()
				model.ClaimDeviceName = connection.DeviceName
				model.ClaimExpires = connection.ExpiresAt.UTC().Format("15:04 MST")
				model.ClaimConnectionUnavailable = false
			}
		}
	}
	if authenticated {
		if !service.renewWebSession(writer, request, session) {
			return
		}
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

func (service *Service) handleAuthorizeDevice(writer http.ResponseWriter, request *http.Request) {
	state, err := service.store.State(request.Context())
	if err != nil || !state.Claimed() {
		http.Error(writer, "Facets Box has not been claimed.", http.StatusConflict)
		return
	}
	csrf, session, authenticated := service.webContext(request)
	if csrf == "" && !authenticated {
		csrf = service.ensurePreauthCSRF(writer, request)
	}
	displayName := state.DisplayName
	if displayName == "" {
		displayName = service.displayName
	}
	model := pageModel{
		Claimed: true, Authenticated: authenticated, CSRF: csrf,
		DisplayName: displayName, BoxID: state.BoxID.String(),
		PublicURL: service.publicBaseURL, Uptime: service.uptimeDescription(),
		ReturnTo: "authorize-device", SpacesSyncName: spacesSyncProductName,
		GroupSpacesName: groupSpacesProductName,
	}
	if authenticated {
		if !service.renewWebSession(writer, request, session) {
			return
		}
		code, invitation, createErr := service.createConnectionInvitation(request.Context())
		if createErr != nil {
			service.internalError(writer, request, "connection_invitation", createErr)
			return
		}
		model.InvitationCode = code
		model.InvitationExpires = invitation.ExpiresAt.Format("at 3:04 PM")
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
	displayName, nameErr := NormalizeBoxDisplayName(request.FormValue("display_name"))
	password, err := normalizeOwnerPassword(request.FormValue("password"))
	confirmation := normPasswordForVerification(request.FormValue("password_confirmation"))
	var claimRequestID uuid.UUID
	claimRequestText := request.FormValue("claim_request_id")
	var connectionErr error
	if _, hasConnection := request.PostForm["claim_request_id"]; hasConnection {
		claimRequestID, connectionErr = uuid.Parse(claimRequestText)
		if connectionErr == nil && claimRequestID == uuid.Nil {
			connectionErr = ErrInvalidCredential
		}
		if connectionErr == nil {
			var connection ConnectionRequest
			connection, connectionErr = service.store.ConnectionRequest(request.Context(), claimRequestID)
			if connectionErr == nil && (connection.ApprovalCodeDigest != claimRequestDigest(claimRequestID) ||
				!connection.ExpiresAt.After(service.now()) || len(connection.EncryptedResult) != 0) {
				connectionErr = ErrInvalidCredential
			}
		}
	}
	if err != nil || nameErr != nil || connectionErr != nil || password != confirmation ||
		!verifySecret(state.ActivationVerifier, activation) {
		service.audit(request.Context(), "box_claim", "rejected")
		query := url.Values{}
		// A stale app-bound request is not a rejected activation code. Its
		// dedicated recovery page must be the only message in that case.
		if connectionErr == nil {
			switch {
			case err != nil || nameErr != nil:
				query.Set("error", errors.Join(err, nameErr).Error())
			case password != confirmation:
				query.Set("error", "The Box Owner passwords do not match. Enter the same password in both fields.")
			default:
				query.Set("error", "That activation code was not accepted. Check the code shown by the Box console, including capital letters. If you requested a replacement, use the newest code.")
			}
		}
		if _, hasConnection := request.PostForm["claim_request_id"]; hasConnection {
			// Preserve only a bounded request identifier, never credentials or form data.
			requestID, parseErr := uuid.Parse(claimRequestText)
			if parseErr == nil && requestID != uuid.Nil {
				query.Set("claim_request_id", requestID.String())
			} else {
				query.Set("claim_request_id", "invalid")
			}
		}
		http.Redirect(writer, request, service.cookiePath+"/?"+query.Encode(), http.StatusSeeOther)
		return
	}
	verifier, err := hashSecret(password, service.random)
	if err != nil {
		service.internalError(writer, request, "box_claim", err)
		return
	}
	if claimRequestID != uuid.Nil {
		err = service.store.ClaimAndAuthorizeConnection(
			request.Context(), state.ActivationVerifier, verifier,
			displayName, claimRequestID, service.now(),
		)
	} else {
		err = service.store.Claim(
			request.Context(), state.ActivationVerifier, verifier,
			displayName, service.now(),
		)
	}
	if err != nil {
		service.internalError(writer, request, "box_claim", err)
		return
	}
	if claimRequestID != uuid.Nil {
		if approvalErr := service.approveConnection(request.Context(), claimRequestID); approvalErr != nil {
			service.logger.Error("complete claiming installation connection failed", "error_type", fmt.Sprintf("%T", approvalErr))
		}
	}
	_, _, err = service.issueWebSession(writer, request)
	if err != nil {
		service.internalError(writer, request, "web_session", err)
		return
	}
	service.audit(request.Context(), "box_claim", "accepted")
	http.Redirect(writer, request, service.cookiePath+"/", http.StatusSeeOther)
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
	returnTo := request.URL.Query().Get("return_to")
	if returnTo == "authorize-device" {
		http.Redirect(writer, request, service.cookiePath+"/authorize-device", http.StatusSeeOther)
		return
	}
	http.Redirect(writer, request, service.cookiePath+"/", http.StatusSeeOther)
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
	Version           int       `json:"version"`
	RequestID         uuid.UUID `json:"requestID"`
	PollTokenDigest   string    `json:"pollTokenDigest"`
	ClientPublicKey   string    `json:"clientPublicKey"`
	DeviceName        string    `json:"deviceName"`
	ExpiresAtMillis   int64     `json:"expiresAtMilliseconds"`
	AuthorizationCode string    `json:"authorizationCode"`
}

func (service *Service) handleCreateClaimConnectionRequest(writer http.ResponseWriter, request *http.Request) {
	state, stateErr := service.store.State(request.Context())
	if stateErr != nil || state.Claimed() {
		http.Error(writer, "Facets Box is already claimed.", http.StatusConflict)
		return
	}
	var input createConnectionRequestBody
	if err := decodeJSON(request, &input); err != nil || input.Version != SchemaVersion {
		http.Error(writer, "Connection request is invalid.", http.StatusBadRequest)
		return
	}
	connection, err := service.connectionRequest(input, claimRequestDigest(input.RequestID))
	if err != nil || service.store.CreateConnectionRequest(request.Context(), connection) != nil {
		http.Error(writer, "Connection request is invalid.", http.StatusBadRequest)
		return
	}
	service.audit(request.Context(), "claim_connection_request", "created")
	writeJSON(writer, http.StatusCreated, struct {
		ExpiresAtMillis int64 `json:"expiresAtMilliseconds"`
	}{ExpiresAtMillis: connection.ExpiresAt.UnixMilli()})
}

func (service *Service) handleRedeemConnectionInvitation(writer http.ResponseWriter, request *http.Request) {
	state, stateErr := service.store.State(request.Context())
	if stateErr != nil || !state.Claimed() {
		http.Error(writer, "Facets Box has not been claimed.", http.StatusConflict)
		return
	}
	key := "connection-invitation:" + service.loginKey(request)
	now := service.now()
	throttle, err := service.store.LoginThrottle(request.Context(), key)
	if err != nil || (!throttle.BlockedUntil.IsZero() && throttle.BlockedUntil.After(now)) {
		http.Error(writer, "Connection authorization is temporarily unavailable.", http.StatusTooManyRequests)
		return
	}
	var input createConnectionRequestBody
	if err := decodeJSON(request, &input); err != nil || input.Version != SchemaVersion {
		http.Error(writer, "Connection request is invalid.", http.StatusBadRequest)
		return
	}
	codeDigest, err := ApprovalCodeDigest(input.AuthorizationCode)
	connection, connectionErr := service.connectionRequest(input, codeDigest)
	if err != nil || connectionErr != nil ||
		service.store.RedeemConnectionInvitation(request.Context(), codeDigest, connection, now) != nil {
		service.recordLoginFailure(request.Context(), key, throttle, now)
		service.audit(request.Context(), "connection_invitation", "rejected")
		http.Error(writer, "The authorization code is invalid or expired.", http.StatusUnauthorized)
		return
	}
	_ = service.store.ClearLoginFailures(request.Context(), key)
	if err := service.approveConnection(request.Context(), connection.RequestID); err != nil {
		service.internalError(writer, request, "connection_invitation", err)
		return
	}
	service.audit(request.Context(), "connection_invitation", "redeemed")
	writeJSON(writer, http.StatusCreated, struct {
		ExpiresAtMillis int64 `json:"expiresAtMilliseconds"`
	}{ExpiresAtMillis: connection.ExpiresAt.UnixMilli()})
}

func (service *Service) connectionRequest(
	input createConnectionRequestBody,
	approvalCodeDigest [32]byte,
) (ConnectionRequest, error) {
	poll, err := base64.RawURLEncoding.Strict().DecodeString(input.PollTokenDigest)
	if err != nil || len(poll) != 32 || base64.RawURLEncoding.EncodeToString(poll) != input.PollTokenDigest {
		return ConnectionRequest{}, errors.New("poll token digest is invalid")
	}
	publicKey, err := base64.RawURLEncoding.Strict().DecodeString(input.ClientPublicKey)
	if err != nil || len(publicKey) != 32 || base64.RawURLEncoding.EncodeToString(publicKey) != input.ClientPublicKey {
		return ConnectionRequest{}, errors.New("client public key is invalid")
	}
	now := service.now()
	expiresAt := time.UnixMilli(input.ExpiresAtMillis)
	lifetime := ConnectionRequestLifetime
	if approvalCodeDigest == claimRequestDigest(input.RequestID) {
		lifetime = ClaimRequestLifetime
	}
	maximumExpiresAt := now.Add(lifetime)
	if expiresAt.After(maximumExpiresAt) {
		expiresAt = maximumExpiresAt
	}
	connection := ConnectionRequest{
		RequestID: input.RequestID, ApprovalCodeDigest: approvalCodeDigest,
		DeviceName: normalizedDisplayName(input.DeviceName), CreatedAt: now,
		ExpiresAt: expiresAt,
	}
	copy(connection.PollTokenDigest[:], poll)
	copy(connection.ClientPublicKey[:], publicKey)
	if err := connection.Validate(now); err != nil {
		return ConnectionRequest{}, err
	}
	return connection, nil
}

func claimRequestDigest(requestID uuid.UUID) [32]byte {
	return sha256.Sum256([]byte("facets-box-claim-request-v1\x00" + requestID.String()))
}

func (service *Service) createConnectionInvitation(
	ctx context.Context,
) (string, ConnectionInvitation, error) {
	for attempt := 0; attempt < 32; attempt++ {
		code, err := service.randomApprovalCode()
		if err != nil {
			return "", ConnectionInvitation{}, err
		}
		digest, err := ApprovalCodeDigest(code)
		if err != nil {
			return "", ConnectionInvitation{}, err
		}
		now := service.now()
		invitation := ConnectionInvitation{
			InvitationID: uuid.New(), ApprovalCodeDigest: digest,
			CreatedAt: now, ExpiresAt: now.Add(ConnectionRequestLifetime),
		}
		if err := invitation.Validate(now); err != nil {
			return "", ConnectionInvitation{}, err
		}
		if err := service.store.CreateConnectionInvitation(ctx, invitation); err == nil {
			service.audit(ctx, "connection_invitation", "created")
			return code, invitation, nil
		}
	}
	return "", ConnectionInvitation{}, errors.New("connection code allocation failed")
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
		state, stateErr := service.store.State(request.Context())
		if stateErr == nil && state.Claimed() && !connection.AuthorizedAt.IsZero() {
			_ = service.approveConnection(request.Context(), requestID)
			connection, storeErr = service.store.ConnectionRequest(request.Context(), requestID)
		}
		if storeErr != nil || len(connection.EncryptedResult) == 0 {
			writer.WriteHeader(http.StatusAccepted)
			return
		}
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

func (service *Service) handleDeviceSyncGroups(writer http.ResponseWriter, request *http.Request) {
	if _, err := service.authorizeGrant(request); err != nil {
		http.Error(writer, "Connection grant rejected.", http.StatusUnauthorized)
		return
	}
	if !service.hasService("device-sync") {
		http.Error(writer, spacesSyncProductName+" is not configured.", http.StatusServiceUnavailable)
		return
	}
	groups, err := service.deviceSync.Groups(request.Context())
	if err != nil {
		service.internalError(writer, request, "device_sync_groups", err)
		return
	}
	if groups == nil {
		groups = []DeviceSyncGroup{}
	}
	if len(groups) > 256 {
		service.internalError(writer, request, "device_sync_groups", errors.New("Device Sync group response is invalid"))
		return
	}
	seen := make(map[string]struct{}, len(groups))
	for _, group := range groups {
		if err := group.Validate(); err != nil {
			service.internalError(writer, request, "device_sync_groups", err)
			return
		}
		if _, exists := seen[group.SetDiscriminator]; exists {
			service.internalError(writer, request, "device_sync_groups", errors.New("Device Sync group response is invalid"))
			return
		}
		seen[group.SetDiscriminator] = struct{}{}
	}
	state, err := service.store.State(request.Context())
	if err != nil {
		service.internalError(writer, request, "device_sync_groups", err)
		return
	}
	writeJSON(writer, http.StatusOK, struct {
		BoxID  uuid.UUID         `json:"boxID"`
		Groups []DeviceSyncGroup `json:"groups"`
	}{BoxID: state.BoxID, Groups: groups})
}

func (service *Service) handleDeviceSyncAccountAdmission(writer http.ResponseWriter, request *http.Request) {
	if _, err := service.authorizeGrant(request); err != nil {
		http.Error(writer, "Connection grant rejected.", http.StatusUnauthorized)
		return
	}
	if !service.hasService("device-sync") {
		http.Error(writer, spacesSyncProductName+" is not configured.", http.StatusServiceUnavailable)
		return
	}
	bootstrap, err := service.deviceSync.IssueAccountBootstrap(request.Context())
	if err != nil {
		service.internalError(writer, request, "device_sync_account_admission", err)
		return
	}
	state, err := service.store.State(request.Context())
	if err != nil {
		service.internalError(writer, request, "device_sync_account_admission", err)
		return
	}
	writeJSON(writer, http.StatusCreated, struct {
		BoxID     uuid.UUID       `json:"boxID"`
		Bootstrap json.RawMessage `json:"bootstrap"`
	}{BoxID: state.BoxID, Bootstrap: bootstrap})
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
	if connection.AuthorizedAt.IsZero() {
		return ErrInvalidCredential
	}
	if len(connection.EncryptedResult) != 0 {
		return nil
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
	sealed, err := sealConnectionResult(requestID, connection.ClientPublicKey, payload, service.random)
	if err != nil {
		_ = service.store.RevokeGrant(ctx, grant.GrantID, now)
		return err
	}
	if err := service.store.CompleteConnectionRequest(ctx, requestID, sealed); err != nil {
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
	displayName := service.displayName
	if state.DisplayName != "" {
		displayName = state.DisplayName
	}
	configured := make(map[string]ServiceDescriptor, len(service.services))
	for _, descriptor := range service.services {
		configured[descriptor.Kind] = descriptor
	}
	healthContext, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	deviceSyncHealthy := service.deviceSync.Healthy(healthContext) == nil
	serviceKinds := []string{"backup", "compute", "device-sync", "edge", "post", "shared-spaces"}
	statuses := make([]AuthenticatedService, 0, len(serviceKinds))
	for _, kind := range serviceKinds {
		descriptor, present := configured[kind]
		if !present {
			statuses = append(statuses, AuthenticatedService{Kind: kind, Status: ServiceNotConfigured})
			continue
		}
		status := ServiceAvailable
		if kind == "device-sync" && !deviceSyncHealthy {
			status = ServiceUnavailable
		}
		statuses = append(statuses, AuthenticatedService{Kind: kind, Endpoint: descriptor.Endpoint, Status: status})
	}
	return AuthenticatedProfile{
		Version: SchemaVersion, BoxID: state.BoxID, DisplayName: displayName,
		Services: statuses,
	}, nil
}

func (service *Service) hasService(kind string) bool {
	for _, descriptor := range service.services {
		if descriptor.Kind == kind {
			return true
		}
	}
	return false
}

func (service *Service) randomApprovalCode() (string, error) {
	digits := make([]byte, ApprovalCodeDigits)
	for index := range digits {
		for {
			var value [1]byte
			if _, err := io.ReadFull(service.random, value[:]); err != nil {
				return "", err
			}
			if value[0] < 250 {
				digits[index] = '0' + value[0]%10
				break
			}
		}
	}
	return string(digits), nil
}

func (service *Service) uptimeDescription() string {
	duration := service.now().Sub(service.startedAt)
	if duration < 0 {
		duration = 0
	}
	if duration < time.Hour {
		return fmt.Sprintf("%d minutes", int(duration.Minutes()))
	}
	if duration < 24*time.Hour {
		return fmt.Sprintf("%d hours", int(duration.Hours()))
	}
	return fmt.Sprintf("%d days", int(duration.Hours()/24))
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
		ExpiresAt: now.Add(WebSessionRenewalLifetime),
	}); err != nil {
		return "", "", err
	}
	service.setSessionCookies(writer, token, csrf)
	return token, csrf, nil
}

// The native administration view uses the existing, read-only home request to
// retain a login while configuration is foregrounded. It never reloads the form
// or supplies an owner password. Normal authenticated navigation renews too.
func (service *Service) renewWebSession(writer http.ResponseWriter, request *http.Request, session WebSession) bool {
	if err := service.store.TouchWebSession(request.Context(), session.TokenDigest, service.now()); err != nil {
		http.Error(writer, "Please sign in to administer this Box.", http.StatusUnauthorized)
		return false
	}
	token, tokenErr := request.Cookie("facets_box_session")
	csrf, csrfErr := request.Cookie("facets_box_csrf")
	if tokenErr != nil || csrfErr != nil {
		return false
	}
	service.setSessionCookies(writer, token.Value, csrf.Value)
	return true
}

func (service *Service) setSessionCookies(writer http.ResponseWriter, token, csrf string) {
	for name, value := range map[string]string{"facets_box_session": token, "facets_box_csrf": csrf} {
		http.SetCookie(writer, &http.Cookie{Name: name, Value: value, Path: service.cookiePath, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: int(WebSessionRenewalLifetime.Seconds())})
	}
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
	http.SetCookie(writer, &http.Cookie{Name: "facets_box_csrf", Value: token, Path: service.cookiePath, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: int(WebSessionRenewalLifetime.Seconds())})
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
	location := service.cookiePath + "/"
	location += "?error=" + url.QueryEscape(err.Error())
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
