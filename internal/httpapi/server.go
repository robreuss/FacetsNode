package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/rendezvous"
)

const maximumRequestByteCount = ((rendezvous.MaximumCiphertextByteCount + 2) / 3 * 4) + 16_384

type Server struct {
	store                  rendezvous.Store
	relayStore             relay.Store
	blobContentStore       relay.BlobContentStore
	relayWakeBroker        *relayWakeBroker
	operatorTokenDigest    [32]byte
	operatorProvisioningOn bool
	logger                 *slog.Logger
	metrics                *Metrics
	now                    func() time.Time
}

func New(store rendezvous.Store, logger *slog.Logger) *Server {
	return &Server{
		store:           store,
		logger:          logger,
		metrics:         &Metrics{},
		now:             time.Now,
		relayWakeBroker: newRelayWakeBroker(),
	}
}

func NewWithRelay(
	store rendezvous.Store,
	relayStore relay.Store,
	blobContentStore relay.BlobContentStore,
	logger *slog.Logger,
	operatorToken string,
) (*Server, error) {
	server := New(store, logger)
	server.relayStore = relayStore
	server.blobContentStore = blobContentStore
	if operatorToken != "" {
		digest, err := operatorDigest(operatorToken)
		if err != nil {
			return nil, err
		}
		server.operatorTokenDigest = digest
		server.operatorProvisioningOn = true
	}
	return server, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /livez", s.handleLive)
	mux.HandleFunc("GET /readyz", s.handleReady)
	mux.HandleFunc("GET /metrics", s.handleMetrics)
	mux.HandleFunc("POST /v1/pairing/routes", s.handleCreateRoute)
	mux.HandleFunc(
		"PUT /v1/pairing/routes/{routeID}/messages/{messageID}",
		s.handlePublish,
	)
	mux.HandleFunc("GET /v1/pairing/routes/{routeID}/messages", s.handleFetch)
	mux.HandleFunc(
		"POST /v1/pairing/routes/{routeID}/messages/{messageID}/acknowledgement",
		s.handleAcknowledge,
	)
	mux.HandleFunc("POST /v1/pairing/routes/{routeID}/close", s.handleClose)
	if s.relayStore != nil {
		if s.operatorProvisioningOn {
			mux.HandleFunc("POST /v1/relay/domains", s.handleCreateRelayDomain)
		}
		mux.HandleFunc(
			"POST /v1/relay/tenants/{tenantID}/domains/{domainID}/delegated-domains",
			s.handleCreateDelegatedRelayDomain,
		)
		mux.HandleFunc(
			"POST /v1/relay/tenants/{tenantID}/domains/{domainID}/members",
			s.handleCreateRelayMember,
		)
		mux.HandleFunc(
			"POST /v1/relay/tenants/{tenantID}/domains/{domainID}/administration/credential-rotations/{rotationID}",
			s.handleRotateRelayAdministrationCredential,
		)
		mux.HandleFunc(
			"POST /v1/relay/tenants/{tenantID}/domains/{domainID}/members/{memberID}/credential-rotations/{rotationID}",
			s.handleRotateRelayMemberCredential,
		)
		mux.HandleFunc(
			"POST /v1/relay/tenants/{tenantID}/domains/{domainID}/admissions",
			s.handleCreateRelayAdmission,
		)
		mux.HandleFunc(
			"POST /v1/relay/tenants/{tenantID}/domains/{domainID}/admissions/collection",
			s.handleCollectRelayAdmissions,
		)
		mux.HandleFunc(
			"POST /v1/relay/tenants/{tenantID}/domains/{domainID}/admissions/{admissionID}/claim",
			s.handleClaimRelayAdmission,
		)
		mux.HandleFunc(
			"POST /v1/relay/tenants/{tenantID}/domains/{domainID}/admissions/{admissionID}/revocation",
			s.handleRevokeRelayAdmission,
		)
		mux.HandleFunc(
			"POST /v1/relay/tenants/{tenantID}/domains/{domainID}/members/{memberID}/revocation",
			s.handleRevokeRelayMember,
		)
		mux.HandleFunc(
			"PUT /v1/relay/tenants/{tenantID}/domains/{domainID}/messages/{messageID}",
			s.handlePublishRelayMessage,
		)
		mux.HandleFunc(
			"GET /v1/relay/tenants/{tenantID}/domains/{domainID}/messages",
			s.handleFetchRelayMessages,
		)
		mux.HandleFunc(
			"GET /v1/relay/tenants/{tenantID}/domains/{domainID}/messages/wake",
			s.handleWaitForRelayMessages,
		)
		mux.HandleFunc(
			"POST /v1/relay/tenants/{tenantID}/domains/{domainID}/messages/{messageID}/acknowledgments",
			s.handleAcknowledgeRelayMessage,
		)
		if s.blobContentStore != nil {
			mux.HandleFunc(
				"PUT /v1/relay/tenants/{tenantID}/domains/{domainID}/blobs/{blobID}",
				s.handlePublishRelayBlob,
			)
			mux.HandleFunc(
				"GET /v1/relay/tenants/{tenantID}/domains/{domainID}/blobs/{blobID}",
				s.handleFetchRelayBlob,
			)
			mux.HandleFunc(
				"HEAD /v1/relay/tenants/{tenantID}/domains/{domainID}/blobs/{blobID}",
				s.handleFetchRelayBlob,
			)
		}
	}
	return s.securityHeaders(s.requestLog(mux))
}

func (s *Server) handleLive(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]string{"status": "live"})
}

func (s *Server) handleReady(writer http.ResponseWriter, request *http.Request) {
	ctx, cancel := context.WithTimeout(request.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.Ready(ctx); err != nil {
		s.logger.Error("readiness check failed", "error", err)
		writeJSON(writer, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) handleMetrics(writer http.ResponseWriter, _ *http.Request) {
	writer.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	if err := s.metrics.WritePrometheus(writer); err != nil {
		s.logger.Error("write metrics", "error", err)
	}
}

func (s *Server) handleCreateRoute(writer http.ResponseWriter, request *http.Request) {
	var registration rendezvous.Registration
	if err := readJSON(writer, request, &registration); err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := credentialFromRequest(request, registration.RouteID)
	if err != nil || credential.Role != rendezvous.RoleSponsor {
		s.writeError(writer, rendezvous.NewProtocolError(
			rendezvous.CodeUnauthorized,
			"route creation requires the sponsor credential",
		))
		return
	}
	acceptance, err := s.store.CreateRoute(
		request.Context(),
		registration,
		credential.Token,
		s.nowMilliseconds(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(string(acceptance))
	status := http.StatusCreated
	if acceptance == rendezvous.AcceptanceDuplicate {
		status = http.StatusOK
	}
	writeJSON(writer, status, map[string]string{"acceptance": string(acceptance)})
}

func (s *Server) handlePublish(writer http.ResponseWriter, request *http.Request) {
	routeID, messageID, err := pathIDs(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := credentialFromRequest(request, routeID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	var envelope rendezvous.Envelope
	if err := readJSON(writer, request, &envelope); err != nil {
		s.writeError(writer, err)
		return
	}
	if envelope.RouteID != routeID || envelope.MessageID != messageID {
		s.writeError(writer, rendezvous.NewProtocolError(
			rendezvous.CodeWrongRoute,
			"path and envelope identifiers differ",
		))
		return
	}
	acceptance, err := s.store.Publish(
		request.Context(), credential, envelope, s.nowMilliseconds(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(string(acceptance))
	status := http.StatusCreated
	if acceptance == rendezvous.AcceptanceDuplicate {
		status = http.StatusOK
	}
	writeJSON(writer, status, map[string]string{"acceptance": string(acceptance)})
}

func (s *Server) handleFetch(writer http.ResponseWriter, request *http.Request) {
	routeID, err := parseUUID(request.PathValue("routeID"))
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := credentialFromRequest(request, routeID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	envelopes, err := s.store.Fetch(request.Context(), credential, s.nowMilliseconds())
	if err != nil {
		s.writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, struct {
		Envelopes []rendezvous.Envelope `json:"envelopes"`
	}{Envelopes: envelopes})
}

func (s *Server) handleAcknowledge(writer http.ResponseWriter, request *http.Request) {
	routeID, messageID, err := pathIDs(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := credentialFromRequest(request, routeID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	if err := s.store.Acknowledge(
		request.Context(), credential, messageID, s.nowMilliseconds(),
	); err != nil {
		s.writeError(writer, err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleClose(writer http.ResponseWriter, request *http.Request) {
	routeID, err := parseUUID(request.PathValue("routeID"))
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := credentialFromRequest(request, routeID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	if err := s.store.Close(request.Context(), credential, s.nowMilliseconds()); err != nil {
		s.writeError(writer, err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (s *Server) writeError(writer http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	code := "internal_error"
	message := "The request could not be completed."
	var protocol *rendezvous.ProtocolError
	if errors.As(err, &protocol) {
		code = string(protocol.Code)
		message = "The rendezvous request was rejected."
		switch protocol.Code {
		case rendezvous.CodeInvalidRegistration, rendezvous.CodeInvalidEnvelope:
			status = http.StatusBadRequest
		case rendezvous.CodeWrongRoute:
			status = http.StatusBadRequest
		case rendezvous.CodeUnauthorized, rendezvous.CodeRouteNotFound:
			status = http.StatusUnauthorized
		case rendezvous.CodeRouteExpired, rendezvous.CodeMessageExpired:
			status = http.StatusGone
		case rendezvous.CodeMessageNotFound:
			status = http.StatusNotFound
		case rendezvous.CodeRouteClosed, rendezvous.CodeRouteCollision,
			rendezvous.CodeMessageCollision, rendezvous.CodeInvalidAcknowledgment:
			status = http.StatusConflict
		case rendezvous.CodeMailboxFull:
			status = http.StatusTooManyRequests
		}
	} else {
		var relayProtocol *relay.ProtocolError
		if errors.As(err, &relayProtocol) {
			code = string(relayProtocol.Code)
			message = "The relay request was rejected."
			switch relayProtocol.Code {
			case relay.CodeInvalidDomain, relay.CodeInvalidMember,
				relay.CodeInvalidAdmission,
				relay.CodeInvalidCredentialRotation,
				relay.CodeInvalidEnvelope, relay.CodeInvalidBlob,
				relay.CodeInvalidCursor,
				relay.CodeWrongScope:
				status = http.StatusBadRequest
			case relay.CodeUnauthorized, relay.CodeDomainNotFound,
				relay.CodeMemberNotFound, relay.CodeAdmissionNotFound:
				status = http.StatusUnauthorized
			case relay.CodeMemberExpired, relay.CodeMemberRevoked,
				relay.CodeAdmissionExpired, relay.CodeAdmissionRevoked,
				relay.CodeMissingCapability:
				status = http.StatusForbidden
			case relay.CodeMessageNotFound, relay.CodeBlobNotFound:
				status = http.StatusNotFound
			case relay.CodeDomainCollision, relay.CodeMemberCollision,
				relay.CodeAdmissionCollision, relay.CodeAdmissionClaimed,
				relay.CodeCredentialRotationCollision,
				relay.CodeCredentialReuse,
				relay.CodeMessageCollision, relay.CodeBlobCollision,
				relay.CodeInvalidAcknowledgment:
				status = http.StatusConflict
			case relay.CodeDomainFull:
				status = http.StatusTooManyRequests
			}
		} else {
			s.logger.Error("request failed", "error", err)
		}
	}
	writeJSON(writer, status, struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{Error: struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}{Code: code, Message: message}})
}

func (s *Server) nowMilliseconds() int64 {
	return s.now().UnixMilli()
}

func readJSON(writer http.ResponseWriter, request *http.Request, destination any) error {
	return decodeJSONWithLimit(
		writer,
		request,
		destination,
		maximumRequestByteCount,
		func(message string) error {
			return rendezvous.NewProtocolError(rendezvous.CodeInvalidEnvelope, message)
		},
	)
}

func decodeJSONWithLimit(
	writer http.ResponseWriter,
	request *http.Request,
	destination any,
	maximumByteCount int,
	invalidRequest func(string) error,
) error {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return invalidRequest("content type must be application/json")
	}
	request.Body = http.MaxBytesReader(writer, request.Body, int64(maximumByteCount))
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return invalidRequest("request JSON is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return invalidRequest("request contains multiple JSON values")
	}
	return nil
}

func credentialFromRequest(request *http.Request, routeID uuid.UUID) (rendezvous.Credential, error) {
	authorization := request.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, "Bearer ") || len(authorization) <= len("Bearer ") {
		return rendezvous.Credential{}, rendezvous.NewProtocolError(
			rendezvous.CodeUnauthorized,
			"bearer credential is required",
		)
	}
	role := rendezvous.Role(request.Header.Get("X-Facets-Rendezvous-Role"))
	if !role.Valid() {
		return rendezvous.Credential{}, rendezvous.NewProtocolError(
			rendezvous.CodeUnauthorized,
			"rendezvous role is required",
		)
	}
	return rendezvous.Credential{
		RouteID: routeID,
		Role:    role,
		Token:   strings.TrimPrefix(authorization, "Bearer "),
	}, nil
}

func pathIDs(request *http.Request) (uuid.UUID, uuid.UUID, error) {
	routeID, err := parseUUID(request.PathValue("routeID"))
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	messageID, err := parseUUID(request.PathValue("messageID"))
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	return routeID, messageID, nil
}

func parseUUID(value string) (uuid.UUID, error) {
	identifier, err := uuid.Parse(value)
	if err != nil || identifier == uuid.Nil {
		return uuid.Nil, rendezvous.NewProtocolError(
			rendezvous.CodeWrongRoute,
			"identifier is invalid",
		)
	}
	return identifier, nil
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (s *Server) requestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		started := time.Now()
		requestID := uuid.NewString()
		writer.Header().Set("X-Request-ID", requestID)
		recorder := &statusRecorder{ResponseWriter: writer, status: http.StatusOK}
		next.ServeHTTP(recorder, request)
		s.metrics.ObserveStatus(recorder.status)
		s.logger.Info(
			"http request",
			"request_id", requestID,
			"method", request.Method,
			"pattern", request.Pattern,
			"status", recorder.status,
			"duration_ms", time.Since(started).Milliseconds(),
		)
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(writer, request)
	})
}
