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

	"github.com/robreuss/FacetsNode/internal/devicesync"
	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/rendezvous"
	"github.com/robreuss/FacetsNode/internal/sharedspaces"
	"github.com/robreuss/FacetsNode/internal/traffic"
)

const maximumRequestByteCount = ((rendezvous.MaximumCiphertextByteCount + 2) / 3 * 4) + 16_384

type Server struct {
	serviceIdentity        string
	store                  rendezvous.Store
	relayStore             relay.Store
	deviceSyncStore        devicesync.Store
	sharedSpacesStore      sharedspaces.Store
	blobContentStore       relay.BlobContentStore
	blobUploadContentStore relay.BlobUploadContentStore
	relayWakeBroker        *relayWakeBroker
	relayWakeNotifier      RelayWakeNotifier
	operatorTokenDigest    [32]byte
	operatorProvisioningOn bool
	logger                 *slog.Logger
	metrics                *Metrics
	traffic                *trafficController
	now                    func() time.Time
}

func New(store rendezvous.Store, logger *slog.Logger) *Server {
	controller, err := newTrafficController(traffic.DefaultLimits())
	if err != nil {
		panic(err)
	}
	return &Server{
		serviceIdentity: "facets-server",
		store:           store,
		logger:          logger,
		metrics:         &Metrics{},
		now:             time.Now,
		relayWakeBroker: newRelayWakeBroker(),
		traffic:         controller,
	}
}

func (s *Server) SetServiceIdentity(identity string) {
	if identity = strings.TrimSpace(identity); identity != "" {
		s.serviceIdentity = identity
	}
}

// SetDeviceSyncStore enables the product-level Device Sync admission routes.
// Shared Spaces intentionally leaves this unset even though it reuses the
// underlying opaque relay implementation.
func (s *Server) SetDeviceSyncStore(store devicesync.Store) {
	s.deviceSyncStore = store
}

// SetSharedSpacesStore enables the product-level Shared Spaces authority
// routes. Device Sync intentionally leaves this unset even though both
// products reuse the same content-blind relay data plane.
func (s *Server) SetSharedSpacesStore(store sharedspaces.Store) {
	s.sharedSpacesStore = store
}

func NewWithRelay(
	store rendezvous.Store,
	relayStore relay.Store,
	blobContentStore relay.BlobContentStore,
	logger *slog.Logger,
	operatorToken string,
	blobUploadStores ...relay.BlobUploadContentStore,
) (*Server, error) {
	server := New(store, logger)
	server.relayStore = relayStore
	server.blobContentStore = blobContentStore
	if len(blobUploadStores) > 0 {
		server.blobUploadContentStore = blobUploadStores[0]
	}
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
	register := func(pattern string, surface traffic.Surface, handler http.HandlerFunc) {
		mux.Handle(pattern, s.trafficHandler(surface, handler))
	}
	register("GET /livez", traffic.SurfaceManagement, s.handleLive)
	register("GET /readyz", traffic.SurfaceManagement, s.handleReady)
	register("GET /metrics", traffic.SurfaceManagement, s.handleMetrics)
	register("POST /v1/pairing/routes", traffic.SurfaceRendezvous, s.handleCreateRoute)
	register(
		"PUT /v1/pairing/routes/{routeID}/messages/{messageID}",
		traffic.SurfaceRendezvous,
		s.handlePublish,
	)
	register("GET /v1/pairing/routes/{routeID}/messages", traffic.SurfaceRendezvous, s.handleFetch)
	register(
		"POST /v1/pairing/routes/{routeID}/messages/{messageID}/acknowledgement",
		traffic.SurfaceRendezvous,
		s.handleAcknowledge,
	)
	register("POST /v1/pairing/routes/{routeID}/close", traffic.SurfaceRendezvous, s.handleClose)
	if s.relayStore != nil {
		if s.operatorProvisioningOn {
			register("POST /v1/relay/tenants", traffic.SurfaceManagement, s.handleProvisionRelayTenant)
		}
		register(
			"POST /v1/relay/tenants/{tenantID}/domains",
			traffic.SurfaceCheckpointAdmin,
			s.handleProvisionRelayDomain,
		)
		register(
			"POST /v1/relay/tenants/{tenantID}/credential-rotations/{rotationID}",
			traffic.SurfaceCheckpointAdmin,
			s.handleRotateRelayTenantCredential,
		)
		register(
			"GET /v1/relay/tenants/{tenantID}/status",
			traffic.SurfaceCheckpointAdmin,
			s.handleRelayTenantStatus,
		)
		register(
			"POST /v1/relay/tenants/{tenantID}/domains/{domainID}/subscriptions",
			traffic.SurfaceCheckpointAdmin,
			s.handleCreateRelaySubscription,
		)
		register(
			"GET /v1/relay/tenants/{tenantID}/domains/{domainID}/subscriptions/{subscriptionID}",
			traffic.SurfaceCheckpointAdmin,
			s.handleGetRelaySubscription,
		)
		register(
			"POST /v1/relay/tenants/{tenantID}/domains/{domainID}/subscriptions/{subscriptionID}/status",
			traffic.SurfaceCheckpointAdmin,
			s.handleChangeRelaySubscriptionStatus,
		)
		register(
			"GET /v1/relay/tenants/{tenantID}/domains/{domainID}/status",
			traffic.SurfaceCheckpointAdmin,
			s.handleRelayDomainStatus,
		)
		register(
			"POST /v1/relay/tenants/{tenantID}/domains/{domainID}/checkpoint-fences",
			traffic.SurfaceCheckpointAdmin,
			s.handleCreateRelayCheckpointFence,
		)
		register(
			"GET /v1/relay/tenants/{tenantID}/domains/{domainID}/checkpoint-fences/{fenceID}",
			traffic.SurfaceCheckpointAdmin,
			s.handleGetRelayCheckpointFence,
		)
		register(
			"POST /v1/relay/tenants/{tenantID}/domains/{domainID}/checkpoint-fences/{fenceID}/abort",
			traffic.SurfaceCheckpointAdmin,
			s.handleAbortRelayCheckpointFence,
		)
		register(
			"POST /v1/relay/tenants/{tenantID}/domains/{domainID}/checkpoints/candidates",
			traffic.SurfaceCheckpointAdmin,
			s.handleStageRelayCheckpoint,
		)
		register(
			"POST /v1/relay/tenants/{tenantID}/domains/{domainID}/checkpoints/{checkpointID}/activation",
			traffic.SurfaceCheckpointAdmin,
			s.handleActivateRelayCheckpoint,
		)
		register(
			"POST /v1/relay/tenants/{tenantID}/domains/{domainID}/checkpoints/{checkpointID}/collection-dry-run",
			traffic.SurfaceCheckpointAdmin,
			s.handleDryRunRelayCheckpointCollection,
		)
		register(
			"POST /v1/relay/tenants/{tenantID}/domains/{domainID}/checkpoints/{checkpointID}/collection",
			traffic.SurfaceCheckpointAdmin,
			s.handleCollectRelayCheckpoint,
		)
		register(
			"POST /v1/relay/tenants/{tenantID}/domains/{domainID}/members",
			traffic.SurfaceCheckpointAdmin,
			s.handleCreateRelayMember,
		)
		register(
			"POST /v1/relay/tenants/{tenantID}/domains/{domainID}/administration/credential-rotations/{rotationID}",
			traffic.SurfaceCheckpointAdmin,
			s.handleRotateRelayAdministrationCredential,
		)
		register(
			"POST /v1/relay/tenants/{tenantID}/domains/{domainID}/members/{memberID}/credential-rotations/{rotationID}",
			traffic.SurfaceCheckpointAdmin,
			s.handleRotateRelayMemberCredential,
		)
		register(
			"POST /v1/relay/tenants/{tenantID}/domains/{domainID}/admissions",
			traffic.SurfaceCheckpointAdmin,
			s.handleCreateRelayAdmission,
		)
		register(
			"POST /v1/relay/tenants/{tenantID}/domains/{domainID}/admissions/collection",
			traffic.SurfaceCheckpointAdmin,
			s.handleCollectRelayAdmissions,
		)
		register(
			"POST /v1/relay/tenants/{tenantID}/domains/{domainID}/admissions/{admissionID}/claim",
			traffic.SurfaceCheckpointAdmin,
			s.handleClaimRelayAdmission,
		)
		register(
			"POST /v1/relay/tenants/{tenantID}/domains/{domainID}/admissions/{admissionID}/revocation",
			traffic.SurfaceCheckpointAdmin,
			s.handleRevokeRelayAdmission,
		)
		register(
			"POST /v1/relay/tenants/{tenantID}/domains/{domainID}/members/{memberID}/revocation",
			traffic.SurfaceCheckpointAdmin,
			s.handleRevokeRelayMember,
		)
		register(
			"PUT /v1/relay/tenants/{tenantID}/domains/{domainID}/messages/{messageID}",
			traffic.SurfaceRelayMessage,
			s.handlePublishRelayMessage,
		)
		register(
			"GET /v1/relay/tenants/{tenantID}/domains/{domainID}/messages",
			traffic.SurfaceRelayMessage,
			s.handleFetchRelayMessages,
		)
		register(
			"GET /v1/relay/tenants/{tenantID}/domains/{domainID}/messages/wake",
			traffic.SurfaceRelayMessage,
			s.handleWaitForRelayMessages,
		)
		register(
			"POST /v1/relay/tenants/{tenantID}/domains/{domainID}/messages/{messageID}/acknowledgments",
			traffic.SurfaceRelayMessage,
			s.handleAcknowledgeRelayMessage,
		)
		if s.blobContentStore != nil {
			register(
				"GET /v1/relay/tenants/{tenantID}/domains/{domainID}/blobs/{blobID}",
				traffic.SurfaceStorage,
				s.handleFetchRelayBlob,
			)
			if s.blobUploadContentStore != nil {
				register("POST /v1/relay/tenants/{tenantID}/domains/{domainID}/blob-uploads", traffic.SurfaceStorage, s.handleCreateRelayBlobUpload)
				register("GET /v1/relay/tenants/{tenantID}/domains/{domainID}/blob-uploads/{uploadID}", traffic.SurfaceStorage, s.handleGetRelayBlobUpload)
				register("PATCH /v1/relay/tenants/{tenantID}/domains/{domainID}/blob-uploads/{uploadID}", traffic.SurfaceStorage, s.handleAppendRelayBlobUpload)
				register("POST /v1/relay/tenants/{tenantID}/domains/{domainID}/blob-uploads/{uploadID}/finalization", traffic.SurfaceStorage, s.handleFinalizeRelayBlobUpload)
			}
			register(
				"HEAD /v1/relay/tenants/{tenantID}/domains/{domainID}/blobs/{blobID}",
				traffic.SurfaceStorage,
				s.handleFetchRelayBlob,
			)
		}
	}
	if s.deviceSyncStore != nil {
		if s.operatorProvisioningOn {
			register(
				"POST /v1/device-sync/account-admissions",
				traffic.SurfaceManagement,
				s.handleCreateDeviceSyncAccountAdmission,
			)
		}
		register(
			"POST /v1/device-sync/account-admissions/{admissionID}/claim",
			traffic.SurfaceManagement,
			s.handleClaimDeviceSyncAccountAdmission,
		)
		register(
			"GET /v1/device-sync/principals/{principalID}/status",
			traffic.SurfaceManagement,
			s.handleGetDeviceSyncPrincipalStatus,
		)
		register(
			"POST /v1/device-sync/principals/{principalID}/devices/{deviceID}/revocation",
			traffic.SurfaceManagement,
			s.handleRevokeDeviceSyncDevice,
		)
		register(
			"POST /v1/device-sync/principals/{principalID}/control-domains/{domainID}/device-admissions",
			traffic.SurfaceManagement,
			s.handleCreateDeviceSyncDeviceAdmission,
		)
		register(
			"POST /v1/device-sync/principals/{principalID}/device-admissions/{admissionID}/claim",
			traffic.SurfaceManagement,
			s.handleClaimDeviceSyncDeviceAdmission,
		)
		register(
			"POST /v1/device-sync/principals/{principalID}/spaces/{spaceID}",
			traffic.SurfaceManagement,
			s.handleProvisionDeviceSyncSpace,
		)
		register(
			"POST /v1/device-sync/principals/{principalID}/spaces/{spaceID}/domains/{domainID}/device-admissions",
			traffic.SurfaceManagement,
			s.handleCreateDeviceSyncSpaceDeviceAdmission,
		)
		register(
			"POST /v1/device-sync/principals/{principalID}/spaces/{spaceID}/device-admissions/{admissionID}/claim",
			traffic.SurfaceManagement,
			s.handleClaimDeviceSyncSpaceDeviceAdmission,
		)
	}
	if s.sharedSpacesStore != nil {
		if s.operatorProvisioningOn {
			register(
				"POST /v1/shared-spaces",
				traffic.SurfaceManagement,
				s.handleProvisionSharedSpace,
			)
		}
		register(
			"GET /v1/shared-spaces/{spaceID}/domains/{domainID}/status",
			traffic.SurfaceManagement,
			s.handleGetSharedSpaceStatus,
		)
		register(
			"GET /v1/shared-spaces/{spaceID}/domains/{domainID}/authority-events",
			traffic.SurfaceManagement,
			s.handleListSharedSpaceAuthorityEvents,
		)
		register(
			"POST /v1/shared-spaces/{spaceID}/domains/{domainID}/invitations",
			traffic.SurfaceManagement,
			s.handleCreateSharedSpaceInvitation,
		)
		register(
			"GET /v1/shared-spaces/{spaceID}/domains/{domainID}/invitations",
			traffic.SurfaceManagement,
			s.handleListSharedSpaceInvitations,
		)
		register(
			"POST /v1/shared-spaces/{spaceID}/domains/{domainID}/invitations/{invitationID}/claim",
			traffic.SurfaceManagement,
			s.handleClaimSharedSpaceInvitation,
		)
		register(
			"POST /v1/shared-spaces/{spaceID}/domains/{domainID}/invitations/{invitationID}/cancellation",
			traffic.SurfaceManagement,
			s.handleCancelSharedSpaceInvitation,
		)
		register(
			"POST /v1/shared-spaces/{spaceID}/domains/{domainID}/participants/{participantID}/role",
			traffic.SurfaceManagement,
			s.handleChangeSharedSpaceParticipantRole,
		)
		register(
			"POST /v1/shared-spaces/{spaceID}/domains/{domainID}/participants/{participantID}/revocation",
			traffic.SurfaceManagement,
			s.handleRevokeSharedSpaceParticipant,
		)
		register(
			"GET /v1/shared-spaces/{spaceID}/domains/{domainID}/participants/{participantID}/status",
			traffic.SurfaceManagement,
			s.handleGetSharedSpaceParticipantStatus,
		)
		register(
			"GET /v1/shared-spaces/{spaceID}/domains/{domainID}/participants/{participantID}/bootstrap",
			traffic.SurfaceManagement,
			s.handleGetSharedSpaceParticipantBootstrap,
		)
		register(
			"GET /v1/shared-spaces/{spaceID}/domains/{domainID}/participants/{participantID}/key-grant",
			traffic.SurfaceManagement,
			s.handleGetSharedSpaceParticipantKeyGrant,
		)
	}
	return s.securityHeaders(s.requestLog(mux))
}

func (s *Server) handleLive(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]string{"status": "live", "service": s.serviceIdentity})
}

func (s *Server) handleReady(writer http.ResponseWriter, request *http.Request) {
	ctx, cancel := context.WithTimeout(request.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.Ready(ctx); err != nil {
		s.logger.Error("readiness check failed", "error", err)
		writeJSON(writer, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ready", "service": s.serviceIdentity})
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
	s.metrics.ObserveAcceptance(traffic.SurfaceRendezvous, string(acceptance))
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
	s.metrics.ObserveAcceptance(traffic.SurfaceRendezvous, string(acceptance))
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
		var deviceSyncProtocol *devicesync.ProtocolError
		if errors.As(err, &deviceSyncProtocol) {
			code = string(deviceSyncProtocol.Code)
			message = "The Device Sync request was rejected."
			switch deviceSyncProtocol.Code {
			case devicesync.CodeInvalidAdmission, devicesync.CodeInvalidPrincipal,
				devicesync.CodeInvalidSpace,
				devicesync.CodeWrongScope:
				status = http.StatusBadRequest
			case devicesync.CodeUnauthorized, devicesync.CodeAdmissionNotFound:
				status = http.StatusUnauthorized
			case devicesync.CodeDeviceNotFound:
				status = http.StatusNotFound
			case devicesync.CodeAdmissionExpired:
				status = http.StatusGone
			case devicesync.CodeAdmissionClaimed, devicesync.CodeAdmissionCollision,
				devicesync.CodePrincipalCollision, devicesync.CodeDeviceCollision,
				devicesync.CodeDeviceRevoked, devicesync.CodeLastDevice,
				devicesync.CodeSpaceCollision:
				status = http.StatusConflict
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
			return
		}
		var sharedSpacesProtocol *sharedspaces.ProtocolError
		if errors.As(err, &sharedSpacesProtocol) {
			code = string(sharedSpacesProtocol.Code)
			message = "The Shared Spaces request was rejected."
			switch sharedSpacesProtocol.Code {
			case sharedspaces.CodeInvalidSpace, sharedspaces.CodeInvalidInvitation,
				sharedspaces.CodeInvalidParticipant, sharedspaces.CodeInvalidAuthorityEvent,
				sharedspaces.CodeWrongScope:
				status = http.StatusBadRequest
			case sharedspaces.CodeUnauthorized:
				status = http.StatusUnauthorized
			case sharedspaces.CodeSpaceNotFound, sharedspaces.CodeInvitationNotFound,
				sharedspaces.CodeParticipantNotFound, sharedspaces.CodeKeyGrantNotFound:
				status = http.StatusNotFound
			case sharedspaces.CodeInvitationCancelled:
				status = http.StatusGone
			case sharedspaces.CodeSpaceCollision, sharedspaces.CodeInvitationCollision,
				sharedspaces.CodeInvitationClaimed, sharedspaces.CodeParticipantCollision,
				sharedspaces.CodeInvitationCancellationCollision,
				sharedspaces.CodeParticipantRoleCollision,
				sharedspaces.CodeParticipantRevoked, sharedspaces.CodeInitialHost,
				sharedspaces.CodeWrongKeyEpoch, sharedspaces.CodeBootstrapNotReady:
				status = http.StatusConflict
			}
			if s.logger != nil {
				s.logger.Warn(
					"Shared Spaces protocol request rejected",
					"code", code,
					"error", sharedSpacesProtocol,
				)
			}
		} else {
			var relayProtocol *relay.ProtocolError
			if errors.As(err, &relayProtocol) {
				code = string(relayProtocol.Code)
				message = "The relay request was rejected."
				switch relayProtocol.Code {
				case relay.CodeInvalidTenant, relay.CodeInvalidDomain,
					relay.CodeInvalidSubscription, relay.CodeInvalidMember,
					relay.CodeInvalidAdmission,
					relay.CodeInvalidCredentialRotation,
					relay.CodeInvalidEnvelope, relay.CodeInvalidBlob, relay.CodeInvalidBlobUpload,
					relay.CodeInvalidCursor, relay.CodeInvalidCheckpoint, relay.CodeInvalidCheckpointFence,
					relay.CodeWrongScope:
					status = http.StatusBadRequest
				case relay.CodeUnauthorized, relay.CodeTenantNotFound, relay.CodeDomainNotFound,
					relay.CodeMemberNotFound, relay.CodeAdmissionNotFound:
					status = http.StatusUnauthorized
				case relay.CodeMemberExpired, relay.CodeMemberRevoked,
					relay.CodeAdmissionExpired, relay.CodeAdmissionRevoked,
					relay.CodeMissingCapability:
					status = http.StatusForbidden
				case relay.CodeSubscriptionNotFound, relay.CodeMessageNotFound, relay.CodeBlobNotFound, relay.CodeBlobUploadNotFound,
					relay.CodeCheckpointNotFound, relay.CodeCheckpointFenceNotFound:
					status = http.StatusNotFound
				case relay.CodeTenantCollision, relay.CodeDomainCollision,
					relay.CodeSubscriptionCollision, relay.CodeMemberCollision,
					relay.CodeAdmissionCollision, relay.CodeAdmissionClaimed,
					relay.CodeCredentialRotationCollision,
					relay.CodeCredentialReuse,
					relay.CodeMessageCollision, relay.CodeBlobCollision, relay.CodeBlobUploadCollision,
					relay.CodeInvalidAcknowledgment, relay.CodeCheckpointCollision, relay.CodeCheckpointFenceCollision,
					relay.CodeCheckpointFenceActive,
					relay.CodeCheckpointNotEligible, relay.CodeCollectionPlanStale:
					status = http.StatusConflict
				case relay.CodeTenantFull, relay.CodeDomainFull:
					status = http.StatusTooManyRequests
				}
			} else {
				s.logger.Error("request failed", "error", err)
			}
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
