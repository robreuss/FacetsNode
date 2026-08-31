package backupcustody

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/serviceauthority"
	"github.com/robreuss/FacetsNode/internal/traffic"
)

const (
	HeaderChunkSHA256               = "X-Facets-Backup-Chunk-SHA256"
	HeaderTargetCredentialBearer    = "X-Facets-Backup-Target-Credential"
	HeaderTargetCredentialReference = "X-Facets-Backup-Target-Reference"
	HeaderGenerationReference       = "X-Facets-Backup-Generation-Reference"
	HeaderCustodyReceipt            = "X-Facets-Backup-Custody-Receipt"
	HeaderOuterDigest               = "X-Facets-Backup-Outer-Digest"
	maximumProvisionRequestBytes    = 2 * 1024 * 1024
	maximumHTTPChunkBytes           = 64 * 1024 * 1024
)

type AdmissionVerifier interface {
	VerifyAccountAdmission(
		AccountAdmissionCredential,
		serviceauthority.InitialEnrollment,
	) bool
}

type ProvisionAccountRequest struct {
	Admission         AccountAdmissionReference          `json:"admission"`
	ClaimID           uuid.UUID                          `json:"claimID"`
	InitialEnrollment serviceauthority.InitialEnrollment `json:"initialEnrollment"`
	Version           int                                `json:"version"`
}

type CreateTargetHTTPBody struct {
	Request          CreateTargetRequest       `json:"request"`
	TargetCredential TargetCredentialReference `json:"targetCredential"`
	Version          int                       `json:"version"`
}

type HTTPHandler struct {
	coordinator               *Coordinator
	provisioning              *ProvisioningCustody
	admissionVerifier         AdmissionVerifier
	deploymentSigner          *serviceauthority.DeploymentSigner
	authorityBindings         *serviceauthority.BindingRegistry
	maximumChunkBytes         uint64
	maximumCredentialLifetime time.Duration
	now                       func() time.Time
	streamNow                 func() time.Time
	streamIdlePeriod          time.Duration
	readiness                 func(context.Context) error
	afterProvision            func() error
	management                backupTrafficControl
	storage                   backupTrafficControl
}

type backupTrafficControl struct {
	identity   *traffic.Limiter
	connection *traffic.Limiter
	concurrent chan struct{}
}

func NewHTTPHandler(
	coordinator *Coordinator,
	provisioning *ProvisioningCustody,
	admissionVerifier AdmissionVerifier,
	deploymentSigner *serviceauthority.DeploymentSigner,
	authorityBindings *serviceauthority.BindingRegistry,
	maximumChunkBytes uint64,
	maximumCredentialLifetime time.Duration,
	streamIdlePeriod time.Duration,
	trafficLimits traffic.Limits,
	readiness func(context.Context) error,
	afterProvision func() error,
) (*HTTPHandler, error) {
	if coordinator == nil || coordinator.validate() != nil || provisioning == nil ||
		provisioning.Store == nil || provisioning.Journal == nil || provisioning.Registry == nil ||
		provisioning.Signer == nil || provisioning.Clock == nil || admissionVerifier == nil ||
		deploymentSigner == nil || authorityBindings == nil ||
		maximumChunkBytes == 0 || maximumChunkBytes > maximumHTTPChunkBytes ||
		maximumChunkBytes > coordinator.MaximumChunkBytes ||
		maximumCredentialLifetime < time.Minute || maximumCredentialLifetime > 365*24*time.Hour ||
		streamIdlePeriod <= 0 || streamIdlePeriod > time.Hour ||
		coordinator.Registry != authorityBindings || coordinator.Signer != deploymentSigner ||
		provisioning.Registry != authorityBindings || provisioning.Signer != deploymentSigner ||
		traffic.ValidateLimits(trafficLimits) != nil || readiness == nil || afterProvision == nil {
		return nil, serviceauthority.ErrInvalid
	}
	management := newBackupTrafficControl(trafficLimits[traffic.SurfaceManagement])
	storage := newBackupTrafficControl(trafficLimits[traffic.SurfaceStorage])
	return &HTTPHandler{
		coordinator:               coordinator,
		provisioning:              provisioning,
		admissionVerifier:         admissionVerifier,
		deploymentSigner:          deploymentSigner,
		authorityBindings:         authorityBindings,
		maximumChunkBytes:         maximumChunkBytes,
		maximumCredentialLifetime: maximumCredentialLifetime,
		now:                       time.Now,
		streamNow:                 time.Now,
		streamIdlePeriod:          streamIdlePeriod,
		readiness:                 readiness,
		afterProvision:            afterProvision,
		management:                management,
		storage:                   storage,
	}, nil
}

func (handler *HTTPHandler) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /livez", handler.limited(handler.management, http.HandlerFunc(handler.handleLive)))
	mux.Handle("GET /readyz", handler.limited(handler.management, http.HandlerFunc(handler.handleReady)))
	mux.Handle("POST /v1/service-deployment/bootstrap-proof", handler.limited(handler.management, http.HandlerFunc(handler.handleBootstrapDeploymentProof)))
	mux.Handle("POST /v1/service-deployment/proof", handler.limited(handler.management, http.HandlerFunc(handler.handleDeploymentProof)))
	mux.Handle("POST /v1/backup-accounts/{accountID}/provision", handler.limited(handler.management, http.HandlerFunc(handler.handleProvisionAccount)))
	mux.Handle("POST /v1/backup-accounts/{accountID}/targets", handler.limited(handler.management, http.HandlerFunc(handler.handleCreateTarget)))
	mux.Handle("POST /v1/backup-accounts/{accountID}/uploads", handler.limited(handler.management, http.HandlerFunc(handler.handleBeginUpload)))
	mux.Handle("PUT /v1/backup-accounts/{accountID}/uploads/{uploadID}/chunks", handler.limited(handler.storage, http.HandlerFunc(handler.handleUploadChunk)))
	mux.Handle("POST /v1/backup-accounts/{accountID}/uploads/{uploadID}/finalize", handler.limited(handler.management, http.HandlerFunc(handler.handleFinalizeUpload)))
	mux.Handle("POST /v1/backup-accounts/{accountID}/read", handler.limited(handler.storage, http.HandlerFunc(handler.handleRead)))
	mux.Handle("POST /v1/backup-accounts/{accountID}/retention-proofs", handler.limited(handler.management, http.HandlerFunc(handler.handleRetentionProof)))
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		mux.ServeHTTP(writer, request)
	})
}

func newBackupTrafficControl(limit traffic.Limit) backupTrafficControl {
	connectionLimit := limit
	connectionLimit.RequestsPerMinute = limit.ConnectionRequestsPerMinute
	connectionLimit.Burst = limit.ConnectionBurst
	return backupTrafficControl{
		identity:   traffic.NewLimiter(limit),
		connection: traffic.NewLimiter(connectionLimit),
		concurrent: make(chan struct{}, limit.Concurrency),
	}
}

func (handler *HTTPHandler) limited(control backupTrafficControl, next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		now := handler.now()
		allowed, retryAfter := control.identity.Allow(backupTrafficIdentity(request), now)
		if !allowed {
			writer.Header().Set("Retry-After", strconv.Itoa(retryAfter))
			writeBackupError(writer, http.StatusTooManyRequests, "rate_limited")
			return
		}
		allowed, retryAfter = control.connection.Allow(backupTrafficConnection(request), now)
		if !allowed {
			writer.Header().Set("Retry-After", strconv.Itoa(retryAfter))
			writeBackupError(writer, http.StatusTooManyRequests, "rate_limited")
			return
		}
		select {
		case control.concurrent <- struct{}{}:
			defer func() { <-control.concurrent }()
		case <-request.Context().Done():
			return
		default:
			writer.Header().Set("Retry-After", "1")
			writeBackupError(writer, http.StatusTooManyRequests, "concurrency_limited")
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func backupTrafficIdentity(request *http.Request) traffic.Key {
	credential := bearerFromAuthorization(request)
	if credential != "" {
		return traffic.Key(sha256.Sum256([]byte("Facets Backup custody HTTP credential traffic v1\x00" + credential)))
	}
	return traffic.Key(sha256.Sum256([]byte("Facets Backup custody HTTP route traffic v1\x00" +
		trustedBackupAddress(request.RemoteAddr) + "\x00" + request.Pattern)))
}

func backupTrafficConnection(request *http.Request) traffic.Key {
	return traffic.Key(sha256.Sum256([]byte("Facets Backup custody HTTP connection traffic v1\x00" +
		trustedBackupAddress(request.RemoteAddr))))
}

func trustedBackupAddress(remoteAddress string) string {
	host, _, err := net.SplitHostPort(remoteAddress)
	if err != nil {
		host = remoteAddress
	}
	if address, err := netip.ParseAddr(host); err == nil {
		return address.Unmap().String()
	}
	if host == "" {
		return "unknown"
	}
	return strings.ToLower(host)
}

type bootstrapDeploymentProofInput struct {
	DeploymentOffer serviceauthority.DeploymentOffer       `json:"deploymentOffer"`
	Request         serviceauthority.BootstrapProofRequest `json:"request"`
}

func (handler *HTTPHandler) handleBootstrapDeploymentProof(writer http.ResponseWriter, request *http.Request) {
	var input bootstrapDeploymentProofInput
	if decodeBoundedJSON(request, &input, 256*1024, true) != nil ||
		input.Request.Validate(input.DeploymentOffer, handler.deploymentSigner.DeploymentID()) != nil ||
		input.Request.Scope.Kind != serviceauthority.ScopeBackupCustody {
		writeBackupError(writer, http.StatusBadRequest, "invalid_bootstrap_deployment_proof")
		return
	}
	proof, err := handler.deploymentSigner.SignBootstrapProof(input.Request, input.DeploymentOffer, handler.now())
	if err != nil {
		writeBackupError(writer, http.StatusBadRequest, "invalid_bootstrap_deployment_proof")
		return
	}
	writeBackupJSON(writer, http.StatusOK, proof)
}

func (handler *HTTPHandler) handleLive(writer http.ResponseWriter, _ *http.Request) {
	writeBackupJSON(writer, http.StatusOK, map[string]string{"status": "live"})
}

func (handler *HTTPHandler) handleReady(writer http.ResponseWriter, request *http.Request) {
	if handler.readiness(request.Context()) != nil {
		writeBackupError(writer, http.StatusServiceUnavailable, "not_ready")
		return
	}
	writeBackupJSON(writer, http.StatusOK, map[string]string{"status": "ready"})
}

func (handler *HTTPHandler) handleDeploymentProof(writer http.ResponseWriter, request *http.Request) {
	var proofRequest serviceauthority.ProofRequest
	if decodeBoundedJSON(request, &proofRequest, MaximumRequestByteCount, false) != nil ||
		proofRequest.Validate(handler.deploymentSigner.DeploymentID()) != nil ||
		proofRequest.Scope.Kind != serviceauthority.ScopeBackupCustody {
		writeBackupError(writer, http.StatusBadRequest, "invalid_deployment_proof")
		return
	}
	binding := serviceauthority.RequestBinding{
		Scope:             proofRequest.Scope,
		AuthorityRevision: proofRequest.AuthorityRevision,
		AuthorityDigest:   proofRequest.AuthorityManifestDigest,
		DeploymentID:      proofRequest.DeploymentID,
		RouteID:           proofRequest.RouteID,
		TrafficClass:      proofRequest.TrafficClass,
	}
	now := handler.now()
	if handler.authorityBindings.AuthorizeAt(binding, now) != nil {
		writeBackupError(writer, http.StatusConflict, "stale_or_invalid_service_authority")
		return
	}
	proof, err := handler.deploymentSigner.SignProof(proofRequest, now)
	if err != nil {
		writeBackupError(writer, http.StatusBadRequest, "invalid_deployment_proof")
		return
	}
	writeBackupJSON(writer, http.StatusOK, proof)
}

func (handler *HTTPHandler) handleProvisionAccount(writer http.ResponseWriter, request *http.Request) {
	accountID, ok := pathUUID(request, "accountID")
	var body ProvisionAccountRequest
	if !ok || decodeBoundedJSON(request, &body, maximumProvisionRequestBytes, true) != nil ||
		body.Version != Version || body.ClaimID == uuid.Nil || body.Admission.Validate() != nil ||
		body.Admission.AccountID != accountID {
		writeBackupError(writer, http.StatusBadRequest, "invalid_account_provisioning")
		return
	}
	credential, ok := accountCredential(request, body.Admission)
	if !ok || !handler.admissionVerifier.VerifyAccountAdmission(credential, body.InitialEnrollment) {
		writeBackupError(writer, http.StatusUnauthorized, "unauthorized")
		return
	}
	provisionErr := handler.provisioning.ProvisionAccount(request.Context(), credential, body.ClaimID, body.InitialEnrollment)
	// Provisioning can durably advance the database and binding registry before
	// the client receives a response. Reconciliation therefore deliberately runs
	// outside the request context; a disconnected client cannot poison global
	// readiness after sound durable work.
	if reconcileErr := handler.afterProvision(); reconcileErr != nil {
		writeBackupError(writer, http.StatusInternalServerError, "custody_unavailable")
		return
	}
	if provisionErr != nil {
		writeBackupOperationError(writer, provisionErr)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (handler *HTTPHandler) handleCreateTarget(writer http.ResponseWriter, request *http.Request) {
	accountID, ok := pathUUID(request, "accountID")
	var body CreateTargetHTTPBody
	now := handler.now().UnixMilli()
	// v1 is intentionally a runnable custody slice, not a complete credential
	// lifecycle: the one-time account admission can create targets only while it
	// remains valid, and target credentials expire without renewal. A later
	// portable+durable rotation protocol is required before ongoing deployment.
	if !ok || decodeBoundedJSON(request, &body, MaximumRequestByteCount, true) != nil || body.Version != Version ||
		body.Request.Validate() != nil || body.TargetCredential.Validate() != nil ||
		body.Request.Admission.AccountID != accountID || body.TargetCredential.AccountID != accountID ||
		body.TargetCredential.TargetID != body.Request.TargetID || body.TargetCredential.BackupSetID != body.Request.BackupSetID ||
		body.TargetCredential.ExpiresAtMilliseconds <= now ||
		body.TargetCredential.ExpiresAtMilliseconds > now+handler.maximumCredentialLifetime.Milliseconds() {
		writeBackupError(writer, http.StatusBadRequest, "invalid_target_request")
		return
	}
	admission, admissionOK := accountCredential(request, body.Request.Admission)
	targetBearer, targetOK := singleHeader(request.Header, HeaderTargetCredentialBearer)
	target, targetErr := ParseTargetCredential(body.TargetCredential, targetBearer)
	binding, bindingErr := handler.binding(request, accountID, serviceauthority.TrafficControl)
	if !admissionOK || !targetOK || targetErr != nil {
		writeBackupError(writer, http.StatusUnauthorized, "unauthorized")
		return
	}
	if bindingErr != nil {
		writeBackupError(writer, http.StatusConflict, "stale_or_invalid_service_authority")
		return
	}
	if err := handler.provisioning.CreateTarget(request.Context(), admission, body.Request, target, binding); err != nil {
		writeBackupOperationError(writer, err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (handler *HTTPHandler) handleBeginUpload(writer http.ResponseWriter, request *http.Request) {
	accountID, ok := pathUUID(request, "accountID")
	body, err := readBoundedBody(request, MaximumRequestByteCount, true)
	if !ok || err != nil {
		writeBackupError(writer, http.StatusBadRequest, "invalid_upload_request")
		return
	}
	publish, err := DecodePublishRequest(body)
	if err != nil || publish.Credential.AccountID != accountID {
		writeBackupError(writer, http.StatusBadRequest, "invalid_upload_request")
		return
	}
	credential, ok := targetCredential(request, publish.Credential)
	binding, bindingErr := handler.binding(request, accountID, serviceauthority.TrafficControl)
	if !ok {
		writeBackupError(writer, http.StatusUnauthorized, "unauthorized")
		return
	}
	if bindingErr != nil {
		writeBackupError(writer, http.StatusConflict, "stale_or_invalid_service_authority")
		return
	}
	upload, err := handler.coordinator.BeginUpload(request.Context(), credential, publish, binding)
	if err != nil {
		writeBackupOperationError(writer, err)
		return
	}
	writeBackupJSON(writer, http.StatusOK, map[string]any{
		"committedBytes": upload.CommittedBytes,
		"uploadID":       upload.UploadID,
	})
}

func (handler *HTTPHandler) handleUploadChunk(writer http.ResponseWriter, request *http.Request) {
	accountID, accountOK := pathUUID(request, "accountID")
	uploadID, uploadOK := pathUUID(request, "uploadID")
	offsetText := request.URL.Query().Get("offset")
	offset, offsetErr := strconv.ParseUint(offsetText, 10, 64)
	digest, digestOK := singleHeader(request.Header, HeaderChunkSHA256)
	validBody := request.Header.Get("Content-Type") == "application/octet-stream" &&
		request.Header.Get("Content-Encoding") == "" && len(request.TransferEncoding) == 0 &&
		request.ContentLength > 0 && uint64(request.ContentLength) <= handler.maximumChunkBytes
	chunk, bodyErr := readBoundedBody(request, handler.maximumChunkBytes, false)
	if !accountOK || !uploadOK || offsetText == "" || offsetErr != nil || !digestOK || !validBody ||
		bodyErr != nil || len(chunk) == 0 || int64(len(chunk)) != request.ContentLength {
		writeBackupError(writer, http.StatusBadRequest, "invalid_upload_chunk")
		return
	}
	reference, credentialOK := targetReferenceHeaders(request, accountID)
	credential, credentialErr := ParseTargetCredential(reference, bearerFromAuthorization(request))
	binding, bindingErr := handler.binding(request, accountID, serviceauthority.TrafficBulk)
	if !credentialOK || credentialErr != nil {
		writeBackupError(writer, http.StatusUnauthorized, "unauthorized")
		return
	}
	if bindingErr != nil {
		writeBackupError(writer, http.StatusConflict, "stale_or_invalid_service_authority")
		return
	}
	next, err := handler.coordinator.AppendUploadChunk(request.Context(), credential, binding, uploadID, offset, chunk, digest)
	if err != nil {
		writeBackupOperationError(writer, err)
		return
	}
	writeBackupJSON(writer, http.StatusOK, map[string]uint64{"nextOffset": next})
}

func (handler *HTTPHandler) handleFinalizeUpload(writer http.ResponseWriter, request *http.Request) {
	accountID, accountOK := pathUUID(request, "accountID")
	uploadID, uploadOK := pathUUID(request, "uploadID")
	validEmptyBody := request.ContentLength == 0 && len(request.TransferEncoding) == 0 && request.Header.Get("Content-Encoding") == ""
	_ = request.Body.Close()
	if !accountOK || !uploadOK || !validEmptyBody {
		writeBackupError(writer, http.StatusBadRequest, "invalid_upload_finalization")
		return
	}
	reference, credentialOK := targetReferenceHeaders(request, accountID)
	credential, credentialErr := ParseTargetCredential(reference, bearerFromAuthorization(request))
	binding, bindingErr := handler.binding(request, accountID, serviceauthority.TrafficControl)
	if !credentialOK || credentialErr != nil {
		writeBackupError(writer, http.StatusUnauthorized, "unauthorized")
		return
	}
	if bindingErr != nil {
		writeBackupError(writer, http.StatusConflict, "stale_or_invalid_service_authority")
		return
	}
	receipt, err := handler.coordinator.FinalizeUpload(request.Context(), credential, binding, uploadID)
	if err != nil {
		writeBackupOperationError(writer, err)
		return
	}
	writeBackupReceipt(writer, receipt)
}

func (handler *HTTPHandler) handleRetentionProof(writer http.ResponseWriter, request *http.Request) {
	accountID, ok := pathUUID(request, "accountID")
	body, err := readBoundedBody(request, MaximumRequestByteCount, true)
	if !ok || err != nil {
		writeBackupError(writer, http.StatusBadRequest, "invalid_retention_request")
		return
	}
	proof, err := DecodeRetentionProofRequest(body)
	if err != nil || proof.Credential.AccountID != accountID {
		writeBackupError(writer, http.StatusBadRequest, "invalid_retention_request")
		return
	}
	credential, credentialOK := targetCredential(request, proof.Credential)
	binding, bindingErr := handler.binding(request, accountID, serviceauthority.TrafficControl)
	if !credentialOK {
		writeBackupError(writer, http.StatusUnauthorized, "unauthorized")
		return
	}
	if bindingErr != nil {
		writeBackupError(writer, http.StatusConflict, "stale_or_invalid_service_authority")
		return
	}
	receipt, err := handler.coordinator.ConfirmRetention(request.Context(), credential, proof, binding)
	if err != nil {
		writeBackupOperationError(writer, err)
		return
	}
	writeBackupReceipt(writer, receipt)
}

func (handler *HTTPHandler) handleRead(writer http.ResponseWriter, request *http.Request) {
	accountID, ok := pathUUID(request, "accountID")
	body, err := readBoundedBody(request, MaximumRequestByteCount, true)
	if !ok || err != nil {
		writeBackupError(writer, http.StatusBadRequest, "invalid_read_request")
		return
	}
	read, err := DecodeReadRequest(body)
	if err != nil || read.Credential.AccountID != accountID {
		writeBackupError(writer, http.StatusBadRequest, "invalid_read_request")
		return
	}
	credential, credentialOK := targetCredential(request, read.Credential)
	binding, bindingErr := handler.binding(request, accountID, serviceauthority.TrafficBulk)
	if !credentialOK {
		writeBackupError(writer, http.StatusUnauthorized, "unauthorized")
		return
	}
	if bindingErr != nil {
		writeBackupError(writer, http.StatusConflict, "stale_or_invalid_service_authority")
		return
	}
	result, err := handler.coordinator.Read(request.Context(), credential, read, binding)
	if err != nil {
		writeBackupOperationError(writer, err)
		return
	}
	defer result.Content.Close()
	controller := http.NewResponseController(writer)
	if err := setBackupStreamWriteDeadline(
		controller, handler.streamNow().Add(handler.streamIdlePeriod),
	); err != nil {
		writeBackupError(writer, http.StatusInternalServerError, "custody_unavailable")
		return
	}
	defer func() { _ = setBackupStreamWriteDeadline(controller, time.Time{}) }()
	receipt, err := result.Generation.CustodyReceipt.CanonicalJSON()
	if err != nil {
		writeBackupError(writer, http.StatusInternalServerError, "custody_unavailable")
		return
	}
	writer.Header().Set("Content-Type", "application/octet-stream")
	writer.Header().Set("Content-Length", strconv.FormatUint(result.Generation.Generation.OuterByteCount, 10))
	writer.Header().Set(HeaderGenerationReference, result.Generation.GenerationReferenceDigest)
	writer.Header().Set(HeaderCustodyReceipt, base64.RawURLEncoding.EncodeToString(receipt))
	writer.Header().Set(HeaderOuterDigest, result.Generation.Generation.OuterDigest)
	writer.WriteHeader(http.StatusOK)
	_, _ = copyBackupStream(
		writer, controller, result.Content, handler.streamIdlePeriod, handler.streamNow,
	)
}

func copyBackupStream(
	writer io.Writer,
	controller *http.ResponseController,
	reader io.Reader,
	idlePeriod time.Duration,
	now func() time.Time,
) (int64, error) {
	if writer == nil || controller == nil || reader == nil || idlePeriod <= 0 || now == nil {
		return 0, serviceauthority.ErrInvalid
	}
	buffer := make([]byte, 64*1024)
	var written int64
	for {
		count, readErr := reader.Read(buffer)
		if count > 0 {
			remaining := buffer[:count]
			for len(remaining) > 0 {
				if err := setBackupStreamWriteDeadline(controller, now().Add(idlePeriod)); err != nil {
					return written, err
				}
				countWritten, writeErr := writer.Write(remaining)
				if countWritten > 0 {
					written += int64(countWritten)
					remaining = remaining[countWritten:]
				}
				if writeErr != nil {
					return written, writeErr
				}
				if countWritten == 0 {
					return written, io.ErrShortWrite
				}
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return written, nil
			}
			return written, readErr
		}
	}
}

func setBackupStreamWriteDeadline(controller *http.ResponseController, deadline time.Time) error {
	err := controller.SetWriteDeadline(deadline)
	if errors.Is(err, http.ErrNotSupported) {
		// net/http's production response writer supports write deadlines. Keeping
		// the copy helper usable with in-memory ResponseRecorders does not weaken
		// the actual server path.
		return nil
	}
	return err
}

func (handler *HTTPHandler) binding(request *http.Request, accountID uuid.UUID, trafficClass serviceauthority.TrafficClass) (serviceauthority.RequestBinding, error) {
	binding, err := serviceauthority.ParseRequestBinding(request.Header, handler.deploymentSigner.DeploymentID(), trafficClass)
	if err != nil || binding.Scope.Kind != serviceauthority.ScopeBackupCustody || binding.Scope.ScopeID != accountID {
		return serviceauthority.RequestBinding{}, serviceauthority.ErrInvalid
	}
	return binding, nil
}

func pathUUID(request *http.Request, name string) (uuid.UUID, bool) {
	value, err := uuid.Parse(request.PathValue(name))
	return value, err == nil && value != uuid.Nil
}

func accountCredential(request *http.Request, reference AccountAdmissionReference) (AccountAdmissionCredential, bool) {
	bearer := bearerFromAuthorization(request)
	credential, err := ParseAccountAdmissionCredential(reference, bearer)
	return credential, err == nil
}

func targetCredential(request *http.Request, reference TargetCredentialReference) (TargetCredential, bool) {
	credential, err := ParseTargetCredential(reference, bearerFromAuthorization(request))
	return credential, err == nil
}

func bearerFromAuthorization(request *http.Request) string {
	value, ok := singleHeader(request.Header, "Authorization")
	if !ok || !strings.HasPrefix(value, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(value, "Bearer ")
}

// Resumable chunk/finalize requests carry the non-secret exact target reference
// in one canonical base64url header because their body is raw bytes or empty.
func targetReferenceHeaders(request *http.Request, accountID uuid.UUID) (TargetCredentialReference, bool) {
	encoded, ok := singleHeader(request.Header, HeaderTargetCredentialReference)
	if !ok {
		return TargetCredentialReference{}, false
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(data) != encoded {
		return TargetCredentialReference{}, false
	}
	reference, err := DecodeTargetCredentialReference(data)
	return reference, err == nil && reference.AccountID == accountID
}

func singleHeader(header http.Header, name string) (string, bool) {
	values := header.Values(name)
	returnValue := ""
	if len(values) == 1 {
		returnValue = values[0]
	}
	return returnValue, len(values) == 1 && returnValue != ""
}

func readBoundedBody(request *http.Request, maximum uint64, requireCanonicalContentType bool) ([]byte, error) {
	defer request.Body.Close()
	if requireCanonicalContentType && request.Header.Get("Content-Type") != "application/json" {
		return nil, serviceauthority.ErrInvalid
	}
	if maximum == 0 || maximum > uint64(^uint(0)>>1) || request.ContentLength > int64(maximum) {
		return nil, serviceauthority.ErrInvalid
	}
	data, err := io.ReadAll(io.LimitReader(request.Body, int64(maximum)+1))
	if err != nil || len(data) == 0 || uint64(len(data)) > maximum {
		return nil, serviceauthority.ErrInvalid
	}
	return data, nil
}

func decodeBoundedJSON(request *http.Request, target any, maximum uint64, canonical bool) error {
	data, err := readBoundedBody(request, maximum, true)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return serviceauthority.ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return serviceauthority.ErrInvalid
	}
	if canonical {
		encoded, err := json.Marshal(target)
		if err != nil || !bytes.Equal(encoded, data) {
			return serviceauthority.ErrInvalid
		}
	}
	return nil
}

func writeBackupOperationError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrUnauthorized):
		writeBackupError(writer, http.StatusUnauthorized, "unauthorized")
	case errors.Is(err, ErrNotFound):
		writeBackupError(writer, http.StatusUnauthorized, "unauthorized")
	case errors.Is(err, ErrConflict):
		// Public callers must not distinguish an absent object, a wrong bearer,
		// or conflicting immutable identity reuse. The engine retains its typed
		// internal error for audit/testing, while the first public slice keeps a
		// single nonenumerating response.
		writeBackupError(writer, http.StatusUnauthorized, "unauthorized")
	case errors.Is(err, ErrClockRollback):
		writeBackupError(writer, http.StatusConflict, "clock_rollback")
	case errors.Is(err, serviceauthority.ErrInvalid):
		writeBackupError(writer, http.StatusBadRequest, "invalid_request")
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		writeBackupError(writer, http.StatusRequestTimeout, "request_interrupted")
	default:
		writeBackupError(writer, http.StatusInternalServerError, "custody_unavailable")
	}
}

func writeBackupReceipt(writer http.ResponseWriter, receipt serviceauthority.BackupCustodyReceipt) {
	encoded, err := receipt.CanonicalJSON()
	if err != nil {
		writeBackupError(writer, http.StatusInternalServerError, "custody_unavailable")
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Content-Length", strconv.Itoa(len(encoded)))
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(encoded)
}

func writeBackupJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func writeBackupError(writer http.ResponseWriter, status int, code string) {
	writeBackupJSON(writer, status, map[string]string{"code": code})
}
