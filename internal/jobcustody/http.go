package jobcustody

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/carriage"
	"github.com/robreuss/FacetsNode/internal/computequeue"
	"github.com/robreuss/FacetsNode/internal/storagecapacity"
	"github.com/robreuss/FacetsNode/internal/traffic"
)

const (
	JobCustodyChunkSectionKind               byte = 65
	JobCustodyWorkerChunkSectionKind         byte = 66
	JobCustodyResultChunkSectionKind         byte = 67
	JobCustodyResultDeliveryChunkSectionKind byte = 68
	MaximumJobCustodyControlBytes                 = 160 * 1024
	JobCustodyCarriageContentType                 = "application/vnd.facets.carriage"
)

type HTTPAdmissionRequest struct {
	AdmissionEnvelope []byte                `json:"admissionEnvelope"`
	Permit            SignedAdmissionPermit `json:"permit"`
}

type HTTPAuthorizationRequest struct {
	Permit SignedAdmissionPermit `json:"permit"`
}

type HTTPWorkerClaimRequest struct {
	Permit SignedWorkerClaimPermit `json:"permit"`
}

type HTTPWorkerResultRequest struct {
	Permit SignedWorkerResultPermit `json:"permit"`
}

type HTTPResultRetrievalRequest struct {
	Permit SignedResultRetrievalPermit `json:"permit"`
}

type HTTPResultMutationRequest struct {
	Permit SignedResultMutationPermit `json:"permit"`
}

type HTTPResultListStatus struct {
	Results []HTTPWorkerResultStatus `json:"results"`
}

type HTTPWorkerResultStatus struct {
	AssignmentID                 computequeue.AssignmentID                        `json:"assignmentID"`
	ClaimID                      uuid.UUID                                        `json:"claimID"`
	CommittedBytes               int64                                            `json:"committedBytes"`
	CustodyReceipt               json.RawMessage                                  `json:"custodyReceipt,omitempty"`
	DeliveryAcknowledgedAt       *computequeue.Timestamp                          `json:"deliveryAcknowledgedAt,omitempty"`
	ExpiryReceipt                json.RawMessage                                  `json:"expiryReceipt,omitempty"`
	ExpiryStartedAt              *computequeue.Timestamp                          `json:"expiryStartedAt,omitempty"`
	ProtectedObject              computequeue.JobCapsuleProtectedObjectDescriptor `json:"protectedObject"`
	ReleaseReceipt               json.RawMessage                                  `json:"releaseReceipt,omitempty"`
	ReleaseRequestedAt           *computequeue.Timestamp                          `json:"releaseRequestedAt,omitempty"`
	ResultCapsuleID              computequeue.JobCapsuleID                        `json:"resultCapsuleID"`
	ResultSetDigest              computequeue.Digest                              `json:"resultSetDigest"`
	RetentionUntil               computequeue.Timestamp                           `json:"retentionUntil"`
	State                        ResultState                                      `json:"state"`
	WorkerExecutionReceiptDigest computequeue.Digest                              `json:"workerExecutionReceiptDigest"`
}

type HTTPWorkerClaimStatus struct {
	AssignmentID    computequeue.AssignmentID                        `json:"assignmentID"`
	CapsuleID       computequeue.JobCapsuleID                        `json:"capsuleID"`
	ClaimID         uuid.UUID                                        `json:"claimID"`
	LeaseExpiresAt  computequeue.Timestamp                           `json:"leaseExpiresAt"`
	ProtectedObject computequeue.JobCapsuleProtectedObjectDescriptor `json:"protectedObject"`
	State           WorkerClaimState                                 `json:"state"`
}

type HTTPWorkerChunkHeader struct {
	CapsuleID   computequeue.JobCapsuleID `json:"capsuleID"`
	ChunkIndex  int64                     `json:"chunkIndex"`
	ChunkSHA256 computequeue.Digest       `json:"chunkSHA256"`
	ClaimID     uuid.UUID                 `json:"claimID"`
	Version     int                       `json:"version"`
}

type HTTPWorkerResultChunkHeader struct {
	ChunkIndex  int64                    `json:"chunkIndex"`
	ChunkSHA256 computequeue.Digest      `json:"chunkSHA256"`
	Permit      SignedWorkerResultPermit `json:"permit"`
	Version     int                      `json:"version"`
}

type HTTPResultDeliveryChunkHeader struct {
	ChunkIndex            int64                     `json:"chunkIndex"`
	ChunkSHA256           computequeue.Digest       `json:"chunkSHA256"`
	InputCapsuleID        computequeue.JobCapsuleID `json:"inputCapsuleID"`
	ResultCapsuleID       computequeue.JobCapsuleID `json:"resultCapsuleID"`
	RetrievalPermitDigest computequeue.Digest       `json:"retrievalPermitDigest"`
	Version               int                       `json:"version"`
}

func (value HTTPResultDeliveryChunkHeader) Validate() error {
	if value.Version != ResultRetrievalPermitVersion || value.ChunkIndex < 0 ||
		value.ChunkSHA256.Validate() != nil || value.InputCapsuleID.Validate() != nil ||
		value.ResultCapsuleID.Validate() != nil || value.RetrievalPermitDigest.Validate() != nil {
		return ErrInvalid
	}
	return nil
}

func (value HTTPWorkerResultChunkHeader) Validate() error {
	if value.Version != WorkerResultPermitVersion || value.ChunkIndex < 0 ||
		value.ChunkSHA256.Validate() != nil || len(value.Permit.Payload) == 0 ||
		value.Permit.Signature.Validate() != nil {
		return ErrInvalid
	}
	return nil
}

func (value HTTPWorkerChunkHeader) Validate() error {
	if value.Version != 1 || value.CapsuleID.Validate() != nil || value.ClaimID == uuid.Nil ||
		value.ChunkIndex < 0 || value.ChunkSHA256.Validate() != nil {
		return ErrInvalid
	}
	return nil
}

// HTTPChunkHeader is canonical JSON inside a Carriage frame. The signed Box
// permit is the only route authority accepted from the caller; expected
// signer and Worker route fields are never repeated as requester assertions.
type HTTPChunkHeader struct {
	ChunkIndex  int64                 `json:"chunkIndex"`
	ChunkSHA256 computequeue.Digest   `json:"chunkSHA256"`
	Permit      SignedAdmissionPermit `json:"permit"`
	Version     int                   `json:"version"`
}

func (value HTTPChunkHeader) Validate() error {
	if value.Version != AdmissionPermitVersion || value.ChunkIndex < 0 ||
		value.ChunkSHA256.Validate() != nil || value.Permit.Payload == nil ||
		value.Permit.Signature.Validate() != nil {
		return ErrInvalid
	}
	return nil
}

type HTTPAdmissionStatus struct {
	CommittedBytes     int64           `json:"committedBytes"`
	CustodyReceipt     json.RawMessage `json:"custodyReceipt,omitempty"`
	ProtectedByteCount int64           `json:"protectedByteCount"`
	State              AdmissionState  `json:"state"`
}

type HTTPHandler struct {
	coordinator        *Coordinator
	workerClaims       *WorkerClaimCoordinator
	results            *ResultCoordinator
	delivery           *ResultDeliveryCoordinator
	permits            *AdmissionPermitVerifier
	now                func() time.Time
	readiness          func(context.Context) error
	admissionReadiness func(context.Context) (storagecapacity.CoarseReadinessSnapshot, error)
	management         jobCustodyTrafficControl
	storage            jobCustodyTrafficControl
}

type jobCustodyTrafficControl struct {
	limiter    *traffic.Limiter
	concurrent chan struct{}
}

func NewHTTPHandler(
	coordinator *Coordinator,
	workerClaims *WorkerClaimCoordinator,
	results *ResultCoordinator,
	delivery *ResultDeliveryCoordinator,
	permits *AdmissionPermitVerifier,
	limits traffic.Limits,
	readiness func(context.Context) error,
	admissionReadiness func(context.Context) (storagecapacity.CoarseReadinessSnapshot, error),
) (*HTTPHandler, error) {
	if coordinator == nil || coordinator.validate() != nil || workerClaims == nil ||
		workerClaims.validate() != nil || results == nil || results.validate() != nil || permits == nil ||
		delivery == nil || delivery.validate() != nil ||
		traffic.ValidateLimits(limits) != nil || readiness == nil || admissionReadiness == nil {
		return nil, ErrInvalid
	}
	return &HTTPHandler{
		coordinator:        coordinator,
		workerClaims:       workerClaims,
		results:            results,
		delivery:           delivery,
		permits:            permits,
		now:                time.Now,
		readiness:          readiness,
		admissionReadiness: admissionReadiness,
		management:         newJobCustodyTrafficControl(limits[traffic.SurfaceManagement]),
		storage:            newJobCustodyTrafficControl(limits[traffic.SurfaceStorage]),
	}, nil
}

func (handler *HTTPHandler) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /livez", handler.limited(handler.management, http.HandlerFunc(handler.handleLive)))
	mux.Handle("GET /readyz", handler.limited(handler.management, http.HandlerFunc(handler.handleReady)))
	mux.Handle("GET /v1/readiness", handler.limited(handler.management, http.HandlerFunc(handler.handleAdmissionReadiness)))
	mux.Handle("POST /v1/job-custody/admissions", handler.limited(handler.management, http.HandlerFunc(handler.handleAdmission)))
	mux.Handle("POST /v1/job-custody/admissions/{capsuleID}/status", handler.limited(handler.management, http.HandlerFunc(handler.handleStatus)))
	mux.Handle("PUT /v1/job-custody/admissions/{capsuleID}/chunks/{chunkIndex}", handler.limited(handler.storage, http.HandlerFunc(handler.handleChunk)))
	mux.Handle("POST /v1/job-custody/admissions/{capsuleID}/finalize", handler.limited(handler.management, http.HandlerFunc(handler.handleFinalize)))
	mux.Handle("POST /v1/job-custody/workers/{workerID}/claims", handler.limited(handler.management, http.HandlerFunc(handler.handleWorkerClaim)))
	mux.Handle("POST /v1/job-custody/claims/{claimID}/renew", handler.limited(handler.management, http.HandlerFunc(handler.handleWorkerClaimRenew)))
	mux.Handle("POST /v1/job-custody/claims/{claimID}/chunks/{chunkIndex}", handler.limited(handler.storage, http.HandlerFunc(handler.handleWorkerClaimChunk)))
	mux.Handle("POST /v1/job-custody/claims/{claimID}/results", handler.limited(handler.management, http.HandlerFunc(handler.handleWorkerResult)))
	mux.Handle("PUT /v1/job-custody/claims/{claimID}/results/{resultCapsuleID}/chunks/{chunkIndex}", handler.limited(handler.storage, http.HandlerFunc(handler.handleWorkerResultChunk)))
	mux.Handle("POST /v1/job-custody/claims/{claimID}/results/{resultCapsuleID}/finalize", handler.limited(handler.management, http.HandlerFunc(handler.handleWorkerResultFinalize)))
	mux.Handle("POST /v1/job-custody/admissions/{capsuleID}/results/status", handler.limited(handler.management, http.HandlerFunc(handler.handleResultList)))
	mux.Handle("POST /v1/job-custody/admissions/{capsuleID}/results/{resultCapsuleID}/chunks/{chunkIndex}", handler.limited(handler.storage, http.HandlerFunc(handler.handleResultDeliveryChunk)))
	mux.Handle("POST /v1/job-custody/admissions/{capsuleID}/results/{resultCapsuleID}/acknowledgement", handler.limited(handler.management, http.HandlerFunc(handler.handleResultDeliveryAcknowledgement)))
	mux.Handle("POST /v1/job-custody/admissions/{capsuleID}/results/{resultCapsuleID}/release", handler.limited(handler.management, http.HandlerFunc(handler.handleResultRelease)))
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		mux.ServeHTTP(writer, request)
	})
}

func newJobCustodyTrafficControl(limit traffic.Limit) jobCustodyTrafficControl {
	return jobCustodyTrafficControl{
		limiter:    traffic.NewLimiter(limit),
		concurrent: make(chan struct{}, limit.Concurrency),
	}
}

func (handler *HTTPHandler) limited(
	control jobCustodyTrafficControl,
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		allowed, retryAfter := control.limiter.Allow(
			jobCustodyTrafficKey(request), handler.now(),
		)
		if !allowed {
			writer.Header().Set("Retry-After", strconv.Itoa(retryAfter))
			writeJobCustodyError(writer, http.StatusTooManyRequests, "rate_limited")
			return
		}
		select {
		case control.concurrent <- struct{}{}:
			defer func() { <-control.concurrent }()
		case <-request.Context().Done():
			return
		default:
			writer.Header().Set("Retry-After", "1")
			writeJobCustodyError(writer, http.StatusTooManyRequests, "concurrency_limited")
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func jobCustodyTrafficKey(request *http.Request) traffic.Key {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		host = request.RemoteAddr
	}
	if address, parseErr := netip.ParseAddr(host); parseErr == nil {
		host = address.Unmap().String()
	} else {
		host = strings.ToLower(host)
	}
	return traffic.Key(sha256.Sum256([]byte(
		"Facets Job Custody HTTP connection traffic v1\x00" + host + "\x00" + request.Pattern,
	)))
}

func (handler *HTTPHandler) handleLive(writer http.ResponseWriter, _ *http.Request) {
	writeJobCustodyJSON(writer, http.StatusOK, map[string]string{"status": "live"})
}

func (handler *HTTPHandler) handleReady(writer http.ResponseWriter, request *http.Request) {
	if handler.readiness(request.Context()) != nil {
		writeJobCustodyError(writer, http.StatusServiceUnavailable, "not_ready")
		return
	}
	writeJobCustodyJSON(writer, http.StatusOK, map[string]string{"status": "ready"})
}

func (handler *HTTPHandler) handleAdmissionReadiness(writer http.ResponseWriter, request *http.Request) {
	readiness, err := handler.admissionReadiness(request.Context())
	if err != nil || readiness.Validate() != nil {
		writeJobCustodyError(writer, http.StatusServiceUnavailable, "readiness_unavailable")
		return
	}
	if readiness.RetryAfterMilliseconds > 0 {
		retryAfterSeconds := max(int64(1), (readiness.RetryAfterMilliseconds+999)/1000)
		writer.Header().Set("Retry-After", strconv.FormatInt(retryAfterSeconds, 10))
	}
	writeJobCustodyJSON(writer, http.StatusOK, readiness)
}

func (handler *HTTPHandler) handleAdmission(writer http.ResponseWriter, request *http.Request) {
	var input HTTPAdmissionRequest
	if decodeJobCustodyJSON(request, &input, MaximumJobCustodyControlBytes) != nil ||
		len(input.AdmissionEnvelope) == 0 {
		writeJobCustodyError(writer, http.StatusBadRequest, "invalid_admission")
		return
	}
	now := computequeue.Timestamp(handler.now().UnixMilli())
	authorization, err := handler.permits.Verify(input.Permit, input.AdmissionEnvelope, now)
	if err != nil {
		writeJobCustodyError(writer, http.StatusUnauthorized, "unauthorized")
		return
	}
	handle, err := handler.coordinator.AdmitAuthorized(
		request.Context(), input.AdmissionEnvelope, authorization,
	)
	if err != nil {
		writeJobCustodyOperationError(writer, err)
		return
	}
	writeJobCustodyJSON(writer, http.StatusOK, admissionHTTPStatus(handle.Record()))
}

func (handler *HTTPHandler) handleStatus(writer http.ResponseWriter, request *http.Request) {
	handle, ok := handler.authorizedStoredAdmission(writer, request)
	if !ok {
		return
	}
	writeJobCustodyJSON(writer, http.StatusOK, admissionHTTPStatus(handle.Record()))
}

func (handler *HTTPHandler) handleChunk(writer http.ResponseWriter, request *http.Request) {
	capsuleID, ok := pathJobCapsuleID(request)
	chunkIndex, indexErr := strconv.ParseInt(request.PathValue("chunkIndex"), 10, 64)
	if !ok || indexErr != nil || chunkIndex < 0 ||
		request.Header.Get("Content-Type") != JobCustodyCarriageContentType {
		writeJobCustodyError(writer, http.StatusBadRequest, "invalid_chunk")
		return
	}
	body, err := readBoundedJobCustodyBody(
		request,
		int64(carriage.FixedHeaderBytes+carriage.MaximumHeaderBytes+carriage.MaximumPayloadBytes),
	)
	if err != nil {
		writeJobCustodyError(writer, http.StatusBadRequest, "invalid_chunk")
		return
	}
	frame, err := carriage.DecodeFrame(body)
	if err != nil || frame.SectionKind != JobCustodyChunkSectionKind {
		writeJobCustodyError(writer, http.StatusBadRequest, "invalid_chunk")
		return
	}
	header, err := computequeue.DecodeCanonical[HTTPChunkHeader](frame.Header)
	if err != nil || header.Validate() != nil || header.ChunkIndex != chunkIndex {
		writeJobCustodyError(writer, http.StatusBadRequest, "invalid_chunk")
		return
	}
	handle, err := handler.authorizeStored(
		request.Context(), capsuleID, header.Permit,
	)
	if errors.Is(err, ErrAdmissionPermitAuthentication) {
		writeJobCustodyError(writer, http.StatusUnauthorized, "unauthorized")
		return
	}
	if err != nil {
		writeJobCustodyOperationError(writer, err)
		return
	}
	next, err := handler.coordinator.AppendChunk(
		request.Context(), handle, chunkIndex, frame.Payload, header.ChunkSHA256,
	)
	if err != nil {
		writeJobCustodyOperationError(writer, err)
		return
	}
	writeJobCustodyJSON(writer, http.StatusOK, map[string]int64{"committedBytes": next})
}

func (handler *HTTPHandler) handleFinalize(writer http.ResponseWriter, request *http.Request) {
	handle, ok := handler.authorizedStoredAdmission(writer, request)
	if !ok {
		return
	}
	record, err := handler.coordinator.Finalize(request.Context(), handle)
	if err != nil {
		writeJobCustodyOperationError(writer, err)
		return
	}
	writeJobCustodyJSON(writer, http.StatusOK, admissionHTTPStatus(record))
}

func (handler *HTTPHandler) handleWorkerClaim(writer http.ResponseWriter, request *http.Request) {
	authorization, ok := handler.authorizedWorkerClaim(writer, request)
	if !ok {
		return
	}
	workerID := computequeue.WorkerID(request.PathValue("workerID"))
	if workerID.Validate() != nil || authorization.Payload().RouteRecipientWorkerID != workerID {
		writeJobCustodyError(writer, http.StatusBadRequest, "invalid_worker_claim")
		return
	}
	handle, err := handler.workerClaims.Claim(request.Context(), authorization)
	if errors.Is(err, ErrNoWork) {
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		writeJobCustodyOperationError(writer, err)
		return
	}
	writeJobCustodyJSON(writer, http.StatusOK, workerClaimHTTPStatus(handle))
}

func (handler *HTTPHandler) handleWorkerClaimRenew(writer http.ResponseWriter, request *http.Request) {
	authorization, ok := handler.authorizedWorkerClaim(writer, request)
	if !ok {
		return
	}
	claimID, err := uuid.Parse(request.PathValue("claimID"))
	if err != nil || claimID == uuid.Nil || authorization.Payload().ClaimID != claimID {
		writeJobCustodyError(writer, http.StatusBadRequest, "invalid_worker_claim")
		return
	}
	handle, err := handler.workerClaims.Renew(request.Context(), authorization)
	if err != nil {
		writeJobCustodyOperationError(writer, err)
		return
	}
	writeJobCustodyJSON(writer, http.StatusOK, workerClaimHTTPStatus(handle))
}

func (handler *HTTPHandler) handleWorkerClaimChunk(writer http.ResponseWriter, request *http.Request) {
	authorization, ok := handler.authorizedWorkerClaim(writer, request)
	if !ok {
		return
	}
	claimID, claimErr := uuid.Parse(request.PathValue("claimID"))
	chunkIndex, indexErr := strconv.ParseInt(request.PathValue("chunkIndex"), 10, 64)
	if claimErr != nil || claimID == uuid.Nil || authorization.Payload().ClaimID != claimID ||
		indexErr != nil || chunkIndex < 0 {
		writeJobCustodyError(writer, http.StatusBadRequest, "invalid_worker_chunk")
		return
	}
	handle, err := handler.workerClaims.Claim(request.Context(), authorization)
	if err != nil {
		writeJobCustodyOperationError(writer, err)
		return
	}
	chunk, err := handler.workerClaims.ReadChunk(handle, chunkIndex)
	if err != nil {
		writeJobCustodyOperationError(writer, err)
		return
	}
	digest := sha256.Sum256(chunk)
	headerBytes, err := computequeue.EncodeCanonical(HTTPWorkerChunkHeader{
		CapsuleID: handle.Admission().Header.CapsuleID, ChunkIndex: chunkIndex,
		ChunkSHA256: computequeue.Digest(fmt.Sprintf("%x", digest[:])),
		ClaimID:     claimID, Version: 1,
	})
	if err != nil {
		writeJobCustodyError(writer, http.StatusInternalServerError, "custody_unavailable")
		return
	}
	wire, err := (carriage.Frame{
		SectionKind: JobCustodyWorkerChunkSectionKind, Header: headerBytes, Payload: chunk,
	}).Encode()
	if err != nil {
		writeJobCustodyError(writer, http.StatusInternalServerError, "custody_unavailable")
		return
	}
	writer.Header().Set("Content-Type", JobCustodyCarriageContentType)
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(wire)
}

func (handler *HTTPHandler) handleWorkerResult(writer http.ResponseWriter, request *http.Request) {
	authorization, ok := handler.authorizedWorkerResult(writer, request)
	if !ok || !workerResultPathMatches(request, authorization) {
		if ok {
			writeJobCustodyError(writer, http.StatusBadRequest, "invalid_worker_result")
		}
		return
	}
	handle, err := handler.results.AcceptAuthorized(request.Context(), authorization)
	if err != nil {
		writeJobCustodyOperationError(writer, err)
		return
	}
	writeJobCustodyJSON(writer, http.StatusOK, workerResultHTTPStatus(handle.Record()))
}

func (handler *HTTPHandler) handleWorkerResultChunk(writer http.ResponseWriter, request *http.Request) {
	claimID, claimErr := uuid.Parse(request.PathValue("claimID"))
	resultCapsuleID := computequeue.JobCapsuleID(request.PathValue("resultCapsuleID"))
	chunkIndex, indexErr := strconv.ParseInt(request.PathValue("chunkIndex"), 10, 64)
	if claimErr != nil || claimID == uuid.Nil || resultCapsuleID.Validate() != nil ||
		indexErr != nil || chunkIndex < 0 ||
		request.Header.Get("Content-Type") != JobCustodyCarriageContentType {
		writeJobCustodyError(writer, http.StatusBadRequest, "invalid_worker_result_chunk")
		return
	}
	body, err := readBoundedJobCustodyBody(
		request,
		int64(carriage.FixedHeaderBytes+carriage.MaximumHeaderBytes+carriage.MaximumPayloadBytes),
	)
	if err != nil {
		writeJobCustodyError(writer, http.StatusBadRequest, "invalid_worker_result_chunk")
		return
	}
	frame, err := carriage.DecodeFrame(body)
	if err != nil || frame.SectionKind != JobCustodyResultChunkSectionKind {
		writeJobCustodyError(writer, http.StatusBadRequest, "invalid_worker_result_chunk")
		return
	}
	header, err := computequeue.DecodeCanonical[HTTPWorkerResultChunkHeader](frame.Header)
	if err != nil || header.Validate() != nil || header.ChunkIndex != chunkIndex {
		writeJobCustodyError(writer, http.StatusBadRequest, "invalid_worker_result_chunk")
		return
	}
	authorization, err := handler.permits.VerifyWorkerResult(
		header.Permit, computequeue.Timestamp(handler.now().UnixMilli()),
	)
	if err != nil {
		writeJobCustodyError(writer, http.StatusUnauthorized, "unauthorized")
		return
	}
	if authorization.Payload().Result.ClaimID != claimID ||
		authorization.Payload().Result.ResultCapsuleID != resultCapsuleID {
		writeJobCustodyError(writer, http.StatusBadRequest, "invalid_worker_result_chunk")
		return
	}
	handle, err := handler.results.AcceptAuthorized(request.Context(), authorization)
	if err != nil {
		writeJobCustodyOperationError(writer, err)
		return
	}
	next, err := handler.results.AppendChunk(
		request.Context(), handle, chunkIndex, frame.Payload, header.ChunkSHA256,
	)
	if err != nil {
		writeJobCustodyOperationError(writer, err)
		return
	}
	writeJobCustodyJSON(writer, http.StatusOK, map[string]int64{"committedBytes": next})
}

func (handler *HTTPHandler) handleWorkerResultFinalize(writer http.ResponseWriter, request *http.Request) {
	authorization, ok := handler.authorizedWorkerResult(writer, request)
	if !ok || !workerResultPathMatches(request, authorization) {
		if ok {
			writeJobCustodyError(writer, http.StatusBadRequest, "invalid_worker_result")
		}
		return
	}
	handle, err := handler.results.AcceptAuthorized(request.Context(), authorization)
	if err != nil {
		writeJobCustodyOperationError(writer, err)
		return
	}
	record, err := handler.results.Finalize(request.Context(), handle)
	if err != nil {
		writeJobCustodyOperationError(writer, err)
		return
	}
	writeJobCustodyJSON(writer, http.StatusOK, workerResultHTTPStatus(record))
}

func (handler *HTTPHandler) authorizedWorkerResult(
	writer http.ResponseWriter,
	request *http.Request,
) (WorkerResultAuthorization, bool) {
	var input HTTPWorkerResultRequest
	if decodeJobCustodyJSON(request, &input, MaximumJobCustodyControlBytes) != nil {
		writeJobCustodyError(writer, http.StatusBadRequest, "invalid_worker_result_authorization")
		return WorkerResultAuthorization{}, false
	}
	authorization, err := handler.permits.VerifyWorkerResult(
		input.Permit, computequeue.Timestamp(handler.now().UnixMilli()),
	)
	if err != nil {
		writeJobCustodyError(writer, http.StatusUnauthorized, "unauthorized")
		return WorkerResultAuthorization{}, false
	}
	return authorization, true
}

func workerResultPathMatches(request *http.Request, authorization WorkerResultAuthorization) bool {
	claimID, err := uuid.Parse(request.PathValue("claimID"))
	if err != nil || claimID == uuid.Nil || authorization.Payload().Result.ClaimID != claimID {
		return false
	}
	if value := request.PathValue("resultCapsuleID"); value != "" {
		resultCapsuleID := computequeue.JobCapsuleID(value)
		return resultCapsuleID.Validate() == nil &&
			authorization.Payload().Result.ResultCapsuleID == resultCapsuleID
	}
	return true
}

func workerResultHTTPStatus(record ResultRecord) HTTPWorkerResultStatus {
	result := HTTPWorkerResultStatus{
		AssignmentID: record.Header.AssignmentID, ClaimID: record.Header.ClaimID,
		CommittedBytes: record.CommittedBytes, ProtectedObject: record.Header.ProtectedObject,
		ResultCapsuleID: record.Header.ResultCapsuleID,
		ResultSetDigest: record.Header.ResultSetDigest,
		RetentionUntil:  record.Header.RetentionUntil, State: record.State,
		WorkerExecutionReceiptDigest: record.Header.WorkerExecutionReceiptDigest,
	}
	if len(record.CustodyReceiptBytes) != 0 {
		result.CustodyReceipt = bytes.Clone(record.CustodyReceiptBytes)
	}
	if record.DeliveryAcknowledgedAt > 0 {
		value := record.DeliveryAcknowledgedAt
		result.DeliveryAcknowledgedAt = &value
	}
	if record.ReleaseRequestedAt > 0 {
		value := record.ReleaseRequestedAt
		result.ReleaseRequestedAt = &value
	}
	if len(record.ReleaseReceiptBytes) != 0 {
		result.ReleaseReceipt = bytes.Clone(record.ReleaseReceiptBytes)
	}
	if record.ExpiryStartedAt > 0 {
		value := record.ExpiryStartedAt
		result.ExpiryStartedAt = &value
	}
	if len(record.ExpiryReceiptBytes) != 0 {
		result.ExpiryReceipt = bytes.Clone(record.ExpiryReceiptBytes)
	}
	return result
}

func (handler *HTTPHandler) handleResultList(writer http.ResponseWriter, request *http.Request) {
	authorization, ok := handler.authorizedResultRetrieval(writer, request)
	if !ok || !resultRetrievalInputPathMatches(request, authorization) {
		if ok {
			writeJobCustodyError(writer, http.StatusBadRequest, "invalid_result_retrieval")
		}
		return
	}
	records, err := handler.delivery.ListAuthorized(request.Context(), authorization)
	if err != nil {
		writeJobCustodyOperationError(writer, err)
		return
	}
	status := HTTPResultListStatus{Results: make([]HTTPWorkerResultStatus, len(records))}
	for index, record := range records {
		status.Results[index] = workerResultHTTPStatus(record)
	}
	writeJobCustodyJSON(writer, http.StatusOK, status)
}

func (handler *HTTPHandler) handleResultDeliveryChunk(
	writer http.ResponseWriter,
	request *http.Request,
) {
	resultCapsuleID := computequeue.JobCapsuleID(request.PathValue("resultCapsuleID"))
	chunkIndex, indexErr := strconv.ParseInt(request.PathValue("chunkIndex"), 10, 64)
	if resultCapsuleID.Validate() != nil || indexErr != nil || chunkIndex < 0 {
		writeJobCustodyError(writer, http.StatusBadRequest, "invalid_result_retrieval_chunk")
		return
	}
	authorization, ok := handler.authorizedResultRetrieval(writer, request)
	if !ok || !resultRetrievalInputPathMatches(request, authorization) {
		if ok {
			writeJobCustodyError(writer, http.StatusBadRequest, "invalid_result_retrieval_chunk")
		}
		return
	}
	handle, err := handler.delivery.OpenAuthorized(
		request.Context(), authorization, resultCapsuleID,
	)
	if err != nil {
		writeJobCustodyOperationError(writer, err)
		return
	}
	chunk, err := handler.delivery.ReadChunk(handle, chunkIndex)
	if err != nil {
		writeJobCustodyOperationError(writer, err)
		return
	}
	digest := sha256.Sum256(chunk)
	headerBytes, err := computequeue.EncodeCanonical(HTTPResultDeliveryChunkHeader{
		ChunkIndex:            chunkIndex,
		ChunkSHA256:           computequeue.Digest(fmt.Sprintf("%x", digest[:])),
		InputCapsuleID:        authorization.Payload().InputCapsuleID,
		ResultCapsuleID:       resultCapsuleID,
		RetrievalPermitDigest: authorization.PermitDigest(),
		Version:               ResultRetrievalPermitVersion,
	})
	if err != nil {
		writeJobCustodyError(writer, http.StatusInternalServerError, "custody_unavailable")
		return
	}
	wire, err := (carriage.Frame{
		SectionKind: JobCustodyResultDeliveryChunkSectionKind,
		Header:      headerBytes, Payload: chunk,
	}).Encode()
	if err != nil {
		writeJobCustodyError(writer, http.StatusInternalServerError, "custody_unavailable")
		return
	}
	writer.Header().Set("Content-Type", JobCustodyCarriageContentType)
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(wire)
}

func (handler *HTTPHandler) handleResultDeliveryAcknowledgement(
	writer http.ResponseWriter,
	request *http.Request,
) {
	authorization, ok := handler.authorizedResultMutation(
		writer, request, ResultMutationAcknowledgeDelivery,
	)
	if !ok {
		return
	}
	record, err := handler.delivery.AcknowledgeDelivery(request.Context(), authorization)
	if err != nil {
		writeJobCustodyOperationError(writer, err)
		return
	}
	writeJobCustodyJSON(writer, http.StatusOK, workerResultHTTPStatus(record))
}

func (handler *HTTPHandler) handleResultRelease(
	writer http.ResponseWriter,
	request *http.Request,
) {
	authorization, ok := handler.authorizedResultMutation(
		writer, request, ResultMutationReleaseCustody,
	)
	if !ok {
		return
	}
	record, err := handler.delivery.ReleaseResult(request.Context(), authorization)
	if err != nil {
		writeJobCustodyOperationError(writer, err)
		return
	}
	writeJobCustodyJSON(writer, http.StatusOK, workerResultHTTPStatus(record))
}

func (handler *HTTPHandler) authorizedResultMutation(
	writer http.ResponseWriter,
	request *http.Request,
	expectedAction ResultMutationAction,
) (ResultMutationAuthorization, bool) {
	var input HTTPResultMutationRequest
	if decodeJobCustodyJSON(request, &input, MaximumJobCustodyControlBytes) != nil {
		writeJobCustodyError(writer, http.StatusBadRequest, "invalid_result_mutation_authorization")
		return ResultMutationAuthorization{}, false
	}
	authorization, err := handler.permits.VerifyResultMutation(
		input.Permit, computequeue.Timestamp(handler.now().UnixMilli()),
	)
	if err != nil {
		writeJobCustodyError(writer, http.StatusUnauthorized, "unauthorized")
		return ResultMutationAuthorization{}, false
	}
	payload := authorization.Payload()
	if payload.Action != expectedAction ||
		payload.InputCapsuleID != computequeue.JobCapsuleID(request.PathValue("capsuleID")) ||
		payload.ResultCapsuleID != computequeue.JobCapsuleID(request.PathValue("resultCapsuleID")) {
		writeJobCustodyError(writer, http.StatusBadRequest, "invalid_result_mutation")
		return ResultMutationAuthorization{}, false
	}
	return authorization, true
}

func (handler *HTTPHandler) authorizedResultRetrieval(
	writer http.ResponseWriter,
	request *http.Request,
) (ResultRetrievalAuthorization, bool) {
	var input HTTPResultRetrievalRequest
	if decodeJobCustodyJSON(request, &input, MaximumJobCustodyControlBytes) != nil {
		writeJobCustodyError(writer, http.StatusBadRequest, "invalid_result_retrieval_authorization")
		return ResultRetrievalAuthorization{}, false
	}
	authorization, err := handler.permits.VerifyResultRetrieval(
		input.Permit, computequeue.Timestamp(handler.now().UnixMilli()),
	)
	if err != nil {
		writeJobCustodyError(writer, http.StatusUnauthorized, "unauthorized")
		return ResultRetrievalAuthorization{}, false
	}
	return authorization, true
}

func resultRetrievalInputPathMatches(
	request *http.Request,
	authorization ResultRetrievalAuthorization,
) bool {
	inputCapsuleID := computequeue.JobCapsuleID(request.PathValue("capsuleID"))
	return inputCapsuleID.Validate() == nil &&
		inputCapsuleID == authorization.Payload().InputCapsuleID
}

func (handler *HTTPHandler) authorizedWorkerClaim(
	writer http.ResponseWriter,
	request *http.Request,
) (WorkerClaimAuthorization, bool) {
	var input HTTPWorkerClaimRequest
	if decodeJobCustodyJSON(request, &input, MaximumJobCustodyControlBytes) != nil {
		writeJobCustodyError(writer, http.StatusBadRequest, "invalid_worker_authorization")
		return WorkerClaimAuthorization{}, false
	}
	authorization, err := handler.permits.VerifyWorkerClaim(
		input.Permit, computequeue.Timestamp(handler.now().UnixMilli()),
	)
	if err != nil {
		writeJobCustodyError(writer, http.StatusUnauthorized, "unauthorized")
		return WorkerClaimAuthorization{}, false
	}
	return authorization, true
}

func workerClaimHTTPStatus(handle WorkerClaimHandle) HTTPWorkerClaimStatus {
	record, admission := handle.Record(), handle.Admission()
	return HTTPWorkerClaimStatus{
		AssignmentID: admission.Header.AssignmentID, CapsuleID: admission.Header.CapsuleID,
		ClaimID: record.ClaimID, LeaseExpiresAt: record.LeaseExpiresAt,
		ProtectedObject: admission.Header.ProtectedObject, State: record.State,
	}
}

func (handler *HTTPHandler) authorizedStoredAdmission(
	writer http.ResponseWriter,
	request *http.Request,
) (AdmissionHandle, bool) {
	capsuleID, ok := pathJobCapsuleID(request)
	var input HTTPAuthorizationRequest
	if !ok || decodeJobCustodyJSON(request, &input, MaximumJobCustodyControlBytes) != nil {
		writeJobCustodyError(writer, http.StatusBadRequest, "invalid_authorization")
		return AdmissionHandle{}, false
	}
	handle, err := handler.authorizeStored(request.Context(), capsuleID, input.Permit)
	if errors.Is(err, ErrAdmissionPermitAuthentication) {
		writeJobCustodyError(writer, http.StatusUnauthorized, "unauthorized")
		return AdmissionHandle{}, false
	}
	if err != nil {
		writeJobCustodyOperationError(writer, err)
		return AdmissionHandle{}, false
	}
	return handle, true
}

func (handler *HTTPHandler) authorizeStored(
	ctx context.Context,
	capsuleID computequeue.JobCapsuleID,
	permit SignedAdmissionPermit,
) (AdmissionHandle, error) {
	record, err := handler.coordinator.Ledger.LoadAdmission(ctx, capsuleID)
	if err != nil {
		return AdmissionHandle{}, err
	}
	authorization, err := handler.permits.Verify(
		permit, record.EnvelopeBytes, computequeue.Timestamp(handler.now().UnixMilli()),
	)
	if err != nil {
		return AdmissionHandle{}, err
	}
	return handler.coordinator.AdmitAuthorized(ctx, record.EnvelopeBytes, authorization)
}

func pathJobCapsuleID(request *http.Request) (computequeue.JobCapsuleID, bool) {
	value := computequeue.JobCapsuleID(request.PathValue("capsuleID"))
	return value, value.Validate() == nil
}

func admissionHTTPStatus(record AdmissionRecord) HTTPAdmissionStatus {
	result := HTTPAdmissionStatus{
		CommittedBytes:     record.CommittedBytes,
		ProtectedByteCount: record.Header.ProtectedObject.ByteCount,
		State:              record.State,
	}
	if len(record.CustodyReceiptBytes) != 0 {
		result.CustodyReceipt = bytes.Clone(record.CustodyReceiptBytes)
	}
	return result
}

func decodeJobCustodyJSON(request *http.Request, target any, maximum int64) error {
	if request.Header.Get("Content-Type") != "application/json" {
		return ErrInvalid
	}
	body, err := readBoundedJobCustodyBody(request, maximum)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	return nil
}

func readBoundedJobCustodyBody(request *http.Request, maximum int64) ([]byte, error) {
	defer request.Body.Close()
	if maximum <= 0 || request.ContentLength > maximum {
		return nil, ErrInvalid
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maximum+1))
	if err != nil || len(body) == 0 || int64(len(body)) > maximum {
		return nil, ErrInvalid
	}
	return body, nil
}

func writeJobCustodyOperationError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrInvalid):
		writeJobCustodyError(writer, http.StatusBadRequest, "invalid_operation")
	case errors.Is(err, ErrMissing):
		writeJobCustodyError(writer, http.StatusNotFound, "admission_not_found")
	case errors.Is(err, ErrConflict):
		writeJobCustodyError(writer, http.StatusConflict, "conflicting_operation")
	case errors.Is(err, ErrUnavailable):
		writeJobCustodyError(writer, http.StatusServiceUnavailable, "custody_unavailable")
	default:
		writeJobCustodyError(writer, http.StatusInternalServerError, "custody_unavailable")
	}
}

func writeJobCustodyError(writer http.ResponseWriter, status int, code string) {
	writeJobCustodyJSON(writer, status, map[string]string{"code": code})
}

func writeJobCustodyJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
