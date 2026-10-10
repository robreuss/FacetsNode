package jobcustody

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/robreuss/FacetsNode/internal/carriage"
	"github.com/robreuss/FacetsNode/internal/computequeue"
	"github.com/robreuss/FacetsNode/internal/traffic"
)

const (
	JobCustodyChunkSectionKind    byte = 65
	MaximumJobCustodyControlBytes      = 160 * 1024
	JobCustodyCarriageContentType      = "application/vnd.facets.carriage"
)

type HTTPAdmissionRequest struct {
	AdmissionEnvelope []byte                `json:"admissionEnvelope"`
	Permit            SignedAdmissionPermit `json:"permit"`
}

type HTTPAuthorizationRequest struct {
	Permit SignedAdmissionPermit `json:"permit"`
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
	coordinator *Coordinator
	permits     *AdmissionPermitVerifier
	now         func() time.Time
	readiness   func(context.Context) error
	management  jobCustodyTrafficControl
	storage     jobCustodyTrafficControl
}

type jobCustodyTrafficControl struct {
	limiter    *traffic.Limiter
	concurrent chan struct{}
}

func NewHTTPHandler(
	coordinator *Coordinator,
	permits *AdmissionPermitVerifier,
	limits traffic.Limits,
	readiness func(context.Context) error,
) (*HTTPHandler, error) {
	if coordinator == nil || coordinator.validate() != nil || permits == nil ||
		traffic.ValidateLimits(limits) != nil || readiness == nil {
		return nil, ErrInvalid
	}
	return &HTTPHandler{
		coordinator: coordinator,
		permits:     permits,
		now:         time.Now,
		readiness:   readiness,
		management:  newJobCustodyTrafficControl(limits[traffic.SurfaceManagement]),
		storage:     newJobCustodyTrafficControl(limits[traffic.SurfaceStorage]),
	}, nil
}

func (handler *HTTPHandler) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /livez", handler.limited(handler.management, http.HandlerFunc(handler.handleLive)))
	mux.Handle("GET /readyz", handler.limited(handler.management, http.HandlerFunc(handler.handleReady)))
	mux.Handle("POST /v1/job-custody/admissions", handler.limited(handler.management, http.HandlerFunc(handler.handleAdmission)))
	mux.Handle("POST /v1/job-custody/admissions/{capsuleID}/status", handler.limited(handler.management, http.HandlerFunc(handler.handleStatus)))
	mux.Handle("PUT /v1/job-custody/admissions/{capsuleID}/chunks/{chunkIndex}", handler.limited(handler.storage, http.HandlerFunc(handler.handleChunk)))
	mux.Handle("POST /v1/job-custody/admissions/{capsuleID}/finalize", handler.limited(handler.management, http.HandlerFunc(handler.handleFinalize)))
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
