package storageauthority

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/serviceauthority"
	"github.com/robreuss/FacetsNode/internal/storagecapacity"
)

const MaximumPrivateCapacityEnvelopeBytes = 128 * 1024

type PrivateCapacityEnvelope struct {
	Body  json.RawMessage                    `json:"body"`
	Proof serviceauthority.CapacityPeerProof `json:"proof"`
}

// NewPrivateCapacityEnvelopeAt is the shared service-side construction path.
// Bodies use canonical Go JSON and are committed byte-for-byte by the service
// deployment key. The envelope itself contains no self-authorizing identity.
func NewPrivateCapacityEnvelopeAt(
	signer *serviceauthority.DeploymentSigner,
	binding storagecapacity.ServiceBinding,
	poolID uuid.UUID,
	operation serviceauthority.CapacityPeerOperation,
	operationID uuid.UUID,
	body any,
	now time.Time,
) (PrivateCapacityEnvelope, error) {
	if signer == nil || binding.Validate() != nil || poolID == uuid.Nil || operationID == uuid.Nil || body == nil {
		return PrivateCapacityEnvelope{}, ErrInvalid
	}
	raw, err := json.Marshal(body)
	if err != nil || len(raw) > serviceauthority.MaximumCapacityPeerBodyBytes {
		return PrivateCapacityEnvelope{}, ErrInvalid
	}
	request, err := serviceauthority.NewCapacityPeerRequest(operation, operationID, poolID, raw)
	if err != nil {
		return PrivateCapacityEnvelope{}, ErrInvalid
	}
	proof, err := signer.SignCapacityPeerRequestAt(binding, request, raw, now)
	if err != nil {
		return PrivateCapacityEnvelope{}, ErrInvalid
	}
	return PrivateCapacityEnvelope{Body: raw, Proof: proof}, nil
}

type PrivateReserveRequest struct {
	ProtocolVersion       int       `json:"protocolVersion"`
	ReservationID         uuid.UUID `json:"reservationID"`
	OperationID           uuid.UUID `json:"operationID"`
	ByteCeiling           int64     `json:"byteCeiling"`
	IssuedAtMilliseconds  int64     `json:"issuedAtMilliseconds"`
	ExpiresAtMilliseconds int64     `json:"expiresAtMilliseconds"`
	BearerToken           string    `json:"bearerToken"`
}

type PrivateRecheckRequest struct {
	ProtocolVersion        int       `json:"protocolVersion"`
	ReservationID          uuid.UUID `json:"reservationID"`
	OperationID            uuid.UUID `json:"operationID"`
	ExpectedRevision       uint64    `json:"expectedRevision"`
	ObservedAtMilliseconds int64     `json:"observedAtMilliseconds"`
	BearerToken            string    `json:"bearerToken"`
}

type PrivateDecisionRequest struct {
	ProtocolVersion        int                                     `json:"protocolVersion"`
	ReservationID          uuid.UUID                               `json:"reservationID"`
	OperationID            uuid.UUID                               `json:"operationID"`
	ExpectedRevision       uint64                                  `json:"expectedRevision"`
	Kind                   storagecapacity.ReservationDecisionKind `json:"kind"`
	ObservedAtMilliseconds int64                                   `json:"observedAtMilliseconds"`
	BearerToken            string                                  `json:"bearerToken"`
}

type PrivateReservationRequest struct {
	ProtocolVersion int       `json:"protocolVersion"`
	ReservationID   uuid.UUID `json:"reservationID"`
	OperationID     uuid.UUID `json:"operationID"`
}

type PrivateReadinessRequest struct {
	ProtocolVersion int       `json:"protocolVersion"`
	OperationID     uuid.UUID `json:"operationID"`
}

// PrivateReservationView omits the persisted token digest, physical pool, and
// service registry details. The authenticated caller already owns the bearer
// it supplied and needs only lifecycle state for reconciliation.
type PrivateReservationView struct {
	ProtocolVersion       int                              `json:"protocolVersion"`
	ReservationID         uuid.UUID                        `json:"reservationID"`
	ByteCeiling           int64                            `json:"byteCeiling"`
	ExpiresAtMilliseconds int64                            `json:"expiresAtMilliseconds"`
	State                 storagecapacity.ReservationState `json:"state"`
	Revision              uint64                           `json:"revision"`
	UpdatedAtMilliseconds int64                            `json:"updatedAtMilliseconds"`
}

type PrivateCapacityError struct {
	Code                   string                          `json:"code"`
	State                  *storagecapacity.ReadinessState `json:"state,omitempty"`
	RetryAfterMilliseconds *int64                          `json:"retryAfterMilliseconds,omitempty"`
}

type capacityService interface {
	Reserve(context.Context, storagecapacity.ReservationRequest, string) (storagecapacity.ReservationRecord, error)
	Recheck(context.Context, uuid.UUID, uint64, string, int64) error
	Decide(context.Context, storagecapacity.ReservationDecision) (storagecapacity.ReservationRecord, error)
	Reservation(context.Context, uuid.UUID) (storagecapacity.ReservationRecord, error)
	CoarseReadiness(context.Context) (storagecapacity.CoarseReadinessSnapshot, error)
}

// PrivateHTTPHandler authenticates every exact request body with an
// owner-provisioned service deployment key before deriving a BoundService.
// No service identity header, body field, bearer token, or network address is
// trusted as identity. Network exposure and TLS remain deployment concerns;
// production must expose this handler only on the private service plane.
type PrivateHTTPHandler struct {
	ledger  *Ledger
	peers   *CapacityPeerRegistry
	now     func() time.Time
	service func(storagecapacity.ServiceBinding) (capacityService, error)
	poolID  uuid.UUID
}

func NewPrivateHTTPHandler(
	ledger *Ledger,
	peers *CapacityPeerRegistry,
) (*PrivateHTTPHandler, error) {
	if ledger == nil || ledger.pool == nil || ledger.poolID == uuid.Nil || peers == nil {
		return nil, ErrInvalid
	}
	return &PrivateHTTPHandler{
		ledger: ledger, peers: peers, now: time.Now, poolID: ledger.poolID,
		service: func(binding storagecapacity.ServiceBinding) (capacityService, error) {
			return BindService(ledger, binding)
		},
	}, nil
}

func (handler *PrivateHTTPHandler) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/reservations/reserve", handler.handleReserve)
	mux.HandleFunc("POST /v1/reservations/recheck", handler.handleRecheck)
	mux.HandleFunc("POST /v1/reservations/decide", handler.handleDecide)
	mux.HandleFunc("POST /v1/reservations/get", handler.handleReservation)
	mux.HandleFunc("POST /v1/readiness/query", handler.handleReadiness)
	return mux
}

func (handler *PrivateHTTPHandler) handleReserve(writer http.ResponseWriter, request *http.Request) {
	var body PrivateReserveRequest
	service, binding, ok := handler.authenticate(writer, request, serviceauthority.CapacityReserve, &body, func() uuid.UUID { return body.OperationID })
	if !ok {
		return
	}
	record, err := service.Reserve(request.Context(), storagecapacity.ReservationRequest{
		ProtocolVersion: body.ProtocolVersion, PoolID: handler.poolID,
		ReservationID: body.ReservationID, OperationID: body.OperationID,
		Service: binding, ByteCeiling: body.ByteCeiling,
		IssuedAtMilliseconds:  body.IssuedAtMilliseconds,
		ExpiresAtMilliseconds: body.ExpiresAtMilliseconds,
	}, body.BearerToken)
	if err != nil {
		handler.writeError(writer, err)
		return
	}
	writePrivateCapacityJSON(writer, http.StatusCreated, privateReservationView(record))
}

func (handler *PrivateHTTPHandler) handleRecheck(writer http.ResponseWriter, request *http.Request) {
	var body PrivateRecheckRequest
	service, _, ok := handler.authenticate(writer, request, serviceauthority.CapacityRecheck, &body, func() uuid.UUID { return body.OperationID })
	if !ok {
		return
	}
	if body.ProtocolVersion != storagecapacity.AuthorityProtocolVersion || body.ReservationID == uuid.Nil ||
		body.ExpectedRevision == 0 || body.ObservedAtMilliseconds <= 0 {
		handler.writeError(writer, ErrInvalid)
		return
	}
	if err := service.Recheck(request.Context(), body.ReservationID, body.ExpectedRevision, body.BearerToken, body.ObservedAtMilliseconds); err != nil {
		handler.writeError(writer, err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (handler *PrivateHTTPHandler) handleDecide(writer http.ResponseWriter, request *http.Request) {
	var body PrivateDecisionRequest
	service, _, ok := handler.authenticate(writer, request, serviceauthority.CapacityDecide, &body, func() uuid.UUID { return body.OperationID })
	if !ok {
		return
	}
	record, err := service.Decide(request.Context(), storagecapacity.ReservationDecision{
		ProtocolVersion: body.ProtocolVersion, ReservationID: body.ReservationID,
		OperationID: body.OperationID, ExpectedRevision: body.ExpectedRevision,
		Kind: body.Kind, ObservedAtMilliseconds: body.ObservedAtMilliseconds,
		BearerToken: body.BearerToken,
	})
	if err != nil {
		handler.writeError(writer, err)
		return
	}
	writePrivateCapacityJSON(writer, http.StatusOK, privateReservationView(record))
}

func (handler *PrivateHTTPHandler) handleReservation(writer http.ResponseWriter, request *http.Request) {
	var body PrivateReservationRequest
	service, _, ok := handler.authenticate(writer, request, serviceauthority.CapacityRead, &body, func() uuid.UUID { return body.OperationID })
	if !ok {
		return
	}
	if body.ProtocolVersion != storagecapacity.AuthorityProtocolVersion || body.ReservationID == uuid.Nil {
		handler.writeError(writer, ErrInvalid)
		return
	}
	record, err := service.Reservation(request.Context(), body.ReservationID)
	if err != nil {
		handler.writeError(writer, err)
		return
	}
	writePrivateCapacityJSON(writer, http.StatusOK, privateReservationView(record))
}

func (handler *PrivateHTTPHandler) handleReadiness(writer http.ResponseWriter, request *http.Request) {
	var body PrivateReadinessRequest
	service, _, ok := handler.authenticate(writer, request, serviceauthority.CapacityReadiness, &body, func() uuid.UUID { return body.OperationID })
	if !ok {
		return
	}
	if body.ProtocolVersion != storagecapacity.AuthorityProtocolVersion {
		handler.writeError(writer, ErrInvalid)
		return
	}
	readiness, err := service.CoarseReadiness(request.Context())
	if err != nil {
		handler.writeError(writer, err)
		return
	}
	writePrivateCapacityJSON(writer, http.StatusOK, readiness)
}

func (handler *PrivateHTTPHandler) authenticate(
	writer http.ResponseWriter,
	request *http.Request,
	operation serviceauthority.CapacityPeerOperation,
	body any,
	operationID func() uuid.UUID,
) (capacityService, storagecapacity.ServiceBinding, bool) {
	if handler == nil || handler.peers == nil || handler.now == nil || handler.service == nil || request == nil {
		writePrivateCapacityError(writer, http.StatusServiceUnavailable, PrivateCapacityError{Code: "authority_unavailable"})
		return nil, storagecapacity.ServiceBinding{}, false
	}
	envelope, err := decodePrivateCapacityEnvelope(request)
	if err != nil || decodeCanonicalPrivateBody(envelope.Body, body) != nil {
		writePrivateCapacityError(writer, http.StatusBadRequest, PrivateCapacityError{Code: "invalid_request"})
		return nil, storagecapacity.ServiceBinding{}, false
	}
	expected, err := serviceauthority.NewCapacityPeerRequest(operation, operationID(), handler.poolID, envelope.Body)
	if err != nil {
		writePrivateCapacityError(writer, http.StatusBadRequest, PrivateCapacityError{Code: "invalid_request"})
		return nil, storagecapacity.ServiceBinding{}, false
	}
	verified, err := handler.peers.VerifyAt(envelope.Proof, expected, envelope.Body, handler.now())
	if err != nil {
		writePrivateCapacityError(writer, http.StatusForbidden, PrivateCapacityError{Code: "service_authority_rejected"})
		return nil, storagecapacity.ServiceBinding{}, false
	}
	service, err := handler.service(verified.Service())
	if err != nil {
		writePrivateCapacityError(writer, http.StatusServiceUnavailable, PrivateCapacityError{Code: "authority_unavailable"})
		return nil, storagecapacity.ServiceBinding{}, false
	}
	return service, verified.Service(), true
}

func decodePrivateCapacityEnvelope(request *http.Request) (PrivateCapacityEnvelope, error) {
	defer request.Body.Close()
	reader := io.LimitReader(request.Body, MaximumPrivateCapacityEnvelopeBytes+1)
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	var envelope PrivateCapacityEnvelope
	if err := decoder.Decode(&envelope); err != nil || len(envelope.Body) == 0 ||
		len(envelope.Body) > serviceauthority.MaximumCapacityPeerBodyBytes {
		return PrivateCapacityEnvelope{}, ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return PrivateCapacityEnvelope{}, ErrInvalid
	}
	return envelope, nil
}

func decodeCanonicalPrivateBody(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(canonical, raw) {
		return ErrInvalid
	}
	return nil
}

func privateReservationView(record storagecapacity.ReservationRecord) PrivateReservationView {
	return PrivateReservationView{
		ProtocolVersion: record.ProtocolVersion, ReservationID: record.ReservationID,
		ByteCeiling: record.ByteCeiling, ExpiresAtMilliseconds: record.ExpiresAtMilliseconds,
		State: record.State, Revision: record.Revision,
		UpdatedAtMilliseconds: record.UpdatedAtMilliseconds,
	}
}

func (handler *PrivateHTTPHandler) writeError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, storagecapacity.ErrPressure):
		state := storagecapacity.ReadinessStoragePressure
		retry := storagecapacity.DefaultReadinessRetryAfterMilliseconds
		writePrivateCapacityError(writer, http.StatusInsufficientStorage, PrivateCapacityError{Code: "storage_pressure", State: &state, RetryAfterMilliseconds: &retry})
	case errors.Is(err, storagecapacity.ErrUnavailable):
		state := storagecapacity.ReadinessCapacityUnavailable
		retry := storagecapacity.DefaultReadinessRetryAfterMilliseconds
		writePrivateCapacityError(writer, http.StatusInsufficientStorage, PrivateCapacityError{Code: "capacity_unavailable", State: &state, RetryAfterMilliseconds: &retry})
	case errors.Is(err, ErrConflict):
		writePrivateCapacityError(writer, http.StatusConflict, PrivateCapacityError{Code: "reservation_conflict"})
	case errors.Is(err, ErrRejected):
		writePrivateCapacityError(writer, http.StatusConflict, PrivateCapacityError{Code: "reservation_rejected"})
	case errors.Is(err, ErrInvalid):
		writePrivateCapacityError(writer, http.StatusBadRequest, PrivateCapacityError{Code: "invalid_request"})
	default:
		writePrivateCapacityError(writer, http.StatusServiceUnavailable, PrivateCapacityError{Code: "authority_unavailable"})
	}
}

func writePrivateCapacityJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func writePrivateCapacityError(writer http.ResponseWriter, status int, value PrivateCapacityError) {
	writePrivateCapacityJSON(writer, status, value)
}
