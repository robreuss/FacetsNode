package computepool

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

const maximumComputePoolRequestBytes = 64 * 1_024

type HTTPHandler struct {
	store               Store
	deploymentSigner    *serviceauthority.DeploymentSigner
	authorityBindings   *serviceauthority.BindingRegistry
	operatorTokenDigest [32]byte
	now                 func() time.Time
}

func NewHTTPHandler(
	store Store,
	deploymentSigner *serviceauthority.DeploymentSigner,
	authorityBindings *serviceauthority.BindingRegistry,
	operatorToken string,
) (*HTTPHandler, error) {
	decodedToken, err := base64.RawURLEncoding.Strict().DecodeString(operatorToken)
	if store == nil || deploymentSigner == nil || authorityBindings == nil ||
		err != nil || len(decodedToken) != 32 ||
		base64.RawURLEncoding.EncodeToString(decodedToken) != operatorToken {
		return nil, ErrInvalid
	}
	return &HTTPHandler{
		store: store, deploymentSigner: deploymentSigner,
		authorityBindings: authorityBindings,
		operatorTokenDigest: sha256.Sum256(append(
			[]byte("facets-compute-pool-operator-v1\x00"),
			decodedToken...,
		)),
		now: time.Now,
	}, nil
}

func (handler *HTTPHandler) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /livez", handler.handleLive)
	mux.HandleFunc("GET /readyz", handler.handleReady)
	mux.HandleFunc("POST /v1/service-deployment/proof", handler.handleDeploymentProof)
	mux.HandleFunc(
		"GET /v1/compute-pools/{poolID}/status",
		handler.handlePoolStatus,
	)
	return mux
}

func (handler *HTTPHandler) handleLive(writer http.ResponseWriter, _ *http.Request) {
	writeComputePoolJSON(writer, http.StatusOK, map[string]string{"status": "live"})
}

func (handler *HTTPHandler) handleReady(writer http.ResponseWriter, _ *http.Request) {
	writeComputePoolJSON(writer, http.StatusOK, map[string]string{"status": "ready"})
}

func (handler *HTTPHandler) handleDeploymentProof(
	writer http.ResponseWriter,
	request *http.Request,
) {
	var proofRequest serviceauthority.ProofRequest
	if decodeComputePoolJSON(request, &proofRequest) != nil ||
		proofRequest.Validate(handler.deploymentSigner.DeploymentID()) != nil {
		writeComputePoolError(writer, http.StatusBadRequest, "invalid_deployment_proof")
		return
	}
	if proofRequest.Scope.Kind != serviceauthority.ScopeComputePool {
		writeComputePoolError(writer, http.StatusConflict, "stale_or_invalid_service_authority")
		return
	}
	binding := serviceauthority.RequestBinding{
		Scope: proofRequest.Scope, AuthorityRevision: proofRequest.AuthorityRevision,
		AuthorityDigest: proofRequest.AuthorityManifestDigest,
		DeploymentID:    proofRequest.DeploymentID, RouteID: proofRequest.RouteID,
		TrafficClass: proofRequest.TrafficClass,
	}
	now := handler.now()
	if handler.authorityBindings.AuthorizeAt(binding, now) != nil {
		writeComputePoolError(writer, http.StatusConflict, "stale_or_invalid_service_authority")
		return
	}
	proof, err := handler.deploymentSigner.SignProof(proofRequest, now)
	if err != nil {
		writeComputePoolError(writer, http.StatusBadRequest, "invalid_deployment_proof")
		return
	}
	writeComputePoolJSON(writer, http.StatusOK, proof)
}

func (handler *HTTPHandler) handlePoolStatus(
	writer http.ResponseWriter,
	request *http.Request,
) {
	poolID, err := uuid.Parse(request.PathValue("poolID"))
	if err != nil || poolID == uuid.Nil {
		writeComputePoolError(writer, http.StatusBadRequest, "invalid_compute_pool")
		return
	}
	binding, err := serviceauthority.ParseRequestBinding(
		request.Header,
		handler.deploymentSigner.DeploymentID(),
		serviceauthority.TrafficControl,
	)
	if err != nil || binding.Scope.Kind != serviceauthority.ScopeComputePool ||
		binding.Scope.ScopeID != poolID ||
		handler.authorityBindings.AuthorizeRequestAt(
			binding,
			serviceauthority.RequestRead,
			handler.now(),
		) != nil {
		writeComputePoolError(writer, http.StatusConflict, "stale_or_invalid_service_authority")
		return
	}
	if !handler.authorizeOperator(request) {
		writeComputePoolError(writer, http.StatusUnauthorized, "unauthorized")
		return
	}
	status, err := handler.store.GetPoolStatus(request.Context(), poolID)
	if errors.Is(err, ErrNotFound) {
		writeComputePoolError(writer, http.StatusNotFound, "compute_pool_not_found")
		return
	}
	if err != nil {
		writeComputePoolError(writer, http.StatusInternalServerError, "compute_pool_unavailable")
		return
	}
	writeComputePoolJSON(writer, http.StatusOK, status)
}

func (handler *HTTPHandler) authorizeOperator(request *http.Request) bool {
	const prefix = "Bearer "
	header := request.Header.Get("Authorization")
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(
		strings.TrimPrefix(header, prefix),
	)
	if err != nil || len(decoded) != 32 {
		return false
	}
	digest := sha256.Sum256(append(
		[]byte("facets-compute-pool-operator-v1\x00"),
		decoded...,
	))
	return subtle.ConstantTimeCompare(digest[:], handler.operatorTokenDigest[:]) == 1
}

func decodeComputePoolJSON(request *http.Request, target any) error {
	defer request.Body.Close()
	reader := io.LimitReader(request.Body, maximumComputePoolRequestBytes+1)
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	return nil
}

func writeComputePoolJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func writeComputePoolError(writer http.ResponseWriter, status int, code string) {
	writeComputePoolJSON(writer, status, map[string]string{"code": code})
}
