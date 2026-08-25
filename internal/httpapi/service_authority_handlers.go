package httpapi

import (
	"context"
	"net/http"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/serviceauthority"
	"github.com/robreuss/FacetsNode/internal/traffic"
)

const (
	maximumDeploymentProofRequestByteCount          = 4 * 1024
	maximumBootstrapDeploymentProofRequestByteCount = 256 * 1024
)

type bulkGrantContextKey struct{}
type serviceAuthorityBindingContextKey struct{}

type bootstrapDeploymentProofInput struct {
	DeploymentOffer serviceauthority.DeploymentOffer       `json:"deploymentOffer"`
	Request         serviceauthority.BootstrapProofRequest `json:"request"`
}

func (s *Server) handleServiceBootstrapDeploymentProof(
	writer http.ResponseWriter,
	request *http.Request,
) {
	var input bootstrapDeploymentProofInput
	if err := decodeJSONWithLimit(
		writer,
		request,
		&input,
		maximumBootstrapDeploymentProofRequestByteCount,
		func(string) error { return serviceauthority.ErrInvalid },
	); err != nil || input.Request.Validate(
		input.DeploymentOffer,
		s.deploymentSigner.DeploymentID(),
	) != nil {
		writeServiceAuthorityError(writer, http.StatusBadRequest)
		return
	}
	if input.Request.Scope.Kind != s.serviceAuthorityScopeKind {
		writeServiceAuthorityError(writer, http.StatusConflict)
		return
	}
	proof, err := s.deploymentSigner.SignBootstrapProof(
		input.Request,
		input.DeploymentOffer,
		s.now(),
	)
	if err != nil {
		writeServiceAuthorityError(writer, http.StatusBadRequest)
		return
	}
	writeJSON(writer, http.StatusOK, proof)
}

func (s *Server) handleServiceDeploymentProof(
	writer http.ResponseWriter,
	request *http.Request,
) {
	var proofRequest serviceauthority.ProofRequest
	if err := decodeJSONWithLimit(
		writer,
		request,
		&proofRequest,
		maximumDeploymentProofRequestByteCount,
		func(string) error { return serviceauthority.ErrInvalid },
	); err != nil || proofRequest.Validate(s.deploymentSigner.DeploymentID()) != nil {
		writeServiceAuthorityError(writer, http.StatusBadRequest)
		return
	}
	if proofRequest.Scope.Kind != s.serviceAuthorityScopeKind {
		writeServiceAuthorityError(writer, http.StatusConflict)
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
	if s.serviceAuthorityBindings.Authorize(binding) != nil {
		writeServiceAuthorityError(writer, http.StatusConflict)
		return
	}
	proof, err := s.deploymentSigner.SignProof(proofRequest, s.now())
	if err != nil {
		writeServiceAuthorityError(writer, http.StatusBadRequest)
		return
	}
	writeJSON(writer, http.StatusOK, proof)
}

func (s *Server) serviceAuthorityBindingHandler(
	trafficClass serviceauthority.TrafficClass,
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		binding, err := serviceauthority.ParseRequestBinding(
			request.Header,
			s.deploymentSigner.DeploymentID(),
			trafficClass,
		)
		if err != nil ||
			s.serviceAuthorityBindings.AuthorizeRequest(binding, request.Method) != nil {
			writeServiceAuthorityError(writer, http.StatusConflict)
			return
		}
		if binding.Scope.Kind != s.serviceAuthorityScopeKind ||
			requestScopeMatchesBinding(request, binding.Scope) != nil {
			writeServiceAuthorityError(writer, http.StatusConflict)
			return
		}
		if trafficClass != serviceauthority.TrafficBulk && hasBulkTransferHeaders(request.Header) {
			writeServiceAuthorityError(writer, http.StatusConflict)
			return
		}
		if trafficClass == serviceauthority.TrafficBulk {
			grant, err := s.serviceAuthorityBindings.AuthorizeBulkTransfer(
				binding,
				request.Header,
				s.now(),
				s.deploymentSigner,
			)
			if err != nil {
				writeServiceAuthorityError(writer, http.StatusConflict)
				return
			}
			request = request.WithContext(context.WithValue(
				request.Context(),
				bulkGrantContextKey{},
				grant,
			))
		}
		request = request.WithContext(context.WithValue(
			request.Context(),
			serviceAuthorityBindingContextKey{},
			binding,
		))
		next.ServeHTTP(writer, request)
	})
}

func requiredServiceAuthorityBinding(
	request *http.Request,
) (serviceauthority.RequestBinding, error) {
	binding, ok := request.Context().Value(serviceAuthorityBindingContextKey{}).(serviceauthority.RequestBinding)
	if !ok {
		return serviceauthority.RequestBinding{}, serviceauthority.ErrInvalid
	}
	return binding, nil
}

func hasBulkTransferHeaders(header http.Header) bool {
	return len(header.Values(serviceauthority.HeaderBulkTransferGrant)) > 0 ||
		len(header.Values(serviceauthority.HeaderBulkResourceID)) > 0 ||
		len(header.Values(serviceauthority.HeaderBulkDirection)) > 0
}

func requiredBulkGrant(request *http.Request) (serviceauthority.BulkGrantPayload, error) {
	grant, ok := request.Context().Value(bulkGrantContextKey{}).(serviceauthority.BulkGrantPayload)
	if !ok {
		return serviceauthority.BulkGrantPayload{}, serviceauthority.ErrInvalid
	}
	return grant, nil
}

func (s *Server) requireBulkOperation(
	writer http.ResponseWriter,
	request *http.Request,
	resourceID string,
	direction serviceauthority.BulkDirection,
	maximumObservedByteCount int64,
) bool {
	if s.deploymentSigner == nil || s.serviceAuthorityBindings == nil {
		return true
	}
	grant, err := requiredBulkGrant(request)
	if err != nil || grant.ResourceID != resourceID || grant.Direction != direction ||
		maximumObservedByteCount < 0 || maximumObservedByteCount > grant.MaximumByteCount {
		writeServiceAuthorityError(writer, http.StatusConflict)
		return false
	}
	return true
}

// Resource-bearing routes use the existing invariant that a Device Sync
// relay tenant ID is its principal ID and a Shared Spaces relay tenant ID is
// its Space ID. Admission/rendezvous routes without one of these path values
// are still constrained to the configured service kind and an exact current
// scope binding; their capability handlers enforce the route/admission ID.
func requestScopeMatchesBinding(request *http.Request, scope serviceauthority.Scope) error {
	var resourceID uuid.UUID
	found := false
	for _, name := range []string{"principalID", "spaceID", "tenantID"} {
		value := request.PathValue(name)
		if value == "" {
			continue
		}
		parsed, err := uuid.Parse(value)
		if err != nil || parsed == uuid.Nil || (found && parsed != resourceID) {
			return serviceauthority.ErrInvalid
		}
		resourceID = parsed
		found = true
	}
	if found && resourceID != scope.ScopeID {
		return serviceauthority.ErrInvalid
	}
	return nil
}

func serviceAuthorityTrafficClass(
	surface traffic.Surface,
) serviceauthority.TrafficClass {
	switch surface {
	case traffic.SurfaceRelayMessage:
		return serviceauthority.TrafficMessage
	case traffic.SurfaceStorage:
		return serviceauthority.TrafficBulk
	default:
		return serviceauthority.TrafficControl
	}
}

func writeServiceAuthorityError(writer http.ResponseWriter, status int) {
	writeJSON(writer, status, map[string]string{
		"code":    "stale_or_invalid_service_authority",
		"message": "The request is not bound to this deployment's current Facets authority.",
	})
}
