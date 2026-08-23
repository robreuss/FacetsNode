package httpapi

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/serviceauthority"
	"github.com/robreuss/FacetsNode/internal/traffic"
)

const maximumDeploymentProofRequestByteCount = 4 * 1024

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
		if err != nil || s.serviceAuthorityBindings.Authorize(binding) != nil {
			writeServiceAuthorityError(writer, http.StatusConflict)
			return
		}
		if binding.Scope.Kind != s.serviceAuthorityScopeKind ||
			requestScopeMatchesBinding(request, binding.Scope) != nil {
			writeServiceAuthorityError(writer, http.StatusConflict)
			return
		}
		next.ServeHTTP(writer, request)
	})
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
