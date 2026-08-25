package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/devicesync"
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
	now := s.now()
	if s.serviceAuthorityBindings.AuthorizeAt(binding, now) != nil {
		writeServiceAuthorityError(writer, http.StatusConflict)
		return
	}
	proof, err := s.deploymentSigner.SignProof(proofRequest, now)
	if err != nil {
		writeServiceAuthorityError(writer, http.StatusBadRequest)
		return
	}
	writeJSON(writer, http.StatusOK, proof)
}

func (s *Server) serviceAuthorityBindingHandler(
	trafficClass serviceauthority.TrafficClass,
	access serviceauthority.RequestAccess,
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		now := s.now()
		binding, err := serviceauthority.ParseRequestBinding(
			request.Header,
			s.deploymentSigner.DeploymentID(),
			trafficClass,
		)
		if err != nil ||
			s.serviceAuthorityBindings.AuthorizeRequestAt(binding, access, now) != nil {
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
		var mutationLease *serviceauthority.ScopeLease
		var durableMutationFence devicesync.MutationFenceLease
		if access == serviceauthority.RequestMutation {
			mutationLease, err = s.serviceAuthorityBindings.AcquireMutationLease(
				request.Context(),
				binding.Scope,
			)
			if err != nil {
				writeServiceAuthorityError(writer, http.StatusConflict)
				return
			}
			defer mutationLease.Release()
			// A migration drain may have staged a fence while this request waited.
			// Revalidate only after admission, then retain the lease through the
			// complete handler, including any filesystem callback it invokes.
			now = s.now()
			authorization, authorizeErr :=
				s.serviceAuthorityBindings.AuthorizeMutationAt(binding, now)
			if authorizeErr != nil {
				writeServiceAuthorityError(writer, http.StatusConflict)
				return
			}
			if binding.Scope.Kind == serviceauthority.ScopeDeviceSync &&
				s.deviceSyncMutationFenceStore != nil {
				durableMutationFence, err =
					s.deviceSyncMutationFenceStore.AcquireDeviceSyncMutationFence(
						request.Context(), authorization,
					)
				if err != nil {
					if errors.Is(err, serviceauthority.ErrInvalid) ||
						errors.Is(err, devicesync.ErrScopeWriteFenced) {
						writeServiceAuthorityError(writer, http.StatusConflict)
					} else {
						writeDeviceSyncAuthorityUnavailable(writer)
					}
					return
				}
				defer func() {
					if releaseErr := durableMutationFence.Release(
						context.WithoutCancel(request.Context()),
					); releaseErr != nil && s.logger != nil {
						s.logger.Error(
							"Device Sync durable mutation fence release failed",
							"error", releaseErr,
						)
					}
				}()
			}
		}
		if trafficClass == serviceauthority.TrafficBulk {
			grant, err := s.serviceAuthorityBindings.AuthorizeBulkTransfer(
				binding,
				access,
				request.Method,
				request.Header,
				now,
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

// executeShortBoundMutation applies the normal mutation boundary around one
// short operation and releases it before returning. Long-poll handlers use it
// for each actual store access so their idle wait never retains a PostgreSQL
// fence connection or blocks unrelated writes.
func (s *Server) executeShortBoundMutation(
	writer http.ResponseWriter,
	request *http.Request,
	operation func(context.Context) error,
) bool {
	if writer == nil || request == nil || operation == nil {
		return false
	}
	if s.deploymentSigner == nil && s.serviceAuthorityBindings == nil {
		if err := operation(request.Context()); err != nil {
			s.writeError(writer, err)
			return false
		}
		return true
	}
	if s.deploymentSigner == nil || s.serviceAuthorityBindings == nil {
		writeServiceAuthorityError(writer, http.StatusConflict)
		return false
	}
	binding, err := requiredServiceAuthorityBinding(request)
	if err != nil || binding.Scope.Kind != s.serviceAuthorityScopeKind ||
		requestScopeMatchesBinding(request, binding.Scope) != nil {
		writeServiceAuthorityError(writer, http.StatusConflict)
		return false
	}
	processLease, err := s.serviceAuthorityBindings.AcquireMutationLease(
		request.Context(), binding.Scope,
	)
	if err != nil {
		writeServiceAuthorityError(writer, http.StatusConflict)
		return false
	}
	defer processLease.Release()

	authorization, err := s.serviceAuthorityBindings.AuthorizeMutationAt(
		binding, s.now(),
	)
	if err != nil {
		writeServiceAuthorityError(writer, http.StatusConflict)
		return false
	}
	var durableLease devicesync.MutationFenceLease
	if binding.Scope.Kind == serviceauthority.ScopeDeviceSync {
		if s.deviceSyncMutationFenceStore == nil {
			writeDeviceSyncAuthorityUnavailable(writer)
			return false
		}
		durableLease, err =
			s.deviceSyncMutationFenceStore.AcquireDeviceSyncMutationFence(
				request.Context(), authorization,
			)
		if err != nil {
			if errors.Is(err, serviceauthority.ErrInvalid) ||
				errors.Is(err, devicesync.ErrScopeWriteFenced) {
				writeServiceAuthorityError(writer, http.StatusConflict)
			} else {
				writeDeviceSyncAuthorityUnavailable(writer)
			}
			return false
		}
	}

	operationErr := operation(request.Context())
	if durableLease != nil {
		if releaseErr := durableLease.Release(
			context.WithoutCancel(request.Context()),
		); releaseErr != nil {
			if s.logger != nil {
				s.logger.Error(
					"Device Sync short mutation fence release failed",
					"error", releaseErr,
				)
			}
			writeDeviceSyncAuthorityUnavailable(writer)
			return false
		}
	}
	if operationErr != nil {
		s.writeError(writer, operationErr)
		return false
	}
	return true
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

// Operator provisioning routes do not carry their new logical scope in the
// path. Once authority binding is enabled, the decoded resource IDs must still
// match the scope whose mutation lease protects the handler.
func (s *Server) requestBodyScopeMatchesBinding(
	request *http.Request,
	resourceIDs ...uuid.UUID,
) error {
	if s.deploymentSigner == nil && s.serviceAuthorityBindings == nil {
		return nil
	}
	if s.deploymentSigner == nil || s.serviceAuthorityBindings == nil {
		return serviceauthority.ErrInvalid
	}
	binding, err := requiredServiceAuthorityBinding(request)
	if err != nil || len(resourceIDs) == 0 {
		return serviceauthority.ErrInvalid
	}
	for _, resourceID := range resourceIDs {
		if resourceID == uuid.Nil || resourceID != binding.Scope.ScopeID {
			return serviceauthority.ErrInvalid
		}
	}
	return nil
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
	var names []string
	switch scope.Kind {
	case serviceauthority.ScopeDeviceSync:
		// A Device Sync Space is nested beneath its personal principal. Its
		// spaceID is content-selection state, not the service-authority scope.
		names = []string{"principalID", "tenantID"}
	case serviceauthority.ScopeSharedSpace:
		// Shared Space control routes name spaceID; their reused opaque relay
		// data plane names the same logical Space as tenantID.
		names = []string{"spaceID", "tenantID"}
	default:
		return serviceauthority.ErrInvalid
	}
	for _, name := range names {
		value := request.PathValue(name)
		if value == "" {
			continue
		}
		parsed, err := uuid.Parse(value)
		if err != nil || parsed == uuid.Nil || parsed != scope.ScopeID {
			return serviceauthority.ErrInvalid
		}
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
