package storageauthority

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/serviceauthority"
	"github.com/robreuss/FacetsNode/internal/storagecapacity"
)

type PrivateHTTPClient struct {
	baseURL  string
	http     *http.Client
	signer   *serviceauthority.DeploymentSigner
	binding  storagecapacity.ServiceBinding
	poolID   uuid.UUID
	now      func() time.Time
	newID    func() uuid.UUID
	newToken func() (string, error)
}

// NewPrivateHTTPClient requires HTTPS even when the HTTP transport dials a
// private Unix socket. The deployment key authenticates the service request;
// TLS separately protects bearer tokens and traffic metadata in transit.
func NewPrivateHTTPClient(
	baseURL string,
	httpClient *http.Client,
	signer *serviceauthority.DeploymentSigner,
	binding storagecapacity.ServiceBinding,
	poolID uuid.UUID,
) (*PrivateHTTPClient, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.Path != "" && parsed.Path != "/") || httpClient == nil || signer == nil ||
		binding.Validate() != nil || binding.InstanceID != signer.DeploymentID() || poolID == uuid.Nil {
		return nil, ErrInvalid
	}
	return &PrivateHTTPClient{
		baseURL: strings.TrimSuffix(baseURL, "/"), http: httpClient,
		signer: signer, binding: binding, poolID: poolID, now: time.Now,
		newID: uuid.New, newToken: storagecapacity.NewReservationToken,
	}, nil
}

func (client *PrivateHTTPClient) Reserve(
	ctx context.Context,
	request PrivateReserveRequest,
) (PrivateReservationView, error) {
	var result PrivateReservationView
	err := client.do(ctx, "/v1/reservations/reserve", http.StatusCreated, serviceauthority.CapacityReserve, request.OperationID, request, &result)
	return result, err
}

func (client *PrivateHTTPClient) Recheck(
	ctx context.Context,
	request PrivateRecheckRequest,
) error {
	return client.do(ctx, "/v1/reservations/recheck", http.StatusNoContent, serviceauthority.CapacityRecheck, request.OperationID, request, nil)
}

func (client *PrivateHTTPClient) Decide(
	ctx context.Context,
	request PrivateDecisionRequest,
) (PrivateReservationView, error) {
	var result PrivateReservationView
	err := client.do(ctx, "/v1/reservations/decide", http.StatusOK, serviceauthority.CapacityDecide, request.OperationID, request, &result)
	return result, err
}

func (client *PrivateHTTPClient) Reservation(
	ctx context.Context,
	request PrivateReservationRequest,
) (PrivateReservationView, error) {
	var result PrivateReservationView
	err := client.do(ctx, "/v1/reservations/get", http.StatusOK, serviceauthority.CapacityRead, request.OperationID, request, &result)
	return result, err
}

func (client *PrivateHTTPClient) Readiness(
	ctx context.Context,
	request PrivateReadinessRequest,
) (storagecapacity.CoarseReadinessSnapshot, error) {
	var result storagecapacity.CoarseReadinessSnapshot
	err := client.do(ctx, "/v1/readiness/query", http.StatusOK, serviceauthority.CapacityReadiness, request.OperationID, request, &result)
	return result, err
}

func (client *PrivateHTTPClient) do(
	ctx context.Context,
	path string,
	expectedStatus int,
	operation serviceauthority.CapacityPeerOperation,
	operationID uuid.UUID,
	body any,
	result any,
) error {
	if client == nil || client.http == nil || client.signer == nil || client.now == nil ||
		ctx == nil || operationID == uuid.Nil {
		return ErrInvalid
	}
	envelope, err := NewPrivateCapacityEnvelopeAt(client.signer, client.binding, client.poolID, operation, operationID, body, client.now())
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(envelope)
	if err != nil || len(encoded) > MaximumPrivateCapacityEnvelopeBytes {
		return ErrInvalid
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, client.baseURL+path, bytes.NewReader(encoded))
	if err != nil {
		return ErrInvalid
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	response, err := client.http.Do(httpRequest)
	if err != nil {
		return ErrUnavailable
	}
	defer response.Body.Close()
	reader := io.LimitReader(response.Body, MaximumPrivateCapacityEnvelopeBytes+1)
	responseBytes, err := io.ReadAll(reader)
	if err != nil || len(responseBytes) > MaximumPrivateCapacityEnvelopeBytes {
		return ErrUnavailable
	}
	if response.StatusCode != expectedStatus {
		return decodePrivateRemoteError(response.StatusCode, responseBytes)
	}
	if expectedStatus == http.StatusNoContent {
		if len(responseBytes) != 0 {
			return ErrInvalid
		}
		return nil
	}
	if result == nil || decodeCanonicalResponse(responseBytes, result) != nil {
		return ErrInvalid
	}
	return nil
}

type PrivateRemoteError struct {
	StatusCode int
	Response   PrivateCapacityError
}

func (value *PrivateRemoteError) Error() string {
	if value == nil {
		return "storage capacity authority request failed"
	}
	return "storage capacity authority request failed: " + value.Response.Code
}

func (value *PrivateRemoteError) Unwrap() error {
	if value == nil {
		return ErrUnavailable
	}
	switch value.Response.Code {
	case "storage_pressure":
		return storagecapacity.ErrPressure
	case "capacity_unavailable":
		return storagecapacity.ErrUnavailable
	case "reservation_conflict":
		return ErrConflict
	case "reservation_rejected", "service_authority_rejected":
		return ErrRejected
	case "invalid_request":
		return ErrInvalid
	default:
		return ErrUnavailable
	}
}

func decodePrivateRemoteError(status int, data []byte) error {
	var response PrivateCapacityError
	if status < 400 || status > 599 || decodeCanonicalResponse(data, &response) != nil || response.Code == "" {
		return ErrUnavailable
	}
	return &PrivateRemoteError{StatusCode: status, Response: response}
}

func decodeCanonicalResponse(data []byte, target any) error {
	trimmed := bytes.TrimSuffix(data, []byte{'\n'})
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(canonical, trimmed) {
		return ErrInvalid
	}
	return nil
}
