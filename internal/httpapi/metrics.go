package httpapi

import (
	"fmt"
	"io"
	"sync/atomic"

	"github.com/robreuss/FacetsNode/internal/traffic"
)

type responseClass uint8

const (
	responseSuccess responseClass = iota
	responseClientError
	responseServerError
	responseClassCount
)

var allResponseClasses = [...]responseClass{
	responseSuccess, responseClientError, responseServerError,
}

func (c responseClass) name() string {
	switch c {
	case responseSuccess:
		return "success"
	case responseClientError:
		return "client_error"
	case responseServerError:
		return "server_error"
	default:
		return "invalid"
	}
}

type operationOutcome uint8

const (
	outcomeAccepted operationOutcome = iota
	outcomeDuplicate
	outcomeCount
)

var allOperationOutcomes = [...]operationOutcome{outcomeAccepted, outcomeDuplicate}

func (o operationOutcome) name() string {
	if o == outcomeAccepted {
		return "accepted"
	}
	return "duplicate"
}

type rejectionClass uint8

const (
	rejectionInvalid rejectionClass = iota
	rejectionUnauthorized
	rejectionForbidden
	rejectionNotFound
	rejectionConflict
	rejectionExpired
	rejectionCapacity
	rejectionIdentityRateLimit
	rejectionConnectionRateLimit
	rejectionConcurrencyLimit
	rejectionInternal
	rejectionClassCount
)

var allRejectionClasses = [...]rejectionClass{
	rejectionInvalid,
	rejectionUnauthorized,
	rejectionForbidden,
	rejectionNotFound,
	rejectionConflict,
	rejectionExpired,
	rejectionCapacity,
	rejectionIdentityRateLimit,
	rejectionConnectionRateLimit,
	rejectionConcurrencyLimit,
	rejectionInternal,
}

func (c rejectionClass) name() string {
	switch c {
	case rejectionInvalid:
		return "invalid"
	case rejectionUnauthorized:
		return "unauthorized"
	case rejectionForbidden:
		return "forbidden"
	case rejectionNotFound:
		return "not_found"
	case rejectionConflict:
		return "conflict"
	case rejectionExpired:
		return "expired"
	case rejectionCapacity:
		return "capacity"
	case rejectionIdentityRateLimit:
		return "identity_rate_limit"
	case rejectionConnectionRateLimit:
		return "connection_rate_limit"
	case rejectionConcurrencyLimit:
		return "concurrency_limit"
	case rejectionInternal:
		return "internal"
	default:
		return "invalid_class"
	}
}

type Metrics struct {
	requests                    [traffic.SurfaceCount]atomic.Uint64
	responses                   [traffic.SurfaceCount][responseClassCount]atomic.Uint64
	outcomes                    [traffic.SurfaceCount][outcomeCount]atomic.Uint64
	rejections                  [traffic.SurfaceCount][rejectionClassCount]atomic.Uint64
	relayWakeNotifications      atomic.Uint64
	relayWakeNotificationErrors atomic.Uint64
	relayWakeReceived           atomic.Uint64
}

func (m *Metrics) ObserveRequest(surface traffic.Surface) {
	m.requests[surface].Add(1)
}

func (m *Metrics) ObserveResponse(surface traffic.Surface, status int) {
	class := responseSuccess
	if status >= 500 {
		class = responseServerError
	} else if status >= 400 {
		class = responseClientError
	}
	m.responses[surface][class].Add(1)
}

func (m *Metrics) ObserveAcceptance(surface traffic.Surface, acceptance string) {
	switch acceptance {
	case "accepted":
		m.outcomes[surface][outcomeAccepted].Add(1)
	case "duplicate":
		m.outcomes[surface][outcomeDuplicate].Add(1)
	}
}

func (m *Metrics) ObserveRejection(surface traffic.Surface, class rejectionClass) {
	m.rejections[surface][class].Add(1)
}

func (m *Metrics) ObserveRelayWakeNotification(success bool) {
	if success {
		m.relayWakeNotifications.Add(1)
	} else {
		m.relayWakeNotificationErrors.Add(1)
	}
}

func (m *Metrics) ObserveRelayWakeReceived() { m.relayWakeReceived.Add(1) }

func (m *Metrics) WritePrometheus(writer io.Writer) error {
	if _, err := io.WriteString(writer, `# HELP facets_server_http_surface_requests_total HTTP requests reaching a fixed API surface.
# TYPE facets_server_http_surface_requests_total counter
`); err != nil {
		return err
	}
	for _, surface := range traffic.Surfaces() {
		if _, err := fmt.Fprintf(writer, "facets_server_http_surface_requests_total{surface=%q} %d\n", surface.Name(), m.requests[surface].Load()); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(writer, `# HELP facets_server_http_surface_responses_total HTTP responses by fixed surface and status class.
# TYPE facets_server_http_surface_responses_total counter
`); err != nil {
		return err
	}
	for _, surface := range traffic.Surfaces() {
		for _, class := range allResponseClasses {
			if _, err := fmt.Fprintf(writer, "facets_server_http_surface_responses_total{surface=%q,class=%q} %d\n", surface.Name(), class.name(), m.responses[surface][class].Load()); err != nil {
				return err
			}
		}
	}
	if _, err := io.WriteString(writer, `# HELP facets_server_operation_outcomes_total Accepted and exact-duplicate durable operation outcomes.
# TYPE facets_server_operation_outcomes_total counter
`); err != nil {
		return err
	}
	for _, surface := range traffic.Surfaces() {
		for _, outcome := range allOperationOutcomes {
			if _, err := fmt.Fprintf(writer, "facets_server_operation_outcomes_total{surface=%q,outcome=%q} %d\n", surface.Name(), outcome.name(), m.outcomes[surface][outcome].Load()); err != nil {
				return err
			}
		}
	}
	if _, err := io.WriteString(writer, `# HELP facets_server_rejections_total Rejected requests by fixed surface and bounded rejection class.
# TYPE facets_server_rejections_total counter
`); err != nil {
		return err
	}
	for _, surface := range traffic.Surfaces() {
		for _, class := range allRejectionClasses {
			if _, err := fmt.Fprintf(writer, "facets_server_rejections_total{surface=%q,class=%q} %d\n", surface.Name(), class.name(), m.rejections[surface][class].Load()); err != nil {
				return err
			}
		}
	}
	_, err := fmt.Fprintf(writer, `# HELP facets_server_relay_wake_notifications_total Cross-instance relay wake hints published.
# TYPE facets_server_relay_wake_notifications_total counter
facets_server_relay_wake_notifications_total %d
# HELP facets_server_relay_wake_notification_errors_total Cross-instance relay wake hint publication failures.
# TYPE facets_server_relay_wake_notification_errors_total counter
facets_server_relay_wake_notification_errors_total %d
# HELP facets_server_relay_wake_received_total Cross-instance relay wake hints received.
# TYPE facets_server_relay_wake_received_total counter
facets_server_relay_wake_received_total %d
`, m.relayWakeNotifications.Load(), m.relayWakeNotificationErrors.Load(), m.relayWakeReceived.Load())
	return err
}

func rejectionForStatus(status int) (rejectionClass, bool) {
	switch status {
	case 400:
		return rejectionInvalid, true
	case 401:
		return rejectionUnauthorized, true
	case 403:
		return rejectionForbidden, true
	case 404:
		return rejectionNotFound, true
	case 409:
		return rejectionConflict, true
	case 410:
		return rejectionExpired, true
	case 429:
		return rejectionCapacity, true
	default:
		if status >= 500 {
			return rejectionInternal, true
		}
		return 0, false
	}
}
