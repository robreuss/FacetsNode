package httpapi

import (
	"fmt"
	"io"
	"sync/atomic"
)

type Metrics struct {
	requests                    atomic.Uint64
	errors                      atomic.Uint64
	accepted                    atomic.Uint64
	duplicates                  atomic.Uint64
	relayWakeNotifications      atomic.Uint64
	relayWakeNotificationErrors atomic.Uint64
	relayWakeReceived           atomic.Uint64
}

func (m *Metrics) ObserveRelayWakeNotification(success bool) {
	if success {
		m.relayWakeNotifications.Add(1)
	} else {
		m.relayWakeNotificationErrors.Add(1)
	}
}

func (m *Metrics) ObserveRelayWakeReceived() { m.relayWakeReceived.Add(1) }

func (m *Metrics) ObserveStatus(status int) {
	m.requests.Add(1)
	if status >= 400 {
		m.errors.Add(1)
	}
}

func (m *Metrics) ObserveAcceptance(acceptance string) {
	switch acceptance {
	case "accepted":
		m.accepted.Add(1)
	case "duplicate":
		m.duplicates.Add(1)
	}
}

func (m *Metrics) WritePrometheus(writer io.Writer) error {
	_, err := fmt.Fprintf(writer, `# HELP facets_node_http_requests_total Total HTTP responses.
# TYPE facets_node_http_requests_total counter
facets_node_http_requests_total %d
# HELP facets_node_http_errors_total Total HTTP error responses.
# TYPE facets_node_http_errors_total counter
facets_node_http_errors_total %d
# HELP facets_node_rendezvous_acceptances_total New routes and messages accepted.
# TYPE facets_node_rendezvous_acceptances_total counter
facets_node_rendezvous_acceptances_total %d
# HELP facets_node_rendezvous_duplicates_total Exact idempotent retries accepted.
# TYPE facets_node_rendezvous_duplicates_total counter
facets_node_rendezvous_duplicates_total %d
# HELP facets_node_relay_wake_notifications_total Cross-instance relay wake hints published.
# TYPE facets_node_relay_wake_notifications_total counter
facets_node_relay_wake_notifications_total %d
# HELP facets_node_relay_wake_notification_errors_total Cross-instance relay wake hint publication failures.
# TYPE facets_node_relay_wake_notification_errors_total counter
facets_node_relay_wake_notification_errors_total %d
# HELP facets_node_relay_wake_received_total Cross-instance relay wake hints received.
# TYPE facets_node_relay_wake_received_total counter
facets_node_relay_wake_received_total %d
`, m.requests.Load(), m.errors.Load(), m.accepted.Load(), m.duplicates.Load(), m.relayWakeNotifications.Load(), m.relayWakeNotificationErrors.Load(), m.relayWakeReceived.Load())
	return err
}
