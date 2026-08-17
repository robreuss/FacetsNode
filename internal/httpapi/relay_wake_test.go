package httpapi

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

type recordingRelayWakeNotifier struct {
	mu    sync.Mutex
	calls []relayWakeDomain
	err   error
}

func (n *recordingRelayWakeNotifier) Notify(
	_ context.Context,
	tenantID uuid.UUID,
	domainID uuid.UUID,
) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.calls = append(n.calls, relayWakeDomain{tenantID: tenantID, domainID: domainID})
	return n.err
}

func (n *recordingRelayWakeNotifier) snapshot() []relayWakeDomain {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]relayWakeDomain(nil), n.calls...)
}

func TestRelayWakeBrokerNotifiesExistingSubscriberAndRotatesSignal(t *testing.T) {
	broker := newRelayWakeBroker()
	tenantID := uuid.New()
	domainID := uuid.New()
	first := broker.subscribe(tenantID, domainID)

	broker.notify(tenantID, domainID)
	select {
	case <-first:
	case <-time.After(time.Second):
		t.Fatal("wake subscriber was not notified")
	}

	second := broker.subscribe(tenantID, domainID)
	select {
	case <-second:
		t.Fatal("replacement wake signal was already closed")
	default:
	}
	broker.notify(tenantID, domainID)
	select {
	case <-second:
	case <-time.After(time.Second):
		t.Fatal("replacement wake subscriber was not notified")
	}
}

func TestRelayWakeNotificationFailureDoesNotSuppressLocalWakeOrLeakScope(t *testing.T) {
	tenantID := uuid.New()
	domainID := uuid.New()
	var logs bytes.Buffer
	server := New(nil, slog.New(slog.NewJSONHandler(&logs, nil)))
	notifier := &recordingRelayWakeNotifier{err: errors.New("notifier unavailable")}
	server.SetRelayWakeNotifier(notifier)
	wake := server.relayWakeBroker.subscribe(tenantID, domainID)

	server.notifyRelayWake(context.Background(), tenantID, domainID)

	select {
	case <-wake:
	case <-time.After(time.Second):
		t.Fatal("local subscriber was not notified when cross-instance notification failed")
	}
	calls := notifier.snapshot()
	if len(calls) != 1 || calls[0] != (relayWakeDomain{tenantID: tenantID, domainID: domainID}) {
		t.Fatalf("unexpected notifier calls: %+v", calls)
	}
	if server.metrics.relayWakeNotificationErrors.Load() != 1 ||
		server.metrics.relayWakeNotifications.Load() != 0 {
		t.Fatalf("unexpected notification metrics: %+v", server.metrics)
	}
	if strings.Contains(logs.String(), tenantID.String()) || strings.Contains(logs.String(), domainID.String()) {
		t.Fatalf("notification failure log leaked routing scope: %s", logs.String())
	}
}

func TestReceiveRelayWakeFeedsLocalBroker(t *testing.T) {
	tenantID := uuid.New()
	domainID := uuid.New()
	server := New(nil, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	wake := server.relayWakeBroker.subscribe(tenantID, domainID)

	server.ReceiveRelayWake(tenantID, domainID)

	select {
	case <-wake:
	case <-time.After(time.Second):
		t.Fatal("received cross-instance wake did not feed the local broker")
	}
	if server.metrics.relayWakeReceived.Load() != 1 {
		t.Fatalf("unexpected received wake count: %d", server.metrics.relayWakeReceived.Load())
	}
	server.ReceiveRelayWake(uuid.Nil, domainID)
	if server.metrics.relayWakeReceived.Load() != 1 {
		t.Fatal("invalid cross-instance wake was observed")
	}
}
