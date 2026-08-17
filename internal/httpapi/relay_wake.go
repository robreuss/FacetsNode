package httpapi

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
)

const relayWakeNotificationTimeout = time.Second

type RelayWakeNotifier interface {
	Notify(context.Context, uuid.UUID, uuid.UUID) error
}

type relayWakeDomain struct {
	tenantID uuid.UUID
	domainID uuid.UUID
}

// relayWakeBroker carries no message data and owns no durable state. Closing
// a domain channel merely asks connected members to perform their ordinary,
// authoritative cursor fetch sooner. A missed close is harmless because the
// clients retain their periodic reconciliation schedule.
type relayWakeBroker struct {
	mu       sync.Mutex
	wakeByID map[relayWakeDomain]chan struct{}
}

func newRelayWakeBroker() *relayWakeBroker {
	return &relayWakeBroker{wakeByID: make(map[relayWakeDomain]chan struct{})}
}

func (b *relayWakeBroker) subscribe(tenantID, domainID uuid.UUID) <-chan struct{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	key := relayWakeDomain{tenantID: tenantID, domainID: domainID}
	if existing := b.wakeByID[key]; existing != nil {
		return existing
	}
	wake := make(chan struct{})
	b.wakeByID[key] = wake
	return wake
}

func (b *relayWakeBroker) notify(tenantID, domainID uuid.UUID) {
	b.mu.Lock()
	defer b.mu.Unlock()
	key := relayWakeDomain{tenantID: tenantID, domainID: domainID}
	if existing := b.wakeByID[key]; existing != nil {
		close(existing)
	}
	b.wakeByID[key] = make(chan struct{})
}

// SetRelayWakeNotifier installs a disposable cross-instance accelerator. It
// does not change durable fetch authority or local wake behavior.
func (s *Server) SetRelayWakeNotifier(notifier RelayWakeNotifier) {
	s.relayWakeNotifier = notifier
}

// ReceiveRelayWake feeds a validated cross-instance hint into this instance's
// local broker. The payload is routing scope only.
func (s *Server) ReceiveRelayWake(tenantID, domainID uuid.UUID) {
	if tenantID == uuid.Nil || domainID == uuid.Nil {
		return
	}
	s.metrics.ObserveRelayWakeReceived()
	s.relayWakeBroker.notify(tenantID, domainID)
}

func (s *Server) notifyRelayWake(ctx context.Context, tenantID, domainID uuid.UUID) {
	s.relayWakeBroker.notify(tenantID, domainID)
	if s.relayWakeNotifier == nil {
		return
	}
	notifyContext, cancel := context.WithTimeout(
		context.WithoutCancel(ctx), relayWakeNotificationTimeout,
	)
	defer cancel()
	if err := s.relayWakeNotifier.Notify(notifyContext, tenantID, domainID); err != nil {
		s.metrics.ObserveRelayWakeNotification(false)
		if s.logger != nil {
			s.logger.Warn("cross-instance relay wake notification failed", "error", err)
		}
		return
	}
	s.metrics.ObserveRelayWakeNotification(true)
}
