package httpapi

import (
	"sync"

	"github.com/google/uuid"
)

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
