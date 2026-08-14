package httpapi

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

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
