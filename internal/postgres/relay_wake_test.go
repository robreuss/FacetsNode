package postgres

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestRelayWakePayloadCarriesOnlyCanonicalRoutingScope(t *testing.T) {
	tenantID := uuid.MustParse("11111111-2222-3333-4444-555555555555")
	domainID := uuid.MustParse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
	payload := encodeRelayWakePayload(tenantID, domainID)
	if payload != "11111111-2222-3333-4444-555555555555/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" {
		t.Fatalf("unexpected relay wake payload: %q", payload)
	}
	decodedTenantID, decodedDomainID, err := decodeRelayWakePayload(payload)
	if err != nil || decodedTenantID != tenantID || decodedDomainID != domainID {
		t.Fatalf("decode tenant=%s domain=%s err=%v", decodedTenantID, decodedDomainID, err)
	}
}

func TestRelayWakePayloadRejectsMalformedOrNoncanonicalScope(t *testing.T) {
	validTenant := "11111111-2222-3333-4444-555555555555"
	validDomain := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	for _, payload := range []string{
		"",
		validTenant,
		validTenant + "/" + validDomain + "/extra",
		"11111111-2222-3333-4444-55555555555Z/" + validDomain,
		validTenant + "/AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
		uuid.Nil.String() + "/" + validDomain,
		validTenant + "/" + uuid.Nil.String(),
		`{"tenantID":"` + validTenant + `","domainID":"` + validDomain + `"}`,
	} {
		if _, _, err := decodeRelayWakePayload(payload); err == nil {
			t.Fatalf("accepted invalid relay wake payload %q", payload)
		}
	}
}

func TestRelayWakeReconnectBackoffStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	if waitRelayWakeBackoff(ctx, time.Hour) {
		t.Fatal("canceled relay wake backoff reported completion")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("canceled relay wake backoff was not prompt: %s", elapsed)
	}
}

func TestRelayWakeListenerReconnectsWithBoundedBackoff(t *testing.T) {
	configuration, err := pgx.ParseConfig("postgres://example.invalid/facets")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var connectCount int
	var waits []time.Duration
	listener := &RelayWakeListener{
		config:           configuration,
		reconnectMinimum: 100 * time.Millisecond,
		reconnectMaximum: 200 * time.Millisecond,
		connect: func(context.Context, *pgx.ConnConfig) (*pgx.Conn, error) {
			connectCount++
			return nil, errors.New("database unavailable")
		},
		waitBackoff: func(_ context.Context, duration time.Duration) bool {
			waits = append(waits, duration)
			if len(waits) == 3 {
				cancel()
				return false
			}
			return true
		},
		ready: make(chan struct{}),
	}
	var observedErrors int

	listener.Run(ctx, func(uuid.UUID, uuid.UUID) {}, func(error) {
		observedErrors++
	})

	if connectCount != 3 || observedErrors != 3 {
		t.Fatalf("connects=%d observedErrors=%d", connectCount, observedErrors)
	}
	if expected := []time.Duration{100 * time.Millisecond, 200 * time.Millisecond, 200 * time.Millisecond}; !reflect.DeepEqual(waits, expected) {
		t.Fatalf("backoff waits=%v expected=%v", waits, expected)
	}
	select {
	case <-listener.Ready():
		t.Fatal("listener became ready without a PostgreSQL LISTEN connection")
	default:
	}
}
