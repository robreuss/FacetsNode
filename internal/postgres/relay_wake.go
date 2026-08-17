package postgres

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const relayWakeChannel = "facets_relay_wake_v1"

const (
	defaultRelayWakeReconnectMinimum = 100 * time.Millisecond
	defaultRelayWakeReconnectMaximum = 5 * time.Second
)

// RelayWakeNotifier publishes only opaque routing scope. PostgreSQL
// notifications are disposable hints; durable relay fetch remains authority.
type RelayWakeNotifier struct {
	pool *pgxpool.Pool
}

func NewRelayWakeNotifier(pool *pgxpool.Pool) *RelayWakeNotifier {
	return &RelayWakeNotifier{pool: pool}
}

func (n *RelayWakeNotifier) Notify(ctx context.Context, tenantID, domainID uuid.UUID) error {
	if n == nil || n.pool == nil || tenantID == uuid.Nil || domainID == uuid.Nil {
		return errors.New("relay wake notifier is unavailable")
	}
	_, err := n.pool.Exec(ctx, `SELECT pg_notify('`+relayWakeChannel+`',$1)`, encodeRelayWakePayload(tenantID, domainID))
	return err
}

// RelayWakeListener owns a dedicated PostgreSQL connection because LISTEN
// session state must not be returned to a shared pool. Run reconnects until its
// context is canceled. Ready closes after the first successful LISTEN.
type RelayWakeListener struct {
	config           *pgx.ConnConfig
	reconnectMinimum time.Duration
	reconnectMaximum time.Duration
	connect          func(context.Context, *pgx.ConnConfig) (*pgx.Conn, error)
	waitBackoff      func(context.Context, time.Duration) bool
	ready            chan struct{}
	readyOnce        sync.Once
}

func NewRelayWakeListener(pool *pgxpool.Pool) *RelayWakeListener {
	var configuration *pgx.ConnConfig
	if pool != nil && pool.Config() != nil && pool.Config().ConnConfig != nil {
		configuration = pool.Config().ConnConfig.Copy()
	}
	return &RelayWakeListener{
		config:           configuration,
		reconnectMinimum: defaultRelayWakeReconnectMinimum,
		reconnectMaximum: defaultRelayWakeReconnectMaximum,
		connect:          pgx.ConnectConfig,
		waitBackoff:      waitRelayWakeBackoff,
		ready:            make(chan struct{}),
	}
}

func (l *RelayWakeListener) Ready() <-chan struct{} { return l.ready }

func (l *RelayWakeListener) Run(ctx context.Context, receive func(uuid.UUID, uuid.UUID), observeError func(error)) {
	if l == nil || l.config == nil || receive == nil {
		if observeError != nil {
			observeError(errors.New("relay wake listener is unavailable"))
		}
		return
	}
	backoff := l.reconnectMinimum
	for ctx.Err() == nil {
		connection, err := l.connect(ctx, l.config.Copy())
		if err == nil {
			_, err = connection.Exec(ctx, `LISTEN `+relayWakeChannel)
		}
		if err == nil {
			l.readyOnce.Do(func() { close(l.ready) })
			backoff = l.reconnectMinimum
			err = l.wait(ctx, connection, receive, observeError)
		}
		if connection != nil {
			_ = connection.Close(context.Background())
		}
		if ctx.Err() != nil {
			return
		}
		if err != nil && observeError != nil {
			observeError(err)
		}
		if !l.waitBackoff(ctx, backoff) {
			return
		}
		backoff *= 2
		if backoff > l.reconnectMaximum {
			backoff = l.reconnectMaximum
		}
	}
}

func (l *RelayWakeListener) wait(ctx context.Context, connection *pgx.Conn, receive func(uuid.UUID, uuid.UUID), observeError func(error)) error {
	for {
		notification, err := connection.WaitForNotification(ctx)
		if err != nil {
			return err
		}
		if notification.Channel != relayWakeChannel {
			continue
		}
		tenantID, domainID, err := decodeRelayWakePayload(notification.Payload)
		if err != nil {
			if observeError != nil {
				observeError(err)
			}
			continue
		}
		receive(tenantID, domainID)
	}
}

func encodeRelayWakePayload(tenantID, domainID uuid.UUID) string {
	return tenantID.String() + "/" + domainID.String()
}

func decodeRelayWakePayload(payload string) (uuid.UUID, uuid.UUID, error) {
	parts := strings.Split(payload, "/")
	if len(parts) != 2 {
		return uuid.Nil, uuid.Nil, errors.New("relay wake payload is invalid")
	}
	tenantID, tenantErr := uuid.Parse(parts[0])
	domainID, domainErr := uuid.Parse(parts[1])
	if tenantErr != nil || domainErr != nil || tenantID == uuid.Nil || domainID == uuid.Nil ||
		tenantID.String() != parts[0] || domainID.String() != parts[1] {
		return uuid.Nil, uuid.Nil, errors.New("relay wake payload is invalid")
	}
	return tenantID, domainID, nil
}

func waitRelayWakeBackoff(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
