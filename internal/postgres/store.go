package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/robreuss/FacetsNode/internal/rendezvous"
)

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) CreateRoute(
	ctx context.Context,
	registration rendezvous.Registration,
	sponsorToken string,
	nowMilliseconds int64,
) (rendezvous.Acceptance, error) {
	if err := registration.ValidateAt(nowMilliseconds); err != nil {
		return "", err
	}
	credential := rendezvous.Credential{
		RouteID: registration.RouteID,
		Role:    rendezvous.RoleSponsor,
		Token:   sponsorToken,
	}
	if err := registration.Authorize(credential, nowMilliseconds); err != nil {
		return "", err
	}
	result, err := s.pool.Exec(ctx, `
		INSERT INTO pairing_routes (
			route_id, version,
			sponsor_authorization_digest, candidate_authorization_digest,
			created_at_milliseconds, expires_at_milliseconds
		) VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (route_id) DO NOTHING
	`, registration.RouteID, registration.Version,
		registration.SponsorAuthorizationDigest,
		registration.CandidateAuthorizationDigest,
		registration.CreatedAtMilliseconds,
		registration.ExpiresAtMilliseconds)
	if err != nil {
		return "", fmt.Errorf("insert pairing route: %w", err)
	}
	if result.RowsAffected() == 1 {
		return rendezvous.AcceptanceAccepted, nil
	}
	existing, _, err := s.loadRoute(ctx, s.pool, registration.RouteID, false)
	if err != nil {
		return "", err
	}
	if err := existing.Authorize(credential, nowMilliseconds); err != nil {
		return "", err
	}
	if existing == registration {
		return rendezvous.AcceptanceDuplicate, nil
	}
	return "", rendezvous.NewProtocolError(
		rendezvous.CodeRouteCollision,
		"route ID was reused with different registration",
	)
}

func (s *Store) Publish(
	ctx context.Context,
	credential rendezvous.Credential,
	envelope rendezvous.Envelope,
	nowMilliseconds int64,
) (rendezvous.Acceptance, error) {
	transaction, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return "", fmt.Errorf("begin publish: %w", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	registration, closedAt, err := s.loadRoute(ctx, transaction, credential.RouteID, true)
	if err != nil {
		return "", err
	}
	if err := registration.Authorize(credential, nowMilliseconds); err != nil {
		return "", err
	}
	if err := envelope.ValidateForPublish(registration, nowMilliseconds); err != nil {
		return "", err
	}

	existing, found, err := loadMessage(ctx, transaction, credential.RouteID, envelope.MessageID, true)
	if err != nil {
		return "", err
	}
	if found {
		if existing.PublisherRole == credential.Role && existing.Envelope == envelope {
			return rendezvous.AcceptanceDuplicate, nil
		}
		return "", rendezvous.NewProtocolError(
			rendezvous.CodeMessageCollision,
			"message ID was reused with different content",
		)
	}
	if closedAt != nil {
		return "", rendezvous.NewProtocolError(rendezvous.CodeRouteClosed, "route is closed")
	}
	var messageCount int
	if err := transaction.QueryRow(
		ctx,
		"SELECT count(*) FROM pairing_messages WHERE route_id = $1",
		credential.RouteID,
	).Scan(&messageCount); err != nil {
		return "", fmt.Errorf("count pairing messages: %w", err)
	}
	if messageCount >= rendezvous.MaximumMessageCount {
		return "", rendezvous.NewProtocolError(rendezvous.CodeMailboxFull, "route reached its message limit")
	}
	if _, err := transaction.Exec(ctx, `
		INSERT INTO pairing_messages (
			route_id, message_id, publisher_role, version, algorithm,
			created_at_milliseconds, expires_at_milliseconds,
			nonce, ciphertext, authentication_tag
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, envelope.RouteID, envelope.MessageID, credential.Role,
		envelope.Version, envelope.Algorithm,
		envelope.CreatedAtMilliseconds, envelope.ExpiresAtMilliseconds,
		envelope.Nonce, envelope.Ciphertext, envelope.AuthenticationTag); err != nil {
		return "", fmt.Errorf("insert pairing message: %w", err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return "", fmt.Errorf("commit publish: %w", err)
	}
	return rendezvous.AcceptanceAccepted, nil
}

func (s *Store) Fetch(
	ctx context.Context,
	credential rendezvous.Credential,
	nowMilliseconds int64,
) ([]rendezvous.Envelope, error) {
	registration, _, err := s.loadRoute(ctx, s.pool, credential.RouteID, false)
	if err != nil {
		return nil, err
	}
	if err := registration.Authorize(credential, nowMilliseconds); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `
		SELECT message_id, version, algorithm,
		       created_at_milliseconds, expires_at_milliseconds,
		       nonce, ciphertext, authentication_tag
		FROM pairing_messages
		WHERE route_id = $1
		  AND publisher_role <> $2
		  AND acknowledged_by IS NULL
		  AND created_at_milliseconds <= $3
		  AND expires_at_milliseconds > $3
		ORDER BY created_at_milliseconds, message_id
	`, credential.RouteID, credential.Role, nowMilliseconds)
	if err != nil {
		return nil, fmt.Errorf("fetch pairing messages: %w", err)
	}
	defer rows.Close()
	envelopes := make([]rendezvous.Envelope, 0)
	for rows.Next() {
		envelope := rendezvous.Envelope{RouteID: credential.RouteID}
		if err := rows.Scan(
			&envelope.MessageID, &envelope.Version, &envelope.Algorithm,
			&envelope.CreatedAtMilliseconds, &envelope.ExpiresAtMilliseconds,
			&envelope.Nonce, &envelope.Ciphertext, &envelope.AuthenticationTag,
		); err != nil {
			return nil, fmt.Errorf("scan pairing message: %w", err)
		}
		if err := envelope.Validate(); err != nil {
			return nil, fmt.Errorf("stored pairing message failed validation: %v", err)
		}
		envelopes = append(envelopes, envelope)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate pairing messages: %w", err)
	}
	return envelopes, nil
}

func (s *Store) Acknowledge(
	ctx context.Context,
	credential rendezvous.Credential,
	messageID uuid.UUID,
	nowMilliseconds int64,
) error {
	transaction, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin acknowledgement: %w", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	registration, _, err := s.loadRoute(ctx, transaction, credential.RouteID, true)
	if err != nil {
		return err
	}
	if err := registration.Authorize(credential, nowMilliseconds); err != nil {
		return err
	}
	entry, found, err := loadMessage(ctx, transaction, credential.RouteID, messageID, true)
	if err != nil {
		return err
	}
	if !found {
		return rendezvous.NewProtocolError(rendezvous.CodeMessageNotFound, "message was not found")
	}
	if entry.Envelope.ExpiresAtMilliseconds <= nowMilliseconds {
		return rendezvous.NewProtocolError(rendezvous.CodeMessageExpired, "message is expired")
	}
	if entry.PublisherRole == credential.Role {
		return rendezvous.NewProtocolError(
			rendezvous.CodeInvalidAcknowledgment,
			"publisher cannot acknowledge its message",
		)
	}
	if _, err := transaction.Exec(ctx, `
		UPDATE pairing_messages
		SET acknowledged_by = $3, acknowledged_at_milliseconds = $4
		WHERE route_id = $1 AND message_id = $2 AND acknowledged_by IS NULL
	`, credential.RouteID, messageID, credential.Role, nowMilliseconds); err != nil {
		return fmt.Errorf("acknowledge pairing message: %w", err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return fmt.Errorf("commit acknowledgement: %w", err)
	}
	return nil
}

func (s *Store) Close(
	ctx context.Context,
	credential rendezvous.Credential,
	nowMilliseconds int64,
) error {
	transaction, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin close: %w", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	registration, _, err := s.loadRoute(ctx, transaction, credential.RouteID, true)
	if err != nil {
		return err
	}
	if err := registration.Authorize(credential, nowMilliseconds); err != nil {
		return err
	}
	if credential.Role != rendezvous.RoleSponsor {
		return rendezvous.NewProtocolError(rendezvous.CodeUnauthorized, "only the sponsor can close a route")
	}
	if _, err := transaction.Exec(ctx, `
		UPDATE pairing_routes
		SET closed_at_milliseconds = COALESCE(closed_at_milliseconds, $2)
		WHERE route_id = $1
	`, credential.RouteID, nowMilliseconds); err != nil {
		return fmt.Errorf("close pairing route: %w", err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return fmt.Errorf("commit close: %w", err)
	}
	return nil
}

func (s *Store) PurgeExpired(ctx context.Context, nowMilliseconds int64) error {
	transaction, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin expiry purge: %w", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	if _, err := transaction.Exec(
		ctx,
		"DELETE FROM pairing_messages WHERE expires_at_milliseconds <= $1",
		nowMilliseconds,
	); err != nil {
		return fmt.Errorf("purge expired pairing messages: %w", err)
	}
	if _, err := transaction.Exec(
		ctx,
		"DELETE FROM pairing_routes WHERE expires_at_milliseconds <= $1",
		nowMilliseconds,
	); err != nil {
		return fmt.Errorf("purge expired pairing routes: %w", err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return fmt.Errorf("commit expiry purge: %w", err)
	}
	return nil
}

func (s *Store) Ready(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

type routeQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func (s *Store) loadRoute(
	ctx context.Context,
	querier routeQuerier,
	routeID uuid.UUID,
	forUpdate bool,
) (rendezvous.Registration, *int64, error) {
	query := `
		SELECT version, sponsor_authorization_digest,
		       candidate_authorization_digest,
		       created_at_milliseconds, expires_at_milliseconds,
		       closed_at_milliseconds
		FROM pairing_routes WHERE route_id = $1
	`
	if forUpdate {
		query += " FOR UPDATE"
	}
	registration := rendezvous.Registration{RouteID: routeID}
	var closedAt *int64
	err := querier.QueryRow(ctx, query, routeID).Scan(
		&registration.Version,
		&registration.SponsorAuthorizationDigest,
		&registration.CandidateAuthorizationDigest,
		&registration.CreatedAtMilliseconds,
		&registration.ExpiresAtMilliseconds,
		&closedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return rendezvous.Registration{}, nil, rendezvous.NewProtocolError(
			rendezvous.CodeRouteNotFound,
			"route was not found",
		)
	}
	if err != nil {
		return rendezvous.Registration{}, nil, fmt.Errorf("load pairing route: %w", err)
	}
	if err := registration.Validate(); err != nil {
		return rendezvous.Registration{}, nil, fmt.Errorf("stored pairing route failed validation: %v", err)
	}
	if closedAt != nil && (*closedAt < registration.CreatedAtMilliseconds ||
		*closedAt >= registration.ExpiresAtMilliseconds) {
		return rendezvous.Registration{}, nil, fmt.Errorf("stored pairing route has invalid close time")
	}
	return registration, closedAt, nil
}

func loadMessage(
	ctx context.Context,
	querier routeQuerier,
	routeID uuid.UUID,
	messageID uuid.UUID,
	forUpdate bool,
) (rendezvous.Entry, bool, error) {
	query := `
		SELECT publisher_role, version, algorithm,
		       created_at_milliseconds, expires_at_milliseconds,
		       nonce, ciphertext, authentication_tag,
		       acknowledged_by IS NOT NULL
		FROM pairing_messages
		WHERE route_id = $1 AND message_id = $2
	`
	if forUpdate {
		query += " FOR UPDATE"
	}
	entry := rendezvous.Entry{
		Envelope: rendezvous.Envelope{RouteID: routeID, MessageID: messageID},
	}
	err := querier.QueryRow(ctx, query, routeID, messageID).Scan(
		&entry.PublisherRole,
		&entry.Envelope.Version,
		&entry.Envelope.Algorithm,
		&entry.Envelope.CreatedAtMilliseconds,
		&entry.Envelope.ExpiresAtMilliseconds,
		&entry.Envelope.Nonce,
		&entry.Envelope.Ciphertext,
		&entry.Envelope.AuthenticationTag,
		&entry.Acknowledged,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return rendezvous.Entry{}, false, nil
	}
	if err != nil {
		return rendezvous.Entry{}, false, fmt.Errorf("load pairing message: %w", err)
	}
	if err := entry.Envelope.Validate(); err != nil {
		return rendezvous.Entry{}, false, fmt.Errorf("stored pairing message failed validation: %v", err)
	}
	return entry, true, nil
}
