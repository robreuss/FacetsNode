package boxcontrol

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	if pool == nil {
		panic("Box controller Postgres pool is nil")
	}
	return &PostgresStore{pool: pool}
}

func (store *PostgresStore) Migrate(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS box_state (
			id boolean PRIMARY KEY DEFAULT TRUE CHECK (id),
			box_id uuid NOT NULL UNIQUE,
			activation_verifier text NOT NULL,
			owner_verifier text NOT NULL DEFAULT '',
			display_name text NOT NULL DEFAULT '',
			claimed_at timestamptz
		)`,
		`CREATE TABLE IF NOT EXISTS web_sessions (
			token_digest bytea PRIMARY KEY CHECK (octet_length(token_digest) = 32),
			csrf_digest bytea NOT NULL CHECK (octet_length(csrf_digest) = 32),
			created_at timestamptz NOT NULL,
			last_seen_at timestamptz NOT NULL,
			expires_at timestamptz NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS login_throttles (
			throttle_key text PRIMARY KEY CHECK (octet_length(throttle_key) BETWEEN 1 AND 256),
			failures integer NOT NULL CHECK (failures >= 0 AND failures <= 1000),
			window_start timestamptz NOT NULL,
			blocked_until timestamptz
		)`,
		`CREATE TABLE IF NOT EXISTS connection_grants (
			grant_id uuid PRIMARY KEY,
			token_digest bytea NOT NULL UNIQUE CHECK (octet_length(token_digest) = 32),
			device_name text NOT NULL CHECK (octet_length(device_name) BETWEEN 1 AND 1024),
			created_at timestamptz NOT NULL,
			last_seen_at timestamptz NOT NULL,
			expires_at timestamptz NOT NULL,
			revoked_at timestamptz
		)`,
		`CREATE TABLE IF NOT EXISTS connection_invitations (
			invitation_id uuid PRIMARY KEY,
			approval_code_digest bytea NOT NULL UNIQUE CHECK (octet_length(approval_code_digest) = 32),
			created_at timestamptz NOT NULL,
			expires_at timestamptz NOT NULL,
			redeemed_request_id uuid,
			redeemed_at timestamptz,
			CHECK ((redeemed_request_id IS NULL) = (redeemed_at IS NULL))
		)`,
		`CREATE TABLE IF NOT EXISTS connection_requests (
			request_id uuid PRIMARY KEY,
			poll_token_digest bytea NOT NULL CHECK (octet_length(poll_token_digest) = 32),
			client_public_key bytea NOT NULL CHECK (octet_length(client_public_key) = 32),
			approval_code_digest bytea NOT NULL UNIQUE CHECK (octet_length(approval_code_digest) = 32),
			device_name text NOT NULL CHECK (octet_length(device_name) BETWEEN 1 AND 1024),
			created_at timestamptz NOT NULL,
			expires_at timestamptz NOT NULL,
			authorized_at timestamptz,
			encrypted_result bytea NOT NULL DEFAULT ''::bytea CHECK (octet_length(encrypted_result) <= 1048576)
		)`,
		`ALTER TABLE connection_requests ADD COLUMN IF NOT EXISTS authorized_at timestamptz`,
		`CREATE TABLE IF NOT EXISTS audit_events (
			sequence bigserial PRIMARY KEY,
			occurred_at timestamptz NOT NULL,
			kind text NOT NULL CHECK (octet_length(kind) BETWEEN 1 AND 128),
			outcome text NOT NULL CHECK (octet_length(outcome) BETWEEN 1 AND 128)
		)`,
	}
	for _, statement := range statements {
		if _, err := store.pool.Exec(ctx, statement); err != nil {
			return fmt.Errorf("migrate Box controller store: %w", err)
		}
	}
	return nil
}

func (store *PostgresStore) Initialize(ctx context.Context, state State) error {
	result, err := store.pool.Exec(ctx, `
		INSERT INTO box_state (id, box_id, activation_verifier, owner_verifier)
		VALUES (TRUE, $1, $2, '')
		ON CONFLICT (id) DO NOTHING`, state.BoxID, state.ActivationVerifier)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrAlreadyInitialized
	}
	return nil
}

func (store *PostgresStore) State(ctx context.Context) (State, error) {
	var state State
	var claimedAt *time.Time
	err := store.pool.QueryRow(ctx, `
		SELECT box_id, activation_verifier, owner_verifier, display_name, claimed_at
		FROM box_state WHERE id = TRUE`).Scan(
		&state.BoxID, &state.ActivationVerifier, &state.OwnerVerifier, &state.DisplayName, &claimedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return State{}, ErrNotInitialized
	}
	if err != nil {
		return State{}, err
	}
	if claimedAt != nil {
		state.ClaimedAt = *claimedAt
	}
	return state, nil
}

func (store *PostgresStore) Claim(
	ctx context.Context,
	activationVerifier string,
	ownerVerifier string,
	displayName string,
	now time.Time,
) error {
	result, err := store.pool.Exec(ctx, `
		UPDATE box_state
		SET activation_verifier = '', owner_verifier = $2, display_name = $3, claimed_at = $4
		WHERE id = TRUE AND owner_verifier = '' AND activation_verifier = $1`,
		activationVerifier, ownerVerifier, displayName, now)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		state, stateErr := store.State(ctx)
		if stateErr != nil {
			return stateErr
		}
		if state.Claimed() {
			return ErrAlreadyClaimed
		}
		return ErrInvalidCredential
	}
	return nil
}

func (store *PostgresStore) ClaimAndAuthorizeConnection(
	ctx context.Context,
	activationVerifier string,
	ownerVerifier string,
	displayName string,
	requestID uuid.UUID,
	now time.Time,
) error {
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	claimDigest := claimRequestDigest(requestID)
	result, err := tx.Exec(ctx, `
		UPDATE connection_requests
		SET authorized_at = $3
		WHERE request_id = $1 AND approval_code_digest = $2
		  AND expires_at > $3 AND authorized_at IS NULL
		  AND octet_length(encrypted_result) = 0`,
		requestID, claimDigest[:], now)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrInvalidCredential
	}
	result, err = tx.Exec(ctx, `
		UPDATE box_state
		SET activation_verifier = '', owner_verifier = $2, display_name = $3, claimed_at = $4
		WHERE id = TRUE AND owner_verifier = '' AND activation_verifier = $1`,
		activationVerifier, ownerVerifier, displayName, now)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		var claimed bool
		if scanErr := tx.QueryRow(ctx, `
			SELECT owner_verifier <> '' FROM box_state WHERE id = TRUE`).Scan(&claimed); scanErr != nil {
			return scanErr
		}
		if claimed {
			return ErrAlreadyClaimed
		}
		return ErrInvalidCredential
	}
	return tx.Commit(ctx)
}

func (store *PostgresStore) ChangeOwnerPassword(ctx context.Context, verifier string, now time.Time) error {
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	result, err := tx.Exec(ctx, `UPDATE box_state SET owner_verifier = $1 WHERE id = TRUE AND owner_verifier <> ''`, verifier)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrNotInitialized
	}
	if _, err := tx.Exec(ctx, `DELETE FROM web_sessions`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE connection_grants SET revoked_at = COALESCE(revoked_at, $1)`, now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (store *PostgresStore) CreateWebSession(ctx context.Context, session WebSession) error {
	_, err := store.pool.Exec(ctx, `
		INSERT INTO web_sessions (token_digest, csrf_digest, created_at, last_seen_at, expires_at)
		VALUES ($1, $2, $3, $4, $5)`, session.TokenDigest[:], session.CSRFDigest[:], session.CreatedAt, session.LastSeenAt, session.ExpiresAt)
	return err
}

func (store *PostgresStore) WebSession(ctx context.Context, digest [32]byte, now time.Time) (WebSession, error) {
	var session WebSession
	var token, csrf []byte
	err := store.pool.QueryRow(ctx, `
		DELETE FROM web_sessions
		WHERE token_digest = $1
		  AND (expires_at <= $2 OR last_seen_at < $2 - INTERVAL '30 minutes')
		RETURNING token_digest, csrf_digest, created_at, last_seen_at, expires_at`, digest[:], now).Scan(
		&token, &csrf, &session.CreatedAt, &session.LastSeenAt, &session.ExpiresAt,
	)
	if err == nil {
		return WebSession{}, ErrInvalidCredential
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return WebSession{}, err
	}
	err = store.pool.QueryRow(ctx, `
		SELECT token_digest, csrf_digest, created_at, last_seen_at, expires_at
		FROM web_sessions WHERE token_digest = $1`, digest[:]).Scan(
		&token, &csrf, &session.CreatedAt, &session.LastSeenAt, &session.ExpiresAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return WebSession{}, ErrInvalidCredential
	}
	if err != nil || len(token) != 32 || len(csrf) != 32 {
		return WebSession{}, err
	}
	copy(session.TokenDigest[:], token)
	copy(session.CSRFDigest[:], csrf)
	return session, nil
}

func (store *PostgresStore) TouchWebSession(ctx context.Context, digest [32]byte, now time.Time) error {
	// Revalidate in the same write: a renewal racing logout/password change must
	// never recreate a deleted session, and an expired session cannot be revived.
	result, err := store.pool.Exec(ctx, `UPDATE web_sessions SET last_seen_at = $2, expires_at = $3
		WHERE token_digest = $1 AND expires_at > $2
		AND last_seen_at >= $2 - INTERVAL '30 minutes'`, digest[:], now, now.Add(WebSessionRenewalLifetime))
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrInvalidCredential
	}
	return nil
}

func (store *PostgresStore) DeleteWebSession(ctx context.Context, digest [32]byte) error {
	_, err := store.pool.Exec(ctx, `DELETE FROM web_sessions WHERE token_digest = $1`, digest[:])
	return err
}

func (store *PostgresStore) RevokeAllWebSessions(ctx context.Context) error {
	_, err := store.pool.Exec(ctx, `DELETE FROM web_sessions`)
	return err
}

func (store *PostgresStore) LoginThrottle(ctx context.Context, key string) (LoginThrottle, error) {
	var throttle LoginThrottle
	var blocked *time.Time
	err := store.pool.QueryRow(ctx, `SELECT failures, window_start, blocked_until FROM login_throttles WHERE throttle_key = $1`, key).Scan(
		&throttle.Failures, &throttle.WindowStart, &blocked,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return LoginThrottle{}, nil
	}
	if err != nil {
		return LoginThrottle{}, err
	}
	if blocked != nil {
		throttle.BlockedUntil = *blocked
	}
	return throttle, nil
}

func (store *PostgresStore) RecordLoginFailure(ctx context.Context, key string, value LoginThrottle) error {
	var blocked any
	if !value.BlockedUntil.IsZero() {
		blocked = value.BlockedUntil
	}
	_, err := store.pool.Exec(ctx, `
		INSERT INTO login_throttles (throttle_key, failures, window_start, blocked_until)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (throttle_key) DO UPDATE SET failures = EXCLUDED.failures, window_start = EXCLUDED.window_start, blocked_until = EXCLUDED.blocked_until`,
		key, value.Failures, value.WindowStart, blocked)
	return err
}

func (store *PostgresStore) ClearLoginFailures(ctx context.Context, key string) error {
	_, err := store.pool.Exec(ctx, `DELETE FROM login_throttles WHERE throttle_key = $1`, key)
	return err
}

func (store *PostgresStore) CreateGrant(ctx context.Context, grant ConnectionGrant) error {
	_, err := store.pool.Exec(ctx, `
		INSERT INTO connection_grants (grant_id, token_digest, device_name, created_at, last_seen_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`, grant.GrantID, grant.TokenDigest[:], grant.DeviceName, grant.CreatedAt, grant.LastSeenAt, grant.ExpiresAt)
	return err
}

func (store *PostgresStore) Grant(ctx context.Context, digest [32]byte, now time.Time) (ConnectionGrant, error) {
	var grant ConnectionGrant
	var token []byte
	var revoked *time.Time
	err := store.pool.QueryRow(ctx, `
		UPDATE connection_grants SET last_seen_at = $2
		WHERE token_digest = $1 AND revoked_at IS NULL AND expires_at > $2
		RETURNING grant_id, token_digest, device_name, created_at, last_seen_at, expires_at, revoked_at`, digest[:], now).Scan(
		&grant.GrantID, &token, &grant.DeviceName, &grant.CreatedAt, &grant.LastSeenAt, &grant.ExpiresAt, &revoked,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return ConnectionGrant{}, ErrInvalidCredential
	}
	if err != nil || len(token) != 32 {
		return ConnectionGrant{}, err
	}
	copy(grant.TokenDigest[:], token)
	if revoked != nil {
		grant.RevokedAt = *revoked
	}
	return grant, nil
}

func (store *PostgresStore) ListGrants(ctx context.Context) ([]ConnectionGrant, error) {
	rows, err := store.pool.Query(ctx, `
		SELECT grant_id, token_digest, device_name, created_at, last_seen_at, expires_at, revoked_at
		FROM connection_grants ORDER BY created_at, grant_id LIMIT 512`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []ConnectionGrant
	for rows.Next() {
		var grant ConnectionGrant
		var token []byte
		var revoked *time.Time
		if err := rows.Scan(&grant.GrantID, &token, &grant.DeviceName, &grant.CreatedAt, &grant.LastSeenAt, &grant.ExpiresAt, &revoked); err != nil {
			return nil, err
		}
		if len(token) != 32 {
			return nil, errors.New("stored connection grant digest is invalid")
		}
		copy(grant.TokenDigest[:], token)
		if revoked != nil {
			grant.RevokedAt = *revoked
		}
		result = append(result, grant)
	}
	return result, rows.Err()
}

func (store *PostgresStore) RevokeGrant(ctx context.Context, grantID uuid.UUID, now time.Time) error {
	result, err := store.pool.Exec(ctx, `UPDATE connection_grants SET revoked_at = COALESCE(revoked_at, $2) WHERE grant_id = $1`, grantID, now)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrInvalidCredential
	}
	return nil
}

func (store *PostgresStore) RevokeAllGrants(ctx context.Context, now time.Time) error {
	_, err := store.pool.Exec(ctx, `UPDATE connection_grants SET revoked_at = COALESCE(revoked_at, $1)`, now)
	return err
}

func (store *PostgresStore) CreateConnectionInvitation(
	ctx context.Context,
	invitation ConnectionInvitation,
) error {
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `
		DELETE FROM connection_invitations
		WHERE approval_code_digest = $1 AND (expires_at <= $2 OR redeemed_at IS NOT NULL)`,
		invitation.ApprovalCodeDigest[:], invitation.CreatedAt); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO connection_invitations
			(invitation_id, approval_code_digest, created_at, expires_at)
		VALUES ($1, $2, $3, $4)`, invitation.InvitationID,
		invitation.ApprovalCodeDigest[:], invitation.CreatedAt,
		invitation.ExpiresAt); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (store *PostgresStore) RedeemConnectionInvitation(
	ctx context.Context,
	digest [32]byte,
	request ConnectionRequest,
	now time.Time,
) error {
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var invitationID uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT invitation_id FROM connection_invitations
		WHERE approval_code_digest = $1 AND expires_at > $2
		  AND redeemed_at IS NULL
		FOR UPDATE`, digest[:], now).Scan(&invitationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrInvalidCredential
	}
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO connection_requests
			(request_id, poll_token_digest, approval_code_digest,
			 client_public_key, device_name, created_at, expires_at, authorized_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, request.RequestID,
		request.PollTokenDigest[:], request.ApprovalCodeDigest[:],
		request.ClientPublicKey[:], request.DeviceName, request.CreatedAt,
		request.ExpiresAt, now); err != nil {
		return err
	}
	result, err := tx.Exec(ctx, `
		UPDATE connection_invitations
		SET redeemed_request_id = $2, redeemed_at = $3
		WHERE invitation_id = $1 AND redeemed_at IS NULL`, invitationID,
		request.RequestID, now)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrRequestReplay
	}
	return tx.Commit(ctx)
}

func (store *PostgresStore) CreateConnectionRequest(ctx context.Context, request ConnectionRequest) error {
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM connection_requests WHERE approval_code_digest = $1 AND expires_at <= $2`, request.ApprovalCodeDigest[:], request.CreatedAt); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO connection_requests (request_id, poll_token_digest, approval_code_digest, client_public_key, device_name, created_at, expires_at, authorized_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NULL)`, request.RequestID, request.PollTokenDigest[:], request.ApprovalCodeDigest[:], request.ClientPublicKey[:], request.DeviceName, request.CreatedAt, request.ExpiresAt); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (store *PostgresStore) ConnectionRequest(ctx context.Context, requestID uuid.UUID) (ConnectionRequest, error) {
	var request ConnectionRequest
	var poll, approvalCode, publicKey []byte
	var authorizedAt *time.Time
	err := store.pool.QueryRow(ctx, `
		SELECT request_id, poll_token_digest, approval_code_digest, client_public_key, device_name, created_at, expires_at, authorized_at, encrypted_result
		FROM connection_requests WHERE request_id = $1`, requestID).Scan(
		&request.RequestID, &poll, &approvalCode, &publicKey, &request.DeviceName, &request.CreatedAt, &request.ExpiresAt, &authorizedAt, &request.EncryptedResult,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return ConnectionRequest{}, ErrInvalidCredential
	}
	if err != nil || len(poll) != 32 || len(approvalCode) != 32 || len(publicKey) != 32 {
		return ConnectionRequest{}, err
	}
	copy(request.PollTokenDigest[:], poll)
	copy(request.ApprovalCodeDigest[:], approvalCode)
	copy(request.ClientPublicKey[:], publicKey)
	if authorizedAt != nil {
		request.AuthorizedAt = *authorizedAt
	}
	return request, nil
}

func (store *PostgresStore) CompleteConnectionRequest(ctx context.Context, requestID uuid.UUID, result []byte) error {
	command, err := store.pool.Exec(ctx, `
		UPDATE connection_requests SET encrypted_result = $2
		WHERE request_id = $1 AND authorized_at IS NOT NULL
		  AND octet_length(encrypted_result) = 0`, requestID, result)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrRequestReplay
	}
	return nil
}

func (store *PostgresStore) AppendAudit(ctx context.Context, event AuditEvent) error {
	_, err := store.pool.Exec(ctx, `INSERT INTO audit_events (occurred_at, kind, outcome) VALUES ($1, $2, $3)`, event.OccurredAt, event.Kind, event.Outcome)
	return err
}

func (store *PostgresStore) RecentAudit(ctx context.Context, limit int) ([]AuditEvent, error) {
	if limit < 1 || limit > 100 {
		limit = 20
	}
	rows, err := store.pool.Query(ctx, `SELECT occurred_at, kind, outcome FROM audit_events ORDER BY sequence DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []AuditEvent
	for rows.Next() {
		var event AuditEvent
		if err := rows.Scan(&event.OccurredAt, &event.Kind, &event.Outcome); err != nil {
			return nil, err
		}
		result = append(result, event)
	}
	return result, rows.Err()
}
