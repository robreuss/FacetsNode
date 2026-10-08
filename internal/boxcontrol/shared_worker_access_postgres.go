package boxcontrol

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func (store *PostgresStore) CreateSharedWorkerAccessRequest(
	ctx context.Context,
	value BoxSharedWorkerAccessRequest,
	nowMilliseconds int64,
) error {
	if !value.validAt(nowMilliseconds) {
		return ErrSharedWorkerAccess
	}
	result, err := store.pool.Exec(ctx, `
		WITH expired AS (
			UPDATE box_shared_worker_access_requests
			SET decision = 'expired', decided_at_milliseconds = $11
			WHERE decision = 'pending' AND expires_at_milliseconds <= $11
			RETURNING request_id
		)
		INSERT INTO box_shared_worker_access_requests
			(request_id, box_id, worker_id, requester_participant_id, requester_device_id,
			 connection_grant_id, capabilities_digest, confirmation_code_digest,
			 requested_at_milliseconds, expires_at_milliseconds)
		SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10
		FROM box_state s
		JOIN box_shared_workers w ON w.box_id = s.box_id AND w.worker_id = $3
		JOIN box_participants p ON p.box_id = s.box_id AND p.participant_id = $4
		JOIN box_participant_devices d ON d.participant_id = p.participant_id AND d.device_id = $5
		JOIN connection_grants c ON c.grant_id = $6
		WHERE s.box_id = $2 AND s.owner_verifier <> ''
		  AND w.expires_at_milliseconds > $11 AND w.capabilities_digest = $7
		  AND w.owner_participant_id <> $4
		  AND p.revoked_at_milliseconds = 0
		  AND d.revoked_through_generation < d.device_generation
		  AND c.revoked_at IS NULL AND c.expires_at > $12
		ON CONFLICT (request_id) DO NOTHING`,
		value.RequestID, value.BoxID, value.WorkerID, value.RequesterParticipantID,
		value.RequesterDeviceID, value.ConnectionGrantID, value.CapabilitiesDigest,
		value.ConfirmationCodeDigest[:], value.RequestedAtMilliseconds,
		value.ExpiresAtMilliseconds, nowMilliseconds, time.UnixMilli(nowMilliseconds))
	if err != nil {
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) && postgresError.Code == "23505" {
			return ErrSharedWorkerAccessCodeCollision
		}
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrSharedWorkerAccess
	}
	return nil
}

func (store *PostgresStore) SharedWorkerAccessRequest(
	ctx context.Context,
	requestID, connectionGrantID uuid.UUID,
	nowMilliseconds int64,
) (BoxSharedWorkerAccessRequestStatus, error) {
	if requestID == uuid.Nil || connectionGrantID == uuid.Nil || nowMilliseconds <= 0 {
		return BoxSharedWorkerAccessRequestStatus{}, ErrSharedWorkerAccess
	}
	_, err := store.pool.Exec(ctx, `
		UPDATE box_shared_worker_access_requests
		SET decision = 'expired', decided_at_milliseconds = $3
		WHERE request_id = $1 AND connection_grant_id = $2
		  AND decision = 'pending' AND expires_at_milliseconds <= $3`,
		requestID, connectionGrantID, nowMilliseconds)
	if err != nil {
		return BoxSharedWorkerAccessRequestStatus{}, err
	}
	status := BoxSharedWorkerAccessRequestStatus{Version: 1}
	var grantID *uuid.UUID
	var grant *BoxSharedWorkerAccessGrant
	row := store.pool.QueryRow(ctx, `
		SELECT r.request_id, r.decision, r.expires_at_milliseconds, r.decided_at_milliseconds,
		       g.grant_id
		FROM box_shared_worker_access_requests r
		JOIN connection_grants c ON c.grant_id = r.connection_grant_id
		LEFT JOIN box_shared_worker_access_grants g ON g.request_id = r.request_id
		WHERE r.request_id = $1 AND r.connection_grant_id = $2
		  AND c.revoked_at IS NULL AND c.expires_at > $3`,
		requestID, connectionGrantID, time.UnixMilli(nowMilliseconds))
	if err := row.Scan(&status.RequestID, &status.Decision, &status.ExpiresAtMilliseconds,
		&status.DecidedAtMilliseconds, &grantID); errors.Is(err, pgx.ErrNoRows) {
		return BoxSharedWorkerAccessRequestStatus{}, ErrSharedWorkerAccess
	} else if err != nil {
		return BoxSharedWorkerAccessRequestStatus{}, err
	}
	if grantID != nil {
		value, err := store.sharedWorkerAccessGrant(ctx, *grantID)
		if err != nil {
			return BoxSharedWorkerAccessRequestStatus{}, err
		}
		grant = &value
	}
	status.Grant = grant
	return status, nil
}

func (store *PostgresStore) sharedWorkerAccessGrant(
	ctx context.Context,
	grantID uuid.UUID,
) (BoxSharedWorkerAccessGrant, error) {
	var value BoxSharedWorkerAccessGrant
	var revision int64
	value.Version = 1
	err := store.pool.QueryRow(ctx, `
		SELECT grant_id, request_id, box_id, worker_id, owner_participant_id,
		       owner_device_id, grantee_participant_id, capabilities_digest,
		       confirmation_code_digest, revision, granted_at_milliseconds,
		       expires_at_milliseconds, revoked_at_milliseconds
		FROM box_shared_worker_access_grants WHERE grant_id = $1`, grantID).Scan(
		&value.GrantID, &value.RequestID, &value.BoxID, &value.WorkerID,
		&value.OwnerParticipantID, &value.OwnerDeviceID, &value.GranteeParticipantID,
		&value.CapabilitiesDigest, &value.ConfirmationCodeDigest, &revision,
		&value.GrantedAtMilliseconds, &value.ExpiresAtMilliseconds,
		&value.RevokedAtMilliseconds)
	if errors.Is(err, pgx.ErrNoRows) {
		return BoxSharedWorkerAccessGrant{}, ErrSharedWorkerAccess
	}
	if err != nil {
		return BoxSharedWorkerAccessGrant{}, err
	}
	if revision <= 0 {
		return BoxSharedWorkerAccessGrant{}, ErrSharedWorkerAccess
	}
	value.Revision = uint64(revision)
	return value, nil
}

func (store *PostgresStore) ConfirmSharedWorkerAccess(
	ctx context.Context,
	grant BoxSharedWorkerAccessGrant,
	codeDigest [32]byte,
	nowMilliseconds int64,
) error {
	if !grant.validAt(nowMilliseconds) || grant.Revision > math.MaxInt64 ||
		sharedWorkerAccessCodeDigestString(codeDigest) != grant.ConfirmationCodeDigest {
		return ErrSharedWorkerAccess
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var request BoxSharedWorkerAccessRequest
	var storedCode []byte
	var grantOwnerParticipantID, grantOwnerDeviceID uuid.UUID
	request.Decision = SharedWorkerAccessPending
	err = tx.QueryRow(ctx, `
		SELECT r.request_id, r.box_id, r.worker_id, r.requester_participant_id,
		       r.requester_device_id, r.capabilities_digest, r.confirmation_code_digest,
		       r.requested_at_milliseconds, r.expires_at_milliseconds,
		       r.failed_code_attempts, r.decision,
		       w.owner_participant_id, w.owner_device_id
		FROM box_shared_worker_access_requests r
		JOIN box_state s ON s.box_id = r.box_id AND s.owner_verifier <> ''
		JOIN box_shared_workers w ON w.worker_id = r.worker_id AND w.box_id = r.box_id
		JOIN box_participants owner ON owner.participant_id = w.owner_participant_id AND owner.box_id = r.box_id
		JOIN box_participant_devices owner_device ON owner_device.participant_id = owner.participant_id AND owner_device.device_id = w.owner_device_id
		JOIN box_participants grantee ON grantee.participant_id = r.requester_participant_id AND grantee.box_id = r.box_id
		JOIN box_participant_devices grantee_device ON grantee_device.participant_id = grantee.participant_id AND grantee_device.device_id = r.requester_device_id
		WHERE r.request_id = $1 AND r.decision = 'pending'
		  AND r.expires_at_milliseconds > $2 AND w.expires_at_milliseconds > $2
		  AND owner.revoked_at_milliseconds = 0
		  AND owner_device.revoked_through_generation < owner_device.device_generation
		  AND grantee.revoked_at_milliseconds = 0
		  AND grantee_device.revoked_through_generation < grantee_device.device_generation
		FOR UPDATE OF r, w, owner, owner_device, grantee, grantee_device`,
		grant.RequestID, nowMilliseconds).Scan(
		&request.RequestID, &request.BoxID, &request.WorkerID,
		&request.RequesterParticipantID, &request.RequesterDeviceID,
		&request.CapabilitiesDigest, &storedCode, &request.RequestedAtMilliseconds,
		&request.ExpiresAtMilliseconds, &request.FailedCodeAttempts, &request.Decision,
		&grantOwnerParticipantID, &grantOwnerDeviceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrSharedWorkerAccess
	}
	if err != nil {
		return err
	}
	copy(request.ConfirmationCodeDigest[:], storedCode)
	if grantOwnerParticipantID != grant.OwnerParticipantID || grantOwnerDeviceID != grant.OwnerDeviceID ||
		request.BoxID != grant.BoxID || request.WorkerID != grant.WorkerID ||
		request.RequesterParticipantID != grant.GranteeParticipantID ||
		request.CapabilitiesDigest != grant.CapabilitiesDigest {
		return ErrSharedWorkerAccess
	}
	if request.ConfirmationCodeDigest != codeDigest {
		request.FailedCodeAttempts++
		decision := SharedWorkerAccessPending
		decidedAt := int64(0)
		resultErr := ErrSharedWorkerAccessCode
		if request.FailedCodeAttempts >= maximumSharedWorkerAccessCodeFailures {
			decision = SharedWorkerAccessRejected
			decidedAt = nowMilliseconds
			resultErr = ErrSharedWorkerAccessLocked
		}
		if _, err := tx.Exec(ctx, `UPDATE box_shared_worker_access_requests
			SET failed_code_attempts = $2, decision = $3, decided_at_milliseconds = $4
			WHERE request_id = $1`, request.RequestID, request.FailedCodeAttempts,
			decision, decidedAt); err != nil {
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
		return resultErr
	}
	result, err := tx.Exec(ctx, `
		INSERT INTO box_shared_worker_access_grants
			(grant_id, request_id, box_id, worker_id, owner_participant_id,
			 owner_device_id, grantee_participant_id, capabilities_digest,
			 confirmation_code_digest, revision, granted_at_milliseconds,
			 expires_at_milliseconds)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		ON CONFLICT DO NOTHING`, grant.GrantID, grant.RequestID, grant.BoxID,
		grant.WorkerID, grant.OwnerParticipantID, grant.OwnerDeviceID,
		grant.GranteeParticipantID, grant.CapabilitiesDigest,
		grant.ConfirmationCodeDigest, int64(grant.Revision),
		grant.GrantedAtMilliseconds, grant.ExpiresAtMilliseconds)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrSharedWorkerAccess
	}
	result, err = tx.Exec(ctx, `UPDATE box_shared_worker_access_requests
		SET decision = 'approved', decided_at_milliseconds = $2
		WHERE request_id = $1 AND decision = 'pending'`, grant.RequestID, nowMilliseconds)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrSharedWorkerAccess
	}
	return tx.Commit(ctx)
}

func (store *PostgresStore) RevokeSharedWorkerAccess(
	ctx context.Context,
	boxID, grantID, ownerParticipantID uuid.UUID,
	revision uint64,
	nowMilliseconds int64,
) error {
	if boxID == uuid.Nil || grantID == uuid.Nil || ownerParticipantID == uuid.Nil ||
		revision == 0 || revision > math.MaxInt64 || nowMilliseconds <= 0 {
		return ErrSharedWorkerAccess
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	result, err := tx.Exec(ctx, `
		UPDATE box_shared_worker_access_grants g
		SET revision = $4, revoked_at_milliseconds = $5
		FROM box_participants p
		WHERE g.grant_id = $2 AND g.box_id = $1 AND g.owner_participant_id = $3
		  AND g.revoked_at_milliseconds = 0 AND g.revision < $4
		  AND p.participant_id = g.owner_participant_id AND p.box_id = g.box_id
		  AND p.revoked_at_milliseconds = 0`,
		boxID, grantID, ownerParticipantID, int64(revision), nowMilliseconds)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrSharedWorkerAccess
	}
	result, err = tx.Exec(ctx, `UPDATE box_shared_worker_access_requests r
		SET decision = 'revoked', decided_at_milliseconds = $2
		FROM box_shared_worker_access_grants g
		WHERE g.grant_id = $1 AND r.request_id = g.request_id`, grantID, nowMilliseconds)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrSharedWorkerAccess
	}
	return tx.Commit(ctx)
}
