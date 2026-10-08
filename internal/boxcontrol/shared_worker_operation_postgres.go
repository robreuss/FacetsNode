package boxcontrol

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type sharedWorkerOperationScanner interface {
	Scan(dest ...any) error
}

const sharedWorkerOperationColumns = `
	o.operation_id, o.box_id, o.worker_id, o.access_grant_id,
	o.requester_participant_id, o.requester_device_id, o.connection_grant_id,
	o.job_id, o.run_id, o.attempt, o.capabilities_digest, o.request_digest,
	o.request_bytes, o.requested_at_milliseconds, o.expires_at_milliseconds,
	o.state, o.claim_id, o.claimed_at_milliseconds,
	o.claim_expires_at_milliseconds, o.response_owner_participant_id,
	o.response_owner_device_id, o.response_digest, o.response_bytes,
	o.responded_at_milliseconds`

func scanSharedWorkerOperation(row sharedWorkerOperationScanner) (BoxSharedWorkerOperation, error) {
	var value BoxSharedWorkerOperation
	var attempt int64
	var claimID *uuid.UUID
	var responseOwnerParticipantID, responseOwnerDeviceID *uuid.UUID
	var responseDigest string
	var responseBytes []byte
	var respondedAtMilliseconds int64
	value.Version = 1
	err := row.Scan(
		&value.OperationID, &value.BoxID, &value.WorkerID, &value.AccessGrantID,
		&value.RequesterParticipantID, &value.RequesterDeviceID, &value.ConnectionGrantID,
		&value.JobID, &value.RunID, &attempt, &value.CapabilitiesDigest, &value.RequestDigest,
		&value.RequestBytes, &value.RequestedAtMilliseconds, &value.ExpiresAtMilliseconds,
		&value.State, &claimID, &value.ClaimedAtMilliseconds,
		&value.ClaimExpiresAtMilliseconds, &responseOwnerParticipantID,
		&responseOwnerDeviceID, &responseDigest, &responseBytes,
		&respondedAtMilliseconds,
	)
	if err != nil {
		return BoxSharedWorkerOperation{}, err
	}
	if attempt <= 0 {
		return BoxSharedWorkerOperation{}, ErrSharedWorkerOperation
	}
	value.Attempt = uint64(attempt)
	if claimID != nil {
		value.ClaimID = *claimID
	}
	if value.State == SharedWorkerOperationResponseReady {
		if responseOwnerParticipantID == nil || responseOwnerDeviceID == nil {
			return BoxSharedWorkerOperation{}, ErrSharedWorkerOperation
		}
		value.Response = &BoxSharedWorkerOperationResponse{
			Version: 1, OperationID: value.OperationID, ClaimID: value.ClaimID,
			BoxID: value.BoxID, WorkerID: value.WorkerID,
			OwnerParticipantID: *responseOwnerParticipantID,
			OwnerDeviceID:      *responseOwnerDeviceID,
			ResponseDigest:     responseDigest, ResponseBytes: responseBytes,
			RespondedAtMilliseconds: respondedAtMilliseconds,
		}
	}
	return value, nil
}

func (store *PostgresStore) EnqueueSharedWorkerOperation(
	ctx context.Context,
	value BoxSharedWorkerOperation,
	nowMilliseconds int64,
) error {
	if !value.validAt(nowMilliseconds) {
		return ErrSharedWorkerOperation
	}
	result, err := store.pool.Exec(ctx, `
		INSERT INTO box_shared_worker_operations
			(operation_id, box_id, worker_id, access_grant_id,
			 requester_participant_id, requester_device_id, connection_grant_id,
			 job_id, run_id, attempt, capabilities_digest, request_digest,
			 request_bytes, requested_at_milliseconds, expires_at_milliseconds, state)
		SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,'queued'
		FROM box_state s
		JOIN box_shared_workers w ON w.box_id = s.box_id AND w.worker_id = $3
		JOIN box_shared_worker_access_grants g ON g.box_id = s.box_id AND g.grant_id = $4
		JOIN box_shared_worker_access_requests r ON r.request_id = g.request_id
		JOIN box_participants p ON p.box_id = s.box_id AND p.participant_id = $5
		JOIN box_participant_devices d ON d.participant_id = p.participant_id AND d.device_id = $6
		JOIN connection_grants c ON c.grant_id = $7
		WHERE s.box_id = $2 AND s.owner_verifier <> ''
		  AND w.expires_at_milliseconds > $16 AND w.capabilities_digest = $11
		  AND g.worker_id = w.worker_id AND g.owner_participant_id = w.owner_participant_id
		  AND g.owner_device_id = w.owner_device_id AND g.grantee_participant_id = $5
		  AND g.capabilities_digest = $11 AND g.granted_at_milliseconds <= $16
		  AND g.expires_at_milliseconds > $16 AND g.revoked_at_milliseconds = 0
		  AND r.connection_grant_id = $7 AND r.decision = 'approved'
		  AND p.revoked_at_milliseconds = 0
		  AND d.revoked_through_generation < d.device_generation
		  AND c.revoked_at IS NULL AND c.expires_at > $17
		ON CONFLICT (operation_id) DO NOTHING`,
		value.OperationID, value.BoxID, value.WorkerID, value.AccessGrantID,
		value.RequesterParticipantID, value.RequesterDeviceID, value.ConnectionGrantID,
		value.JobID, value.RunID, int64(value.Attempt), value.CapabilitiesDigest,
		value.RequestDigest, value.RequestBytes, value.RequestedAtMilliseconds,
		value.ExpiresAtMilliseconds, nowMilliseconds, time.UnixMilli(nowMilliseconds))
	if err != nil {
		return err
	}
	if result.RowsAffected() == 1 {
		return nil
	}
	existing, err := scanSharedWorkerOperation(store.pool.QueryRow(ctx,
		`SELECT `+sharedWorkerOperationColumns+`
		 FROM box_shared_worker_operations o WHERE o.operation_id = $1`, value.OperationID))
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrSharedWorkerOperation
	}
	if err != nil {
		return err
	}
	if sameSharedWorkerOperation(existing, value) {
		return nil
	}
	return ErrSharedWorkerOperationCollision
}

func (store *PostgresStore) ClaimSharedWorkerOperation(
	ctx context.Context,
	claim BoxSharedWorkerOperationClaim,
	nowMilliseconds int64,
) (*BoxSharedWorkerOperation, error) {
	if !claim.validAt(nowMilliseconds) {
		return nil, ErrSharedWorkerOperation
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `
		UPDATE box_shared_worker_operations
		SET state = 'expired', claim_id = NULL,
		    claimed_at_milliseconds = 0, claim_expires_at_milliseconds = 0
		WHERE state IN ('queued','claimed') AND expires_at_milliseconds <= $1`,
		nowMilliseconds); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE box_shared_worker_operations
		SET state = 'queued', claim_id = NULL,
		    claimed_at_milliseconds = 0, claim_expires_at_milliseconds = 0
		WHERE state = 'claimed' AND claim_expires_at_milliseconds <= $1
		  AND expires_at_milliseconds > $1`, nowMilliseconds); err != nil {
		return nil, err
	}
	operation, err := scanSharedWorkerOperation(tx.QueryRow(ctx,
		`SELECT `+sharedWorkerOperationColumns+`
		 FROM box_shared_worker_operations o
		 JOIN box_shared_workers w ON w.worker_id = o.worker_id AND w.box_id = o.box_id
		 JOIN box_shared_worker_access_grants g ON g.grant_id = o.access_grant_id
		 JOIN box_participants p ON p.participant_id = w.owner_participant_id AND p.box_id = w.box_id
		 JOIN box_participant_devices d ON d.participant_id = p.participant_id AND d.device_id = w.owner_device_id
		 JOIN connection_grants c ON c.grant_id = o.connection_grant_id
		 WHERE o.box_id = $1 AND o.worker_id = $2 AND o.state = 'queued'
		   AND o.expires_at_milliseconds > $5
		   AND w.owner_participant_id = $3 AND w.owner_device_id = $4
		   AND w.expires_at_milliseconds > $5
		   AND p.revoked_at_milliseconds = 0
		   AND d.revoked_through_generation < d.device_generation
		   AND g.worker_id = o.worker_id AND g.box_id = o.box_id
		   AND g.owner_participant_id = $3 AND g.owner_device_id = $4
		   AND g.grantee_participant_id = o.requester_participant_id
		   AND g.capabilities_digest = o.capabilities_digest
		   AND g.granted_at_milliseconds <= $5
		   AND g.expires_at_milliseconds > $5 AND g.revoked_at_milliseconds = 0
		   AND c.revoked_at IS NULL AND c.expires_at > $6
		 ORDER BY o.requested_at_milliseconds, o.operation_id
		 FOR UPDATE OF o SKIP LOCKED LIMIT 1`,
		claim.BoxID, claim.WorkerID, claim.OwnerParticipantID, claim.OwnerDeviceID,
		nowMilliseconds, time.UnixMilli(nowMilliseconds)))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrSharedWorkerOperationNoWork
	}
	if err != nil {
		return nil, err
	}
	result, err := tx.Exec(ctx, `
		UPDATE box_shared_worker_operations
		SET state = 'claimed', claim_id = $2, claimed_at_milliseconds = $3,
		    claim_expires_at_milliseconds = $4
		WHERE operation_id = $1 AND state = 'queued'`, operation.OperationID,
		claim.ClaimID, nowMilliseconds, claim.ExpiresAtMilliseconds)
	if err != nil {
		return nil, err
	}
	if result.RowsAffected() != 1 {
		return nil, ErrSharedWorkerOperationNoWork
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	operation.State = SharedWorkerOperationClaimed
	operation.ClaimID = claim.ClaimID
	operation.ClaimedAtMilliseconds = nowMilliseconds
	operation.ClaimExpiresAtMilliseconds = claim.ExpiresAtMilliseconds
	operation.ConnectionGrantID = uuid.Nil
	return &operation, nil
}

func (store *PostgresStore) CompleteSharedWorkerOperation(
	ctx context.Context,
	response BoxSharedWorkerOperationResponse,
	nowMilliseconds int64,
) error {
	if !response.validAt(nowMilliseconds) {
		return ErrSharedWorkerOperation
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	operation, err := scanSharedWorkerOperation(tx.QueryRow(ctx,
		`SELECT `+sharedWorkerOperationColumns+`
		 FROM box_shared_worker_operations o
		 WHERE o.operation_id = $1 FOR UPDATE`, response.OperationID))
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrSharedWorkerOperation
	}
	if err != nil {
		return err
	}
	if operation.State == SharedWorkerOperationResponseReady && operation.Response != nil {
		if sameSharedWorkerOperationResponse(*operation.Response, response) {
			return nil
		}
		return ErrSharedWorkerOperationCollision
	}
	result, err := tx.Exec(ctx, `
		UPDATE box_shared_worker_operations o
		SET state = 'response-ready', response_owner_participant_id = $5,
		    response_owner_device_id = $6, response_digest = $7,
		    response_bytes = $8, responded_at_milliseconds = $9
		FROM box_shared_workers w, box_shared_worker_access_grants g,
		     box_participants p, box_participant_devices d
		WHERE o.operation_id = $1 AND o.state = 'claimed' AND o.claim_id = $2
		  AND o.box_id = $3 AND o.worker_id = $4
		  AND o.claim_expires_at_milliseconds > $10 AND o.expires_at_milliseconds > $10
		  AND w.worker_id = o.worker_id AND w.box_id = o.box_id
		  AND w.owner_participant_id = $5 AND w.owner_device_id = $6
		  AND w.expires_at_milliseconds > $10
		  AND g.grant_id = o.access_grant_id AND g.box_id = o.box_id
		  AND g.worker_id = o.worker_id AND g.owner_participant_id = $5
		  AND g.owner_device_id = $6 AND g.grantee_participant_id = o.requester_participant_id
		  AND g.capabilities_digest = o.capabilities_digest
		  AND g.granted_at_milliseconds <= $10
		  AND g.expires_at_milliseconds > $10 AND g.revoked_at_milliseconds = 0
		  AND p.participant_id = $5 AND p.box_id = o.box_id AND p.revoked_at_milliseconds = 0
		  AND d.participant_id = p.participant_id AND d.device_id = $6
		  AND d.revoked_through_generation < d.device_generation`,
		response.OperationID, response.ClaimID, response.BoxID, response.WorkerID,
		response.OwnerParticipantID, response.OwnerDeviceID,
		response.ResponseDigest, response.ResponseBytes, response.RespondedAtMilliseconds,
		nowMilliseconds)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrSharedWorkerOperation
	}
	return tx.Commit(ctx)
}

func (store *PostgresStore) SharedWorkerOperationStatus(
	ctx context.Context,
	operationID, connectionGrantID uuid.UUID,
	nowMilliseconds int64,
) (BoxSharedWorkerOperationStatus, error) {
	if operationID == uuid.Nil || connectionGrantID == uuid.Nil || nowMilliseconds <= 0 {
		return BoxSharedWorkerOperationStatus{}, ErrSharedWorkerOperation
	}
	_, err := store.pool.Exec(ctx, `
		UPDATE box_shared_worker_operations
		SET state = 'expired', claim_id = NULL,
		    claimed_at_milliseconds = 0, claim_expires_at_milliseconds = 0
		WHERE operation_id = $1 AND connection_grant_id = $2
		  AND state IN ('queued','claimed') AND expires_at_milliseconds <= $3`,
		operationID, connectionGrantID, nowMilliseconds)
	if err != nil {
		return BoxSharedWorkerOperationStatus{}, err
	}
	operation, err := scanSharedWorkerOperation(store.pool.QueryRow(ctx,
		`SELECT `+sharedWorkerOperationColumns+`
		 FROM box_shared_worker_operations o
		 JOIN connection_grants c ON c.grant_id = o.connection_grant_id
		 WHERE o.operation_id = $1 AND o.connection_grant_id = $2
		   AND c.revoked_at IS NULL AND c.expires_at > $3`,
		operationID, connectionGrantID, time.UnixMilli(nowMilliseconds)))
	if errors.Is(err, pgx.ErrNoRows) {
		return BoxSharedWorkerOperationStatus{}, ErrSharedWorkerOperation
	}
	if err != nil {
		return BoxSharedWorkerOperationStatus{}, err
	}
	status := BoxSharedWorkerOperationStatus{
		Version: 1, OperationID: operation.OperationID, State: operation.State,
		ExpiresAtMilliseconds: operation.ExpiresAtMilliseconds,
	}
	if operation.Response != nil {
		status.Response = operation.Response
	}
	return status, nil
}
