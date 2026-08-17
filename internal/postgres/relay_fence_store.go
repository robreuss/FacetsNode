package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/robreuss/FacetsNode/internal/relay"
)

type storedFence struct {
	state                         relay.CheckpointFenceState
	retryID, holderSubscriptionID uuid.UUID
	requestedAt                   int64
	abortRetryID                  *uuid.UUID
	abortedAt                     *int64
}

func (s *RelayStore) CreateCheckpointFence(ctx context.Context, credential relay.Credential, request relay.CheckpointFenceRequest, now int64) (relay.CheckpointFenceResponse, error) {
	if err := request.Validate(); err != nil {
		return relay.CheckpointFenceResponse{}, err
	}
	if request.RequestedAtMilliseconds > now {
		return relay.CheckpointFenceResponse{}, relay.NewProtocolError(relay.CodeInvalidCheckpointFence, "fence request is in the future")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return relay.CheckpointFenceResponse{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := loadRelayTenant(ctx, tx, credential.TenantID, "FOR UPDATE"); err != nil {
		return relay.CheckpointFenceResponse{}, err
	}
	_, _, _, _, _, last, err := loadRelayDomain(ctx, tx, credential.TenantID, credential.DomainID, "FOR UPDATE")
	if err != nil {
		return relay.CheckpointFenceResponse{}, err
	}
	subscriptionID, err := authorizeFenceMember(ctx, tx, credential, now)
	if err != nil {
		return relay.CheckpointFenceResponse{}, err
	}
	if err := expirePostgresFence(ctx, tx, credential.TenantID, credential.DomainID, now); err != nil {
		return relay.CheckpointFenceResponse{}, err
	}
	if existing, found, err := loadFenceByRetry(ctx, tx, credential.TenantID, credential.DomainID, request.RetryID); err != nil {
		return relay.CheckpointFenceResponse{}, err
	} else if found {
		if existing.state.FenceID == request.FenceID && existing.requestedAt == request.RequestedAtMilliseconds && existing.holderSubscriptionID == subscriptionID {
			return postgresFenceResponse(existing, request.RetryID, relay.AcceptanceDuplicate), nil
		}
		return relay.CheckpointFenceResponse{}, relay.NewProtocolError(relay.CodeCheckpointFenceCollision, "fence retry ID was reused")
	}
	if _, found, err := loadFence(ctx, tx, credential.TenantID, credential.DomainID, request.FenceID, "FOR UPDATE"); err != nil {
		return relay.CheckpointFenceResponse{}, err
	} else if found {
		return relay.CheckpointFenceResponse{}, relay.NewProtocolError(relay.CodeCheckpointFenceCollision, "fence ID was reused")
	}
	var active bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM relay_checkpoint_fences WHERE tenant_id=$1 AND domain_id=$2 AND status='active')`, credential.TenantID, credential.DomainID).Scan(&active); err != nil {
		return relay.CheckpointFenceResponse{}, err
	}
	if active {
		return relay.CheckpointFenceResponse{}, relay.NewProtocolError(relay.CodeCheckpointFenceActive, "domain already has an active fence")
	}
	expires := now + s.checkpointFenceTTL.Milliseconds()
	if _, err := tx.Exec(ctx, `INSERT INTO relay_checkpoint_fences (tenant_id,domain_id,fence_id,create_retry_id,holder_subscription_id,status,boundary_sequence,requested_at_milliseconds,acquired_at_milliseconds,expires_at_milliseconds) VALUES($1,$2,$3,$4,$5,'active',$6,$7,$8,$9)`, credential.TenantID, credential.DomainID, request.FenceID, request.RetryID, subscriptionID, last, request.RequestedAtMilliseconds, now, expires); err != nil {
		return relay.CheckpointFenceResponse{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return relay.CheckpointFenceResponse{}, err
	}
	return relay.CheckpointFenceResponse{Acceptance: relay.AcceptanceAccepted, RetryID: request.RetryID, FenceID: request.FenceID, BoundaryCursor: relay.EncodeCursor(uint64(last)), AcquiredAtMilliseconds: now, ExpiresAtMilliseconds: expires}, nil
}

func (s *RelayStore) GetCheckpointFence(ctx context.Context, credential relay.Credential, fenceID uuid.UUID, now int64) (relay.CheckpointFenceState, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return relay.CheckpointFenceState{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := loadRelayTenant(ctx, tx, credential.TenantID, "FOR UPDATE"); err != nil {
		return relay.CheckpointFenceState{}, err
	}
	if _, _, _, _, _, _, err := loadRelayDomain(ctx, tx, credential.TenantID, credential.DomainID, "FOR UPDATE"); err != nil {
		return relay.CheckpointFenceState{}, err
	}
	subscriptionID, err := authorizeFenceMember(ctx, tx, credential, now)
	if err != nil {
		return relay.CheckpointFenceState{}, err
	}
	if err := expirePostgresFence(ctx, tx, credential.TenantID, credential.DomainID, now); err != nil {
		return relay.CheckpointFenceState{}, err
	}
	fence, found, err := loadFence(ctx, tx, credential.TenantID, credential.DomainID, fenceID, "FOR UPDATE")
	if err != nil {
		return relay.CheckpointFenceState{}, err
	}
	if !found {
		return relay.CheckpointFenceState{}, relay.NewProtocolError(relay.CodeCheckpointFenceNotFound, "fence was not found")
	}
	if fence.holderSubscriptionID != subscriptionID {
		return relay.CheckpointFenceState{}, relay.NewProtocolError(relay.CodeWrongScope, "fence belongs to another subscription")
	}
	if err := tx.Commit(ctx); err != nil {
		return relay.CheckpointFenceState{}, err
	}
	return fence.state, nil
}

func (s *RelayStore) AbortCheckpointFence(ctx context.Context, credential relay.Credential, request relay.CheckpointFenceAbortRequest, now int64) (relay.CheckpointFenceAbortResponse, error) {
	if err := request.Validate(); err != nil {
		return relay.CheckpointFenceAbortResponse{}, err
	}
	if request.AbortedAtMilliseconds > now {
		return relay.CheckpointFenceAbortResponse{}, relay.NewProtocolError(relay.CodeInvalidCheckpointFence, "fence abort is in the future")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return relay.CheckpointFenceAbortResponse{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := loadRelayTenant(ctx, tx, credential.TenantID, "FOR UPDATE"); err != nil {
		return relay.CheckpointFenceAbortResponse{}, err
	}
	if _, _, _, _, _, _, err := loadRelayDomain(ctx, tx, credential.TenantID, credential.DomainID, "FOR UPDATE"); err != nil {
		return relay.CheckpointFenceAbortResponse{}, err
	}
	subscriptionID, err := authorizeFenceMember(ctx, tx, credential, now)
	if err != nil {
		return relay.CheckpointFenceAbortResponse{}, err
	}
	var storedFenceID, storedHolder uuid.UUID
	var storedAbort int64
	err = tx.QueryRow(ctx, `SELECT fence_id,holder_subscription_id,aborted_at_milliseconds FROM relay_checkpoint_fences WHERE tenant_id=$1 AND domain_id=$2 AND abort_retry_id=$3`, credential.TenantID, credential.DomainID, request.RetryID).Scan(&storedFenceID, &storedHolder, &storedAbort)
	if err == nil {
		if storedFenceID == request.FenceID && storedHolder == subscriptionID && storedAbort == request.AbortedAtMilliseconds {
			return relay.CheckpointFenceAbortResponse{Acceptance: relay.AcceptanceDuplicate, RetryID: request.RetryID, FenceID: request.FenceID, Status: relay.CheckpointFenceAborted}, nil
		}
		return relay.CheckpointFenceAbortResponse{}, relay.NewProtocolError(relay.CodeCheckpointFenceCollision, "fence abort retry ID was reused")
	}
	if err != pgx.ErrNoRows {
		return relay.CheckpointFenceAbortResponse{}, err
	}
	if err := expirePostgresFence(ctx, tx, credential.TenantID, credential.DomainID, now); err != nil {
		return relay.CheckpointFenceAbortResponse{}, err
	}
	fence, found, err := loadFence(ctx, tx, credential.TenantID, credential.DomainID, request.FenceID, "FOR UPDATE")
	if err != nil {
		return relay.CheckpointFenceAbortResponse{}, err
	}
	if !found {
		return relay.CheckpointFenceAbortResponse{}, relay.NewProtocolError(relay.CodeCheckpointFenceNotFound, "fence was not found")
	}
	if fence.holderSubscriptionID != subscriptionID {
		return relay.CheckpointFenceAbortResponse{}, relay.NewProtocolError(relay.CodeWrongScope, "fence belongs to another subscription")
	}
	if fence.state.Status != relay.CheckpointFenceActive {
		return relay.CheckpointFenceAbortResponse{}, relay.NewProtocolError(relay.CodeCheckpointFenceCollision, "fence is not active")
	}
	if _, err := tx.Exec(ctx, `UPDATE relay_checkpoint_fences SET status='aborted',abort_retry_id=$4,aborted_at_milliseconds=$5,updated_at=now() WHERE tenant_id=$1 AND domain_id=$2 AND fence_id=$3`, credential.TenantID, credential.DomainID, request.FenceID, request.RetryID, request.AbortedAtMilliseconds); err != nil {
		return relay.CheckpointFenceAbortResponse{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE relay_checkpoints SET state='invalidated',updated_at=now() WHERE tenant_id=$1 AND domain_id=$2 AND fence_id=$3 AND state='staged'`, credential.TenantID, credential.DomainID, request.FenceID); err != nil {
		return relay.CheckpointFenceAbortResponse{}, err
	}
	if err := cleanupPostgresFenceAuthority(ctx, tx, credential.TenantID, credential.DomainID, request.FenceID, now); err != nil {
		return relay.CheckpointFenceAbortResponse{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return relay.CheckpointFenceAbortResponse{}, err
	}
	return relay.CheckpointFenceAbortResponse{Acceptance: relay.AcceptanceAccepted, RetryID: request.RetryID, FenceID: request.FenceID, Status: relay.CheckpointFenceAborted}, nil
}

func authorizeFenceMember(ctx context.Context, q relayQuerier, c relay.Credential, now int64) (uuid.UUID, error) {
	m, found, err := loadRelayMember(ctx, q, c.TenantID, c.DomainID, c.MemberID, "FOR SHARE")
	if err != nil {
		return uuid.Nil, err
	}
	if !found {
		return uuid.Nil, relay.NewProtocolError(relay.CodeMemberNotFound, "member was not found")
	}
	if err := m.Authorize(c, relay.CapabilityPublishCheckpoint, now); err != nil {
		return uuid.Nil, err
	}
	return loadActiveMemberSubscription(ctx, q, c.TenantID, c.DomainID, c.MemberID, "FOR SHARE")
}
func expirePostgresFence(ctx context.Context, tx pgx.Tx, tenantID, domainID uuid.UUID, now int64) error {
	if _, err := tx.Exec(ctx, `UPDATE relay_checkpoint_fences SET status='expired',updated_at=now() WHERE tenant_id=$1 AND domain_id=$2 AND status='active' AND expires_at_milliseconds <= $3`, tenantID, domainID, now); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE relay_checkpoints c SET state='invalidated',updated_at=now() FROM relay_checkpoint_fences f WHERE c.tenant_id=$1 AND c.domain_id=$2 AND c.state='staged' AND c.fence_id=f.fence_id AND f.status='expired'`, tenantID, domainID); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT fence_id FROM relay_checkpoint_fences WHERE tenant_id=$1 AND domain_id=$2 AND status IN ('expired','aborted')`, tenantID, domainID)
	if err != nil {
		return err
	}
	var fenceIDs []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		fenceIDs = append(fenceIDs, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, fenceID := range fenceIDs {
		if err := cleanupPostgresFenceAuthority(ctx, tx, tenantID, domainID, fenceID, now); err != nil {
			return err
		}
	}
	return nil
}

func cleanupPostgresFenceAuthority(ctx context.Context, tx pgx.Tx, tenantID, domainID, fenceID uuid.UUID, now int64) error {
	const batch = 10_000
	var messageCount, messageBytes int64
	if err := tx.QueryRow(ctx, `WITH doomed AS (
		SELECT message_id FROM relay_messages WHERE tenant_id=$1 AND domain_id=$2 AND checkpoint_fence_id=$3 ORDER BY domain_sequence LIMIT $4
	), tombstoned AS (
		INSERT INTO relay_checkpoint_fence_message_tombstones (tenant_id,domain_id,message_id,fence_id,publisher_member_id,envelope_digest,domain_sequence,ciphertext_byte_count)
		SELECT m.tenant_id,m.domain_id,m.message_id,$3,m.publisher_member_id,m.envelope_digest,m.domain_sequence,m.ciphertext_byte_count
		FROM relay_messages m JOIN doomed d USING (message_id) WHERE m.tenant_id=$1 AND m.domain_id=$2 ON CONFLICT DO NOTHING
	), deleted AS (
		DELETE FROM relay_messages m USING doomed d WHERE m.tenant_id=$1 AND m.domain_id=$2 AND m.message_id=d.message_id RETURNING m.ciphertext_byte_count
	) SELECT count(*),COALESCE(sum(ciphertext_byte_count),0) FROM deleted`, tenantID, domainID, fenceID, batch).Scan(&messageCount, &messageBytes); err != nil {
		return err
	}
	if messageCount > 0 {
		if _, err := tx.Exec(ctx, `UPDATE relay_domains SET message_count=message_count-$3,message_byte_count=message_byte_count-$4 WHERE tenant_id=$1 AND domain_id=$2`, tenantID, domainID, messageCount, messageBytes); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE relay_tenants SET message_count=message_count-$2,aggregate_message_byte_count=aggregate_message_byte_count-$3 WHERE tenant_id=$1`, tenantID, messageCount, messageBytes); err != nil {
			return err
		}
	}
	var blobCount, blobBytes int64
	if err := tx.QueryRow(ctx, `WITH doomed AS (
		SELECT blob_id,byte_count FROM relay_blobs WHERE tenant_id=$1 AND domain_id=$2 AND checkpoint_fence_id=$3 ORDER BY blob_id LIMIT $4
	), queued AS (
		INSERT INTO relay_collected_blob_deletions (tenant_id,domain_id,blob_id,collected_at_milliseconds)
		SELECT $1,$2,blob_id,$5 FROM doomed ON CONFLICT (tenant_id,domain_id,blob_id) DO UPDATE SET collected_at_milliseconds=LEAST(relay_collected_blob_deletions.collected_at_milliseconds,EXCLUDED.collected_at_milliseconds)
	), deleted AS (
		DELETE FROM relay_blobs b USING doomed d WHERE b.tenant_id=$1 AND b.domain_id=$2 AND b.blob_id=d.blob_id RETURNING b.byte_count
	) SELECT count(*),COALESCE(sum(byte_count),0) FROM deleted`, tenantID, domainID, fenceID, batch, now).Scan(&blobCount, &blobBytes); err != nil {
		return err
	}
	if blobCount > 0 {
		if _, err := tx.Exec(ctx, `UPDATE relay_domains SET blob_count=blob_count-$3,blob_byte_count=blob_byte_count-$4 WHERE tenant_id=$1 AND domain_id=$2`, tenantID, domainID, blobCount, blobBytes); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE relay_tenants SET blob_count=blob_count-$2,aggregate_blob_byte_count=aggregate_blob_byte_count-$3 WHERE tenant_id=$1`, tenantID, blobCount, blobBytes); err != nil {
			return err
		}
	}
	for _, table := range []string{"relay_checkpoint_retained_messages", "relay_checkpoint_retained_blobs"} {
		if _, err := tx.Exec(ctx, `DELETE FROM `+table+` r USING relay_checkpoints c WHERE r.tenant_id=$1 AND r.domain_id=$2 AND r.checkpoint_id=c.checkpoint_id AND c.tenant_id=$1 AND c.domain_id=$2 AND c.fence_id=$3 AND c.state='invalidated'`, tenantID, domainID, fenceID); err != nil {
			return err
		}
	}
	return nil
}
func loadFence(ctx context.Context, q relayQuerier, tenantID, domainID, fenceID uuid.UUID, lock string) (storedFence, bool, error) {
	query := `SELECT create_retry_id,holder_subscription_id,status,boundary_sequence,requested_at_milliseconds,acquired_at_milliseconds,expires_at_milliseconds,abort_retry_id,aborted_at_milliseconds FROM relay_checkpoint_fences WHERE tenant_id=$1 AND domain_id=$2 AND fence_id=$3`
	if lock != "" {
		query += " " + lock
	}
	var f storedFence
	f.state.FenceID = fenceID
	var boundary int64
	err := q.QueryRow(ctx, query, tenantID, domainID, fenceID).Scan(&f.retryID, &f.holderSubscriptionID, &f.state.Status, &boundary, &f.requestedAt, &f.state.AcquiredAtMilliseconds, &f.state.ExpiresAtMilliseconds, &f.abortRetryID, &f.abortedAt)
	if err == pgx.ErrNoRows {
		return storedFence{}, false, nil
	}
	if err != nil {
		return storedFence{}, false, fmt.Errorf("load checkpoint fence: %w", err)
	}
	f.state.BoundaryCursor = relay.EncodeCursor(uint64(boundary))
	return f, true, nil
}
func loadFenceByRetry(ctx context.Context, q relayQuerier, tenantID, domainID, retryID uuid.UUID) (storedFence, bool, error) {
	var id uuid.UUID
	err := q.QueryRow(ctx, `SELECT fence_id FROM relay_checkpoint_fences WHERE tenant_id=$1 AND domain_id=$2 AND create_retry_id=$3`, tenantID, domainID, retryID).Scan(&id)
	if err == pgx.ErrNoRows {
		return storedFence{}, false, nil
	}
	if err != nil {
		return storedFence{}, false, err
	}
	return loadFence(ctx, q, tenantID, domainID, id, "FOR UPDATE")
}
func postgresFenceResponse(f storedFence, retryID uuid.UUID, a relay.Acceptance) relay.CheckpointFenceResponse {
	return relay.CheckpointFenceResponse{Acceptance: a, RetryID: retryID, FenceID: f.state.FenceID, BoundaryCursor: f.state.BoundaryCursor, AcquiredAtMilliseconds: f.state.AcquiredAtMilliseconds, ExpiresAtMilliseconds: f.state.ExpiresAtMilliseconds}
}
func postgresFenceAllowsWrite(ctx context.Context, tx pgx.Tx, tenantID, domainID, subscriptionID uuid.UUID, now int64) error {
	if err := expirePostgresFence(ctx, tx, tenantID, domainID, now); err != nil {
		return err
	}
	var holder uuid.UUID
	err := tx.QueryRow(ctx, `SELECT holder_subscription_id FROM relay_checkpoint_fences WHERE tenant_id=$1 AND domain_id=$2 AND status='active' LIMIT 1`, tenantID, domainID).Scan(&holder)
	if err == pgx.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	if holder != subscriptionID {
		return relay.NewProtocolError(relay.CodeCheckpointFenceActive, "another subscription holds the checkpoint fence")
	}
	return nil
}

func postgresActiveFenceForSubscription(ctx context.Context, q relayQuerier, tenantID, domainID, subscriptionID uuid.UUID) (*uuid.UUID, error) {
	var fenceID uuid.UUID
	err := q.QueryRow(ctx, `SELECT fence_id FROM relay_checkpoint_fences WHERE tenant_id=$1 AND domain_id=$2 AND holder_subscription_id=$3 AND status='active' LIMIT 1`, tenantID, domainID, subscriptionID).Scan(&fenceID)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &fenceID, nil
}
