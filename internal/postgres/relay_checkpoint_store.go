package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/robreuss/FacetsNode/internal/relay"
)

func (s *RelayStore) StageCheckpoint(ctx context.Context, credential relay.Credential, candidate relay.CheckpointCandidate, nowMilliseconds int64) (relay.CheckpointStageResponse, error) {
	if err := candidate.Validate(); err != nil {
		return relay.CheckpointStageResponse{}, err
	}
	if candidate.TenantID != credential.TenantID || candidate.DomainID != credential.DomainID || candidate.CreatedAtMilliseconds > nowMilliseconds {
		return relay.CheckpointStageResponse{}, relay.NewProtocolError(relay.CodeWrongScope, "checkpoint candidate scope or time is invalid")
	}
	covered, err := relay.DecodeCursor(candidate.CoveredThroughCursor)
	if err != nil {
		return relay.CheckpointStageResponse{}, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return relay.CheckpointStageResponse{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := loadRelayTenant(ctx, tx, credential.TenantID, "FOR UPDATE"); err != nil {
		return relay.CheckpointStageResponse{}, err
	}
	_, _, _, _, _, lastSequence, err := loadRelayDomain(ctx, tx, credential.TenantID, credential.DomainID, "FOR UPDATE")
	if err != nil {
		return relay.CheckpointStageResponse{}, err
	}
	member, found, err := loadRelayMember(ctx, tx, credential.TenantID, credential.DomainID, credential.MemberID, "FOR SHARE")
	if err != nil {
		return relay.CheckpointStageResponse{}, err
	}
	if !found {
		return relay.CheckpointStageResponse{}, relay.NewProtocolError(relay.CodeMemberNotFound, "member was not found")
	}
	if err := member.Authorize(credential, relay.CapabilityPublishCheckpoint, nowMilliseconds); err != nil {
		return relay.CheckpointStageResponse{}, err
	}
	subscriptionID, err := loadActiveMemberSubscription(ctx, tx, credential.TenantID, credential.DomainID, credential.MemberID, "FOR SHARE")
	if err != nil {
		return relay.CheckpointStageResponse{}, err
	}
	if subscriptionID != candidate.PublisherSubscriptionID || covered > uint64(lastSequence) {
		return relay.CheckpointStageResponse{}, relay.NewProtocolError(relay.CodeInvalidCheckpoint, "checkpoint publisher or covered cursor is invalid")
	}
	var existingID uuid.UUID
	err = tx.QueryRow(ctx, `SELECT checkpoint_id FROM relay_checkpoints WHERE tenant_id=$1 AND domain_id=$2 AND stage_retry_id=$3 FOR UPDATE`, credential.TenantID, credential.DomainID, candidate.RetryID).Scan(&existingID)
	if err == nil {
		if existingID != candidate.CheckpointID {
			return relay.CheckpointStageResponse{}, relay.NewProtocolError(relay.CodeCheckpointCollision, "checkpoint retry ID was reused")
		}
		equal, compareErr := postgresCheckpointCandidateEqual(ctx, tx, candidate, subscriptionID)
		if compareErr != nil {
			return relay.CheckpointStageResponse{}, compareErr
		}
		if equal {
			return relay.CheckpointStageResponse{Acceptance: relay.AcceptanceDuplicate, RetryID: candidate.RetryID, CheckpointID: candidate.CheckpointID}, nil
		}
		return relay.CheckpointStageResponse{}, relay.NewProtocolError(relay.CodeCheckpointCollision, "checkpoint retry ID was reused")
	}
	if err != pgx.ErrNoRows {
		return relay.CheckpointStageResponse{}, err
	}
	var activeKeyEpoch, activeCovered int64
	err = tx.QueryRow(ctx, `SELECT key_epoch,covered_through_sequence FROM relay_checkpoints WHERE tenant_id=$1 AND domain_id=$2 AND state='activated' ORDER BY activation_ordinal DESC LIMIT 1`, credential.TenantID, credential.DomainID).Scan(&activeKeyEpoch, &activeCovered)
	if err == nil {
		if activeKeyEpoch < 0 || activeCovered < 0 || candidate.KeyEpoch < uint64(activeKeyEpoch) || covered < uint64(activeCovered) {
			return relay.CheckpointStageResponse{}, relay.NewProtocolError(relay.CodeInvalidCheckpoint, "checkpoint candidate regresses the active checkpoint frontier")
		}
	} else if err != pgx.ErrNoRows {
		return relay.CheckpointStageResponse{}, err
	}
	if err := expirePostgresFence(ctx, tx, credential.TenantID, credential.DomainID, nowMilliseconds); err != nil {
		return relay.CheckpointStageResponse{}, err
	}
	fence, found, err := loadFence(ctx, tx, credential.TenantID, credential.DomainID, candidate.FenceID, "FOR UPDATE")
	if err != nil {
		return relay.CheckpointStageResponse{}, err
	}
	boundary, boundaryErr := relay.DecodeCursor(fence.state.BoundaryCursor)
	if !found || boundaryErr != nil || fence.state.Status != relay.CheckpointFenceActive ||
		fence.holderSubscriptionID != subscriptionID || boundary != covered {
		return relay.CheckpointStageResponse{}, relay.NewProtocolError(relay.CodeInvalidCheckpointFence, "checkpoint candidate does not match an active fence")
	}
	var collision bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM relay_checkpoints WHERE tenant_id=$1 AND domain_id=$2 AND checkpoint_id=$3)`, credential.TenantID, credential.DomainID, candidate.CheckpointID).Scan(&collision); err != nil {
		return relay.CheckpointStageResponse{}, err
	}
	if collision {
		return relay.CheckpointStageResponse{}, relay.NewProtocolError(relay.CodeCheckpointCollision, "checkpoint ID was reused")
	}
	if matches, err := postgresFenceSuffixMatches(ctx, tx, credential.TenantID, credential.DomainID, subscriptionID, int64(boundary), candidate.RetainedMessageIDs); err != nil {
		return relay.CheckpointStageResponse{}, err
	} else if !matches {
		return relay.CheckpointStageResponse{}, relay.NewProtocolError(relay.CodeInvalidCheckpoint, "retained messages are not the exact fenced holder suffix")
	}
	for _, id := range candidate.RetainedBlobIDs {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM relay_blobs WHERE tenant_id=$1 AND domain_id=$2 AND blob_id=$3)`, credential.TenantID, credential.DomainID, id).Scan(&exists); err != nil {
			return relay.CheckpointStageResponse{}, err
		}
		if !exists {
			return relay.CheckpointStageResponse{}, relay.NewProtocolError(relay.CodeInvalidCheckpoint, "retained blob is missing")
		}
	}
	_, err = tx.Exec(ctx, `INSERT INTO relay_checkpoints (tenant_id,domain_id,checkpoint_id,stage_retry_id,candidate_digest,version,publisher_subscription_id,publisher_member_id,covered_through_sequence,created_at_milliseconds,fence_id,key_epoch) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, candidate.TenantID, candidate.DomainID, candidate.CheckpointID, candidate.RetryID, relay.CheckpointCandidateDigest(candidate), candidate.Version, candidate.PublisherSubscriptionID, credential.MemberID, int64(covered), candidate.CreatedAtMilliseconds, candidate.FenceID, candidate.KeyEpoch)
	if err != nil {
		return relay.CheckpointStageResponse{}, fmt.Errorf("insert checkpoint: %w", err)
	}
	for _, id := range candidate.RetainedMessageIDs {
		if _, err := tx.Exec(ctx, `INSERT INTO relay_checkpoint_retained_messages VALUES ($1,$2,$3,$4)`, candidate.TenantID, candidate.DomainID, candidate.CheckpointID, id); err != nil {
			return relay.CheckpointStageResponse{}, err
		}
	}
	for _, id := range candidate.RetainedBlobIDs {
		if _, err := tx.Exec(ctx, `INSERT INTO relay_checkpoint_retained_blobs VALUES ($1,$2,$3,$4)`, candidate.TenantID, candidate.DomainID, candidate.CheckpointID, id); err != nil {
			return relay.CheckpointStageResponse{}, err
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO relay_audit_events (tenant_id,domain_id,subscription_id,member_id,checkpoint_id,event_type,occurred_at_milliseconds) VALUES ($1,$2,$3,$4,$5,'checkpoint_staged',$6)`, candidate.TenantID, candidate.DomainID, candidate.PublisherSubscriptionID, credential.MemberID, candidate.CheckpointID, nowMilliseconds); err != nil {
		return relay.CheckpointStageResponse{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return relay.CheckpointStageResponse{}, err
	}
	return relay.CheckpointStageResponse{Acceptance: relay.AcceptanceAccepted, RetryID: candidate.RetryID, CheckpointID: candidate.CheckpointID}, nil
}

func (s *RelayStore) ActivateCheckpoint(ctx context.Context, credential relay.AdministrationCredential, request relay.CheckpointActivationRequest, nowMilliseconds int64) (relay.CheckpointActivationResponse, error) {
	if err := request.Validate(); err != nil {
		return relay.CheckpointActivationResponse{}, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return relay.CheckpointActivationResponse{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := loadRelayTenant(ctx, tx, credential.TenantID, "FOR UPDATE"); err != nil {
		return relay.CheckpointActivationResponse{}, err
	}
	domain, _, _, _, _, _, err := loadRelayDomain(ctx, tx, credential.TenantID, credential.DomainID, "FOR UPDATE")
	if err != nil {
		return relay.CheckpointActivationResponse{}, err
	}
	if err := domain.Authorize(credential); err != nil {
		return relay.CheckpointActivationResponse{}, err
	}
	var retryCheckpoint uuid.UUID
	var retryActivated, retryStart int64
	err = tx.QueryRow(ctx, `SELECT checkpoint_id,activated_at_milliseconds,start_sequence FROM relay_checkpoints WHERE tenant_id=$1 AND domain_id=$2 AND activation_retry_id=$3 FOR UPDATE`, credential.TenantID, credential.DomainID, request.RetryID).Scan(&retryCheckpoint, &retryActivated, &retryStart)
	if err == nil {
		if retryCheckpoint == request.CheckpointID && retryActivated == request.ActivatedAtMilliseconds {
			return relay.CheckpointActivationResponse{Acceptance: relay.AcceptanceDuplicate, RetryID: request.RetryID, CheckpointID: request.CheckpointID, ActivatedAtMilliseconds: retryActivated, StartCursor: relay.EncodeCursor(uint64(retryStart))}, nil
		}
		return relay.CheckpointActivationResponse{}, relay.NewProtocolError(relay.CodeCheckpointCollision, "checkpoint activation retry ID was reused")
	}
	if err != pgx.ErrNoRows {
		return relay.CheckpointActivationResponse{}, err
	}
	var state string
	var covered, created, keyEpoch int64
	var fenceID uuid.UUID
	var publisherSubscriptionID uuid.UUID
	err = tx.QueryRow(ctx, `SELECT state,covered_through_sequence,created_at_milliseconds,key_epoch,fence_id,publisher_subscription_id FROM relay_checkpoints WHERE tenant_id=$1 AND domain_id=$2 AND checkpoint_id=$3 FOR UPDATE`, credential.TenantID, credential.DomainID, request.CheckpointID).Scan(&state, &covered, &created, &keyEpoch, &fenceID, &publisherSubscriptionID)
	if err == pgx.ErrNoRows {
		return relay.CheckpointActivationResponse{}, relay.NewProtocolError(relay.CodeCheckpointNotFound, "checkpoint was not found")
	}
	if err != nil {
		return relay.CheckpointActivationResponse{}, err
	}
	if err := expirePostgresFence(ctx, tx, credential.TenantID, credential.DomainID, nowMilliseconds); err != nil {
		return relay.CheckpointActivationResponse{}, err
	}
	fence, found, err := loadFence(ctx, tx, credential.TenantID, credential.DomainID, fenceID, "FOR UPDATE")
	if err != nil {
		return relay.CheckpointActivationResponse{}, err
	}
	if state != "staged" || request.ActivatedAtMilliseconds < created || request.ActivatedAtMilliseconds > nowMilliseconds {
		if found && (fence.state.Status == relay.CheckpointFenceExpired || fence.state.Status == relay.CheckpointFenceAborted) {
			return relay.CheckpointActivationResponse{}, relay.NewProtocolError(relay.CodeInvalidCheckpointFence, "checkpoint fence is no longer activatable")
		}
		return relay.CheckpointActivationResponse{}, relay.NewProtocolError(relay.CodeCheckpointCollision, "checkpoint was already activated or activation time is invalid")
	}
	boundary, boundaryErr := relay.DecodeCursor(fence.state.BoundaryCursor)
	if !found || boundaryErr != nil || fence.state.Status != relay.CheckpointFenceActive ||
		fence.holderSubscriptionID != publisherSubscriptionID || int64(boundary) != covered {
		return relay.CheckpointActivationResponse{}, relay.NewProtocolError(relay.CodeInvalidCheckpointFence, "checkpoint fence is no longer activatable")
	}
	var retained []uuid.UUID
	rows, err := tx.Query(ctx, `SELECT message_id FROM relay_checkpoint_retained_messages WHERE tenant_id=$1 AND domain_id=$2 AND checkpoint_id=$3 ORDER BY message_id`, credential.TenantID, credential.DomainID, request.CheckpointID)
	if err != nil {
		return relay.CheckpointActivationResponse{}, err
	}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return relay.CheckpointActivationResponse{}, err
		}
		retained = append(retained, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return relay.CheckpointActivationResponse{}, err
	}
	if matches, err := postgresFenceSuffixMatches(ctx, tx, credential.TenantID, credential.DomainID, publisherSubscriptionID, covered, retained); err != nil {
		return relay.CheckpointActivationResponse{}, err
	} else if !matches {
		return relay.CheckpointActivationResponse{}, relay.NewProtocolError(relay.CodeInvalidCheckpointFence, "checkpoint holder suffix changed")
	}
	var recoveryActive bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM relay_subscription_rebootstrap_requests recovery
			JOIN relay_subscriptions subscription
			  ON subscription.tenant_id=recovery.tenant_id
			 AND subscription.domain_id=recovery.domain_id
			 AND subscription.subscription_id=recovery.subscription_id
			WHERE recovery.tenant_id=$1 AND recovery.domain_id=$2
			  AND subscription.status='rebootstrap_required'
			  AND recovery.lease_expires_at_milliseconds>$3
			  AND NOT EXISTS (
			      SELECT 1 FROM relay_subscription_rebootstrap_cancellations cancellation
			      WHERE cancellation.tenant_id=recovery.tenant_id
			        AND cancellation.domain_id=recovery.domain_id
			        AND cancellation.request_retry_id=recovery.retry_id)
			  AND NOT EXISTS (
			      SELECT 1 FROM relay_subscription_rebootstrap_completions completion
			      WHERE completion.tenant_id=recovery.tenant_id
			        AND completion.domain_id=recovery.domain_id
			        AND completion.request_retry_id=recovery.retry_id)
		)
	`, credential.TenantID, credential.DomainID, nowMilliseconds).Scan(&recoveryActive); err != nil {
		return relay.CheckpointActivationResponse{}, err
	}
	if recoveryActive {
		return relay.CheckpointActivationResponse{}, relay.NewProtocolError(relay.CodeCheckpointNotEligible, "checkpoint activation is blocked by an active client-authorized recovery")
	}
	startSequence := covered
	var previousID uuid.UUID
	var previousKeyEpoch, previousCovered int64
	var previousArgument any
	err = tx.QueryRow(ctx, `SELECT checkpoint_id,key_epoch,covered_through_sequence FROM relay_checkpoints WHERE tenant_id=$1 AND domain_id=$2 AND state='activated' ORDER BY activation_ordinal DESC LIMIT 1`, credential.TenantID, credential.DomainID).Scan(&previousID, &previousKeyEpoch, &previousCovered)
	if err == nil {
		if keyEpoch < previousKeyEpoch || covered < previousCovered {
			return relay.CheckpointActivationResponse{}, relay.NewProtocolError(relay.CodeInvalidCheckpoint, "checkpoint candidate regresses the active checkpoint frontier")
		}
		previousArgument = previousID
	} else if err != pgx.ErrNoRows {
		return relay.CheckpointActivationResponse{}, err
	}
	var ordinal int64
	if err := tx.QueryRow(ctx, `UPDATE relay_domains SET checkpoint_activation_ordinal=checkpoint_activation_ordinal+1,updated_at=now() WHERE tenant_id=$1 AND domain_id=$2 RETURNING checkpoint_activation_ordinal`, credential.TenantID, credential.DomainID).Scan(&ordinal); err != nil {
		return relay.CheckpointActivationResponse{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO relay_checkpoint_required_subscriptions SELECT tenant_id,domain_id,$3,subscription_id FROM relay_subscriptions WHERE tenant_id=$1 AND domain_id=$2 AND status='active'`, credential.TenantID, credential.DomainID, request.CheckpointID); err != nil {
		return relay.CheckpointActivationResponse{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO relay_checkpoint_deletion_messages (tenant_id,domain_id,checkpoint_id,message_id,domain_sequence,byte_count) SELECT m.tenant_id,m.domain_id,$3,m.message_id,m.domain_sequence,m.ciphertext_byte_count FROM relay_messages m WHERE m.tenant_id=$1 AND m.domain_id=$2 AND m.domain_sequence <= $4 AND NOT EXISTS (SELECT 1 FROM relay_checkpoint_retained_messages r WHERE r.tenant_id=m.tenant_id AND r.domain_id=m.domain_id AND r.message_id=m.message_id AND (r.checkpoint_id=$3 OR r.checkpoint_id=$5))`, credential.TenantID, credential.DomainID, request.CheckpointID, covered, previousArgument); err != nil {
		return relay.CheckpointActivationResponse{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO relay_checkpoint_deletion_blobs (tenant_id,domain_id,checkpoint_id,blob_id,byte_count) SELECT b.tenant_id,b.domain_id,$3,b.blob_id,b.byte_count FROM relay_blobs b WHERE b.tenant_id=$1 AND b.domain_id=$2 AND NOT EXISTS (SELECT 1 FROM relay_checkpoint_retained_blobs r WHERE r.tenant_id=b.tenant_id AND r.domain_id=b.domain_id AND r.blob_id=b.blob_id AND (r.checkpoint_id=$3 OR r.checkpoint_id=$4))`, credential.TenantID, credential.DomainID, request.CheckpointID, previousArgument); err != nil {
		return relay.CheckpointActivationResponse{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE relay_checkpoints SET state='activated',activation_retry_id=$4,activation_ordinal=$5,activated_at_milliseconds=$6,start_sequence=$7,updated_at=now() WHERE tenant_id=$1 AND domain_id=$2 AND checkpoint_id=$3`, credential.TenantID, credential.DomainID, request.CheckpointID, request.RetryID, ordinal, request.ActivatedAtMilliseconds, startSequence); err != nil {
		return relay.CheckpointActivationResponse{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE relay_checkpoint_fences SET status='activated',updated_at=now() WHERE tenant_id=$1 AND domain_id=$2 AND fence_id=$3 AND status='active'`, credential.TenantID, credential.DomainID, fenceID); err != nil {
		return relay.CheckpointActivationResponse{}, err
	}
	retiredRows, err := tx.Query(ctx, `UPDATE relay_checkpoints SET state='retired',updated_at=now() WHERE tenant_id=$1 AND domain_id=$2 AND state='activated' AND checkpoint_id<>$3 AND ($4::uuid IS NULL OR checkpoint_id<>$4) RETURNING checkpoint_id`, credential.TenantID, credential.DomainID, request.CheckpointID, previousArgument)
	if err != nil {
		return relay.CheckpointActivationResponse{}, err
	}
	retiredIDs := make([]uuid.UUID, 0)
	for retiredRows.Next() {
		var checkpointID uuid.UUID
		if err := retiredRows.Scan(&checkpointID); err != nil {
			retiredRows.Close()
			return relay.CheckpointActivationResponse{}, err
		}
		retiredIDs = append(retiredIDs, checkpointID)
	}
	retiredRows.Close()
	if err := retiredRows.Err(); err != nil {
		return relay.CheckpointActivationResponse{}, err
	}
	if len(retiredIDs) > 0 {
		for _, table := range []string{
			"relay_checkpoint_retained_messages",
			"relay_checkpoint_retained_blobs",
			"relay_checkpoint_required_subscriptions",
			"relay_checkpoint_deletion_messages",
			"relay_checkpoint_deletion_blobs",
		} {
			if _, err := tx.Exec(ctx, `DELETE FROM `+table+` WHERE tenant_id=$1 AND domain_id=$2 AND checkpoint_id=ANY($3)`, credential.TenantID, credential.DomainID, retiredIDs); err != nil {
				return relay.CheckpointActivationResponse{}, fmt.Errorf("prune retired checkpoint %s: %w", table, err)
			}
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO relay_audit_events (tenant_id,domain_id,checkpoint_id,event_type,occurred_at_milliseconds) VALUES ($1,$2,$3,'checkpoint_activated',$4)`, credential.TenantID, credential.DomainID, request.CheckpointID, request.ActivatedAtMilliseconds); err != nil {
		return relay.CheckpointActivationResponse{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return relay.CheckpointActivationResponse{}, err
	}
	return relay.CheckpointActivationResponse{Acceptance: relay.AcceptanceAccepted, RetryID: request.RetryID, CheckpointID: request.CheckpointID, ActivatedAtMilliseconds: request.ActivatedAtMilliseconds, StartCursor: relay.EncodeCursor(uint64(startSequence))}, nil
}

func (s *RelayStore) DryRunCheckpointCollection(ctx context.Context, credential relay.AdministrationCredential, request relay.CheckpointDryRunRequest) (relay.CheckpointDryRunResponse, error) {
	if err := request.Validate(); err != nil {
		return relay.CheckpointDryRunResponse{}, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return relay.CheckpointDryRunResponse{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := loadRelayTenant(ctx, tx, credential.TenantID, "FOR SHARE"); err != nil {
		return relay.CheckpointDryRunResponse{}, err
	}
	domain, _, _, _, _, _, err := loadRelayDomain(ctx, tx, credential.TenantID, credential.DomainID, "FOR SHARE")
	if err != nil {
		return relay.CheckpointDryRunResponse{}, err
	}
	if err := domain.Authorize(credential); err != nil {
		return relay.CheckpointDryRunResponse{}, err
	}
	return postgresCheckpointPlan(ctx, tx, credential.TenantID, credential.DomainID, request.CheckpointID)
}

func (s *RelayStore) CollectCheckpoint(ctx context.Context, credential relay.AdministrationCredential, request relay.CheckpointCollectionRequest) (relay.CheckpointCollectionResponse, error) {
	if err := request.Validate(); err != nil {
		return relay.CheckpointCollectionResponse{}, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return relay.CheckpointCollectionResponse{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := loadRelayTenant(ctx, tx, credential.TenantID, "FOR UPDATE"); err != nil {
		return relay.CheckpointCollectionResponse{}, err
	}
	domain, _, _, _, _, _, err := loadRelayDomain(ctx, tx, credential.TenantID, credential.DomainID, "FOR UPDATE")
	if err != nil {
		return relay.CheckpointCollectionResponse{}, err
	}
	if err := domain.Authorize(credential); err != nil {
		return relay.CheckpointCollectionResponse{}, err
	}
	var activatedAt *int64
	err = tx.QueryRow(ctx, `SELECT activated_at_milliseconds FROM relay_checkpoints WHERE tenant_id=$1 AND domain_id=$2 AND checkpoint_id=$3`, credential.TenantID, credential.DomainID, request.CheckpointID).Scan(&activatedAt)
	if err == pgx.ErrNoRows {
		return relay.CheckpointCollectionResponse{}, relay.NewProtocolError(relay.CodeCheckpointNotFound, "checkpoint was not found")
	}
	if err != nil {
		return relay.CheckpointCollectionResponse{}, err
	}
	if activatedAt != nil && request.RequestedAtMilliseconds < *activatedAt {
		return relay.CheckpointCollectionResponse{}, relay.NewProtocolError(relay.CodeInvalidCheckpoint, "checkpoint collection predates activation")
	}
	var stored relay.CheckpointCollectionResponse
	var storedMaxMessages, storedMaxBlobs, storedRequested int64
	err = tx.QueryRow(ctx, `SELECT checkpoint_id,plan_digest,maximum_message_count,maximum_blob_count,requested_at_milliseconds,deleted_message_count,deleted_message_byte_count,deleted_blob_count,deleted_blob_byte_count,completed FROM relay_checkpoint_collections WHERE tenant_id=$1 AND domain_id=$2 AND retry_id=$3 FOR UPDATE`, credential.TenantID, credential.DomainID, request.RetryID).Scan(&stored.CheckpointID, &stored.PlanDigest, &storedMaxMessages, &storedMaxBlobs, &storedRequested, &stored.DeletedMessageCount, &stored.DeletedMessageByteCount, &stored.DeletedBlobCount, &stored.DeletedBlobByteCount, &stored.Completed)
	if err == nil {
		if stored.CheckpointID == request.CheckpointID && stored.PlanDigest == request.PlanDigest && storedMaxMessages == request.MaximumMessageCount && storedMaxBlobs == request.MaximumBlobCount && storedRequested == request.RequestedAtMilliseconds {
			stored.Duplicate = true
			stored.RetryID = request.RetryID
			return stored, nil
		}
		return relay.CheckpointCollectionResponse{}, relay.NewProtocolError(relay.CodeCheckpointCollision, "checkpoint collection retry ID was reused")
	}
	if err != pgx.ErrNoRows {
		return relay.CheckpointCollectionResponse{}, err
	}
	plan, err := postgresCheckpointPlan(ctx, tx, credential.TenantID, credential.DomainID, request.CheckpointID)
	if err != nil {
		return relay.CheckpointCollectionResponse{}, err
	}
	if plan.PlanDigest != request.PlanDigest {
		return relay.CheckpointCollectionResponse{}, relay.NewProtocolError(relay.CodeCollectionPlanStale, "collection plan changed")
	}
	if !plan.Eligible {
		return relay.CheckpointCollectionResponse{}, relay.NewProtocolError(relay.CodeCheckpointNotEligible, "checkpoint lacks required custody")
	}
	messages, blobs, ordinal, err := loadCheckpointPlanEntries(ctx, tx, credential.TenantID, credential.DomainID, request.CheckpointID)
	_ = ordinal
	if err != nil {
		return relay.CheckpointCollectionResponse{}, err
	}
	if int64(len(messages)) > request.MaximumMessageCount {
		messages = messages[:request.MaximumMessageCount]
	}
	if int64(len(blobs)) > request.MaximumBlobCount {
		blobs = blobs[:request.MaximumBlobCount]
	}
	messageIDs := make([]uuid.UUID, len(messages))
	blobIDs := make([]string, len(blobs))
	response := relay.CheckpointCollectionResponse{RetryID: request.RetryID, CheckpointID: request.CheckpointID, PlanDigest: request.PlanDigest}
	for i, item := range messages {
		messageIDs[i] = item.MessageID
		response.DeletedMessageCount++
		response.DeletedMessageByteCount += item.ByteCount
	}
	for i, item := range blobs {
		blobIDs[i] = item.BlobID
		response.DeletedBlobCount++
		response.DeletedBlobByteCount += item.ByteCount
	}
	if len(messageIDs) > 0 {
		if _, err := tx.Exec(ctx, `DELETE FROM relay_messages WHERE tenant_id=$1 AND domain_id=$2 AND message_id=ANY($3)`, credential.TenantID, credential.DomainID, messageIDs); err != nil {
			return relay.CheckpointCollectionResponse{}, err
		}
		if _, err := tx.Exec(ctx, `UPDATE relay_checkpoint_deletion_messages SET collected_at_milliseconds=$4 WHERE tenant_id=$1 AND domain_id=$2 AND checkpoint_id=$3 AND message_id=ANY($5)`, credential.TenantID, credential.DomainID, request.CheckpointID, request.RequestedAtMilliseconds, messageIDs); err != nil {
			return relay.CheckpointCollectionResponse{}, err
		}
	}
	if len(blobIDs) > 0 {
		if _, err := tx.Exec(ctx, `DELETE FROM relay_blobs WHERE tenant_id=$1 AND domain_id=$2 AND blob_id=ANY($3)`, credential.TenantID, credential.DomainID, blobIDs); err != nil {
			return relay.CheckpointCollectionResponse{}, err
		}
		if _, err := tx.Exec(ctx, `UPDATE relay_checkpoint_deletion_blobs SET collected_at_milliseconds=$4 WHERE tenant_id=$1 AND domain_id=$2 AND checkpoint_id=$3 AND blob_id=ANY($5)`, credential.TenantID, credential.DomainID, request.CheckpointID, request.RequestedAtMilliseconds, blobIDs); err != nil {
			return relay.CheckpointCollectionResponse{}, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO relay_collected_blob_deletions (tenant_id,domain_id,blob_id,collected_at_milliseconds) SELECT $1,$2,unnest($3::text[]),$4 ON CONFLICT (tenant_id,domain_id,blob_id) DO UPDATE SET collected_at_milliseconds=EXCLUDED.collected_at_milliseconds`, credential.TenantID, credential.DomainID, blobIDs, request.RequestedAtMilliseconds); err != nil {
			return relay.CheckpointCollectionResponse{}, err
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE relay_domains SET message_count=message_count-$3::integer,message_byte_count=message_byte_count-$4,blob_count=blob_count-$5::integer,blob_byte_count=blob_byte_count-$6,updated_at=now() WHERE tenant_id=$1 AND domain_id=$2`, credential.TenantID, credential.DomainID, response.DeletedMessageCount, response.DeletedMessageByteCount, response.DeletedBlobCount, response.DeletedBlobByteCount); err != nil {
		return relay.CheckpointCollectionResponse{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE relay_tenants SET message_count=message_count-$2::integer,aggregate_message_byte_count=aggregate_message_byte_count-$3,blob_count=blob_count-$4::integer,aggregate_blob_byte_count=aggregate_blob_byte_count-$5,updated_at=now() WHERE tenant_id=$1`, credential.TenantID, response.DeletedMessageCount, response.DeletedMessageByteCount, response.DeletedBlobCount, response.DeletedBlobByteCount); err != nil {
		return relay.CheckpointCollectionResponse{}, err
	}
	var remaining bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM relay_checkpoint_deletion_messages WHERE tenant_id=$1 AND domain_id=$2 AND checkpoint_id=$3 AND collected_at_milliseconds IS NULL) OR EXISTS(SELECT 1 FROM relay_checkpoint_deletion_blobs WHERE tenant_id=$1 AND domain_id=$2 AND checkpoint_id=$3 AND collected_at_milliseconds IS NULL)`, credential.TenantID, credential.DomainID, request.CheckpointID).Scan(&remaining); err != nil {
		return relay.CheckpointCollectionResponse{}, err
	}
	response.Completed = !remaining
	if _, err := tx.Exec(ctx, `INSERT INTO relay_checkpoint_collections (tenant_id,domain_id,retry_id,checkpoint_id,plan_digest,maximum_message_count,maximum_blob_count,requested_at_milliseconds,deleted_message_count,deleted_message_byte_count,deleted_blob_count,deleted_blob_byte_count,completed) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, credential.TenantID, credential.DomainID, request.RetryID, request.CheckpointID, request.PlanDigest, request.MaximumMessageCount, request.MaximumBlobCount, request.RequestedAtMilliseconds, response.DeletedMessageCount, response.DeletedMessageByteCount, response.DeletedBlobCount, response.DeletedBlobByteCount, response.Completed); err != nil {
		return relay.CheckpointCollectionResponse{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO relay_audit_events (tenant_id,domain_id,checkpoint_id,event_type,occurred_at_milliseconds) VALUES ($1,$2,$3,'checkpoint_collected',$4)`, credential.TenantID, credential.DomainID, request.CheckpointID, request.RequestedAtMilliseconds); err != nil {
		return relay.CheckpointCollectionResponse{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return relay.CheckpointCollectionResponse{}, err
	}
	return response, nil
}

func postgresCheckpointPlan(ctx context.Context, q relayQuerier, tenantID, domainID, checkpointID uuid.UUID) (relay.CheckpointDryRunResponse, error) {
	messages, blobs, ordinal, err := loadCheckpointPlanEntries(ctx, q, tenantID, domainID, checkpointID)
	if err != nil {
		return relay.CheckpointDryRunResponse{}, err
	}
	rows, err := q.Query(ctx, `SELECT r.subscription_id FROM relay_checkpoint_required_subscriptions r JOIN relay_subscriptions s USING (tenant_id,domain_id,subscription_id) WHERE r.tenant_id=$1 AND r.domain_id=$2 AND r.checkpoint_id=$3 AND s.status='active' AND EXISTS (SELECT 1 FROM relay_checkpoint_deletion_messages d JOIN relay_messages m USING (tenant_id,domain_id,message_id) WHERE d.tenant_id=r.tenant_id AND d.domain_id=r.domain_id AND d.checkpoint_id=r.checkpoint_id AND d.collected_at_milliseconds IS NULL AND m.publisher_subscription_id<>r.subscription_id AND NOT EXISTS (SELECT 1 FROM relay_acknowledgments a WHERE a.tenant_id=d.tenant_id AND a.domain_id=d.domain_id AND a.message_id=d.message_id AND a.subscription_id=r.subscription_id) AND NOT EXISTS (SELECT 1 FROM relay_subscription_rebootstrap_completions c WHERE c.tenant_id=r.tenant_id AND c.domain_id=r.domain_id AND c.subscription_id=r.subscription_id AND c.recovery_start_sequence>=m.domain_sequence)) ORDER BY r.subscription_id`, tenantID, domainID, checkpointID)
	if err != nil {
		return relay.CheckpointDryRunResponse{}, err
	}
	defer rows.Close()
	missing := make([]uuid.UUID, 0)
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return relay.CheckpointDryRunResponse{}, err
		}
		missing = append(missing, id)
	}
	if err := rows.Err(); err != nil {
		return relay.CheckpointDryRunResponse{}, err
	}
	response := relay.CheckpointDryRunResponse{CheckpointID: checkpointID, Eligible: len(missing) == 0, MissingCustodySubscriptionIDs: missing}
	for _, item := range messages {
		response.MessageCount++
		response.MessageByteCount += item.ByteCount
	}
	for _, item := range blobs {
		response.BlobCount++
		response.BlobByteCount += item.ByteCount
	}
	response.PlanDigest = relay.CheckpointPlanDigest(tenantID, domainID, checkpointID, uint64(ordinal), messages, blobs)
	return response, nil
}

func loadCheckpointPlanEntries(ctx context.Context, q relayQuerier, tenantID, domainID, checkpointID uuid.UUID) ([]relay.CheckpointPlanMessage, []relay.CheckpointPlanBlob, int64, error) {
	var state string
	var ordinal int64
	var latest int64
	err := q.QueryRow(ctx, `SELECT state,COALESCE(activation_ordinal,0),(SELECT COALESCE(max(activation_ordinal),0) FROM relay_checkpoints WHERE tenant_id=$1 AND domain_id=$2 AND state='activated') FROM relay_checkpoints WHERE tenant_id=$1 AND domain_id=$2 AND checkpoint_id=$3`, tenantID, domainID, checkpointID).Scan(&state, &ordinal, &latest)
	if err == pgx.ErrNoRows {
		return nil, nil, 0, relay.NewProtocolError(relay.CodeCheckpointNotFound, "checkpoint was not found")
	}
	if err != nil {
		return nil, nil, 0, err
	}
	if state != "activated" || ordinal != latest {
		return nil, nil, 0, relay.NewProtocolError(relay.CodeCheckpointNotEligible, "only the latest activated checkpoint is collectable")
	}
	messageRows, err := q.Query(ctx, `SELECT domain_sequence,message_id,byte_count FROM relay_checkpoint_deletion_messages WHERE tenant_id=$1 AND domain_id=$2 AND checkpoint_id=$3 AND collected_at_milliseconds IS NULL ORDER BY domain_sequence`, tenantID, domainID, checkpointID)
	if err != nil {
		return nil, nil, 0, err
	}
	messages := make([]relay.CheckpointPlanMessage, 0)
	for messageRows.Next() {
		var item relay.CheckpointPlanMessage
		var sequence int64
		if err := messageRows.Scan(&sequence, &item.MessageID, &item.ByteCount); err != nil {
			messageRows.Close()
			return nil, nil, 0, err
		}
		item.Sequence = uint64(sequence)
		messages = append(messages, item)
	}
	messageRows.Close()
	if err := messageRows.Err(); err != nil {
		return nil, nil, 0, err
	}
	blobRows, err := q.Query(ctx, `SELECT blob_id,byte_count FROM relay_checkpoint_deletion_blobs WHERE tenant_id=$1 AND domain_id=$2 AND checkpoint_id=$3 AND collected_at_milliseconds IS NULL ORDER BY blob_id`, tenantID, domainID, checkpointID)
	if err != nil {
		return nil, nil, 0, err
	}
	blobs := make([]relay.CheckpointPlanBlob, 0)
	for blobRows.Next() {
		var item relay.CheckpointPlanBlob
		if err := blobRows.Scan(&item.BlobID, &item.ByteCount); err != nil {
			blobRows.Close()
			return nil, nil, 0, err
		}
		blobs = append(blobs, item)
	}
	blobRows.Close()
	if err := blobRows.Err(); err != nil {
		return nil, nil, 0, err
	}
	return messages, blobs, ordinal, nil
}

func postgresCheckpointCandidateEqual(ctx context.Context, q relayQuerier, candidate relay.CheckpointCandidate, subscriptionID uuid.UUID) (bool, error) {
	var candidateDigest string
	var publisherSubscription uuid.UUID
	err := q.QueryRow(ctx, `SELECT candidate_digest,publisher_subscription_id FROM relay_checkpoints WHERE tenant_id=$1 AND domain_id=$2 AND checkpoint_id=$3`, candidate.TenantID, candidate.DomainID, candidate.CheckpointID).Scan(&candidateDigest, &publisherSubscription)
	if err != nil {
		return false, err
	}
	return publisherSubscription == subscriptionID && candidateDigest == relay.CheckpointCandidateDigest(candidate), nil
}

func postgresFenceSuffixMatches(ctx context.Context, q relayQuerier, tenantID, domainID, subscriptionID uuid.UUID, boundary int64, retained []uuid.UUID) (bool, error) {
	rows, err := q.Query(ctx, `SELECT message_id FROM relay_messages WHERE tenant_id=$1 AND domain_id=$2 AND publisher_subscription_id=$3 AND domain_sequence>$4 ORDER BY message_id`, tenantID, domainID, subscriptionID, boundary)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	expected := make([]uuid.UUID, 0, len(retained))
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return false, err
		}
		expected = append(expected, id)
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	if len(expected) != len(retained) {
		return false, nil
	}
	for index := range expected {
		if expected[index] != retained[index] {
			return false, nil
		}
	}
	return true, nil
}
