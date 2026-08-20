package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/robreuss/FacetsNode/internal/relay"
)

// RequestSubscriptionRebootstrap lets an enrolled member discard only its own
// local replica and restart from the latest activated opaque checkpoint. The
// relay chooses the boundary; it never opens the checkpoint or FEF payload.
func (s *RelayStore) RequestSubscriptionRebootstrap(
	ctx context.Context,
	credential relay.Credential,
	request relay.SubscriptionRebootstrapRequest,
	nowMilliseconds int64,
) (relay.SubscriptionRebootstrapResponse, error) {
	if err := request.Validate(); err != nil {
		return relay.SubscriptionRebootstrapResponse{}, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return relay.SubscriptionRebootstrapResponse{}, fmt.Errorf("begin subscription rebootstrap request: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	response, err := requestSubscriptionRebootstrapTx(ctx, tx, credential, request, nowMilliseconds)
	if err != nil {
		return relay.SubscriptionRebootstrapResponse{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return relay.SubscriptionRebootstrapResponse{}, fmt.Errorf("commit subscription rebootstrap request: %w", err)
	}
	return response, nil
}

func requestSubscriptionRebootstrapTx(
	ctx context.Context,
	tx pgx.Tx,
	credential relay.Credential,
	request relay.SubscriptionRebootstrapRequest,
	nowMilliseconds int64,
) (relay.SubscriptionRebootstrapResponse, error) {
	if err := request.Validate(); err != nil {
		return relay.SubscriptionRebootstrapResponse{}, err
	}
	if _, err := loadRelayTenant(ctx, tx, credential.TenantID, "FOR SHARE"); err != nil {
		return relay.SubscriptionRebootstrapResponse{}, err
	}
	if _, _, _, _, _, _, err := loadRelayDomain(ctx, tx, credential.TenantID, credential.DomainID, "FOR UPDATE"); err != nil {
		return relay.SubscriptionRebootstrapResponse{}, err
	}
	member, found, err := loadRelayMember(ctx, tx, credential.TenantID, credential.DomainID, credential.MemberID, "FOR SHARE")
	if err != nil {
		return relay.SubscriptionRebootstrapResponse{}, err
	}
	if !found {
		return relay.SubscriptionRebootstrapResponse{}, relay.NewProtocolError(relay.CodeMemberNotFound, "member was not found")
	}
	if err := member.Authorize(credential, relay.CapabilityFetchMessage, nowMilliseconds); err != nil {
		return relay.SubscriptionRebootstrapResponse{}, err
	}
	subscriptionID, status, err := loadReadableMemberSubscription(ctx, tx, credential.TenantID, credential.DomainID, credential.MemberID, "FOR UPDATE")
	if err != nil {
		return relay.SubscriptionRebootstrapResponse{}, err
	}

	var storedSubscriptionID uuid.UUID
	var storedRequestedAt, storedStart, storedUpdatedAt int64
	err = tx.QueryRow(ctx, `
		SELECT subscription_id, requested_at_milliseconds, result_start_sequence, result_updated_at_milliseconds
		FROM relay_subscription_rebootstrap_requests
		WHERE tenant_id=$1 AND domain_id=$2 AND retry_id=$3
		FOR UPDATE
	`, credential.TenantID, credential.DomainID, request.RetryID).Scan(
		&storedSubscriptionID, &storedRequestedAt, &storedStart, &storedUpdatedAt,
	)
	if err == nil {
		if storedSubscriptionID != subscriptionID || storedRequestedAt != request.RequestedAtMilliseconds {
			return relay.SubscriptionRebootstrapResponse{}, relay.NewProtocolError(relay.CodeSubscriptionCollision, "subscription rebootstrap retry ID was reused")
		}
		subscription, _, found, loadErr := loadSubscription(ctx, tx, credential.TenantID, credential.DomainID, subscriptionID, "")
		if loadErr != nil {
			return relay.SubscriptionRebootstrapResponse{}, loadErr
		}
		if !found {
			return relay.SubscriptionRebootstrapResponse{}, relay.NewProtocolError(relay.CodeSubscriptionNotFound, "subscription was not found")
		}
		start := relay.EncodeCursor(uint64(storedStart))
		subscription.Status = relay.SubscriptionRebootstrapRequired
		subscription.StartCursor = &start
		subscription.UpdatedAtMilliseconds = storedUpdatedAt
		return relay.SubscriptionRebootstrapResponse{Acceptance: relay.AcceptanceDuplicate, RetryID: request.RetryID, Subscription: subscription}, nil
	}
	if err != pgx.ErrNoRows {
		return relay.SubscriptionRebootstrapResponse{}, err
	}

	var startSequence *int64
	if status == relay.SubscriptionRebootstrapRequired {
		if err := tx.QueryRow(ctx, `SELECT start_sequence FROM relay_subscriptions WHERE tenant_id=$1 AND domain_id=$2 AND subscription_id=$3`, credential.TenantID, credential.DomainID, subscriptionID).Scan(&startSequence); err != nil {
			return relay.SubscriptionRebootstrapResponse{}, fmt.Errorf("load current rebootstrap cursor: %w", err)
		}
	} else {
		startSequence, err = latestActivatedCheckpointStart(ctx, tx, credential.TenantID, credential.DomainID)
		if err != nil {
			return relay.SubscriptionRebootstrapResponse{}, err
		}
		if startSequence == nil {
			return relay.SubscriptionRebootstrapResponse{}, relay.NewProtocolError(relay.CodeCheckpointUnavailable, "no activated checkpoint is available for recovery")
		}
		if _, err := tx.Exec(ctx, `
			UPDATE relay_subscriptions
			SET status=$4,start_sequence=$5,updated_at_milliseconds=$6,updated_at=now()
			WHERE tenant_id=$1 AND domain_id=$2 AND subscription_id=$3
		`, credential.TenantID, credential.DomainID, subscriptionID, relay.SubscriptionRebootstrapRequired, startSequence, nowMilliseconds); err != nil {
			return relay.SubscriptionRebootstrapResponse{}, fmt.Errorf("begin subscription rebootstrap: %w", err)
		}
	}
	if startSequence == nil {
		return relay.SubscriptionRebootstrapResponse{}, relay.NewProtocolError(relay.CodeCheckpointUnavailable, "no checkpoint cursor is available for recovery")
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO relay_subscription_rebootstrap_requests (
			tenant_id,domain_id,retry_id,subscription_id,requested_at_milliseconds,result_start_sequence,result_updated_at_milliseconds
		) VALUES ($1,$2,$3,$4,$5,$6,$7)
	`, credential.TenantID, credential.DomainID, request.RetryID, subscriptionID, request.RequestedAtMilliseconds, *startSequence, nowMilliseconds); err != nil {
		return relay.SubscriptionRebootstrapResponse{}, fmt.Errorf("record subscription rebootstrap request: %w", err)
	}
	if err := insertRelayAudit(ctx, tx, credential.TenantID, credential.DomainID, &credential.MemberID, nil, "subscription_rebootstrap_requested", nowMilliseconds); err != nil {
		return relay.SubscriptionRebootstrapResponse{}, err
	}
	subscription, _, found, err := loadSubscription(ctx, tx, credential.TenantID, credential.DomainID, subscriptionID, "")
	if err != nil {
		return relay.SubscriptionRebootstrapResponse{}, err
	}
	if !found {
		return relay.SubscriptionRebootstrapResponse{}, relay.NewProtocolError(relay.CodeSubscriptionNotFound, "subscription was not found")
	}
	return relay.SubscriptionRebootstrapResponse{Acceptance: relay.AcceptanceAccepted, RetryID: request.RetryID, Subscription: subscription}, nil
}

// CompleteSubscriptionRebootstrap restores publication only after the member
// has durably recorded application receipts for every visible retained tail
// message. This is a delivery proof, not a content inspection.
func (s *RelayStore) CompleteSubscriptionRebootstrap(
	ctx context.Context,
	credential relay.Credential,
	completion relay.SubscriptionRebootstrapCompletion,
	nowMilliseconds int64,
) (relay.SubscriptionRebootstrapCompletionResponse, error) {
	if err := completion.Validate(); err != nil {
		return relay.SubscriptionRebootstrapCompletionResponse{}, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return relay.SubscriptionRebootstrapCompletionResponse{}, fmt.Errorf("begin subscription rebootstrap completion: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	response, err := completeSubscriptionRebootstrapTx(ctx, tx, credential, completion, nowMilliseconds)
	if err != nil {
		return relay.SubscriptionRebootstrapCompletionResponse{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return relay.SubscriptionRebootstrapCompletionResponse{}, fmt.Errorf("commit subscription rebootstrap completion: %w", err)
	}
	return response, nil
}

func completeSubscriptionRebootstrapTx(
	ctx context.Context,
	tx pgx.Tx,
	credential relay.Credential,
	completion relay.SubscriptionRebootstrapCompletion,
	nowMilliseconds int64,
) (relay.SubscriptionRebootstrapCompletionResponse, error) {
	if err := completion.Validate(); err != nil {
		return relay.SubscriptionRebootstrapCompletionResponse{}, err
	}
	completedThrough, err := relay.DecodeCursor(completion.CompletedThroughCursor)
	if err != nil {
		return relay.SubscriptionRebootstrapCompletionResponse{}, relay.NewProtocolError(relay.CodeInvalidCursor, "rebootstrap completion cursor is invalid")
	}
	if _, err := loadRelayTenant(ctx, tx, credential.TenantID, "FOR SHARE"); err != nil {
		return relay.SubscriptionRebootstrapCompletionResponse{}, err
	}
	if _, _, _, _, _, lastSequence, err := loadRelayDomain(ctx, tx, credential.TenantID, credential.DomainID, "FOR UPDATE"); err != nil {
		return relay.SubscriptionRebootstrapCompletionResponse{}, err
	} else if completedThrough > uint64(lastSequence) {
		return relay.SubscriptionRebootstrapCompletionResponse{}, relay.NewProtocolError(relay.CodeInvalidCursor, "rebootstrap completion cursor is beyond the relay tail")
	}
	member, found, err := loadRelayMember(ctx, tx, credential.TenantID, credential.DomainID, credential.MemberID, "FOR SHARE")
	if err != nil {
		return relay.SubscriptionRebootstrapCompletionResponse{}, err
	}
	if !found {
		return relay.SubscriptionRebootstrapCompletionResponse{}, relay.NewProtocolError(relay.CodeMemberNotFound, "member was not found")
	}
	if err := member.Authorize(credential, relay.CapabilityAcknowledgeMessage, nowMilliseconds); err != nil {
		return relay.SubscriptionRebootstrapCompletionResponse{}, err
	}
	subscriptionID, status, err := loadReadableMemberSubscription(ctx, tx, credential.TenantID, credential.DomainID, credential.MemberID, "FOR UPDATE")
	if err != nil {
		return relay.SubscriptionRebootstrapCompletionResponse{}, err
	}

	var storedSubscriptionID uuid.UUID
	var storedCompletedThrough, storedCompletedAt, storedUpdatedAt int64
	err = tx.QueryRow(ctx, `
		SELECT subscription_id, completed_through_sequence, completed_at_milliseconds, result_updated_at_milliseconds
		FROM relay_subscription_rebootstrap_completions
		WHERE tenant_id=$1 AND domain_id=$2 AND retry_id=$3
		FOR UPDATE
	`, credential.TenantID, credential.DomainID, completion.RetryID).Scan(
		&storedSubscriptionID, &storedCompletedThrough, &storedCompletedAt, &storedUpdatedAt,
	)
	if err == nil {
		if storedSubscriptionID != subscriptionID || storedCompletedThrough != int64(completedThrough) || storedCompletedAt != completion.CompletedAtMilliseconds {
			return relay.SubscriptionRebootstrapCompletionResponse{}, relay.NewProtocolError(relay.CodeSubscriptionCollision, "subscription rebootstrap completion retry ID was reused")
		}
		subscription, _, found, loadErr := loadSubscription(ctx, tx, credential.TenantID, credential.DomainID, subscriptionID, "")
		if loadErr != nil {
			return relay.SubscriptionRebootstrapCompletionResponse{}, loadErr
		}
		if !found {
			return relay.SubscriptionRebootstrapCompletionResponse{}, relay.NewProtocolError(relay.CodeSubscriptionNotFound, "subscription was not found")
		}
		subscription.Status = relay.SubscriptionActive
		subscription.StartCursor = nil
		subscription.UpdatedAtMilliseconds = storedUpdatedAt
		return relay.SubscriptionRebootstrapCompletionResponse{Acceptance: relay.AcceptanceDuplicate, RetryID: completion.RetryID, Subscription: subscription}, nil
	}
	if err != pgx.ErrNoRows {
		return relay.SubscriptionRebootstrapCompletionResponse{}, err
	}
	if status != relay.SubscriptionRebootstrapRequired {
		return relay.SubscriptionRebootstrapCompletionResponse{}, relay.NewProtocolError(relay.CodeInvalidSubscription, "subscription does not require rebootstrap")
	}
	var startSequence *int64
	if err := tx.QueryRow(ctx, `SELECT start_sequence FROM relay_subscriptions WHERE tenant_id=$1 AND domain_id=$2 AND subscription_id=$3`, credential.TenantID, credential.DomainID, subscriptionID).Scan(&startSequence); err != nil {
		return relay.SubscriptionRebootstrapCompletionResponse{}, fmt.Errorf("load rebootstrap cursor: %w", err)
	}
	if startSequence == nil || completedThrough < uint64(*startSequence) {
		return relay.SubscriptionRebootstrapCompletionResponse{}, relay.NewProtocolError(relay.CodeRebootstrapIncomplete, "checkpoint tail has not been restored")
	}

	var missing bool
	err = tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM relay_messages m
			WHERE m.tenant_id=$1 AND m.domain_id=$2
			  AND m.domain_sequence > $3 AND m.domain_sequence <= $4
			  AND m.publisher_subscription_id <> $5
			  AND (m.checkpoint_fence_id IS NULL OR EXISTS (
			      SELECT 1 FROM relay_checkpoint_fences f
			      WHERE f.tenant_id=m.tenant_id AND f.domain_id=m.domain_id
			        AND f.fence_id=m.checkpoint_fence_id AND f.status='activated'))
			  AND NOT EXISTS (
			      SELECT 1 FROM relay_acknowledgments a
			      WHERE a.tenant_id=m.tenant_id AND a.domain_id=m.domain_id
			        AND a.message_id=m.message_id AND a.subscription_id=$5
			        AND a.stage='applied')
		)
	`, credential.TenantID, credential.DomainID, *startSequence, int64(completedThrough), subscriptionID).Scan(&missing)
	if err != nil {
		return relay.SubscriptionRebootstrapCompletionResponse{}, fmt.Errorf("verify rebootstrap acknowledgments: %w", err)
	}
	if missing {
		return relay.SubscriptionRebootstrapCompletionResponse{}, relay.NewProtocolError(relay.CodeRebootstrapIncomplete, "checkpoint tail has unapplied messages")
	}
	if _, err := tx.Exec(ctx, `
		UPDATE relay_subscriptions
		SET status=$4,start_sequence=NULL,updated_at_milliseconds=$5,updated_at=now()
		WHERE tenant_id=$1 AND domain_id=$2 AND subscription_id=$3
	`, credential.TenantID, credential.DomainID, subscriptionID, relay.SubscriptionActive, nowMilliseconds); err != nil {
		return relay.SubscriptionRebootstrapCompletionResponse{}, fmt.Errorf("complete subscription rebootstrap: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO relay_subscription_rebootstrap_completions (
			tenant_id,domain_id,retry_id,subscription_id,recovery_start_sequence,completed_through_sequence,completed_at_milliseconds,result_updated_at_milliseconds
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
	`, credential.TenantID, credential.DomainID, completion.RetryID, subscriptionID, int64(*startSequence), int64(completedThrough), completion.CompletedAtMilliseconds, nowMilliseconds); err != nil {
		return relay.SubscriptionRebootstrapCompletionResponse{}, fmt.Errorf("record subscription rebootstrap completion: %w", err)
	}
	if err := insertRelayAudit(ctx, tx, credential.TenantID, credential.DomainID, &credential.MemberID, nil, "subscription_rebootstrap_completed", nowMilliseconds); err != nil {
		return relay.SubscriptionRebootstrapCompletionResponse{}, err
	}
	subscription, _, found, err := loadSubscription(ctx, tx, credential.TenantID, credential.DomainID, subscriptionID, "")
	if err != nil {
		return relay.SubscriptionRebootstrapCompletionResponse{}, err
	}
	if !found {
		return relay.SubscriptionRebootstrapCompletionResponse{}, relay.NewProtocolError(relay.CodeSubscriptionNotFound, "subscription was not found")
	}
	return relay.SubscriptionRebootstrapCompletionResponse{Acceptance: relay.AcceptanceAccepted, RetryID: completion.RetryID, Subscription: subscription}, nil
}
