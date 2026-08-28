package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/robreuss/FacetsNode/internal/relay"
)

// RequestSubscriptionRebootstrap lets an enrolled member discard only its own
// local replica and restart from the exact activated checkpoint/root pair its
// client authorized. The relay validates opaque identities and never opens the
// checkpoint or FEF payload.
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
	leaseExpiresAt, err := request.LeaseExpiresAt(nowMilliseconds)
	if err != nil {
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

	var storedSubscriptionID, storedCheckpointID, storedRootMessageID uuid.UUID
	var storedRequestedAt, storedLeaseDuration, storedLeaseExpiresAt int64
	var storedStart, storedUpdatedAt int64
	err = tx.QueryRow(ctx, `
		SELECT subscription_id, checkpoint_id, root_message_id,
		       requested_at_milliseconds, lease_duration_milliseconds,
		       lease_expires_at_milliseconds, result_start_sequence,
		       result_updated_at_milliseconds
		FROM relay_subscription_rebootstrap_requests
		WHERE tenant_id=$1 AND domain_id=$2 AND retry_id=$3
		FOR UPDATE
	`, credential.TenantID, credential.DomainID, request.RetryID).Scan(
		&storedSubscriptionID, &storedCheckpointID, &storedRootMessageID,
		&storedRequestedAt, &storedLeaseDuration, &storedLeaseExpiresAt,
		&storedStart, &storedUpdatedAt,
	)
	if err == nil {
		if storedSubscriptionID != subscriptionID ||
			storedCheckpointID != request.CheckpointID ||
			storedRootMessageID != request.RootMessageID ||
			storedRequestedAt != request.RequestedAtMilliseconds ||
			storedLeaseDuration != request.LeaseDurationMilliseconds {
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
		return relay.SubscriptionRebootstrapResponse{
			Acceptance: relay.AcceptanceDuplicate, RetryID: request.RetryID,
			CheckpointID: request.CheckpointID, RootMessageID: request.RootMessageID,
			LeaseExpiresAtMilliseconds: storedLeaseExpiresAt,
			Subscription:               subscription,
		}, nil
	}
	if err != pgx.ErrNoRows {
		return relay.SubscriptionRebootstrapResponse{}, err
	}

	checkpointStart, checkpointIsLatest, err := activatedCheckpointRecoverySelection(
		ctx, tx, credential.TenantID, credential.DomainID,
		request.CheckpointID, request.RootMessageID,
	)
	if err != nil {
		return relay.SubscriptionRebootstrapResponse{}, err
	}
	if checkpointStart == nil {
		return relay.SubscriptionRebootstrapResponse{}, relay.NewProtocolError(relay.CodeCheckpointUnavailable, "authorized recovery checkpoint/root is unavailable")
	}

	var startSequence *int64
	if status == relay.SubscriptionRebootstrapRequired {
		var active bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1
				FROM relay_subscription_rebootstrap_requests r
				WHERE r.tenant_id=$1 AND r.domain_id=$2 AND r.subscription_id=$3
				  AND r.lease_expires_at_milliseconds>$4
				  AND NOT EXISTS (
				      SELECT 1 FROM relay_subscription_rebootstrap_cancellations c
				      WHERE c.tenant_id=r.tenant_id AND c.domain_id=r.domain_id
				        AND c.request_retry_id=r.retry_id)
				  AND NOT EXISTS (
				      SELECT 1 FROM relay_subscription_rebootstrap_completions completion
				      WHERE completion.tenant_id=r.tenant_id AND completion.domain_id=r.domain_id
				        AND completion.request_retry_id=r.retry_id)
			)
		`, credential.TenantID, credential.DomainID, subscriptionID, nowMilliseconds).Scan(&active); err != nil {
			return relay.SubscriptionRebootstrapResponse{}, fmt.Errorf("verify active subscription rebootstrap: %w", err)
		}
		if active {
			return relay.SubscriptionRebootstrapResponse{}, relay.NewProtocolError(relay.CodeSubscriptionCollision, "subscription recovery already has an active lease")
		}
	}
	if !checkpointIsLatest {
		return relay.SubscriptionRebootstrapResponse{}, relay.NewProtocolError(relay.CodeCheckpointUnavailable, "authorized recovery checkpoint is not the latest activated checkpoint")
	}
	startSequence = checkpointStart
	if _, err := tx.Exec(ctx, `
			DELETE FROM relay_acknowledgments a
			USING relay_messages m
			WHERE a.tenant_id=$1 AND a.domain_id=$2
			  AND a.subscription_id=$3
			  AND m.tenant_id=a.tenant_id AND m.domain_id=a.domain_id
			  AND m.message_id=a.message_id AND m.domain_sequence>$4
	`, credential.TenantID, credential.DomainID, subscriptionID, *startSequence); err != nil {
		return relay.SubscriptionRebootstrapResponse{}, fmt.Errorf("reset rebootstrap acknowledgments: %w", err)
	}
	if _, err := tx.Exec(ctx, `
			UPDATE relay_subscriptions
			SET status=$4,start_sequence=$5,updated_at_milliseconds=$6,updated_at=now()
			WHERE tenant_id=$1 AND domain_id=$2 AND subscription_id=$3
	`, credential.TenantID, credential.DomainID, subscriptionID, relay.SubscriptionRebootstrapRequired, startSequence, nowMilliseconds); err != nil {
		return relay.SubscriptionRebootstrapResponse{}, fmt.Errorf("begin subscription rebootstrap: %w", err)
	}
	if startSequence == nil {
		return relay.SubscriptionRebootstrapResponse{}, relay.NewProtocolError(relay.CodeCheckpointUnavailable, "no checkpoint cursor is available for recovery")
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO relay_subscription_rebootstrap_requests (
			tenant_id,domain_id,retry_id,subscription_id,checkpoint_id,root_message_id,
			requested_at_milliseconds,lease_duration_milliseconds,
			lease_expires_at_milliseconds,result_start_sequence,result_updated_at_milliseconds
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
	`, credential.TenantID, credential.DomainID, request.RetryID, subscriptionID,
		request.CheckpointID, request.RootMessageID, request.RequestedAtMilliseconds,
		request.LeaseDurationMilliseconds, leaseExpiresAt,
		*startSequence, nowMilliseconds); err != nil {
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
	return relay.SubscriptionRebootstrapResponse{
		Acceptance: relay.AcceptanceAccepted, RetryID: request.RetryID,
		CheckpointID: request.CheckpointID, RootMessageID: request.RootMessageID,
		LeaseExpiresAtMilliseconds: leaseExpiresAt,
		Subscription:               subscription,
	}, nil
}

// RenewSubscriptionRebootstrap extends the exact active recovery request. It
// never rewrites the subscription start cursor or deletes acknowledgements.
func (s *RelayStore) RenewSubscriptionRebootstrap(
	ctx context.Context,
	credential relay.Credential,
	renewal relay.SubscriptionRebootstrapRenewal,
	nowMilliseconds int64,
) (relay.SubscriptionRebootstrapRenewalResponse, error) {
	if err := renewal.Validate(); err != nil {
		return relay.SubscriptionRebootstrapRenewalResponse{}, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return relay.SubscriptionRebootstrapRenewalResponse{}, fmt.Errorf("begin subscription rebootstrap renewal: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	response, err := renewSubscriptionRebootstrapTx(
		ctx, tx, credential, renewal, nowMilliseconds,
	)
	if err != nil {
		return relay.SubscriptionRebootstrapRenewalResponse{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return relay.SubscriptionRebootstrapRenewalResponse{}, fmt.Errorf("commit subscription rebootstrap renewal: %w", err)
	}
	return response, nil
}

func renewSubscriptionRebootstrapTx(
	ctx context.Context,
	tx pgx.Tx,
	credential relay.Credential,
	renewal relay.SubscriptionRebootstrapRenewal,
	nowMilliseconds int64,
) (relay.SubscriptionRebootstrapRenewalResponse, error) {
	if err := renewal.Validate(); err != nil {
		return relay.SubscriptionRebootstrapRenewalResponse{}, err
	}
	candidateExpiresAt, err := renewal.LeaseExpiresAt(nowMilliseconds)
	if err != nil {
		return relay.SubscriptionRebootstrapRenewalResponse{}, err
	}
	if _, err := loadRelayTenant(ctx, tx, credential.TenantID, "FOR SHARE"); err != nil {
		return relay.SubscriptionRebootstrapRenewalResponse{}, err
	}
	if _, _, _, _, _, _, err := loadRelayDomain(ctx, tx, credential.TenantID, credential.DomainID, "FOR UPDATE"); err != nil {
		return relay.SubscriptionRebootstrapRenewalResponse{}, err
	}
	member, found, err := loadRelayMember(ctx, tx, credential.TenantID, credential.DomainID, credential.MemberID, "FOR SHARE")
	if err != nil {
		return relay.SubscriptionRebootstrapRenewalResponse{}, err
	}
	if !found {
		return relay.SubscriptionRebootstrapRenewalResponse{}, relay.NewProtocolError(relay.CodeMemberNotFound, "member was not found")
	}
	if err := member.Authorize(credential, relay.CapabilityFetchMessage, nowMilliseconds); err != nil {
		return relay.SubscriptionRebootstrapRenewalResponse{}, err
	}
	subscriptionID, status, err := loadReadableMemberSubscription(ctx, tx, credential.TenantID, credential.DomainID, credential.MemberID, "FOR UPDATE")
	if err != nil {
		return relay.SubscriptionRebootstrapRenewalResponse{}, err
	}

	var storedSubscriptionID, storedRequestRetryID, storedCheckpointID, storedRootMessageID uuid.UUID
	var storedExpectedExpiry, storedRequestedAt, storedDuration int64
	var storedPreviousExpiry, storedExpiry, storedStart, storedUpdatedAt int64
	err = tx.QueryRow(ctx, `
		SELECT subscription_id,request_retry_id,checkpoint_id,root_message_id,
		       expected_lease_expires_at_milliseconds,requested_at_milliseconds,
		       lease_duration_milliseconds,previous_lease_expires_at_milliseconds,
		       lease_expires_at_milliseconds,result_start_sequence,
		       result_updated_at_milliseconds
		FROM relay_subscription_rebootstrap_renewals
		WHERE tenant_id=$1 AND domain_id=$2 AND retry_id=$3
		FOR UPDATE
	`, credential.TenantID, credential.DomainID, renewal.RetryID).Scan(
		&storedSubscriptionID, &storedRequestRetryID, &storedCheckpointID,
		&storedRootMessageID, &storedExpectedExpiry, &storedRequestedAt,
		&storedDuration, &storedPreviousExpiry, &storedExpiry, &storedStart,
		&storedUpdatedAt,
	)
	if err == nil {
		if storedSubscriptionID != subscriptionID ||
			storedRequestRetryID != renewal.RequestRetryID ||
			storedCheckpointID != renewal.CheckpointID ||
			storedRootMessageID != renewal.RootMessageID ||
			storedExpectedExpiry != renewal.ExpectedLeaseExpiresAtMilliseconds ||
			storedRequestedAt != renewal.RequestedAtMilliseconds ||
			storedDuration != renewal.LeaseDurationMilliseconds {
			return relay.SubscriptionRebootstrapRenewalResponse{}, relay.NewProtocolError(relay.CodeSubscriptionCollision, "subscription rebootstrap renewal retry ID was reused")
		}
		subscription, _, found, loadErr := loadSubscription(ctx, tx, credential.TenantID, credential.DomainID, subscriptionID, "")
		if loadErr != nil {
			return relay.SubscriptionRebootstrapRenewalResponse{}, loadErr
		}
		if !found {
			return relay.SubscriptionRebootstrapRenewalResponse{}, relay.NewProtocolError(relay.CodeSubscriptionNotFound, "subscription was not found")
		}
		start := relay.EncodeCursor(uint64(storedStart))
		subscription.Status = relay.SubscriptionRebootstrapRequired
		subscription.StartCursor = &start
		subscription.UpdatedAtMilliseconds = storedUpdatedAt
		return relay.SubscriptionRebootstrapRenewalResponse{
			Acceptance: relay.AcceptanceDuplicate, RetryID: renewal.RetryID,
			RequestRetryID: renewal.RequestRetryID,
			CheckpointID:   renewal.CheckpointID, RootMessageID: renewal.RootMessageID,
			PreviousLeaseExpiresAtMilliseconds: storedPreviousExpiry,
			LeaseExpiresAtMilliseconds:         storedExpiry, Subscription: subscription,
		}, nil
	}
	if err != pgx.ErrNoRows {
		return relay.SubscriptionRebootstrapRenewalResponse{}, err
	}

	var requestSubscriptionID, requestCheckpointID, requestRootMessageID uuid.UUID
	var currentExpiry, startSequence, resultUpdatedAt int64
	err = tx.QueryRow(ctx, `
		SELECT subscription_id,checkpoint_id,root_message_id,
		       lease_expires_at_milliseconds,result_start_sequence,
		       result_updated_at_milliseconds
		FROM relay_subscription_rebootstrap_requests
		WHERE tenant_id=$1 AND domain_id=$2 AND retry_id=$3
		FOR UPDATE
	`, credential.TenantID, credential.DomainID, renewal.RequestRetryID).Scan(
		&requestSubscriptionID, &requestCheckpointID, &requestRootMessageID,
		&currentExpiry, &startSequence, &resultUpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return relay.SubscriptionRebootstrapRenewalResponse{}, relay.NewProtocolError(relay.CodeSubscriptionCollision, "subscription rebootstrap renewal has no matching request")
	}
	if err != nil {
		return relay.SubscriptionRebootstrapRenewalResponse{}, err
	}
	if requestSubscriptionID != subscriptionID ||
		requestCheckpointID != renewal.CheckpointID ||
		requestRootMessageID != renewal.RootMessageID {
		return relay.SubscriptionRebootstrapRenewalResponse{}, relay.NewProtocolError(relay.CodeSubscriptionCollision, "subscription rebootstrap renewal does not match its request")
	}
	if currentExpiry != renewal.ExpectedLeaseExpiresAtMilliseconds {
		return relay.SubscriptionRebootstrapRenewalResponse{}, relay.NewProtocolError(relay.CodeSubscriptionCollision, "subscription rebootstrap renewal lease is stale")
	}
	var finalized bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM relay_subscription_rebootstrap_cancellations
			WHERE tenant_id=$1 AND domain_id=$2 AND request_retry_id=$3
			UNION ALL
			SELECT 1 FROM relay_subscription_rebootstrap_completions
			WHERE tenant_id=$1 AND domain_id=$2 AND request_retry_id=$3
		)
	`, credential.TenantID, credential.DomainID, renewal.RequestRetryID).Scan(&finalized); err != nil {
		return relay.SubscriptionRebootstrapRenewalResponse{}, fmt.Errorf("verify subscription rebootstrap renewal state: %w", err)
	}
	if finalized || currentExpiry <= nowMilliseconds {
		return relay.SubscriptionRebootstrapRenewalResponse{}, relay.NewProtocolError(relay.CodeRebootstrapExpired, "subscription rebootstrap lease expired or was finalized")
	}
	if status != relay.SubscriptionRebootstrapRequired {
		return relay.SubscriptionRebootstrapRenewalResponse{}, relay.NewProtocolError(relay.CodeSubscriptionCollision, "subscription rebootstrap renewal state changed")
	}
	leaseExpiresAt := currentExpiry
	if candidateExpiresAt > leaseExpiresAt {
		leaseExpiresAt = candidateExpiresAt
	}
	if _, err := tx.Exec(ctx, `
		UPDATE relay_subscription_rebootstrap_requests
		SET lease_expires_at_milliseconds=$4
		WHERE tenant_id=$1 AND domain_id=$2 AND retry_id=$3
	`, credential.TenantID, credential.DomainID, renewal.RequestRetryID, leaseExpiresAt); err != nil {
		return relay.SubscriptionRebootstrapRenewalResponse{}, fmt.Errorf("extend subscription rebootstrap lease: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO relay_subscription_rebootstrap_renewals (
			tenant_id,domain_id,retry_id,subscription_id,request_retry_id,
			checkpoint_id,root_message_id,expected_lease_expires_at_milliseconds,
			requested_at_milliseconds,lease_duration_milliseconds,
			previous_lease_expires_at_milliseconds,lease_expires_at_milliseconds,
			result_start_sequence,result_updated_at_milliseconds
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
	`, credential.TenantID, credential.DomainID, renewal.RetryID, subscriptionID,
		renewal.RequestRetryID, renewal.CheckpointID, renewal.RootMessageID,
		renewal.ExpectedLeaseExpiresAtMilliseconds, renewal.RequestedAtMilliseconds,
		renewal.LeaseDurationMilliseconds, currentExpiry, leaseExpiresAt,
		startSequence, resultUpdatedAt); err != nil {
		return relay.SubscriptionRebootstrapRenewalResponse{}, fmt.Errorf("record subscription rebootstrap renewal: %w", err)
	}
	if err := insertRelayAudit(ctx, tx, credential.TenantID, credential.DomainID, &credential.MemberID, nil, "subscription_rebootstrap_renewed", nowMilliseconds); err != nil {
		return relay.SubscriptionRebootstrapRenewalResponse{}, err
	}
	subscription, _, found, err := loadSubscription(ctx, tx, credential.TenantID, credential.DomainID, subscriptionID, "")
	if err != nil {
		return relay.SubscriptionRebootstrapRenewalResponse{}, err
	}
	if !found {
		return relay.SubscriptionRebootstrapRenewalResponse{}, relay.NewProtocolError(relay.CodeSubscriptionNotFound, "subscription was not found")
	}
	start := relay.EncodeCursor(uint64(startSequence))
	if subscription.Status != relay.SubscriptionRebootstrapRequired ||
		subscription.StartCursor == nil || *subscription.StartCursor != start {
		return relay.SubscriptionRebootstrapRenewalResponse{}, relay.NewProtocolError(relay.CodeSubscriptionCollision, "subscription rebootstrap renewal cursor changed")
	}
	return relay.SubscriptionRebootstrapRenewalResponse{
		Acceptance: relay.AcceptanceAccepted, RetryID: renewal.RetryID,
		RequestRetryID: renewal.RequestRetryID,
		CheckpointID:   renewal.CheckpointID, RootMessageID: renewal.RootMessageID,
		PreviousLeaseExpiresAtMilliseconds: currentExpiry,
		LeaseExpiresAtMilliseconds:         leaseExpiresAt, Subscription: subscription,
	}, nil
}

// CancelSubscriptionRebootstrap releases only the bounded recovery lease. The
// subscription remains fenced in rebootstrap_required until a later exact
// recovery request completes successfully.
func (s *RelayStore) CancelSubscriptionRebootstrap(
	ctx context.Context,
	credential relay.Credential,
	cancellation relay.SubscriptionRebootstrapCancellation,
	nowMilliseconds int64,
) (relay.SubscriptionRebootstrapCancellationResponse, error) {
	if err := cancellation.Validate(); err != nil {
		return relay.SubscriptionRebootstrapCancellationResponse{}, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return relay.SubscriptionRebootstrapCancellationResponse{}, fmt.Errorf("begin subscription rebootstrap cancellation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	response, err := cancelSubscriptionRebootstrapTx(
		ctx, tx, credential, cancellation, nowMilliseconds,
	)
	if err != nil {
		return relay.SubscriptionRebootstrapCancellationResponse{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return relay.SubscriptionRebootstrapCancellationResponse{}, fmt.Errorf("commit subscription rebootstrap cancellation: %w", err)
	}
	return response, nil
}

func cancelSubscriptionRebootstrapTx(
	ctx context.Context,
	tx pgx.Tx,
	credential relay.Credential,
	cancellation relay.SubscriptionRebootstrapCancellation,
	nowMilliseconds int64,
) (relay.SubscriptionRebootstrapCancellationResponse, error) {
	if err := cancellation.Validate(); err != nil {
		return relay.SubscriptionRebootstrapCancellationResponse{}, err
	}
	if _, err := loadRelayTenant(ctx, tx, credential.TenantID, "FOR SHARE"); err != nil {
		return relay.SubscriptionRebootstrapCancellationResponse{}, err
	}
	if _, _, _, _, _, _, err := loadRelayDomain(ctx, tx, credential.TenantID, credential.DomainID, "FOR UPDATE"); err != nil {
		return relay.SubscriptionRebootstrapCancellationResponse{}, err
	}
	member, found, err := loadRelayMember(
		ctx, tx, credential.TenantID, credential.DomainID,
		credential.MemberID, "FOR SHARE",
	)
	if err != nil {
		return relay.SubscriptionRebootstrapCancellationResponse{}, err
	}
	if !found {
		return relay.SubscriptionRebootstrapCancellationResponse{}, relay.NewProtocolError(relay.CodeMemberNotFound, "member was not found")
	}
	if err := member.Authorize(credential, relay.CapabilityFetchMessage, nowMilliseconds); err != nil {
		return relay.SubscriptionRebootstrapCancellationResponse{}, err
	}
	subscriptionID, _, err := loadReadableMemberSubscription(
		ctx, tx, credential.TenantID, credential.DomainID,
		credential.MemberID, "FOR UPDATE",
	)
	if err != nil {
		return relay.SubscriptionRebootstrapCancellationResponse{}, err
	}

	var storedSubscriptionID, storedRequestRetryID uuid.UUID
	var storedCheckpointID, storedRootMessageID uuid.UUID
	var storedCancelledAt, storedUpdatedAt int64
	err = tx.QueryRow(ctx, `
		SELECT subscription_id,request_retry_id,checkpoint_id,root_message_id,
		       cancelled_at_milliseconds,result_updated_at_milliseconds
		FROM relay_subscription_rebootstrap_cancellations
		WHERE tenant_id=$1 AND domain_id=$2 AND retry_id=$3
		FOR UPDATE
	`, credential.TenantID, credential.DomainID, cancellation.RetryID).Scan(
		&storedSubscriptionID, &storedRequestRetryID, &storedCheckpointID,
		&storedRootMessageID, &storedCancelledAt, &storedUpdatedAt,
	)
	if err == nil {
		if storedSubscriptionID != subscriptionID ||
			storedRequestRetryID != cancellation.RequestRetryID ||
			storedCheckpointID != cancellation.CheckpointID ||
			storedRootMessageID != cancellation.RootMessageID ||
			storedCancelledAt != cancellation.CancelledAtMilliseconds {
			return relay.SubscriptionRebootstrapCancellationResponse{}, relay.NewProtocolError(relay.CodeSubscriptionCollision, "subscription rebootstrap cancellation retry ID was reused")
		}
		subscription, _, found, loadErr := loadSubscription(
			ctx, tx, credential.TenantID, credential.DomainID,
			subscriptionID, "",
		)
		if loadErr != nil {
			return relay.SubscriptionRebootstrapCancellationResponse{}, loadErr
		}
		if !found {
			return relay.SubscriptionRebootstrapCancellationResponse{}, relay.NewProtocolError(relay.CodeSubscriptionNotFound, "subscription was not found")
		}
		subscription.UpdatedAtMilliseconds = storedUpdatedAt
		return relay.SubscriptionRebootstrapCancellationResponse{
			Acceptance: relay.AcceptanceDuplicate, RetryID: cancellation.RetryID,
			RequestRetryID: cancellation.RequestRetryID,
			CheckpointID:   cancellation.CheckpointID, RootMessageID: cancellation.RootMessageID,
			Subscription: subscription,
		}, nil
	}
	if err != pgx.ErrNoRows {
		return relay.SubscriptionRebootstrapCancellationResponse{}, err
	}

	var requestSubscriptionID, requestCheckpointID, requestRootMessageID uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT subscription_id,checkpoint_id,root_message_id
		FROM relay_subscription_rebootstrap_requests
		WHERE tenant_id=$1 AND domain_id=$2 AND retry_id=$3
		FOR SHARE
	`, credential.TenantID, credential.DomainID, cancellation.RequestRetryID).Scan(
		&requestSubscriptionID, &requestCheckpointID, &requestRootMessageID,
	)
	if err == pgx.ErrNoRows || requestSubscriptionID != subscriptionID ||
		requestCheckpointID != cancellation.CheckpointID ||
		requestRootMessageID != cancellation.RootMessageID {
		return relay.SubscriptionRebootstrapCancellationResponse{}, relay.NewProtocolError(relay.CodeSubscriptionCollision, "subscription rebootstrap cancellation does not match its request")
	}
	if err != nil {
		return relay.SubscriptionRebootstrapCancellationResponse{}, err
	}
	var alreadyFinal bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM relay_subscription_rebootstrap_cancellations
			WHERE tenant_id=$1 AND domain_id=$2 AND subscription_id=$3
			  AND request_retry_id=$4
			UNION ALL
			SELECT 1 FROM relay_subscription_rebootstrap_completions
			WHERE tenant_id=$1 AND domain_id=$2 AND subscription_id=$3
			  AND request_retry_id=$4
		)
	`, credential.TenantID, credential.DomainID, subscriptionID,
		cancellation.RequestRetryID).Scan(&alreadyFinal); err != nil {
		return relay.SubscriptionRebootstrapCancellationResponse{}, err
	}
	if alreadyFinal {
		return relay.SubscriptionRebootstrapCancellationResponse{}, relay.NewProtocolError(relay.CodeSubscriptionCollision, "subscription rebootstrap is already finalized")
	}
	subscription, _, found, err := loadSubscription(
		ctx, tx, credential.TenantID, credential.DomainID,
		subscriptionID, "",
	)
	if err != nil {
		return relay.SubscriptionRebootstrapCancellationResponse{}, err
	}
	if !found {
		return relay.SubscriptionRebootstrapCancellationResponse{}, relay.NewProtocolError(relay.CodeSubscriptionNotFound, "subscription was not found")
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO relay_subscription_rebootstrap_cancellations (
			tenant_id,domain_id,retry_id,subscription_id,request_retry_id,
			checkpoint_id,root_message_id,cancelled_at_milliseconds,
			result_updated_at_milliseconds
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
	`, credential.TenantID, credential.DomainID, cancellation.RetryID,
		subscriptionID, cancellation.RequestRetryID,
		cancellation.CheckpointID, cancellation.RootMessageID,
		cancellation.CancelledAtMilliseconds,
		subscription.UpdatedAtMilliseconds); err != nil {
		return relay.SubscriptionRebootstrapCancellationResponse{}, fmt.Errorf("record subscription rebootstrap cancellation: %w", err)
	}
	if err := insertRelayAudit(
		ctx, tx, credential.TenantID, credential.DomainID,
		&credential.MemberID, nil, "subscription_rebootstrap_cancelled",
		nowMilliseconds,
	); err != nil {
		return relay.SubscriptionRebootstrapCancellationResponse{}, err
	}
	return relay.SubscriptionRebootstrapCancellationResponse{
		Acceptance: relay.AcceptanceAccepted, RetryID: cancellation.RetryID,
		RequestRetryID: cancellation.RequestRetryID,
		CheckpointID:   cancellation.CheckpointID, RootMessageID: cancellation.RootMessageID,
		Subscription: subscription,
	}, nil
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

	var storedSubscriptionID, storedRequestRetryID, storedCheckpointID, storedRootMessageID uuid.UUID
	var storedCompletedThrough, storedCompletedAt, storedUpdatedAt int64
	err = tx.QueryRow(ctx, `
		SELECT subscription_id, request_retry_id, checkpoint_id, root_message_id,
		       completed_through_sequence, completed_at_milliseconds, result_updated_at_milliseconds
		FROM relay_subscription_rebootstrap_completions
		WHERE tenant_id=$1 AND domain_id=$2 AND retry_id=$3
		FOR UPDATE
	`, credential.TenantID, credential.DomainID, completion.RetryID).Scan(
		&storedSubscriptionID, &storedRequestRetryID, &storedCheckpointID,
		&storedRootMessageID, &storedCompletedThrough, &storedCompletedAt,
		&storedUpdatedAt,
	)
	if err == nil {
		if storedSubscriptionID != subscriptionID ||
			storedRequestRetryID != completion.RequestRetryID ||
			storedCheckpointID != completion.CheckpointID ||
			storedRootMessageID != completion.RootMessageID ||
			storedCompletedThrough != int64(completedThrough) ||
			storedCompletedAt != completion.CompletedAtMilliseconds {
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
		return relay.SubscriptionRebootstrapCompletionResponse{
			Acceptance: relay.AcceptanceDuplicate, RetryID: completion.RetryID,
			RequestRetryID: completion.RequestRetryID,
			CheckpointID:   completion.CheckpointID, RootMessageID: completion.RootMessageID,
			Subscription: subscription,
		}, nil
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
	var requestSubscriptionID, requestCheckpointID, requestRootMessageID uuid.UUID
	var requestStartSequence, requestLeaseExpiresAt int64
	err = tx.QueryRow(ctx, `
		SELECT subscription_id, checkpoint_id, root_message_id,
		       result_start_sequence, lease_expires_at_milliseconds
		FROM relay_subscription_rebootstrap_requests
		WHERE tenant_id=$1 AND domain_id=$2 AND retry_id=$3
		FOR SHARE
	`, credential.TenantID, credential.DomainID, completion.RequestRetryID).Scan(
		&requestSubscriptionID, &requestCheckpointID, &requestRootMessageID,
		&requestStartSequence, &requestLeaseExpiresAt,
	)
	if err == pgx.ErrNoRows {
		return relay.SubscriptionRebootstrapCompletionResponse{}, relay.NewProtocolError(relay.CodeSubscriptionCollision, "rebootstrap completion has no matching request")
	}
	if err != nil {
		return relay.SubscriptionRebootstrapCompletionResponse{}, err
	}
	if requestSubscriptionID != subscriptionID ||
		requestCheckpointID != completion.CheckpointID ||
		requestRootMessageID != completion.RootMessageID ||
		requestStartSequence != *startSequence {
		return relay.SubscriptionRebootstrapCompletionResponse{}, relay.NewProtocolError(relay.CodeSubscriptionCollision, "rebootstrap completion does not match its authorized checkpoint/root")
	}
	var cancelled bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM relay_subscription_rebootstrap_cancellations
			WHERE tenant_id=$1 AND domain_id=$2 AND subscription_id=$3
			  AND request_retry_id=$4
		)
	`, credential.TenantID, credential.DomainID, subscriptionID,
		completion.RequestRetryID).Scan(&cancelled); err != nil {
		return relay.SubscriptionRebootstrapCompletionResponse{}, err
	}
	if nowMilliseconds >= requestLeaseExpiresAt || cancelled {
		return relay.SubscriptionRebootstrapCompletionResponse{}, relay.NewProtocolError(relay.CodeRebootstrapExpired, "subscription rebootstrap lease expired or was cancelled")
	}

	var missing bool
	err = tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM relay_messages m
			WHERE m.tenant_id=$1 AND m.domain_id=$2
			  AND m.domain_sequence > $3 AND m.domain_sequence <= $4
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
			tenant_id,domain_id,retry_id,subscription_id,request_retry_id,
			checkpoint_id,root_message_id,recovery_start_sequence,
			completed_through_sequence,completed_at_milliseconds,result_updated_at_milliseconds
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
	`, credential.TenantID, credential.DomainID, completion.RetryID, subscriptionID,
		completion.RequestRetryID, completion.CheckpointID, completion.RootMessageID,
		int64(*startSequence), int64(completedThrough),
		completion.CompletedAtMilliseconds, nowMilliseconds); err != nil {
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
	return relay.SubscriptionRebootstrapCompletionResponse{
		Acceptance: relay.AcceptanceAccepted, RetryID: completion.RetryID,
		RequestRetryID: completion.RequestRetryID,
		CheckpointID:   completion.CheckpointID, RootMessageID: completion.RootMessageID,
		Subscription: subscription,
	}, nil
}
