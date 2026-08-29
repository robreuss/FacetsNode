package postgres_test

import (
	"context"
	"os"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"

	postgresstore "github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/testfixture"
)

func TestPostgresCheckpointFreezesCollectionAndPersistsExactRetry(t *testing.T) {
	databaseURL := os.Getenv("FACETS_SERVER_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("FACETS_SERVER_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	lockDisposablePostgres(t, ctx, databaseURL)
	pool := openPool(t, ctx, databaseURL)
	if err := postgresstore.Migrate(ctx, pool); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	store := postgresstore.NewRelayStore(pool)
	tenantID, domainID := uuid.New(), uuid.New()
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM relay_tenants WHERE tenant_id=$1`, tenantID)
		pool.Close()
	})

	admin := relay.AdministrationCredential{TenantID: tenantID, DomainID: domainID, Token: postgresRelayToken(244)}
	adminDigest, err := relay.AdministrationDigest(admin)
	if err != nil {
		t.Fatal(err)
	}
	publisher := relay.Credential{TenantID: tenantID, DomainID: domainID, MemberID: uuid.New(), Token: postgresRelayToken(245)}
	publisherDigest, err := relay.AuthorizationDigest(publisher)
	if err != nil {
		t.Fatal(err)
	}
	domain := relay.DomainRegistration{
		Version: relay.SchemaVersion, TenantID: tenantID, DomainID: domainID,
		AdministrationDigest: adminDigest, CreatedAtMilliseconds: 1_000,
		MaximumMessageCount: 20, MaximumMessageByteCount: 1_000_000,
		MaximumBlobCount: 20, MaximumBlobByteCount: 1_000_000,
	}
	publisherRegistration := relay.MemberRegistration{
		Version: relay.SchemaVersion, TenantID: tenantID, DomainID: domainID,
		MemberID: publisher.MemberID, AuthorizationDigest: publisherDigest,
		Capabilities: []relay.Capability{
			relay.CapabilityPublishBlob, relay.CapabilityPublishCheckpoint,
			relay.CapabilityAcknowledgeMessage, relay.CapabilityFetchMessage,
			relay.CapabilityPublishMessage,
		},
		CreatedAtMilliseconds: 1_000,
	}
	if _, acceptance, err := postgresProvisionTenant(ctx, store, domain, publisherRegistration, publisher.MemberID, 243); err != nil || acceptance != relay.AcceptanceAccepted {
		t.Fatalf("provision tenant acceptance=%q err=%v", acceptance, err)
	}
	recipientSubscriptionID := uuid.New()
	if _, err := store.CreateSubscription(ctx, admin, relay.SubscriptionCreateRequest{RetryID: uuid.New(), SubscriptionID: recipientSubscriptionID, CreatedAtMilliseconds: 1_050}); err != nil {
		t.Fatal(err)
	}
	recipient := relay.Credential{TenantID: tenantID, DomainID: domainID, MemberID: uuid.New(), Token: postgresRelayToken(246)}
	recipientDigest, err := relay.AuthorizationDigest(recipient)
	if err != nil {
		t.Fatal(err)
	}
	recipientRegistration := relay.MemberRegistration{
		Version: relay.SchemaVersion, TenantID: tenantID, DomainID: domainID,
		MemberID: recipient.MemberID, AuthorizationDigest: recipientDigest,
		Capabilities: []relay.Capability{
			relay.CapabilityPublishBlob, relay.CapabilityAcknowledgeMessage,
			relay.CapabilityFetchMessage, relay.CapabilityPublishMessage,
		},
		CreatedAtMilliseconds: 1_050,
	}
	if acceptance, err := store.CreateSubscriptionMember(ctx, admin, recipientSubscriptionID, recipientRegistration, 1_050); err != nil || acceptance != relay.AcceptanceAccepted {
		t.Fatalf("create recipient acceptance=%q err=%v", acceptance, err)
	}

	fixture, err := testfixture.LoadRelayCarrier()
	if err != nil {
		t.Fatal(err)
	}
	first := fixture.Envelope
	first.TenantID, first.DomainID = tenantID, domainID
	first.MessageID, first.PublisherMemberID = uuid.New(), publisher.MemberID
	first.CreatedAtMilliseconds = 1_100
	second := first
	second.MessageID = uuid.New()
	second.CreatedAtMilliseconds = 1_101
	for _, envelope := range []relay.Envelope{first, second} {
		if _, err := store.Publish(ctx, publisher, envelope, envelope.CreatedAtMilliseconds); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Acknowledge(ctx, recipient, envelope.MessageID, relay.AcknowledgmentAccepted, 1_150); err != nil {
			t.Fatal(err)
		}
	}
	blobOneBytes, blobTwoBytes := []byte("checkpoint-delete"), []byte("checkpoint-retain")
	blobOneID, blobTwoID := relay.BlobID(blobOneBytes), relay.BlobID(blobTwoBytes)
	for id, byteCount := range map[string]int64{blobOneID: int64(len(blobOneBytes)), blobTwoID: int64(len(blobTwoBytes))} {
		if err := store.PrepareBlobPublish(ctx, publisher, id, byteCount, 1_150); err != nil {
			t.Fatal(err)
		}
		if _, err := store.CommitBlobPublish(ctx, publisher, id, byteCount, 1_150); err != nil {
			t.Fatal(err)
		}
	}
	exactBlobBytes := []byte("pre-fence-exact")
	exactBlobID := relay.BlobID(exactBlobBytes)
	if err := store.PrepareBlobPublish(ctx, recipient, exactBlobID, int64(len(exactBlobBytes)), 1_160); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitBlobPublish(ctx, recipient, exactBlobID, int64(len(exactBlobBytes)), 1_160); err != nil {
		t.Fatal(err)
	}
	blockedBlobBytes := []byte("prepared-before-fence")
	blockedBlobID := relay.BlobID(blockedBlobBytes)
	if err := store.PrepareBlobPublish(ctx, recipient, blockedBlobID, int64(len(blockedBlobBytes)), 1_170); err != nil {
		t.Fatal(err)
	}
	fenceRequest := relay.CheckpointFenceRequest{RetryID: uuid.New(), FenceID: uuid.New(), RequestedAtMilliseconds: 1_175}
	fence, err := store.CreateCheckpointFence(ctx, publisher, fenceRequest, 1_175)
	if err != nil {
		t.Fatal(err)
	}
	if duplicate, err := store.CreateCheckpointFence(ctx, publisher, fenceRequest, 1_176); err != nil || duplicate.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("fence exact retry=%+v err=%v", duplicate, err)
	}
	collision := fenceRequest
	collision.FenceID = uuid.New()
	if _, err := store.CreateCheckpointFence(ctx, publisher, collision, 1_176); !relay.ErrorHasCode(err, relay.CodeCheckpointFenceCollision) {
		t.Fatalf("fence retry collision err=%v", err)
	}
	secondFence := relay.CheckpointFenceRequest{RetryID: uuid.New(), FenceID: uuid.New(), RequestedAtMilliseconds: 1_176}
	if _, err := store.CreateCheckpointFence(ctx, publisher, secondFence, 1_176); !relay.ErrorHasCode(err, relay.CodeCheckpointFenceActive) {
		t.Fatalf("second active fence err=%v", err)
	}
	blocked := first
	blocked.MessageID, blocked.PublisherMemberID, blocked.CreatedAtMilliseconds = uuid.New(), recipient.MemberID, 1_176
	if _, err := store.Publish(ctx, recipient, blocked, 1_176); !relay.ErrorHasCode(err, relay.CodeCheckpointFenceActive) {
		t.Fatalf("foreign publish under fence err=%v", err)
	}
	if duplicate, err := store.CommitBlobPublish(ctx, recipient, exactBlobID, int64(len(exactBlobBytes)), 1_176); err != nil || duplicate.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("pre-fence blob exact retry=%+v err=%v", duplicate, err)
	}
	if _, err := store.CommitBlobPublish(ctx, recipient, blockedBlobID, int64(len(blockedBlobBytes)), 1_176); !relay.ErrorHasCode(err, relay.CodeCheckpointFenceActive) {
		t.Fatalf("prepared blob commit under fence err=%v", err)
	}
	retainedSuffix := first
	retainedSuffix.MessageID = uuid.New()
	retainedSuffix.CreatedAtMilliseconds = 1_176
	if _, err := store.Publish(ctx, publisher, retainedSuffix, 1_176); err != nil {
		t.Fatal(err)
	}
	if fetched, err := store.Fetch(ctx, recipient, 2, 10, 1_176); err != nil || len(fetched.Messages) != 0 || fetched.NextSequence != 2 {
		t.Fatalf("postgres quarantined suffix fetch=%+v err=%v", fetched, err)
	}

	retainedBlobIDs := []string{blobTwoID, exactBlobID}
	sort.Strings(retainedBlobIDs)
	candidate := relay.CheckpointCandidate{
		Version: relay.SchemaVersion, RetryID: uuid.New(), CheckpointID: uuid.New(),
		FenceID:  fence.FenceID,
		TenantID: tenantID, DomainID: domainID, PublisherSubscriptionID: publisher.MemberID,
		KeyEpoch:             1,
		CoveredThroughCursor: fence.BoundaryCursor, RetainedMessageIDs: []uuid.UUID{retainedSuffix.MessageID},
		RetainedBlobIDs: retainedBlobIDs, CreatedAtMilliseconds: 1_200,
	}
	staged, err := store.StageCheckpoint(ctx, publisher, candidate, 1_200)
	if err != nil || staged.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("stage=%+v err=%v", staged, err)
	}
	if retried, err := store.StageCheckpoint(ctx, publisher, candidate, 1_200); err != nil || retried.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("stage retry=%+v err=%v", retried, err)
	}

	activationRequest := relay.CheckpointActivationRequest{RetryID: uuid.New(), CheckpointID: candidate.CheckpointID, ActivatedAtMilliseconds: 1_251}
	if _, err := store.ActivateCheckpoint(ctx, admin, activationRequest, 1_250); !relay.ErrorHasCode(err, relay.CodeCheckpointCollision) {
		t.Fatalf("future activation err=%v", err)
	}
	third := first
	third.MessageID = uuid.New()
	third.CreatedAtMilliseconds = 1_251
	activatedResponse, activateErr := store.ActivateCheckpoint(ctx, admin, activationRequest, 1_251)
	if activateErr != nil || activatedResponse.StartCursor != relay.EncodeCursor(2) {
		t.Fatalf("activation=%+v err=%v", activatedResponse, activateErr)
	}
	if fetched, err := store.Fetch(ctx, recipient, 2, 10, 1_251); err != nil || len(fetched.Messages) != 1 || fetched.Messages[0].Envelope.MessageID != retainedSuffix.MessageID {
		t.Fatalf("postgres activated suffix fetch=%+v err=%v", fetched, err)
	}
	if _, err := store.Publish(ctx, publisher, third, 1_251); err != nil {
		t.Fatalf("concurrent publish: %v", err)
	}
	if retry, err := store.ActivateCheckpoint(ctx, admin, activationRequest, 1_249); err != nil || retry.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("activation retry=%+v err=%v", retry, err)
	}

	regressionFenceRequest := relay.CheckpointFenceRequest{RetryID: uuid.New(), FenceID: uuid.New(), RequestedAtMilliseconds: 1_260}
	regressionFence, err := store.CreateCheckpointFence(ctx, publisher, regressionFenceRequest, 1_260)
	if err != nil {
		t.Fatal(err)
	}
	regressed := relay.CheckpointCandidate{
		Version: relay.SchemaVersion, RetryID: uuid.New(), CheckpointID: uuid.New(),
		FenceID: regressionFence.FenceID, TenantID: tenantID, DomainID: domainID,
		PublisherSubscriptionID: publisher.MemberID, KeyEpoch: 1,
		CoveredThroughCursor:  regressionFence.BoundaryCursor,
		CreatedAtMilliseconds: 1_260,
	}
	if _, err := pool.Exec(ctx, `UPDATE relay_checkpoints SET key_epoch=2 WHERE tenant_id=$1 AND domain_id=$2 AND checkpoint_id=$3`, tenantID, domainID, candidate.CheckpointID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.StageCheckpoint(ctx, publisher, regressed, 1_260); !relay.ErrorHasCode(err, relay.CodeInvalidCheckpoint) {
		t.Fatalf("key epoch regression err=%v", err)
	}
	activeCovered, err := relay.DecodeCursor(activatedResponse.StartCursor)
	if err != nil {
		t.Fatal(err)
	}
	regressionBoundary, err := relay.DecodeCursor(regressionFence.BoundaryCursor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE relay_checkpoints SET key_epoch=1,covered_through_sequence=$4 WHERE tenant_id=$1 AND domain_id=$2 AND checkpoint_id=$3`, tenantID, domainID, candidate.CheckpointID, int64(regressionBoundary+1)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.StageCheckpoint(ctx, publisher, regressed, 1_260); !relay.ErrorHasCode(err, relay.CodeInvalidCheckpoint) {
		t.Fatalf("covered cursor regression err=%v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE relay_checkpoints SET covered_through_sequence=$4 WHERE tenant_id=$1 AND domain_id=$2 AND checkpoint_id=$3`, tenantID, domainID, candidate.CheckpointID, int64(activeCovered)); err != nil {
		t.Fatal(err)
	}
	abortRegressionFence := relay.CheckpointFenceAbortRequest{
		RetryID: uuid.New(), FenceID: regressionFence.FenceID,
		AbortedAtMilliseconds: 1_261,
	}
	if _, err := store.AbortCheckpointFence(ctx, publisher, abortRegressionFence, 1_261); err != nil {
		t.Fatal(err)
	}

	// A rebootstrap-required recipient deliberately discards its local cursor.
	// It must still be able to read and acknowledge the server-selected
	// checkpoint tail, even when it asks with a stale cursor beyond the tail.
	// It remains unable to publish until an explicit, later rebootstrap
	// completion moves it back to active.
	rebootstrapRequest := relay.SubscriptionRebootstrapRequest{
		RetryID: uuid.New(), CheckpointID: candidate.CheckpointID,
		RootMessageID: retainedSuffix.MessageID, RequestedAtMilliseconds: 1_252,
		LeaseDurationMilliseconds: relay.DefaultSubscriptionRebootstrapLeaseMilliseconds,
	}
	if _, err := store.Acknowledge(ctx, recipient, retainedSuffix.MessageID, relay.AcknowledgmentAccepted, 1_251); err != nil {
		t.Fatalf("pre-rebootstrap accepted acknowledgment err=%v", err)
	}
	if _, err := store.Acknowledge(ctx, recipient, retainedSuffix.MessageID, relay.AcknowledgmentApplied, 1_251); err != nil {
		t.Fatalf("pre-rebootstrap applied acknowledgment err=%v", err)
	}
	wrongRecoveryRoot := rebootstrapRequest
	wrongRecoveryRoot.RetryID = uuid.New()
	wrongRecoveryRoot.RootMessageID = uuid.New()
	if _, err := store.RequestSubscriptionRebootstrap(ctx, recipient, wrongRecoveryRoot, 1_252); !relay.ErrorHasCode(err, relay.CodeCheckpointUnavailable) {
		t.Fatalf("unretained recovery root err=%v", err)
	}
	rebootstrap, err := store.RequestSubscriptionRebootstrap(ctx, recipient, rebootstrapRequest, 1_252)
	if err != nil || rebootstrap.Acceptance != relay.AcceptanceAccepted ||
		rebootstrap.CheckpointID != candidate.CheckpointID ||
		rebootstrap.RootMessageID != retainedSuffix.MessageID ||
		rebootstrap.Subscription.StartCursor == nil || *rebootstrap.Subscription.StartCursor != activatedResponse.StartCursor {
		t.Fatalf("rebootstrap request=%+v err=%v", rebootstrap, err)
	}
	if duplicate, err := store.RequestSubscriptionRebootstrap(ctx, recipient, rebootstrapRequest, 1_252); err != nil || duplicate.Acceptance != relay.AcceptanceDuplicate || !reflect.DeepEqual(duplicate.Subscription, rebootstrap.Subscription) {
		t.Fatalf("rebootstrap request retry=%+v err=%v", duplicate, err)
	}
	renewal := relay.SubscriptionRebootstrapRenewal{
		RetryID: uuid.New(), RequestRetryID: rebootstrapRequest.RetryID,
		CheckpointID: candidate.CheckpointID, RootMessageID: retainedSuffix.MessageID,
		ExpectedLeaseExpiresAtMilliseconds: rebootstrap.LeaseExpiresAtMilliseconds,
		RequestedAtMilliseconds:            1_253,
		LeaseDurationMilliseconds:          relay.DefaultSubscriptionRebootstrapLeaseMilliseconds,
	}
	renewed, err := store.RenewSubscriptionRebootstrap(ctx, recipient, renewal, 1_253)
	if err != nil || renewed.Acceptance != relay.AcceptanceAccepted ||
		renewed.PreviousLeaseExpiresAtMilliseconds != rebootstrap.LeaseExpiresAtMilliseconds ||
		renewed.LeaseExpiresAtMilliseconds <= rebootstrap.LeaseExpiresAtMilliseconds ||
		!reflect.DeepEqual(renewed.Subscription, rebootstrap.Subscription) {
		t.Fatalf("rebootstrap renewal=%+v err=%v", renewed, err)
	}
	if duplicate, err := store.RenewSubscriptionRebootstrap(ctx, recipient, renewal, 1_253); err != nil || duplicate.Acceptance != relay.AcceptanceDuplicate || duplicate.LeaseExpiresAtMilliseconds != renewed.LeaseExpiresAtMilliseconds {
		t.Fatalf("rebootstrap renewal retry=%+v err=%v", duplicate, err)
	}
	staleRenewal := renewal
	staleRenewal.RetryID = uuid.New()
	if _, err := store.RenewSubscriptionRebootstrap(ctx, recipient, staleRenewal, 1_253); !relay.ErrorHasCode(err, relay.CodeSubscriptionCollision) {
		t.Fatalf("stale rebootstrap renewal err=%v", err)
	}
	recoveryFenceRequest := relay.CheckpointFenceRequest{
		RetryID: uuid.New(), FenceID: uuid.New(),
		RequestedAtMilliseconds: 1_262,
	}
	recoveryFence, err := store.CreateCheckpointFence(
		ctx, publisher, recoveryFenceRequest, 1_262,
	)
	if err != nil {
		t.Fatal(err)
	}
	recoverySuffix := retainedSuffix
	recoverySuffix.MessageID = uuid.New()
	recoverySuffix.CreatedAtMilliseconds = 1_263
	recoverySuffixPublish, err := store.Publish(ctx, publisher, recoverySuffix, 1_263)
	if err != nil || recoverySuffixPublish.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("publish recovery suffix=%+v err=%v", recoverySuffixPublish, err)
	}
	recoveryCandidate := relay.CheckpointCandidate{
		Version: relay.SchemaVersion, RetryID: uuid.New(), CheckpointID: uuid.New(),
		FenceID: recoveryFence.FenceID, TenantID: tenantID, DomainID: domainID,
		PublisherSubscriptionID: publisher.MemberID, KeyEpoch: 1,
		CoveredThroughCursor:  recoveryFence.BoundaryCursor,
		RetainedMessageIDs:    []uuid.UUID{recoverySuffix.MessageID},
		CreatedAtMilliseconds: 1_264,
	}
	if _, err := store.StageCheckpoint(ctx, publisher, recoveryCandidate, 1_264); err != nil {
		t.Fatal(err)
	}
	blockedRecoveryActivation := relay.CheckpointActivationRequest{
		RetryID: uuid.New(), CheckpointID: recoveryCandidate.CheckpointID,
		ActivatedAtMilliseconds: 1_265,
	}
	if _, err := store.ActivateCheckpoint(ctx, admin, blockedRecoveryActivation, 1_265); !relay.ErrorHasCode(err, relay.CodeCheckpointNotEligible) {
		t.Fatalf("postgres checkpoint activation during bound recovery err=%v", err)
	}
	if _, err := store.AbortCheckpointFence(ctx, publisher, relay.CheckpointFenceAbortRequest{
		RetryID: uuid.New(), FenceID: recoveryFence.FenceID,
		AbortedAtMilliseconds: 1_266,
	}, 1_266); err != nil {
		t.Fatal(err)
	}
	rebootstrapFetch, err := store.Fetch(ctx, recipient, relay.MaximumSequence, 10, 1_252)
	if err != nil || len(rebootstrapFetch.Messages) != 2 ||
		rebootstrapFetch.Messages[0].Envelope.MessageID != retainedSuffix.MessageID ||
		rebootstrapFetch.Messages[1].Envelope.MessageID != third.MessageID {
		t.Fatalf("rebootstrap fetch=%+v err=%v", rebootstrapFetch, err)
	}
	blockedRebootstrapPublish := retainedSuffix
	blockedRebootstrapPublish.MessageID = uuid.New()
	blockedRebootstrapPublish.PublisherMemberID = recipient.MemberID
	blockedRebootstrapPublish.CreatedAtMilliseconds = 1_252
	if _, err := store.Publish(ctx, recipient, blockedRebootstrapPublish, 1_252); !relay.ErrorHasCode(err, relay.CodeInvalidSubscription) {
		t.Fatalf("rebootstrap publish err=%v", err)
	}
	for _, message := range rebootstrapFetch.Messages {
		if acknowledgment, err := store.Acknowledge(ctx, recipient, message.Envelope.MessageID, relay.AcknowledgmentAccepted, 1_252); err != nil || acknowledgment.Acceptance != relay.AcceptanceAccepted {
			t.Fatalf("rebootstrap accepted acknowledgment=%+v err=%v", acknowledgment, err)
		}
	}
	completion := relay.SubscriptionRebootstrapCompletion{
		RetryID: uuid.New(), RequestRetryID: rebootstrapRequest.RetryID,
		CheckpointID: candidate.CheckpointID, RootMessageID: retainedSuffix.MessageID,
		CompletedThroughCursor:  relay.EncodeCursor(rebootstrapFetch.NextSequence),
		CompletedAtMilliseconds: 1_253,
	}
	substitutedCompletion := completion
	substitutedCompletion.RetryID = uuid.New()
	substitutedCompletion.CheckpointID = uuid.New()
	if _, err := store.CompleteSubscriptionRebootstrap(ctx, recipient, substitutedCompletion, 1_253); !relay.ErrorHasCode(err, relay.CodeSubscriptionCollision) {
		t.Fatalf("substituted recovery completion err=%v", err)
	}
	if _, err := store.CompleteSubscriptionRebootstrap(ctx, recipient, completion, 1_253); !relay.ErrorHasCode(err, relay.CodeRebootstrapIncomplete) {
		t.Fatalf("incomplete rebootstrap completion err=%v", err)
	}
	for _, message := range rebootstrapFetch.Messages {
		if acknowledgment, err := store.Acknowledge(ctx, recipient, message.Envelope.MessageID, relay.AcknowledgmentApplied, 1_254); err != nil || acknowledgment.Acceptance != relay.AcceptanceAccepted {
			t.Fatalf("rebootstrap applied acknowledgment=%+v err=%v", acknowledgment, err)
		}
	}
	if quiet, err := store.Fetch(ctx, recipient, relay.MaximumSequence, 10, 1_254); err != nil || len(quiet.Messages) != 0 || quiet.NextSequence != rebootstrapFetch.NextSequence {
		t.Fatalf("rebootstrap quiet tail=%+v err=%v", quiet, err)
	}
	completed, err := store.CompleteSubscriptionRebootstrap(ctx, recipient, completion, 1_255)
	if err != nil || completed.Acceptance != relay.AcceptanceAccepted || completed.Subscription.Status != relay.SubscriptionActive {
		t.Fatalf("rebootstrap completion=%+v err=%v", completed, err)
	}
	if duplicate, err := store.CompleteSubscriptionRebootstrap(ctx, recipient, completion, 1_256); err != nil || duplicate.Acceptance != relay.AcceptanceDuplicate || duplicate.Subscription != completed.Subscription {
		t.Fatalf("rebootstrap completion retry=%+v err=%v", duplicate, err)
	}
	// Recovery is also valid when the discarded replica belongs to the
	// checkpoint publisher. Its own retained ciphertext must be visible only
	// for this exact, server-bound rebootstrap interval.
	publisherRequest := relay.SubscriptionRebootstrapRequest{
		RetryID: uuid.New(), CheckpointID: candidate.CheckpointID,
		RootMessageID: retainedSuffix.MessageID, RequestedAtMilliseconds: 1_257,
		LeaseDurationMilliseconds: relay.DefaultSubscriptionRebootstrapLeaseMilliseconds,
	}
	if requested, err := store.RequestSubscriptionRebootstrap(ctx, publisher, publisherRequest, 1_257); err != nil || requested.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("publisher rebootstrap request=%+v err=%v", requested, err)
	}
	publisherFetch, err := store.Fetch(ctx, publisher, relay.MaximumSequence, 10, 1_258)
	if err != nil || len(publisherFetch.Messages) != 2 ||
		publisherFetch.Messages[0].Envelope.MessageID != retainedSuffix.MessageID ||
		publisherFetch.Messages[1].Envelope.MessageID != third.MessageID {
		t.Fatalf("publisher rebootstrap fetch=%+v err=%v", publisherFetch, err)
	}
	for _, message := range publisherFetch.Messages {
		if _, err := store.Acknowledge(ctx, publisher, message.Envelope.MessageID, relay.AcknowledgmentAccepted, 1_259); err != nil {
			t.Fatalf("publisher rebootstrap accepted acknowledgment err=%v", err)
		}
		if _, err := store.Acknowledge(ctx, publisher, message.Envelope.MessageID, relay.AcknowledgmentApplied, 1_260); err != nil {
			t.Fatalf("publisher rebootstrap applied acknowledgment err=%v", err)
		}
	}
	publisherCompletion := relay.SubscriptionRebootstrapCompletion{
		RetryID: uuid.New(), RequestRetryID: publisherRequest.RetryID,
		CheckpointID: candidate.CheckpointID, RootMessageID: retainedSuffix.MessageID,
		CompletedThroughCursor:  relay.EncodeCursor(publisherFetch.NextSequence),
		CompletedAtMilliseconds: 1_261,
	}
	if completed, err := store.CompleteSubscriptionRebootstrap(ctx, publisher, publisherCompletion, 1_261); err != nil || completed.Subscription.Status != relay.SubscriptionActive {
		t.Fatalf("publisher rebootstrap completion=%+v err=%v", completed, err)
	}

	plan, err := store.DryRunCheckpointCollection(ctx, admin, relay.CheckpointDryRunRequest{CheckpointID: candidate.CheckpointID})
	if err != nil || !plan.Eligible || plan.MessageCount != 2 || plan.BlobCount != 1 {
		t.Fatalf("plan=%+v err=%v", plan, err)
	}
	firstCollection := relay.CheckpointCollectionRequest{
		RetryID: uuid.New(), CheckpointID: candidate.CheckpointID, PlanDigest: plan.PlanDigest,
		MaximumMessageCount: 2, RequestedAtMilliseconds: 1_300,
	}
	partial, err := store.CollectCheckpoint(ctx, admin, firstCollection)
	if err != nil || partial.Completed || partial.DeletedMessageCount != 2 || partial.DeletedBlobCount != 0 {
		t.Fatalf("partial collection=%+v err=%v", partial, err)
	}
	stale := firstCollection
	stale.RetryID = uuid.New()
	if _, err := store.CollectCheckpoint(ctx, admin, stale); !relay.ErrorHasCode(err, relay.CodeCollectionPlanStale) {
		t.Fatalf("stale collection err=%v", err)
	}
	remaining, err := store.DryRunCheckpointCollection(ctx, admin, relay.CheckpointDryRunRequest{CheckpointID: candidate.CheckpointID})
	if err != nil || remaining.MessageCount != 0 || remaining.BlobCount != 1 || remaining.PlanDigest == plan.PlanDigest {
		t.Fatalf("remaining plan=%+v err=%v", remaining, err)
	}
	finalRequest := relay.CheckpointCollectionRequest{
		RetryID: uuid.New(), CheckpointID: candidate.CheckpointID, PlanDigest: remaining.PlanDigest,
		MaximumBlobCount: 1, RequestedAtMilliseconds: 1_350,
	}
	collected, err := store.CollectCheckpoint(ctx, admin, finalRequest)
	if err != nil || !collected.Completed || collected.DeletedBlobCount != 1 {
		t.Fatalf("final collection=%+v err=%v", collected, err)
	}
	if retried, err := store.CollectCheckpoint(ctx, admin, finalRequest); err != nil || !retried.Duplicate || !retried.Completed {
		t.Fatalf("collection retry=%+v err=%v", retried, err)
	}
	// Packet 4A queues physical deletion rather than deleting bytes immediately.
	// Re-publication of the same content address must therefore restore database
	// authority safely before the packet-5 reconciler considers that queue row.
	if err := store.PrepareBlobPublish(ctx, publisher, blobOneID, int64(len(blobOneBytes)), 1_375); err != nil {
		t.Fatalf("prepare same-ID re-publication: %v", err)
	}
	if republished, err := store.CommitBlobPublish(ctx, publisher, blobOneID, int64(len(blobOneBytes)), 1_375); err != nil || republished.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("same-ID re-publication=%+v err=%v", republished, err)
	}

	newSubscription, err := store.CreateSubscription(ctx, admin, relay.SubscriptionCreateRequest{RetryID: uuid.New(), SubscriptionID: uuid.New(), CreatedAtMilliseconds: 1_400})
	if err != nil || newSubscription.Subscription.StartCursor == nil || *newSubscription.Subscription.StartCursor != activatedResponse.StartCursor {
		t.Fatalf("new subscription=%+v err=%v", newSubscription, err)
	}
	status, err := store.GetDomainStatus(ctx, admin)
	if err != nil || status.MessageCount != 2 || status.BlobCount != 3 || status.LatestActivatedCheckpointID == nil || *status.LatestActivatedCheckpointID != candidate.CheckpointID {
		t.Fatalf("domain status=%+v err=%v", status, err)
	}
	var lastSequence, queuedBlobDeletions, republishedBlobAuthority int64
	if err := pool.QueryRow(ctx, `SELECT last_sequence FROM relay_domains WHERE tenant_id=$1 AND domain_id=$2`, tenantID, domainID).Scan(&lastSequence); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM relay_collected_blob_deletions WHERE tenant_id=$1 AND domain_id=$2`, tenantID, domainID).Scan(&queuedBlobDeletions); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM relay_blobs WHERE tenant_id=$1 AND domain_id=$2 AND blob_id=$3`, tenantID, domainID, blobOneID).Scan(&republishedBlobAuthority); err != nil {
		t.Fatal(err)
	}
	if lastSequence != int64(recoverySuffixPublish.Sequence) || queuedBlobDeletions != 1 || republishedBlobAuthority != 1 {
		t.Fatalf("last_sequence=%d queued_blob_deletions=%d republished_blob_authority=%d", lastSequence, queuedBlobDeletions, republishedBlobAuthority)
	}
	for index := 0; index < 2; index++ {
		fenceRequest := relay.CheckpointFenceRequest{RetryID: uuid.New(), FenceID: uuid.New(), RequestedAtMilliseconds: int64(1_440 + index*100)}
		fence, err := store.CreateCheckpointFence(ctx, publisher, fenceRequest, fenceRequest.RequestedAtMilliseconds)
		if err != nil {
			t.Fatal(err)
		}
		suffix := first
		suffix.MessageID = uuid.New()
		suffix.CreatedAtMilliseconds = fenceRequest.RequestedAtMilliseconds + 1
		if _, err := store.Publish(ctx, publisher, suffix, suffix.CreatedAtMilliseconds); err != nil {
			t.Fatal(err)
		}
		next := relay.CheckpointCandidate{
			Version: relay.SchemaVersion, RetryID: uuid.New(), CheckpointID: uuid.New(),
			FenceID:  fence.FenceID,
			TenantID: tenantID, DomainID: domainID, PublisherSubscriptionID: publisher.MemberID,
			KeyEpoch:             1,
			CoveredThroughCursor: fence.BoundaryCursor, RetainedMessageIDs: []uuid.UUID{suffix.MessageID},
			RetainedBlobIDs: []string{blobTwoID}, CreatedAtMilliseconds: int64(1_450 + index*100),
		}
		if _, err := store.StageCheckpoint(ctx, publisher, next, next.CreatedAtMilliseconds); err != nil {
			t.Fatalf("stage retention checkpoint %d: %v", index, err)
		}
		if _, err := store.ActivateCheckpoint(ctx, admin, relay.CheckpointActivationRequest{RetryID: uuid.New(), CheckpointID: next.CheckpointID, ActivatedAtMilliseconds: next.CreatedAtMilliseconds + 1}, next.CreatedAtMilliseconds+1); err != nil {
			t.Fatalf("activate retention checkpoint %d: %v", index, err)
		}
	}
	if retried, err := store.StageCheckpoint(ctx, publisher, candidate, 1_700); err != nil || retried.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("pruned postgres stage retry=%+v err=%v", retried, err)
	}
	if retried, err := store.CollectCheckpoint(ctx, admin, finalRequest); err != nil || !retried.Duplicate {
		t.Fatalf("retired postgres collection retry=%+v err=%v", retried, err)
	}
	var activatedCheckpointCount, retiredChildRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM relay_checkpoints WHERE tenant_id=$1 AND domain_id=$2 AND state='activated'`, tenantID, domainID).Scan(&activatedCheckpointCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM relay_checkpoint_retained_messages WHERE tenant_id=$1 AND domain_id=$2 AND checkpoint_id=$3) +
			(SELECT count(*) FROM relay_checkpoint_retained_blobs WHERE tenant_id=$1 AND domain_id=$2 AND checkpoint_id=$3) +
			(SELECT count(*) FROM relay_checkpoint_required_subscriptions WHERE tenant_id=$1 AND domain_id=$2 AND checkpoint_id=$3) +
			(SELECT count(*) FROM relay_checkpoint_deletion_messages WHERE tenant_id=$1 AND domain_id=$2 AND checkpoint_id=$3) +
			(SELECT count(*) FROM relay_checkpoint_deletion_blobs WHERE tenant_id=$1 AND domain_id=$2 AND checkpoint_id=$3)
	`, tenantID, domainID, candidate.CheckpointID).Scan(&retiredChildRows); err != nil {
		t.Fatal(err)
	}
	if activatedCheckpointCount != 2 || retiredChildRows != 0 {
		t.Fatalf("activated checkpoints=%d retired child rows=%d", activatedCheckpointCount, retiredChildRows)
	}
	finalizedUpload := relay.BlobUploadRequest{RetryID: uuid.New(), UploadID: uuid.New(), RelayBlobID: relay.BlobID(nil), ByteCount: 0, CreatedAtMilliseconds: 2_000}
	if _, err := store.CreateBlobUpload(ctx, publisher, finalizedUpload, 2_000); err != nil {
		t.Fatal(err)
	}
	if _, err := store.FinalizeBlobUpload(ctx, publisher, relay.BlobUploadFinalizationRequest{RetryID: uuid.New(), UploadID: finalizedUpload.UploadID, RelayBlobID: finalizedUpload.RelayBlobID, ByteCount: 0, FinalizedAtMilliseconds: 2_001}, 2_001, func(relay.BlobUploadStatus) error { return nil }); err != nil {
		t.Fatal(err)
	}
	makeFailedFence := func(at int64, expire bool) {
		t.Helper()
		before, err := store.GetDomainStatus(ctx, admin)
		if err != nil {
			t.Fatal(err)
		}
		request := relay.CheckpointFenceRequest{RetryID: uuid.New(), FenceID: uuid.New(), RequestedAtMilliseconds: at}
		fence, err := store.CreateCheckpointFence(ctx, publisher, request, at)
		if err != nil {
			t.Fatal(err)
		}
		suffix := first
		suffix.MessageID, suffix.CreatedAtMilliseconds = uuid.New(), at+1
		if _, err := store.Publish(ctx, publisher, suffix, at+1); err != nil {
			t.Fatal(err)
		}
		candidate := relay.CheckpointCandidate{Version: 1, RetryID: uuid.New(), CheckpointID: uuid.New(), FenceID: fence.FenceID, TenantID: tenantID, DomainID: domainID, PublisherSubscriptionID: publisher.MemberID, KeyEpoch: 1, CoveredThroughCursor: fence.BoundaryCursor, RetainedMessageIDs: []uuid.UUID{suffix.MessageID}, RetainedBlobIDs: []string{}, CreatedAtMilliseconds: at + 2}
		if _, err := store.StageCheckpoint(ctx, publisher, candidate, at+2); err != nil {
			t.Fatal(err)
		}
		if expire {
			if state, err := store.GetCheckpointFence(ctx, publisher, fence.FenceID, fence.ExpiresAtMilliseconds); err != nil || state.Status != relay.CheckpointFenceExpired {
				t.Fatalf("expired fence=%+v err=%v", state, err)
			}
		} else {
			abort := relay.CheckpointFenceAbortRequest{RetryID: uuid.New(), FenceID: fence.FenceID, AbortedAtMilliseconds: at + 3}
			if _, err := store.AbortCheckpointFence(ctx, publisher, abort, at+3); err != nil {
				t.Fatal(err)
			}
		}
		if retry, err := store.Publish(ctx, publisher, suffix, fence.ExpiresAtMilliseconds+1); err != nil || retry.Acceptance != relay.AcceptanceDuplicate {
			t.Fatalf("failed-fence message retry=%+v err=%v", retry, err)
		}
		after, err := store.GetDomainStatus(ctx, admin)
		if err != nil || after.MessageCount != before.MessageCount || after.MessageByteCount != before.MessageByteCount {
			t.Fatalf("failed-fence counters before=%+v after=%+v err=%v", before, after, err)
		}
	}
	makeFailedFence(2_100, false)
	makeFailedFence(2_200, true)
	activeFenceRequest := relay.CheckpointFenceRequest{RetryID: uuid.New(), FenceID: uuid.New(), RequestedAtMilliseconds: 10_000_000}
	activeFence, err := store.CreateCheckpointFence(ctx, publisher, activeFenceRequest, activeFenceRequest.RequestedAtMilliseconds)
	if err != nil {
		t.Fatal(err)
	}
	activeSuffix := first
	activeSuffix.MessageID, activeSuffix.CreatedAtMilliseconds = uuid.New(), activeFenceRequest.RequestedAtMilliseconds+1
	if _, err := store.Publish(ctx, publisher, activeSuffix, activeSuffix.CreatedAtMilliseconds); err != nil {
		t.Fatal(err)
	}
	activeCandidate := relay.CheckpointCandidate{Version: 1, RetryID: uuid.New(), CheckpointID: uuid.New(), FenceID: activeFence.FenceID, TenantID: tenantID, DomainID: domainID, PublisherSubscriptionID: publisher.MemberID, KeyEpoch: 1, CoveredThroughCursor: activeFence.BoundaryCursor, RetainedMessageIDs: []uuid.UUID{activeSuffix.MessageID}, RetainedBlobIDs: []string{}, CreatedAtMilliseconds: activeFenceRequest.RequestedAtMilliseconds + 2}
	if _, err := store.StageCheckpoint(ctx, publisher, activeCandidate, activeCandidate.CreatedAtMilliseconds); err != nil {
		t.Fatal(err)
	}
	activeUpload := relay.BlobUploadRequest{RetryID: uuid.New(), UploadID: uuid.New(), RelayBlobID: relay.BlobID([]byte("active-upload")), ByteCount: int64(len("active-upload")), CreatedAtMilliseconds: activeFenceRequest.RequestedAtMilliseconds + 3}
	if _, err := store.CreateBlobUpload(ctx, publisher, activeUpload, activeUpload.CreatedAtMilliseconds); err != nil {
		t.Fatal(err)
	}
	if result, err := pool.Exec(ctx, `DELETE FROM relay_domains WHERE tenant_id=$1 AND domain_id=$2`, tenantID, domainID); err != nil || result.RowsAffected() != 1 {
		t.Fatalf("delete checkpoint domain rows=%d err=%v", result.RowsAffected(), err)
	}
	var checkpointRows int
	if err := pool.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM relay_checkpoints WHERE tenant_id=$1 AND domain_id=$2) +
			(SELECT count(*) FROM relay_checkpoint_retained_messages WHERE tenant_id=$1 AND domain_id=$2) +
			(SELECT count(*) FROM relay_checkpoint_retained_blobs WHERE tenant_id=$1 AND domain_id=$2) +
			(SELECT count(*) FROM relay_checkpoint_required_subscriptions WHERE tenant_id=$1 AND domain_id=$2) +
			(SELECT count(*) FROM relay_checkpoint_deletion_messages WHERE tenant_id=$1 AND domain_id=$2) +
			(SELECT count(*) FROM relay_checkpoint_deletion_blobs WHERE tenant_id=$1 AND domain_id=$2) +
			(SELECT count(*) FROM relay_checkpoint_collections WHERE tenant_id=$1 AND domain_id=$2) +
			(SELECT count(*) FROM relay_collected_blob_deletions WHERE tenant_id=$1 AND domain_id=$2) +
			(SELECT count(*) FROM relay_checkpoint_fences WHERE tenant_id=$1 AND domain_id=$2) +
			(SELECT count(*) FROM relay_checkpoint_fence_message_tombstones WHERE tenant_id=$1 AND domain_id=$2) +
			(SELECT count(*) FROM relay_blob_uploads WHERE tenant_id=$1 AND domain_id=$2) +
			(SELECT count(*) FROM relay_blob_upload_finalizations WHERE tenant_id=$1 AND domain_id=$2)
	`, tenantID, domainID).Scan(&checkpointRows); err != nil {
		t.Fatal(err)
	}
	if checkpointRows != 0 {
		t.Fatalf("domain deletion left %d checkpoint rows", checkpointRows)
	}
}
