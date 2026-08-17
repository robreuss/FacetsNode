package relay_test

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/testfixture"
)

func TestMemoryCheckpointFreezesCustodyCollectsAndPreservesSequence(t *testing.T) {
	ctx := context.Background()
	store, admin, publisher, recipient, first, second := checkpointMemoryFixture(t)
	if _, err := store.Acknowledge(ctx, recipient, first.MessageID, relay.AcknowledgmentAccepted, 1_300); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Acknowledge(ctx, recipient, second.MessageID, relay.AcknowledgmentAccepted, 1_300); err != nil {
		t.Fatal(err)
	}
	candidate := relay.CheckpointCandidate{
		Version: relay.SchemaVersion, RetryID: uuid.New(), CheckpointID: uuid.New(),
		TenantID: admin.TenantID, DomainID: admin.DomainID,
		PublisherSubscriptionID: publisher.MemberID,
		CoveredThroughCursor:    relay.EncodeCursor(2), RetainedMessageIDs: []uuid.UUID{second.MessageID},
		CreatedAtMilliseconds: 1_400,
	}
	staged, err := store.StageCheckpoint(ctx, publisher, candidate, 1_400)
	if err != nil || staged.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("stage=%+v err=%v", staged, err)
	}
	retry, err := store.StageCheckpoint(ctx, publisher, candidate, 1_400)
	if err != nil || retry.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("stage retry=%+v err=%v", retry, err)
	}
	activation := relay.CheckpointActivationRequest{RetryID: uuid.New(), CheckpointID: candidate.CheckpointID, ActivatedAtMilliseconds: 1_500}
	activated, err := store.ActivateCheckpoint(ctx, admin, activation)
	if err != nil || activated.StartCursor != relay.EncodeCursor(1) {
		t.Fatalf("activation=%+v err=%v", activated, err)
	}
	third := first
	third.MessageID = uuid.New()
	third.CreatedAtMilliseconds = 1_600
	published, err := store.Publish(ctx, publisher, third, 1_600)
	if err != nil || published.Sequence != 3 {
		t.Fatalf("concurrent publish=%+v err=%v", published, err)
	}
	plan, err := store.DryRunCheckpointCollection(ctx, admin, relay.CheckpointDryRunRequest{CheckpointID: candidate.CheckpointID})
	if err != nil || !plan.Eligible || plan.MessageCount != 1 {
		t.Fatalf("plan=%+v err=%v", plan, err)
	}
	request := relay.CheckpointCollectionRequest{RetryID: uuid.New(), CheckpointID: candidate.CheckpointID, PlanDigest: plan.PlanDigest, MaximumMessageCount: 1, RequestedAtMilliseconds: 1_700}
	collected, err := store.CollectCheckpoint(ctx, admin, request)
	if err != nil || !collected.Completed || collected.DeletedMessageCount != 1 {
		t.Fatalf("collection=%+v err=%v", collected, err)
	}
	duplicate, err := store.CollectCheckpoint(ctx, admin, request)
	if err != nil || !duplicate.Duplicate || duplicate.DeletedMessageCount != 1 {
		t.Fatalf("collection retry=%+v err=%v", duplicate, err)
	}
	stale := request
	stale.RetryID = uuid.New()
	if _, err := store.CollectCheckpoint(ctx, admin, stale); !relay.ErrorHasCode(err, relay.CodeCollectionPlanStale) {
		t.Fatalf("stale plan err=%v", err)
	}
	newSubscriptionID := uuid.New()
	created, err := store.CreateSubscription(ctx, admin, relay.SubscriptionCreateRequest{RetryID: uuid.New(), SubscriptionID: newSubscriptionID, CreatedAtMilliseconds: 1_800})
	if err != nil || created.Subscription.StartCursor == nil || *created.Subscription.StartCursor != activated.StartCursor {
		t.Fatalf("new subscription=%+v err=%v", created, err)
	}
	fetched, err := store.Fetch(ctx, recipient, 0, 10, 1_800)
	if err != nil || len(fetched.Messages) != 2 || fetched.Messages[0].Sequence != 2 || fetched.Messages[1].Sequence != 3 {
		t.Fatalf("post-collection fetch=%+v err=%v", fetched, err)
	}
	fourth := first
	fourth.MessageID = uuid.New()
	fourth.CreatedAtMilliseconds = 1_900
	published, err = store.Publish(ctx, publisher, fourth, 1_900)
	if err != nil || published.Sequence != 4 {
		t.Fatalf("sequence after collection=%+v err=%v", published, err)
	}
}

func TestMemoryCheckpointRebootstrapWaivesFrozenCustody(t *testing.T) {
	ctx := context.Background()
	store, admin, publisher, recipient, first, second := checkpointMemoryFixture(t)
	candidate := relay.CheckpointCandidate{Version: 1, RetryID: uuid.New(), CheckpointID: uuid.New(), TenantID: admin.TenantID, DomainID: admin.DomainID, PublisherSubscriptionID: publisher.MemberID, CoveredThroughCursor: relay.EncodeCursor(2), RetainedMessageIDs: []uuid.UUID{second.MessageID}, CreatedAtMilliseconds: 1_400}
	if _, err := store.StageCheckpoint(ctx, publisher, candidate, 1_400); err != nil {
		t.Fatal(err)
	}
	activation, err := store.ActivateCheckpoint(ctx, admin, relay.CheckpointActivationRequest{RetryID: uuid.New(), CheckpointID: candidate.CheckpointID, ActivatedAtMilliseconds: 1_500})
	if err != nil {
		t.Fatal(err)
	}
	blocked, err := store.DryRunCheckpointCollection(ctx, admin, relay.CheckpointDryRunRequest{CheckpointID: candidate.CheckpointID})
	if err != nil || blocked.Eligible || len(blocked.MissingCustodySubscriptionIDs) != 1 {
		t.Fatalf("blocked=%+v err=%v", blocked, err)
	}
	changed, err := store.ChangeSubscriptionStatus(ctx, admin, recipient.MemberID, relay.SubscriptionStatusChangeRequest{RetryID: uuid.New(), Status: relay.SubscriptionRebootstrapRequired, ChangedAtMilliseconds: 1_600})
	if err != nil || changed.Subscription.StartCursor == nil || *changed.Subscription.StartCursor != activation.StartCursor {
		t.Fatalf("rebootstrap=%+v err=%v", changed, err)
	}
	eligible, err := store.DryRunCheckpointCollection(ctx, admin, relay.CheckpointDryRunRequest{CheckpointID: candidate.CheckpointID})
	if err != nil || !eligible.Eligible {
		t.Fatalf("eligible=%+v err=%v first=%s", eligible, err, first.MessageID)
	}
}

func TestMemoryCheckpointProtectsPreviousActivatedRetainedSet(t *testing.T) {
	ctx := context.Background()
	store, admin, publisher, recipient, first, second := checkpointMemoryFixture(t)
	for _, message := range []relay.Envelope{first, second} {
		if _, err := store.Acknowledge(ctx, recipient, message.MessageID, relay.AcknowledgmentAccepted, 1_300); err != nil {
			t.Fatal(err)
		}
	}
	candidates := make([]relay.CheckpointCandidate, 0, 4)
	activate := func(created int64, retained []uuid.UUID) uuid.UUID {
		t.Helper()
		candidate := relay.CheckpointCandidate{
			Version: relay.SchemaVersion, RetryID: uuid.New(), CheckpointID: uuid.New(),
			TenantID: admin.TenantID, DomainID: admin.DomainID,
			PublisherSubscriptionID: publisher.MemberID,
			CoveredThroughCursor:    relay.EncodeCursor(2), RetainedMessageIDs: retained,
			RetainedBlobIDs: []string{}, CreatedAtMilliseconds: created,
		}
		if _, err := store.StageCheckpoint(ctx, publisher, candidate, created); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ActivateCheckpoint(ctx, admin, relay.CheckpointActivationRequest{RetryID: uuid.New(), CheckpointID: candidate.CheckpointID, ActivatedAtMilliseconds: created + 1}); err != nil {
			t.Fatal(err)
		}
		candidates = append(candidates, candidate)
		return candidate.CheckpointID
	}
	activate(1_400, []uuid.UUID{second.MessageID})
	activate(1_500, []uuid.UUID{first.MessageID})
	thirdID := activate(1_600, []uuid.UUID{second.MessageID})
	thirdPlan, err := store.DryRunCheckpointCollection(ctx, admin, relay.CheckpointDryRunRequest{CheckpointID: thirdID})
	if err != nil || thirdPlan.MessageCount != 0 {
		t.Fatalf("previous retained set was not protected plan=%+v err=%v", thirdPlan, err)
	}
	fourthID := activate(1_700, []uuid.UUID{second.MessageID})
	fourthPlan, err := store.DryRunCheckpointCollection(ctx, admin, relay.CheckpointDryRunRequest{CheckpointID: fourthID})
	if err != nil || fourthPlan.MessageCount != 1 {
		t.Fatalf("retired retained set remained protected plan=%+v err=%v", fourthPlan, err)
	}
	if retried, err := store.StageCheckpoint(ctx, publisher, candidates[0], 1_800); err != nil || retried.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("pruned candidate retry=%+v err=%v", retried, err)
	}
	collision := candidates[0]
	collision.CreatedAtMilliseconds++
	if _, err := store.StageCheckpoint(ctx, publisher, collision, 1_800); !relay.ErrorHasCode(err, relay.CodeCheckpointCollision) {
		t.Fatalf("pruned candidate collision err=%v", err)
	}
}

func TestCheckpointCollectionRejectsUnboundedOrEmptyWork(t *testing.T) {
	base := relay.CheckpointCollectionRequest{
		RetryID: uuid.New(), CheckpointID: uuid.New(),
		PlanDigest: strings.Repeat("a", 64), RequestedAtMilliseconds: 1,
	}
	if err := base.Validate(); !relay.ErrorHasCode(err, relay.CodeInvalidCheckpoint) {
		t.Fatalf("empty collection bounds err=%v", err)
	}
	base.MaximumMessageCount = relay.MaximumCheckpointCollectionCount + 1
	if err := base.Validate(); !relay.ErrorHasCode(err, relay.CodeInvalidCheckpoint) {
		t.Fatalf("unbounded collection err=%v", err)
	}
}

func checkpointMemoryFixture(t *testing.T) (*relay.MemoryStore, relay.AdministrationCredential, relay.Credential, relay.Credential, relay.Envelope, relay.Envelope) {
	t.Helper()
	ctx := context.Background()
	fixture, err := testfixture.LoadRelayCarrier()
	if err != nil {
		t.Fatal(err)
	}
	tenantID, domainID := uuid.New(), uuid.New()
	admin := relay.AdministrationCredential{TenantID: tenantID, DomainID: domainID, Token: token(90)}
	adminDigest, _ := relay.AdministrationDigest(admin)
	publisher := relay.Credential{TenantID: tenantID, DomainID: domainID, MemberID: uuid.New(), Token: token(91)}
	publisherDigest, _ := relay.AuthorizationDigest(publisher)
	store := relay.NewMemoryStore()
	_, err = store.CreateDomain(ctx, relay.DomainRegistration{Version: 1, TenantID: tenantID, DomainID: domainID, AdministrationDigest: adminDigest, CreatedAtMilliseconds: 1_000, MaximumMessageCount: 100, MaximumMessageByteCount: 1_000_000, MaximumBlobCount: 100, MaximumBlobByteCount: 1_000_000}, relay.MemberRegistration{Version: 1, TenantID: tenantID, DomainID: domainID, MemberID: publisher.MemberID, AuthorizationDigest: publisherDigest, Capabilities: []relay.Capability{relay.CapabilityPublishCheckpoint, relay.CapabilityPublishMessage}, CreatedAtMilliseconds: 1_000})
	if err != nil {
		t.Fatal(err)
	}
	recipient := relay.Credential{TenantID: tenantID, DomainID: domainID, MemberID: uuid.New(), Token: token(92)}
	recipientDigest, _ := relay.AuthorizationDigest(recipient)
	_, err = store.CreateMember(ctx, admin, relay.MemberRegistration{Version: 1, TenantID: tenantID, DomainID: domainID, MemberID: recipient.MemberID, AuthorizationDigest: recipientDigest, Capabilities: []relay.Capability{relay.CapabilityAcknowledgeMessage, relay.CapabilityFetchMessage}, CreatedAtMilliseconds: 1_000}, 1_100)
	if err != nil {
		t.Fatal(err)
	}
	first := fixture.Envelope
	first.TenantID = tenantID
	first.DomainID = domainID
	first.MessageID = uuid.New()
	first.PublisherMemberID = publisher.MemberID
	first.CreatedAtMilliseconds = 1_200
	second := first
	second.MessageID = uuid.New()
	second.CreatedAtMilliseconds = 1_201
	if _, err := store.Publish(ctx, publisher, first, 1_200); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Publish(ctx, publisher, second, 1_201); err != nil {
		t.Fatal(err)
	}
	return store, admin, publisher, recipient, first, second
}
