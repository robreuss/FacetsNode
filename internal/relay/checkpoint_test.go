package relay_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/testfixture"
)

func TestMemoryCheckpointFenceBlocksOnlyNewForeignWritesAndExpiresByServerTime(t *testing.T) {
	ctx := context.Background()
	store, admin, holder, reader, template, _ := checkpointMemoryFixture(t)
	other := relay.Credential{TenantID: admin.TenantID, DomainID: admin.DomainID, MemberID: uuid.New(), Token: token(93)}
	digest, _ := relay.AuthorizationDigest(other)
	registration := relay.MemberRegistration{Version: 1, TenantID: admin.TenantID, DomainID: admin.DomainID, MemberID: other.MemberID, AuthorizationDigest: digest, Capabilities: []relay.Capability{relay.CapabilityPublishBlob, relay.CapabilityPublishMessage}, CreatedAtMilliseconds: 1_300}
	if _, err := store.CreateMember(ctx, admin, registration, 1_300); err != nil {
		t.Fatal(err)
	}
	foreignMessage := template
	foreignMessage.MessageID, foreignMessage.PublisherMemberID = uuid.New(), other.MemberID
	foreignMessage.CreatedAtMilliseconds = 1_310
	if _, err := store.Publish(ctx, other, foreignMessage, 1_310); err != nil {
		t.Fatal(err)
	}
	upload := relay.BlobUploadRequest{RetryID: uuid.New(), UploadID: uuid.New(), RelayBlobID: relay.BlobID(nil), ByteCount: 0, CreatedAtMilliseconds: 1_320}
	if _, err := store.CreateBlobUpload(ctx, other, upload, 1_320); err != nil {
		t.Fatal(err)
	}
	finalize := relay.BlobUploadFinalizationRequest{RetryID: uuid.New(), UploadID: upload.UploadID, RelayBlobID: upload.RelayBlobID, ByteCount: 0, FinalizedAtMilliseconds: 1_321}
	if _, err := store.FinalizeBlobUpload(ctx, other, finalize, 1_321, func(relay.BlobUploadStatus) error { return nil }); err != nil {
		t.Fatal(err)
	}
	legacyPendingID := relay.BlobID([]byte("prepared-before-fence"))
	if err := store.PrepareBlobPublish(ctx, other, legacyPendingID, int64(len("prepared-before-fence")), 1_330); err != nil {
		t.Fatal(err)
	}

	request := relay.CheckpointFenceRequest{RetryID: uuid.New(), FenceID: uuid.New(), RequestedAtMilliseconds: 1_400}
	fence, err := store.CreateCheckpointFence(ctx, holder, request, 1_400)
	if err != nil || fence.ExpiresAtMilliseconds-fence.AcquiredAtMilliseconds != relay.DefaultCheckpointFenceLifetimeMilliseconds {
		t.Fatalf("fence=%+v err=%v", fence, err)
	}
	if duplicate, err := store.CreateCheckpointFence(ctx, holder, request, 1_401); err != nil || duplicate.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("fence retry=%+v err=%v", duplicate, err)
	}
	fenceCollision := request
	fenceCollision.FenceID = uuid.New()
	if _, err := store.CreateCheckpointFence(ctx, holder, fenceCollision, 1_401); !relay.ErrorHasCode(err, relay.CodeCheckpointFenceCollision) {
		t.Fatalf("fence retry collision err=%v", err)
	}
	if _, err := store.Publish(ctx, other, foreignMessage, 1_401); err != nil {
		t.Fatalf("pre-fence message exact retry: %v", err)
	}
	if duplicate, err := store.CreateBlobUpload(ctx, other, upload, 1_401); err != nil || duplicate.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("pre-fence upload exact retry=%+v err=%v", duplicate, err)
	}
	if duplicate, err := store.FinalizeBlobUpload(ctx, other, finalize, 1_401, nil); err != nil || duplicate.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("pre-fence finalize exact retry=%+v err=%v", duplicate, err)
	}
	if duplicate, err := store.CommitBlobPublish(ctx, other, upload.RelayBlobID, 0, 1_401); err != nil || duplicate.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("pre-fence legacy blob exact retry=%+v err=%v", duplicate, err)
	}
	if _, err := store.CommitBlobPublish(ctx, other, legacyPendingID, int64(len("prepared-before-fence")), 1_401); !relay.ErrorHasCode(err, relay.CodeCheckpointFenceActive) {
		t.Fatalf("prepared foreign blob commit err=%v", err)
	}
	blockedMessage := foreignMessage
	blockedMessage.MessageID, blockedMessage.CreatedAtMilliseconds = uuid.New(), 1_402
	if _, err := store.Publish(ctx, other, blockedMessage, 1_402); !relay.ErrorHasCode(err, relay.CodeCheckpointFenceActive) {
		t.Fatalf("foreign publish err=%v", err)
	}
	blockedUpload := upload
	blockedUpload.RetryID, blockedUpload.UploadID, blockedUpload.CreatedAtMilliseconds = uuid.New(), uuid.New(), 1_402
	if _, err := store.CreateBlobUpload(ctx, other, blockedUpload, 1_402); !relay.ErrorHasCode(err, relay.CodeCheckpointFenceActive) {
		t.Fatalf("foreign upload err=%v", err)
	}

	holderSuffix := template
	holderSuffix.MessageID, holderSuffix.CreatedAtMilliseconds = uuid.New(), 1_403
	if _, err := store.Publish(ctx, holder, holderSuffix, 1_403); err != nil {
		t.Fatalf("holder publish: %v", err)
	}
	if fetched, err := store.Fetch(ctx, reader, 3, 10, 1_403); err != nil || len(fetched.Messages) != 0 || fetched.NextSequence != 3 {
		t.Fatalf("quarantined fetch=%+v err=%v", fetched, err)
	}
	fencedBytes := []byte("fenced")
	fencedDigest := sha256.Sum256(fencedBytes)
	holderUpload := relay.BlobUploadRequest{RetryID: uuid.New(), UploadID: uuid.New(), RelayBlobID: relay.BlobID(fencedBytes), ByteCount: int64(len(fencedBytes)), CreatedAtMilliseconds: 1_403}
	if _, err := store.CreateBlobUpload(ctx, holder, holderUpload, 1_403); err != nil {
		t.Fatal(err)
	}
	chunk := relay.BlobUploadChunkRequest{UploadID: holderUpload.UploadID, Offset: 0, ByteCount: holderUpload.ByteCount, ChunkSHA256: hex.EncodeToString(fencedDigest[:])}
	if _, err := store.AppendBlobUploadChunk(ctx, holder, chunk, 1_403, func(relay.BlobUploadStatus) error { return nil }); err != nil {
		t.Fatal(err)
	}
	holderFinalize := relay.BlobUploadFinalizationRequest{RetryID: uuid.New(), UploadID: holderUpload.UploadID, RelayBlobID: holderUpload.RelayBlobID, ByteCount: holderUpload.ByteCount, FinalizedAtMilliseconds: 1_403}
	if _, err := store.FinalizeBlobUpload(ctx, holder, holderFinalize, 1_403, func(relay.BlobUploadStatus) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetBlobMetadata(ctx, reader, holderUpload.RelayBlobID, 1_403); !relay.ErrorHasCode(err, relay.CodeBlobNotFound) {
		t.Fatalf("quarantined blob fetch err=%v", err)
	}
	candidate := relay.CheckpointCandidate{Version: 1, RetryID: uuid.New(), CheckpointID: uuid.New(), FenceID: fence.FenceID, TenantID: admin.TenantID, DomainID: admin.DomainID, PublisherSubscriptionID: holder.MemberID, KeyEpoch: 1, CoveredThroughCursor: fence.BoundaryCursor, RetainedMessageIDs: []uuid.UUID{holderSuffix.MessageID}, CreatedAtMilliseconds: 1_404}
	if _, err := store.StageCheckpoint(ctx, holder, candidate, 1_404); err != nil {
		t.Fatal(err)
	}
	activation := relay.CheckpointActivationRequest{RetryID: uuid.New(), CheckpointID: candidate.CheckpointID, ActivatedAtMilliseconds: 1_405}
	if _, err := store.ActivateCheckpoint(ctx, admin, activation, fence.ExpiresAtMilliseconds); !relay.ErrorHasCode(err, relay.CodeInvalidCheckpointFence) {
		t.Fatalf("expired activation err=%v", err)
	}
	state, err := store.GetCheckpointFence(ctx, holder, fence.FenceID, fence.ExpiresAtMilliseconds)
	if err != nil || state.Status != relay.CheckpointFenceExpired {
		t.Fatalf("expired state=%+v err=%v", state, err)
	}
	if retry, err := store.Publish(ctx, holder, holderSuffix, fence.ExpiresAtMilliseconds); err != nil || retry.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("cleaned suffix exact retry=%+v err=%v", retry, err)
	}
	if retry, err := store.FinalizeBlobUpload(ctx, holder, holderFinalize, fence.ExpiresAtMilliseconds, nil); err != nil || retry.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("cleaned blob retry=%+v err=%v", retry, err)
	}
	if fetched, err := store.Fetch(ctx, reader, 3, 10, fence.ExpiresAtMilliseconds); err != nil || len(fetched.Messages) != 0 || fetched.NextSequence != 4 {
		t.Fatalf("failed suffix became visible fetch=%+v err=%v", fetched, err)
	}
	status, err := store.GetDomainStatus(ctx, admin)
	if err != nil || status.MessageCount != 3 || status.BlobCount != 1 {
		t.Fatalf("post-expiry counters=%+v err=%v", status, err)
	}
	if _, err := store.Publish(ctx, other, blockedMessage, fence.ExpiresAtMilliseconds); err != nil {
		t.Fatalf("write after expiry: %v", err)
	}

	abortRequest := relay.CheckpointFenceRequest{RetryID: uuid.New(), FenceID: uuid.New(), RequestedAtMilliseconds: fence.ExpiresAtMilliseconds + 1}
	abortFence, err := store.CreateCheckpointFence(ctx, holder, abortRequest, abortRequest.RequestedAtMilliseconds)
	if err != nil {
		t.Fatal(err)
	}
	abortSuffix := template
	abortSuffix.MessageID, abortSuffix.CreatedAtMilliseconds = uuid.New(), abortRequest.RequestedAtMilliseconds+1
	if _, err := store.Publish(ctx, holder, abortSuffix, abortSuffix.CreatedAtMilliseconds); err != nil {
		t.Fatal(err)
	}
	abort := relay.CheckpointFenceAbortRequest{RetryID: uuid.New(), FenceID: abortFence.FenceID, AbortedAtMilliseconds: abortRequest.RequestedAtMilliseconds + 1}
	if result, err := store.AbortCheckpointFence(ctx, holder, abort, abort.AbortedAtMilliseconds); err != nil || result.Status != relay.CheckpointFenceAborted {
		t.Fatalf("abort=%+v err=%v", result, err)
	}
	if result, err := store.AbortCheckpointFence(ctx, holder, abort, abort.AbortedAtMilliseconds+1); err != nil || result.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("abort retry=%+v err=%v", result, err)
	}
	if retry, err := store.Publish(ctx, holder, abortSuffix, abort.AbortedAtMilliseconds+1); err != nil || retry.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("aborted suffix exact retry=%+v err=%v", retry, err)
	}
	if fetched, err := store.Fetch(ctx, reader, 5, 10, abort.AbortedAtMilliseconds+1); err != nil || len(fetched.Messages) != 0 || fetched.NextSequence != 6 {
		t.Fatalf("aborted suffix fetch=%+v err=%v", fetched, err)
	}
	abortCollision := abort
	abortCollision.AbortedAtMilliseconds++
	if _, err := store.AbortCheckpointFence(ctx, holder, abortCollision, abortCollision.AbortedAtMilliseconds); !relay.ErrorHasCode(err, relay.CodeCheckpointFenceCollision) {
		t.Fatalf("abort retry collision err=%v", err)
	}
}

func TestMemoryCheckpointActivationRejectsFutureTimeAndPreservesExactRetry(t *testing.T) {
	ctx := context.Background()
	store, admin, holder, _, template, _ := checkpointMemoryFixture(t)
	fence, suffix := acquireMemoryFenceAndPublishSuffix(t, store, holder, template, 1_400)
	candidate := relay.CheckpointCandidate{Version: 1, RetryID: uuid.New(), CheckpointID: uuid.New(), FenceID: fence.FenceID, TenantID: admin.TenantID, DomainID: admin.DomainID, PublisherSubscriptionID: holder.MemberID, KeyEpoch: 1, CoveredThroughCursor: fence.BoundaryCursor, RetainedMessageIDs: []uuid.UUID{suffix.MessageID}, CreatedAtMilliseconds: 1_402}
	if _, err := store.StageCheckpoint(ctx, holder, candidate, 1_402); err != nil {
		t.Fatal(err)
	}
	clientAhead := relay.CheckpointActivationRequest{RetryID: uuid.New(), CheckpointID: candidate.CheckpointID, ActivatedAtMilliseconds: 1_404}
	if _, err := store.ActivateCheckpoint(ctx, admin, clientAhead, 1_403); !relay.ErrorHasCode(err, relay.CodeCheckpointCollision) {
		t.Fatalf("future activation err=%v", err)
	}
	activated, err := store.ActivateCheckpoint(ctx, admin, clientAhead, 1_404)
	if err != nil || activated.StartCursor != fence.BoundaryCursor {
		t.Fatalf("activation=%+v err=%v", activated, err)
	}
	if duplicate, err := store.ActivateCheckpoint(ctx, admin, clientAhead, 1_403); err != nil || duplicate.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("exact activation retry=%+v err=%v", duplicate, err)
	}
}

func TestMemoryCheckpointRejectsActiveFrontierRegression(t *testing.T) {
	ctx := context.Background()
	store, admin, holder, _, template, _ := checkpointMemoryFixture(t)
	activate := func(acquiredAt int64, keyEpoch uint64) relay.CheckpointCandidate {
		t.Helper()
		fence, suffix := acquireMemoryFenceAndPublishSuffix(t, store, holder, template, acquiredAt)
		candidate := relay.CheckpointCandidate{
			Version: relay.SchemaVersion, RetryID: uuid.New(), CheckpointID: uuid.New(),
			FenceID: fence.FenceID, TenantID: admin.TenantID, DomainID: admin.DomainID,
			PublisherSubscriptionID: holder.MemberID, KeyEpoch: keyEpoch,
			CoveredThroughCursor:  fence.BoundaryCursor,
			RetainedMessageIDs:    []uuid.UUID{suffix.MessageID},
			CreatedAtMilliseconds: acquiredAt + 2,
		}
		if _, err := store.StageCheckpoint(ctx, holder, candidate, acquiredAt+2); err != nil {
			t.Fatal(err)
		}
		request := relay.CheckpointActivationRequest{
			RetryID: uuid.New(), CheckpointID: candidate.CheckpointID,
			ActivatedAtMilliseconds: acquiredAt + 3,
		}
		if _, err := store.ActivateCheckpoint(ctx, admin, request, acquiredAt+3); err != nil {
			t.Fatal(err)
		}
		return candidate
	}
	active := activate(1_400, 2)
	activate(1_500, 3)
	if duplicate, err := store.StageCheckpoint(ctx, holder, active, 1_500); err != nil || duplicate.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("active candidate exact retry=%+v err=%v", duplicate, err)
	}

	fence, suffix := acquireMemoryFenceAndPublishSuffix(t, store, holder, template, 1_600)
	regressed := relay.CheckpointCandidate{
		Version: relay.SchemaVersion, RetryID: uuid.New(), CheckpointID: uuid.New(),
		FenceID: fence.FenceID, TenantID: admin.TenantID, DomainID: admin.DomainID,
		PublisherSubscriptionID: holder.MemberID, KeyEpoch: 1,
		CoveredThroughCursor:  fence.BoundaryCursor,
		RetainedMessageIDs:    []uuid.UUID{suffix.MessageID},
		CreatedAtMilliseconds: 1_602,
	}
	if _, err := store.StageCheckpoint(ctx, holder, regressed, 1_602); !relay.ErrorHasCode(err, relay.CodeInvalidCheckpoint) {
		t.Fatalf("regressed checkpoint err=%v", err)
	}
}

func TestMemoryCheckpointFenceSerializesHolderPublishAndActivation(t *testing.T) {
	ctx := context.Background()
	for iteration := 0; iteration < 20; iteration++ {
		store, admin, holder, _, template, _ := checkpointMemoryFixture(t)
		acquiredAt := int64(1_400 + iteration*10)
		fence, suffix := acquireMemoryFenceAndPublishSuffix(t, store, holder, template, acquiredAt)
		candidate := relay.CheckpointCandidate{Version: 1, RetryID: uuid.New(), CheckpointID: uuid.New(), FenceID: fence.FenceID, TenantID: admin.TenantID, DomainID: admin.DomainID, PublisherSubscriptionID: holder.MemberID, KeyEpoch: 1, CoveredThroughCursor: fence.BoundaryCursor, RetainedMessageIDs: []uuid.UUID{suffix.MessageID}, CreatedAtMilliseconds: acquiredAt + 2}
		if _, err := store.StageCheckpoint(ctx, holder, candidate, acquiredAt+2); err != nil {
			t.Fatal(err)
		}
		concurrent := template
		concurrent.MessageID, concurrent.CreatedAtMilliseconds = uuid.New(), acquiredAt+3
		start := make(chan struct{})
		activationErrors := make(chan error, 1)
		publishErrors := make(chan error, 1)
		go func() {
			<-start
			_, err := store.ActivateCheckpoint(ctx, admin, relay.CheckpointActivationRequest{RetryID: uuid.New(), CheckpointID: candidate.CheckpointID, ActivatedAtMilliseconds: acquiredAt + 3}, acquiredAt+3)
			activationErrors <- err
		}()
		go func() {
			<-start
			_, err := store.Publish(ctx, holder, concurrent, acquiredAt+3)
			publishErrors <- err
		}()
		close(start)
		if err := <-publishErrors; err != nil {
			t.Fatalf("iteration %d holder publish: %v", iteration, err)
		}
		if err := <-activationErrors; err != nil && !relay.ErrorHasCode(err, relay.CodeInvalidCheckpointFence) {
			t.Fatalf("iteration %d activation: %v", iteration, err)
		}
	}
}

func TestMemoryCheckpointFreezesCustodyCollectsAndPreservesSequence(t *testing.T) {
	ctx := context.Background()
	store, admin, publisher, recipient, first, second := checkpointMemoryFixture(t)
	if _, err := store.Acknowledge(ctx, recipient, first.MessageID, relay.AcknowledgmentAccepted, 1_300); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Acknowledge(ctx, recipient, second.MessageID, relay.AcknowledgmentAccepted, 1_300); err != nil {
		t.Fatal(err)
	}
	fence, retained := acquireMemoryFenceAndPublishSuffix(t, store, publisher, first, 1_400)
	candidate := relay.CheckpointCandidate{
		Version: relay.SchemaVersion, RetryID: uuid.New(), CheckpointID: uuid.New(),
		FenceID:  fence.FenceID,
		TenantID: admin.TenantID, DomainID: admin.DomainID,
		PublisherSubscriptionID: publisher.MemberID,
		KeyEpoch:                1,
		CoveredThroughCursor:    fence.BoundaryCursor, RetainedMessageIDs: []uuid.UUID{retained.MessageID},
		CreatedAtMilliseconds: 1_402,
	}
	incomplete := candidate
	incomplete.RetryID, incomplete.CheckpointID, incomplete.RetainedMessageIDs = uuid.New(), uuid.New(), []uuid.UUID{}
	if _, err := store.StageCheckpoint(ctx, publisher, incomplete, 1_402); !relay.ErrorHasCode(err, relay.CodeInvalidCheckpoint) {
		t.Fatalf("incomplete fenced suffix err=%v", err)
	}
	staged, err := store.StageCheckpoint(ctx, publisher, candidate, 1_402)
	if err != nil || staged.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("stage=%+v err=%v", staged, err)
	}
	retry, err := store.StageCheckpoint(ctx, publisher, candidate, 1_402)
	if err != nil || retry.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("stage retry=%+v err=%v", retry, err)
	}
	activation := relay.CheckpointActivationRequest{RetryID: uuid.New(), CheckpointID: candidate.CheckpointID, ActivatedAtMilliseconds: 1_500}
	activated, err := store.ActivateCheckpoint(ctx, admin, activation, 1_500)
	if err != nil || activated.StartCursor != relay.EncodeCursor(2) {
		t.Fatalf("activation=%+v err=%v", activated, err)
	}
	if fetched, err := store.Fetch(ctx, recipient, 2, 10, 1_500); err != nil || len(fetched.Messages) != 1 || fetched.Messages[0].Envelope.MessageID != retained.MessageID {
		t.Fatalf("activated suffix fetch=%+v err=%v", fetched, err)
	}
	third := first
	third.MessageID = uuid.New()
	third.CreatedAtMilliseconds = 1_600
	published, err := store.Publish(ctx, publisher, third, 1_600)
	if err != nil || published.Sequence != 4 {
		t.Fatalf("concurrent publish=%+v err=%v", published, err)
	}
	plan, err := store.DryRunCheckpointCollection(ctx, admin, relay.CheckpointDryRunRequest{CheckpointID: candidate.CheckpointID})
	if err != nil || !plan.Eligible || plan.MessageCount != 2 {
		t.Fatalf("plan=%+v err=%v", plan, err)
	}
	request := relay.CheckpointCollectionRequest{RetryID: uuid.New(), CheckpointID: candidate.CheckpointID, PlanDigest: plan.PlanDigest, MaximumMessageCount: 2, RequestedAtMilliseconds: 1_700}
	collected, err := store.CollectCheckpoint(ctx, admin, request)
	if err != nil || !collected.Completed || collected.DeletedMessageCount != 2 {
		t.Fatalf("collection=%+v err=%v", collected, err)
	}
	duplicate, err := store.CollectCheckpoint(ctx, admin, request)
	if err != nil || !duplicate.Duplicate || duplicate.DeletedMessageCount != 2 {
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
	if err != nil || len(fetched.Messages) != 2 || fetched.Messages[0].Sequence != 3 || fetched.Messages[1].Sequence != 4 {
		t.Fatalf("post-collection fetch=%+v err=%v", fetched, err)
	}
	fourth := first
	fourth.MessageID = uuid.New()
	fourth.CreatedAtMilliseconds = 1_900
	published, err = store.Publish(ctx, publisher, fourth, 1_900)
	if err != nil || published.Sequence != 5 {
		t.Fatalf("sequence after collection=%+v err=%v", published, err)
	}
}

func TestMemoryCheckpointRebootstrapWaivesFrozenCustody(t *testing.T) {
	ctx := context.Background()
	store, admin, publisher, recipient, first, _ := checkpointMemoryFixture(t)
	fence, retained := acquireMemoryFenceAndPublishSuffix(t, store, publisher, first, 1_400)
	candidate := relay.CheckpointCandidate{Version: 1, RetryID: uuid.New(), CheckpointID: uuid.New(), FenceID: fence.FenceID, TenantID: admin.TenantID, DomainID: admin.DomainID, PublisherSubscriptionID: publisher.MemberID, KeyEpoch: 1, CoveredThroughCursor: fence.BoundaryCursor, RetainedMessageIDs: []uuid.UUID{retained.MessageID}, CreatedAtMilliseconds: 1_402}
	if _, err := store.StageCheckpoint(ctx, publisher, candidate, 1_402); err != nil {
		t.Fatal(err)
	}
	activation, err := store.ActivateCheckpoint(ctx, admin, relay.CheckpointActivationRequest{RetryID: uuid.New(), CheckpointID: candidate.CheckpointID, ActivatedAtMilliseconds: 1_500}, 1_500)
	if err != nil {
		t.Fatal(err)
	}
	blocked, err := store.DryRunCheckpointCollection(ctx, admin, relay.CheckpointDryRunRequest{CheckpointID: candidate.CheckpointID})
	if err != nil || blocked.Eligible || len(blocked.MissingCustodySubscriptionIDs) != 1 {
		t.Fatalf("blocked=%+v err=%v", blocked, err)
	}
	request := relay.SubscriptionRebootstrapRequest{
		RetryID: uuid.New(), CheckpointID: candidate.CheckpointID,
		RootMessageID: retained.MessageID, RequestedAtMilliseconds: 1_600,
		LeaseDurationMilliseconds: relay.DefaultSubscriptionRebootstrapLeaseMilliseconds,
	}
	if _, err := store.Acknowledge(ctx, recipient, retained.MessageID, relay.AcknowledgmentAccepted, 1_599); err != nil {
		t.Fatalf("pre-rebootstrap accepted acknowledgment err=%v", err)
	}
	if _, err := store.Acknowledge(ctx, recipient, retained.MessageID, relay.AcknowledgmentApplied, 1_599); err != nil {
		t.Fatalf("pre-rebootstrap applied acknowledgment err=%v", err)
	}
	wrongRoot := request
	wrongRoot.RetryID = uuid.New()
	wrongRoot.RootMessageID = uuid.New()
	if _, err := store.RequestSubscriptionRebootstrap(ctx, recipient, wrongRoot, 1_600); !relay.ErrorHasCode(err, relay.CodeCheckpointUnavailable) {
		t.Fatalf("unretained recovery root err=%v", err)
	}
	rebootstrap, err := store.RequestSubscriptionRebootstrap(ctx, recipient, request, 1_600)
	if err != nil || rebootstrap.CheckpointID != candidate.CheckpointID ||
		rebootstrap.RootMessageID != retained.MessageID ||
		rebootstrap.Subscription.StartCursor == nil || *rebootstrap.Subscription.StartCursor != activation.StartCursor {
		t.Fatalf("rebootstrap=%+v err=%v", rebootstrap, err)
	}
	if duplicate, err := store.RequestSubscriptionRebootstrap(ctx, recipient, request, 1_600); err != nil || duplicate.Acceptance != relay.AcceptanceDuplicate || duplicate.Subscription != rebootstrap.Subscription {
		t.Fatalf("rebootstrap retry=%+v err=%v", duplicate, err)
	}
	if rebootstrap.LeaseExpiresAtMilliseconds != 1_600+relay.DefaultSubscriptionRebootstrapLeaseMilliseconds {
		t.Fatalf("rebootstrap lease expiry=%d", rebootstrap.LeaseExpiresAtMilliseconds)
	}
	cancellation := relay.SubscriptionRebootstrapCancellation{
		RetryID: uuid.New(), RequestRetryID: request.RetryID,
		CheckpointID: candidate.CheckpointID, RootMessageID: retained.MessageID,
		CancelledAtMilliseconds: 1_600,
	}
	if cancelled, err := store.CancelSubscriptionRebootstrap(ctx, recipient, cancellation, 1_600); err != nil || cancelled.Acceptance != relay.AcceptanceAccepted || cancelled.Subscription.Status != relay.SubscriptionRebootstrapRequired {
		t.Fatalf("cancel rebootstrap=%+v err=%v", cancelled, err)
	}
	if _, err := store.Fetch(ctx, recipient, relay.MaximumSequence, 10, 1_600); !relay.ErrorHasCode(err, relay.CodeRebootstrapExpired) {
		t.Fatalf("cancelled rebootstrap fetch err=%v", err)
	}
	renewedRequest := request
	renewedRequest.RetryID = uuid.New()
	renewedRequest.RequestedAtMilliseconds = 1_601
	if renewed, err := store.RequestSubscriptionRebootstrap(ctx, recipient, renewedRequest, 1_601); err != nil || renewed.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("renew rebootstrap=%+v err=%v", renewed, err)
	}
	request = renewedRequest
	recoveryFence, recoverySuffix := acquireMemoryFenceAndPublishSuffix(
		t, store, publisher, retained, 1_601,
	)
	recoveryCandidate := relay.CheckpointCandidate{
		Version: relay.SchemaVersion, RetryID: uuid.New(), CheckpointID: uuid.New(),
		FenceID: recoveryFence.FenceID, TenantID: admin.TenantID,
		DomainID: admin.DomainID, PublisherSubscriptionID: publisher.MemberID,
		KeyEpoch: 1, CoveredThroughCursor: recoveryFence.BoundaryCursor,
		RetainedMessageIDs:    []uuid.UUID{recoverySuffix.MessageID},
		CreatedAtMilliseconds: 1_603,
	}
	if _, err := store.StageCheckpoint(ctx, publisher, recoveryCandidate, 1_603); err != nil {
		t.Fatal(err)
	}
	blockedActivation := relay.CheckpointActivationRequest{
		RetryID: uuid.New(), CheckpointID: recoveryCandidate.CheckpointID,
		ActivatedAtMilliseconds: 1_604,
	}
	if _, err := store.ActivateCheckpoint(ctx, admin, blockedActivation, 1_604); !relay.ErrorHasCode(err, relay.CodeCheckpointNotEligible) {
		t.Fatalf("checkpoint activation during bound recovery err=%v", err)
	}
	if _, err := store.AbortCheckpointFence(ctx, publisher, relay.CheckpointFenceAbortRequest{
		RetryID: uuid.New(), FenceID: recoveryFence.FenceID,
		AbortedAtMilliseconds: 1_605,
	}, 1_605); err != nil {
		t.Fatal(err)
	}
	// A rebootstrap-required subscription is intentionally read-only, but it
	// must be able to force its stale local cursor back to the checkpoint
	// boundary and acknowledge the retained ciphertext after durable repair.
	fetched, err := store.Fetch(ctx, recipient, relay.MaximumSequence, 10, 1_606)
	if err != nil || len(fetched.Messages) != 1 || fetched.Messages[0].Envelope.MessageID != retained.MessageID {
		t.Fatalf("rebootstrap fetch=%+v err=%v", fetched, err)
	}
	if _, err := store.Acknowledge(ctx, recipient, retained.MessageID, relay.AcknowledgmentAccepted, 1_607); err != nil {
		t.Fatalf("rebootstrap acknowledge err=%v", err)
	}
	completion := relay.SubscriptionRebootstrapCompletion{
		RetryID: uuid.New(), RequestRetryID: request.RetryID,
		CheckpointID: candidate.CheckpointID, RootMessageID: retained.MessageID,
		CompletedThroughCursor:  relay.EncodeCursor(fetched.NextSequence),
		CompletedAtMilliseconds: 1_608,
	}
	substitutedCompletion := completion
	substitutedCompletion.RetryID = uuid.New()
	substitutedCompletion.RootMessageID = uuid.New()
	if _, err := store.CompleteSubscriptionRebootstrap(ctx, recipient, substitutedCompletion, 1_608); !relay.ErrorHasCode(err, relay.CodeSubscriptionCollision) {
		t.Fatalf("substituted recovery completion err=%v", err)
	}
	if _, err := store.CompleteSubscriptionRebootstrap(ctx, recipient, completion, 1_608); !relay.ErrorHasCode(err, relay.CodeRebootstrapIncomplete) {
		t.Fatalf("rebootstrap completion before applied err=%v", err)
	}
	if _, err := store.Acknowledge(ctx, recipient, retained.MessageID, relay.AcknowledgmentApplied, 1_609); err != nil {
		t.Fatalf("rebootstrap applied receipt err=%v", err)
	}
	if quiet, err := store.Fetch(ctx, recipient, relay.MaximumSequence, 10, 1_609); err != nil || len(quiet.Messages) != 0 || quiet.NextSequence != fetched.NextSequence {
		t.Fatalf("rebootstrap quiet tail=%+v err=%v", quiet, err)
	}
	completed, err := store.CompleteSubscriptionRebootstrap(ctx, recipient, completion, 1_610)
	if err != nil || completed.Subscription.Status != relay.SubscriptionActive || completed.Subscription.StartCursor != nil {
		t.Fatalf("rebootstrap completion=%+v err=%v", completed, err)
	}
	if duplicate, err := store.CompleteSubscriptionRebootstrap(ctx, recipient, completion, 1_610); err != nil || duplicate.Acceptance != relay.AcceptanceDuplicate || duplicate.Subscription != completed.Subscription {
		t.Fatalf("rebootstrap completion retry=%+v err=%v", duplicate, err)
	}
	// A publisher restoring its own discarded replica must receive the exact
	// checkpoint bytes it previously published. Ordinary active delivery still
	// suppresses same-subscription echoes.
	publisherRequest := relay.SubscriptionRebootstrapRequest{
		RetryID: uuid.New(), CheckpointID: candidate.CheckpointID,
		RootMessageID: retained.MessageID, RequestedAtMilliseconds: 1_611,
		LeaseDurationMilliseconds: relay.DefaultSubscriptionRebootstrapLeaseMilliseconds,
	}
	if requested, err := store.RequestSubscriptionRebootstrap(ctx, publisher, publisherRequest, 1_611); err != nil || requested.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("publisher rebootstrap request=%+v err=%v", requested, err)
	}
	publisherFetch, err := store.Fetch(ctx, publisher, relay.MaximumSequence, 10, 1_612)
	if err != nil || len(publisherFetch.Messages) != 1 || publisherFetch.Messages[0].Envelope.MessageID != retained.MessageID {
		t.Fatalf("publisher rebootstrap fetch=%+v err=%v", publisherFetch, err)
	}
	if _, err := store.Acknowledge(ctx, publisher, retained.MessageID, relay.AcknowledgmentAccepted, 1_613); err != nil {
		t.Fatalf("publisher rebootstrap accepted receipt err=%v", err)
	}
	if _, err := store.Acknowledge(ctx, publisher, retained.MessageID, relay.AcknowledgmentApplied, 1_614); err != nil {
		t.Fatalf("publisher rebootstrap applied receipt err=%v", err)
	}
	publisherCompletion := relay.SubscriptionRebootstrapCompletion{
		RetryID: uuid.New(), RequestRetryID: publisherRequest.RetryID,
		CheckpointID: candidate.CheckpointID, RootMessageID: retained.MessageID,
		CompletedThroughCursor:  relay.EncodeCursor(publisherFetch.NextSequence),
		CompletedAtMilliseconds: 1_615,
	}
	if completed, err := store.CompleteSubscriptionRebootstrap(ctx, publisher, publisherCompletion, 1_615); err != nil || completed.Subscription.Status != relay.SubscriptionActive {
		t.Fatalf("publisher rebootstrap completion=%+v err=%v", completed, err)
	}
	eligible, err := store.DryRunCheckpointCollection(ctx, admin, relay.CheckpointDryRunRequest{CheckpointID: candidate.CheckpointID})
	if err != nil || !eligible.Eligible {
		t.Fatalf("eligible=%+v err=%v first=%s", eligible, err, first.MessageID)
	}
	recoveredPublish := retained
	recoveredPublish.MessageID = uuid.New()
	recoveredPublish.PublisherMemberID = recipient.MemberID
	recoveredPublish.CreatedAtMilliseconds = 1_616
	if _, err := store.Publish(ctx, recipient, recoveredPublish, 1_616); err != nil {
		t.Fatalf("rebootstrap publish after completion err=%v", err)
	}
}

func TestMemorySubscriptionRebootstrapLeaseExpiresAndCanBeRenewed(t *testing.T) {
	ctx := context.Background()
	store, admin, publisher, recipient, first, _ := checkpointMemoryFixture(t)
	fence, retained := acquireMemoryFenceAndPublishSuffix(t, store, publisher, first, 1_400)
	candidate := relay.CheckpointCandidate{
		Version: relay.SchemaVersion, RetryID: uuid.New(), CheckpointID: uuid.New(),
		FenceID: fence.FenceID, TenantID: admin.TenantID, DomainID: admin.DomainID,
		PublisherSubscriptionID: publisher.MemberID, KeyEpoch: 1,
		CoveredThroughCursor:  fence.BoundaryCursor,
		RetainedMessageIDs:    []uuid.UUID{retained.MessageID},
		CreatedAtMilliseconds: 1_402,
	}
	if _, err := store.StageCheckpoint(ctx, publisher, candidate, 1_402); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ActivateCheckpoint(ctx, admin, relay.CheckpointActivationRequest{
		RetryID: uuid.New(), CheckpointID: candidate.CheckpointID,
		ActivatedAtMilliseconds: 1_500,
	}, 1_500); err != nil {
		t.Fatal(err)
	}
	request := relay.SubscriptionRebootstrapRequest{
		RetryID: uuid.New(), CheckpointID: candidate.CheckpointID,
		RootMessageID: retained.MessageID, RequestedAtMilliseconds: 1_600,
		LeaseDurationMilliseconds: relay.MinimumSubscriptionRebootstrapLeaseMilliseconds,
	}
	accepted, err := store.RequestSubscriptionRebootstrap(ctx, recipient, request, 1_600)
	if err != nil {
		t.Fatal(err)
	}
	expiresAt := accepted.LeaseExpiresAtMilliseconds
	if _, err := store.Fetch(ctx, recipient, relay.MaximumSequence, 10, expiresAt-1); err != nil {
		t.Fatalf("fetch immediately before lease expiry err=%v", err)
	}
	if _, err := store.Fetch(ctx, recipient, relay.MaximumSequence, 10, expiresAt); !relay.ErrorHasCode(err, relay.CodeRebootstrapExpired) {
		t.Fatalf("fetch at lease expiry err=%v", err)
	}
	renewed := request
	renewed.RetryID = uuid.New()
	renewed.RequestedAtMilliseconds = expiresAt
	result, err := store.RequestSubscriptionRebootstrap(ctx, recipient, renewed, expiresAt)
	if err != nil || result.Acceptance != relay.AcceptanceAccepted ||
		result.LeaseExpiresAtMilliseconds != expiresAt+relay.MinimumSubscriptionRebootstrapLeaseMilliseconds {
		t.Fatalf("renewed rebootstrap=%+v err=%v", result, err)
	}
}

func TestMemorySubscriptionRebootstrapLeaseRenewsWithoutResettingProgress(t *testing.T) {
	ctx := context.Background()
	store, admin, publisher, recipient, first, _ := checkpointMemoryFixture(t)
	fence, retained := acquireMemoryFenceAndPublishSuffix(t, store, publisher, first, 1_400)
	candidate := relay.CheckpointCandidate{
		Version: relay.SchemaVersion, RetryID: uuid.New(), CheckpointID: uuid.New(),
		FenceID: fence.FenceID, TenantID: admin.TenantID, DomainID: admin.DomainID,
		PublisherSubscriptionID: publisher.MemberID, KeyEpoch: 1,
		CoveredThroughCursor:  fence.BoundaryCursor,
		RetainedMessageIDs:    []uuid.UUID{retained.MessageID},
		CreatedAtMilliseconds: 1_402,
	}
	if _, err := store.StageCheckpoint(ctx, publisher, candidate, 1_402); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ActivateCheckpoint(ctx, admin, relay.CheckpointActivationRequest{
		RetryID: uuid.New(), CheckpointID: candidate.CheckpointID,
		ActivatedAtMilliseconds: 1_500,
	}, 1_500); err != nil {
		t.Fatal(err)
	}
	request := relay.SubscriptionRebootstrapRequest{
		RetryID: uuid.New(), CheckpointID: candidate.CheckpointID,
		RootMessageID: retained.MessageID, RequestedAtMilliseconds: 1_600,
		LeaseDurationMilliseconds: relay.MinimumSubscriptionRebootstrapLeaseMilliseconds,
	}
	accepted, err := store.RequestSubscriptionRebootstrap(ctx, recipient, request, 1_600)
	if err != nil {
		t.Fatal(err)
	}
	page, err := store.Fetch(ctx, recipient, relay.MaximumSequence, 10, 1_601)
	if err != nil || len(page.Messages) == 0 {
		t.Fatalf("rebootstrap fetch=%+v err=%v", page, err)
	}
	for _, message := range page.Messages {
		if _, err := store.Acknowledge(ctx, recipient, message.Envelope.MessageID, relay.AcknowledgmentAccepted, 1_602); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Acknowledge(ctx, recipient, message.Envelope.MessageID, relay.AcknowledgmentApplied, 1_603); err != nil {
			t.Fatal(err)
		}
	}
	renewal := relay.SubscriptionRebootstrapRenewal{
		RetryID: uuid.New(), RequestRetryID: request.RetryID,
		CheckpointID: candidate.CheckpointID, RootMessageID: retained.MessageID,
		ExpectedLeaseExpiresAtMilliseconds: accepted.LeaseExpiresAtMilliseconds,
		RequestedAtMilliseconds: accepted.LeaseExpiresAtMilliseconds -
			relay.MinimumSubscriptionRebootstrapLeaseMilliseconds/2,
		LeaseDurationMilliseconds: relay.MinimumSubscriptionRebootstrapLeaseMilliseconds,
	}
	renewed, err := store.RenewSubscriptionRebootstrap(
		ctx, recipient, renewal, renewal.RequestedAtMilliseconds,
	)
	if err != nil || renewed.Acceptance != relay.AcceptanceAccepted ||
		renewed.PreviousLeaseExpiresAtMilliseconds != accepted.LeaseExpiresAtMilliseconds ||
		renewed.LeaseExpiresAtMilliseconds <= accepted.LeaseExpiresAtMilliseconds ||
		renewed.Subscription.StartCursor == nil || accepted.Subscription.StartCursor == nil ||
		*renewed.Subscription.StartCursor != *accepted.Subscription.StartCursor {
		t.Fatalf("renewed rebootstrap=%+v err=%v", renewed, err)
	}
	if duplicate, err := store.RenewSubscriptionRebootstrap(
		ctx, recipient, renewal, renewal.RequestedAtMilliseconds,
	); err != nil || duplicate.Acceptance != relay.AcceptanceDuplicate ||
		duplicate.LeaseExpiresAtMilliseconds != renewed.LeaseExpiresAtMilliseconds {
		t.Fatalf("renewal retry=%+v err=%v", duplicate, err)
	}
	stale := renewal
	stale.RetryID = uuid.New()
	if _, err := store.RenewSubscriptionRebootstrap(
		ctx, recipient, stale, renewal.RequestedAtMilliseconds,
	); !relay.ErrorHasCode(err, relay.CodeSubscriptionCollision) {
		t.Fatalf("stale renewal err=%v", err)
	}
	completion := relay.SubscriptionRebootstrapCompletion{
		RetryID: uuid.New(), RequestRetryID: request.RetryID,
		CheckpointID: candidate.CheckpointID, RootMessageID: retained.MessageID,
		CompletedThroughCursor:  relay.EncodeCursor(page.NextSequence),
		CompletedAtMilliseconds: renewal.RequestedAtMilliseconds + 1,
	}
	completed, err := store.CompleteSubscriptionRebootstrap(
		ctx, recipient, completion, completion.CompletedAtMilliseconds,
	)
	if err != nil || completed.Subscription.Status != relay.SubscriptionActive {
		t.Fatalf("completion after renewal=%+v err=%v", completed, err)
	}
	postCompletion := renewal
	postCompletion.RetryID = uuid.New()
	postCompletion.ExpectedLeaseExpiresAtMilliseconds =
		renewed.LeaseExpiresAtMilliseconds
	if _, err := store.RenewSubscriptionRebootstrap(
		ctx, recipient, postCompletion, completion.CompletedAtMilliseconds,
	); !relay.ErrorHasCode(err, relay.CodeRebootstrapExpired) {
		t.Fatalf("post-completion renewal err=%v", err)
	}
}

func acquireMemoryFenceAndPublishSuffix(t *testing.T, store *relay.MemoryStore, publisher relay.Credential, template relay.Envelope, acquiredAt int64) (relay.CheckpointFenceResponse, relay.Envelope) {
	t.Helper()
	request := relay.CheckpointFenceRequest{RetryID: uuid.New(), FenceID: uuid.New(), RequestedAtMilliseconds: acquiredAt}
	fence, err := store.CreateCheckpointFence(context.Background(), publisher, request, acquiredAt)
	if err != nil {
		t.Fatal(err)
	}
	suffix := template
	suffix.MessageID = uuid.New()
	suffix.CreatedAtMilliseconds = acquiredAt + 1
	if _, err := store.Publish(context.Background(), publisher, suffix, acquiredAt+1); err != nil {
		t.Fatal(err)
	}
	return fence, suffix
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
	activate := func(created int64, _ []uuid.UUID) uuid.UUID {
		t.Helper()
		fence, suffix := acquireMemoryFenceAndPublishSuffix(t, store, publisher, first, created)
		candidate := relay.CheckpointCandidate{
			Version: relay.SchemaVersion, RetryID: uuid.New(), CheckpointID: uuid.New(),
			FenceID:  fence.FenceID,
			TenantID: admin.TenantID, DomainID: admin.DomainID,
			PublisherSubscriptionID: publisher.MemberID,
			KeyEpoch:                1,
			CoveredThroughCursor:    fence.BoundaryCursor, RetainedMessageIDs: []uuid.UUID{suffix.MessageID},
			RetainedBlobIDs: []string{}, CreatedAtMilliseconds: created + 2,
		}
		if _, err := store.StageCheckpoint(ctx, publisher, candidate, created+2); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ActivateCheckpoint(ctx, admin, relay.CheckpointActivationRequest{RetryID: uuid.New(), CheckpointID: candidate.CheckpointID, ActivatedAtMilliseconds: created + 3}, created+3); err != nil {
			t.Fatal(err)
		}
		candidates = append(candidates, candidate)
		return candidate.CheckpointID
	}
	activate(1_400, []uuid.UUID{second.MessageID})
	activate(1_500, []uuid.UUID{first.MessageID})
	thirdID := activate(1_600, []uuid.UUID{second.MessageID})
	thirdPlan, err := store.DryRunCheckpointCollection(ctx, admin, relay.CheckpointDryRunRequest{CheckpointID: thirdID})
	if err != nil || thirdPlan.MessageCount != 3 {
		t.Fatalf("third fenced plan=%+v err=%v", thirdPlan, err)
	}
	fourthID := activate(1_700, []uuid.UUID{second.MessageID})
	fourthPlan, err := store.DryRunCheckpointCollection(ctx, admin, relay.CheckpointDryRunRequest{CheckpointID: fourthID})
	if err != nil || fourthPlan.MessageCount != 4 {
		t.Fatalf("fourth fenced plan=%+v err=%v", fourthPlan, err)
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
	_, err = store.CreateDomain(ctx, relay.DomainRegistration{Version: 1, TenantID: tenantID, DomainID: domainID, AdministrationDigest: adminDigest, CreatedAtMilliseconds: 1_000, MaximumMessageCount: 100, MaximumMessageByteCount: 1_000_000, MaximumBlobCount: 100, MaximumBlobByteCount: 1_000_000}, relay.MemberRegistration{Version: 1, TenantID: tenantID, DomainID: domainID, MemberID: publisher.MemberID, AuthorizationDigest: publisherDigest, Capabilities: []relay.Capability{relay.CapabilityPublishBlob, relay.CapabilityPublishCheckpoint, relay.CapabilityAcknowledgeMessage, relay.CapabilityFetchMessage, relay.CapabilityPublishMessage}, CreatedAtMilliseconds: 1_000})
	if err != nil {
		t.Fatal(err)
	}
	recipient := relay.Credential{TenantID: tenantID, DomainID: domainID, MemberID: uuid.New(), Token: token(92)}
	recipientDigest, _ := relay.AuthorizationDigest(recipient)
	_, err = store.CreateMember(ctx, admin, relay.MemberRegistration{Version: 1, TenantID: tenantID, DomainID: domainID, MemberID: recipient.MemberID, AuthorizationDigest: recipientDigest, Capabilities: []relay.Capability{relay.CapabilityFetchBlob, relay.CapabilityAcknowledgeMessage, relay.CapabilityFetchMessage, relay.CapabilityPublishMessage}, CreatedAtMilliseconds: 1_000}, 1_100)
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
