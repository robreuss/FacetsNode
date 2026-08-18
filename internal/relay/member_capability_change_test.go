package relay_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/testfixture"
)

func TestMemoryStoreReplacesMemberCapabilitiesIdempotently(t *testing.T) {
	ctx := context.Background()
	fixture, err := testfixture.LoadRelayCarrier()
	if err != nil {
		t.Fatal(err)
	}
	admin := relay.AdministrationCredential{
		TenantID: fixture.Envelope.TenantID,
		DomainID: fixture.Envelope.DomainID,
		Token:    token(211),
	}
	adminDigest, err := relay.AdministrationDigest(admin)
	if err != nil {
		t.Fatal(err)
	}
	domain := relay.DomainRegistration{
		Version: relay.SchemaVersion, TenantID: admin.TenantID, DomainID: admin.DomainID,
		AdministrationDigest: adminDigest, CreatedAtMilliseconds: 1_000,
		MaximumMessageCount: 10, MaximumMessageByteCount: 1_000_000,
		MaximumBlobCount: 10, MaximumBlobByteCount: 1_000_000,
	}
	store := relay.NewMemoryStore()
	if acceptance, createErr := store.CreateDomain(ctx, domain, fixture.PublisherRegistration); createErr != nil || acceptance != relay.AcceptanceAccepted {
		t.Fatalf("create domain acceptance=%q err=%v", acceptance, createErr)
	}

	change := relay.MemberCapabilityChange{
		Version: relay.SchemaVersion, RetryID: uuid.New(), MemberID: fixture.PublisherRegistration.MemberID,
		PreviousCapabilities:  fixture.PublisherRegistration.Capabilities,
		NextCapabilities:      []relay.Capability{relay.CapabilityFetchMessage},
		ChangedAtMilliseconds: 1_200,
	}
	changed, err := store.ChangeMemberCapabilities(ctx, admin, change, 1_200)
	if err != nil || changed.Acceptance != relay.AcceptanceAccepted ||
		!reflect.DeepEqual(changed.CurrentCapabilities, change.NextCapabilities) {
		t.Fatalf("change=%+v err=%v", changed, err)
	}
	retried, err := store.ChangeMemberCapabilities(ctx, admin, change, 1_201)
	if err != nil || retried.Acceptance != relay.AcceptanceDuplicate ||
		!reflect.DeepEqual(retried.CurrentCapabilities, change.NextCapabilities) {
		t.Fatalf("retry=%+v err=%v", retried, err)
	}
	if _, err := store.Publish(ctx, fixture.PublisherAccess.Credential(), fixture.Envelope, 1_201); !relay.ErrorHasCode(err, relay.CodeMissingCapability) {
		t.Fatalf("publish after demotion err=%v", err)
	}

	collision := change
	collision.ChangedAtMilliseconds++
	if _, err := store.ChangeMemberCapabilities(ctx, admin, collision, 1_201); !relay.ErrorHasCode(err, relay.CodeMemberCapabilityCollision) {
		t.Fatalf("retry collision err=%v", err)
	}
	stale := relay.MemberCapabilityChange{
		Version: relay.SchemaVersion, RetryID: uuid.New(), MemberID: fixture.PublisherRegistration.MemberID,
		PreviousCapabilities:  fixture.PublisherRegistration.Capabilities,
		NextCapabilities:      []relay.Capability{relay.CapabilityPublishMessage},
		ChangedAtMilliseconds: 1_202,
	}
	if _, err := store.ChangeMemberCapabilities(ctx, admin, stale, 1_202); !relay.ErrorHasCode(err, relay.CodeMemberCapabilityCollision) {
		t.Fatalf("stale capability change err=%v", err)
	}

	promote := relay.MemberCapabilityChange{
		Version: relay.SchemaVersion, RetryID: uuid.New(), MemberID: fixture.PublisherRegistration.MemberID,
		PreviousCapabilities:  change.NextCapabilities,
		NextCapabilities:      fixture.PublisherRegistration.Capabilities,
		ChangedAtMilliseconds: 1_203,
	}
	if result, err := store.ChangeMemberCapabilities(ctx, admin, promote, 1_203); err != nil || result.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("promotion=%+v err=%v", result, err)
	}
	if result, err := store.Publish(ctx, fixture.PublisherAccess.Credential(), fixture.Envelope, 1_203); err != nil || result.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("publish after promotion=%+v err=%v", result, err)
	}
}
