package relay_test

import (
	"context"
	"encoding/base64"
	"reflect"
	"testing"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/testfixture"
)

func TestMemoryStoreDeliversOncePerDomainWithPerMemberFacts(t *testing.T) {
	ctx := context.Background()
	fixture, err := testfixture.LoadRelayCarrier()
	if err != nil {
		t.Fatal(err)
	}
	admin := relay.AdministrationCredential{
		TenantID: fixture.Envelope.TenantID,
		DomainID: fixture.Envelope.DomainID,
		Token:    token(128),
	}
	adminDigest, err := relay.AdministrationDigest(admin)
	if err != nil {
		t.Fatal(err)
	}
	domain := relay.DomainRegistration{
		Version:                relay.SchemaVersion,
		TenantID:               admin.TenantID,
		DomainID:               admin.DomainID,
		AdministrationDigest:   adminDigest,
		CreatedAtMilliseconds:  1_000,
		MaximumMessageCount:    10,
		MaximumBlobCount:       10,
		MaximumStoredByteCount: 2_048,
	}
	store := relay.NewMemoryStore()
	acceptance, err := store.CreateDomain(ctx, domain, fixture.PublisherRegistration)
	if err != nil || acceptance != relay.AcceptanceAccepted {
		t.Fatalf("create domain acceptance=%q err=%v", acceptance, err)
	}

	recipientCredential := fixture.RecipientAccess.Credential()
	recipientDigest, err := relay.AuthorizationDigest(recipientCredential)
	if err != nil {
		t.Fatal(err)
	}
	recipient := relay.MemberRegistration{
		Version:             relay.SchemaVersion,
		TenantID:            recipientCredential.TenantID,
		DomainID:            recipientCredential.DomainID,
		MemberID:            recipientCredential.MemberID,
		AuthorizationDigest: recipientDigest,
		Capabilities: []relay.Capability{
			relay.CapabilityAcknowledgeMessage,
			relay.CapabilityFetchMessage,
		},
		CreatedAtMilliseconds: 1_000,
	}
	acceptance, err = store.CreateMember(ctx, admin, recipient, 1_500)
	if err != nil || acceptance != relay.AcceptanceAccepted {
		t.Fatalf("create member acceptance=%q err=%v", acceptance, err)
	}

	published, err := store.Publish(
		ctx,
		fixture.PublisherAccess.Credential(),
		fixture.Envelope,
		1_500,
	)
	if err != nil || published.Acceptance != relay.AcceptanceAccepted ||
		published.Sequence != 1 {
		t.Fatalf("publish=%+v err=%v", published, err)
	}
	retry, err := store.Publish(
		ctx,
		fixture.PublisherAccess.Credential(),
		fixture.Envelope,
		1_500,
	)
	if err != nil || retry.Acceptance != relay.AcceptanceDuplicate ||
		retry.Sequence != published.Sequence {
		t.Fatalf("retry=%+v err=%v", retry, err)
	}

	fetched, err := store.Fetch(ctx, recipientCredential, 0, 10, 1_500)
	if err != nil || len(fetched.Messages) != 1 ||
		fetched.Messages[0].Envelope != fixture.Envelope ||
		fetched.NextSequence != 1 {
		t.Fatalf("fetch=%+v err=%v", fetched, err)
	}
	publisherFetch, err := store.Fetch(
		ctx,
		fixture.PublisherAccess.Credential(),
		0,
		10,
		1_500,
	)
	if err != nil || len(publisherFetch.Messages) != 0 ||
		publisherFetch.NextSequence != 1 {
		t.Fatalf("publisher fetch=%+v err=%v", publisherFetch, err)
	}

	if _, err := store.Acknowledge(
		ctx,
		recipientCredential,
		fixture.Envelope.MessageID,
		relay.AcknowledgmentApplied,
		1_500,
	); !relay.ErrorHasCode(err, relay.CodeInvalidAcknowledgment) {
		t.Fatalf("applied-before-accepted err=%v", err)
	}
	accepted, err := store.Acknowledge(
		ctx,
		recipientCredential,
		fixture.Envelope.MessageID,
		relay.AcknowledgmentAccepted,
		1_500,
	)
	if err != nil || accepted.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("accepted=%+v err=%v", accepted, err)
	}
	applied, err := store.Acknowledge(
		ctx,
		recipientCredential,
		fixture.Envelope.MessageID,
		relay.AcknowledgmentApplied,
		1_500,
	)
	if err != nil || applied.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("applied=%+v err=%v", applied, err)
	}
	lowerRetry, err := store.Acknowledge(
		ctx,
		recipientCredential,
		fixture.Envelope.MessageID,
		relay.AcknowledgmentAccepted,
		1_500,
	)
	if err != nil || lowerRetry.Acceptance != relay.AcceptanceDuplicate ||
		lowerRetry.Stage != relay.AcknowledgmentApplied {
		t.Fatalf("lower retry=%+v err=%v", lowerRetry, err)
	}

	revocation, err := store.RevokeMember(
		ctx,
		admin,
		recipientCredential.MemberID,
		1_600,
	)
	if err != nil || revocation != relay.AcceptanceAccepted {
		t.Fatalf("revocation=%q err=%v", revocation, err)
	}
	if _, err := store.Fetch(ctx, recipientCredential, 0, 10, 1_600); !relay.ErrorHasCode(err, relay.CodeMemberRevoked) {
		t.Fatalf("fetch after revocation err=%v", err)
	}
}

func TestMemoryStoreRejectsScopeCapabilityAndMessageCollisions(t *testing.T) {
	ctx := context.Background()
	fixture, err := testfixture.LoadRelayCarrier()
	if err != nil {
		t.Fatal(err)
	}
	admin := relay.AdministrationCredential{
		TenantID: fixture.Envelope.TenantID,
		DomainID: fixture.Envelope.DomainID,
		Token:    token(128),
	}
	digest, _ := relay.AdministrationDigest(admin)
	store := relay.NewMemoryStore()
	_, err = store.CreateDomain(ctx, relay.DomainRegistration{
		Version:                relay.SchemaVersion,
		TenantID:               admin.TenantID,
		DomainID:               admin.DomainID,
		AdministrationDigest:   digest,
		CreatedAtMilliseconds:  1_000,
		MaximumMessageCount:    10,
		MaximumBlobCount:       10,
		MaximumStoredByteCount: 2_048,
	}, fixture.PublisherRegistration)
	if err != nil {
		t.Fatal(err)
	}

	changed := fixture.Envelope
	changed.AuthenticationTag = "AAAAAAAAAAAAAAAAAAAAAA"
	if _, err := store.Publish(
		ctx,
		fixture.PublisherAccess.Credential(),
		fixture.Envelope,
		1_500,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Publish(
		ctx,
		fixture.PublisherAccess.Credential(),
		changed,
		1_500,
	); !relay.ErrorHasCode(err, relay.CodeMessageCollision) {
		t.Fatalf("collision err=%v", err)
	}

	wrongScope := fixture.PublisherAccess.Credential()
	wrongScope.DomainID = uuid.New()
	if _, err := store.Publish(ctx, wrongScope, fixture.Envelope, 1_500); !relay.ErrorHasCode(err, relay.CodeDomainNotFound) {
		t.Fatalf("wrong scope err=%v", err)
	}

	fetchOnlyCredential := fixture.RecipientAccess.Credential()
	fetchOnlyDigest, err := relay.AuthorizationDigest(fetchOnlyCredential)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.CreateMember(ctx, admin, relay.MemberRegistration{
		Version:               relay.SchemaVersion,
		TenantID:              fetchOnlyCredential.TenantID,
		DomainID:              fetchOnlyCredential.DomainID,
		MemberID:              fetchOnlyCredential.MemberID,
		AuthorizationDigest:   fetchOnlyDigest,
		Capabilities:          []relay.Capability{relay.CapabilityFetchMessage},
		CreatedAtMilliseconds: 1_000,
	}, 1_500)
	if err != nil {
		t.Fatal(err)
	}
	fetchOnlyEnvelope := fixture.Envelope
	fetchOnlyEnvelope.MessageID = uuid.New()
	fetchOnlyEnvelope.PublisherMemberID = fetchOnlyCredential.MemberID
	if _, err := store.Publish(
		ctx,
		fetchOnlyCredential,
		fetchOnlyEnvelope,
		1_500,
	); !relay.ErrorHasCode(err, relay.CodeMissingCapability) {
		t.Fatalf("publish without capability err=%v", err)
	}

	expiredCredential := relay.Credential{
		TenantID: admin.TenantID,
		DomainID: admin.DomainID,
		MemberID: uuid.New(),
		Token:    token(64),
	}
	expiredDigest, err := relay.AuthorizationDigest(expiredCredential)
	if err != nil {
		t.Fatal(err)
	}
	expiresAt := int64(1_400)
	_, err = store.CreateMember(ctx, admin, relay.MemberRegistration{
		Version:               relay.SchemaVersion,
		TenantID:              expiredCredential.TenantID,
		DomainID:              expiredCredential.DomainID,
		MemberID:              expiredCredential.MemberID,
		AuthorizationDigest:   expiredDigest,
		Capabilities:          []relay.Capability{relay.CapabilityPublishMessage},
		CreatedAtMilliseconds: 1_000,
		ExpiresAtMilliseconds: &expiresAt,
	}, 1_200)
	if err != nil {
		t.Fatal(err)
	}
	expiredEnvelope := fixture.Envelope
	expiredEnvelope.MessageID = uuid.New()
	expiredEnvelope.PublisherMemberID = expiredCredential.MemberID
	if _, err := store.Publish(
		ctx,
		expiredCredential,
		expiredEnvelope,
		1_500,
	); !relay.ErrorHasCode(err, relay.CodeMemberExpired) {
		t.Fatalf("publish after member expiry err=%v", err)
	}
}

func TestMemoryStoreEnforcesStoredByteQuotaWithoutChargingRetries(t *testing.T) {
	ctx := context.Background()
	fixture, err := testfixture.LoadRelayCarrier()
	if err != nil {
		t.Fatal(err)
	}
	ciphertextByteCount, err := fixture.Envelope.CiphertextByteCount()
	if err != nil {
		t.Fatal(err)
	}
	admin := relay.AdministrationCredential{
		TenantID: fixture.Envelope.TenantID,
		DomainID: fixture.Envelope.DomainID,
		Token:    token(128),
	}
	adminDigest, err := relay.AdministrationDigest(admin)
	if err != nil {
		t.Fatal(err)
	}
	store := relay.NewMemoryStore()
	_, err = store.CreateDomain(ctx, relay.DomainRegistration{
		Version:                relay.SchemaVersion,
		TenantID:               admin.TenantID,
		DomainID:               admin.DomainID,
		AdministrationDigest:   adminDigest,
		CreatedAtMilliseconds:  1_000,
		MaximumMessageCount:    10,
		MaximumBlobCount:       10,
		MaximumStoredByteCount: ciphertextByteCount,
	}, fixture.PublisherRegistration)
	if err != nil {
		t.Fatal(err)
	}
	credential := fixture.PublisherAccess.Credential()
	first, err := store.Publish(ctx, credential, fixture.Envelope, 1_500)
	if err != nil || first.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("first publish=%+v err=%v", first, err)
	}
	retry, err := store.Publish(ctx, credential, fixture.Envelope, 1_500)
	if err != nil || retry.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("retry=%+v err=%v", retry, err)
	}
	second := fixture.Envelope
	second.MessageID = uuid.New()
	if _, err := store.Publish(ctx, credential, second, 1_500); !relay.ErrorHasCode(err, relay.CodeDomainFull) {
		t.Fatalf("publish beyond stored-byte quota err=%v", err)
	}
}

func TestMemoryStoreAuthorizesAndAccountsForOpaqueBlobs(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	domainID := uuid.New()
	publisherCredential := relay.Credential{
		TenantID: tenantID,
		DomainID: domainID,
		MemberID: uuid.New(),
		Token:    token(96),
	}
	publisherDigest, err := relay.AuthorizationDigest(publisherCredential)
	if err != nil {
		t.Fatal(err)
	}
	admin := relay.AdministrationCredential{
		TenantID: tenantID,
		DomainID: domainID,
		Token:    token(128),
	}
	adminDigest, err := relay.AdministrationDigest(admin)
	if err != nil {
		t.Fatal(err)
	}
	store := relay.NewMemoryStore()
	_, err = store.CreateDomain(ctx, relay.DomainRegistration{
		Version:                relay.SchemaVersion,
		TenantID:               tenantID,
		DomainID:               domainID,
		AdministrationDigest:   adminDigest,
		CreatedAtMilliseconds:  1_000,
		MaximumMessageCount:    1,
		MaximumBlobCount:       1,
		MaximumStoredByteCount: 4,
	}, relay.MemberRegistration{
		Version:               relay.SchemaVersion,
		TenantID:              tenantID,
		DomainID:              domainID,
		MemberID:              publisherCredential.MemberID,
		AuthorizationDigest:   publisherDigest,
		Capabilities:          []relay.Capability{relay.CapabilityPublishBlob},
		CreatedAtMilliseconds: 1_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	blobBytes := []byte{1, 2, 3, 4}
	blobID := relay.BlobID(blobBytes)
	if err := store.PrepareBlobPublish(
		ctx, publisherCredential, blobID, int64(len(blobBytes)), 1_500,
	); err != nil {
		t.Fatal(err)
	}
	published, err := store.CommitBlobPublish(
		ctx, publisherCredential, blobID, int64(len(blobBytes)), 1_500,
	)
	if err != nil || published.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("blob publish=%+v err=%v", published, err)
	}
	retry, err := store.CommitBlobPublish(
		ctx, publisherCredential, blobID, int64(len(blobBytes)), 1_500,
	)
	if err != nil || retry.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("blob retry=%+v err=%v", retry, err)
	}
	secondBytes := []byte{5}
	if err := store.PrepareBlobPublish(
		ctx,
		publisherCredential,
		relay.BlobID(secondBytes),
		int64(len(secondBytes)),
		1_500,
	); !relay.ErrorHasCode(err, relay.CodeDomainFull) {
		t.Fatalf("blob over quota err=%v", err)
	}

	fetchCredential := relay.Credential{
		TenantID: tenantID,
		DomainID: domainID,
		MemberID: uuid.New(),
		Token:    token(32),
	}
	fetchDigest, err := relay.AuthorizationDigest(fetchCredential)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.CreateMember(ctx, admin, relay.MemberRegistration{
		Version:               relay.SchemaVersion,
		TenantID:              tenantID,
		DomainID:              domainID,
		MemberID:              fetchCredential.MemberID,
		AuthorizationDigest:   fetchDigest,
		Capabilities:          []relay.Capability{relay.CapabilityFetchBlob},
		CreatedAtMilliseconds: 1_000,
	}, 1_500)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := store.GetBlobMetadata(ctx, fetchCredential, blobID, 1_500)
	if err != nil || metadata.ByteCount != int64(len(blobBytes)) ||
		metadata.PublisherMemberID != publisherCredential.MemberID {
		t.Fatalf("blob metadata=%+v err=%v", metadata, err)
	}
	if _, err := store.RevokeMember(
		ctx, admin, fetchCredential.MemberID, 1_600,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetBlobMetadata(
		ctx, fetchCredential, blobID, 1_600,
	); !relay.ErrorHasCode(err, relay.CodeMemberRevoked) {
		t.Fatalf("blob fetch after revocation err=%v", err)
	}
	if _, err := store.RevokeMember(
		ctx, admin, publisherCredential.MemberID, 1_700,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitBlobPublish(
		ctx,
		publisherCredential,
		blobID,
		int64(len(blobBytes)),
		1_700,
	); !relay.ErrorHasCode(err, relay.CodeMemberRevoked) {
		t.Fatalf("blob commit after publisher revocation err=%v", err)
	}
}

func TestMemoryStoreClaimsAdmissionOnceAndRevokesBeforeClaim(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	domainID := uuid.New()
	admin := relay.AdministrationCredential{
		TenantID: tenantID,
		DomainID: domainID,
		Token:    token(128),
	}
	adminDigest, err := relay.AdministrationDigest(admin)
	if err != nil {
		t.Fatal(err)
	}
	initialCredential := relay.Credential{
		TenantID: tenantID,
		DomainID: domainID,
		MemberID: uuid.New(),
		Token:    token(96),
	}
	initialDigest, err := relay.AuthorizationDigest(initialCredential)
	if err != nil {
		t.Fatal(err)
	}
	store := relay.NewMemoryStore()
	if _, err := store.CreateDomain(ctx, relay.DomainRegistration{
		Version:                relay.SchemaVersion,
		TenantID:               tenantID,
		DomainID:               domainID,
		AdministrationDigest:   adminDigest,
		CreatedAtMilliseconds:  1_000,
		MaximumMessageCount:    10,
		MaximumBlobCount:       10,
		MaximumStoredByteCount: 1_024,
	}, relay.MemberRegistration{
		Version:               relay.SchemaVersion,
		TenantID:              tenantID,
		DomainID:              domainID,
		MemberID:              initialCredential.MemberID,
		AuthorizationDigest:   initialDigest,
		Capabilities:          []relay.Capability{relay.CapabilityFetchMessage},
		CreatedAtMilliseconds: 1_000,
	}); err != nil {
		t.Fatal(err)
	}

	admissionCredential := relay.AdmissionCredential{
		TenantID:    tenantID,
		DomainID:    domainID,
		AdmissionID: uuid.New(),
		Token:       token(64),
	}
	admissionDigest, err := relay.AdmissionAuthorizationDigest(admissionCredential)
	if err != nil {
		t.Fatal(err)
	}
	admission := relay.MemberAdmission{
		Version:               relay.SchemaVersion,
		TenantID:              tenantID,
		DomainID:              domainID,
		AdmissionID:           admissionCredential.AdmissionID,
		AuthorizationDigest:   admissionDigest,
		Capabilities:          []relay.Capability{relay.CapabilityFetchMessage},
		CreatedAtMilliseconds: 1_500,
		ExpiresAtMilliseconds: 2_500,
	}
	accepted, err := store.CreateAdmission(ctx, admin, admission, 1_500)
	if err != nil || accepted.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("create admission result=%+v err=%v", accepted, err)
	}
	retriedAdmission := admission
	retriedAdmission.CreatedAtMilliseconds = 1_600
	duplicate, err := store.CreateAdmission(ctx, admin, retriedAdmission, 1_600)
	if err != nil || duplicate.Acceptance != relay.AcceptanceDuplicate ||
		duplicate.Admission.CreatedAtMilliseconds != 1_500 {
		t.Fatalf("duplicate admission result=%+v err=%v", duplicate, err)
	}

	memberCredential := relay.Credential{
		TenantID: tenantID,
		DomainID: domainID,
		MemberID: uuid.New(),
		Token:    token(32),
	}
	memberDigest, err := relay.AuthorizationDigest(memberCredential)
	if err != nil {
		t.Fatal(err)
	}
	claim := relay.MemberAdmissionClaim{
		MemberID:            memberCredential.MemberID,
		AuthorizationDigest: memberDigest,
	}
	wrongAdmissionCredential := admissionCredential
	wrongAdmissionCredential.Token = token(65)
	if _, err := store.ClaimAdmission(
		ctx, wrongAdmissionCredential, claim, 1_700,
	); !relay.ErrorHasCode(err, relay.CodeUnauthorized) {
		t.Fatalf("wrong admission token err=%v", err)
	}
	claimed, err := store.ClaimAdmission(
		ctx, admissionCredential, claim, 1_700,
	)
	if err != nil || claimed.Acceptance != relay.AcceptanceAccepted ||
		claimed.Member.MemberID != memberCredential.MemberID ||
		len(claimed.Member.Capabilities) != 1 ||
		claimed.Member.Capabilities[0] != relay.CapabilityFetchMessage {
		t.Fatalf("claim=%+v err=%v", claimed, err)
	}
	creationRetryAfterClaim := admission
	creationRetryAfterClaim.CreatedAtMilliseconds = 1_800
	current, err := store.CreateAdmission(
		ctx, admin, creationRetryAfterClaim, 1_800,
	)
	if err != nil || current.Acceptance != relay.AcceptanceDuplicate ||
		current.Admission.ClaimedMemberID == nil ||
		*current.Admission.ClaimedMemberID != memberCredential.MemberID {
		t.Fatalf("creation retry after claim=%+v err=%v", current, err)
	}
	if _, err := store.Fetch(
		ctx, memberCredential, 0, 10, 1_800,
	); err != nil {
		t.Fatalf("claimed member was not authorized: %v", err)
	}
	// Exact retry remains recoverable after the one-time admission expires.
	retry, err := store.ClaimAdmission(
		ctx, admissionCredential, claim, 3_000,
	)
	if err != nil || retry.Acceptance != relay.AcceptanceDuplicate ||
		!reflect.DeepEqual(retry.Member, claimed.Member) {
		t.Fatalf("claim retry=%+v err=%v", retry, err)
	}
	otherClaim := claim
	otherClaim.MemberID = uuid.New()
	if _, err := store.ClaimAdmission(
		ctx, admissionCredential, otherClaim, 3_000,
	); !relay.ErrorHasCode(err, relay.CodeAdmissionClaimed) {
		t.Fatalf("second claimant err=%v", err)
	}

	revokedCredential := relay.AdmissionCredential{
		TenantID:    tenantID,
		DomainID:    domainID,
		AdmissionID: uuid.New(),
		Token:       token(160),
	}
	revokedDigest, err := relay.AdmissionAuthorizationDigest(revokedCredential)
	if err != nil {
		t.Fatal(err)
	}
	revokedAdmission := admission
	revokedAdmission.AdmissionID = revokedCredential.AdmissionID
	revokedAdmission.AuthorizationDigest = revokedDigest
	revokedAdmission.CreatedAtMilliseconds = 3_000
	revokedAdmission.ExpiresAtMilliseconds = 4_000
	if _, err := store.CreateAdmission(
		ctx, admin, revokedAdmission, 3_000,
	); err != nil {
		t.Fatal(err)
	}
	if acceptance, err := store.RevokeAdmission(
		ctx, admin, revokedCredential.AdmissionID, 3_100,
	); err != nil || acceptance != relay.AcceptanceAccepted {
		t.Fatalf("revoke acceptance=%q err=%v", acceptance, err)
	}
	if acceptance, err := store.RevokeAdmission(
		ctx, admin, revokedCredential.AdmissionID, 3_200,
	); err != nil || acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("revoke retry acceptance=%q err=%v", acceptance, err)
	}
	if _, err := store.ClaimAdmission(
		ctx, revokedCredential, relay.MemberAdmissionClaim{
			MemberID:            uuid.New(),
			AuthorizationDigest: memberDigest,
		}, 3_300,
	); !relay.ErrorHasCode(err, relay.CodeAdmissionRevoked) {
		t.Fatalf("claim revoked admission err=%v", err)
	}
}

func token(seed byte) string {
	bytes := make([]byte, 32)
	for index := range bytes {
		bytes[index] = seed + byte(index)
	}
	return base64.RawURLEncoding.EncodeToString(bytes)
}
