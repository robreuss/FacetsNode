package rendezvous_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/rendezvous"
	"github.com/robreuss/FacetsNode/internal/testfixture"
)

func TestSwiftFixtureAuthorizationDigests(t *testing.T) {
	t.Parallel()
	fixture := loadFixture(t)
	if fixture.Format != "facets.principal-pairing-rendezvous-fixture.v1" {
		t.Fatalf("unexpected fixture format %q", fixture.Format)
	}
	if fixture.Warning == "" {
		t.Fatal("fixture must retain its test-only warning")
	}
	sponsorDigest, err := rendezvous.AuthorizationDigest(
		fixture.SponsorAccess.RouterAuthorizationToken,
		fixture.Registration.RouteID,
		rendezvous.RoleSponsor,
	)
	if err != nil {
		t.Fatal(err)
	}
	if sponsorDigest != fixture.Registration.SponsorAuthorizationDigest {
		t.Fatalf("sponsor digest mismatch: %s", sponsorDigest)
	}
	candidateDigest, err := rendezvous.AuthorizationDigest(
		fixture.CandidateAccess.RouterAuthorizationToken,
		fixture.Registration.RouteID,
		rendezvous.RoleCandidate,
	)
	if err != nil {
		t.Fatal(err)
	}
	if candidateDigest != fixture.Registration.CandidateAuthorizationDigest {
		t.Fatalf("candidate digest mismatch: %s", candidateDigest)
	}
}

func TestSwiftFixtureEnvelopeReferenceDigest(t *testing.T) {
	t.Parallel()
	fixture := loadFixture(t)
	canonicalEnvelope, err := json.Marshal(map[string]any{
		"algorithm":             fixture.Envelope.Algorithm,
		"authenticationTag":     fixture.Envelope.AuthenticationTag,
		"ciphertext":            fixture.Envelope.Ciphertext,
		"createdAtMilliseconds": fixture.Envelope.CreatedAtMilliseconds,
		"expiresAtMilliseconds": fixture.Envelope.ExpiresAtMilliseconds,
		"messageID":             strings.ToUpper(fixture.Envelope.MessageID.String()),
		"nonce":                 fixture.Envelope.Nonce,
		"routeID":               strings.ToUpper(fixture.Envelope.RouteID.String()),
		"version":               fixture.Envelope.Version,
	})
	if err != nil {
		t.Fatal(err)
	}
	referenceDomain := []byte("Facets principal pairing rendezvous envelope reference v1\x00")
	digest := sha256.Sum256(append(referenceDomain, canonicalEnvelope...))
	if actual := hex.EncodeToString(digest[:]); actual != fixture.Expected.EnvelopeReferenceDigest {
		t.Fatalf("envelope reference digest=%s; want %s", actual, fixture.Expected.EnvelopeReferenceDigest)
	}
}

func TestMemoryStoreMatchesFrozenMailboxSemantics(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fixture := loadFixture(t)
	store := rendezvous.NewMemoryStore()
	sponsor := credential(
		fixture.Registration.RouteID,
		rendezvous.RoleSponsor,
		fixture.SponsorAccess.RouterAuthorizationToken,
	)
	candidate := credential(
		fixture.Registration.RouteID,
		rendezvous.RoleCandidate,
		fixture.CandidateAccess.RouterAuthorizationToken,
	)

	acceptance, err := store.CreateRoute(
		ctx, fixture.Registration, sponsor.Token, 3_000,
	)
	requireAcceptance(t, acceptance, err, rendezvous.AcceptanceAccepted)
	acceptance, err = store.CreateRoute(
		ctx, fixture.Registration, sponsor.Token, 3_000,
	)
	requireAcceptance(t, acceptance, err, rendezvous.AcceptanceDuplicate)
	acceptance, err = store.Publish(ctx, candidate, fixture.Envelope, 3_000)
	requireAcceptance(t, acceptance, err, rendezvous.AcceptanceAccepted)
	acceptance, err = store.Publish(ctx, candidate, fixture.Envelope, 3_000)
	requireAcceptance(t, acceptance, err, rendezvous.AcceptanceDuplicate)

	collision := fixture.Envelope
	collision.Ciphertext = "AQ"
	_, err = store.Publish(ctx, candidate, collision, 3_000)
	requireCode(t, err, rendezvous.CodeMessageCollision)

	candidateMessages, err := store.Fetch(ctx, candidate, 3_000)
	if err != nil || len(candidateMessages) != 0 {
		t.Fatalf("candidate fetched own message: count=%d err=%v", len(candidateMessages), err)
	}
	sponsorMessages, err := store.Fetch(ctx, sponsor, 3_000)
	if err != nil || len(sponsorMessages) != 1 || sponsorMessages[0] != fixture.Envelope {
		t.Fatalf("sponsor fetch mismatch: count=%d err=%v", len(sponsorMessages), err)
	}
	if err := store.Acknowledge(ctx, candidate, fixture.Envelope.MessageID, 3_000); err == nil {
		t.Fatal("publisher acknowledged its own message")
	} else {
		requireCode(t, err, rendezvous.CodeInvalidAcknowledgment)
	}
	if err := store.Acknowledge(ctx, sponsor, fixture.Envelope.MessageID, 3_000); err != nil {
		t.Fatal(err)
	}
	if err := store.Acknowledge(ctx, sponsor, fixture.Envelope.MessageID, 3_000); err != nil {
		t.Fatalf("acknowledgement retry was not idempotent: %v", err)
	}
	sponsorMessages, err = store.Fetch(ctx, sponsor, 3_000)
	if err != nil || len(sponsorMessages) != 0 {
		t.Fatalf("acknowledged message was fetched: count=%d err=%v", len(sponsorMessages), err)
	}

	requireCode(t, store.Close(ctx, candidate, 3_000), rendezvous.CodeUnauthorized)
	if err := store.Close(ctx, sponsor, 3_000); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(ctx, sponsor, 3_000); err != nil {
		t.Fatalf("close retry was not idempotent: %v", err)
	}
	acceptance, err = store.Publish(ctx, candidate, fixture.Envelope, 3_000)
	requireAcceptance(t, acceptance, err, rendezvous.AcceptanceDuplicate)
	newEnvelope := fixture.Envelope
	newEnvelope.MessageID = uuid.MustParse("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeef")
	_, err = store.Publish(ctx, candidate, newEnvelope, 3_000)
	requireCode(t, err, rendezvous.CodeRouteClosed)
	requireCode(t, store.Close(ctx, sponsor, 10_000), rendezvous.CodeRouteExpired)
}

func TestRegistrationAndEnvelopeLimitsFailClosed(t *testing.T) {
	t.Parallel()
	fixture := loadFixture(t)
	maximumLifetime := fixture.Registration
	maximumLifetime.CreatedAtMilliseconds = 2_000
	maximumLifetime.ExpiresAtMilliseconds =
		maximumLifetime.CreatedAtMilliseconds + rendezvous.MaximumRouteLifetimeMS
	if err := maximumLifetime.ValidateAt(2_000); err != nil {
		t.Fatalf("maximum route lifetime was rejected: %v", err)
	}
	futureCreated := fixture.Registration
	futureCreated.CreatedAtMilliseconds = 1_000_000
	futureCreated.ExpiresAtMilliseconds = 1_060_000
	earliestAccepted := futureCreated.CreatedAtMilliseconds -
		rendezvous.MaximumCreationClockSkewMS
	if err := futureCreated.ValidateAt(earliestAccepted); err != nil {
		t.Fatalf("bounded creation clock skew was rejected: %v", err)
	}
	if err := futureCreated.ValidateAt(earliestAccepted - 1); err == nil {
		t.Fatal("creation clock skew beyond the bound was accepted")
	} else {
		requireCode(t, err, rendezvous.CodeRouteExpired)
	}
	tooLong := fixture.Registration
	tooLong.CreatedAtMilliseconds = 2_000
	tooLong.ExpiresAtMilliseconds =
		tooLong.CreatedAtMilliseconds + rendezvous.MaximumRouteLifetimeMS + 1
	if err := tooLong.ValidateAt(2_000); err == nil {
		t.Fatal("overlong route registration was accepted")
	} else {
		requireCode(t, err, rendezvous.CodeInvalidRegistration)
	}
	badEnvelope := fixture.Envelope
	badEnvelope.Nonce = "not_base64url!"
	if err := badEnvelope.Validate(); err == nil {
		t.Fatal("invalid nonce was accepted")
	} else {
		requireCode(t, err, rendezvous.CodeInvalidEnvelope)
	}
	if _, err := rendezvous.AuthorizationDigest(
		fixture.SponsorAccess.RouterAuthorizationToken+"\n",
		fixture.Registration.RouteID,
		rendezvous.RoleSponsor,
	); err == nil {
		t.Fatal("non-canonical bearer token was accepted")
	}
}

func credential(routeID uuid.UUID, role rendezvous.Role, token string) rendezvous.Credential {
	return rendezvous.Credential{RouteID: routeID, Role: role, Token: token}
}

func loadFixture(t *testing.T) testfixture.Rendezvous {
	t.Helper()
	fixture, err := testfixture.LoadRendezvous()
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func requireAcceptance(
	t *testing.T,
	actual rendezvous.Acceptance,
	err error,
	expected rendezvous.Acceptance,
) {
	t.Helper()
	if err != nil || actual != expected {
		t.Fatalf("acceptance=%q err=%v; want %q", actual, err, expected)
	}
}

func requireCode(t *testing.T, err error, expected rendezvous.ErrorCode) {
	t.Helper()
	if !rendezvous.ErrorHasCode(err, expected) {
		t.Fatalf("error=%v; want code %s", err, expected)
	}
}
