package boxcontrol

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"sync"
	"testing"

	"github.com/google/uuid"
)

type participantFixture struct {
	anchor      BoxParticipantAnchor
	device      BoxParticipantDevice
	root        BoxSignedPrincipalRecord
	grant       BoxSignedPrincipalRecord
	proof       BoxSignedParticipantProof
	challengeID uuid.UUID
	now         int64
	rootKey     *ecdsa.PrivateKey
}

type fixtureChallengeStore struct {
	mu            sync.Mutex
	boxID         uuid.UUID
	participantID uuid.UUID
	deviceID      uuid.UUID
	challengeID   uuid.UUID
	enrollment    BoxParticipantEnrollment
	consumed      bool
}

func (store *fixtureChallengeStore) PinnedParticipant(_ context.Context,
	boxID, participantID, deviceID uuid.UUID) (BoxParticipantEnrollment, error) {
	if boxID != store.boxID || participantID != store.participantID || deviceID != store.deviceID {
		return BoxParticipantEnrollment{}, ErrParticipantAuthority
	}
	return cloneParticipantEnrollment(store.enrollment), nil
}

func (store *fixtureChallengeStore) ConsumeParticipantChallenge(_ context.Context, boxID,
	participantID, deviceID, challengeID uuid.UUID, _ int64) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.consumed || boxID != store.boxID || participantID != store.participantID ||
		deviceID != store.deviceID || challengeID != store.challengeID {
		return false, nil
	}
	store.consumed = true
	return true, nil
}

func (fixture participantFixture) verifier(t *testing.T) *BoxParticipantProofVerifier {
	t.Helper()
	verifier, err := NewBoxParticipantProofVerifier(&fixtureChallengeStore{
		boxID: fixture.anchor.BoxID, participantID: fixture.anchor.ParticipantID,
		deviceID: fixture.device.DeviceID, challengeID: fixture.challengeID,
		enrollment: BoxParticipantEnrollment{
			Anchor: fixture.anchor, Device: fixture.device,
			RootRecord: fixture.root, GrantRecord: fixture.grant,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

func newParticipantFixture(t *testing.T) participantFixture {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootPublic := elliptic.Marshal(elliptic.P256(), rootKey.PublicKey.X, rootKey.PublicKey.Y)
	devicePublic := elliptic.Marshal(elliptic.P256(), deviceKey.PublicKey.X, deviceKey.PublicKey.Y)
	rootFingerprint := participantFingerprint(rootPublic)
	deviceFingerprint := participantFingerprint(devicePublic)
	boxID, participantID, principalID := uuid.New(), uuid.New(), uuid.New()
	deviceID, grantID, challengeID := uuid.New(), uuid.New(), uuid.New()
	now := int64(1_735_689_601_500)
	root := signParticipantRecord(t, boxPrincipalRoot{
		Version: 1, PrincipalID: principalID, PrincipalKind: "human",
		RootPublicSigningKeyX963:  base64.RawURLEncoding.EncodeToString(rootPublic),
		RootSigningKeyFingerprint: rootFingerprint, RootKeyGeneration: 1,
		CreatedAtMilliseconds: now - 1_500,
	}, rootKey, rootFingerprint, principalRootDomain)
	grant := signParticipantRecord(t, boxPrincipalDeviceGrant{
		Version: 1, ID: grantID, PrincipalID: principalID, DeviceID: deviceID,
		DeviceGeneration: 1, DeviceName: "Test Mac",
		SigningPublicKeyX963:       base64.RawURLEncoding.EncodeToString(devicePublic),
		SigningKeyFingerprint:      deviceFingerprint,
		KeyAgreementPublicKeyX963:  base64.RawURLEncoding.EncodeToString(devicePublic),
		KeyAgreementKeyFingerprint: deviceFingerprint,
		Capabilities:               []string{boxParticipantCapability},
		IssuedAtMilliseconds:       now - 1_000, NotBeforeMilliseconds: now - 1_000,
		ExpiresAtMilliseconds: now + 60_000,
	}, rootKey, rootFingerprint, principalDeviceDomain)
	proofUnsorted, err := json.Marshal(BoxParticipantProofPayload{
		Version: 1, BoxID: boxID, ParticipantID: participantID,
		BoxScopedPrincipalID: principalID, DeviceID: deviceID, GrantID: grantID,
		DeviceGeneration: 1, ChallengeID: challengeID,
		IssuedAtMilliseconds: now - 100, ExpiresAtMilliseconds: now + 30_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	var proofObject map[string]json.RawMessage
	if err := json.Unmarshal(proofUnsorted, &proofObject); err != nil {
		t.Fatal(err)
	}
	proofPayload, err := json.Marshal(proofObject)
	if err != nil {
		t.Fatal(err)
	}
	return participantFixture{
		anchor: BoxParticipantAnchor{BoxID: boxID, ParticipantID: participantID,
			BoxScopedPrincipalID: principalID, RootKeyFingerprint: rootFingerprint,
			ApprovedAtMilliseconds: now - 500},
		device: BoxParticipantDevice{ParticipantID: participantID, DeviceID: deviceID,
			GrantID: grantID, DeviceGeneration: 1, SigningKeyFingerprint: deviceFingerprint},
		root: root, grant: grant,
		proof: BoxSignedParticipantProof{Payload: proofPayload,
			Signature: signParticipantBytes(t, deviceKey, participantProofDomain, proofPayload)},
		challengeID: challengeID, now: now, rootKey: rootKey,
	}
}

func participantFingerprint(public []byte) string {
	digest := sha256.Sum256(public)
	return hex.EncodeToString(digest[:])
}

func signParticipantRecord(t *testing.T, value any, key *ecdsa.PrivateKey, fingerprint, domain string) BoxSignedPrincipalRecord {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	result := BoxSignedPrincipalRecord{Payload: payload}
	result.Signature.Algorithm = "ES256"
	result.Signature.SigningKeyFingerprint = fingerprint
	result.Signature.Signature = signParticipantBytes(t, key, domain, payload)
	return result
}

func signParticipantBytes(t *testing.T, key *ecdsa.PrivateKey, domain string, payload []byte) string {
	t.Helper()
	digest := sha256.Sum256(append([]byte(domain), payload...))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	return base64.RawURLEncoding.EncodeToString(raw)
}

func (fixture participantFixture) authorize(verifier *BoxParticipantProofVerifier, revocations []BoxSignedPrincipalRecord) error {
	return verifier.Authorize(context.Background(), fixture.anchor, fixture.device, fixture.root, fixture.grant,
		revocations, fixture.proof, fixture.challengeID, fixture.now)
}

func TestBoxParticipantProofRequiresPinnedPrincipalAndExactEnrolledDevice(t *testing.T) {
	fixture := newParticipantFixture(t)
	verifier := fixture.verifier(t)
	if err := fixture.authorize(verifier, nil); err != nil {
		t.Fatal(err)
	}
	if err := fixture.authorize(verifier, nil); !errors.Is(err, ErrParticipantReplay) {
		t.Fatalf("exact replay: got %v", err)
	}
	tests := []struct {
		name   string
		change func(*participantFixture)
	}{
		{"wrong Box", func(f *participantFixture) { f.anchor.BoxID = uuid.New() }},
		{"wrong participant", func(f *participantFixture) { f.anchor.ParticipantID = uuid.New() }},
		{"wrong scoped Principal", func(f *participantFixture) { f.anchor.BoxScopedPrincipalID = uuid.New() }},
		{"unapproved root", func(f *participantFixture) { f.anchor.RootKeyFingerprint = "" }},
		{"wrong device", func(f *participantFixture) { f.device.DeviceID = uuid.New() }},
		{"wrong grant", func(f *participantFixture) { f.device.GrantID = uuid.New() }},
		{"unsupported rotated grant", func(f *participantFixture) { f.device.DeviceGeneration = 2 }},
		{"revoked enrollment", func(f *participantFixture) { f.device.RevokedThroughGeneration = 1 }},
		{"revoked participant", func(f *participantFixture) { f.anchor.RevokedAtMilliseconds = f.now - 1 }},
		{"stale proof", func(f *participantFixture) { f.now += 60_000 }},
		{"wrong challenge", func(f *participantFixture) { f.challengeID = uuid.New() }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := fixture
			test.change(&changed)
			if err := changed.authorize(changed.verifier(t), nil); !errors.Is(err, ErrParticipantAuthority) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestBoxParticipantVerifierRejectsUnpinnedApprovalStateBeforeChallengeUse(t *testing.T) {
	fixture := newParticipantFixture(t)
	verifier := fixture.verifier(t)
	substituted := fixture
	substituted.anchor.ApprovedAtMilliseconds--
	if err := substituted.authorize(verifier, nil); !errors.Is(err, ErrParticipantAuthority) {
		t.Fatalf("caller-supplied approval state replaced the Box pin: %v", err)
	}
	if err := fixture.authorize(verifier, nil); err != nil {
		t.Fatalf("valid pinned proof was consumed by substitution attempt: %v", err)
	}
}

func TestIndependentBoxesRejectCrossBoxIdentityAndProof(t *testing.T) {
	first := newParticipantFixture(t)
	second := newParticipantFixture(t)
	if first.anchor.BoxScopedPrincipalID == second.anchor.BoxScopedPrincipalID ||
		first.anchor.RootKeyFingerprint == second.anchor.RootKeyFingerprint {
		t.Fatal("independent Box fixtures reused scoped identity or root")
	}
	if err := first.authorize(first.verifier(t), nil); err != nil {
		t.Fatal(err)
	}
	first.anchor = second.anchor
	if err := first.authorize(first.verifier(t), nil); !errors.Is(err, ErrParticipantAuthority) {
		t.Fatalf("first Box proof presented as second Box participant: %v", err)
	}
	encoded, err := json.Marshal(second.anchor)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(`"principalID"`)) ||
		!bytes.Contains(encoded, []byte(`"boxScopedPrincipalID"`)) {
		t.Fatalf("Box anchor must expose only its scoped identity: %s", encoded)
	}
}

func TestBoxParticipantRejectsMissingCapabilityAndSignedRevocation(t *testing.T) {
	fixture := newParticipantFixture(t)
	var grant boxPrincipalDeviceGrant
	if err := json.Unmarshal(fixture.grant.Payload, &grant); err != nil {
		t.Fatal(err)
	}
	grant.Capabilities = []string{"facets.replica.send"}
	fixture.grant = signParticipantRecord(t, grant, fixture.rootKey,
		fixture.anchor.RootKeyFingerprint, principalDeviceDomain)
	if err := fixture.authorize(fixture.verifier(t), nil); !errors.Is(err, ErrParticipantAuthority) {
		t.Fatalf("missing capability: got %v", err)
	}
	fixture = newParticipantFixture(t)
	revocation := signParticipantRecord(t, boxPrincipalDeviceRevocation{
		Version: 1, ID: uuid.New(), PrincipalID: fixture.anchor.BoxScopedPrincipalID,
		DeviceID: fixture.device.DeviceID, RevokedThroughGeneration: 1,
		IssuedAtMilliseconds: fixture.now - 1, Reason: "userRequested",
	}, fixture.rootKey, fixture.anchor.RootKeyFingerprint, principalRevocationDomain)
	if err := fixture.authorize(fixture.verifier(t), []BoxSignedPrincipalRecord{revocation}); !errors.Is(err, ErrParticipantAuthority) {
		t.Fatalf("signed revocation: got %v", err)
	}
}

func TestBoxDiscoveryGrantIsNotParticipantAuthority(t *testing.T) {
	fixture := newParticipantFixture(t)
	fixture.anchor.ApprovedAtMilliseconds = 0
	if err := fixture.authorize(fixture.verifier(t), nil); !errors.Is(err, ErrParticipantAuthority) {
		t.Fatalf("missing owner-approved anchor: got %v", err)
	}
	// A Box connection token intentionally is not an input to this verifier.
}

func TestBoxPresentationIsNotAuthorityAndCannotExposeSpacePersonaIdentity(t *testing.T) {
	fixture := newParticipantFixture(t)
	presentation := BoxParticipantPresentation{
		ParticipantID: fixture.anchor.ParticipantID,
		DisplayName:   "Sue", Revision: 1,
	}
	if err := presentation.Validate(); err != nil {
		t.Fatal(err)
	}
	presentation.DisplayName = "Sue\nAdmin"
	if err := presentation.Validate(); !errors.Is(err, ErrParticipantAuthority) {
		t.Fatalf("invalid presentation: %v", err)
	}
	// Presentation is absent from the signed proof and verifier arguments.
}

func TestParticipantSignatureUsesP256RawRS(t *testing.T) {
	fixture := newParticipantFixture(t)
	keyBytes, err := participantBase64URL(fixture.proof.Signature)
	if err != nil || len(keyBytes) != 64 {
		t.Fatalf("signature encoding: %v", err)
	}
	if new(big.Int).SetBytes(keyBytes[:32]).Sign() <= 0 || new(big.Int).SetBytes(keyBytes[32:]).Sign() <= 0 {
		t.Fatal("empty signature component")
	}
}

func TestSwiftPrincipalTrustFixtureSignaturesVerifyInBox(t *testing.T) {
	bytes, err := os.ReadFile("../testfixture/principal-trust-portable-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Root struct {
			SignedRecord BoxSignedPrincipalRecord `json:"signedRecord"`
		} `json:"root"`
		DeviceGrant struct {
			SignedRecord BoxSignedPrincipalRecord `json:"signedRecord"`
		} `json:"deviceGrant"`
		DeviceRevocation struct {
			SignedRecord BoxSignedPrincipalRecord `json:"signedRecord"`
		} `json:"deviceRevocation"`
	}
	if err := json.Unmarshal(bytes, &fixture); err != nil {
		t.Fatal(err)
	}
	var root boxPrincipalRoot
	if err := strictParticipantJSON(fixture.Root.SignedRecord.Payload, &root); err != nil {
		t.Fatal(err)
	}
	key, err := participantPublicKey(root.RootPublicSigningKeyX963, root.RootSigningKeyFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		name   string
		record BoxSignedPrincipalRecord
		domain string
	}{
		{"root", fixture.Root.SignedRecord, principalRootDomain},
		{"grant", fixture.DeviceGrant.SignedRecord, principalDeviceDomain},
		{"revocation", fixture.DeviceRevocation.SignedRecord, principalRevocationDomain},
	} {
		if err := verifyPrincipalRecord(check.record, key, root.RootSigningKeyFingerprint, check.domain); err != nil {
			t.Fatalf("Swift %s signature: %v", check.name, err)
		}
	}
	// The older portable grant was not issued for Box participation. Valid
	// cross-language signatures alone must not expand its capabilities.
	var grant boxPrincipalDeviceGrant
	if err := strictParticipantJSON(fixture.DeviceGrant.SignedRecord.Payload, &grant); err != nil {
		t.Fatal(err)
	}
	if hasParticipantCapability(grant.Capabilities) {
		t.Fatal("fixture unexpectedly grants Box participation")
	}
}

func TestBoxParticipantPortableSignedFixture(t *testing.T) {
	bytes, err := os.ReadFile("../testfixture/box-participant-authority-portable-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Format          string                    `json:"format"`
		Anchor          BoxParticipantAnchor      `json:"anchor"`
		Device          BoxParticipantDevice      `json:"device"`
		Root            BoxSignedPrincipalRecord  `json:"root"`
		Grant           BoxSignedPrincipalRecord  `json:"grant"`
		Proof           BoxSignedParticipantProof `json:"proof"`
		ChallengeID     uuid.UUID                 `json:"challengeID"`
		NowMilliseconds int64                     `json:"nowMilliseconds"`
	}
	if err := json.Unmarshal(bytes, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Format != "facets.box-participant-authority-fixture.v1" {
		t.Fatalf("wrong format: %q", fixture.Format)
	}
	encodedAnchor, err := json.Marshal(fixture.Anchor)
	if err != nil {
		t.Fatal(err)
	}
	var anchorFields map[string]json.RawMessage
	if err := json.Unmarshal(encodedAnchor, &anchorFields); err != nil {
		t.Fatal(err)
	}
	if _, present := anchorFields["boxID"]; !present {
		t.Fatal("Go Box anchor does not encode the portable field names")
	}
	verifier, err := NewBoxParticipantProofVerifier(&fixtureChallengeStore{
		boxID: fixture.Anchor.BoxID, participantID: fixture.Anchor.ParticipantID,
		deviceID: fixture.Device.DeviceID, challengeID: fixture.ChallengeID,
		enrollment: BoxParticipantEnrollment{
			Anchor: fixture.Anchor, Device: fixture.Device,
			RootRecord: fixture.Root, GrantRecord: fixture.Grant,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Authorize(context.Background(), fixture.Anchor, fixture.Device,
		fixture.Root, fixture.Grant, nil, fixture.Proof, fixture.ChallengeID,
		fixture.NowMilliseconds); err != nil {
		t.Fatal(err)
	}
	if err := verifier.Authorize(context.Background(), fixture.Anchor, fixture.Device,
		fixture.Root, fixture.Grant, nil, fixture.Proof, fixture.ChallengeID,
		fixture.NowMilliseconds); !errors.Is(err, ErrParticipantReplay) {
		t.Fatalf("portable replay: %v", err)
	}
}

func TestBoxParticipantChallengeCanBeConsumedOnlyOnceConcurrently(t *testing.T) {
	fixture := newParticipantFixture(t)
	verifier := fixture.verifier(t)
	results := make(chan error, 16)
	var group sync.WaitGroup
	for i := 0; i < cap(results); i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			results <- fixture.authorize(verifier, nil)
		}()
	}
	group.Wait()
	close(results)
	successes, replays := 0, 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrParticipantReplay):
			replays++
		default:
			t.Fatalf("unexpected result: %v", err)
		}
	}
	if successes != 1 || replays != cap(results)-1 {
		t.Fatalf("success=%d replay=%d", successes, replays)
	}
}

func TestBoxParticipantProofRejectsAmbiguousJSON(t *testing.T) {
	fixture := newParticipantFixture(t)
	payload := append([]byte{}, fixture.proof.Payload[:len(fixture.proof.Payload)-1]...)
	payload = append(payload, []byte(`,"version":1}`)...)
	if canonicalParticipantProof(payload) {
		t.Fatal("duplicate proof field was accepted as canonical")
	}
}
