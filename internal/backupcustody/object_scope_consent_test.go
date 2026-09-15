package backupcustody

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"math"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func fixtureObjectConsent(s credentialAuthoritySequence) ObjectScopeConsent {
	return ObjectScopeConsent{Version: 1, AccountID: s.accountID, TargetID: s.targetID, BackupSetID: s.backupSetID,
		BindingID: credentialAuthorityUUID(60), ContentEpoch: 1, ContentScopeID: credentialAuthorityUUID(61),
		LedgerID: credentialAuthorityUUID(62), LinkID: credentialAuthorityUUID(63), PoolID: credentialAuthorityUUID(64),
		LinkIntentDigest: strings.Repeat("a", 64)}
}

func TestObjectScopeConsentLifecycleAndRotation(t *testing.T) {
	s := makeCredentialAuthoritySequence(t)
	state, _ := NewCredentialAuthorityState(s.initialAnchor)
	if err := state.Apply(s.commands[0]); err != nil {
		t.Fatal(err)
	}
	consent := fixtureObjectConsent(s)
	ref, err := consent.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	command := s.signCommand(t, 2, state.Head.ReferenceDigest, s.first,
		ControlEffect{Kind: ConsentObjectScope, ObjectScopeConsent: &consent}, 80, nil)
	commandRef, _ := command.ReferenceDigest()
	// Swift verifies this retained signed fixture. Fresh CryptoKit signatures
	// are randomized and therefore need not have an identical record digest.
	if ref != "75991ed0cdd8320d1b611d054447daab935005c2d365842534044cb88c787960" ||
		commandRef != "834a09f30c231fd83972e1205301b0818c9306ca09eb083983ceb268d623184e" {
		t.Fatal("portable consent/command commitment changed")
	}
	if state.Apply(command) != nil || state.Apply(command) != nil || len(state.ObjectScopeConsents) != 1 {
		t.Fatal("consent or exact tail replay failed")
	}
	accepted := state.ObjectScopeConsents[ref]
	if accepted.Consent != consent || accepted.Revoked || accepted.ReferenceDigest != ref {
		t.Fatal("wrong projection")
	}
	rotation := s.signCommand(t, 3, state.Head.ReferenceDigest, s.first,
		ControlEffect{Kind: RotateControlKey, ControlAnchor: &s.secondAnchor}, 81, &s.second)
	if state.Apply(rotation) != nil || state.ObjectScopeConsents[ref].Revoked {
		t.Fatal("rotation changed consent")
	}
	oldKey := s.signCommand(t, 4, state.Head.ReferenceDigest, s.first,
		ControlEffect{Kind: RevokeObjectScopeConsent, PriorObjectScopeConsentDigest: &ref}, 82, nil)
	if state.Apply(oldKey) == nil {
		t.Fatal("old control key revoked consent")
	}
	revoke := s.signCommand(t, 4, state.Head.ReferenceDigest, s.second,
		ControlEffect{Kind: RevokeObjectScopeConsent, PriorObjectScopeConsentDigest: &ref}, 83, nil)
	if state.Apply(revoke) != nil || state.Apply(revoke) != nil || !state.ObjectScopeConsents[ref].Revoked {
		t.Fatal("revocation or exact tail replay failed")
	}
	if state.Apply(command) == nil {
		t.Fatal("historical reducer replay resurrected consent")
	}
	reopened, _ := NewCredentialAuthorityState(s.initialAnchor)
	if reopened.ApplyAll(state.Records) != nil || !reflect.DeepEqual(reopened, state) {
		t.Fatal("replay projection differs")
	}
	if _, ok := state.ActiveGrant(s.grants[0].Credential.CredentialID); !ok {
		t.Fatal("consent revoked unrelated target credential")
	}
	// Projections hold values, not the command builder's mutable pointer.
	consent.ContentEpoch++
	if state.ObjectScopeConsents[ref] != (AcceptedObjectScopeConsent{Consent: fixtureObjectConsent(s), ReferenceDigest: ref, Revoked: true}) {
		t.Fatal("caller modified retained projection")
	}
}

type objectConsentPortableFixture struct {
	Format                  string   `json:"format"`
	InitialAnchorCanonical  []byte   `json:"initialAnchorCanonical"`
	CommandsCanonical       [][]byte `json:"commandsCanonical"`
	ConsentReferenceDigest  string   `json:"consentReferenceDigest"`
	CommandReferenceDigests []string `json:"commandReferenceDigests"`
}

func TestObjectScopeConsentPortableFixture(t *testing.T) {
	s := makeCredentialAuthoritySequence(t)
	consent := fixtureObjectConsent(s)
	ref, _ := consent.ReferenceDigest()
	prior, _ := s.commands[0].ReferenceDigest()
	command := s.signCommand(t, 2, prior, s.first, ControlEffect{Kind: ConsentObjectScope, ObjectScopeConsent: &consent}, 80, nil)
	prior, _ = command.ReferenceDigest()
	revoke := s.signCommand(t, 3, prior, s.first, ControlEffect{Kind: RevokeObjectScopeConsent, PriorObjectScopeConsentDigest: &ref}, 81, nil)
	anchor, _ := s.initialAnchor.CanonicalJSON()
	expected := objectConsentPortableFixture{Format: "facets.backup-object-scope-consent.v1", InitialAnchorCanonical: anchor, ConsentReferenceDigest: ref}
	for _, r := range []SignedControlCommand{s.commands[0], command, revoke} {
		encoded, _ := r.CanonicalJSON()
		reference, _ := r.ReferenceDigest()
		expected.CommandsCanonical = append(expected.CommandsCanonical, encoded)
		expected.CommandReferenceDigests = append(expected.CommandReferenceDigests, reference)
	}
	stored, err := os.ReadFile("testdata/backup-object-scope-consent-v1.json")
	var actual objectConsentPortableFixture
	if err != nil || json.Unmarshal(stored, &actual) != nil || !reflect.DeepEqual(expected, actual) {
		t.Fatal("portable fixture changed or unavailable")
	}
}

func TestObjectScopeConsentCryptoKitFixture(t *testing.T) {
	stored, err := os.ReadFile("testdata/backup-object-scope-consent-cryptokit-v1.json")
	var fixture objectConsentPortableFixture
	if err != nil || json.Unmarshal(stored, &fixture) != nil || fixture.Format != "facets.backup-object-scope-consent.v1" ||
		len(fixture.CommandsCanonical) != 3 || len(fixture.CommandReferenceDigests) != 3 {
		t.Fatal("invalid CryptoKit fixture")
	}
	anchor, err := DecodeControlPossessionAnchor(fixture.InitialAnchorCanonical)
	if err != nil {
		t.Fatal(err)
	}
	state, err := NewCredentialAuthorityState(anchor)
	if err != nil {
		t.Fatal(err)
	}
	for i, encoded := range fixture.CommandsCanonical {
		command, err := DecodeSignedControlCommand(encoded)
		reference, refErr := command.ReferenceDigest()
		if err != nil || refErr != nil || reference != fixture.CommandReferenceDigests[i] || state.Apply(command) != nil {
			t.Fatal("CryptoKit signed record rejected")
		}
	}
	consent, ok := state.ObjectScopeConsents[fixture.ConsentReferenceDigest]
	if !ok || !consent.Revoked || state.Head.Sequence != 3 {
		t.Fatal("CryptoKit replay diverged")
	}
}

func TestObjectScopeConsentConflictsAreAtomic(t *testing.T) {
	s := makeCredentialAuthoritySequence(t)
	base, _ := NewCredentialAuthorityState(s.initialAnchor)
	_ = base.Apply(s.commands[0])
	consent := fixtureObjectConsent(s)
	ref, _ := consent.ReferenceDigest()
	_ = base.Apply(s.signCommand(t, 2, base.Head.ReferenceDigest, s.first, ControlEffect{Kind: ConsentObjectScope, ObjectScopeConsent: &consent}, 80, nil))
	_ = base.Apply(s.signCommand(t, 3, base.Head.ReferenceDigest, s.first, ControlEffect{Kind: RevokeObjectScopeConsent, PriorObjectScopeConsentDigest: &ref}, 81, nil))
	for name, mutate := range map[string]func(*ObjectScopeConsent){
		"same revoked consent": func(c *ObjectScopeConsent) { *c = consent },
		"binding reuse":        func(c *ObjectScopeConsent) { c.BindingID = consent.BindingID },
		"link reuse":           func(c *ObjectScopeConsent) { c.LinkID = consent.LinkID },
		"intent reuse":         func(c *ObjectScopeConsent) { c.LinkIntentDigest = consent.LinkIntentDigest },
		"unknown target":       func(c *ObjectScopeConsent) { c.TargetID = uuid.New() },
		"different set":        func(c *ObjectScopeConsent) { c.BackupSetID = uuid.New() },
	} {
		t.Run(name, func(t *testing.T) {
			state, _ := NewCredentialAuthorityState(s.initialAnchor)
			_ = state.ApplyAll(base.Records)
			candidate := consent
			candidate.BindingID, candidate.LinkID, candidate.LinkIntentDigest = uuid.New(), uuid.New(), strings.Repeat("b", 64)
			mutate(&candidate)
			command := s.signCommand(t, 4, state.Head.ReferenceDigest, s.first, ControlEffect{Kind: ConsentObjectScope, ObjectScopeConsent: &candidate}, 82, nil)
			if state.Apply(command) == nil || !reflect.DeepEqual(base, state) {
				t.Fatal("rejected mutation changed state or was accepted")
			}
		})
	}
	for _, prior := range []string{ref, strings.Repeat("c", 64)} {
		command := s.signCommand(t, 4, base.Head.ReferenceDigest, s.first, ControlEffect{Kind: RevokeObjectScopeConsent, PriorObjectScopeConsentDigest: &prior}, 83, nil)
		if base.Apply(command) == nil {
			t.Fatal("duplicate or unknown revocation accepted")
		}
	}
	next := consent
	next.BindingID, next.LinkID, next.LinkIntentDigest, next.ContentEpoch = uuid.New(), uuid.New(), strings.Repeat("b", 64), 2
	if base.Apply(s.signCommand(t, 4, base.Head.ReferenceDigest, s.first, ControlEffect{Kind: ConsentObjectScope, ObjectScopeConsent: &next}, 84, nil)) != nil {
		t.Fatal("fresh epoch consent rejected")
	}
}

func TestObjectScopeConsentWireRejectsInvalidOrMixedFields(t *testing.T) {
	s := makeCredentialAuthoritySequence(t)
	consent := fixtureObjectConsent(s)
	for _, field := range []string{"AccountID", "BackupSetID", "BindingID", "ContentScopeID", "LedgerID", "LinkID", "PoolID", "TargetID"} {
		t.Run(field, func(t *testing.T) {
			c := consent
			reflect.ValueOf(&c).Elem().FieldByName(field).Set(reflect.ValueOf(uuid.Nil))
			if c.Validate() == nil {
				t.Fatal("zero ID accepted")
			}
		})
	}
	for _, mutate := range []func(*ObjectScopeConsent){
		func(c *ObjectScopeConsent) { c.Version = 2 }, func(c *ObjectScopeConsent) { c.ContentEpoch = 0 },
		func(c *ObjectScopeConsent) { c.LinkIntentDigest = strings.Repeat("A", 64) },
		func(c *ObjectScopeConsent) { c.LinkIntentDigest = strings.Repeat("a", 63) },
	} {
		c := consent
		mutate(&c)
		if _, err := c.ReferenceDigest(); err == nil {
			t.Fatal("invalid consent was committed")
		}
	}
	validEffect := ControlEffect{Kind: ConsentObjectScope, ObjectScopeConsent: &consent}
	prior := strings.Repeat("b", 64)
	for _, extra := range []func(*ControlEffect){
		func(e *ControlEffect) { e.Grant = &s.grants[0] }, func(e *ControlEffect) { e.TargetID = &s.targetID },
		func(e *ControlEffect) { e.BackupSetID = &s.backupSetID }, func(e *ControlEffect) { e.ControlAnchor = &s.initialAnchor },
		func(e *ControlEffect) { e.PriorGrantReferenceDigest = &prior },
		func(e *ControlEffect) { e.PriorObjectScopeConsentDigest = &prior },
	} {
		e := validEffect
		extra(&e)
		if e.Validate() == nil {
			t.Fatal("mixed consent effect accepted")
		}
	}
	for _, kind := range []ControlEffectKind{CreateTargetWithInitialGrant, GrantCredential, SupersedeCredential, RevokeCredential, RotateControlKey, RevokeObjectScopeConsent, "unknown"} {
		e := validEffect
		e.Kind = kind
		if e.Validate() == nil {
			t.Fatal("wrong effect accepted consent")
		}
	}
	state, _ := NewCredentialAuthorityState(s.initialAnchor)
	_ = state.Apply(s.commands[0])
	record := s.signCommand(t, 2, state.Head.ReferenceDigest, s.first, validEffect, 80, nil)
	for name, mutate := range map[string]func([]byte) []byte{
		"unknown": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"objectScopeConsent":{`), []byte(`"objectScopeConsent":{"unknown":1,`), 1)
		},
		"duplicate": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"contentEpoch":1,`), []byte(`"contentEpoch":1,"contentEpoch":1,`), 1)
		},
		"null": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"contentEpoch":1,`), []byte(`"contentEpoch":null,`), 1)
		},
		"overflow": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"contentEpoch":1,`), []byte(`"contentEpoch":18446744073709551616,`), 1)
		},
		"fraction": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"contentEpoch":1,`), []byte(`"contentEpoch":1.0,`), 1)
		},
		"cross account": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"objectScopeConsent":{"accountID":"`+s.accountID.String()), []byte(`"objectScopeConsent":{"accountID":"`+uuid.NewString()), 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := record
			bad.Payload = mutate(bytes.Clone(record.Payload))
			if bytes.Equal(bad.Payload, record.Payload) {
				t.Fatal("fixture did not change")
			}
			// Sign malformed bytes to exercise canonical decoding, not just signature rejection.
			bad.AuthoritySignature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.first.privateKey,
				append([]byte(controlCommandAuthoritySignatureDomain), bad.Payload...)))
			if state.Apply(bad) == nil {
				t.Fatal("malformed signed consent accepted")
			}
		})
	}
	tampered := record
	tampered.Payload = bytes.Replace(record.Payload, []byte(`"contentEpoch":1,`), []byte(`"contentEpoch":2,`), 1)
	if state.Apply(tampered) == nil {
		t.Fatal("changed consent accepted with original signature")
	}
	consent.ContentEpoch = math.MaxUint64
	maxRecord := s.signCommand(t, 2, state.Head.ReferenceDigest, s.first, ControlEffect{Kind: ConsentObjectScope, ObjectScopeConsent: &consent}, 81, nil)
	if state.Apply(maxRecord) != nil {
		t.Fatal("exact UInt64 epoch rejected")
	}
	encoded, _ := json.Marshal(consent)
	for _, forbidden := range []string{"principalID", "spaceID", "password", "bearer", "key", "path", "media", "plaintext"} {
		if strings.Contains(strings.ToLower(string(encoded)), strings.ToLower(forbidden)) {
			t.Fatalf("private coordinate %s", forbidden)
		}
	}
}
