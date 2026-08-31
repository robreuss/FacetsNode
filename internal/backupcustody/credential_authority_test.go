package backupcustody

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

type credentialAuthorityPortableFixture struct {
	AcceptedControlHeadReferenceDigest string    `json:"acceptedControlHeadReferenceDigest"`
	AuthorizationDigests               []string  `json:"authorizationDigests"`
	CommandReferenceDigests            []string  `json:"commandReferenceDigests"`
	CommandsCanonical                  [][]byte  `json:"commandsCanonical"`
	ExpectedActiveCredentialID         uuid.UUID `json:"expectedActiveCredentialID"`
	Format                             string    `json:"format"`
	GrantReferenceDigests              []string  `json:"grantReferenceDigests"`
	InitialAnchorCanonical             []byte    `json:"initialAnchorCanonical"`
	InitialAnchorReferenceDigest       string    `json:"initialAnchorReferenceDigest"`
}

type credentialAuthoritySequence struct {
	accountID     uuid.UUID
	targetID      uuid.UUID
	backupSetID   uuid.UUID
	first         testControlSigner
	second        testControlSigner
	initialAnchor ControlPossessionAnchor
	secondAnchor  ControlPossessionAnchor
	credentials   []TargetCredential
	grants        []CredentialGrant
	commands      []SignedControlCommand
	bearers       []string
}

func TestCredentialAuthorityPortableFixtureAndReducer(t *testing.T) {
	sequence := makeCredentialAuthoritySequence(t)
	expected := sequence.portableFixture(t)
	bytesOnDisk, err := os.ReadFile(filepath.Join(
		"testdata", "backup-custody-credential-authority-portable-v1.json",
	))
	if err != nil {
		t.Fatal(err)
	}
	var fixture credentialAuthorityPortableFixture
	if err := json.Unmarshal(bytesOnDisk, &fixture); err != nil {
		t.Fatal(err)
	}
	if !fixtureEqual(fixture, expected) {
		t.Fatal("portable credential-authority fixture drifted")
	}

	state, err := NewCredentialAuthorityState(sequence.initialAnchor)
	if err != nil || state.ApplyAll(sequence.commands) != nil {
		t.Fatalf("valid committed sequence rejected: %v", err)
	}
	if state.Head.Sequence != 5 || state.Head.ControlGeneration != 2 ||
		state.Head.ReferenceDigest != expected.AcceptedControlHeadReferenceDigest {
		t.Fatal("accepted control head mismatch")
	}
	if grant, ok := state.ActiveGrant(expected.ExpectedActiveCredentialID); !ok ||
		grant.Status != GrantActive || !reflect.DeepEqual(grant.Grant, sequence.grants[2]) {
		t.Fatal("active replacement grant mismatch")
	}
	firstReference, _ := sequence.grants[0].ReferenceDigest()
	secondReference, _ := sequence.grants[1].ReferenceDigest()
	if state.Grants[firstReference].Status != GrantSuperseded ||
		state.Grants[secondReference].Status != GrantRevoked {
		t.Fatal("grant lifecycle mismatch")
	}
	if err := state.Apply(sequence.commands[len(sequence.commands)-1]); err != nil {
		t.Fatal("exact current replay was not idempotent")
	}
	if err := state.Apply(sequence.commands[0]); err == nil {
		t.Fatal("historical replay was treated as the current CAS head")
	}

	wire := append([]byte(nil), expected.InitialAnchorCanonical...)
	for _, record := range expected.CommandsCanonical {
		wire = append(wire, record...)
	}
	text := string(wire)
	for _, forbidden := range []string{"principalID", "recoveryRootID", "protectedHead", "recovery"} {
		if strings.Contains(strings.ToLower(text), strings.ToLower(forbidden)) {
			t.Fatalf("server wire exposed local-only coordinate %q", forbidden)
		}
	}
	for _, bearer := range sequence.bearers {
		if strings.Contains(text, bearer) || strings.Contains(string(bytesOnDisk), bearer) {
			t.Fatal("portable bytes exposed bearer")
		}
	}
}

func TestCredentialAuthoritySequenceHeadAndGrantConflictsFailClosed(t *testing.T) {
	sequence := makeCredentialAuthoritySequence(t)
	state, _ := NewCredentialAuthorityState(sequence.initialAnchor)
	if err := state.Apply(sequence.commands[0]); err != nil {
		t.Fatal(err)
	}

	skipped := sequence.signCommand(t, 3, state.Head.ReferenceDigest, sequence.first,
		ControlEffect{Kind: GrantCredential, Grant: &sequence.grants[1]}, 90, nil)
	if state.Apply(skipped) == nil {
		t.Fatal("skipped account-wide sequence accepted")
	}
	wrongPredecessor := strings.Repeat("a", 64)
	wrongHead := sequence.signCommand(t, 2, wrongPredecessor, sequence.first,
		ControlEffect{Kind: GrantCredential, Grant: &sequence.grants[1]}, 91, nil)
	if state.Apply(wrongHead) == nil {
		t.Fatal("wrong predecessor head accepted")
	}
	other := newTestControlSigner(t, sequence.accountID, 1, 99)
	wrongKey := sequence.signCommand(t, 2, state.Head.ReferenceDigest, other,
		ControlEffect{Kind: GrantCredential, Grant: &sequence.grants[1]}, 92, nil)
	if state.Apply(wrongKey) == nil {
		t.Fatal("wrong control key accepted")
	}
	duplicate := sequence.signCommand(t, 2, state.Head.ReferenceDigest, sequence.first,
		ControlEffect{Kind: GrantCredential, Grant: &sequence.grants[0]}, 93, nil)
	if state.Apply(duplicate) == nil {
		t.Fatal("duplicate credential ID accepted")
	}
	duplicateCommandID := sequence.signCommand(t, 2, state.Head.ReferenceDigest, sequence.first,
		ControlEffect{Kind: GrantCredential, Grant: &sequence.grants[1]}, 20, nil)
	if state.Apply(duplicateCommandID) == nil {
		t.Fatal("duplicate command ID accepted")
	}
	crossAccount := sequence.grants[1]
	crossAccount.Credential.AccountID = credentialAuthorityUUID(96)
	crossAccount.Credential.CredentialID = credentialAuthorityUUID(97)
	crossAccount.AuthorizationDigest = strings.Repeat("a", 64)
	crossAccountPayload := ControlCommandPayload{
		AccountID: sequence.accountID, CommandID: credentialAuthorityUUID(98),
		ControlGeneration: sequence.first.generation, ControlKeyID: sequence.first.keyID,
		Effect:                     ControlEffect{Kind: GrantCredential, Grant: &crossAccount},
		PredecessorReferenceDigest: state.Head.ReferenceDigest, Sequence: 2,
		Version: CredentialAuthorityVersion,
	}
	if crossAccountPayload.Validate() == nil {
		t.Fatal("cross-account credential grant accepted")
	}
}

func TestCredentialAuthorityRotationRequiresBothExactSignatures(t *testing.T) {
	sequence := makeCredentialAuthoritySequence(t)
	state, _ := NewCredentialAuthorityState(sequence.initialAnchor)
	if err := state.ApplyAll(sequence.commands[:4]); err != nil {
		t.Fatal(err)
	}
	rotation := sequence.commands[4]
	missing := rotation
	missing.NewPossessionSignature = nil
	if state.Apply(missing) == nil {
		t.Fatal("rotation missing new possession signature accepted")
	}
	tampered := rotation
	signature, _ := base64.RawURLEncoding.DecodeString(*tampered.NewPossessionSignature)
	signature[0] ^= 1
	value := base64.RawURLEncoding.EncodeToString(signature)
	tampered.NewPossessionSignature = &value
	if state.Apply(tampered) == nil {
		t.Fatal("rotation with invalid new possession signature accepted")
	}
	wrongNew := newTestControlSigner(t, sequence.accountID, 2, 77)
	payload, _ := rotation.DecodedPayload()
	if _, err := signControlCommand(payload, sequence.first, &wrongNew); err == nil {
		t.Fatal("rotation payload accepted a different new possession key")
	}
	if err := state.Apply(rotation); err != nil {
		t.Fatalf("dual-signed exact rotation rejected: %v", err)
	}
	reusedFirstKey := newTestControlSigner(t, sequence.accountID, 3, 17)
	reusedAnchor := reusedFirstKey.anchor(t)
	resurrection := sequence.signCommand(t, 6, state.Head.ReferenceDigest, sequence.second,
		ControlEffect{Kind: RotateControlKey, ControlAnchor: &reusedAnchor}, 99, &reusedFirstKey)
	if state.Apply(resurrection) == nil {
		t.Fatal("retired control key was resurrected at a later generation")
	}
}

func TestCredentialAuthorityStrictCanonicalDecode(t *testing.T) {
	sequence := makeCredentialAuthoritySequence(t)
	record, _ := sequence.commands[0].CanonicalJSON()
	if _, err := DecodeSignedControlCommand(record); err != nil {
		t.Fatal(err)
	}
	unknown := bytes.Replace(record, []byte(`{"authoritySignature":`),
		[]byte(`{"extra":1,"authoritySignature":`), 1)
	if _, err := DecodeSignedControlCommand(unknown); err == nil {
		t.Fatal("unknown field accepted")
	}
	duplicate := bytes.Replace(record, []byte(`{"authoritySignature":`),
		[]byte(`{"authoritySignature":"bogus","authoritySignature":`), 1)
	if _, err := DecodeSignedControlCommand(duplicate); err == nil {
		t.Fatal("duplicate field accepted")
	}
	if _, err := DecodeSignedControlCommand(append(record, '\n')); err == nil {
		t.Fatal("noncanonical trailing byte accepted")
	}
	tampered := append([]byte(nil), record...)
	for index, value := range tampered {
		if value == 'A' {
			tampered[index] = 'B'
			break
		}
	}
	tamperedRecord, err := DecodeSignedControlCommand(tampered)
	if err != nil {
		return
	}
	if _, err := tamperedRecord.Verify(sequence.initialAnchor); err == nil {
		t.Fatal("tampered signed record verified")
	}
}

type testControlSigner struct {
	accountID  uuid.UUID
	generation uint64
	keyID      uuid.UUID
	privateKey ed25519.PrivateKey
}

func newTestControlSigner(t *testing.T, accountID uuid.UUID, generation uint64, seed byte) testControlSigner {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	return testControlSigner{
		accountID: accountID, generation: generation,
		keyID: controlKeyID(privateKey.Public().(ed25519.PublicKey)), privateKey: privateKey,
	}
}

func (signer testControlSigner) anchor(t *testing.T) ControlPossessionAnchor {
	t.Helper()
	publicKey := signer.privateKey.Public().(ed25519.PublicKey)
	unsigned := ControlPossessionAnchorUnsigned{
		AccountID: signer.accountID, Algorithm: CredentialAuthoritySignatureAlgorithm,
		ControlGeneration: signer.generation, ControlKeyID: signer.keyID,
		PublicSigningKey:      base64.RawURLEncoding.EncodeToString(publicKey),
		SigningKeyFingerprint: hexDigest(publicKey), Version: CredentialAuthorityVersion,
	}
	encoded, _ := json.Marshal(unsigned)
	signature := ed25519.Sign(signer.privateKey,
		append([]byte(controlAnchorPossessionSignatureDomain), encoded...))
	anchor := ControlPossessionAnchor{
		PossessionSignature: base64.RawURLEncoding.EncodeToString(signature), Unsigned: unsigned,
	}
	if anchor.VerifyPossession() != nil {
		t.Fatal("test anchor did not verify")
	}
	return anchor
}

func signControlCommand(
	payload ControlCommandPayload,
	authority testControlSigner,
	newAuthority *testControlSigner,
) (SignedControlCommand, error) {
	if payload.Validate() != nil || payload.AccountID != authority.accountID ||
		payload.ControlGeneration != authority.generation || payload.ControlKeyID != authority.keyID {
		return SignedControlCommand{}, serviceauthority.ErrInvalid
	}
	if payload.Effect.Kind == RotateControlKey {
		if newAuthority == nil || payload.Effect.ControlAnchor == nil || newAuthority.generation != authority.generation+1 ||
			payload.Effect.ControlAnchor.Unsigned != newAuthority.anchorNoTest().Unsigned {
			return SignedControlCommand{}, serviceauthority.ErrInvalid
		}
	} else if newAuthority != nil {
		return SignedControlCommand{}, serviceauthority.ErrInvalid
	}
	encoded, _ := json.Marshal(payload)
	record := SignedControlCommand{
		AuthoritySignature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(
			authority.privateKey, append([]byte(controlCommandAuthoritySignatureDomain), encoded...),
		)), Payload: encoded,
	}
	if newAuthority != nil {
		signature := base64.RawURLEncoding.EncodeToString(ed25519.Sign(
			newAuthority.privateKey, append([]byte(controlCommandNewPossessionSignatureDomain), encoded...),
		))
		record.NewPossessionSignature = &signature
	}
	return record, nil
}

func (signer testControlSigner) anchorNoTest() ControlPossessionAnchor {
	publicKey := signer.privateKey.Public().(ed25519.PublicKey)
	unsigned := ControlPossessionAnchorUnsigned{
		AccountID: signer.accountID, Algorithm: CredentialAuthoritySignatureAlgorithm,
		ControlGeneration: signer.generation, ControlKeyID: signer.keyID,
		PublicSigningKey:      base64.RawURLEncoding.EncodeToString(publicKey),
		SigningKeyFingerprint: hexDigest(publicKey), Version: CredentialAuthorityVersion,
	}
	encoded, _ := json.Marshal(unsigned)
	return ControlPossessionAnchor{
		PossessionSignature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(
			signer.privateKey, append([]byte(controlAnchorPossessionSignatureDomain), encoded...),
		)), Unsigned: unsigned,
	}
}

func makeCredentialAuthoritySequence(t *testing.T) credentialAuthoritySequence {
	t.Helper()
	accountID := credentialAuthorityUUID(1)
	targetID := credentialAuthorityUUID(2)
	backupSetID := credentialAuthorityUUID(3)
	first := newTestControlSigner(t, accountID, 1, 17)
	second := newTestControlSigner(t, accountID, 2, 34)
	initialAnchor, secondAnchor := first.anchor(t), second.anchor(t)
	bearers := []string{
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, 32)),
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32)),
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x43}, 32)),
	}
	credentials := make([]TargetCredential, 0, 3)
	grants := make([]CredentialGrant, 0, 3)
	for index := 0; index < 3; index++ {
		reference := TargetCredentialReference{
			AccountID: accountID, BackupSetID: backupSetID,
			Capabilities:          []Capability{Publish, Read, RetentionProof},
			CredentialID:          credentialAuthorityUUID(byte(10 + index)),
			ExpiresAtMilliseconds: 9_000_000_000_000,
			RequestNonce:          base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(0x51 + index)}, 32)),
			TargetID:              targetID, Version: Version,
		}
		credential, err := ParseTargetCredential(reference, bearers[index])
		if err != nil {
			t.Fatal(err)
		}
		digest, _ := credential.AuthorizationDigest()
		credentials = append(credentials, credential)
		grants = append(grants, CredentialGrant{
			AuthorizationDigest: digest, Credential: reference, Version: CredentialAuthorityVersion,
		})
	}
	firstReference, _ := grants[0].ReferenceDigest()
	secondReference, _ := grants[1].ReferenceDigest()
	effects := []ControlEffect{
		{BackupSetID: &backupSetID, Grant: &grants[0], Kind: CreateTargetWithInitialGrant, TargetID: &targetID},
		{Grant: &grants[1], Kind: GrantCredential},
		{Grant: &grants[2], Kind: SupersedeCredential, PriorGrantReferenceDigest: &firstReference},
		{Kind: RevokeCredential, PriorGrantReferenceDigest: &secondReference},
		{ControlAnchor: &secondAnchor, Kind: RotateControlKey},
	}
	predecessor, _ := initialAnchor.ReferenceDigest()
	commands := make([]SignedControlCommand, 0, len(effects))
	for index, effect := range effects {
		payload := ControlCommandPayload{
			AccountID: accountID, CommandID: credentialAuthorityUUID(byte(20 + index)),
			ControlGeneration: 1, ControlKeyID: first.keyID, Effect: effect,
			PredecessorReferenceDigest: predecessor, Sequence: uint64(index + 1),
			Version: CredentialAuthorityVersion,
		}
		var newAuthority *testControlSigner
		if effect.Kind == RotateControlKey {
			newAuthority = &second
		}
		record, err := signControlCommand(payload, first, newAuthority)
		if err != nil {
			t.Fatal(err)
		}
		commands = append(commands, record)
		predecessor, _ = record.ReferenceDigest()
	}
	return credentialAuthoritySequence{
		accountID: accountID, targetID: targetID, backupSetID: backupSetID,
		first: first, second: second, initialAnchor: initialAnchor, secondAnchor: secondAnchor,
		credentials: credentials, grants: grants, commands: commands, bearers: bearers,
	}
}

func (sequence credentialAuthoritySequence) signCommand(
	t *testing.T,
	sequenceNumber uint64,
	predecessor string,
	authority testControlSigner,
	effect ControlEffect,
	commandSuffix byte,
	newAuthority *testControlSigner,
) SignedControlCommand {
	t.Helper()
	record, err := signControlCommand(ControlCommandPayload{
		AccountID: sequence.accountID, CommandID: credentialAuthorityUUID(commandSuffix),
		ControlGeneration: authority.generation, ControlKeyID: authority.keyID, Effect: effect,
		PredecessorReferenceDigest: predecessor, Sequence: sequenceNumber,
		Version: CredentialAuthorityVersion,
	}, authority, newAuthority)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func (sequence credentialAuthoritySequence) portableFixture(t *testing.T) credentialAuthorityPortableFixture {
	t.Helper()
	anchorBytes, _ := sequence.initialAnchor.CanonicalJSON()
	anchorReference, _ := sequence.initialAnchor.ReferenceDigest()
	commands := make([][]byte, 0, len(sequence.commands))
	commandReferences := make([]string, 0, len(sequence.commands))
	for _, command := range sequence.commands {
		bytes, _ := command.CanonicalJSON()
		reference, _ := command.ReferenceDigest()
		commands = append(commands, bytes)
		commandReferences = append(commandReferences, reference)
	}
	grantReferences := make([]string, 0, len(sequence.grants))
	authorizationDigests := make([]string, 0, len(sequence.credentials))
	for index, grant := range sequence.grants {
		reference, _ := grant.ReferenceDigest()
		digest, _ := sequence.credentials[index].AuthorizationDigest()
		grantReferences = append(grantReferences, reference)
		authorizationDigests = append(authorizationDigests, digest)
	}
	return credentialAuthorityPortableFixture{
		AcceptedControlHeadReferenceDigest: commandReferences[len(commandReferences)-1],
		AuthorizationDigests:               authorizationDigests, CommandReferenceDigests: commandReferences,
		CommandsCanonical: commands, ExpectedActiveCredentialID: sequence.grants[2].Credential.CredentialID,
		Format: "facets.backup-custody-credential-authority.v1", GrantReferenceDigests: grantReferences,
		InitialAnchorCanonical: anchorBytes, InitialAnchorReferenceDigest: anchorReference,
	}
}

func fixtureEqual(left, right credentialAuthorityPortableFixture) bool {
	leftBytes, leftErr := json.Marshal(left)
	rightBytes, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

func credentialAuthorityUUID(suffix byte) uuid.UUID {
	return uuid.UUID{0x70, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, suffix}
}
