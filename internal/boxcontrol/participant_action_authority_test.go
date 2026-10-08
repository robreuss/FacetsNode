package boxcontrol

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func signedParticipantActionProof(
	t *testing.T,
	fixture participantFixture,
	action BoxParticipantAction,
	request []byte,
) BoxSignedParticipantActionProof {
	t.Helper()
	encoded, err := json.Marshal(BoxParticipantActionProofPayload{
		Version:               1,
		BoxID:                 fixture.anchor.BoxID,
		ParticipantID:         fixture.anchor.ParticipantID,
		BoxScopedPrincipalID:  fixture.anchor.BoxScopedPrincipalID,
		DeviceID:              fixture.device.DeviceID,
		GrantID:               fixture.device.GrantID,
		DeviceGeneration:      fixture.device.DeviceGeneration,
		ChallengeID:           fixture.challengeID,
		Action:                action,
		RequestDigest:         BoxParticipantRequestDigest(request),
		IssuedAtMilliseconds:  fixture.now - 100,
		ExpiresAtMilliseconds: fixture.now + 30_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &object); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return BoxSignedParticipantActionProof{
		Payload: payload,
		Signature: signParticipantBytes(
			t, fixture.deviceKey, participantActionProofDomain, payload,
		),
	}
}

func authorizeParticipantAction(
	fixture participantFixture,
	verifier *BoxParticipantProofVerifier,
	proof BoxSignedParticipantActionProof,
	action BoxParticipantAction,
	request []byte,
) error {
	return verifier.AuthorizeAction(
		context.Background(), fixture.anchor, fixture.device, fixture.root,
		fixture.grant, nil, proof, fixture.challengeID, action, request,
		fixture.now,
	)
}

func TestBoxParticipantActionProofBindsActionAndCanonicalRequest(t *testing.T) {
	fixture := newParticipantFixture(t)
	request := []byte(`{"availability":"available","workerID":"worker-1"}`)
	proof := signedParticipantActionProof(
		t, fixture, ParticipantActionAdvertiseWorker, request,
	)
	verifier := fixture.verifier(t)

	if err := authorizeParticipantAction(
		fixture, verifier, proof, ParticipantActionWithdrawWorker, request,
	); !errors.Is(err, ErrParticipantAuthority) {
		t.Fatalf("different action authorized: %v", err)
	}
	if err := authorizeParticipantAction(
		fixture, verifier, proof, ParticipantActionAdvertiseWorker,
		[]byte(`{"availability":"offline","workerID":"worker-1"}`),
	); !errors.Is(err, ErrParticipantAuthority) {
		t.Fatalf("substituted request authorized: %v", err)
	}
	if err := authorizeParticipantAction(
		fixture, verifier, proof, ParticipantActionAdvertiseWorker, request,
	); err != nil {
		t.Fatal(err)
	}
	if err := authorizeParticipantAction(
		fixture, verifier, proof, ParticipantActionAdvertiseWorker, request,
	); !errors.Is(err, ErrParticipantReplay) {
		t.Fatalf("replayed action proof: %v", err)
	}
}

func TestBoxParticipantActionProofRejectsIdentitySignatureAndExpiryChanges(t *testing.T) {
	request := []byte("worker advertisement")
	tests := []struct {
		name   string
		change func(*participantFixture, *BoxSignedParticipantActionProof)
	}{
		{"wrong challenge", func(f *participantFixture, _ *BoxSignedParticipantActionProof) {
			f.challengeID = uuid.New()
		}},
		{"wrong participant", func(f *participantFixture, _ *BoxSignedParticipantActionProof) {
			f.anchor.ParticipantID = uuid.New()
		}},
		{"expired", func(f *participantFixture, _ *BoxSignedParticipantActionProof) {
			f.now += 31_000
		}},
		{"bad signature", func(_ *participantFixture, proof *BoxSignedParticipantActionProof) {
			proof.Signature = "bad"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newParticipantFixture(t)
			proof := signedParticipantActionProof(
				t, fixture, ParticipantActionAdvertiseWorker, request,
			)
			verifier := fixture.verifier(t)
			test.change(&fixture, &proof)
			if err := authorizeParticipantAction(
				fixture, verifier, proof, ParticipantActionAdvertiseWorker, request,
			); !errors.Is(err, ErrParticipantAuthority) {
				t.Fatalf("changed action proof authorized: %v", err)
			}
		})
	}
}

func TestBoxParticipantActionProofRejectsUnknownActionAndMalformedDigest(t *testing.T) {
	fixture := newParticipantFixture(t)
	request := []byte("worker advertisement")
	for _, action := range []BoxParticipantAction{"", "worker.admin", "WORKER.ADVERTISE"} {
		proof := signedParticipantActionProof(t, fixture, action, request)
		if err := verifyBoxParticipantActionProof(
			fixture.anchor, fixture.device, fixture.root, fixture.grant, nil,
			proof, fixture.challengeID, action, request, fixture.now,
		); !errors.Is(err, ErrParticipantAuthority) {
			t.Fatalf("unknown action %q authorized: %v", action, err)
		}
	}

	proof := signedParticipantActionProof(
		t, fixture, ParticipantActionAdvertiseWorker, request,
	)
	var object map[string]json.RawMessage
	if err := json.Unmarshal(proof.Payload, &object); err != nil {
		t.Fatal(err)
	}
	object["requestDigest"] = json.RawMessage(`"ABC"`)
	payload, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	proof.Payload = payload
	proof.Signature = signParticipantBytes(
		t, fixture.deviceKey, participantActionProofDomain, payload,
	)
	if err := verifyBoxParticipantActionProof(
		fixture.anchor, fixture.device, fixture.root, fixture.grant, nil,
		proof, fixture.challengeID, ParticipantActionAdvertiseWorker,
		request, fixture.now,
	); !errors.Is(err, ErrParticipantAuthority) {
		t.Fatalf("malformed request digest authorized: %v", err)
	}
}
