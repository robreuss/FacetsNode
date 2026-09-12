package main

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/boxcontrol"
)

type rotationStore struct {
	state boxcontrol.State
	calls int
	fail  bool
}

func (s *rotationStore) State(context.Context) (boxcontrol.State, error) { return s.state, nil }
func (s *rotationStore) ReplaceActivationVerifier(_ context.Context, id uuid.UUID, previous, replacement string) error {
	s.calls++
	if s.fail || id != s.state.BoxID || previous != s.state.ActivationVerifier || replacement == previous || replacement == "" {
		return errors.New("compare-and-swap failed")
	}
	s.state.ActivationVerifier = replacement
	return nil
}

func TestReplaceActivationCodeRequiresExactUnclaimedBox(t *testing.T) {
	for _, kind := range []string{"missing", "zero", "wrong", "claimed", "valid", "race"} {
		t.Run(kind, func(t *testing.T) {
			id := uuid.New()
			s := &rotationStore{state: boxcontrol.State{BoxID: id, ActivationVerifier: "prior-verifier"}}
			args := []string{"--box-id", id.String()}
			switch kind {
			case "missing":
				args = nil
			case "zero":
				args[1] = uuid.Nil.String()
			case "wrong":
				args[1] = uuid.NewString()
			case "claimed":
				s.state.OwnerVerifier = "owner-verifier"
			case "race":
				s.fail = true
			}
			code, err := replaceActivationCode(context.Background(), s, args)
			if kind == "valid" {
				if err != nil || len(code) != 14 || s.calls != 1 || s.state.BoxID != id || s.state.Claimed() {
					t.Fatal("rotation did not preserve unclaimed Box identity", err)
				}
			} else if err == nil || code != "" || (kind != "race" && s.calls != 0) {
				t.Fatal("rejected rotation leaked a code or changed state")
			}
		})
	}
}
