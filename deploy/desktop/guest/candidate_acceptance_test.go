//go:build fbd_candidate_failure

package main

import (
	"errors"
	"testing"
)

func TestCandidateFailureRequiresPendingAcceptanceRelease(t *testing.T) {
	for _, tc := range []struct {
		pending bool
		release string
	}{{false, "acceptance-test"}, {true, "ordinary-release"}} {
		err := runCandidateFailureProbe(tc.pending, tc.release, func(string) (string, error) { t.Fatal("SQL executed outside test candidate"); return "", nil })
		if err == nil {
			t.Fatal("test appliance permitted normal operation")
		}
	}
}

func TestCandidateFailureRequiresCommittedReadAndAlwaysFails(t *testing.T) {
	for failAt := -1; failAt < 3; failAt++ {
		calls := 0
		err := runCandidateFailureProbe(true, "acceptance-test", func(sql string) (string, error) {
			index := calls
			calls++
			if sql != []string{candidateProbeAbsent, candidateProbeWrite, candidateProbeRead}[index] {
				t.Fatal("unexpected SQL")
			}
			if index == failAt {
				return "", errors.New("private detail")
			}
			return []string{"t", "", "committed-before-activation"}[index], nil
		})
		if err == nil {
			t.Fatal("probe must never allow activation")
		}
		if failAt == -1 && (calls != 3 || err.Error() != candidateProbeCommittedFailure) {
			t.Fatal("missing committed proof")
		}
		if failAt >= 0 && (calls != failAt+1 || err.Error() == candidateProbeCommittedFailure) {
			t.Fatal("claimed unverified mutation")
		}
	}
}

func TestCandidateFailureRejectsExistingTableAndWrongMarker(t *testing.T) {
	for _, replies := range [][]string{{"f"}, {"t", "", "wrong"}} {
		calls := 0
		err := runCandidateFailureProbe(true, "acceptance-test", func(string) (string, error) {
			if calls >= len(replies) {
				t.Fatal("query after rejected evidence")
			}
			value := replies[calls]
			calls++
			return value, nil
		})
		if err == nil || err.Error() == candidateProbeCommittedFailure || calls != len(replies) {
			t.Fatal("unverified evidence accepted")
		}
	}
}
