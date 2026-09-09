package main

import (
	"encoding/json"
	"testing"
)

func TestManagementRequiresActiveMatchingServiceRelease(t *testing.T) {
	state := serviceActivation{Version: 1, InstallationID: "installation", ReleaseID: "release", Phase: "active"}
	b, _ := json.Marshal(state)
	if err := validateManagementActivation(b, "installation", "release"); err != nil {
		t.Fatal(err)
	}
	if validateManagementActivation(b, "different", "release") == nil || validateManagementActivation(b, "installation", "different") == nil {
		t.Fatal("accepted mismatched activation")
	}
	for _, phase := range []string{"", "candidate", "authorized", "failed"} {
		state.Phase = phase
		b, _ = json.Marshal(state)
		if validateManagementActivation(b, "installation", "release") == nil {
			t.Fatal("allowed writes before activation")
		}
	}
}
