package main

import (
	"encoding/json"
	"testing"
)

func TestInitializationCleanupRequiresExactOwnership(t *testing.T) {
	r := map[string]any{"Name": "/test", "Config": map[string]any{"Image": "sha256:expected", "Labels": map[string]string{"net.simplyformed.facets.box.installation": "installation", "net.simplyformed.facets.box.initialization": "onion"}}}
	b, _ := json.Marshal([]any{r})
	if err := validateInitializationContainer(b, "test", "installation", "onion", "sha256:expected"); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][4]string{{"different", "installation", "onion", "sha256:expected"}, {"test", "different", "onion", "sha256:expected"}, {"test", "installation", "controller", "sha256:expected"}, {"test", "installation", "onion", "sha256:different"}} {
		if validateInitializationContainer(b, args[0], args[1], args[2], args[3]) == nil {
			t.Fatal("accepted foreign container")
		}
	}
}
