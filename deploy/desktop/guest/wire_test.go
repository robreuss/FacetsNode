package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"testing"
)

func TestAuthenticatedNamedOperations(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	for _, operation := range []string{"status", "shutdown", "activate", "exec"} {
		payload, _ := json.Marshal(request{ID: "00000000-0000-0000-0000-000000000001", Operation: operation})
		mac := hmac.New(sha256.New, key)
		mac.Write(payload)
		data, _ := json.Marshal(frame{payload, mac.Sum(nil)})
		_, err := decodeRequest(data, key)
		if (err == nil) != (operation != "exec") {
			t.Fatalf("operation %s: %v", operation, err)
		}
		if _, err = decodeRequest(data, []byte("wrong")); err == nil {
			t.Fatal("accepted wrong key")
		}
	}
}
