package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSetupCodeIsSeparateFromHealthAndExplicitManagementDetails(t *testing.T) {
	h := &health{Version: 1, Services: map[string]string{}, ServiceMode: "active", ServiceIdentity: strings.Repeat("a", 64)}
	details := &managementDetails{Onion: "private.onion", SetupRequired: true}
	reply := response{Status: h, Management: details, SetupCode: "PRIVATE-SETUP-CODE"}
	b, err := json.Marshal(reply.Status)
	if err != nil || strings.Contains(string(b), "PRIVATE") || strings.Contains(string(b), "onion") || strings.Contains(string(b), "setupCode") {
		t.Fatal("setup material leaked into diagnostic health")
	}
	b, _ = json.Marshal(reply.Management)
	if strings.Contains(string(b), "PRIVATE") || strings.Contains(string(b), "setupCode") {
		t.Fatal("setup code leaked into ordinary management metadata")
	}
	noSetup := response{Status: h, Management: details}
	b, _ = json.Marshal(noSetup)
	if strings.Contains(string(b), "setupCode") {
		t.Fatal("setup code field appeared without explicit disclosure")
	}
}
