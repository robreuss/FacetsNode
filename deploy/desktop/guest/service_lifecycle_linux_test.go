//go:build linux

package main

import (
	"testing"
	"time"
)

func TestApplianceHealthDoesNotConfuseCandidateAndActiveOrRetainStaleReadiness(t *testing.T) {
	defer setServiceMode("")
	for _, mode := range []string{"preparing", "candidate", "activating", "active", "failed"} {
		setServiceMode(mode)
		applianceServices.Lock()
		applianceServices.states = map[string]string{"device-sync": "ready"}
		applianceServices.checked = time.Now()
		applianceServices.Unlock()
		h := &health{Services: map[string]string{}}
		serviceHealth(h)
		if h.ServiceMode != mode || h.IngressEnabled != (mode == "active" || mode == "activating") {
			t.Fatal("serving mode or ingress state was flattened")
		}
		applianceServices.Lock()
		applianceServices.checked = time.Now().Add(-time.Minute)
		applianceServices.Unlock()
		serviceHealth(h)
		if h.Services["device-sync"] != "unavailable" {
			t.Fatal("stale readiness survived")
		}
	}
}
