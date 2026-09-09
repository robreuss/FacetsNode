package serverapp

import (
	"context"
	"net/http"
	"sync"
)

const servingModeHeader = "X-Facets-Serving-Mode"

// Candidate startup may migrate schemas and reconcile durable authority state.
// This is a serving/background-work fence, NOT a read-only database mode. The
// appliance must also withhold ingress and retain its pre-activation disk pair.
func candidateMaintenanceHandler(next http.Handler, candidate bool) http.Handler {
	if !candidate {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(servingModeHeader, "candidate")
		w.Header().Set("Cache-Control", "no-store")
		healthPath := r.URL.Path == "/livez" || r.URL.Path == "/readyz"
		if (r.Method == http.MethodGet || r.Method == http.MethodHead) &&
			healthPath && r.URL.RawPath == "" && r.URL.RawQuery == "" &&
			r.Header.Get("Upgrade") == "" {
			next.ServeHTTP(w, r)
			return
		}
		http.Error(w, "candidate maintenance: application serving withheld", http.StatusServiceUnavailable)
	})
}

// All steady-state workers in the Device Sync/Shared Spaces entry point enter
// through this fence. A candidate never starts them, even for one timer tick.
// Both modes return a joinable completion channel for orderly shutdown.
func startServingBackground(ctx context.Context, candidate bool, relayWake, expiry, blobs func(context.Context)) <-chan struct{} {
	done := make(chan struct{})
	if candidate {
		close(done)
		return done
	}
	var workers sync.WaitGroup
	for _, run := range []func(context.Context){relayWake, expiry, blobs} {
		workers.Add(1)
		go func(run func(context.Context)) {
			defer workers.Done()
			run(ctx)
		}(run)
	}
	go func() {
		workers.Wait()
		close(done)
	}()
	return done
}
