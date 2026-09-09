package serverapp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestCandidateMaintenanceRejectsApplicationBeforeDispatch(t *testing.T) {
	var calls int
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path == "/readyz" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	candidate := candidateMaintenanceHandler(next, true)
	for _, path := range []string{"/", "/facetsbox/", "/v1/relay/messages", "/v1/relay/stream", "/metrics", "/readyz/", "/livez?application=true", "/%6civez", "/readyz/../livez"} {
		for _, method := range []string{"GET", "POST", "DELETE", "HEAD", "OPTIONS", "CONNECT"} {
			w := httptest.NewRecorder()
			candidate.ServeHTTP(w, httptest.NewRequest(method, path, nil))
			if w.Code != 503 || calls != 0 || w.Header().Get(servingModeHeader) != "candidate" {
				t.Fatalf("unfenced request %s %s", method, path)
			}
		}
	}
	for _, path := range []string{"/livez", "/readyz"} {
		for _, method := range []string{"GET", "HEAD"} {
			w := httptest.NewRecorder()
			candidate.ServeHTTP(w, httptest.NewRequest(method, path, nil))
			want := http.StatusNoContent
			if path == "/readyz" {
				want = http.StatusServiceUnavailable
			}
			if w.Code != want || w.Header().Get(servingModeHeader) != "candidate" {
				t.Fatal("health result was replaced or candidate mode missing")
			}
		}
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", path, nil)
		r.Header.Set("Upgrade", "websocket")
		candidate.ServeHTTP(w, r)
		if w.Code != 503 {
			t.Fatal("upgrade accepted during candidate startup")
		}
	}
	if calls != 4 {
		t.Fatalf("unexpected downstream dispatches: %d", calls)
	}
	if candidateMaintenanceHandler(next, false) == nil {
		t.Fatal("normal handler missing")
	}
	w := httptest.NewRecorder()
	candidateMaintenanceHandler(next, false).ServeHTTP(w, httptest.NewRequest("POST", "/application", nil))
	if w.Code != 204 || calls != 5 || w.Header().Get(servingModeHeader) != "" {
		t.Fatal("default serving changed")
	}
}

func TestCandidateStartsNoExpiryBlobOrRelayWorkersAndJoins(t *testing.T) {
	for _, candidate := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		var started, finished atomic.Int32
		entered := make(chan struct{}, 3)
		worker := func(ctx context.Context) { started.Add(1); entered <- struct{}{}; <-ctx.Done(); finished.Add(1) }
		done := startServingBackground(ctx, candidate, worker, worker, worker)
		if !candidate {
			for i := 0; i < 3; i++ {
				select {
				case <-entered:
				case <-time.After(time.Second):
					cancel()
					t.Fatal("normal worker did not start")
				}
			}
		}
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("worker shutdown did not join")
		}
		want := int32(3)
		if candidate {
			want = 0
		}
		if started.Load() != want || finished.Load() != want {
			t.Fatal("candidate workers ran or normal workers failed to join")
		}
	}
}

func TestCandidateHealthProbeRequiresExplicitModeAndHealthyDatabase(t *testing.T) {
	for _, candidate := range []bool{true, false} {
		for _, code := range []int{http.StatusOK, http.StatusServiceUnavailable} {
			s := httptest.NewServer(candidateMaintenanceHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(code) }), candidate))
			if checkHealth(s.URL+"/readyz", true) != (candidate && code == 200) {
				t.Fatal("candidate probe accepted wrong mode or unavailable database")
			}
			if checkHealth(s.URL+"/readyz", false) != (code == 200) {
				t.Fatal("existing health probe behavior changed")
			}
			s.Close()
		}
	}
}
