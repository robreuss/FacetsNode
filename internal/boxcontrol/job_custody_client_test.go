package boxcontrol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/robreuss/FacetsNode/internal/storagecapacity"
)

func TestJobCustodyHTTPClientReportsOperationalAndCoarseAdmissionReadiness(t *testing.T) {
	pressure := storagecapacity.CoarseReadinessSnapshot{
		ProtocolVersion: storagecapacity.AuthorityProtocolVersion,
		Revision:        7, State: storagecapacity.ReadinessStoragePressure,
		ObservedAtMilliseconds: 1_000,
		RetryAfterMilliseconds: storagecapacity.DefaultReadinessRetryAfterMilliseconds,
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/readyz":
			_ = json.NewEncoder(writer).Encode(map[string]string{"status": "ready"})
		case "/v1/readiness":
			_ = json.NewEncoder(writer).Encode(pressure)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client, err := NewJobCustodyHTTPClient(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Healthy(context.Background()); err != nil {
		t.Fatalf("healthy service rejected: %v", err)
	}
	readiness, err := client.AdmissionReadiness(context.Background())
	if err != nil || readiness != pressure {
		t.Fatalf("readiness=%+v error=%v", readiness, err)
	}
}

func TestJobCustodyHTTPClientRejectsInvalidEndpointAndReadiness(t *testing.T) {
	for _, endpoint := range []string{
		"", "https://job-custody.internal", "http://user@job-custody.internal",
		"http://job-custody.internal/path", "http://job-custody.internal?query=true",
	} {
		if _, err := NewJobCustodyHTTPClient(endpoint, http.DefaultClient); err == nil {
			t.Fatalf("invalid endpoint %q accepted", endpoint)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/readyz" {
			http.Error(writer, "unavailable", http.StatusServiceUnavailable)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"protocolVersion":1,"revision":1,"state":"ready","observedAtMilliseconds":1,"retryAfterMilliseconds":0,"unexpected":true}`))
	}))
	defer server.Close()
	client, err := NewJobCustodyHTTPClient(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Healthy(context.Background()); err == nil {
		t.Fatal("unhealthy service accepted")
	}
	if _, err := client.AdmissionReadiness(context.Background()); err == nil {
		t.Fatal("non-canonical readiness projection accepted")
	}

	oversized := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(strings.Repeat("x", maximumJobCustodyReadinessBytes+1)))
	}))
	defer oversized.Close()
	client, err = NewJobCustodyHTTPClient(oversized.URL, oversized.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.AdmissionReadiness(context.Background()); err == nil {
		t.Fatal("oversized readiness projection accepted")
	}
}
