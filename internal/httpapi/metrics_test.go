package httpapi

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"github.com/robreuss/FacetsNode/internal/traffic"
)

func TestMetricsFixedSurfaceSnapshot(t *testing.T) {
	metrics := &Metrics{}
	metrics.ObserveRequest(traffic.SurfaceRendezvous)
	metrics.ObserveResponse(traffic.SurfaceRendezvous, 201)
	metrics.ObserveAcceptance(traffic.SurfaceRendezvous, "accepted")
	metrics.ObserveRequest(traffic.SurfaceStorage)
	metrics.ObserveResponse(traffic.SurfaceStorage, 429)
	metrics.ObserveRejection(traffic.SurfaceStorage, rejectionConnectionRateLimit)
	metrics.ObserveRelayWakeNotification(true)
	metrics.ObserveRelayWakeNotification(false)
	metrics.ObserveRelayWakeReceived()
	var output bytes.Buffer
	if err := metrics.WritePrometheus(&output); err != nil {
		t.Fatal(err)
	}
	snapshot := output.String()
	digest := sha256.Sum256([]byte(snapshot))
	const expectedSHA256 = "1738aeec306daa4bd62714de69c31d69917c11302c0cfd81d079e7bfd97c4d50"
	if got := fmt.Sprintf("%x", digest); got != expectedSHA256 {
		t.Fatalf("metrics snapshot SHA-256=%s", got)
	}
	for _, surface := range traffic.Surfaces() {
		if count := strings.Count(snapshot, `surface="`+surface.Name()+`"`); count != 17 {
			t.Fatalf("surface %q sample count=%d", surface.Name(), count)
		}
	}
	for _, obsoleteOrProtected := range []string{
		"facets_node_rendezvous_acceptances_total",
		"tenantID", "memberID", "messageID", "client_ip", "ciphertext", "token",
	} {
		if strings.Contains(snapshot, obsoleteOrProtected) {
			t.Fatalf("metrics snapshot contains forbidden text %q", obsoleteOrProtected)
		}
	}
}

func TestRejectionStatusClassesAreFixed(t *testing.T) {
	for status, expected := range map[int]rejectionClass{
		400: rejectionInvalid,
		401: rejectionUnauthorized,
		403: rejectionForbidden,
		404: rejectionNotFound,
		409: rejectionConflict,
		410: rejectionExpired,
		429: rejectionCapacity,
		500: rejectionInternal,
		503: rejectionInternal,
	} {
		class, rejected := rejectionForStatus(status)
		if !rejected || class != expected {
			t.Fatalf("status=%d class=%s rejected=%v", status, class.name(), rejected)
		}
	}
	for _, status := range []int{200, 201, 204, 301} {
		if _, rejected := rejectionForStatus(status); rejected {
			t.Fatalf("successful status=%d classified as rejection", status)
		}
	}
}
