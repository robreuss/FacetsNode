//go:build linux

package main

import "testing"

func TestPortableAcceptanceRequiresDormantRuntime(t *testing.T) {
	acceptance := map[string]string{
		"dockerfileTests": "passed", "ociVerification": "passed", "renderedComposeBoundary": "passed",
		"ingressConfiguration": "passed", "offlineOnionIdentity": "passed", "isolatedServiceRuntime": "passed",
		"isolatedControllerClaimHTTPS": "passed", "containerRecreationIdentity": "passed", "candidateMaintenance": "passed",
		"serviceRuntime": "not-installed", "spacesSync": "not-run",
		"jobCustodyRuntime": "not-run", "storageCapacityRuntime": "not-run",
	}
	if !portableAcceptanceComplete(acceptance) {
		t.Fatal("complete dormant acceptance was rejected")
	}
	acceptance["serviceRuntime"] = "active"
	if portableAcceptanceComplete(acceptance) {
		t.Fatal("active service runtime was accepted as a dormant kit")
	}
	acceptance["serviceRuntime"] = "not-installed"
	delete(acceptance, "jobCustodyRuntime")
	if portableAcceptanceComplete(acceptance) {
		t.Fatal("missing Job Custody runtime evidence was accepted")
	}
}

func TestPortableRuntimeFixtureNames(t *testing.T) {
	for _, name := range []string{"fbd-device-sync_server_1", "fbd-shared-spaces-postgres", "fbd-job-custody_job-custody_1", "fbd-storage-capacity-postgres", "fbd-validation-device-test_postgres", "fbd-build-onion-test"} {
		if !portableRuntimeFixture(name) {
			t.Fatalf("fixture %q was not detected", name)
		}
	}
	for _, name := range []string{"buildx_buildkit_fbd-builder0", "unrelated", "fbd-device"} {
		if portableRuntimeFixture(name) {
			t.Fatalf("unrelated runtime object %q was rejected", name)
		}
	}
}
