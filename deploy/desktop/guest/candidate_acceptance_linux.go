//go:build linux && fbd_candidate_failure

package main

import "context"

// This separately signed developer-only appliance always fails preparation;
// it cannot reach the candidate/activation state or start public ingress.
func candidateAcceptanceProbe(ctx context.Context, c configuration) error {
	return runCandidateFailureProbe(c.ActivationPending, c.ReleaseID, func(sql string) (string, error) {
		return controllerQuery(ctx, sql)
	})
}
