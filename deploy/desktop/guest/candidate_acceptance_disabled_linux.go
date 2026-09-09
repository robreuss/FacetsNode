//go:build linux && !fbd_candidate_failure

package main

import "context"

// Production appliances contain no database-mutating acceptance probe.
func candidateAcceptanceProbe(context.Context, configuration) error { return nil }
