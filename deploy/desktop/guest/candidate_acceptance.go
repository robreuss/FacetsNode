//go:build fbd_candidate_failure

package main

import (
	"errors"
	"strings"
)

const candidateProbeAbsent = "SELECT to_regclass('public.fbd_candidate_rollback_probe') IS NULL"
const candidateProbeWrite = "CREATE TABLE public.fbd_candidate_rollback_probe (marker text NOT NULL); INSERT INTO public.fbd_candidate_rollback_probe VALUES ('committed-before-activation')"
const candidateProbeRead = "SELECT marker FROM public.fbd_candidate_rollback_probe"
const candidateProbeCommittedFailure = "acceptance-only failure: committed database probe verified; activation withheld"

// Three independent psql sessions establish absence, commit a schema/data
// mutation, then read that committed row. These are fixed statements, not a
// management operation or a caller-supplied SQL interface. Every path fails.
func runCandidateFailureProbe(pending bool, release string, query func(string) (string, error)) error {
	if !pending || !strings.HasPrefix(release, "acceptance-") {
		return errors.New("acceptance-only appliance cannot run normally")
	}
	absent, err := query(candidateProbeAbsent)
	if err != nil || absent != "t" {
		return errors.New("acceptance probe requires an unused reserved table name")
	}
	if _, err = query(candidateProbeWrite); err != nil {
		return errors.New("acceptance database write failed")
	}
	marker, err := query(candidateProbeRead)
	if err != nil || marker != "committed-before-activation" {
		return errors.New("acceptance committed database read failed")
	}
	return errors.New(candidateProbeCommittedFailure)
}
