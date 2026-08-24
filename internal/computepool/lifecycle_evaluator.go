package computepool

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
)

var ErrInvalidLifecycle = errors.New("invalid Facets Compute job lifecycle")

type JobLifecycleEvaluation struct {
	JobID                            uuid.UUID
	CurrentState                     JobState
	AcceptedTransitionCount          int
	DuplicateTransitionCount         int
	AcceptedExecutionReceiptCount    int
	DuplicateExecutionReceiptCount   int
	AcceptedApplicationReceiptCount  int
	DuplicateApplicationReceiptCount int
}

func EvaluateJobLifecycle(
	transitions []PoolJobTransition,
	executions []WorkerExecutionReceipt,
	applications []ResultApplicationReceipt,
	expectedPoolID uuid.UUID,
	expectedPoolAuthorityID uuid.UUID,
	expectedPoolSigningKeyFingerprint string,
) (JobLifecycleEvaluation, error) {
	if len(transitions) == 0 {
		return JobLifecycleEvaluation{}, ErrInvalidLifecycle
	}
	uniqueTransitions := make([]PoolJobTransition, 0, len(transitions))
	transitionByID := map[uuid.UUID]string{}
	transitionBySequence := map[uint64]string{}
	duplicateTransitions := 0
	var previousInputSequence uint64
	for _, transition := range transitions {
		if transition.Sequence < previousInputSequence || transition.Validate() != nil {
			return JobLifecycleEvaluation{}, ErrInvalidLifecycle
		}
		previousInputSequence = transition.Sequence
		digest, err := transition.Digest()
		if err != nil {
			return JobLifecycleEvaluation{}, ErrInvalidLifecycle
		}
		if prior, found := transitionByID[transition.TransitionID]; found {
			if prior != digest {
				return JobLifecycleEvaluation{}, ErrInvalidLifecycle
			}
			duplicateTransitions++
			continue
		}
		if prior, found := transitionBySequence[transition.Sequence]; found {
			if prior != digest {
				return JobLifecycleEvaluation{}, ErrInvalidLifecycle
			}
			duplicateTransitions++
			continue
		}
		if transition.PoolID != expectedPoolID || transition.Signature.SignerID != expectedPoolAuthorityID ||
			transition.Signature.SigningKeyFingerprint != expectedPoolSigningKeyFingerprint {
			return JobLifecycleEvaluation{}, ErrInvalidLifecycle
		}
		transitionByID[transition.TransitionID] = digest
		transitionBySequence[transition.Sequence] = digest
		uniqueTransitions = append(uniqueTransitions, transition)
	}
	executionByID, executionDuplicates, err := dedupeExecutions(executions)
	if err != nil {
		return JobLifecycleEvaluation{}, err
	}
	applicationByID, applicationDuplicates, err := dedupeApplications(applications)
	if err != nil {
		return JobLifecycleEvaluation{}, err
	}
	jobID := uniqueTransitions[0].JobID
	for _, receipt := range executionByID {
		if receipt.JobID != jobID {
			return JobLifecycleEvaluation{}, ErrInvalidLifecycle
		}
	}
	for _, receipt := range applicationByID {
		if receipt.JobID != jobID {
			return JobLifecycleEvaluation{}, ErrInvalidLifecycle
		}
	}
	var previous *PoolJobTransition
	sawResultApplied := false
	for index := range uniqueTransitions {
		transition := &uniqueTransitions[index]
		if transition.JobID != jobID {
			return JobLifecycleEvaluation{}, ErrInvalidLifecycle
		}
		if previous == nil {
			if transition.Sequence != 1 || transition.PredecessorDigest != nil || transition.State != JobAuthorized {
				return JobLifecycleEvaluation{}, ErrInvalidLifecycle
			}
		} else {
			priorDigest, _ := previous.Digest()
			if transition.Sequence != previous.Sequence+1 || transition.PredecessorDigest == nil ||
				*transition.PredecessorDigest != priorDigest || transition.OccurredAtMilliseconds < previous.OccurredAtMilliseconds ||
				!allowedJobTransition(previous.State, transition.State) {
				return JobLifecycleEvaluation{}, ErrInvalidLifecycle
			}
		}
		if transition.State == JobResultStaged || transition.State == JobResultDelivered {
			if transition.EvidenceDigest == nil || !containsExecutionDigest(executionByID, *transition.EvidenceDigest) {
				return JobLifecycleEvaluation{}, ErrInvalidLifecycle
			}
		}
		if transition.State == JobResultApplied {
			if transition.EvidenceDigest == nil || !containsApplicationDigest(applicationByID, *transition.EvidenceDigest) {
				return JobLifecycleEvaluation{}, ErrInvalidLifecycle
			}
			sawResultApplied = true
		}
		if transition.State == JobCompleted && !sawResultApplied {
			return JobLifecycleEvaluation{}, ErrInvalidLifecycle
		}
		previous = transition
	}
	return JobLifecycleEvaluation{
		JobID: jobID, CurrentState: uniqueTransitions[len(uniqueTransitions)-1].State,
		AcceptedTransitionCount: len(uniqueTransitions), DuplicateTransitionCount: duplicateTransitions,
		AcceptedExecutionReceiptCount: len(executionByID), DuplicateExecutionReceiptCount: executionDuplicates,
		AcceptedApplicationReceiptCount: len(applicationByID), DuplicateApplicationReceiptCount: applicationDuplicates,
	}, nil
}

func dedupeExecutions(receipts []WorkerExecutionReceipt) (map[uuid.UUID]WorkerExecutionReceipt, int, error) {
	byID := map[uuid.UUID]WorkerExecutionReceipt{}
	byAttempt := map[string]string{}
	for _, receipt := range receipts {
		if receipt.Validate() != nil {
			return nil, 0, ErrInvalidLifecycle
		}
		digest, _ := receipt.Digest()
		if prior, found := byID[receipt.ReceiptID]; found {
			priorDigest, _ := prior.Digest()
			if priorDigest != digest {
				return nil, 0, ErrInvalidLifecycle
			}
			continue
		}
		key := fmt.Sprintf("%s|%d", receipt.JobID, receipt.Attempt)
		if prior, found := byAttempt[key]; found && prior != digest {
			return nil, 0, ErrInvalidLifecycle
		}
		byID[receipt.ReceiptID] = receipt
		byAttempt[key] = digest
	}
	return byID, len(receipts) - len(byID), nil
}

func dedupeApplications(receipts []ResultApplicationReceipt) (map[uuid.UUID]ResultApplicationReceipt, int, error) {
	byID := map[uuid.UUID]ResultApplicationReceipt{}
	byJob := map[uuid.UUID]string{}
	for _, receipt := range receipts {
		if receipt.Validate() != nil {
			return nil, 0, ErrInvalidLifecycle
		}
		digest, _ := receipt.Digest()
		if prior, found := byID[receipt.ReceiptID]; found {
			priorDigest, _ := prior.Digest()
			if priorDigest != digest {
				return nil, 0, ErrInvalidLifecycle
			}
			continue
		}
		if prior, found := byJob[receipt.JobID]; found && prior != digest {
			return nil, 0, ErrInvalidLifecycle
		}
		byID[receipt.ReceiptID] = receipt
		byJob[receipt.JobID] = digest
	}
	return byID, len(receipts) - len(byID), nil
}

func containsExecutionDigest(receipts map[uuid.UUID]WorkerExecutionReceipt, digest string) bool {
	for _, receipt := range receipts {
		candidate, _ := receipt.Digest()
		if candidate == digest {
			return true
		}
	}
	return false
}

func containsApplicationDigest(receipts map[uuid.UUID]ResultApplicationReceipt, digest string) bool {
	for _, receipt := range receipts {
		candidate, _ := receipt.Digest()
		if candidate == digest {
			return true
		}
	}
	return false
}

func allowedJobTransition(from, to JobState) bool {
	switch from {
	case JobAuthorized:
		return contains([]JobState{JobAdmitted, JobCancelRequested, JobExpired}, to)
	case JobAdmitted:
		return contains([]JobState{JobQueued, JobLeased, JobCancelRequested, JobExpired}, to)
	case JobQueued:
		return contains([]JobState{JobLeased, JobPaused, JobCancelRequested, JobFailed, JobExpired}, to)
	case JobLeased:
		return contains([]JobState{JobExecuting, JobQueued, JobRetryWait, JobCancelRequested, JobFailed, JobExpired}, to)
	case JobExecuting:
		return contains([]JobState{JobResultStaged, JobRetryWait, JobCancelRequested, JobFailed, JobExpired}, to)
	case JobRetryWait:
		return contains([]JobState{JobQueued, JobLeased, JobPaused, JobCancelRequested, JobFailed, JobExpired}, to)
	case JobResultStaged:
		return contains([]JobState{JobResultDelivered, JobCancelRequested, JobFailed}, to)
	case JobResultDelivered:
		return contains([]JobState{JobResultApplied, JobCancelRequested, JobFailed}, to)
	case JobResultApplied:
		return to == JobCompleted
	case JobCancelRequested:
		return contains([]JobState{JobCancelled, JobFailed, JobExpired}, to)
	case JobPaused:
		return contains([]JobState{JobQueued, JobCancelRequested, JobExpired}, to)
	}
	return false
}
