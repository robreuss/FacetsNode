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
	authorization InvocationAuthorization,
	admission PoolAdmission,
	signedWorkerCard SignedWorkerCard,
	workerEnrollment WorkerEnrollment,
	offering Offering,
	permittedInvocationAuthorities []P256SigningAuthority,
	permittedApplicationAuthorities []P256SigningAuthority,
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
	poolAuthority := P256SigningAuthority{
		SignerID: expectedPoolAuthorityID, SigningKeyFingerprint: expectedPoolSigningKeyFingerprint,
	}
	if admission.JobID != jobID || admission.PoolID != expectedPoolID ||
		admission.ValidateInputRelease(authorization, signedWorkerCard, workerEnrollment, offering,
			poolAuthority, permittedInvocationAuthorities, admission.AdmittedAtMilliseconds) != nil {
		return JobLifecycleEvaluation{}, ErrInvalidLifecycle
	}
	for _, receipt := range executionByID {
		if receipt.JobID != jobID ||
			receipt.ValidateAdmission(admission, authorization, workerEnrollment) != nil ||
			receipt.StartedAtMilliseconds >= admission.LeaseExpiresAtMilliseconds ||
			receipt.FinishedAtMilliseconds > admission.ExpiresAtMilliseconds ||
			receipt.FinishedAtMilliseconds > authorization.ExpiresAtMilliseconds {
			return JobLifecycleEvaluation{}, ErrInvalidLifecycle
		}
	}
	for _, receipt := range applicationByID {
		execution, found := executionByID[receipt.ExecutionReceiptID]
		if receipt.JobID != jobID || !found ||
			!anyP256AuthorityAuthorizes(permittedApplicationAuthorities, receipt.Signature) ||
			receipt.ValidateExecution(execution) != nil {
			return JobLifecycleEvaluation{}, ErrInvalidLifecycle
		}
	}
	authorizationDigest, _ := authorization.Digest()
	admissionDigest, _ := admission.Digest()
	var previous *PoolJobTransition
	sawResultApplied := false
	appliedEvidenceDigest := ""
	for index := range uniqueTransitions {
		transition := &uniqueTransitions[index]
		if transition.JobID != jobID {
			return JobLifecycleEvaluation{}, ErrInvalidLifecycle
		}
		if previous == nil {
			if transition.Sequence != 1 || transition.PredecessorDigest != nil || transition.State != JobAuthorized ||
				transition.EvidenceDigest == nil || *transition.EvidenceDigest != authorizationDigest ||
				transition.OccurredAtMilliseconds < authorization.AuthorizedAtMilliseconds ||
				transition.OccurredAtMilliseconds >= authorization.ExpiresAtMilliseconds {
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
		if transition.State == JobAdmitted {
			if transition.EvidenceDigest == nil || *transition.EvidenceDigest != admissionDigest ||
				transition.OccurredAtMilliseconds < admission.AdmittedAtMilliseconds ||
				transition.OccurredAtMilliseconds >= admission.ExpiresAtMilliseconds {
				return JobLifecycleEvaluation{}, ErrInvalidLifecycle
			}
		}
		if (transition.State == JobLeased || transition.State == JobExecuting) &&
			transition.OccurredAtMilliseconds >= admission.LeaseExpiresAtMilliseconds {
			return JobLifecycleEvaluation{}, ErrInvalidLifecycle
		}
		if transition.State == JobResultStaged || transition.State == JobResultDelivered {
			receipt, found := executionForDigest(executionByID, transition.EvidenceDigest)
			if !found || receipt.FinishedAtMilliseconds > transition.OccurredAtMilliseconds {
				return JobLifecycleEvaluation{}, ErrInvalidLifecycle
			}
		}
		if transition.State == JobResultApplied {
			receipt, found := applicationForDigest(applicationByID, transition.EvidenceDigest)
			if !found || receipt.AppliedAtMilliseconds > transition.OccurredAtMilliseconds {
				return JobLifecycleEvaluation{}, ErrInvalidLifecycle
			}
			sawResultApplied = true
			appliedEvidenceDigest = *transition.EvidenceDigest
		}
		if transition.State == JobCompleted {
			if !sawResultApplied || transition.EvidenceDigest == nil || *transition.EvidenceDigest != appliedEvidenceDigest {
				return JobLifecycleEvaluation{}, ErrInvalidLifecycle
			}
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

func executionForDigest(receipts map[uuid.UUID]WorkerExecutionReceipt, digest *string) (WorkerExecutionReceipt, bool) {
	if digest == nil {
		return WorkerExecutionReceipt{}, false
	}
	for _, receipt := range receipts {
		candidate, _ := receipt.Digest()
		if candidate == *digest {
			return receipt, true
		}
	}
	return WorkerExecutionReceipt{}, false
}

func applicationForDigest(receipts map[uuid.UUID]ResultApplicationReceipt, digest *string) (ResultApplicationReceipt, bool) {
	if digest == nil {
		return ResultApplicationReceipt{}, false
	}
	for _, receipt := range receipts {
		candidate, _ := receipt.Digest()
		if candidate == *digest {
			return receipt, true
		}
	}
	return ResultApplicationReceipt{}, false
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
