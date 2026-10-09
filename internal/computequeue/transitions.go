package computequeue

const maximumSupportingReceiptIDs = 2_048

type transitionState interface {
	ScheduleState | OccurrenceState | AttemptState | AssignmentState
}

// StateTransition is the portable revision-fenced event shared by every
// lifecycle. The state type keeps schedule, occurrence, attempt, and
// assignment transitions from being accidentally interchanged in Go.
type StateTransition[S transitionState] struct {
	ProtocolVersion           int                 `json:"protocolVersion"`
	ID                        TransitionID        `json:"id"`
	LifecycleID               LifecycleID         `json:"lifecycleID"`
	From                      S                   `json:"from"`
	To                        S                   `json:"to"`
	Authority                 TransitionAuthority `json:"authority"`
	ExpectedRevision          uint64              `json:"expectedRevision"`
	ResultingRevision         uint64              `json:"resultingRevision"`
	OccurredAt                Timestamp           `json:"occurredAt"`
	SupportingReceiptIDs      []ReceiptID         `json:"supportingReceiptIDs"`
	SealedAssignmentSetDigest *Digest             `json:"sealedAssignmentSetDigest,omitempty"`
	Reason                    *TransitionReason   `json:"reason,omitempty"`
	LeaseID                   *LeaseID            `json:"leaseID,omitempty"`
	LeaseRevision             *uint64             `json:"leaseRevision,omitempty"`
	CancellationFence         uint64              `json:"cancellationFence"`
}

type ScheduleTransition = StateTransition[ScheduleState]
type OccurrenceTransition = StateTransition[OccurrenceState]
type AttemptTransition = StateTransition[AttemptState]
type AssignmentTransition = StateTransition[AssignmentState]

func (value StateTransition[S]) Validate() error {
	if err := requireProtocol(value.ProtocolVersion); err != nil {
		return err
	}
	if err := value.ID.Validate(); err != nil {
		return err
	}
	if err := value.LifecycleID.Validate(); err != nil {
		return err
	}
	if !transitionStateValid(value.From) || !transitionStateValid(value.To) {
		return invalid("transition.state")
	}
	if value.ExpectedRevision == ^uint64(0) || value.ResultingRevision != value.ExpectedRevision+1 {
		return invalid("transition.revision")
	}
	if !transitionPermits(value.To, value.From) {
		return invalid("transition.predecessor")
	}
	if value.Reason != nil {
		if err := value.Reason.Validate(); err != nil {
			return err
		}
	}
	if !transitionPermitsReason(value.To, value.From, value.Reason) {
		return invalid("transition.reason")
	}
	switch {
	case value.LeaseID == nil && value.LeaseRevision == nil:
		if value.CancellationFence != 0 {
			return invalid("transition.cancellationFence")
		}
	case value.LeaseID != nil && value.LeaseRevision != nil:
		if err := value.LeaseID.Validate(); err != nil {
			return err
		}
		if *value.LeaseRevision == 0 || value.CancellationFence == 0 {
			return invalid("transition.lease")
		}
	default:
		return invalid("transition.lease")
	}
	requiredAuthority := transitionRequiredAuthority(value.To)
	if value.Authority != requiredAuthority {
		return invalid("transition.authority")
	}
	requiredStages := transitionRequiredReceiptStages(value.To)
	if (value.Authority != AuthoritySourceDevice && len(requiredStages) == 0) ||
		((value.Authority != AuthoritySourceDevice || len(requiredStages) != 0) && len(value.SupportingReceiptIDs) == 0) {
		return invalid("transition.receipts")
	}
	if value.SupportingReceiptIDs == nil || len(value.SupportingReceiptIDs) > maximumSupportingReceiptIDs {
		return invalid("supportingReceiptIDs")
	}
	raw := make([]string, len(value.SupportingReceiptIDs))
	for index, id := range value.SupportingReceiptIDs {
		if err := id.Validate(); err != nil {
			return err
		}
		raw[index] = string(id)
	}
	if err := requireUniqueSorted(raw, "supportingReceiptIDs"); err != nil {
		return err
	}
	if transitionRequiresSealedDigest(value.From) || transitionRequiresSealedDigest(value.To) {
		if value.SealedAssignmentSetDigest == nil {
			return invalid("sealedAssignmentSetDigest")
		}
		if err := value.SealedAssignmentSetDigest.Validate(); err != nil {
			return err
		}
	} else if value.SealedAssignmentSetDigest != nil {
		if err := value.SealedAssignmentSetDigest.Validate(); err != nil {
			return err
		}
	}
	return value.OccurredAt.Validate()
}

// validateAgainst deliberately accepts only the package-private verified
// receipt index. A raw decoded ReceiptRecord must never satisfy transition
// evidence merely because its ID and stage match.
func (value StateTransition[S]) validateAgainst(
	currentState S,
	currentRevision uint64,
	lifecycleID LifecycleID,
	currentSealedAssignmentSetDigest *Digest,
	appliedEventIDs map[TransitionID]struct{},
	receipts verifiedReceiptIndex,
) error {
	if err := value.Validate(); err != nil {
		return err
	}
	if _, replayed := appliedEventIDs[value.ID]; replayed {
		return invalid("transition.replayed")
	}
	if value.LifecycleID != lifecycleID {
		return invalid("lifecycleID")
	}
	if value.ExpectedRevision != currentRevision {
		return invalid("transition.staleRevision")
	}
	if value.From != currentState {
		return invalid("transition.predecessor")
	}
	if currentSealedAssignmentSetDigest != nil && (value.SealedAssignmentSetDigest == nil || *value.SealedAssignmentSetDigest != *currentSealedAssignmentSetDigest) {
		return invalid("sealedAssignmentSetDigest")
	}
	stages := map[ReceiptStage]struct{}{}
	for _, id := range value.SupportingReceiptIDs {
		receipt, present := receipts.get(id)
		if !present {
			return invalid("transition.receipts")
		}
		stages[receipt.record.Stage] = struct{}{}
	}
	for _, stage := range transitionRequiredReceiptStages(value.To) {
		if _, present := stages[stage]; !present {
			return invalid("transition.receipts")
		}
	}
	return nil
}

func transitionStateValid[S transitionState](state S) bool {
	switch any(state).(type) {
	case ScheduleState:
		return ScheduleState(state).valid()
	case OccurrenceState:
		return OccurrenceState(state).valid()
	case AttemptState:
		return AttemptState(state).valid()
	case AssignmentState:
		return AssignmentState(state).valid()
	default:
		return false
	}
}

func transitionRequiresSealedDigest[S transitionState](state S) bool {
	switch any(state).(type) {
	case AttemptState, AssignmentState:
		return string(state) != "prepared"
	default:
		return false
	}
}

func transitionRequiredAuthority[S transitionState](state S) TransitionAuthority {
	switch any(state).(type) {
	case ScheduleState, OccurrenceState:
		return AuthoritySourceDevice
	default:
		switch string(state) {
		case "custodied", "waitingForWorker", "resultCustodied", "retryableRejected", "expired", "custodyCancellationConfirmed":
			return AuthorityJobCustody
		case "claimed", "executing", "workerCancellationConfirmed", "executionFailed":
			return AuthorityWorker
		default:
			return AuthoritySourceDevice
		}
	}
}

func transitionRequiredReceiptStages[S transitionState](to S) []ReceiptStage {
	switch any(to).(type) {
	case OccurrenceState:
		switch string(to) {
		case "securelyQueued":
			return []ReceiptStage{"custodyAccepted"}
		case "running":
			return []ReceiptStage{"executionStarted"}
		case "localRunning":
			return []ReceiptStage{"localExecutionStarted"}
		case "resultsPendingSpace":
			return []ReceiptStage{"resultCustodied"}
		case "applying":
			return []ReceiptStage{"resultDelivered"}
		case "localApplying":
			return []ReceiptStage{"localExecutionCompleted"}
		case "completed":
			return []ReceiptStage{"sourceApplied"}
		case "cancellationUnconfirmed":
			return []ReceiptStage{"cancellationRequested"}
		default:
			return nil
		}
	case AttemptState, AssignmentState:
		switch string(to) {
		case "sealed":
			return []ReceiptStage{"sourceSealed"}
		case "custodied":
			return []ReceiptStage{"custodyAccepted"}
		case "waitingForWorker":
			return []ReceiptStage{"waitingForWorker"}
		case "claimed":
			return []ReceiptStage{"workerClaimed"}
		case "executing":
			return []ReceiptStage{"executionStarted"}
		case "resultCustodied":
			return []ReceiptStage{"resultCustodied"}
		case "delivered":
			return []ReceiptStage{"resultDelivered"}
		case "applied":
			return []ReceiptStage{"sourceApplied"}
		case "retryableRejected":
			return []ReceiptStage{"admissionRejected"}
		case "expired":
			return []ReceiptStage{"leaseExpired"}
		case "custodyCancellationRequested", "workerCancellationRequested", "uncertainTermination", "localCancellationRequested", "localUncertainTermination":
			return []ReceiptStage{"cancellationRequested"}
		case "custodyCancellationConfirmed":
			return []ReceiptStage{"custodyCancellationConfirmed"}
		case "workerCancellationConfirmed":
			return []ReceiptStage{"workerCancellationConfirmed"}
		case "executionFailed":
			return []ReceiptStage{"executionCompleted"}
		case "invalidResult":
			return []ReceiptStage{"resultDelivered"}
		case "localExecuting":
			return []ReceiptStage{"localExecutionStarted"}
		case "localResultReady", "localExecutionFailed", "localInvalidResult":
			return []ReceiptStage{"localExecutionCompleted"}
		case "localApplied":
			return []ReceiptStage{"sourceApplied"}
		case "localReleased":
			return []ReceiptStage{"localReleased"}
		case "localCancellationConfirmed":
			return []ReceiptStage{"localCancellationConfirmed"}
		default:
			return nil
		}
	default:
		return nil
	}
}

func transitionPermits[S transitionState](to, from S) bool {
	if _, ok := any(to).(ScheduleState); ok {
		switch string(to) {
		case "active":
			return string(from) == "paused"
		case "paused":
			return string(from) == "active"
		case "cancelled", "expired":
			return oneOf(string(from), "active", "paused")
		}
	}
	if _, ok := any(to).(OccurrenceState); ok {
		terminal := occurrenceTerminal(OccurrenceState(from))
		switch string(to) {
		case "eligible":
			return false
		case "preparing":
			return oneOf(string(from), "eligible", "waitingForSpace", "waitingForStorage", "paused", "needsAttention")
		case "waitingForSpace":
			return oneOf(string(from), "eligible", "preparing", "paused", "needsAttention")
		case "waitingForStorage":
			return oneOf(string(from), "preparing", "paused", "needsAttention")
		case "securelyQueued":
			return oneOf(string(from), "preparing", "waitingForStorage")
		case "running":
			return string(from) == "securelyQueued"
		case "localRunning":
			return oneOf(string(from), "preparing", "waitingForSpace", "paused")
		case "resultsPendingSpace":
			return string(from) == "running"
		case "applying":
			return oneOf(string(from), "running", "resultsPendingSpace")
		case "localApplying":
			return string(from) == "localRunning"
		case "completed":
			return oneOf(string(from), "applying", "localApplying")
		case "completedWithErrors":
			return oneOf(string(from), "applying", "localApplying", "running", "resultsPendingSpace", "localRunning", "cancellationRequested", "cancellationUnconfirmed", "preparing", "waitingForSpace", "waitingForStorage")
		case "paused":
			return oneOf(string(from), "eligible", "preparing", "waitingForSpace", "waitingForStorage", "needsAttention")
		case "cancellationRequested":
			return !terminal && string(from) != "cancellationRequested"
		case "cancellationUnconfirmed":
			return string(from) == "cancellationRequested"
		case "cancelled":
			return oneOf(string(from), "cancellationRequested", "cancellationUnconfirmed", "eligible", "preparing", "waitingForSpace", "waitingForStorage")
		case "failed", "needsAttention":
			return !terminal && string(from) != string(to)
		}
	}
	// Attempt and Assignment share the same graph, except Assignment cannot be settled.
	switch string(to) {
	case "prepared":
		return false
	case "sealed":
		return string(from) == "prepared"
	case "admissionPending":
		return string(from) == "sealed"
	case "custodied":
		return string(from) == "admissionPending"
	case "waitingForWorker":
		return string(from) == "custodied"
	case "claimed":
		return oneOf(string(from), "custodied", "waitingForWorker")
	case "executing":
		return string(from) == "claimed"
	case "resultCustodied":
		return string(from) == "executing"
	case "delivered":
		return string(from) == "resultCustodied"
	case "applied":
		return string(from) == "delivered"
	case "released":
		return oneOf(string(from), "applied", "custodyCancellationConfirmed", "workerCancellationConfirmed", "executionFailed", "invalidResult", "expired", "uncertainTermination", "settled")
	case "retryableRejected":
		return string(from) == "admissionPending"
	case "expired":
		return oneOf(string(from), "admissionPending", "custodied", "waitingForWorker", "claimed")
	case "custodyCancellationRequested":
		return oneOf(string(from), "admissionPending", "custodied", "waitingForWorker", "retryableRejected")
	case "custodyCancellationConfirmed":
		return oneOf(string(from), "custodyCancellationRequested", "uncertainTermination")
	case "workerCancellationRequested":
		return oneOf(string(from), "claimed", "executing")
	case "workerCancellationConfirmed":
		return oneOf(string(from), "workerCancellationRequested", "uncertainTermination")
	case "executionFailed":
		return oneOf(string(from), "claimed", "executing")
	case "invalidResult":
		return oneOf(string(from), "resultCustodied", "delivered")
	case "uncertainTermination":
		return oneOf(string(from), "custodyCancellationRequested", "workerCancellationRequested")
	case "settled":
		return !attemptTerminal(AttemptState(from))
	case "localExecuting":
		return string(from) == "sealed"
	case "localResultReady":
		return string(from) == "localExecuting"
	case "localApplied":
		return string(from) == "localResultReady"
	case "localReleased":
		return oneOf(string(from), "localApplied", "localCancellationConfirmed", "localExecutionFailed", "localInvalidResult", "localUncertainTermination")
	case "localCancellationRequested":
		return oneOf(string(from), "localExecuting", "localResultReady")
	case "localCancellationConfirmed":
		return oneOf(string(from), "localCancellationRequested", "localUncertainTermination")
	case "localExecutionFailed":
		return string(from) == "localExecuting"
	case "localInvalidResult":
		return string(from) == "localResultReady"
	case "localUncertainTermination":
		return string(from) == "localCancellationRequested"
	default:
		return false
	}
}

func transitionPermitsReason[S transitionState](to, from S, reason *TransitionReason) bool {
	required := []string(nil)
	if _, ok := any(to).(ScheduleState); ok {
		switch string(to) {
		case "active":
			required = []string{"userRequested"}
		case "paused":
			required = []string{"userRequested", "automaticClose"}
		case "cancelled":
			required = []string{"userRequested", "automaticClose", "scheduleExpired", "error"}
		case "expired":
			required = []string{"scheduleExpired"}
		}
	} else if _, ok := any(to).(OccurrenceState); ok {
		switch string(to) {
		case "waitingForSpace":
			required = []string{"waitingForOpenSpace"}
		case "waitingForStorage", "failed", "needsAttention":
			required = []string{"error"}
		case "paused":
			required = []string{"userRequested", "automaticClose"}
		case "cancellationRequested":
			required = []string{"userRequested", "automaticClose", "scheduleExpired"}
		case "cancellationUnconfirmed":
			required = []string{"cancellationUnconfirmed"}
		case "completedWithErrors":
			required = []string{"mixedTerminalOutcomes"}
		case "cancelled":
			if !oneOf(string(from), "cancellationRequested", "cancellationUnconfirmed") {
				required = []string{"userRequested", "automaticClose", "scheduleExpired"}
			}
		}
	} else {
		switch string(to) {
		case "retryableRejected", "executionFailed", "invalidResult", "localExecutionFailed", "localInvalidResult":
			required = []string{"error"}
		case "expired":
			required = []string{"leaseExpired"}
		case "custodyCancellationRequested", "workerCancellationRequested", "localCancellationRequested":
			required = []string{"userRequested", "automaticClose", "scheduleExpired"}
		case "uncertainTermination", "localUncertainTermination":
			required = []string{"cancellationUnconfirmed"}
		case "settled":
			required = []string{"mixedTerminalOutcomes"}
		}
	}
	if required == nil {
		return reason == nil
	}
	if reason == nil {
		return false
	}
	return oneOf(string(reason.Code), required...)
}

func attemptTerminal(state AttemptState) bool {
	return oneOf(string(state), "released", "expired", "custodyCancellationConfirmed", "workerCancellationConfirmed", "executionFailed", "invalidResult", "uncertainTermination", "localReleased", "localCancellationConfirmed", "localExecutionFailed", "localInvalidResult", "localUncertainTermination")
}
