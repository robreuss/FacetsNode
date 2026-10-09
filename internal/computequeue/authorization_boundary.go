package computequeue

import "fmt"

// AuthorizedAttempt is deliberately not a wire contract. It proves that the
// wrapped source record crossed the complete schedule, occurrence, population,
// and (when applicable) retry-evidence boundary.
type AuthorizedAttempt struct {
	record AttemptRecord
}

func (value AuthorizedAttempt) Record() AttemptRecord { return cloneAttemptRecord(value.record) }

func (value AttemptRecord) validateAuthorizedBySchedule(schedule ScheduleRecord) error {
	if err := value.Validate(); err != nil {
		return err
	}
	if err := schedule.Validate(); err != nil {
		return err
	}
	if value.ExecutionIdentity.Digest() != schedule.ExecutionIdentity.Digest() ||
		value.OperationBindingDigest != schedule.OperationBinding.Digest() ||
		value.RetryPolicyDigest != schedule.PolicyBinding.RetryPolicy.Digest() ||
		value.DestinationKind != schedule.DestinationPolicy.Kind ||
		value.SourceReceiptSigner != schedule.SourceReceiptSigner ||
		!sameSigner(value.CustodyReceiptSigner, schedule.DestinationPolicy.CustodyReceiptSigner) {
		return invalid("scheduleExecutionAuthorization")
	}
	switch value.DestinationKind {
	case DestinationDirectLocal:
		return nil
	case DestinationFixedWorkers:
		if schedule.DestinationPolicy.FixedWorkerSet == nil || value.AuthorizedWorkerSetDigest == nil || *value.AuthorizedWorkerSetDigest != schedule.DestinationPolicy.FixedWorkerSet.Digest {
			return invalid("fixedWorkerSet")
		}
		authorized := map[WorkerID]WorkerBinding{}
		for _, worker := range schedule.DestinationPolicy.FixedWorkerSet.Workers {
			authorized[worker.WorkerID] = worker
		}
		for _, assignment := range value.AssignmentPlan.Assignments {
			if assignment.Executor.Worker == nil {
				return invalid("fixedWorkerSet")
			}
			worker, present := authorized[assignment.Executor.Worker.WorkerID]
			if !present || worker != *assignment.Executor.Worker {
				return invalid("fixedWorkerSet")
			}
		}
	case DestinationComputePool:
		if schedule.DestinationPolicy.ComputePoolPolicyDigest == nil || value.ComputePoolPolicyDigest == nil || *value.ComputePoolPolicyDigest != *schedule.DestinationPolicy.ComputePoolPolicyDigest || value.ComputePoolGrantDigest == nil || value.ComputePoolAssignmentSetDigest == nil || *value.ComputePoolAssignmentSetDigest != value.AssignmentPlan.AssignmentSetDigest {
			return invalid("computePoolGrant")
		}
	}
	return nil
}

func (value AttemptRecord) validateCreationBoundary(schedule ScheduleRecord, occurrence OccurrenceRecord, items []ItemRecord) ([]ItemRecord, error) {
	if err := value.validateAuthorizedBySchedule(schedule); err != nil {
		return nil, err
	}
	if err := occurrence.ValidateAuthorizedBy(schedule); err != nil {
		return nil, err
	}
	if err := occurrence.ValidateAgainstItems(items); err != nil {
		return nil, err
	}
	if occurrence.ID != value.OccurrenceID || occurrence.DestinationKind != value.DestinationKind ||
		value.OccurrenceSnapshotDigest != occurrence.OccurrenceSnapshotDigest ||
		value.OperationBindingDigest != occurrence.OperationBinding.Digest() ||
		value.PolicySnapshotDigest != occurrence.PolicySnapshot.Digest() ||
		value.RetryPolicyDigest != occurrence.PolicySnapshot.PolicyBinding.RetryPolicy.Digest() ||
		value.CreatedAt < occurrence.EligibleAt || value.CreatedAt < occurrence.PolicySnapshot.AdmissionNotBeforeAt || value.CreatedAt >= occurrence.PolicySnapshot.ExecutionExpiresAt ||
		(value.DeadlineAt != nil && *value.DeadlineAt > occurrence.PolicySnapshot.ExecutionExpiresAt) {
		return nil, invalid("attempt.occurrenceAuthorization")
	}
	executionBoundary := occurrence.PolicySnapshot.ExecutionExpiresAt
	if value.DeadlineAt != nil && *value.DeadlineAt < executionBoundary {
		executionBoundary = *value.DeadlineAt
	}
	for _, assignment := range value.AssignmentPlan.Assignments {
		if assignment.InitialLease != nil && assignment.InitialLease.MaximumExpiresAt > executionBoundary {
			return nil, invalid("attempt.occurrenceAuthorization")
		}
	}
	policy := occurrence.PolicySnapshot.PolicyBinding.RetryPolicy
	if value.AttemptNumber > policy.MaximumAttempts() {
		return nil, invalid("attempt.retryLimit")
	}
	itemsByID := make(map[ItemID]ItemRecord, len(items))
	for _, item := range items {
		if uint64(len(item.Executions)) > policy.MaximumAttempts() {
			return nil, invalid("attempt.retryLimit")
		}
		if _, duplicate := itemsByID[item.ID]; duplicate {
			return nil, duplicateValue("occurrence.items")
		}
		itemsByID[item.ID] = item
	}
	planned := make([]ItemRecord, 0)
	plannedIDs := map[ItemID]AssignmentAuthorization{}
	for _, authorization := range value.AssignmentPlan.Assignments {
		for _, itemID := range authorization.ItemIDs {
			item, present := itemsByID[itemID]
			if !present {
				return nil, invalid("assignmentPlan.coverage")
			}
			if _, duplicate := plannedIDs[itemID]; duplicate {
				return nil, duplicateValue("assignmentPlan.coverage")
			}
			plannedIDs[itemID] = authorization
			planned = append(planned, item)
		}
	}
	if err := value.AssignmentPlan.ValidateCovers(itemIDs(planned)); err != nil {
		return nil, err
	}
	for _, item := range items {
		if _, included := plannedIDs[item.ID]; included {
			continue
		}
		if len(item.Executions) == 0 {
			if item.Disposition == nil || !oneOf(string(*item.Disposition), "skippedSourceMissing", "skippedSourceMissingBeforeDisclosure", "skippedSourceChangedBeforeDisclosure", "failedPreparation", "cancelledBeforeDisclosure") {
				return nil, invalid("assignmentPlan.omittedRunnableItem")
			}
		} else if item.Disposition == nil || item.CurrentExecution().CancellationUnconfirmed {
			return nil, invalid("assignmentPlan.priorAttemptOutcome")
		}
	}
	for _, item := range planned {
		authorization := plannedIDs[item.ID]
		current := item.CurrentExecution()
		if value.AttemptNumber == 1 {
			if current == nil || current.AttemptID != value.ID || current.AssignmentID != authorization.AssignmentID || current.Outcome != nil {
				return nil, invalid("assignmentPlan.itemAssignment")
			}
			if authorization.Executor.Kind == ExecutorSourceLocal {
				if current.WorkerID != nil {
					return nil, invalid("fixedWorkerSet")
				}
			} else if current.WorkerID == nil || *current.WorkerID != authorization.Executor.Worker.WorkerID {
				return nil, invalid("fixedWorkerSet")
			}
		} else {
			if current == nil || current.AttemptID == value.ID || item.Disposition != nil || !current.authorizesRetry() || current.CancellationUnconfirmed {
				return nil, invalid("assignmentPlan.itemRetryCandidate")
			}
		}
	}
	return planned, nil
}

func AuthorizeInitialAttempt(record AttemptRecord, schedule ScheduleRecord, occurrence OccurrenceRecord, items []ItemRecord) (AuthorizedAttempt, error) {
	planned, err := record.validateCreationBoundary(schedule, occurrence, items)
	if err != nil {
		return AuthorizedAttempt{}, err
	}
	if record.AttemptNumber != 1 || record.PreviousAttemptID != nil || record.RetryErrorID != nil || record.NotBeforeAt != nil {
		return AuthorizedAttempt{}, invalid("attempt.retryLineage")
	}
	for _, item := range planned {
		current := item.CurrentExecution()
		if len(item.Executions) != 1 || current == nil || current.AttemptID != record.ID || current.AttemptNumber != 1 || current.Outcome != nil {
			return AuthorizedAttempt{}, invalid("attempt.retryLineage")
		}
	}
	return newAuthorizedAttempt(record), nil
}

func AuthorizeRetryAttempt(record AttemptRecord, schedule ScheduleRecord, occurrence OccurrenceRecord, items []ItemRecord, previous AuthorizedAttempt, retryError ErrorRecord, previousTerminalTransition AttemptTransition, retryEvidence VerifiedReceipt) (AuthorizedAttempt, error) {
	planned, err := record.validateCreationBoundary(schedule, occurrence, items)
	if err != nil {
		return AuthorizedAttempt{}, err
	}
	prior := previous.record
	policy := occurrence.PolicySnapshot.PolicyBinding.RetryPolicy
	if record.AttemptNumber <= 1 || record.PreviousAttemptID == nil || *record.PreviousAttemptID != prior.ID || record.RetryErrorID == nil || *record.RetryErrorID != retryError.ID || record.NotBeforeAt == nil ||
		prior.OccurrenceID != record.OccurrenceID || prior.AttemptNumber == ^uint64(0) || record.AttemptNumber != prior.AttemptNumber+1 ||
		prior.OccurrenceSnapshotDigest != record.OccurrenceSnapshotDigest || prior.OperationBindingDigest != record.OperationBindingDigest || prior.PolicySnapshotDigest != record.PolicySnapshotDigest || prior.RetryPolicyDigest != record.RetryPolicyDigest || prior.ExecutionIdentity.Digest() != record.ExecutionIdentity.Digest() || prior.DestinationKind != record.DestinationKind || prior.SourceReceiptSigner != record.SourceReceiptSigner || !sameSigner(prior.CustodyReceiptSigner, record.CustodyReceiptSigner) ||
		!oneOf(string(prior.State), "retryableRejected", "executionFailed", "localExecutionFailed") || retryError.OccurrenceID != record.OccurrenceID || retryError.AttemptID == nil || *retryError.AttemptID != prior.ID || retryError.ItemID != nil || !retryError.Retryable || retryError.ObservedAt < prior.CreatedAt || retryError.ObservedAt > record.CreatedAt || !containsErrorCode(policy.RetryableErrorCodes, retryError.Code) {
		return AuthorizedAttempt{}, invalid("attempt.retryLineage")
	}
	for _, item := range planned {
		current := item.CurrentExecution()
		expectedOutcome := ItemAttemptOutcome("failedExecution")
		if prior.State == "retryableRejected" {
			expectedOutcome = "admissionRejected"
		}
		if current == nil || current.AttemptID != prior.ID || current.AttemptNumber != prior.AttemptNumber || current.ErrorID == nil || *current.ErrorID != retryError.ID || current.Outcome == nil || *current.Outcome != expectedOutcome || current.CancellationUnconfirmed {
			return AuthorizedAttempt{}, invalid("attempt.itemRetryLineage")
		}
	}
	if err := retryError.Validate(); err != nil {
		return AuthorizedAttempt{}, err
	}
	if err := previousTerminalTransition.Validate(); err != nil {
		return AuthorizedAttempt{}, err
	}
	expectedStage := ReceiptStage("localExecutionCompleted")
	if prior.State == "retryableRejected" {
		expectedStage = "admissionRejected"
	} else if prior.State == "executionFailed" {
		expectedStage = "executionCompleted"
	}
	evidenceRecord := retryEvidence.record
	if previousTerminalTransition.LifecycleID != LifecycleID(prior.ID) || previousTerminalTransition.To != prior.State || previousTerminalTransition.ResultingRevision != prior.Revision || previousTerminalTransition.Reason == nil || previousTerminalTransition.Reason.Code != "error" || previousTerminalTransition.Reason.ErrorID == nil || *previousTerminalTransition.Reason.ErrorID != retryError.ID || len(previousTerminalTransition.SupportingReceiptIDs) != 1 || previousTerminalTransition.SupportingReceiptIDs[0] != evidenceRecord.ID || previousTerminalTransition.OccurredAt < evidenceRecord.RecordedAt || previousTerminalTransition.OccurredAt > record.CreatedAt || !containsReceiptID(prior.ReceiptIDs, evidenceRecord.ID) || evidenceRecord.OccurrenceID != record.OccurrenceID || evidenceRecord.AttemptID != prior.ID || evidenceRecord.AssignmentID == nil || retryError.AssignmentID == nil || *evidenceRecord.AssignmentID != *retryError.AssignmentID || evidenceRecord.ItemID != nil || evidenceRecord.Stage != expectedStage || evidenceRecord.ErrorID == nil || *evidenceRecord.ErrorID != retryError.ID || evidenceRecord.ErrorDigest == nil || *evidenceRecord.ErrorDigest != retryError.Digest() || evidenceRecord.Authority != retryError.Authority || retryError.ObservedAt != evidenceRecord.RecordedAt {
		return AuthorizedAttempt{}, invalid("attempt.retryEvidence")
	}
	if err := prior.validateReceiptTrust(retryEvidence); err != nil {
		return AuthorizedAttempt{}, err
	}
	retryIndex := record.AttemptNumber - 2
	if retryIndex >= uint64(len(policy.BackoffMillisecondsByRetry)) {
		return AuthorizedAttempt{}, invalid("attempt.retryBackoff")
	}
	delay := policy.BackoffMillisecondsByRetry[retryIndex]
	if delay > uint64(^uint64(0)>>1) || retryError.ObservedAt > Timestamp(int64(^uint64(0)>>1))-Timestamp(delay) {
		return AuthorizedAttempt{}, invalid("attempt.retryBackoff")
	}
	expectedNotBefore := retryError.ObservedAt + Timestamp(delay)
	executionBoundary := occurrence.PolicySnapshot.ExecutionExpiresAt
	if record.DeadlineAt != nil && *record.DeadlineAt < executionBoundary {
		executionBoundary = *record.DeadlineAt
	}
	if *record.NotBeforeAt != expectedNotBefore || *record.NotBeforeAt >= executionBoundary {
		return AuthorizedAttempt{}, invalid("attempt.retryBackoff")
	}
	return newAuthorizedAttempt(record), nil
}

// AttemptAdvanceEvidence supplies the assignment barrier and replay context
// required to advance an already-authorized attempt. It is not a wire record.
type AttemptAdvanceEvidence struct {
	Assignments     []AssignmentRecord
	ResultManifests []AssignmentResultManifest
	AppliedEventIDs map[TransitionID]struct{}
}

func (value AuthorizedAttempt) Advance(updated AttemptRecord, transition AttemptTransition, receipts []VerifiedReceipt, evidence ...AttemptAdvanceEvidence) (AuthorizedAttempt, error) {
	previous := value.record
	if err := previous.Validate(); err != nil {
		return AuthorizedAttempt{}, err
	}
	if err := updated.Validate(); err != nil {
		return AuthorizedAttempt{}, err
	}
	if len(evidence) > 1 {
		return AuthorizedAttempt{}, invalid("attempt.advanceEvidence")
	}
	context := AttemptAdvanceEvidence{}
	if len(evidence) == 1 {
		context = evidence[0]
	}
	if updated.ID != previous.ID || updated.OccurrenceID != previous.OccurrenceID || updated.AttemptNumber != previous.AttemptNumber || updated.DestinationKind != previous.DestinationKind || updated.ExecutionIdentity.Digest() != previous.ExecutionIdentity.Digest() || updated.OccurrenceSnapshotDigest != previous.OccurrenceSnapshotDigest || updated.OperationBindingDigest != previous.OperationBindingDigest || updated.PolicySnapshotDigest != previous.PolicySnapshotDigest || updated.RetryPolicyDigest != previous.RetryPolicyDigest || !equalOptionalAttemptID(updated.PreviousAttemptID, previous.PreviousAttemptID) || !equalOptionalErrorID(updated.RetryErrorID, previous.RetryErrorID) || !equalOptionalTimestamp(updated.NotBeforeAt, previous.NotBeforeAt) || updated.AssignmentPlan.AssignmentSetDigest != previous.AssignmentPlan.AssignmentSetDigest || !equalOptionalDigest(updated.AuthorizedWorkerSetDigest, previous.AuthorizedWorkerSetDigest) || !equalOptionalDigest(updated.ComputePoolPolicyDigest, previous.ComputePoolPolicyDigest) || !equalOptionalDigest(updated.ComputePoolGrantDigest, previous.ComputePoolGrantDigest) || !equalOptionalDigest(updated.ComputePoolAssignmentSetDigest, previous.ComputePoolAssignmentSetDigest) || updated.SourceReceiptSigner != previous.SourceReceiptSigner || !sameSigner(updated.CustodyReceiptSigner, previous.CustodyReceiptSigner) || updated.CreatedAt != previous.CreatedAt || !equalOptionalTimestamp(updated.DeadlineAt, previous.DeadlineAt) || updated.Revision != transition.ResultingRevision || updated.State != transition.To {
		return AuthorizedAttempt{}, invalid("attempt.update")
	}
	if transition.To != "settled" && !equalOptionalDigest(updated.TerminalAssignmentOutcomesDigest, previous.TerminalAssignmentOutcomesDigest) {
		return AuthorizedAttempt{}, invalid("terminalAssignmentOutcomesDigest")
	}
	receiptIndex, err := newVerifiedReceiptIndex(receipts)
	if err != nil {
		return AuthorizedAttempt{}, err
	}
	sealed := (*Digest)(nil)
	if previous.State != "prepared" {
		digest := previous.AssignmentPlan.AssignmentSetDigest
		sealed = &digest
	}
	if err := transition.validateAgainst(previous.State, previous.Revision, LifecycleID(previous.ID), sealed, context.AppliedEventIDs, receiptIndex); err != nil {
		return AuthorizedAttempt{}, err
	}
	if transitionRequiresSealedDigest(transition.To) && (transition.SealedAssignmentSetDigest == nil || *transition.SealedAssignmentSetDigest != previous.AssignmentPlan.AssignmentSetDigest) {
		return AuthorizedAttempt{}, invalid("fixedWorkerSet")
	}
	for _, id := range updated.ReceiptIDs {
		receipt, present := receiptIndex.get(id)
		if !present {
			return AuthorizedAttempt{}, invalid("receiptIDs")
		}
		if err := previous.validateReceiptTrust(receipt); err != nil {
			return AuthorizedAttempt{}, err
		}
	}
	if !receiptSubset(previous.ReceiptIDs, updated.ReceiptIDs) || !receiptSubset(transition.SupportingReceiptIDs, updated.ReceiptIDs) {
		return AuthorizedAttempt{}, invalid("receiptIDs")
	}
	if transition.To != "sealed" {
		if err := value.validateAssignmentBarrier(updated, transition, context.Assignments, context.ResultManifests, receiptIndex); err != nil {
			return AuthorizedAttempt{}, err
		}
	}
	if transition.To == "released" {
		assignmentIDs := make([]AssignmentID, len(previous.AssignmentPlan.Assignments))
		for index, authorization := range previous.AssignmentPlan.Assignments {
			assignmentIDs[index] = authorization.AssignmentID
		}
		if err := requireExternalReleaseEvidence(previous.OccurrenceID, previous.ID, assignmentIDs, previous.ReceiptIDs, transition.SupportingReceiptIDs, receiptIndex); err != nil {
			return AuthorizedAttempt{}, err
		}
	}
	return newAuthorizedAttempt(updated), nil
}

func (value AuthorizedAttempt) validateAssignmentBarrier(
	updated AttemptRecord,
	transition AttemptTransition,
	assignments []AssignmentRecord,
	resultManifests []AssignmentResultManifest,
	receiptIndex verifiedReceiptIndex,
) error {
	if err := value.validateExactAssignments(assignments, verifiedReceiptSlice(receiptIndex)); err != nil {
		return err
	}
	if transition.To == "settled" {
		for _, assignment := range assignments {
			if !attemptTerminal(AttemptState(assignment.State)) {
				return invalid("attempt.assignmentBarrier")
			}
		}
		digest, err := MakeTerminalAssignmentOutcomesDigest(assignments)
		if err != nil || updated.TerminalAssignmentOutcomesDigest == nil || *updated.TerminalAssignmentOutcomesDigest != digest {
			return invalid("terminalAssignmentOutcomesDigest")
		}
		return nil
	}
	targetState := AssignmentState(transition.To)
	if !targetState.valid() {
		return nil
	}
	manifests, err := indexResultManifests(resultManifests)
	if err != nil {
		return err
	}
	for _, assignment := range assignments {
		if attemptTerminal(AttemptState(assignment.State)) && !attemptTerminal(transition.To) {
			continue
		}
		if assignment.State != targetState {
			return invalid("attempt.assignmentBarrier")
		}
		requiredStages := transitionRequiredReceiptStages(targetState)
		if len(requiredStages) > 0 {
			byStage, err := indexAssignmentStageReceipts(transition.SupportingReceiptIDs, receiptIndex, assignment.ID)
			if err != nil {
				return err
			}
			receipt, present := byStage[requiredStages[0]]
			if !present || !containsReceiptID(assignment.ReceiptIDs, receipt.record.ID) {
				return invalid("missingTransitionReceipt")
			}
		}
		switch transition.To {
		case "resultCustodied":
			manifest := manifests[assignment.ID]
			if err := assignment.validateSuccessfulResultEvidence(transition.SupportingReceiptIDs, receiptIndex, manifest, true); err != nil {
				return err
			}
		case "delivered":
			manifest := manifests[assignment.ID]
			if err := assignment.validateDeliveredResultEvidence(transition.SupportingReceiptIDs, receiptIndex, manifest); err != nil {
				return err
			}
		case "executionFailed":
			if err := assignment.validateFailedExecutionEvidence(transition.SupportingReceiptIDs, receiptIndex, true); err != nil {
				return err
			}
		}
	}
	return nil
}

func indexResultManifests(values []AssignmentResultManifest) (map[AssignmentID]*AssignmentResultManifest, error) {
	if len(values) > maximumAssignments {
		return nil, invalid("resultManifests")
	}
	result := make(map[AssignmentID]*AssignmentResultManifest, len(values))
	totalEntries := 0
	for index := range values {
		if err := values[index].Validate(); err != nil {
			return nil, err
		}
		totalEntries += len(values[index].Entries)
		if totalEntries > maximumItems {
			return nil, invalid("resultManifests.entries")
		}
		if _, duplicate := result[values[index].AssignmentID]; duplicate {
			return nil, duplicateValue("resultManifests.assignmentID")
		}
		result[values[index].AssignmentID] = &values[index]
	}
	return result, nil
}

func verifiedReceiptSlice(index verifiedReceiptIndex) []VerifiedReceipt {
	result := make([]VerifiedReceipt, 0, len(index.byID))
	for _, receipt := range index.byID {
		result = append(result, receipt)
	}
	return result
}

// ValidateAuthorizedBy accepts the non-wire proof rather than a raw Attempt.
// Capsule and lease bindings must match the immutable authorization exactly,
// including at the prepared->sealed boundary.
func (value AssignmentRecord) ValidateAuthorizedBy(attempt AuthorizedAttempt, receipts []VerifiedReceipt) error {
	if err := value.Validate(); err != nil {
		return err
	}
	record := attempt.record
	if err := record.Validate(); err != nil {
		return err
	}
	var authorization *AssignmentAuthorization
	for index := range record.AssignmentPlan.Assignments {
		if record.AssignmentPlan.Assignments[index].AssignmentID == value.ID {
			authorization = &record.AssignmentPlan.Assignments[index]
			break
		}
	}
	if authorization == nil || value.AttemptID != record.ID || value.OccurrenceID != record.OccurrenceID || !equalExecutorBinding(value.Executor, authorization.Executor) || !equalItemIDs(value.ItemIDs, authorization.ItemIDs) || value.ItemSetDigest != authorization.ItemSetDigest || value.ExecutionPayloadDigest != authorization.ExecutionPayloadDigest || !equalOptionalLease(value.InitialLease, authorization.InitialLease) || value.InitialCancellationFence != authorization.CancellationFence || value.SourceReceiptSigner != record.SourceReceiptSigner || !sameSigner(value.CustodyReceiptSigner, record.CustodyReceiptSigner) || !equalOptionalTimestamp(value.DeadlineAt, record.DeadlineAt) {
		return invalid("assignment.authorization")
	}
	if !assignmentFenceAuthorized(value, authorization.CancellationFence) {
		return invalid("assignment.cancellationFence")
	}
	if assignmentHasSealedItemSet(value.State) && (!equalOptionalJobCapsuleID(value.CapsuleID, authorization.CapsuleID) || !equalOptionalDigest(value.CapsuleDigest, authorization.CapsuleDigest)) {
		return invalid("assignment.capsuleAuthorization")
	}
	receiptIndex, err := newVerifiedReceiptIndex(receipts)
	if err != nil {
		return err
	}
	acceptedLeases, err := value.validatedLeaseHistory(receiptIndex)
	if err != nil {
		return err
	}
	for _, receiptID := range value.ReceiptIDs {
		receipt, present := receiptIndex.get(receiptID)
		if !present {
			return invalid("missingTransitionReceipt")
		}
		if err := value.validateReceiptTrustWithLeases(receipt, acceptedLeases); err != nil {
			return err
		}
	}
	return nil
}

func newAuthorizedAttempt(record AttemptRecord) AuthorizedAttempt {
	return AuthorizedAttempt{record: cloneAttemptRecord(record)}
}

// cloneAttemptRecord gives Go the value semantics that the corresponding
// Swift proof receives automatically. In particular, the caller's assignment
// plan and receipt slices cannot be mutated after authorization to widen what
// the proof permits, and Record never exposes the proof's backing storage.
func cloneAttemptRecord(value AttemptRecord) AttemptRecord {
	result := value
	result.PreviousAttemptID = clonePointer(value.PreviousAttemptID)
	result.RetryErrorID = clonePointer(value.RetryErrorID)
	result.NotBeforeAt = clonePointer(value.NotBeforeAt)
	result.AssignmentPlan.Assignments = make([]AssignmentAuthorization, len(value.AssignmentPlan.Assignments))
	for index, authorization := range value.AssignmentPlan.Assignments {
		cloned := authorization
		cloned.Executor = cloneExecutorBinding(authorization.Executor)
		cloned.ItemIDs = append([]ItemID(nil), authorization.ItemIDs...)
		cloned.CapsuleID = clonePointer(authorization.CapsuleID)
		cloned.CapsuleDigest = clonePointer(authorization.CapsuleDigest)
		cloned.InitialLease = clonePointer(authorization.InitialLease)
		result.AssignmentPlan.Assignments[index] = cloned
	}
	result.AuthorizedWorkerSetDigest = clonePointer(value.AuthorizedWorkerSetDigest)
	result.ComputePoolPolicyDigest = clonePointer(value.ComputePoolPolicyDigest)
	result.ComputePoolGrantDigest = clonePointer(value.ComputePoolGrantDigest)
	result.ComputePoolAssignmentSetDigest = clonePointer(value.ComputePoolAssignmentSetDigest)
	result.CustodyReceiptSigner = clonePointer(value.CustodyReceiptSigner)
	result.TerminalAssignmentOutcomesDigest = clonePointer(value.TerminalAssignmentOutcomesDigest)
	result.DeadlineAt = clonePointer(value.DeadlineAt)
	if value.ReceiptIDs != nil {
		result.ReceiptIDs = make([]ReceiptID, len(value.ReceiptIDs))
		copy(result.ReceiptIDs, value.ReceiptIDs)
	}
	return result
}

func cloneExecutorBinding(value ExecutorBinding) ExecutorBinding {
	result := value
	result.SourceLocal = clonePointer(value.SourceLocal)
	result.Worker = clonePointer(value.Worker)
	return result
}

func clonePointer[T any](value *T) *T {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func (value AttemptRecord) validateReceiptTrust(receipt VerifiedReceipt) error {
	record := receipt.record
	expectedSigner, expectedSubject, err := value.expectedReceiptTrust(record)
	if err != nil {
		return err
	}
	if !receipt.matches(expectedSigner, expectedSubject) {
		return invalid("receipt.subjectDigest")
	}
	return nil
}

func (value AttemptRecord) expectedReceiptTrust(record ReceiptRecord) (ReceiptSignerBinding, Digest, error) {
	if record.OccurrenceID != value.OccurrenceID || record.AttemptID != value.ID {
		return ReceiptSignerBinding{}, "", invalid("receipt.attemptID")
	}
	var authorization *AssignmentAuthorization
	if record.AssignmentID != nil {
		for index := range value.AssignmentPlan.Assignments {
			if value.AssignmentPlan.Assignments[index].AssignmentID == *record.AssignmentID {
				authorization = &value.AssignmentPlan.Assignments[index]
				break
			}
		}
	}
	var expectedSigner ReceiptSignerBinding
	if oneOf(string(record.Stage), "localExecutionStarted", "localExecutionCompleted", "localReleased", "localCancellationConfirmed") {
		if authorization == nil || authorization.Executor.SourceLocal == nil {
			return ReceiptSignerBinding{}, "", invalid("receipt.signer")
		}
		expectedSigner = authorization.Executor.SourceLocal.ReceiptSigner
	} else {
		switch receiptAuthority(record.Stage) {
		case AuthoritySourceDevice:
			expectedSigner = value.SourceReceiptSigner
		case AuthorityJobCustody:
			if value.CustodyReceiptSigner == nil {
				return ReceiptSignerBinding{}, "", invalid("receipt.signer")
			}
			expectedSigner = *value.CustodyReceiptSigner
		case AuthorityWorker:
			if authorization == nil || authorization.Executor.Worker == nil {
				return ReceiptSignerBinding{}, "", invalid("receipt.signer")
			}
			expectedSigner = authorization.Executor.Worker.ReceiptSigner
		default:
			return ReceiptSignerBinding{}, "", invalid("receipt.signer")
		}
	}
	expectedSubject := value.attemptReceiptSubjectDigest(record, authorization)
	return expectedSigner, expectedSubject, nil
}

func (value AttemptRecord) attemptReceiptSubjectDigest(receipt ReceiptRecord, authorization *AssignmentAuthorization) Digest {
	if authorization != nil {
		return authorization.receiptSubjectDigest(value.OccurrenceID, value.ID, receipt)
	}
	return SHA256Digest("facets.compute-queue.attempt-receipt-subject.v1", string(value.OccurrenceID), string(value.ID), string(value.DestinationKind), string(value.ExecutionIdentity.Digest()), string(value.AssignmentPlan.AssignmentSetDigest), string(receipt.Stage), optionalItemID(receipt.ItemID), optionalErrorID(receipt.ErrorID), optionalDigest(receipt.ErrorDigest))
}

func MakeTerminalAssignmentOutcomesDigest(assignments []AssignmentRecord) (Digest, error) {
	if len(assignments) == 0 || len(assignments) > maximumAssignments {
		return "", invalid("terminalAssignments")
	}
	ordered := append([]AssignmentRecord(nil), assignments...)
	sortAssignments(ordered)
	components := []string{}
	previous := AssignmentID("")
	for _, assignment := range ordered {
		if err := assignment.Validate(); err != nil {
			return "", err
		}
		if assignment.ID == previous || !attemptTerminal(AttemptState(assignment.State)) {
			return "", invalid("terminalAssignments")
		}
		previous = assignment.ID
		components = append(components, string(assignment.ID), string(assignment.AttemptID), fmt.Sprint(assignment.Revision), string(assignment.State), assignment.Executor.stableID(), string(assignment.ItemSetDigest), string(assignment.ExecutionPayloadDigest), optionalJobCapsuleID(assignment.CapsuleID), optionalDigest(assignment.CapsuleDigest))
		for _, id := range assignment.ReceiptIDs {
			components = append(components, string(id))
		}
	}
	return SHA256Digest("facets.compute-queue.terminal-assignment-outcomes.v1", components...), nil
}

func itemIDs(items []ItemRecord) []ItemID {
	result := make([]ItemID, len(items))
	for index, item := range items {
		result[index] = item.ID
	}
	return result
}
func containsErrorCode(values []ErrorCode, value ErrorCode) bool {
	for _, current := range values {
		if current == value {
			return true
		}
	}
	return false
}
func containsReceiptID(values []ReceiptID, value ReceiptID) bool {
	for _, current := range values {
		if current == value {
			return true
		}
	}
	return false
}
func receiptSubset(left, right []ReceiptID) bool {
	set := map[ReceiptID]struct{}{}
	for _, id := range right {
		set[id] = struct{}{}
	}
	for _, id := range left {
		if _, ok := set[id]; !ok {
			return false
		}
	}
	return true
}
func equalOptionalAttemptID(left, right *AttemptID) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}
func equalOptionalTimestamp(left, right *Timestamp) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}
func equalOptionalDigest(left, right *Digest) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}
func equalOptionalJobCapsuleID(left, right *JobCapsuleID) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}
func equalOptionalLease(left, right *LeaseBinding) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}
func equalItemIDs(left, right []ItemID) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
func assignmentFenceAuthorized(value AssignmentRecord, authorizedFence uint64) bool {
	if value.Executor.Kind == ExecutorSourceLocal {
		return value.CancellationFence == 0
	}
	nextFence := authorizedFence + 1
	canIncrement := authorizedFence != ^uint64(0)
	if oneOf(string(value.State), "custodyCancellationRequested", "custodyCancellationConfirmed", "workerCancellationRequested", "workerCancellationConfirmed", "uncertainTermination") {
		return canIncrement && value.CancellationFence == nextFence
	}
	if value.State == "released" {
		return value.CancellationFence == authorizedFence || (canIncrement && value.CancellationFence == nextFence)
	}
	return value.CancellationFence == authorizedFence
}
func sortAssignments(values []AssignmentRecord) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j].ID < values[j-1].ID; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}
