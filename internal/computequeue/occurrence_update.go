package computequeue

// OccurrenceUpdateEvidence is the complete non-wire proof bundle required to
// publish an occurrence transition. Keeping it explicit prevents a caller
// from advancing source-authoritative state with decoded attempts or receipts.
type OccurrenceUpdateEvidence struct {
	Receipts           []VerifiedReceipt
	ActiveAttempt      *AuthorizedAttempt
	AuthorizedAttempts []AuthorizedAttempt
	Assignments        []AssignmentRecord
	Items              []ItemRecord
	ResultManifests    []AssignmentResultManifest
	ErrorRecords       []ErrorRecord
	AppliedEventIDs    map[TransitionID]struct{}
}

// ValidateTransitionUpdateFrom is the source publication boundary for an occurrence
// transition. It binds the resulting record to the event, rejects counter or
// receipt rollback, and requires complete terminal evidence before terminal
// state can be persisted.
func (value OccurrenceRecord) ValidateTransitionUpdateFrom(previous OccurrenceRecord, transition OccurrenceTransition, evidence OccurrenceUpdateEvidence) error {
	if err := value.Validate(); err != nil {
		return err
	}
	if value.ID != previous.ID || value.ScheduleID != previous.ScheduleID ||
		value.DestinationKind != previous.DestinationKind || value.EligibilityKey != previous.EligibilityKey ||
		value.EligibilityDigest != previous.EligibilityDigest || value.ScheduledFor != previous.ScheduledFor ||
		value.EligibleAt != previous.EligibleAt || value.ScheduleRevision != previous.ScheduleRevision ||
		value.TargetSetDigest != previous.TargetSetDigest || value.OperationBinding.Digest() != previous.OperationBinding.Digest() ||
		value.PolicySnapshot.Digest() != previous.PolicySnapshot.Digest() ||
		value.ExecutionIdentityDigest != previous.ExecutionIdentityDigest ||
		value.DestinationPolicyDigest != previous.DestinationPolicyDigest ||
		value.OccurrenceSnapshotDigest != previous.OccurrenceSnapshotDigest ||
		value.SourceReceiptSigner != previous.SourceReceiptSigner || !sameSigner(value.CustodyReceiptSigner, previous.CustodyReceiptSigner) ||
		value.Revision != transition.ResultingRevision || value.State != transition.To ||
		value.LastTransitionID == nil || *value.LastTransitionID != transition.ID ||
		value.StateChangedAt != transition.OccurredAt || !sameTransitionReason(value.LastReason, transition.Reason) ||
		!equalOptionalErrorID(value.LastErrorID, transitionReasonErrorID(transition.Reason)) {
		return invalid("occurrence")
	}
	if previous.PreparedAt != nil && !equalOptionalTimestamp(value.PreparedAt, previous.PreparedAt) {
		return invalid("preparedAt")
	}
	if value.Report.Targeted != previous.Report.Targeted {
		return invalid("counters.targeted")
	}
	oldCounters, newCounters := previous.Report.values(), value.Report.values()
	for index := 1; index < len(oldCounters)-1; index++ {
		if newCounters[index] < oldCounters[index] {
			return invalid("counters.regression")
		}
	}
	if value.State == "completedWithErrors" && oneOf(string(previous.State), "preparing", "waitingForSpace", "waitingForStorage") {
		if value.Report.Submitted != 0 || value.Report.Completed != 0 || value.Report.Applied != 0 ||
			value.Report.ResultNotAppliedSourceMissing != 0 || value.Report.ResultNotAppliedSourceChanged != 0 ||
			value.Report.FailedExecution != 0 || value.Report.InvalidResult != 0 ||
			value.Report.CancelledAfterDisclosure != 0 || value.Report.TerminalCount() != value.Report.Targeted {
			return invalid("counters.preExecutionTerminal")
		}
	}
	if !receiptSubset(previous.ReceiptIDs, value.ReceiptIDs) || !receiptSubset(transition.SupportingReceiptIDs, value.ReceiptIDs) {
		return invalid("receiptIDs")
	}
	if err := previous.ValidateTransition(transition, evidence.Receipts, evidence.ActiveAttempt, evidence.AuthorizedAttempts, evidence.Assignments, evidence.Items, evidence.AppliedEventIDs); err != nil {
		return err
	}
	if !occurrenceTerminal(value.State) {
		return nil
	}
	if err := value.ValidateAgainstItems(evidence.Items); err != nil {
		return err
	}
	receiptIndex, err := newVerifiedReceiptIndex(evidence.Receipts)
	if err != nil {
		return err
	}
	if err := value.validateTerminalResultEvidence(evidence.Items, evidence.AuthorizedAttempts, evidence.Assignments, evidence.ResultManifests, evidence.ErrorRecords, receiptIndex); err != nil {
		return err
	}
	for _, item := range evidence.Items {
		if err := item.validateApplication(receiptIndex, value.SourceReceiptSigner); err != nil {
			return err
		}
		if item.ApplicationReceiptID != nil && !containsReceiptID(value.ReceiptIDs, *item.ApplicationReceiptID) {
			return invalid("missingTransitionReceipt")
		}
	}
	return nil
}

func sameTransitionReason(left, right *TransitionReason) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.Code == right.Code && equalOptionalErrorID(left.ErrorID, right.ErrorID)
}

func transitionReasonErrorID(value *TransitionReason) *ErrorID {
	if value == nil {
		return nil
	}
	return value.ErrorID
}

type assignmentExecutionSummary struct {
	itemCount                     int
	terminalOutcomeCount          int
	outcomes                      map[ItemAttemptOutcome]struct{}
	errorIDs                      map[ErrorID]struct{}
	hasCancellationUnconfirmed    bool
	hasProtectedByteParticipation bool
}

func (value OccurrenceRecord) validateTerminalResultEvidence(
	items []ItemRecord,
	authorizedAttempts []AuthorizedAttempt,
	assignments []AssignmentRecord,
	resultManifests []AssignmentResultManifest,
	errorRecords []ErrorRecord,
	receiptIndex verifiedReceiptIndex,
) error {
	hasExecutionEvidence := false
	for _, item := range items {
		if len(item.Executions) > 0 {
			hasExecutionEvidence = true
			break
		}
	}
	if !hasExecutionEvidence {
		if len(resultManifests) != 0 || len(assignments) != 0 || len(authorizedAttempts) != 0 || len(errorRecords) != 0 {
			return invalid("terminal.assignmentEvidence")
		}
		return nil
	}
	if len(authorizedAttempts) > maximumAssignments || len(errorRecords) > maximumItems+maximumAssignments {
		return invalid("terminal.attemptEvidence")
	}
	attemptsByID := make(map[AttemptID]AuthorizedAttempt, len(authorizedAttempts))
	for _, proof := range authorizedAttempts {
		attempt := proof.record
		if err := attempt.Validate(); err != nil {
			return err
		}
		if attempt.OccurrenceID != value.ID || attempt.OccurrenceSnapshotDigest != value.OccurrenceSnapshotDigest {
			return invalid("terminal.attemptEvidence")
		}
		if _, duplicate := attemptsByID[attempt.ID]; duplicate {
			return invalid("terminal.attemptEvidence")
		}
		attemptsByID[attempt.ID] = proof
	}
	if len(assignments) > maximumAssignments {
		return invalid("assignments")
	}
	assignmentsByID := make(map[AssignmentID]AssignmentRecord, len(assignments))
	assignmentsByAttempt := make(map[AttemptID][]AssignmentRecord)
	for _, assignment := range assignments {
		if err := assignment.Validate(); err != nil {
			return err
		}
		if _, duplicate := assignmentsByID[assignment.ID]; duplicate {
			return duplicateValue("assignments")
		}
		assignmentsByID[assignment.ID] = assignment
		assignmentsByAttempt[assignment.AttemptID] = append(assignmentsByAttempt[assignment.AttemptID], assignment)
	}
	itemsByID := make(map[ItemID]ItemRecord, len(items))
	for _, item := range items {
		if _, duplicate := itemsByID[item.ID]; duplicate {
			return duplicateValue("items")
		}
		itemsByID[item.ID] = item
	}
	indexedManifests, err := indexResultManifests(resultManifests)
	if err != nil {
		return err
	}
	manifestsByAssignment := make(map[AssignmentID]AssignmentResultManifest, len(indexedManifests))
	for assignmentID, manifestPointer := range indexedManifests {
		manifest := *manifestPointer
		assignment, present := assignmentsByID[assignmentID]
		if !present {
			return invalid("resultManifest.assignmentID")
		}
		if err := manifest.ValidateAuthorizedBy(assignment, value.ID); err != nil {
			return err
		}
		if err := manifest.validateAgainstItemIndex(itemsByID); err != nil {
			return err
		}
		manifestsByAssignment[assignmentID] = manifest
	}
	errorsByID := make(map[ErrorID]ErrorRecord, len(errorRecords))
	for _, record := range errorRecords {
		if err := record.Validate(); err != nil {
			return err
		}
		if record.OccurrenceID != value.ID {
			return invalid("terminal.errorRecords")
		}
		if _, duplicate := errorsByID[record.ID]; duplicate {
			return invalid("terminal.errorRecords")
		}
		errorsByID[record.ID] = record
	}
	summaries := make(map[AssignmentID]*assignmentExecutionSummary)
	usedAttempts := make(map[AttemptID]struct{})
	for _, item := range items {
		for _, execution := range item.Executions {
			proof, proofPresent := attemptsByID[execution.AttemptID]
			assignment, assignmentPresent := assignmentsByID[execution.AssignmentID]
			if !proofPresent || !assignmentPresent || proof.record.AttemptNumber != execution.AttemptNumber ||
				assignment.AttemptID != execution.AttemptID || assignment.OccurrenceID != value.ID || !containsItemID(assignment.ItemIDs, item.ID) {
				return invalid("terminal.executionAuthorization")
			}
			var authorization *AssignmentAuthorization
			for index := range proof.record.AssignmentPlan.Assignments {
				candidate := &proof.record.AssignmentPlan.Assignments[index]
				if candidate.AssignmentID == execution.AssignmentID {
					authorization = candidate
					break
				}
			}
			if authorization == nil || !containsItemID(authorization.ItemIDs, item.ID) {
				return invalid("terminal.executionAuthorization")
			}
			var expectedWorkerID *WorkerID
			if authorization.Executor.Worker != nil {
				workerID := authorization.Executor.Worker.WorkerID
				expectedWorkerID = &workerID
			}
			if !equalOptionalWorkerID(execution.WorkerID, expectedWorkerID) {
				return invalid("terminal.executionAuthorization")
			}
			usedAttempts[execution.AttemptID] = struct{}{}
			summary := summaries[execution.AssignmentID]
			if summary == nil {
				summary = &assignmentExecutionSummary{outcomes: map[ItemAttemptOutcome]struct{}{}, errorIDs: map[ErrorID]struct{}{}}
				summaries[execution.AssignmentID] = summary
			}
			summary.itemCount++
			if execution.Outcome != nil {
				summary.terminalOutcomeCount++
				summary.outcomes[*execution.Outcome] = struct{}{}
			}
			if execution.ErrorID != nil {
				summary.errorIDs[*execution.ErrorID] = struct{}{}
			}
			summary.hasCancellationUnconfirmed = summary.hasCancellationUnconfirmed || execution.CancellationUnconfirmed
			if execution.DestinationKind == DestinationDirectLocal {
				summary.hasProtectedByteParticipation = summary.hasProtectedByteParticipation || execution.ExecutionInputCommittedAt != nil
			} else {
				summary.hasProtectedByteParticipation = summary.hasProtectedByteParticipation || execution.DisclosureCommittedAt != nil || execution.CustodyAcceptedAt != nil
			}
		}
	}
	if len(assignmentsByID) != len(summaries) || len(attemptsByID) != len(usedAttempts) || len(assignmentsByAttempt) != len(usedAttempts) {
		return invalid("terminal.assignmentCoverage")
	}
	for attemptID, attemptAssignments := range assignmentsByAttempt {
		proof, present := attemptsByID[attemptID]
		if !present {
			return invalid("terminal.attemptCoverage")
		}
		if err := proof.validateExactAssignments(attemptAssignments, verifiedReceiptSlice(receiptIndex)); err != nil {
			return err
		}
		if proof.record.State == "settled" {
			digest, err := MakeTerminalAssignmentOutcomesDigest(attemptAssignments)
			if err != nil || proof.record.TerminalAssignmentOutcomesDigest == nil || *proof.record.TerminalAssignmentOutcomesDigest != digest {
				return invalid("terminal.attemptOutcome")
			}
		} else {
			for _, assignment := range attemptAssignments {
				if string(assignment.State) != string(proof.record.State) {
					return invalid("terminal.attemptOutcome")
				}
			}
		}
	}
	usedManifests := make(map[AssignmentID]struct{})
	usedErrors := make(map[ErrorID]struct{})
	receiptErrorIDs := make(map[ErrorID]struct{})
	sourceRejectionReceiptIDs := make(map[ReceiptID]struct{})
	usedSourceRejectionReceiptIDs := make(map[ReceiptID]struct{})
	for assignmentID, summary := range summaries {
		assignment := assignmentsByID[assignmentID]
		if assignment.OccurrenceID != value.ID || summary.itemCount != len(assignment.ItemIDs) ||
			summary.terminalOutcomeCount != summary.itemCount || summary.hasCancellationUnconfirmed ||
			!receiptSubset(assignment.ReceiptIDs, value.ReceiptIDs) {
			return invalid("terminal.incompleteAssignmentOutcome")
		}
		for _, receiptID := range assignment.ReceiptIDs {
			receipt, present := receiptIndex.get(receiptID)
			if !present {
				return invalid("missingTransitionReceipt")
			}
			signer, signerPresent := assignment.expectedSigner(receipt.record)
			if !signerPresent || receipt.record.OccurrenceID != value.ID || receipt.record.AttemptID != assignment.AttemptID ||
				receipt.record.AssignmentID == nil || *receipt.record.AssignmentID != assignment.ID ||
				!receipt.matches(signer, assignment.receiptSubjectDigest(receipt.record)) {
				return invalid("missingTransitionReceipt")
			}
			if receipt.record.Stage == "sourceResultRejected" {
				sourceRejectionReceiptIDs[receiptID] = struct{}{}
			}
			if receipt.record.ErrorID != nil {
				receiptErrorIDs[*receipt.record.ErrorID] = struct{}{}
			}
		}
		if assignment.State == "released" {
			if err := requireExternalReleaseEvidence(value.ID, assignment.AttemptID, []AssignmentID{assignment.ID}, assignment.ReceiptIDs, assignment.ReceiptIDs, receiptIndex); err != nil {
				return err
			}
		} else if assignment.State == "localReleased" {
			found := false
			for _, receiptID := range assignment.ReceiptIDs {
				receipt, _ := receiptIndex.get(receiptID)
				found = found || (receipt.record.Stage == "localReleased" && assignment.terminalReceiptMatchesCurrentLease(receipt))
			}
			if !found {
				return invalid("missingTransitionReceipt")
			}
		}
		if manifest, present := manifestsByAssignment[assignmentID]; present {
			usedManifests[assignmentID] = struct{}{}
			if err := validateTerminalManifestAssignment(value, assignment, summary, manifest, items, attemptsByID, errorsByID, usedErrors, usedSourceRejectionReceiptIDs, receiptIndex); err != nil {
				return err
			}
		} else if err := validateManifestlessTerminalAssignment(value, assignment, summary, items, attemptsByID, errorsByID, usedErrors, receiptIndex); err != nil {
			return err
		}
	}
	if len(usedManifests) != len(manifestsByAssignment) || !sameErrorIDSet(usedErrors, errorsByID) ||
		!errorIDSetSubset(receiptErrorIDs, usedErrors) || !sameReceiptIDSet(usedSourceRejectionReceiptIDs, sourceRejectionReceiptIDs) {
		return invalid("terminal.unusedEvidence")
	}
	return nil
}

func validateTerminalManifestAssignment(
	occurrence OccurrenceRecord,
	assignment AssignmentRecord,
	summary *assignmentExecutionSummary,
	manifest AssignmentResultManifest,
	items []ItemRecord,
	attemptsByID map[AttemptID]AuthorizedAttempt,
	errorsByID map[ErrorID]ErrorRecord,
	usedErrors map[ErrorID]struct{},
	usedSourceRejections map[ReceiptID]struct{},
	receiptIndex verifiedReceiptIndex,
) error {
	stages := assignmentReceiptStageSet(assignment, receiptIndex, false)
	if containsAnyReceiptStage(stages, "admissionRejected", "leaseExpired") {
		return invalid("terminal.incompatibleErrorEvidence")
	}
	hasInvalidResult := false
	if _, present := summary.outcomes["invalidResult"]; present {
		hasInvalidResult = true
	}
	if assignment.Executor.Kind == ExecutorSourceLocal {
		stateIsInvalid := assignment.State == "localInvalidResult"
		if stateIsInvalid != hasInvalidResult || (!stateIsInvalid && !oneOf(string(assignment.State), "localResultReady", "localApplied", "localReleased")) ||
			!containsAnyReceiptStage(stages, "localExecutionStarted") {
			return invalid("missingTransitionReceipt")
		}
		var completions []VerifiedReceipt
		for _, id := range assignment.ReceiptIDs {
			receipt, _ := receiptIndex.get(id)
			if receipt.record.Stage == "localExecutionCompleted" {
				completions = append(completions, receipt)
			}
		}
		if len(completions) != 1 || completions[0].record.ExecutionOutcome == nil || *completions[0].record.ExecutionOutcome != "succeeded" || completions[0].record.ResultDigest == nil || *completions[0].record.ResultDigest != manifest.ResultSetDigest {
			return invalid("missingTransitionReceipt")
		}
		for _, execution := range executionsForAssignment(items, assignment.ID) {
			if execution.ResultCompletedAt != nil {
				if err := validateSuccessfulResultChronology(execution, completions[0].record.RecordedAt, nil, nil); err != nil {
					return err
				}
			}
		}
	} else {
		stateIsInvalid := assignment.State == "invalidResult"
		if stateIsInvalid != hasInvalidResult || (!stateIsInvalid && !oneOf(string(assignment.State), "delivered", "applied", "released")) ||
			!summary.hasProtectedByteParticipation || !containsAnyReceiptStage(stages, "custodyAccepted") || !containsAnyReceiptStage(stages, "executionStarted") {
			return invalid("missingTransitionReceipt")
		}
		resultReceiptIDs, err := assignmentResultEvidenceReceiptIDs(assignment, receiptIndex)
		if err != nil {
			return err
		}
		if err := assignment.validateDeliveredResultEvidence(resultReceiptIDs, receiptIndex, &manifest); err != nil {
			return err
		}
		var executionCompletedAt, resultCustodiedAt, resultDeliveredAt *Timestamp
		for _, id := range assignment.ReceiptIDs {
			receipt, _ := receiptIndex.get(id)
			if !assignment.terminalReceiptMatchesCurrentLease(receipt) {
				continue
			}
			timestamp := receipt.record.RecordedAt
			switch receipt.record.Stage {
			case "executionCompleted":
				executionCompletedAt = &timestamp
			case "resultCustodied":
				resultCustodiedAt = &timestamp
			case "resultDelivered":
				resultDeliveredAt = &timestamp
			}
		}
		if executionCompletedAt == nil || resultCustodiedAt == nil || resultDeliveredAt == nil {
			return invalid("missingTransitionReceipt")
		}
		for _, execution := range executionsForAssignment(items, assignment.ID) {
			if execution.ResultCompletedAt != nil {
				if err := validateSuccessfulResultChronology(execution, *executionCompletedAt, resultCustodiedAt, resultDeliveredAt); err != nil {
					return err
				}
			}
		}
	}
	entriesByItem := make(map[ItemID]AssignmentResultEntry, len(manifest.Entries))
	for _, entry := range manifest.Entries {
		entriesByItem[entry.ItemID] = entry
	}
	for _, item := range items {
		for _, execution := range item.Executions {
			if execution.AssignmentID != assignment.ID || execution.ErrorID == nil ||
				(execution.Outcome == nil || !oneOf(string(*execution.Outcome), "failedExecution", "invalidResult")) {
				continue
			}
			entry, entryPresent := entriesByItem[item.ID]
			errorRecord, errorPresent := errorsByID[*execution.ErrorID]
			attempt, attemptPresent := attemptsByID[assignment.AttemptID]
			if !entryPresent || !errorPresent || !attemptPresent ||
				validateErrorHierarchy(errorRecord, occurrence, &attempt.record, &assignment, &item, &execution) != nil {
				return invalid("missingTransitionReceipt")
			}
			if *execution.Outcome == "failedExecution" {
				expectedAuthority := AuthorityWorker
				if assignment.Executor.Kind == ExecutorSourceLocal {
					expectedAuthority = AuthoritySourceDevice
				}
				if entry.Outcome != "failed" || entry.ErrorID == nil || *entry.ErrorID != errorRecord.ID ||
					entry.ErrorDigest == nil || *entry.ErrorDigest != errorRecord.Digest() || errorRecord.Authority != expectedAuthority {
					return invalid("missingTransitionReceipt")
				}
				if err := validateTerminalEvidenceChronology(execution, nil, &errorRecord); err != nil {
					return err
				}
				usedErrors[errorRecord.ID] = struct{}{}
				continue
			}
			if entry.Outcome != "succeeded" || errorRecord.Authority != AuthoritySourceDevice {
				return invalid("missingTransitionReceipt")
			}
			matched := false
			for _, receiptID := range assignment.ReceiptIDs {
				rejection, _ := receiptIndex.get(receiptID)
				record := rejection.record
				if record.Stage == "sourceResultRejected" && record.ItemID != nil && *record.ItemID == item.ID &&
					equalOptionalDigest(record.ResultDigest, execution.ResultDigest) && record.ErrorID != nil && *record.ErrorID == errorRecord.ID &&
					record.ErrorDigest != nil && *record.ErrorDigest == errorRecord.Digest() && assignment.terminalReceiptMatchesCurrentLease(rejection) &&
					errorRecord.ObservedAt == record.RecordedAt {
					if err := validateTerminalEvidenceChronology(execution, &record.RecordedAt, &errorRecord); err != nil {
						return err
					}
					usedErrors[errorRecord.ID] = struct{}{}
					usedSourceRejections[receiptID] = struct{}{}
					matched = true
					break
				}
			}
			if !matched {
				return invalid("missingTransitionReceipt")
			}
		}
	}
	return nil
}

func assignmentResultEvidenceReceiptIDs(
	assignment AssignmentRecord,
	receiptIndex verifiedReceiptIndex,
) ([]ReceiptID, error) {
	result := make([]ReceiptID, 0, len(assignment.ReceiptIDs))
	for _, receiptID := range assignment.ReceiptIDs {
		receipt, present := receiptIndex.get(receiptID)
		if !present {
			return nil, invalid("missingTransitionReceipt")
		}
		if receipt.record.Stage != "sourceResultRejected" {
			result = append(result, receiptID)
		}
	}
	return result, nil
}

func validateManifestlessTerminalAssignment(
	occurrence OccurrenceRecord,
	assignment AssignmentRecord,
	summary *assignmentExecutionSummary,
	items []ItemRecord,
	attemptsByID map[AttemptID]AuthorizedAttempt,
	errorsByID map[ErrorID]ErrorRecord,
	usedErrors map[ErrorID]struct{},
	receiptIndex verifiedReceiptIndex,
) error {
	stages := assignmentReceiptStageSet(assignment, receiptIndex, false)
	if len(summary.outcomes) == 1 {
		if _, allFailed := summary.outcomes["failedExecution"]; allFailed {
			validState := (assignment.Executor.Kind == ExecutorSourceLocal && oneOf(string(assignment.State), "localExecutionFailed", "localReleased")) ||
				(assignment.Executor.Kind == ExecutorWorker && oneOf(string(assignment.State), "executionFailed", "released"))
			hasAntecedents := containsAnyReceiptStage(stages, "localExecutionStarted")
			if assignment.Executor.Kind == ExecutorWorker {
				hasAntecedents = summary.hasProtectedByteParticipation && containsAnyReceiptStage(stages, "custodyAccepted") && containsAnyReceiptStage(stages, "executionStarted")
			}
			if !validState || !hasAntecedents || len(summary.errorIDs) != 1 {
				return invalid("missingTransitionReceipt")
			}
			stages, err := indexAssignmentStageReceipts(assignment.ReceiptIDs, receiptIndex, assignment.ID)
			if err != nil || assignment.validateFailedExecutionEvidence(assignment.ReceiptIDs, receiptIndex, true) != nil {
				return invalid("missingTransitionReceipt")
			}
			failureStage := ReceiptStage("executionCompleted")
			if assignment.Executor.Kind == ExecutorSourceLocal {
				failureStage = "localExecutionCompleted"
			}
			failure, present := stages[failureStage]
			if !present || failure.record.ErrorID == nil || failure.record.ErrorDigest == nil {
				return invalid("missingTransitionReceipt")
			}
			errorRecord, present := errorsByID[*failure.record.ErrorID]
			if !present || !errorIDSetEqualsOne(summary.errorIDs, errorRecord.ID) || errorRecord.Digest() != *failure.record.ErrorDigest ||
				errorRecord.AttemptID == nil || *errorRecord.AttemptID != assignment.AttemptID || errorRecord.AssignmentID == nil || *errorRecord.AssignmentID != assignment.ID ||
				errorRecord.ItemID != nil || errorRecord.Authority != failure.record.Authority || errorRecord.ObservedAt != failure.record.RecordedAt {
				return invalid("missingTransitionReceipt")
			}
			attempt, present := attemptsByID[assignment.AttemptID]
			if !present || validateErrorHierarchy(errorRecord, occurrence, &attempt.record, &assignment, nil, nil) != nil {
				return invalid("missingTransitionReceipt")
			}
			for _, execution := range executionsForAssignment(items, assignment.ID) {
				if err := validateTerminalEvidenceChronology(execution, &failure.record.RecordedAt, &errorRecord); err != nil {
					return err
				}
			}
			usedErrors[errorRecord.ID] = struct{}{}
			return nil
		}
		if _, allAdmissionRejected := summary.outcomes["admissionRejected"]; allAdmissionRejected {
			if assignment.State != "retryableRejected" || len(summary.errorIDs) != 1 {
				return invalid("missingTransitionReceipt")
			}
			for _, id := range assignment.ReceiptIDs {
				receipt, _ := receiptIndex.get(id)
				if receipt.record.Stage == "admissionRejected" && receipt.record.ErrorID != nil && receipt.record.ErrorDigest != nil {
					errorRecord, present := errorsByID[*receipt.record.ErrorID]
					attempt, attemptPresent := attemptsByID[assignment.AttemptID]
					if present && attemptPresent && errorIDSetEqualsOne(summary.errorIDs, errorRecord.ID) && errorRecord.Digest() == *receipt.record.ErrorDigest &&
						errorRecord.Authority == AuthorityJobCustody && errorRecord.AttemptID != nil && *errorRecord.AttemptID == assignment.AttemptID &&
						errorRecord.AssignmentID != nil && *errorRecord.AssignmentID == assignment.ID && errorRecord.ItemID == nil && errorRecord.Retryable &&
						receipt.record.RecordedAt == errorRecord.ObservedAt && assignment.terminalReceiptMatchesCurrentLease(receipt) &&
						validateErrorHierarchy(errorRecord, occurrence, &attempt.record, &assignment, nil, nil) == nil {
						for _, execution := range executionsForAssignment(items, assignment.ID) {
							if err := validateTerminalEvidenceChronology(execution, &receipt.record.RecordedAt, &errorRecord); err != nil {
								return err
							}
						}
						usedErrors[errorRecord.ID] = struct{}{}
						return nil
					}
				}
			}
			return invalid("missingTransitionReceipt")
		}
	}
	for outcome := range summary.outcomes {
		if !oneOf(string(outcome), "cancelledBeforeDisclosure", "cancelledAfterDisclosure") {
			return invalid("missingTransitionReceipt")
		}
	}
	if len(summary.outcomes) == 0 {
		return invalid("missingTransitionReceipt")
	}
	receiptParticipation := containsAnyReceiptStage(stages, "localExecutionStarted", "localExecutionCompleted")
	if assignment.Executor.Kind == ExecutorWorker {
		receiptParticipation = containsAnyReceiptStage(stages, "custodyAccepted", "waitingForWorker", "workerClaimed", "executionStarted", "executionCompleted", "resultCustodied", "resultDelivered")
	}
	hasParticipation := summary.hasProtectedByteParticipation || receiptParticipation
	currentStages := assignmentReceiptStageSet(assignment, receiptIndex, true)
	var acceptedExpiry *VerifiedReceipt
	for _, id := range assignment.ReceiptIDs {
		receipt, _ := receiptIndex.get(id)
		if receipt.record.Stage == "leaseExpired" && receipt.record.ErrorID != nil && receipt.record.ErrorDigest != nil && assignment.terminalReceiptMatchesCurrentLease(receipt) {
			candidate := receipt
			acceptedExpiry = &candidate
			break
		}
	}
	if err := validateCancellationRequestSemantics(hasParticipation, acceptedExpiry != nil, currentStages); err != nil {
		return err
	}
	if !hasParticipation {
		if !oneOf(string(assignment.State), "prepared", "sealed", "custodyCancellationConfirmed", "workerCancellationConfirmed", "localCancellationConfirmed", "released", "localReleased") {
			return invalid("missingTransitionReceipt")
		}
		return nil
	}
	validState := (assignment.Executor.Kind == ExecutorSourceLocal && oneOf(string(assignment.State), "localCancellationConfirmed", "localReleased")) ||
		(assignment.Executor.Kind == ExecutorWorker && oneOf(string(assignment.State), "custodyCancellationConfirmed", "workerCancellationConfirmed", "expired", "released"))
	if !validState {
		return invalid("missingTransitionReceipt")
	}
	if acceptedExpiry != nil {
		record := acceptedExpiry.record
		if record.ErrorID == nil || record.ErrorDigest == nil {
			return invalid("missingTransitionReceipt")
		}
		errorRecord, errorPresent := errorsByID[*record.ErrorID]
		attempt, attemptPresent := attemptsByID[assignment.AttemptID]
		if !errorPresent || !attemptPresent || errorRecord.Digest() != *record.ErrorDigest || errorRecord.Authority != AuthorityJobCustody ||
			errorRecord.AttemptID == nil || *errorRecord.AttemptID != assignment.AttemptID || errorRecord.AssignmentID == nil || *errorRecord.AssignmentID != assignment.ID ||
			errorRecord.ItemID != nil || errorRecord.ObservedAt != record.RecordedAt || validateErrorHierarchy(errorRecord, occurrence, &attempt.record, &assignment, nil, nil) != nil {
			return invalid("missingTransitionReceipt")
		}
		for _, execution := range executionsForAssignment(items, assignment.ID) {
			if err := validateTerminalEvidenceChronology(execution, &record.RecordedAt, &errorRecord); err != nil {
				return err
			}
		}
		usedErrors[errorRecord.ID] = struct{}{}
		return nil
	}
	if err := requireOccurrenceCancellationEvidence(occurrence.DestinationKind, occurrence.ID, []AssignmentID{assignment.ID}, assignment.ReceiptIDs, assignment.ReceiptIDs, receiptIndex); err != nil {
		return err
	}
	requiredStages := []ReceiptStage{"localCancellationConfirmed"}
	if assignment.Executor.Kind == ExecutorWorker {
		requiredStages = []ReceiptStage{"custodyCancellationConfirmed"}
		if containsAnyReceiptStage(stages, "workerClaimed", "executionStarted", "executionCompleted") {
			requiredStages = append(requiredStages, "workerCancellationConfirmed")
		}
	}
	if !containsAnyReceiptStage(currentStages, "cancellationRequested") {
		return invalid("missingTransitionReceipt")
	}
	for _, stage := range requiredStages {
		if !containsAnyReceiptStage(currentStages, stage) {
			return invalid("missingTransitionReceipt")
		}
	}
	var requestAt *Timestamp
	currentRecords := make([]ReceiptRecord, 0)
	for _, id := range assignment.ReceiptIDs {
		receipt, _ := receiptIndex.get(id)
		if !assignment.terminalReceiptMatchesCurrentLease(receipt) || !oneOf(string(receipt.record.Stage), "cancellationRequested", "custodyCancellationConfirmed", "workerCancellationConfirmed", "localCancellationConfirmed") {
			continue
		}
		currentRecords = append(currentRecords, receipt.record)
		if receipt.record.Stage == "cancellationRequested" {
			timestamp := receipt.record.RecordedAt
			requestAt = &timestamp
		}
	}
	if requestAt == nil {
		return invalid("missingTransitionReceipt")
	}
	for _, record := range currentRecords {
		if record.Stage != "cancellationRequested" && record.RecordedAt < *requestAt {
			return invalid("receipt.timestamp")
		}
		for _, execution := range executionsForAssignment(items, assignment.ID) {
			if err := validateTerminalEvidenceChronology(execution, &record.RecordedAt, nil); err != nil {
				return err
			}
		}
	}
	return nil
}

func executionsForAssignment(items []ItemRecord, assignmentID AssignmentID) []ItemExecutionRecord {
	result := make([]ItemExecutionRecord, 0)
	for _, item := range items {
		for _, execution := range item.Executions {
			if execution.AssignmentID == assignmentID {
				result = append(result, execution)
			}
		}
	}
	return result
}

func assignmentReceiptStageSet(assignment AssignmentRecord, receiptIndex verifiedReceiptIndex, currentLeaseOnly bool) map[ReceiptStage]struct{} {
	result := make(map[ReceiptStage]struct{})
	for _, id := range assignment.ReceiptIDs {
		receipt, present := receiptIndex.get(id)
		if !present || (currentLeaseOnly && !assignment.terminalReceiptMatchesCurrentLease(receipt)) {
			continue
		}
		result[receipt.record.Stage] = struct{}{}
	}
	return result
}

func validateCancellationRequestSemantics(hasProtectedByteParticipation, acceptedExpiry bool, currentStages map[ReceiptStage]struct{}) error {
	confirmationsPresent := containsAnyReceiptStage(currentStages, "custodyCancellationConfirmed", "workerCancellationConfirmed", "localCancellationConfirmed")
	if acceptedExpiry {
		if !containsAnyReceiptStage(currentStages, "leaseExpired") || (confirmationsPresent && !containsAnyReceiptStage(currentStages, "cancellationRequested")) {
			return invalid("missingTransitionReceipt")
		}
		return nil
	}
	if hasProtectedByteParticipation {
		if !containsAnyReceiptStage(currentStages, "cancellationRequested") {
			return invalid("missingTransitionReceipt")
		}
		return nil
	}
	if confirmationsPresent || containsAnyReceiptStage(currentStages, "leaseExpired") {
		return invalid("missingTransitionReceipt")
	}
	return nil
}

func validateTerminalEvidenceChronology(execution ItemExecutionRecord, evidenceAt *Timestamp, errorRecord *ErrorRecord) error {
	var lowerBound *Timestamp
	for _, candidate := range []*Timestamp{execution.ResultCompletedAt, execution.CustodyAcceptedAt, execution.DisclosureCommittedAt, execution.ExecutionInputCommittedAt} {
		if candidate != nil {
			lowerBound = candidate
			break
		}
	}
	if evidenceAt != nil && lowerBound != nil && *evidenceAt < *lowerBound {
		return invalid("receipt.timestamp")
	}
	if evidenceAt != nil && execution.TerminalAt != nil && *evidenceAt > *execution.TerminalAt {
		return invalid("receipt.timestamp")
	}
	if errorRecord != nil {
		if lowerBound != nil && errorRecord.ObservedAt < *lowerBound {
			return invalid("error.timestamp")
		}
		if execution.TerminalAt != nil && errorRecord.ObservedAt > *execution.TerminalAt {
			return invalid("error.timestamp")
		}
	}
	return nil
}

func validateSuccessfulResultChronology(execution ItemExecutionRecord, executionCompletedAt Timestamp, resultCustodiedAt, resultDeliveredAt *Timestamp) error {
	if execution.ResultCompletedAt == nil || *execution.ResultCompletedAt > executionCompletedAt {
		return invalid("receipt.timestamp")
	}
	if resultCustodiedAt != nil && executionCompletedAt > *resultCustodiedAt {
		return invalid("receipt.timestamp")
	}
	if resultDeliveredAt != nil && (resultCustodiedAt == nil || *resultCustodiedAt > *resultDeliveredAt) {
		return invalid("receipt.timestamp")
	}
	return nil
}

func validateErrorHierarchy(record ErrorRecord, occurrence OccurrenceRecord, attempt *AttemptRecord, assignment *AssignmentRecord, item *ItemRecord, execution *ItemExecutionRecord) error {
	if err := record.Validate(); err != nil {
		return err
	}
	if record.OccurrenceID != occurrence.ID || !equalOptionalAttemptID(record.AttemptID, attemptIDPointer(attempt)) ||
		!equalOptionalAssignmentID(record.AssignmentID, assignmentIDPointerOrNil(assignment)) || !equalOptionalItemID(record.ItemID, itemIDPointerOrNil(item)) {
		return invalid("error.lifecycleHierarchy")
	}
	if attempt != nil && attempt.OccurrenceID != occurrence.ID {
		return invalid("error.lifecycleHierarchy")
	}
	if assignment != nil && (attempt == nil || assignment.OccurrenceID != occurrence.ID || assignment.AttemptID != attempt.ID) {
		return invalid("error.lifecycleHierarchy")
	}
	if item != nil {
		if execution == nil || item.OccurrenceID != occurrence.ID || execution.OccurrenceID != occurrence.ID || execution.ItemID != item.ID ||
			attempt == nil || execution.AttemptID != attempt.ID || assignment == nil || execution.AssignmentID != assignment.ID ||
			execution.ErrorID == nil || *execution.ErrorID != record.ID || !containsItemExecution(item.Executions, *execution) {
			return invalid("error.lifecycleHierarchy")
		}
	} else if execution != nil {
		return invalid("error.lifecycleHierarchy")
	}
	return nil
}

func containsItemExecution(values []ItemExecutionRecord, expected ItemExecutionRecord) bool {
	for _, value := range values {
		if equalItemExecution(value, expected) {
			return true
		}
	}
	return false
}

func attemptIDPointer(value *AttemptRecord) *AttemptID {
	if value == nil {
		return nil
	}
	return &value.ID
}

func assignmentIDPointerOrNil(value *AssignmentRecord) *AssignmentID {
	if value == nil {
		return nil
	}
	return &value.ID
}

func itemIDPointerOrNil(value *ItemRecord) *ItemID {
	if value == nil {
		return nil
	}
	return &value.ID
}

func equalOptionalAssignmentID(left, right *AssignmentID) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}

func equalOptionalItemID(left, right *ItemID) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}

func errorIDSetEqualsOne(values map[ErrorID]struct{}, expected ErrorID) bool {
	_, present := values[expected]
	return len(values) == 1 && present
}

func sameErrorIDSet(used map[ErrorID]struct{}, all map[ErrorID]ErrorRecord) bool {
	if len(used) != len(all) {
		return false
	}
	for id := range all {
		if _, present := used[id]; !present {
			return false
		}
	}
	return true
}

func errorIDSetSubset(subset, superset map[ErrorID]struct{}) bool {
	for id := range subset {
		if _, present := superset[id]; !present {
			return false
		}
	}
	return true
}

func sameReceiptIDSet(left, right map[ReceiptID]struct{}) bool {
	if len(left) != len(right) {
		return false
	}
	for id := range left {
		if _, present := right[id]; !present {
			return false
		}
	}
	return true
}
