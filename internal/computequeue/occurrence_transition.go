package computequeue

// ValidateTransition validates one occurrence event without accepting a raw
// Attempt as authority. Any transition that depends on active execution must
// receive the non-wire AuthorizedAttempt proof created at the fail-closed
// schedule/occurrence/retry boundary.
func (value OccurrenceRecord) ValidateTransition(
	transition OccurrenceTransition,
	receipts []VerifiedReceipt,
	activeAttempt *AuthorizedAttempt,
	authorizedAttempts []AuthorizedAttempt,
	assignments []AssignmentRecord,
	items []ItemRecord,
	appliedEventIDs map[TransitionID]struct{},
) error {
	receiptIndex, err := newVerifiedReceiptIndex(receipts)
	if err != nil {
		return err
	}
	if len(assignments) > maximumAssignments {
		return invalid("assignments")
	}
	if len(items) > maximumItems {
		return invalid("items")
	}
	assignmentIndex := make(map[AssignmentID]AssignmentRecord, len(assignments))
	for _, assignment := range assignments {
		if err := assignment.Validate(); err != nil {
			return err
		}
		if _, duplicate := assignmentIndex[assignment.ID]; duplicate {
			return duplicateValue("assignments")
		}
		assignmentIndex[assignment.ID] = assignment
	}
	itemIndex := make(map[ItemID]ItemRecord, len(items))
	for _, item := range items {
		if err := item.Validate(); err != nil {
			return err
		}
		if _, duplicate := itemIndex[item.ID]; duplicate {
			return duplicateValue("items")
		}
		itemIndex[item.ID] = item
	}
	proofsByAttemptID := make(map[AttemptID]AuthorizedAttempt, len(authorizedAttempts)+1)
	for _, proof := range authorizedAttempts {
		if existing, duplicate := proofsByAttemptID[proof.record.ID]; duplicate {
			if !sameAuthorizedAttempt(existing, proof) {
				return duplicateValue("occurrence.authorizedAttempt")
			}
			continue
		}
		proofsByAttemptID[proof.record.ID] = proof
	}
	if activeAttempt != nil {
		if existing, duplicate := proofsByAttemptID[activeAttempt.record.ID]; duplicate {
			if !sameAuthorizedAttempt(existing, *activeAttempt) {
				return duplicateValue("occurrence.authorizedAttempt")
			}
		} else {
			proofsByAttemptID[activeAttempt.record.ID] = *activeAttempt
		}
	}
	if err := transition.validateAgainst(value.State, value.Revision, LifecycleID(value.ID), nil, appliedEventIDs, receiptIndex); err != nil {
		return err
	}
	if transition.OccurredAt < value.StateChangedAt {
		return invalid("transition.occurredAt")
	}
	assignmentEvidenceAttempts := make(map[AttemptID]struct{})
	for _, id := range append(append([]ReceiptID(nil), value.ReceiptIDs...), transition.SupportingReceiptIDs...) {
		if receipt, present := receiptIndex.get(id); present && receipt.record.AssignmentID != nil {
			assignmentEvidenceAttempts[receipt.record.AttemptID] = struct{}{}
		}
	}
	for attemptID := range assignmentEvidenceAttempts {
		proof, present := proofsByAttemptID[attemptID]
		if !present || proof.record.OccurrenceID != value.ID || proof.record.DestinationKind != value.DestinationKind {
			return invalid("missingTransitionReceipt")
		}
		attemptAssignments := assignmentsForAttempt(assignments, attemptID)
		if err := proof.validateExactAssignments(attemptAssignments, receipts); err != nil {
			return err
		}
	}
	for _, id := range value.ReceiptIDs {
		receipt, present := receiptIndex.get(id)
		if !present {
			return invalid("receiptIDs")
		}
		if err := value.validateReceiptTrust(receipt, proofsByAttemptID, assignmentIndex, itemIndex); err != nil {
			return err
		}
	}
	for _, id := range transition.SupportingReceiptIDs {
		receipt, present := receiptIndex.get(id)
		if !present || receipt.record.OccurrenceID != value.ID {
			return invalid("transition.receipts")
		}
		if err := value.validateReceiptTrust(receipt, proofsByAttemptID, assignmentIndex, itemIndex); err != nil {
			return err
		}
	}
	if transition.To == "securelyQueued" {
		if activeAttempt == nil || activeAttempt.record.OccurrenceID != value.ID || activeAttempt.record.DestinationKind != value.DestinationKind {
			return invalid("occurrence.activeAttempt")
		}
		activeAssignments := assignmentsForAttempt(assignments, activeAttempt.record.ID)
		if err := activeAttempt.validateExactAssignments(activeAssignments, receipts); err != nil {
			return err
		}
		// Every assignment supplied to this source transition must already be
		// safely custodied. Restricting this check to the active plan would let
		// an unrelated decoded assignment bypass the queue admission boundary.
		for _, assignment := range assignments {
			if oneOf(string(assignment.State), "prepared", "sealed", "admissionPending", "retryableRejected") {
				return invalid("occurrence.assignments")
			}
			found := false
			for _, receiptID := range transition.SupportingReceiptIDs {
				receipt, _ := receiptIndex.get(receiptID)
				record := receipt.record
				if record.AssignmentID != nil && *record.AssignmentID == assignment.ID && record.Stage == "custodyAccepted" && containsReceiptID(assignment.ReceiptIDs, record.ID) {
					found = true
					break
				}
			}
			if !found {
				return invalid("occurrence.custodyAccepted")
			}
		}
	}
	if oneOf(string(transition.To), "cancelled", "completedWithErrors") && oneOf(string(transition.From), "cancellationRequested", "cancellationUnconfirmed") {
		requiredAssignmentIDs := make([]AssignmentID, 0, len(items))
		for _, item := range items {
			if current := item.CurrentExecution(); current != nil {
				requiredAssignmentIDs = append(requiredAssignmentIDs, current.AssignmentID)
			}
		}
		if err := requireOccurrenceCancellationEvidence(value.DestinationKind, value.ID, requiredAssignmentIDs, value.ReceiptIDs, transition.SupportingReceiptIDs, receiptIndex); err != nil {
			return err
		}
	}
	return nil
}

func requireOccurrenceCancellationEvidence(
	destinationKind DestinationKind,
	occurrenceID OccurrenceID,
	requiredAssignmentIDs []AssignmentID,
	durableReceiptIDs []ReceiptID,
	supportingReceiptIDs []ReceiptID,
	receiptIndex verifiedReceiptIndex,
) error {
	if len(requiredAssignmentIDs) > maximumItems {
		return invalid("requiredAssignmentIDs")
	}
	required := make(map[AssignmentID]struct{})
	for _, assignmentID := range requiredAssignmentIDs {
		required[assignmentID] = struct{}{}
	}
	if len(required) > maximumAssignments {
		return invalid("requiredAssignmentIDs")
	}
	for _, receiptID := range uniqueReceiptIDs(durableReceiptIDs, supportingReceiptIDs) {
		receipt, present := receiptIndex.get(receiptID)
		if !present || receipt.record.OccurrenceID != occurrenceID {
			return invalid("missingTransitionReceipt")
		}
	}
	historyStages := receiptStagesByAssignment(durableReceiptIDs, receiptIndex)
	confirmationStages := receiptStagesByAssignment(supportingReceiptIDs, receiptIndex)
	participating := make(map[AssignmentID]struct{}, len(required))
	for assignmentID := range required {
		participating[assignmentID] = struct{}{}
	}
	for assignmentID, stages := range historyStages {
		if destinationKind == DestinationDirectLocal {
			if containsAnyReceiptStage(stages, "localExecutionStarted", "localExecutionCompleted") {
				participating[assignmentID] = struct{}{}
			}
		} else if containsAnyReceiptStage(stages, "custodyAccepted", "waitingForWorker", "workerClaimed", "executionStarted", "executionCompleted", "resultCustodied") {
			participating[assignmentID] = struct{}{}
		}
	}
	for assignmentID := range participating {
		history := historyStages[assignmentID]
		confirmations := confirmationStages[assignmentID]
		if destinationKind == DestinationDirectLocal {
			if !containsAnyReceiptStage(confirmations, "localCancellationConfirmed") {
				return invalid("missingTransitionReceipt")
			}
			continue
		}
		workerParticipated := containsAnyReceiptStage(history, "workerClaimed", "executionStarted", "executionCompleted")
		_, explicitlyRequired := required[assignmentID]
		custodyParticipated := workerParticipated || explicitlyRequired || containsAnyReceiptStage(history, "custodyAccepted", "waitingForWorker", "resultCustodied")
		if custodyParticipated && !containsAnyReceiptStage(confirmations, "custodyCancellationConfirmed") {
			return invalid("missingTransitionReceipt")
		}
		if workerParticipated && !containsAnyReceiptStage(confirmations, "workerCancellationConfirmed") {
			return invalid("missingTransitionReceipt")
		}
	}
	return nil
}

func (value OccurrenceRecord) validateReceiptTrust(receipt VerifiedReceipt, authorizedAttempts map[AttemptID]AuthorizedAttempt, assignments map[AssignmentID]AssignmentRecord, items map[ItemID]ItemRecord) error {
	record := receipt.record
	if record.OccurrenceID != value.ID {
		return invalid("receipt.occurrenceID")
	}
	if record.Stage == "sourceApplied" && record.ItemID != nil {
		item, present := items[*record.ItemID]
		if !present || !receipt.matches(value.SourceReceiptSigner, item.ApplicationProofDigest()) {
			return invalid("receipt.sourceApplied")
		}
		return nil
	}
	if record.AssignmentID != nil {
		assignment, present := assignments[*record.AssignmentID]
		proof, proofPresent := authorizedAttempts[record.AttemptID]
		if !present || !proofPresent || assignment.AttemptID != proof.record.ID {
			return invalid("receipt.assignmentID")
		}
		signer, signerPresent := assignment.expectedSigner(record)
		if !signerPresent {
			return invalid("receipt.signer")
		}
		if !receipt.matches(signer, assignment.receiptSubjectDigest(record)) {
			return invalid("receipt.signer")
		}
		return nil
	}
	if record.Authority != AuthoritySourceDevice {
		return invalid("receipt.signer")
	}
	expected := SHA256Digest("facets.compute-queue.occurrence-receipt-subject.v1", string(value.ID), string(value.ScheduleID), string(value.TargetSetDigest), string(value.OccurrenceSnapshotDigest), string(record.AttemptID), string(record.Stage), optionalItemID(record.ItemID))
	if !receipt.matches(value.SourceReceiptSigner, expected) {
		return invalid("receipt.subjectDigest")
	}
	return nil
}

func assignmentsForAttempt(assignments []AssignmentRecord, attemptID AttemptID) []AssignmentRecord {
	result := make([]AssignmentRecord, 0)
	for _, assignment := range assignments {
		if assignment.AttemptID == attemptID {
			result = append(result, assignment)
		}
	}
	return result
}

func sameAuthorizedAttempt(left, right AuthorizedAttempt) bool {
	leftBytes, leftErr := EncodeCanonical(left.record)
	rightBytes, rightErr := EncodeCanonical(right.record)
	return leftErr == nil && rightErr == nil && string(leftBytes) == string(rightBytes)
}

// validateExactAssignments prevents a decoded assignment from selecting the
// signer or capsule binding used to authenticate assignment-scoped evidence.
func (value AuthorizedAttempt) validateExactAssignments(assignments []AssignmentRecord, receipts []VerifiedReceipt) error {
	expected := value.record.AssignmentPlan.Assignments
	if len(assignments) != len(expected) {
		return invalid("fixedWorkerSetMutation")
	}
	ordered := append([]AssignmentRecord(nil), assignments...)
	sortAssignments(ordered)
	for index, assignment := range ordered {
		if assignment.ID != expected[index].AssignmentID {
			return invalid("fixedWorkerSetMutation")
		}
		if err := assignment.ValidateAuthorizedBy(value, receipts); err != nil {
			return err
		}
	}
	return nil
}

func receiptMatchesSigner(receipt ReceiptRecord, signer ReceiptSignerBinding) bool {
	return receipt.SignerID == signer.SignerID && receipt.SigningKeyID == signer.SigningKeyID && receipt.SigningKeyRevision == signer.SigningKeyRevision
}
