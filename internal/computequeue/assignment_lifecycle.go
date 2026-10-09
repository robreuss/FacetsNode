package computequeue

import "sort"

// ValidateUpdateFrom validates a same-state assignment revision. Both records
// must remain authorized by the same non-wire Attempt proof; this keeps raw
// decoded assignments from becoming lifecycle advancement authority.
func (value AssignmentRecord) ValidateUpdateFrom(
	previous AssignmentRecord,
	authorizedBy AuthorizedAttempt,
	receipts []VerifiedReceipt,
) error {
	if err := value.Validate(); err != nil {
		return err
	}
	if value.State != previous.State {
		return invalid("assignment.state")
	}
	if value.ID != previous.ID || value.AttemptID != previous.AttemptID ||
		previous.Revision == ^uint64(0) || value.Revision != previous.Revision+1 ||
		!equalExecutorBinding(value.Executor, previous.Executor) ||
		value.OccurrenceID != previous.OccurrenceID ||
		value.ExecutionPayloadDigest != previous.ExecutionPayloadDigest ||
		!equalOptionalLease(value.InitialLease, previous.InitialLease) ||
		!equalOptionalLease(value.CurrentLease, previous.CurrentLease) ||
		value.InitialCancellationFence != previous.InitialCancellationFence ||
		value.CancellationFence != previous.CancellationFence ||
		value.SourceReceiptSigner != previous.SourceReceiptSigner ||
		!sameSigner(value.CustodyReceiptSigner, previous.CustodyReceiptSigner) ||
		value.ItemSetDigest != previous.ItemSetDigest {
		return invalid("assignment.update")
	}
	if assignmentHasSealedItemSet(previous.State) &&
		(!equalOptionalJobCapsuleID(value.CapsuleID, previous.CapsuleID) ||
			!equalOptionalDigest(value.CapsuleDigest, previous.CapsuleDigest)) {
		return invalid("assignment.capsuleMutation")
	}
	if value.CreatedAt != previous.CreatedAt ||
		!equalOptionalTimestamp(value.DeadlineAt, previous.DeadlineAt) ||
		!receiptSubset(previous.ReceiptIDs, value.ReceiptIDs) {
		return invalid("assignment.lifecycle")
	}
	if err := previous.ValidateAuthorizedBy(authorizedBy, receipts); err != nil {
		return err
	}
	return value.ValidateAuthorizedBy(authorizedBy, receipts)
}

func (value AssignmentRecord) ValidateLeaseRenewalFrom(
	previous AssignmentRecord,
	authorizedBy AuthorizedAttempt,
	receipt VerifiedReceipt,
	receipts []VerifiedReceipt,
) error {
	if err := value.Validate(); err != nil {
		return err
	}
	receiptIndex, err := newVerifiedReceiptIndex(receipts)
	if err != nil {
		return err
	}
	indexedReceipt, present := receiptIndex.get(receipt.record.ID)
	if !present || !sameVerifiedReceipt(indexedReceipt, receipt) {
		return invalid("missingTransitionReceipt")
	}
	if err := previous.ValidateAuthorizedBy(authorizedBy, receipts); err != nil {
		return err
	}
	if err := value.ValidateAuthorizedBy(authorizedBy, receipts); err != nil {
		return err
	}
	if value.Executor.Kind != ExecutorWorker || !oneOf(string(previous.State), "claimed", "executing") || value.State != previous.State || value.ID != previous.ID || value.OccurrenceID != previous.OccurrenceID || value.AttemptID != previous.AttemptID || !equalExecutorBinding(value.Executor, previous.Executor) || value.ItemSetDigest != previous.ItemSetDigest || value.ExecutionPayloadDigest != previous.ExecutionPayloadDigest || !equalOptionalJobCapsuleID(value.CapsuleID, previous.CapsuleID) || !equalOptionalDigest(value.CapsuleDigest, previous.CapsuleDigest) || !equalOptionalLease(value.InitialLease, previous.InitialLease) || value.InitialCancellationFence != previous.InitialCancellationFence || value.SourceReceiptSigner != previous.SourceReceiptSigner || !sameSigner(value.CustodyReceiptSigner, previous.CustodyReceiptSigner) || value.CreatedAt != previous.CreatedAt || !equalOptionalTimestamp(value.DeadlineAt, previous.DeadlineAt) || value.CancellationFence != previous.CancellationFence || previous.Revision == ^uint64(0) || value.Revision != previous.Revision+1 || value.CurrentLease == nil || previous.CurrentLease == nil {
		return invalid("assignmentLeaseRenewal")
	}
	if err := value.CurrentLease.ValidateRenewal(*previous.CurrentLease); err != nil {
		return err
	}
	record := receipt.record
	if record.OccurrenceID != value.OccurrenceID || record.AttemptID != value.AttemptID || record.AssignmentID == nil || *record.AssignmentID != value.ID || record.Stage != "leaseRenewed" || record.LeaseID == nil || *record.LeaseID != value.CurrentLease.ID || record.LeaseRevision == nil || *record.LeaseRevision != value.CurrentLease.Revision || record.LeaseExpiresAt == nil || *record.LeaseExpiresAt != value.CurrentLease.ExpiresAt || record.CancellationFence != value.CancellationFence || record.RecordedAt != value.CurrentLease.IssuedAt || record.RecordedAt > previous.CurrentLease.ExpiresAt || value.Executor.Worker == nil || !receipt.matches(value.Executor.Worker.ReceiptSigner, value.receiptSubjectDigest(record)) {
		return invalid("assignmentLeaseRenewal.receipt")
	}
	if !containsReceiptID(value.ReceiptIDs, record.ID) || !receiptSubset(previous.ReceiptIDs, value.ReceiptIDs) {
		return invalid("assignmentLeaseRenewal.receiptIDs")
	}
	return nil
}

func (value AssignmentRecord) ValidateTransitionFrom(
	previous AssignmentRecord,
	transition AssignmentTransition,
	authorizedBy AuthorizedAttempt,
	receipts []VerifiedReceipt,
	resultManifest *AssignmentResultManifest,
	appliedEventIDs map[TransitionID]struct{},
) error {
	if err := value.Validate(); err != nil {
		return err
	}
	if value.ID != previous.ID || value.OccurrenceID != previous.OccurrenceID || value.AttemptID != previous.AttemptID || !equalExecutorBinding(value.Executor, previous.Executor) || value.ExecutionPayloadDigest != previous.ExecutionPayloadDigest || !equalOptionalLease(value.InitialLease, previous.InitialLease) || !equalOptionalLease(value.CurrentLease, previous.CurrentLease) || value.SourceReceiptSigner != previous.SourceReceiptSigner || !sameSigner(value.CustodyReceiptSigner, previous.CustodyReceiptSigner) || value.Revision != transition.ResultingRevision || value.State != transition.To || value.ItemSetDigest != previous.ItemSetDigest || value.CreatedAt != previous.CreatedAt || !equalOptionalTimestamp(value.DeadlineAt, previous.DeadlineAt) {
		return invalid("assignment.update")
	}
	if previous.State != "prepared" && (!equalOptionalJobCapsuleID(value.CapsuleID, previous.CapsuleID) || !equalOptionalDigest(value.CapsuleDigest, previous.CapsuleDigest)) {
		return invalid("assignment.capsuleMutation")
	}
	if !receiptSubset(previous.ReceiptIDs, value.ReceiptIDs) || !receiptSubset(transition.SupportingReceiptIDs, value.ReceiptIDs) {
		return invalid("assignment.receiptIDs")
	}
	if err := previous.ValidateAuthorizedBy(authorizedBy, receipts); err != nil {
		return err
	}
	if err := value.ValidateAuthorizedBy(authorizedBy, receipts); err != nil {
		return err
	}
	cancellationRequest := oneOf(string(transition.To), "custodyCancellationRequested", "workerCancellationRequested")
	if cancellationRequest {
		if previous.CancellationFence == ^uint64(0) || value.CancellationFence != previous.CancellationFence+1 {
			return invalid("assignment.cancellationFence")
		}
	} else if value.CancellationFence != previous.CancellationFence {
		return invalid("assignment.cancellationFence")
	}
	receiptIndex, err := newVerifiedReceiptIndex(receipts)
	if err != nil {
		return err
	}
	switch value.Executor.Kind {
	case ExecutorSourceLocal:
		if transition.LeaseID != nil || transition.LeaseRevision != nil || transition.CancellationFence != 0 {
			return invalid("assignment.transitionLease")
		}
	case ExecutorWorker:
		expectedFence := previous.CancellationFence
		if cancellationRequest {
			if previous.CancellationFence == ^uint64(0) {
				return invalid("assignment.transitionLease")
			}
			expectedFence++
		}
		if previous.CurrentLease == nil || transition.LeaseID == nil || *transition.LeaseID != previous.CurrentLease.ID || transition.LeaseRevision == nil || *transition.LeaseRevision != previous.CurrentLease.Revision || transition.CancellationFence != expectedFence {
			return invalid("assignment.transitionLease")
		}
	}
	sealed := (*Digest)(nil)
	if previous.State != "prepared" {
		digest := previous.ItemSetDigest
		sealed = &digest
	}
	if err := transition.validateAgainst(previous.State, previous.Revision, LifecycleID(previous.ID), sealed, appliedEventIDs, receiptIndex); err != nil {
		return err
	}
	if transitionRequiresSealedDigest(transition.To) && (transition.SealedAssignmentSetDigest == nil || *transition.SealedAssignmentSetDigest != value.ItemSetDigest) {
		return invalid("assignment.itemSetDigest")
	}
	acceptedLeases, err := value.validatedLeaseHistory(receiptIndex)
	if err != nil {
		return err
	}
	for _, receiptID := range transition.SupportingReceiptIDs {
		receipt, present := receiptIndex.get(receiptID)
		if !present || !value.matchesLeaseContext(receipt.record, acceptedLeases, &transition.CancellationFence, true) {
			return invalid("missingTransitionReceipt")
		}
		signer, present := value.expectedSigner(receipt.record)
		if !present || !receipt.matches(signer, value.receiptSubjectDigest(receipt.record)) {
			return invalid("missingTransitionReceipt")
		}
	}
	retryAuthorizingStage := ReceiptStage("")
	switch transition.To {
	case "retryableRejected":
		retryAuthorizingStage = "admissionRejected"
	case "executionFailed":
		retryAuthorizingStage = "executionCompleted"
	case "localExecutionFailed":
		retryAuthorizingStage = "localExecutionCompleted"
	}
	if retryAuthorizingStage != "" {
		if transition.Reason == nil || transition.Reason.Code != "error" || transition.Reason.ErrorID == nil {
			return invalid("missingTransitionReceipt")
		}
		found := false
		for _, receiptID := range transition.SupportingReceiptIDs {
			record := receiptIndex.byID[receiptID].record
			if record.Stage == retryAuthorizingStage && record.ErrorID != nil && *record.ErrorID == *transition.Reason.ErrorID && record.ErrorDigest != nil {
				found = true
				break
			}
		}
		if !found {
			return invalid("missingTransitionReceipt")
		}
	}
	switch transition.To {
	case "resultCustodied":
		if err := value.validateSuccessfulResultEvidence(transition.SupportingReceiptIDs, receiptIndex, resultManifest, false); err != nil {
			return err
		}
	case "delivered":
		if err := value.validateDeliveredResultEvidence(transition.SupportingReceiptIDs, receiptIndex, resultManifest); err != nil {
			return err
		}
	case "executionFailed":
		if err := value.validateFailedExecutionEvidence(transition.SupportingReceiptIDs, receiptIndex, false); err != nil {
			return err
		}
	case "released":
		if err := requireExternalReleaseEvidence(value.OccurrenceID, value.AttemptID, []AssignmentID{value.ID}, previous.ReceiptIDs, transition.SupportingReceiptIDs, receiptIndex); err != nil {
			return err
		}
	}
	return nil
}

func (value AssignmentRecord) validateSuccessfulResultEvidence(
	receiptIDs []ReceiptID,
	receiptIndex verifiedReceiptIndex,
	resultManifest *AssignmentResultManifest,
	requireDurableReceiptIDs bool,
) error {
	if value.Executor.Kind != ExecutorWorker || resultManifest == nil {
		return invalid("missingTransitionReceipt")
	}
	byStage, err := indexAssignmentStageReceipts(receiptIDs, receiptIndex, value.ID)
	if err != nil {
		return err
	}
	workerReceipt, workerPresent := byStage[ReceiptStage("executionCompleted")]
	custodyReceipt, custodyPresent := byStage[ReceiptStage("resultCustodied")]
	if !workerPresent || !custodyPresent ||
		!value.terminalReceiptMatchesCurrentLease(workerReceipt) ||
		!value.terminalReceiptMatchesCurrentLease(custodyReceipt) {
		return invalid("missingTransitionReceipt")
	}
	if err := resultManifest.ValidateAuthorizedBy(value, workerReceipt.record.OccurrenceID); err != nil {
		return err
	}
	workerRecord, custodyRecord := workerReceipt.record, custodyReceipt.record
	if workerRecord.OccurrenceID != custodyRecord.OccurrenceID ||
		workerRecord.ExecutionOutcome == nil || *workerRecord.ExecutionOutcome != "succeeded" ||
		custodyRecord.ExecutionOutcome == nil || *custodyRecord.ExecutionOutcome != "succeeded" ||
		workerRecord.ResultDigest == nil || *workerRecord.ResultDigest != resultManifest.ResultSetDigest ||
		custodyRecord.ResultDigest == nil || *custodyRecord.ResultDigest != resultManifest.ResultSetDigest ||
		workerRecord.ResultCapsuleDigest == nil || custodyRecord.ResultCapsuleDigest == nil ||
		*workerRecord.ResultCapsuleDigest != *custodyRecord.ResultCapsuleDigest {
		return invalid("assignment.resultEvidence")
	}
	if requireDurableReceiptIDs && (!containsReceiptID(value.ReceiptIDs, workerRecord.ID) || !containsReceiptID(value.ReceiptIDs, custodyRecord.ID)) {
		return invalid("missingTransitionReceipt")
	}
	return nil
}

func (value AssignmentRecord) validateDeliveredResultEvidence(
	supportingReceiptIDs []ReceiptID,
	receiptIndex verifiedReceiptIndex,
	resultManifest *AssignmentResultManifest,
) error {
	if resultManifest == nil {
		return invalid("missingTransitionReceipt")
	}
	allEvidenceIDs := uniqueReceiptIDs(value.ReceiptIDs, supportingReceiptIDs)
	if err := value.validateSuccessfulResultEvidence(allEvidenceIDs, receiptIndex, resultManifest, false); err != nil {
		return err
	}
	byStage, err := indexAssignmentStageReceipts(allEvidenceIDs, receiptIndex, value.ID)
	if err != nil {
		return err
	}
	delivery, deliveryPresent := byStage[ReceiptStage("resultDelivered")]
	custody, custodyPresent := byStage[ReceiptStage("resultCustodied")]
	if !deliveryPresent || !custodyPresent || !containsReceiptID(supportingReceiptIDs, delivery.record.ID) ||
		!value.terminalReceiptMatchesCurrentLease(delivery) ||
		!value.terminalReceiptMatchesCurrentLease(custody) ||
		delivery.record.ExecutionOutcome == nil || *delivery.record.ExecutionOutcome != "succeeded" ||
		delivery.record.ResultDigest == nil || *delivery.record.ResultDigest != resultManifest.ResultSetDigest ||
		custody.record.ResultDigest == nil || *delivery.record.ResultDigest != *custody.record.ResultDigest ||
		delivery.record.ResultCapsuleDigest == nil || custody.record.ResultCapsuleDigest == nil ||
		*delivery.record.ResultCapsuleDigest != *custody.record.ResultCapsuleDigest {
		return invalid("assignment.deliveryResultEvidence")
	}
	return nil
}

func (value AssignmentRecord) validateFailedExecutionEvidence(
	receiptIDs []ReceiptID,
	receiptIndex verifiedReceiptIndex,
	requireDurableReceiptIDs bool,
) error {
	stage := ReceiptStage("executionCompleted")
	if value.Executor.Kind == ExecutorSourceLocal {
		stage = "localExecutionCompleted"
	}
	byStage, err := indexAssignmentStageReceipts(receiptIDs, receiptIndex, value.ID)
	if err != nil {
		return err
	}
	receipt, present := byStage[stage]
	if !present || !value.terminalReceiptMatchesCurrentLease(receipt) ||
		receipt.record.ExecutionOutcome == nil || *receipt.record.ExecutionOutcome != "failed" ||
		receipt.record.ResultDigest != nil || receipt.record.ResultCapsuleDigest != nil ||
		receipt.record.ErrorID == nil || receipt.record.ErrorDigest == nil {
		return invalid("missingTransitionReceipt")
	}
	if requireDurableReceiptIDs && !containsReceiptID(value.ReceiptIDs, receipt.record.ID) {
		return invalid("missingTransitionReceipt")
	}
	return nil
}

func (value AssignmentRecord) terminalReceiptMatchesCurrentLease(receipt VerifiedReceipt) bool {
	if value.Executor.Kind == ExecutorSourceLocal {
		return value.matchesLeaseContext(receipt.record, map[uint64]LeaseBinding{}, uint64Pointer(0), true)
	}
	if value.CurrentLease == nil {
		return false
	}
	accepted := map[uint64]LeaseBinding{value.CurrentLease.Revision: *value.CurrentLease}
	return value.matchesLeaseContext(receipt.record, accepted, &value.CancellationFence, true)
}

func indexAssignmentStageReceipts(receiptIDs []ReceiptID, receiptIndex verifiedReceiptIndex, assignmentID AssignmentID) (map[ReceiptStage]VerifiedReceipt, error) {
	result := make(map[ReceiptStage]VerifiedReceipt)
	for _, receiptID := range receiptIDs {
		receipt, present := receiptIndex.get(receiptID)
		if !present {
			return nil, invalid("missingTransitionReceipt")
		}
		if receipt.record.AssignmentID == nil || *receipt.record.AssignmentID != assignmentID {
			continue
		}
		if _, duplicate := result[receipt.record.Stage]; duplicate {
			return nil, duplicateValue("receipts.assignmentStage")
		}
		result[receipt.record.Stage] = receipt
	}
	return result, nil
}

func requireExternalReleaseEvidence(
	occurrenceID OccurrenceID,
	attemptID AttemptID,
	assignmentIDs []AssignmentID,
	durableReceiptIDs []ReceiptID,
	supportingReceiptIDs []ReceiptID,
	receiptIndex verifiedReceiptIndex,
) error {
	relevantIDs := uniqueReceiptIDs(durableReceiptIDs, supportingReceiptIDs)
	for _, receiptID := range relevantIDs {
		receipt, present := receiptIndex.get(receiptID)
		if !present || receipt.record.OccurrenceID != occurrenceID || receipt.record.AttemptID != attemptID {
			return invalid("missingTransitionReceipt")
		}
	}
	historyStages := receiptStagesByAssignment(durableReceiptIDs, receiptIndex)
	releaseStages := receiptStagesByAssignment(supportingReceiptIDs, receiptIndex)
	for _, assignmentID := range assignmentIDs {
		history := historyStages[assignmentID]
		releases := releaseStages[assignmentID]
		workerParticipated := containsAnyReceiptStage(history, "workerClaimed", "executionStarted", "executionCompleted", "workerCancellationConfirmed", "workerReleased")
		custodyParticipated := workerParticipated || containsAnyReceiptStage(history, "custodyAccepted", "waitingForWorker", "resultCustodied", "custodyCancellationConfirmed", "custodyReleased")
		if custodyParticipated && !containsAnyReceiptStage(releases, "custodyReleased") {
			return invalid("missingTransitionReceipt")
		}
		if workerParticipated && !containsAnyReceiptStage(releases, "workerReleased", "leaseExpired") {
			return invalid("missingTransitionReceipt")
		}
	}
	return nil
}

func receiptStagesByAssignment(receiptIDs []ReceiptID, receiptIndex verifiedReceiptIndex) map[AssignmentID]map[ReceiptStage]struct{} {
	result := make(map[AssignmentID]map[ReceiptStage]struct{})
	for _, receiptID := range receiptIDs {
		receipt, present := receiptIndex.get(receiptID)
		if !present || receipt.record.AssignmentID == nil {
			continue
		}
		assignmentID := *receipt.record.AssignmentID
		if result[assignmentID] == nil {
			result[assignmentID] = make(map[ReceiptStage]struct{})
		}
		result[assignmentID][receipt.record.Stage] = struct{}{}
	}
	return result
}

func containsAnyReceiptStage(stages map[ReceiptStage]struct{}, candidates ...ReceiptStage) bool {
	for _, candidate := range candidates {
		if _, present := stages[candidate]; present {
			return true
		}
	}
	return false
}

func uniqueReceiptIDs(groups ...[]ReceiptID) []ReceiptID {
	seen := make(map[ReceiptID]struct{})
	result := make([]ReceiptID, 0)
	for _, group := range groups {
		for _, receiptID := range group {
			if _, present := seen[receiptID]; present {
				continue
			}
			seen[receiptID] = struct{}{}
			result = append(result, receiptID)
		}
	}
	return result
}

func uint64Pointer(value uint64) *uint64 { return &value }

func (value AssignmentRecord) validateReceiptTrust(receipt VerifiedReceipt) error {
	index, err := newVerifiedReceiptIndex([]VerifiedReceipt{receipt})
	if err != nil {
		return err
	}
	acceptedLeases, err := value.validatedLeaseHistory(index)
	if err != nil {
		return err
	}
	return value.validateReceiptTrustWithLeases(receipt, acceptedLeases)
}

func (value AssignmentRecord) validateReceiptTrustWithLeases(receipt VerifiedReceipt, acceptedLeases map[uint64]LeaseBinding) error {
	record := receipt.record
	if record.OccurrenceID != value.OccurrenceID || record.AttemptID != value.AttemptID || record.AssignmentID == nil || *record.AssignmentID != value.ID {
		return invalid("receipt.assignmentID")
	}
	signer, present := value.expectedSigner(record)
	if !present {
		return invalid("receipt.signer")
	}
	if !receipt.matches(signer, value.receiptSubjectDigest(record)) {
		return invalid("receipt.trust")
	}
	if !value.matchesLeaseContext(record, acceptedLeases, nil, false) {
		return invalid("receipt.lease")
	}
	return nil
}

func (value AssignmentRecord) expectedSigner(record ReceiptRecord) (ReceiptSignerBinding, bool) {
	if oneOf(string(record.Stage), "localExecutionStarted", "localExecutionCompleted", "localReleased", "localCancellationConfirmed") {
		if value.Executor.SourceLocal == nil {
			return ReceiptSignerBinding{}, false
		}
		return value.Executor.SourceLocal.ReceiptSigner, true
	}
	switch receiptAuthority(record.Stage) {
	case AuthoritySourceDevice:
		return value.SourceReceiptSigner, true
	case AuthorityJobCustody:
		if value.CustodyReceiptSigner == nil {
			return ReceiptSignerBinding{}, false
		}
		return *value.CustodyReceiptSigner, true
	case AuthorityWorker:
		if value.Executor.Worker == nil {
			return ReceiptSignerBinding{}, false
		}
		return value.Executor.Worker.ReceiptSigner, true
	default:
		return ReceiptSignerBinding{}, false
	}
}

func (value AssignmentRecord) matchesLeaseContext(record ReceiptRecord, acceptedLeases map[uint64]LeaseBinding, expectedFence *uint64, requireCurrentRevision bool) bool {
	if value.Executor.Kind == ExecutorSourceLocal {
		return record.LeaseID == nil && record.LeaseRevision == nil && record.LeaseExpiresAt == nil && record.CancellationFence == 0
	}
	if value.CurrentLease == nil || record.LeaseID == nil || *record.LeaseID != value.CurrentLease.ID || record.LeaseRevision == nil || record.LeaseExpiresAt == nil || record.CancellationFence == 0 {
		return false
	}
	accepted, present := acceptedLeases[*record.LeaseRevision]
	if !present || *record.LeaseExpiresAt != accepted.ExpiresAt || record.RecordedAt < accepted.IssuedAt {
		return false
	}
	if record.Stage == "leaseExpired" {
		if record.RecordedAt < accepted.ExpiresAt {
			return false
		}
	} else if oneOf(string(record.Stage), "waitingForWorker", "workerClaimed", "executionStarted", "executionCompleted", "leaseRenewed") && record.RecordedAt > accepted.ExpiresAt {
		return false
	}
	if expectedFence != nil {
		if record.CancellationFence != *expectedFence {
			return false
		}
	} else if record.CancellationFence > value.CancellationFence {
		return false
	}
	if requireCurrentRevision {
		return *record.LeaseRevision == value.CurrentLease.Revision && *record.LeaseExpiresAt == value.CurrentLease.ExpiresAt
	}
	return true
}

func (value AssignmentRecord) validatedLeaseHistory(receiptIndex verifiedReceiptIndex) (map[uint64]LeaseBinding, error) {
	if value.Executor.Kind == ExecutorSourceLocal {
		if value.InitialLease != nil || value.CurrentLease != nil {
			return nil, invalid("assignment.leaseHistory")
		}
		return map[uint64]LeaseBinding{}, nil
	}
	if value.InitialLease == nil || value.CurrentLease == nil {
		return nil, invalid("assignment.leaseHistory")
	}
	renewals := make([]VerifiedReceipt, 0)
	for _, receiptID := range value.ReceiptIDs {
		receipt, present := receiptIndex.get(receiptID)
		if present && receipt.record.Stage == "leaseRenewed" {
			renewals = append(renewals, receipt)
		}
	}
	sort.Slice(renewals, func(left, right int) bool {
		leftRevision, rightRevision := uint64(0), uint64(0)
		if renewals[left].record.LeaseRevision != nil {
			leftRevision = *renewals[left].record.LeaseRevision
		}
		if renewals[right].record.LeaseRevision != nil {
			rightRevision = *renewals[right].record.LeaseRevision
		}
		return leftRevision < rightRevision
	})
	history := map[uint64]LeaseBinding{value.InitialLease.Revision: *value.InitialLease}
	previous := *value.InitialLease
	for _, receipt := range renewals {
		record := receipt.record
		signer, signerPresent := value.expectedSigner(record)
		if record.OccurrenceID != value.OccurrenceID || record.AttemptID != value.AttemptID || record.AssignmentID == nil || *record.AssignmentID != value.ID || record.Stage != "leaseRenewed" || record.LeaseID == nil || *record.LeaseID != previous.ID || record.LeaseRevision == nil || record.LeaseExpiresAt == nil || record.RecordedAt > previous.ExpiresAt || record.CancellationFence != value.InitialCancellationFence || !signerPresent || !receipt.matches(signer, value.receiptSubjectDigest(record)) {
			return nil, invalid("assignment.leaseHistory")
		}
		renewal := LeaseBinding{ID: previous.ID, Revision: *record.LeaseRevision, IssuedAt: record.RecordedAt, ExpiresAt: *record.LeaseExpiresAt, MaximumExpiresAt: previous.MaximumExpiresAt}
		if err := renewal.ValidateRenewal(previous); err != nil {
			return nil, err
		}
		if _, duplicate := history[renewal.Revision]; duplicate {
			return nil, duplicateValue("assignment.leaseRevision")
		}
		history[renewal.Revision] = renewal
		previous = renewal
	}
	if previous != *value.CurrentLease {
		return nil, invalid("assignment.leaseHistory")
	}
	return history, nil
}
