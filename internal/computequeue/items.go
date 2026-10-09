package computequeue

import (
	"fmt"
	"sort"
)

type AssignmentResultEntry struct {
	ItemID       ItemID               `json:"itemID"`
	Outcome      ItemExecutionOutcome `json:"outcome"`
	ResultDigest *Digest              `json:"resultDigest,omitempty"`
	ErrorID      *ErrorID             `json:"errorID,omitempty"`
	ErrorDigest  *Digest              `json:"errorDigest,omitempty"`
}

func (value AssignmentResultEntry) Validate() error {
	if err := value.ItemID.Validate(); err != nil {
		return err
	}
	if !value.Outcome.valid() {
		return invalid("resultEntry.outcome")
	}
	if value.ResultDigest != nil {
		if err := value.ResultDigest.Validate(); err != nil {
			return err
		}
	}
	if value.ErrorID != nil {
		if err := value.ErrorID.Validate(); err != nil {
			return err
		}
	}
	if value.ErrorDigest != nil {
		if err := value.ErrorDigest.Validate(); err != nil {
			return err
		}
	}
	if value.Outcome == "succeeded" {
		if value.ResultDigest == nil || value.ErrorID != nil || value.ErrorDigest != nil {
			return invalid("resultEntry.resultDigest")
		}
	} else if value.ResultDigest != nil || value.ErrorID == nil || value.ErrorDigest == nil {
		return invalid("resultEntry.resultDigest")
	}
	return nil
}

func (value AssignmentResultEntry) digestComponents() []string {
	return []string{string(value.ItemID), string(value.Outcome), optionalDigest(value.ResultDigest), optionalErrorID(value.ErrorID), optionalDigest(value.ErrorDigest)}
}

type AssignmentResultManifest struct {
	ProtocolVersion int                     `json:"protocolVersion"`
	OccurrenceID    OccurrenceID            `json:"occurrenceID"`
	AttemptID       AttemptID               `json:"attemptID"`
	AssignmentID    AssignmentID            `json:"assignmentID"`
	Entries         []AssignmentResultEntry `json:"entries"`
	ResultSetDigest Digest                  `json:"resultSetDigest"`
}

func (value AssignmentResultManifest) Validate() error {
	if err := requireProtocol(value.ProtocolVersion); err != nil {
		return err
	}
	if err := value.OccurrenceID.Validate(); err != nil {
		return err
	}
	if err := value.AttemptID.Validate(); err != nil {
		return err
	}
	if err := value.AssignmentID.Validate(); err != nil {
		return err
	}
	if len(value.Entries) == 0 || len(value.Entries) > maximumAssignmentItems {
		return invalid("resultManifest.entries")
	}
	ids, components := make([]string, len(value.Entries)), []string{string(value.OccurrenceID), string(value.AttemptID), string(value.AssignmentID)}
	for index, entry := range value.Entries {
		if err := entry.Validate(); err != nil {
			return err
		}
		ids[index] = string(entry.ItemID)
		components = append(components, entry.digestComponents()...)
	}
	if err := requireUniqueSorted(ids, "resultManifest.itemIDs"); err != nil {
		return err
	}
	if value.ResultSetDigest != SHA256Digest("facets.compute-queue.assignment-result-set.v1", components...) {
		return invalid("resultManifest.resultSetDigest")
	}
	return nil
}

func (value AssignmentResultManifest) ValidateAuthorizedBy(assignment AssignmentRecord, expectedOccurrenceID OccurrenceID) error {
	if err := value.Validate(); err != nil {
		return err
	}
	if err := assignment.Validate(); err != nil {
		return err
	}
	if value.OccurrenceID != expectedOccurrenceID || value.AttemptID != assignment.AttemptID || value.AssignmentID != assignment.ID || len(value.Entries) != len(assignment.ItemIDs) {
		return invalid("resultManifest.authorization")
	}
	for index, entry := range value.Entries {
		if entry.ItemID != assignment.ItemIDs[index] {
			return invalid("resultManifest.authorization")
		}
	}
	return nil
}

// ValidateAgainstItems binds every manifest entry to the exact execution that
// produced it. A successful result may later become invalidResult at the
// source validation boundary, but a failed manifest entry must retain its
// signed error identity and digest.
func (value AssignmentResultManifest) ValidateAgainstItems(items []ItemRecord) error {
	itemsByID := make(map[ItemID]ItemRecord, len(items))
	for _, item := range items {
		if _, duplicate := itemsByID[item.ID]; duplicate {
			return duplicateValue("resultManifest.items.id")
		}
		itemsByID[item.ID] = item
	}
	return value.validateAgainstItemIndex(itemsByID)
}

func (value AssignmentResultManifest) validateAgainstItemIndex(itemsByID map[ItemID]ItemRecord) error {
	if err := value.Validate(); err != nil {
		return err
	}
	for _, entry := range value.Entries {
		item, present := itemsByID[entry.ItemID]
		if !present {
			return invalid("resultManifest.itemCoverage")
		}
		var execution *ItemExecutionRecord
		for index := range item.Executions {
			candidate := &item.Executions[index]
			if candidate.AttemptID == value.AttemptID && candidate.AssignmentID == value.AssignmentID {
				execution = candidate
				break
			}
		}
		if execution == nil {
			return invalid("resultManifest.itemCoverage")
		}
		if item.OccurrenceID != value.OccurrenceID || execution.OccurrenceID != value.OccurrenceID {
			return invalid("resultManifest.itemIdentity")
		}
		switch entry.Outcome {
		case "succeeded":
			if execution.ResultCompletedAt == nil || !equalOptionalDigest(execution.ResultDigest, entry.ResultDigest) ||
				execution.Outcome == nil || !oneOf(string(*execution.Outcome), "succeeded", "invalidResult") {
				return invalid("resultManifest.itemResult")
			}
		case "failed":
			if execution.ResultCompletedAt != nil || execution.ResultDigest != nil || execution.Outcome == nil || *execution.Outcome != "failedExecution" ||
				!equalOptionalErrorID(execution.ErrorID, entry.ErrorID) {
				return invalid("resultManifest.itemResult")
			}
		}
	}
	return nil
}

type ItemExecutionRecord struct {
	ProtocolVersion           int                 `json:"protocolVersion"`
	Revision                  uint64              `json:"revision"`
	OccurrenceID              OccurrenceID        `json:"occurrenceID"`
	ItemID                    ItemID              `json:"itemID"`
	DestinationKind           DestinationKind     `json:"destinationKind"`
	AttemptID                 AttemptID           `json:"attemptID"`
	AttemptNumber             uint64              `json:"attemptNumber"`
	AssignmentID              AssignmentID        `json:"assignmentID"`
	WorkerID                  *WorkerID           `json:"workerID,omitempty"`
	ExecutionInputCommittedAt *Timestamp          `json:"executionInputCommittedAt,omitempty"`
	DisclosureCommittedAt     *Timestamp          `json:"disclosureCommittedAt,omitempty"`
	CustodyAcceptedAt         *Timestamp          `json:"custodyAcceptedAt,omitempty"`
	ResultCompletedAt         *Timestamp          `json:"resultCompletedAt,omitempty"`
	TerminalAt                *Timestamp          `json:"terminalAt,omitempty"`
	ResultDigest              *Digest             `json:"resultDigest,omitempty"`
	CancellationUnconfirmed   bool                `json:"cancellationUnconfirmed"`
	Outcome                   *ItemAttemptOutcome `json:"outcome,omitempty"`
	ErrorID                   *ErrorID            `json:"errorID,omitempty"`
}

func (value ItemExecutionRecord) Validate() error {
	if err := requireProtocol(value.ProtocolVersion); err != nil {
		return err
	}
	if err := requirePositive(value.Revision, "revision"); err != nil {
		return err
	}
	for _, err := range []error{value.OccurrenceID.Validate(), value.ItemID.Validate(), value.AttemptID.Validate(), value.AssignmentID.Validate()} {
		if err != nil {
			return err
		}
	}
	if !value.DestinationKind.valid() {
		return invalid("itemExecution.destinationKind")
	}
	if err := requirePositive(value.AttemptNumber, "itemExecution.attemptNumber"); err != nil {
		return err
	}
	if value.WorkerID != nil {
		if err := value.WorkerID.Validate(); err != nil {
			return err
		}
	}
	if value.ResultDigest != nil {
		if err := value.ResultDigest.Validate(); err != nil {
			return err
		}
	}
	if value.ErrorID != nil {
		if err := value.ErrorID.Validate(); err != nil {
			return err
		}
	}
	if value.Outcome != nil && !value.Outcome.valid() {
		return invalid("itemExecution.outcome")
	}
	if value.DestinationKind == DestinationDirectLocal {
		if value.WorkerID != nil || value.DisclosureCommittedAt != nil || value.CustodyAcceptedAt != nil {
			return invalid("itemExecution.directLocal")
		}
	} else if value.WorkerID == nil {
		return invalid("itemExecution.workerID")
	}
	if value.DisclosureCommittedAt != nil && value.ExecutionInputCommittedAt == nil {
		return invalid("itemExecution.disclosureCommittedAt")
	}
	if value.CustodyAcceptedAt != nil && value.DisclosureCommittedAt == nil {
		return invalid("itemExecution.custodyAcceptedAt")
	}
	if value.ResultCompletedAt != nil && value.ExecutionInputCommittedAt == nil {
		return invalid("itemExecution.resultCompletedAt")
	}
	if (value.ResultCompletedAt == nil) != (value.ResultDigest == nil) || (value.TerminalAt == nil) != (value.Outcome == nil) {
		return invalid("itemExecution.terminal")
	}
	if value.DestinationKind != DestinationDirectLocal && value.ResultCompletedAt != nil && value.CustodyAcceptedAt == nil {
		return invalid("itemExecution.externalResultWithoutCustody")
	}
	if value.CancellationUnconfirmed && (value.Outcome != nil || value.ExecutionInputCommittedAt == nil || (value.DestinationKind != DestinationDirectLocal && value.DisclosureCommittedAt == nil)) {
		return invalid("itemExecution.cancellationUnconfirmed")
	}
	switch outcome := value.Outcome; {
	case outcome == nil:
		if value.ErrorID != nil {
			return invalid("itemExecution.errorID")
		}
	case *outcome == "admissionRejected":
		if value.ExecutionInputCommittedAt != nil || value.DisclosureCommittedAt != nil || value.CustodyAcceptedAt != nil || value.ResultCompletedAt != nil || value.ErrorID == nil {
			return invalid("itemExecution.admissionRejected")
		}
	case *outcome == "succeeded":
		if value.ResultCompletedAt == nil || value.ResultDigest == nil || value.ErrorID != nil {
			return invalid("itemExecution.succeeded")
		}
	case *outcome == "failedExecution":
		if value.ExecutionInputCommittedAt == nil || (value.DestinationKind != DestinationDirectLocal && (value.DisclosureCommittedAt == nil || value.CustodyAcceptedAt == nil)) || value.ResultCompletedAt != nil || value.ErrorID == nil {
			return invalid("itemExecution.failedExecution")
		}
	case *outcome == "invalidResult":
		if value.ResultCompletedAt == nil || value.ResultDigest == nil || value.ErrorID == nil {
			return invalid("itemExecution.invalidResult")
		}
	case *outcome == "cancelledBeforeDisclosure":
		if value.DisclosureCommittedAt != nil || value.CustodyAcceptedAt != nil || value.ResultCompletedAt != nil || value.ErrorID != nil {
			return invalid("itemExecution.cancelledBeforeDisclosure")
		}
	case *outcome == "cancelledAfterDisclosure":
		if value.DestinationKind == DestinationDirectLocal || value.DisclosureCommittedAt == nil || value.ResultCompletedAt != nil || value.ErrorID != nil {
			return invalid("itemExecution.cancelledAfterDisclosure")
		}
	}
	times := []*Timestamp{value.ExecutionInputCommittedAt, value.DisclosureCommittedAt, value.CustodyAcceptedAt, value.ResultCompletedAt, value.TerminalAt}
	var previous *Timestamp
	for _, current := range times {
		if current != nil {
			if err := current.Validate(); err != nil {
				return err
			}
			if previous != nil && *current < *previous {
				return invalid("itemExecution.timestamps")
			}
			previous = current
		}
	}
	return nil
}

func (value ItemExecutionRecord) authorizesRetry() bool {
	return value.Outcome != nil && (*value.Outcome == "admissionRejected" || *value.Outcome == "failedExecution")
}

// ValidateUpdateFrom validates a monotonic update to one execution record.
// Once a milestone has been recorded it is immutable, and a terminal
// execution cannot be revised through this general update boundary.
func (value ItemExecutionRecord) ValidateUpdateFrom(previous ItemExecutionRecord) error {
	if err := value.Validate(); err != nil {
		return err
	}
	if value.OccurrenceID != previous.OccurrenceID || value.ItemID != previous.ItemID ||
		value.DestinationKind != previous.DestinationKind || value.AttemptID != previous.AttemptID ||
		value.AttemptNumber != previous.AttemptNumber || value.AssignmentID != previous.AssignmentID ||
		!equalOptionalWorkerID(value.WorkerID, previous.WorkerID) ||
		previous.Revision == ^uint64(0) || value.Revision != previous.Revision+1 {
		return invalid("itemExecution.identity")
	}
	if previous.ExecutionInputCommittedAt != nil && !equalOptionalTimestamp(value.ExecutionInputCommittedAt, previous.ExecutionInputCommittedAt) {
		return invalid("itemExecution.executionInputCommittedAt")
	}
	if previous.DisclosureCommittedAt != nil && !equalOptionalTimestamp(value.DisclosureCommittedAt, previous.DisclosureCommittedAt) {
		return invalid("itemExecution.disclosureCommittedAt")
	}
	if previous.CustodyAcceptedAt != nil && !equalOptionalTimestamp(value.CustodyAcceptedAt, previous.CustodyAcceptedAt) {
		return invalid("itemExecution.custodyAcceptedAt")
	}
	if previous.ResultCompletedAt != nil &&
		(!equalOptionalTimestamp(value.ResultCompletedAt, previous.ResultCompletedAt) || !equalOptionalDigest(value.ResultDigest, previous.ResultDigest)) {
		return invalid("itemExecution.result")
	}
	if previous.CancellationUnconfirmed && !value.CancellationUnconfirmed {
		return invalid("itemExecution.cancellationUnconfirmed")
	}
	if previous.Outcome != nil {
		return invalid("itemExecution.terminal")
	}
	return nil
}

func (value ItemExecutionRecord) validateCancellationReconciliationFrom(previous ItemExecutionRecord) error {
	if err := value.Validate(); err != nil {
		return err
	}
	expectedOutcome := ItemAttemptOutcome("cancelledAfterDisclosure")
	if value.DestinationKind == DestinationDirectLocal {
		expectedOutcome = "cancelledBeforeDisclosure"
	}
	if value.OccurrenceID != previous.OccurrenceID || value.ItemID != previous.ItemID ||
		value.DestinationKind != previous.DestinationKind || value.AttemptID != previous.AttemptID ||
		value.AttemptNumber != previous.AttemptNumber || value.AssignmentID != previous.AssignmentID ||
		!equalOptionalWorkerID(value.WorkerID, previous.WorkerID) ||
		previous.Revision == ^uint64(0) || value.Revision != previous.Revision+1 ||
		!equalOptionalTimestamp(value.ExecutionInputCommittedAt, previous.ExecutionInputCommittedAt) ||
		!equalOptionalTimestamp(value.DisclosureCommittedAt, previous.DisclosureCommittedAt) ||
		!equalOptionalTimestamp(value.CustodyAcceptedAt, previous.CustodyAcceptedAt) ||
		!equalOptionalTimestamp(value.ResultCompletedAt, previous.ResultCompletedAt) ||
		!equalOptionalDigest(value.ResultDigest, previous.ResultDigest) ||
		!previous.CancellationUnconfirmed || value.CancellationUnconfirmed || previous.Outcome != nil ||
		value.Outcome == nil || *value.Outcome != expectedOutcome || value.ErrorID != nil {
		return invalid("itemExecution.cancellationReconciliation")
	}
	return nil
}

type ItemRecord struct {
	ProtocolVersion      int                   `json:"protocolVersion"`
	ID                   ItemID                `json:"id"`
	OccurrenceID         OccurrenceID          `json:"occurrenceID"`
	Revision             uint64                `json:"revision"`
	DestinationKind      DestinationKind       `json:"destinationKind"`
	SourceObjectID       FacetsObjectID        `json:"sourceObjectID"`
	SourceRevision       *string               `json:"sourceRevision,omitempty"`
	SourceFingerprint    *Digest               `json:"sourceFingerprint,omitempty"`
	PreparedAt           *Timestamp            `json:"preparedAt,omitempty"`
	Executions           []ItemExecutionRecord `json:"executions"`
	TerminalAt           *Timestamp            `json:"terminalAt,omitempty"`
	ApplicationReceiptID *ReceiptID            `json:"applicationReceiptID,omitempty"`
	Disposition          *ItemDisposition      `json:"disposition,omitempty"`
	ErrorID              *ErrorID              `json:"errorID,omitempty"`
}

func (value ItemRecord) Validate() error {
	if err := requireProtocol(value.ProtocolVersion); err != nil {
		return err
	}
	if err := value.ID.Validate(); err != nil {
		return err
	}
	if err := value.OccurrenceID.Validate(); err != nil {
		return err
	}
	if err := requirePositive(value.Revision, "revision"); err != nil {
		return err
	}
	if !value.DestinationKind.valid() {
		return invalid("item.destinationKind")
	}
	if err := value.SourceObjectID.Validate(); err != nil {
		return err
	}
	if value.SourceRevision != nil {
		if err := requireNonempty(*value.SourceRevision, "sourceRevision"); err != nil {
			return err
		}
	}
	if value.SourceFingerprint != nil {
		if err := value.SourceFingerprint.Validate(); err != nil {
			return err
		}
	}
	if (value.PreparedAt == nil) != (value.SourceFingerprint == nil) {
		return invalid("sourceFingerprint")
	}
	if value.Executions == nil || len(value.Executions) > MaximumRetries+1 {
		return invalid("item.executions")
	}
	attemptIDs := make([]string, len(value.Executions))
	for index, execution := range value.Executions {
		if err := execution.Validate(); err != nil {
			return err
		}
		if execution.OccurrenceID != value.OccurrenceID || execution.ItemID != value.ID || execution.DestinationKind != value.DestinationKind || execution.AttemptNumber != uint64(index+1) {
			return invalid("item.executions.identity")
		}
		if index < len(value.Executions)-1 && (!execution.authorizesRetry() || execution.CancellationUnconfirmed) {
			return invalid("item.executions.retryLineage")
		}
		attemptIDs[index] = string(execution.AttemptID)
	}
	sortedAttemptIDs := append([]string(nil), attemptIDs...)
	sort.Strings(sortedAttemptIDs)
	if len(attemptIDs) > 0 {
		for i := 1; i < len(sortedAttemptIDs); i++ {
			if sortedAttemptIDs[i] == sortedAttemptIDs[i-1] {
				return invalid("item.executions.attemptID")
			}
		}
	}
	if len(value.Executions) > 0 && value.PreparedAt == nil {
		return invalid("item.executions.preparedAt")
	}
	if (value.Disposition == nil) != (value.TerminalAt == nil) {
		return invalid("terminalAt")
	}
	if value.Disposition != nil && !value.Disposition.valid() {
		return invalid("disposition")
	}
	if value.ErrorID != nil {
		if err := value.ErrorID.Validate(); err != nil {
			return err
		}
	}
	failed := value.Disposition != nil && oneOf(string(*value.Disposition), "failedPreparation", "failedExecution", "invalidResult")
	if failed != (value.ErrorID != nil) {
		return invalid("item.errorID")
	}
	if value.ApplicationReceiptID != nil {
		if err := value.ApplicationReceiptID.Validate(); err != nil {
			return err
		}
	}
	current := value.CurrentExecution()
	if value.Disposition != nil && *value.Disposition == "applied" {
		if current == nil || current.ResultCompletedAt == nil || current.ResultDigest == nil || current.Outcome == nil || *current.Outcome != "succeeded" || value.ApplicationReceiptID == nil {
			return invalid("applied")
		}
	} else if value.ApplicationReceiptID != nil {
		return invalid("applicationReceiptID")
	}
	if err := value.validateDisposition(); err != nil {
		return err
	}
	if value.PreparedAt != nil {
		if err := value.PreparedAt.Validate(); err != nil {
			return err
		}
	}
	if value.TerminalAt != nil {
		if err := value.TerminalAt.Validate(); err != nil {
			return err
		}
		if value.PreparedAt != nil && *value.TerminalAt < *value.PreparedAt {
			return invalid("terminalAt")
		}
		if current != nil && current.TerminalAt != nil && *value.TerminalAt < *current.TerminalAt {
			return invalid("terminalAt")
		}
	}
	return nil
}

func (value ItemRecord) CurrentExecution() *ItemExecutionRecord {
	if len(value.Executions) == 0 {
		return nil
	}
	return &value.Executions[len(value.Executions)-1]
}

// ValidateUpdateFrom is the general source-side item mutation boundary. Retry
// appends and cancellation reconciliation deliberately have separate,
// evidence-bearing entry points below.
func (value ItemRecord) ValidateUpdateFrom(previous ItemRecord) error {
	return value.validateUpdateFrom(previous, false)
}

func (value ItemRecord) validateUpdateFrom(previous ItemRecord, allowCancellationReconciliation bool) error {
	if err := value.Validate(); err != nil {
		return err
	}
	if value.ID != previous.ID || value.OccurrenceID != previous.OccurrenceID ||
		value.DestinationKind != previous.DestinationKind || value.SourceObjectID != previous.SourceObjectID {
		return invalid("item")
	}
	if previous.Revision == ^uint64(0) || value.Revision != previous.Revision+1 {
		return invalid("item.revision")
	}
	if len(value.Executions) == len(previous.Executions) {
		if len(value.Executions) > 0 {
			if !equalItemExecutionPrefix(value.Executions[:len(value.Executions)-1], previous.Executions[:len(previous.Executions)-1]) {
				return invalid("item.executions.history")
			}
			current := value.Executions[len(value.Executions)-1]
			prior := previous.Executions[len(previous.Executions)-1]
			if !equalItemExecution(current, prior) {
				if allowCancellationReconciliation {
					if err := current.validateCancellationReconciliationFrom(prior); err != nil {
						return err
					}
				} else if err := current.ValidateUpdateFrom(prior); err != nil {
					return err
				}
			}
		}
	} else if len(previous.Executions) != 0 || len(value.Executions) != 1 || value.Executions[0].AttemptNumber != 1 {
		return invalid("item.executions")
	}
	if previous.Disposition != nil && !equalOptionalItemDisposition(value.Disposition, previous.Disposition) {
		return invalid("disposition")
	}
	if previous.PreparedAt != nil &&
		(!equalOptionalString(value.SourceRevision, previous.SourceRevision) ||
			!equalOptionalDigest(value.SourceFingerprint, previous.SourceFingerprint) ||
			!equalOptionalTimestamp(value.PreparedAt, previous.PreparedAt)) {
		return invalid("preparedSnapshot")
	}
	priorExecution := previous.CurrentExecution()
	currentExecution := value.CurrentExecution()
	if priorExecution != nil && priorExecution.ExecutionInputCommittedAt != nil {
		if currentExecution == nil || currentExecution.AttemptID != priorExecution.AttemptID ||
			currentExecution.AssignmentID != priorExecution.AssignmentID ||
			!equalOptionalWorkerID(currentExecution.WorkerID, priorExecution.WorkerID) ||
			!equalOptionalDigest(value.SourceFingerprint, previous.SourceFingerprint) {
			return invalid("executionInput")
		}
	}
	if priorExecution != nil {
		if priorExecution.ExecutionInputCommittedAt != nil && (currentExecution == nil || !equalOptionalTimestamp(currentExecution.ExecutionInputCommittedAt, priorExecution.ExecutionInputCommittedAt)) {
			return invalid("executionInputCommittedAt")
		}
		if priorExecution.DisclosureCommittedAt != nil && (currentExecution == nil || !equalOptionalTimestamp(currentExecution.DisclosureCommittedAt, priorExecution.DisclosureCommittedAt)) {
			return invalid("disclosureCommittedAt")
		}
		if priorExecution.CustodyAcceptedAt != nil && (currentExecution == nil || !equalOptionalTimestamp(currentExecution.CustodyAcceptedAt, priorExecution.CustodyAcceptedAt)) {
			return invalid("custodyAcceptedAt")
		}
		if priorExecution.ResultCompletedAt != nil && (currentExecution == nil || !equalOptionalTimestamp(currentExecution.ResultCompletedAt, priorExecution.ResultCompletedAt) || !equalOptionalDigest(currentExecution.ResultDigest, priorExecution.ResultDigest)) {
			return invalid("completedResult")
		}
		if priorExecution.CancellationUnconfirmed && (currentExecution == nil || !currentExecution.CancellationUnconfirmed) && !allowCancellationReconciliation {
			return invalid("cancellationUnconfirmed")
		}
	}
	if previous.Disposition != nil {
		return invalid("terminalItem")
	}
	return nil
}

// ValidateReconciledUpdateFrom is the sole path that may clear an uncertain
// cancellation. It requires authenticated confirmation from every participant
// that could still hold or execute protected bytes.
func (value ItemRecord) ValidateReconciledUpdateFrom(previous ItemRecord, assignment AssignmentRecord, receipts []VerifiedReceipt) error {
	receiptIndex, err := newVerifiedReceiptIndex(receipts)
	if err != nil {
		return err
	}
	expectedDisposition := ItemDisposition("cancelledAfterDisclosure")
	if value.DestinationKind == DestinationDirectLocal {
		expectedDisposition = "cancelledBeforeDisclosure"
	}
	prior := previous.CurrentExecution()
	current := value.CurrentExecution()
	if prior == nil || current == nil || !prior.CancellationUnconfirmed || current.CancellationUnconfirmed ||
		value.Disposition == nil || *value.Disposition != expectedDisposition ||
		assignment.ID != current.AssignmentID || assignment.AttemptID != current.AttemptID || !containsItemID(assignment.ItemIDs, value.ID) {
		return invalid("cancellationReconciliation")
	}
	supportingReceiptIDs := make([]ReceiptID, 0)
	for _, receiptID := range assignment.ReceiptIDs {
		receipt, present := receiptIndex.get(receiptID)
		if !present {
			return invalid("missingTransitionReceipt")
		}
		record := receipt.record
		signer, signerPresent := assignment.expectedSigner(record)
		if !signerPresent || record.AttemptID != assignment.AttemptID || record.AssignmentID == nil || *record.AssignmentID != assignment.ID ||
			!receipt.matches(signer, assignment.receiptSubjectDigest(record)) {
			return invalid("missingTransitionReceipt")
		}
		if oneOf(string(record.Stage), "custodyCancellationConfirmed", "workerCancellationConfirmed", "localCancellationConfirmed") {
			supportingReceiptIDs = append(supportingReceiptIDs, receiptID)
		}
	}
	stages := receiptStagesByAssignment(supportingReceiptIDs, receiptIndex)[assignment.ID]
	if value.DestinationKind == DestinationDirectLocal {
		if !containsAnyReceiptStage(stages, "localCancellationConfirmed") {
			return invalid("missingTransitionReceipt")
		}
	} else {
		if !containsAnyReceiptStage(stages, "custodyCancellationConfirmed") ||
			(current.WorkerID != nil && !containsAnyReceiptStage(stages, "workerCancellationConfirmed")) {
			return invalid("missingTransitionReceipt")
		}
	}
	if err := requireOccurrenceCancellationEvidence(value.DestinationKind, value.OccurrenceID, []AssignmentID{assignment.ID}, assignment.ReceiptIDs, supportingReceiptIDs, receiptIndex); err != nil {
		return err
	}
	return value.validateUpdateFrom(previous, true)
}

// ValidateRetryAppend is the only update path that may append a second or
// later execution. The AuthorizedAttempt proof prevents callers from
// manufacturing retry lineage from a merely decoded AttemptRecord.
func (value ItemRecord) ValidateRetryAppendFrom(previous ItemRecord, authorizedBy AuthorizedAttempt) error {
	if err := value.Validate(); err != nil {
		return err
	}
	attempt := authorizedBy.record
	if value.ID != previous.ID ||
		value.OccurrenceID != previous.OccurrenceID ||
		value.DestinationKind != previous.DestinationKind ||
		value.SourceObjectID != previous.SourceObjectID ||
		!equalOptionalString(value.SourceRevision, previous.SourceRevision) ||
		!equalOptionalDigest(value.SourceFingerprint, previous.SourceFingerprint) ||
		!equalOptionalTimestamp(value.PreparedAt, previous.PreparedAt) ||
		previous.Revision == ^uint64(0) || value.Revision != previous.Revision+1 ||
		previous.Disposition != nil || value.Disposition != nil ||
		value.TerminalAt != nil || value.ApplicationReceiptID != nil || value.ErrorID != nil ||
		len(value.Executions) != len(previous.Executions)+1 ||
		!equalItemExecutionPrefix(value.Executions[:len(value.Executions)-1], previous.Executions) {
		return invalid("item.retryAppend")
	}
	prior := previous.CurrentExecution()
	current := value.CurrentExecution()
	if prior == nil || current == nil || !prior.authorizesRetry() || prior.CancellationUnconfirmed ||
		prior.AttemptNumber == ^uint64(0) || current.AttemptNumber != prior.AttemptNumber+1 ||
		current.AttemptID != attempt.ID || current.AttemptNumber != attempt.AttemptNumber ||
		current.OccurrenceID != attempt.OccurrenceID || current.ItemID != value.ID ||
		current.Outcome != nil || current.ExecutionInputCommittedAt != nil ||
		current.DisclosureCommittedAt != nil || current.CustodyAcceptedAt != nil ||
		current.ResultCompletedAt != nil || current.CancellationUnconfirmed ||
		attempt.PreviousAttemptID == nil || *attempt.PreviousAttemptID != prior.AttemptID ||
		attempt.RetryErrorID == nil || prior.ErrorID == nil || *attempt.RetryErrorID != *prior.ErrorID {
		return invalid("item.retryAppend")
	}
	var authorization *AssignmentAuthorization
	for index := range attempt.AssignmentPlan.Assignments {
		candidate := &attempt.AssignmentPlan.Assignments[index]
		if candidate.AssignmentID == current.AssignmentID {
			authorization = candidate
			break
		}
	}
	if authorization == nil || !containsItemID(authorization.ItemIDs, value.ID) {
		return invalid("item.retryAppend")
	}
	var expectedWorkerID *WorkerID
	if authorization.Executor.Worker != nil {
		workerID := authorization.Executor.Worker.WorkerID
		expectedWorkerID = &workerID
	}
	if !equalOptionalWorkerID(current.WorkerID, expectedWorkerID) {
		return invalid("item.retryAppend")
	}
	return nil
}

// ValidateApplication checks the authenticated per-item sourceApplied proof.
// A terminal `applied` disposition is not itself proof that the result crossed
// the source application boundary.
func (value ItemRecord) ValidateApplication(receipts []VerifiedReceipt, sourceReceiptSigner ReceiptSignerBinding) error {
	receiptIndex, err := newVerifiedReceiptIndex(receipts)
	if err != nil {
		return err
	}
	return value.validateApplication(receiptIndex, sourceReceiptSigner)
}

func (value ItemRecord) validateApplication(receiptIndex verifiedReceiptIndex, sourceReceiptSigner ReceiptSignerBinding) error {
	if err := value.Validate(); err != nil {
		return err
	}
	if value.Disposition == nil || *value.Disposition != "applied" {
		return nil
	}
	if value.ApplicationReceiptID == nil {
		return invalid("missingTransitionReceipt")
	}
	current := value.CurrentExecution()
	if current == nil {
		return invalid("missingTransitionReceipt")
	}
	receipt, present := receiptIndex.get(*value.ApplicationReceiptID)
	if !present {
		return invalid("missingTransitionReceipt")
	}
	record := receipt.record
	if record.Stage != "sourceApplied" || record.Authority != AuthoritySourceDevice ||
		record.OccurrenceID != value.OccurrenceID || record.AttemptID != current.AttemptID ||
		record.AssignmentID == nil || *record.AssignmentID != current.AssignmentID ||
		record.ItemID == nil || *record.ItemID != value.ID ||
		!receipt.matches(sourceReceiptSigner, value.ApplicationProofDigest()) {
		return invalid("missingTransitionReceipt")
	}
	return nil
}

func equalItemExecutionPrefix(left, right []ItemExecutionRecord) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !equalItemExecution(left[index], right[index]) {
			return false
		}
	}
	return true
}

func equalItemExecution(left, right ItemExecutionRecord) bool {
	return left.ProtocolVersion == right.ProtocolVersion && left.Revision == right.Revision &&
		left.OccurrenceID == right.OccurrenceID && left.ItemID == right.ItemID &&
		left.DestinationKind == right.DestinationKind && left.AttemptID == right.AttemptID &&
		left.AttemptNumber == right.AttemptNumber && left.AssignmentID == right.AssignmentID &&
		equalOptionalWorkerID(left.WorkerID, right.WorkerID) &&
		equalOptionalTimestamp(left.ExecutionInputCommittedAt, right.ExecutionInputCommittedAt) &&
		equalOptionalTimestamp(left.DisclosureCommittedAt, right.DisclosureCommittedAt) &&
		equalOptionalTimestamp(left.CustodyAcceptedAt, right.CustodyAcceptedAt) &&
		equalOptionalTimestamp(left.ResultCompletedAt, right.ResultCompletedAt) &&
		equalOptionalTimestamp(left.TerminalAt, right.TerminalAt) &&
		equalOptionalDigest(left.ResultDigest, right.ResultDigest) &&
		left.CancellationUnconfirmed == right.CancellationUnconfirmed &&
		equalOptionalItemAttemptOutcome(left.Outcome, right.Outcome) &&
		equalOptionalErrorID(left.ErrorID, right.ErrorID)
}

func equalOptionalString(left, right *string) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}

func equalOptionalWorkerID(left, right *WorkerID) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}

func equalOptionalItemAttemptOutcome(left, right *ItemAttemptOutcome) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}

func equalOptionalItemDisposition(left, right *ItemDisposition) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}

func containsItemID(values []ItemID, value ItemID) bool {
	for _, current := range values {
		if current == value {
			return true
		}
	}
	return false
}

func (value ItemRecord) validateDisposition() error {
	if value.Disposition == nil {
		return nil
	}
	current := value.CurrentExecution()
	var input, disclosure, custody, completed *Timestamp
	var result *Digest
	var outcome *ItemAttemptOutcome
	if current != nil {
		input = current.ExecutionInputCommittedAt
		disclosure = current.DisclosureCommittedAt
		custody = current.CustodyAcceptedAt
		completed = current.ResultCompletedAt
		result = current.ResultDigest
		outcome = current.Outcome
	}
	switch *value.Disposition {
	case "applied":
	case "skippedSourceMissing":
		if value.PreparedAt != nil || current != nil {
			return invalid("skippedSourceMissing")
		}
	case "skippedSourceMissingBeforeDisclosure", "skippedSourceChangedBeforeDisclosure":
		if value.PreparedAt == nil || input != nil || disclosure != nil || custody != nil || completed != nil || result != nil {
			return invalid("skippedBeforeDisclosure")
		}
	case "resultNotAppliedSourceMissing", "resultNotAppliedSourceChanged":
		if input == nil || completed == nil || result == nil || outcome == nil || *outcome != "succeeded" {
			return invalid("resultNotApplied")
		}
	case "failedPreparation":
		if input != nil || disclosure != nil || custody != nil || completed != nil || result != nil || (current != nil && (outcome == nil || *outcome != "admissionRejected")) {
			return invalid("terminalBeforeDisclosure")
		}
	case "cancelledBeforeDisclosure":
		if disclosure != nil || custody != nil || completed != nil || result != nil || (current != nil && (outcome == nil || *outcome != "cancelledBeforeDisclosure")) {
			return invalid("cancelledBeforeDisclosure")
		}
	case "failedExecution":
		if current == nil || input == nil || completed != nil || result != nil || outcome == nil || *outcome != "failedExecution" || !equalOptionalErrorID(current.ErrorID, value.ErrorID) {
			return invalid("failedExecution")
		}
	case "cancelledAfterDisclosure":
		if value.DestinationKind == DestinationDirectLocal || disclosure == nil || outcome == nil || *outcome != "cancelledAfterDisclosure" {
			return invalid("terminalAfterDisclosure")
		}
	case "invalidResult":
		if current == nil || input == nil || completed == nil || result == nil || outcome == nil || *outcome != "invalidResult" || !equalOptionalErrorID(current.ErrorID, value.ErrorID) {
			return invalid("invalidResult")
		}
	}
	return nil
}

func (value ItemRecord) ApplicationProofDigest() Digest {
	current := value.CurrentExecution()
	attempt, assignment, sourceFingerprint, result, disposition, terminal := "", "", "", "", "", ""
	if current != nil {
		attempt = string(current.AttemptID)
		assignment = string(current.AssignmentID)
		result = optionalDigest(current.ResultDigest)
	}
	if value.SourceFingerprint != nil {
		sourceFingerprint = string(*value.SourceFingerprint)
	}
	if value.Disposition != nil {
		disposition = string(*value.Disposition)
	}
	if value.TerminalAt != nil {
		terminal = fmt.Sprint(*value.TerminalAt)
	}
	return SHA256Digest("facets.compute-queue.item-application-proof.v1", string(value.ID), string(value.OccurrenceID), attempt, assignment, value.SourceObjectID.RawValue(), optionalString(value.SourceRevision), sourceFingerprint, result, disposition, terminal)
}

type ReportCounters struct {
	Targeted                             int64 `json:"targeted"`
	Prepared                             int64 `json:"prepared"`
	Submitted                            int64 `json:"submitted"`
	Completed                            int64 `json:"completed"`
	Applied                              int64 `json:"applied"`
	SkippedSourceMissing                 int64 `json:"skippedSourceMissing"`
	SkippedSourceMissingBeforeDisclosure int64 `json:"skippedSourceMissingBeforeDisclosure"`
	SkippedSourceChangedBeforeDisclosure int64 `json:"skippedSourceChangedBeforeDisclosure"`
	ResultNotAppliedSourceMissing        int64 `json:"resultNotAppliedSourceMissing"`
	ResultNotAppliedSourceChanged        int64 `json:"resultNotAppliedSourceChanged"`
	FailedPreparation                    int64 `json:"failedPreparation"`
	FailedExecution                      int64 `json:"failedExecution"`
	InvalidResult                        int64 `json:"invalidResult"`
	CancelledBeforeDisclosure            int64 `json:"cancelledBeforeDisclosure"`
	CancelledAfterDisclosure             int64 `json:"cancelledAfterDisclosure"`
	CancellationUnconfirmed              int64 `json:"cancellationUnconfirmed"`
}

func (value ReportCounters) Validate() error { return value.ValidateLogicalBounds(false) }
func (value ReportCounters) values() []int64 {
	return []int64{value.Targeted, value.Prepared, value.Submitted, value.Completed, value.Applied, value.SkippedSourceMissing, value.SkippedSourceMissingBeforeDisclosure, value.SkippedSourceChangedBeforeDisclosure, value.ResultNotAppliedSourceMissing, value.ResultNotAppliedSourceChanged, value.FailedPreparation, value.FailedExecution, value.InvalidResult, value.CancelledBeforeDisclosure, value.CancelledAfterDisclosure, value.CancellationUnconfirmed}
}
func (value ReportCounters) TerminalCount() int64 {
	return value.Applied + value.SkippedSourceMissing + value.SkippedSourceMissingBeforeDisclosure + value.SkippedSourceChangedBeforeDisclosure + value.ResultNotAppliedSourceMissing + value.ResultNotAppliedSourceChanged + value.FailedPreparation + value.FailedExecution + value.InvalidResult + value.CancelledBeforeDisclosure + value.CancelledAfterDisclosure
}
func (value ReportCounters) ValidateLogicalBounds(allTerminal bool) error {
	values := value.values()
	if value.Targeted < 0 || value.Targeted > maximumItems {
		return invalid("counters.targeted")
	}
	for _, current := range values[1:] {
		if current < 0 || current > value.Targeted {
			return invalid("counters.bounds")
		}
	}
	resultTerminal := value.Applied + value.ResultNotAppliedSourceMissing + value.ResultNotAppliedSourceChanged + value.InvalidResult
	executionTerminal := resultTerminal + value.FailedExecution + value.CancelledAfterDisclosure
	if value.Prepared > value.Targeted || value.Submitted > value.Prepared || value.Completed > value.Submitted || value.Applied > value.Completed || resultTerminal > value.Completed || executionTerminal > value.Submitted || value.TerminalCount() > value.Targeted || value.CancellationUnconfirmed > value.Submitted || value.CancellationUnconfirmed+value.TerminalCount() > value.Targeted || (allTerminal && value.TerminalCount() != value.Targeted) {
		return invalid("counters.bounds")
	}
	return nil
}
func (value ReportCounters) Digest() Digest {
	components := []string{}
	for _, current := range value.values() {
		components = append(components, fmt.Sprint(current))
	}
	return SHA256Digest("facets.compute-queue.report-counters.v1", components...)
}

func ReconcileReport(items []ItemRecord) (ReportCounters, error) {
	r := ReportCounters{Targeted: int64(len(items))}
	for _, item := range items {
		if err := item.Validate(); err != nil {
			return ReportCounters{}, err
		}
		if item.PreparedAt != nil {
			r.Prepared++
		}
		submitted, completed := false, false
		for _, execution := range item.Executions {
			submitted = submitted || execution.ExecutionInputCommittedAt != nil
			completed = completed || execution.ResultCompletedAt != nil
		}
		if submitted {
			r.Submitted++
		}
		if completed {
			r.Completed++
		}
		if current := item.CurrentExecution(); current != nil && current.CancellationUnconfirmed {
			r.CancellationUnconfirmed++
		}
		if item.Disposition == nil {
			continue
		}
		switch *item.Disposition {
		case "applied":
			r.Applied++
		case "skippedSourceMissing":
			r.SkippedSourceMissing++
		case "skippedSourceMissingBeforeDisclosure":
			r.SkippedSourceMissingBeforeDisclosure++
		case "skippedSourceChangedBeforeDisclosure":
			r.SkippedSourceChangedBeforeDisclosure++
		case "resultNotAppliedSourceMissing":
			r.ResultNotAppliedSourceMissing++
		case "resultNotAppliedSourceChanged":
			r.ResultNotAppliedSourceChanged++
		case "failedPreparation":
			r.FailedPreparation++
		case "failedExecution":
			r.FailedExecution++
		case "invalidResult":
			r.InvalidResult++
		case "cancelledBeforeDisclosure":
			r.CancelledBeforeDisclosure++
		case "cancelledAfterDisclosure":
			r.CancelledAfterDisclosure++
		}
	}
	return r, r.Validate()
}

func TerminalItemOutcomesDigest(items []ItemRecord) (Digest, error) {
	if len(items) == 0 || len(items) > maximumItems {
		return "", invalid("terminalItems")
	}
	ordered := append([]ItemRecord(nil), items...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	components := []string{}
	var previous ItemID
	for _, item := range ordered {
		if err := item.Validate(); err != nil {
			return "", err
		}
		if item.Disposition == nil || item.ID == previous {
			return "", invalid("terminalItems")
		}
		previous = item.ID
		components = append(components, string(item.ID), string(item.OccurrenceID), fmt.Sprint(item.Revision), item.SourceObjectID.RawValue(), optionalString(item.SourceRevision), optionalDigest(item.SourceFingerprint), string(item.DestinationKind), string(*item.Disposition), optionalTimestamp(item.PreparedAt), fmt.Sprint(len(item.Executions)))
		for _, e := range item.Executions {
			components = append(components, fmt.Sprint(e.Revision), string(e.AttemptID), fmt.Sprint(e.AttemptNumber), string(e.AssignmentID), optionalWorkerID(e.WorkerID), optionalTimestamp(e.ExecutionInputCommittedAt), optionalTimestamp(e.DisclosureCommittedAt), optionalTimestamp(e.CustodyAcceptedAt), optionalTimestamp(e.ResultCompletedAt), optionalTimestamp(e.TerminalAt), optionalDigest(e.ResultDigest), optionalItemAttemptOutcome(e.Outcome), optionalErrorID(e.ErrorID), fmt.Sprint(e.CancellationUnconfirmed))
		}
		components = append(components, optionalTimestamp(item.TerminalAt), optionalReceiptID(item.ApplicationReceiptID), optionalErrorID(item.ErrorID))
	}
	return SHA256Digest("facets.compute-queue.terminal-item-outcomes.v1", components...), nil
}

func optionalWorkerID(value *WorkerID) string {
	if value == nil {
		return ""
	}
	return string(*value)
}
func optionalReceiptID(value *ReceiptID) string {
	if value == nil {
		return ""
	}
	return string(*value)
}
func optionalItemAttemptOutcome(value *ItemAttemptOutcome) string {
	if value == nil {
		return ""
	}
	return string(*value)
}

func equalOptionalErrorID(left, right *ErrorID) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}
