package computequeue

import (
	"fmt"
	"sort"
)

// OccurrenceRecord is the immutable, source-authoritative snapshot for one
// eligible schedule slot plus its monotonically updated progress report.
// It is intentionally source-only; custody never receives this complete
// semantic record.
type OccurrenceRecord struct {
	ProtocolVersion            int                      `json:"protocolVersion"`
	ID                         OccurrenceID             `json:"id"`
	ScheduleID                 ScheduleID               `json:"scheduleID"`
	DestinationKind            DestinationKind          `json:"destinationKind"`
	Revision                   uint64                   `json:"revision"`
	EligibilityKey             string                   `json:"eligibilityKey"`
	EligibilityDigest          Digest                   `json:"eligibilityDigest"`
	ScheduledFor               Timestamp                `json:"scheduledFor"`
	EligibleAt                 Timestamp                `json:"eligibleAt"`
	PreparedAt                 *Timestamp               `json:"preparedAt,omitempty"`
	State                      OccurrenceState          `json:"state"`
	ScheduleRevision           uint64                   `json:"scheduleRevision"`
	TargetSetDigest            Digest                   `json:"targetSetDigest"`
	OperationBinding           OperationBinding         `json:"operationBinding"`
	PolicySnapshot             OccurrencePolicySnapshot `json:"policySnapshot"`
	ExecutionIdentityDigest    Digest                   `json:"executionIdentityDigest"`
	DestinationPolicyDigest    Digest                   `json:"destinationPolicyDigest"`
	OccurrenceSnapshotDigest   Digest                   `json:"occurrenceSnapshotDigest"`
	Report                     ReportCounters           `json:"report"`
	TerminalItemOutcomesDigest *Digest                  `json:"terminalItemOutcomesDigest,omitempty"`
	TerminalReportDigest       *Digest                  `json:"terminalReportDigest,omitempty"`
	ReceiptIDs                 []ReceiptID              `json:"receiptIDs"`
	SourceReceiptSigner        ReceiptSignerBinding     `json:"sourceReceiptSigner"`
	CustodyReceiptSigner       *ReceiptSignerBinding    `json:"custodyReceiptSigner,omitempty"`
	LastTransitionID           *TransitionID            `json:"lastTransitionID,omitempty"`
	StateChangedAt             Timestamp                `json:"stateChangedAt"`
	LastReason                 *TransitionReason        `json:"lastReason,omitempty"`
	LastErrorID                *ErrorID                 `json:"lastErrorID,omitempty"`
}

func MakeEligibilityKey(scheduledFor Timestamp) string {
	return "slot:" + fmt.Sprint(scheduledFor)
}

func (value OccurrenceRecord) ScheduleAuthorizationDigest() Digest {
	return scheduleAuthorizationDigest(
		value.ScheduleID,
		value.EligibilityDigest,
		value.Report.Targeted,
		value.TargetSetDigest,
		value.OperationBinding.Digest(),
		value.PolicySnapshot.PolicyBinding.Digest(),
		value.ExecutionIdentityDigest,
		value.DestinationPolicyDigest,
		value.SourceReceiptSigner,
		value.CustodyReceiptSigner,
	)
}

func (value OccurrenceRecord) MakeSnapshotDigest() Digest {
	components := []string{
		string(value.ID),
		string(value.ScheduleID),
		fmt.Sprint(value.ScheduleRevision),
		string(value.DestinationKind),
		value.EligibilityKey,
		string(value.EligibilityDigest),
		fmt.Sprint(value.ScheduledFor),
		fmt.Sprint(value.EligibleAt),
		fmt.Sprint(value.Report.Targeted),
		string(value.TargetSetDigest),
		string(value.OperationBinding.Digest()),
		string(value.PolicySnapshot.Digest()),
		string(value.ExecutionIdentityDigest),
		string(value.DestinationPolicyDigest),
		string(value.SourceReceiptSigner.SignerID),
		string(value.SourceReceiptSigner.SigningKeyID),
		fmt.Sprint(value.SourceReceiptSigner.SigningKeyRevision),
		value.SourceReceiptSigner.SignatureProfileID,
	}
	if value.CustodyReceiptSigner == nil {
		components = append(components, "", "", "", "")
	} else {
		components = append(components,
			string(value.CustodyReceiptSigner.SignerID),
			string(value.CustodyReceiptSigner.SigningKeyID),
			fmt.Sprint(value.CustodyReceiptSigner.SigningKeyRevision),
			value.CustodyReceiptSigner.SignatureProfileID,
		)
	}
	return SHA256Digest("facets.compute-queue.occurrence-snapshot.v1", components...)
}

func MakeTerminalReportDigest(reportDigest, itemOutcomesDigest Digest) Digest {
	return SHA256Digest("facets.compute-queue.terminal-report.v1", string(reportDigest), string(itemOutcomesDigest))
}

func (value OccurrenceRecord) Validate() error {
	if err := requireProtocol(value.ProtocolVersion); err != nil {
		return err
	}
	for _, err := range []error{
		value.ID.Validate(), value.ScheduleID.Validate(), value.EligibilityDigest.Validate(),
		value.TargetSetDigest.Validate(), value.ExecutionIdentityDigest.Validate(),
		value.DestinationPolicyDigest.Validate(), value.OccurrenceSnapshotDigest.Validate(),
		value.SourceReceiptSigner.Validate(),
	} {
		if err != nil {
			return err
		}
	}
	if err := requirePositive(value.Revision, "revision"); err != nil {
		return err
	}
	if err := requirePositive(value.ScheduleRevision, "scheduleRevision"); err != nil {
		return err
	}
	if !value.DestinationKind.valid() || !value.State.valid() {
		return invalid("occurrence.state")
	}
	if err := value.OperationBinding.Validate(); err != nil {
		return err
	}
	if err := value.PolicySnapshot.Validate(); err != nil {
		return err
	}
	if err := requireNonempty(value.EligibilityKey, "eligibilityKey"); err != nil {
		return err
	}
	if value.EligibilityKey != MakeEligibilityKey(value.ScheduledFor) {
		return invalid("occurrence.eligibilityKey")
	}
	if err := value.ScheduledFor.Validate(); err != nil {
		return err
	}
	if err := value.EligibleAt.Validate(); err != nil {
		return err
	}
	if value.EligibleAt < value.ScheduledFor {
		return invalid("eligibleAt")
	}
	if value.PreparedAt != nil {
		if err := value.PreparedAt.Validate(); err != nil {
			return err
		}
		if *value.PreparedAt < value.EligibleAt {
			return invalid("preparedAt")
		}
	}
	if err := value.StateChangedAt.Validate(); err != nil {
		return err
	}
	if value.StateChangedAt < value.EligibleAt || value.EligibleAt < value.PolicySnapshot.AdmissionNotBeforeAt || value.EligibleAt >= value.PolicySnapshot.ExecutionExpiresAt {
		return invalid("occurrenceSnapshotDigest")
	}
	if value.OccurrenceSnapshotDigest != value.MakeSnapshotDigest() {
		return invalid("occurrenceSnapshotDigest")
	}
	if value.LastReason != nil {
		if err := value.LastReason.Validate(); err != nil {
			return err
		}
	}
	if !sameErrorID(value.LastReason, value.LastErrorID) {
		return invalid("occurrence.lastTransition")
	}
	if value.LastTransitionID == nil {
		if value.State != "eligible" || value.Revision != 1 || value.StateChangedAt != value.EligibleAt || value.LastReason != nil || value.LastErrorID != nil {
			return invalid("occurrence.initialState")
		}
	} else {
		if err := value.LastTransitionID.Validate(); err != nil {
			return err
		}
		if value.Revision <= 1 {
			return invalid("occurrence.lastTransition")
		}
	}
	if value.DestinationKind == DestinationDirectLocal {
		if occurrenceExternalOnly(value.State) || value.CustodyReceiptSigner != nil {
			return invalid("occurrence.directLocalState")
		}
	} else {
		if occurrenceLocalOnly(value.State) || value.CustodyReceiptSigner == nil {
			return invalid("occurrence.externalState")
		}
		if err := value.CustodyReceiptSigner.Validate(); err != nil {
			return err
		}
	}
	if err := value.Report.ValidateLogicalBounds(occurrenceTerminal(value.State)); err != nil {
		return err
	}
	if value.ReceiptIDs == nil || len(value.ReceiptIDs) > maximumReceipts {
		return invalid("receiptIDs")
	}
	receipts := make([]string, len(value.ReceiptIDs))
	for index, id := range value.ReceiptIDs {
		if err := id.Validate(); err != nil {
			return err
		}
		receipts[index] = string(id)
	}
	if err := requireUniqueSorted(receipts, "receiptIDs"); err != nil {
		return err
	}
	if occurrenceTerminal(value.State) {
		if value.TerminalItemOutcomesDigest == nil || value.TerminalReportDigest == nil {
			return invalid("terminalReportDigest")
		}
		if err := value.TerminalItemOutcomesDigest.Validate(); err != nil {
			return err
		}
		if err := value.TerminalReportDigest.Validate(); err != nil {
			return err
		}
		if *value.TerminalReportDigest != MakeTerminalReportDigest(value.Report.Digest(), *value.TerminalItemOutcomesDigest) {
			return invalid("terminalReportDigest")
		}
	} else if value.TerminalItemOutcomesDigest != nil || value.TerminalReportDigest != nil {
		return invalid("terminalReportDigest")
	}
	return value.validateTerminalStateReport()
}

// ValidateUpdateFrom validates a same-state occurrence revision. State
// transitions use the evidence-bearing overload in occurrence_update.go.
func (value OccurrenceRecord) ValidateUpdateFrom(previous OccurrenceRecord) error {
	if err := value.Validate(); err != nil {
		return err
	}
	if occurrenceTerminal(previous.State) || value.State != previous.State ||
		value.ID != previous.ID || value.ScheduleID != previous.ScheduleID || value.DestinationKind != previous.DestinationKind ||
		value.EligibilityKey != previous.EligibilityKey || value.EligibilityDigest != previous.EligibilityDigest ||
		value.ScheduledFor != previous.ScheduledFor || value.EligibleAt != previous.EligibleAt ||
		value.ScheduleRevision != previous.ScheduleRevision || value.TargetSetDigest != previous.TargetSetDigest ||
		value.OperationBinding.Digest() != previous.OperationBinding.Digest() || value.PolicySnapshot.Digest() != previous.PolicySnapshot.Digest() ||
		value.ExecutionIdentityDigest != previous.ExecutionIdentityDigest || value.DestinationPolicyDigest != previous.DestinationPolicyDigest ||
		value.OccurrenceSnapshotDigest != previous.OccurrenceSnapshotDigest || value.SourceReceiptSigner != previous.SourceReceiptSigner ||
		!sameSigner(value.CustodyReceiptSigner, previous.CustodyReceiptSigner) ||
		!equalOptionalTransitionID(value.LastTransitionID, previous.LastTransitionID) || value.StateChangedAt != previous.StateChangedAt ||
		!sameTransitionReason(value.LastReason, previous.LastReason) || !equalOptionalErrorID(value.LastErrorID, previous.LastErrorID) {
		return invalid("occurrence")
	}
	if previous.PreparedAt != nil && !equalOptionalTimestamp(value.PreparedAt, previous.PreparedAt) {
		return invalid("preparedAt")
	}
	if previous.Revision == ^uint64(0) || value.Revision != previous.Revision+1 {
		return invalid("occurrence.revision")
	}
	oldCounters, newCounters := previous.Report.values(), value.Report.values()
	if value.Report.Targeted != previous.Report.Targeted {
		return invalid("counters.regression")
	}
	for index := 1; index < len(oldCounters)-1; index++ {
		if newCounters[index] < oldCounters[index] {
			return invalid("counters.regression")
		}
	}
	if !receiptSubset(previous.ReceiptIDs, value.ReceiptIDs) {
		return invalid("receiptIDs")
	}
	return nil
}

func equalOptionalTransitionID(left, right *TransitionID) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}

func (value OccurrenceRecord) ValidateAuthorizedBy(schedule ScheduleRecord) error {
	if err := value.Validate(); err != nil {
		return err
	}
	if err := schedule.Validate(); err != nil {
		return err
	}
	if value.ScheduleID != schedule.ID || value.ScheduleRevision > schedule.Revision ||
		value.ScheduleAuthorizationDigest() != schedule.AuthorizationDigest() ||
		value.EligibilityDigest != schedule.Eligibility.Digest() ||
		value.DestinationKind != schedule.DestinationPolicy.Kind ||
		value.TargetSetDigest != schedule.TargetSetDigest ||
		value.OperationBinding != schedule.OperationBinding ||
		value.PolicySnapshot.PolicyBinding.Digest() != schedule.PolicyBinding.Digest() ||
		value.ExecutionIdentityDigest != schedule.ExecutionIdentity.Digest() ||
		value.DestinationPolicyDigest != schedule.DestinationPolicy.Digest() ||
		value.Report.Targeted != schedule.TargetCount ||
		value.SourceReceiptSigner != schedule.SourceReceiptSigner ||
		!sameSigner(value.CustodyReceiptSigner, schedule.DestinationPolicy.CustodyReceiptSigner) {
		return invalid("scheduleOccurrenceAuthorization")
	}
	return nil
}

func (value OccurrenceRecord) ValidateCreation(schedule ScheduleRecord) error {
	if err := value.ValidateAuthorizedBy(schedule); err != nil {
		return err
	}
	if schedule.State != "active" || value.ScheduleRevision != schedule.Revision {
		return invalid("occurrence.scheduleCreationAuthorization")
	}
	if schedule.Eligibility.Kind == "immediate" {
		if value.ScheduledFor != schedule.Eligibility.FirstEligibleAt || value.EligibleAt != schedule.Eligibility.FirstEligibleAt {
			return invalid("occurrence.immediateEligibility")
		}
	} else if value.ScheduledFor < schedule.Eligibility.FirstEligibleAt {
		return invalid("occurrence.recurringEligibility")
	}
	return nil
}

func (value OccurrenceRecord) ValidateAgainstItems(items []ItemRecord) error {
	if err := value.Validate(); err != nil {
		return err
	}
	ids := make([]FacetsObjectID, len(items))
	for index, item := range items {
		if err := item.Validate(); err != nil {
			return err
		}
		if item.OccurrenceID != value.ID || item.DestinationKind != value.DestinationKind {
			return invalid("occurrence.items")
		}
		ids[index] = item.SourceObjectID
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].RawValue() < ids[j].RawValue() })
	raw := make([]string, len(ids))
	for index, id := range ids {
		raw[index] = id.RawValue()
	}
	if err := requireUniqueSorted(raw, "occurrence.items.sourceObjectID"); err != nil {
		return err
	}
	if MakeTargetSetDigest(ids) != value.TargetSetDigest {
		return invalid("targetSetDigest")
	}
	reconciled, err := ReconcileReport(items)
	if err != nil {
		return err
	}
	if reconciled != value.Report {
		return invalid("report")
	}
	if occurrenceTerminal(value.State) {
		digest, err := TerminalItemOutcomesDigest(items)
		if err != nil {
			return err
		}
		if value.TerminalItemOutcomesDigest == nil || *value.TerminalItemOutcomesDigest != digest || value.TerminalReportDigest == nil || *value.TerminalReportDigest != MakeTerminalReportDigest(value.Report.Digest(), digest) {
			return invalid("terminalReportDigest")
		}
	}
	return nil
}

// ValidateSourceBound is the strong authorization boundary for an occurrence
// loaded for persistence or publication. It proves the schedule and frozen
// population bindings, authenticated terminal execution evidence, and every
// durable source-application receipt. Decoded attempts and raw receipts are
// deliberately insufficient; callers must supply authorization proofs.
func (value OccurrenceRecord) ValidateSourceBound(
	schedule ScheduleRecord,
	items []ItemRecord,
	receipts []VerifiedReceipt,
	authorizedAttempts []AuthorizedAttempt,
	assignments []AssignmentRecord,
	resultManifests []AssignmentResultManifest,
	errorRecords []ErrorRecord,
) error {
	if err := value.ValidateAuthorizedBy(schedule); err != nil {
		return err
	}
	if err := value.ValidateAgainstItems(items); err != nil {
		return err
	}
	receiptIndex, err := newVerifiedReceiptIndex(receipts)
	if err != nil {
		return err
	}
	if err := value.validateTerminalResultEvidence(items, authorizedAttempts, assignments, resultManifests, errorRecords, receiptIndex); err != nil {
		return err
	}
	for _, item := range items {
		if err := item.validateApplication(receiptIndex, value.SourceReceiptSigner); err != nil {
			return err
		}
		if item.ApplicationReceiptID != nil && !containsReceiptID(value.ReceiptIDs, *item.ApplicationReceiptID) {
			return invalid("missingTransitionReceipt")
		}
	}
	return nil
}

func (value OccurrenceRecord) validateTerminalStateReport() error {
	if !occurrenceTerminal(value.State) {
		return nil
	}
	switch value.State {
	case "completed":
		if value.Report.Applied != value.Report.Targeted {
			return invalid("completedState")
		}
	case "cancelled":
		if value.Report.CancelledBeforeDisclosure+value.Report.CancelledAfterDisclosure != value.Report.Targeted {
			return invalid("cancelledState")
		}
	case "failed":
		if value.Report.FailedPreparation+value.Report.FailedExecution+value.Report.InvalidResult != value.Report.Targeted {
			return invalid("failedState")
		}
	case "completedWithErrors":
		cancelled := value.Report.CancelledBeforeDisclosure + value.Report.CancelledAfterDisclosure
		failed := value.Report.FailedPreparation + value.Report.FailedExecution + value.Report.InvalidResult
		if value.Report.Applied == value.Report.Targeted || cancelled == value.Report.Targeted || failed == value.Report.Targeted {
			return invalid("completedWithErrorsState")
		}
	}
	return nil
}

func occurrenceTerminal(state OccurrenceState) bool {
	return oneOf(string(state), "completed", "completedWithErrors", "cancelled", "failed")
}

func occurrenceExternalOnly(state OccurrenceState) bool {
	return oneOf(string(state), "waitingForSpace", "waitingForStorage", "securelyQueued", "running", "resultsPendingSpace", "applying")
}

func occurrenceLocalOnly(state OccurrenceState) bool {
	return oneOf(string(state), "localRunning", "localApplying")
}

func sameSigner(left, right *ReceiptSignerBinding) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}

func sameErrorID(reason *TransitionReason, errorID *ErrorID) bool {
	if reason == nil {
		return errorID == nil
	}
	if reason.ErrorID == nil || errorID == nil {
		return reason.ErrorID == nil && errorID == nil
	}
	return *reason.ErrorID == *errorID
}
