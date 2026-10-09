package computequeue

import (
	"fmt"
	"sort"
)

type AssignmentAuthorization struct {
	AssignmentID           AssignmentID    `json:"assignmentID"`
	Executor               ExecutorBinding `json:"executor"`
	ItemIDs                []ItemID        `json:"itemIDs"`
	ItemSetDigest          Digest          `json:"itemSetDigest"`
	ExecutionPayloadDigest Digest          `json:"executionPayloadDigest"`
	CapsuleID              *JobCapsuleID   `json:"capsuleID,omitempty"`
	CapsuleDigest          *Digest         `json:"capsuleDigest,omitempty"`
	InitialLease           *LeaseBinding   `json:"initialLease,omitempty"`
	CancellationFence      uint64          `json:"cancellationFence"`
}

func MakeAssignmentItemSetDigest(itemIDs []ItemID) Digest {
	components := make([]string, len(itemIDs))
	for index, id := range itemIDs {
		components[index] = string(id)
	}
	return SHA256Digest("facets.compute-queue.assignment-item-set.v1", components...)
}

func (value AssignmentAuthorization) Validate() error {
	if err := value.AssignmentID.Validate(); err != nil {
		return err
	}
	if err := value.Executor.Validate(); err != nil {
		return err
	}
	if len(value.ItemIDs) == 0 || len(value.ItemIDs) > maximumAssignmentItems {
		return invalid("assignmentAuthorization.itemIDs")
	}
	raw := make([]string, len(value.ItemIDs))
	for index, id := range value.ItemIDs {
		if err := id.Validate(); err != nil {
			return err
		}
		raw[index] = string(id)
	}
	if err := requireUniqueSorted(raw, "assignmentAuthorization.itemIDs"); err != nil {
		return err
	}
	if value.ItemSetDigest != MakeAssignmentItemSetDigest(value.ItemIDs) {
		return invalid("assignmentAuthorization.itemIDs")
	}
	if err := value.ExecutionPayloadDigest.Validate(); err != nil {
		return err
	}
	if value.Executor.Kind == ExecutorSourceLocal {
		if value.CapsuleID != nil || value.CapsuleDigest != nil || value.InitialLease != nil || value.CancellationFence != 0 {
			return invalid("assignmentAuthorization.localCapsule")
		}
	} else {
		if value.CapsuleID == nil || value.CapsuleDigest == nil || value.InitialLease == nil || value.CancellationFence != 1 {
			return invalid("assignmentAuthorization.workerCapsule")
		}
		if err := value.CapsuleID.Validate(); err != nil {
			return err
		}
		if err := value.CapsuleDigest.Validate(); err != nil {
			return err
		}
		if err := value.InitialLease.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (value AssignmentAuthorization) digestComponents() []string {
	components := []string{string(value.AssignmentID)}
	components = append(components, value.Executor.digestComponents()...)
	for _, id := range value.ItemIDs {
		components = append(components, string(id))
	}
	leaseDigest := ""
	if value.InitialLease != nil {
		leaseDigest = string(value.InitialLease.Digest())
	}
	return append(components,
		string(value.ItemSetDigest),
		string(value.ExecutionPayloadDigest),
		optionalJobCapsuleID(value.CapsuleID),
		optionalDigest(value.CapsuleDigest),
		leaseDigest,
		fmt.Sprint(value.CancellationFence),
	)
}

func (value AssignmentAuthorization) receiptSubjectDigest(
	occurrenceID OccurrenceID,
	attemptID AttemptID,
	receipt ReceiptRecord,
) Digest {
	components := []string{string(occurrenceID), string(attemptID), string(value.AssignmentID)}
	components = append(components, value.Executor.digestComponents()...)
	for _, id := range value.ItemIDs {
		components = append(components, string(id))
	}
	leaseID, leaseRevision, leaseExpiresAt := receipt.LeaseID, receipt.LeaseRevision, receipt.LeaseExpiresAt
	if value.InitialLease != nil {
		if leaseID == nil {
			leaseID = &value.InitialLease.ID
		}
		if leaseRevision == nil {
			leaseRevision = &value.InitialLease.Revision
		}
		if leaseExpiresAt == nil {
			leaseExpiresAt = &value.InitialLease.ExpiresAt
		}
	}
	components = append(components,
		string(value.ItemSetDigest), string(value.ExecutionPayloadDigest),
		optionalJobCapsuleID(value.CapsuleID), optionalDigest(value.CapsuleDigest),
		string(receipt.Stage), optionalItemID(receipt.ItemID), optionalExecutionOutcome(receipt.ExecutionOutcome),
		optionalDigest(receipt.ResultDigest), optionalDigest(receipt.ResultCapsuleDigest), optionalErrorID(receipt.ErrorID),
		optionalDigest(receipt.ErrorDigest), optionalLeaseID(leaseID), optionalUint64(leaseRevision),
		optionalTimestamp(leaseExpiresAt), fmt.Sprint(receipt.CancellationFence),
	)
	return SHA256Digest("facets.compute-queue.assignment-receipt-subject.v1", components...)
}

type AssignmentPlan struct {
	Assignments         []AssignmentAuthorization `json:"assignments"`
	AssignmentSetDigest Digest                    `json:"assignmentSetDigest"`
}

func (value AssignmentPlan) Validate() error {
	if len(value.Assignments) == 0 || len(value.Assignments) > maximumAssignments {
		return invalid("assignments")
	}
	assignmentIDs := make([]string, len(value.Assignments))
	seenExecutors := map[string]struct{}{}
	seenOfferings := map[string]struct{}{}
	seenItems := map[ItemID]struct{}{}
	totalItems := 0
	for index, assignment := range value.Assignments {
		if err := assignment.Validate(); err != nil {
			return err
		}
		assignmentIDs[index] = string(assignment.AssignmentID)
		stableID := assignment.Executor.stableID()
		if _, exists := seenExecutors[stableID]; exists {
			return invalid("assignments.executor")
		}
		seenExecutors[stableID] = struct{}{}
		if assignment.Executor.Worker != nil {
			offering := string(assignment.Executor.Worker.OfferingID)
			if _, exists := seenOfferings[offering]; exists {
				return invalid("assignments.offeringID")
			}
			seenOfferings[offering] = struct{}{}
		}
		totalItems += len(assignment.ItemIDs)
		if totalItems > maximumItems {
			return invalid("assignments.itemIDs")
		}
		for _, id := range assignment.ItemIDs {
			if _, exists := seenItems[id]; exists {
				return invalid("assignments.itemIDs")
			}
			seenItems[id] = struct{}{}
		}
	}
	if err := requireUniqueSorted(assignmentIDs, "assignments.assignmentID"); err != nil {
		return err
	}
	if value.AssignmentSetDigest != value.makeDigest() {
		return invalid("assignmentSetDigest")
	}
	return nil
}

func (value AssignmentPlan) makeDigest() Digest {
	components := []string{}
	for _, assignment := range value.Assignments {
		components = append(components, assignment.digestComponents()...)
	}
	return SHA256Digest("facets.compute-queue.assignment-set.v1", components...)
}

func (value AssignmentPlan) ValidateCovers(itemIDs []ItemID) error {
	if err := value.Validate(); err != nil {
		return err
	}
	expected := append([]ItemID(nil), itemIDs...)
	actual := []ItemID{}
	for _, assignment := range value.Assignments {
		actual = append(actual, assignment.ItemIDs...)
	}
	sort.Slice(expected, func(i, j int) bool { return expected[i] < expected[j] })
	sort.Slice(actual, func(i, j int) bool { return actual[i] < actual[j] })
	if len(expected) != len(actual) {
		return invalid("assignmentPlan.coverage")
	}
	for index := range expected {
		if expected[index] != actual[index] {
			return invalid("assignmentPlan.coverage")
		}
	}
	return nil
}

func (value AssignmentPlan) WorkerSetDigest() *Digest {
	workers := make([]WorkerBinding, 0, len(value.Assignments))
	for _, assignment := range value.Assignments {
		if assignment.Executor.Worker == nil {
			return nil
		}
		workers = append(workers, *assignment.Executor.Worker)
	}
	sort.Slice(workers, func(i, j int) bool { return workers[i].WorkerID < workers[j].WorkerID })
	components := []string{}
	for _, worker := range workers {
		components = append(components, worker.digestComponents()...)
	}
	digest := SHA256Digest("facets.compute-queue.fixed-worker-set.v1", components...)
	return &digest
}

type AttemptRecord struct {
	ProtocolVersion                  int                   `json:"protocolVersion"`
	ID                               AttemptID             `json:"id"`
	OccurrenceID                     OccurrenceID          `json:"occurrenceID"`
	Revision                         uint64                `json:"revision"`
	AttemptNumber                    uint64                `json:"attemptNumber"`
	State                            AttemptState          `json:"state"`
	DestinationKind                  DestinationKind       `json:"destinationKind"`
	ExecutionIdentity                ExecutionIdentity     `json:"executionIdentity"`
	OccurrenceSnapshotDigest         Digest                `json:"occurrenceSnapshotDigest"`
	OperationBindingDigest           Digest                `json:"operationBindingDigest"`
	PolicySnapshotDigest             Digest                `json:"policySnapshotDigest"`
	RetryPolicyDigest                Digest                `json:"retryPolicyDigest"`
	PreviousAttemptID                *AttemptID            `json:"previousAttemptID,omitempty"`
	RetryErrorID                     *ErrorID              `json:"retryErrorID,omitempty"`
	NotBeforeAt                      *Timestamp            `json:"notBeforeAt,omitempty"`
	AssignmentPlan                   AssignmentPlan        `json:"assignmentPlan"`
	AuthorizedWorkerSetDigest        *Digest               `json:"authorizedWorkerSetDigest,omitempty"`
	ComputePoolPolicyDigest          *Digest               `json:"computePoolPolicyDigest,omitempty"`
	ComputePoolGrantDigest           *Digest               `json:"computePoolGrantDigest,omitempty"`
	ComputePoolAssignmentSetDigest   *Digest               `json:"computePoolAssignmentSetDigest,omitempty"`
	SourceReceiptSigner              ReceiptSignerBinding  `json:"sourceReceiptSigner"`
	CustodyReceiptSigner             *ReceiptSignerBinding `json:"custodyReceiptSigner,omitempty"`
	TerminalAssignmentOutcomesDigest *Digest               `json:"terminalAssignmentOutcomesDigest,omitempty"`
	CreatedAt                        Timestamp             `json:"createdAt"`
	DeadlineAt                       *Timestamp            `json:"deadlineAt,omitempty"`
	ReceiptIDs                       []ReceiptID           `json:"receiptIDs"`
}

func (value AttemptRecord) Validate() error {
	if err := requireProtocol(value.ProtocolVersion); err != nil {
		return err
	}
	for _, err := range []error{value.ID.Validate(), value.OccurrenceID.Validate(), value.ExecutionIdentity.Validate(), value.OccurrenceSnapshotDigest.Validate(), value.OperationBindingDigest.Validate(), value.PolicySnapshotDigest.Validate(), value.RetryPolicyDigest.Validate(), value.SourceReceiptSigner.Validate()} {
		if err != nil {
			return err
		}
	}
	if err := requirePositive(value.Revision, "revision"); err != nil {
		return err
	}
	if err := requirePositive(value.AttemptNumber, "attemptNumber"); err != nil {
		return err
	}
	if !value.State.valid() || !value.DestinationKind.valid() {
		return invalid("attempt.state")
	}
	if err := value.AssignmentPlan.Validate(); err != nil {
		return err
	}
	if value.AttemptNumber == 1 {
		if value.PreviousAttemptID != nil || value.RetryErrorID != nil || value.NotBeforeAt != nil {
			return invalid("attempt.retryLineage")
		}
	} else {
		if value.PreviousAttemptID == nil || value.RetryErrorID == nil || value.NotBeforeAt == nil {
			return invalid("attempt.retryLineage")
		}
		if err := value.PreviousAttemptID.Validate(); err != nil {
			return err
		}
		if err := value.RetryErrorID.Validate(); err != nil {
			return err
		}
		if err := value.NotBeforeAt.Validate(); err != nil {
			return err
		}
	}
	if value.DestinationKind == DestinationDirectLocal {
		if len(value.AssignmentPlan.Assignments) != 1 || value.AssignmentPlan.Assignments[0].Executor.Kind != ExecutorSourceLocal || attemptExternalOnly(value.State) || value.AuthorizedWorkerSetDigest != nil || value.ComputePoolPolicyDigest != nil || value.ComputePoolGrantDigest != nil || value.ComputePoolAssignmentSetDigest != nil || value.CustodyReceiptSigner != nil {
			return invalid("attempt.directLocal")
		}
	} else if value.DestinationKind == DestinationFixedWorkers {
		workerDigest := value.AssignmentPlan.WorkerSetDigest()
		if workerDigest == nil || value.AuthorizedWorkerSetDigest == nil || attemptLocalOnly(value.State) || value.CustodyReceiptSigner == nil || value.ComputePoolPolicyDigest != nil || value.ComputePoolGrantDigest != nil || value.ComputePoolAssignmentSetDigest != nil {
			return invalid("attempt.fixedWorkers")
		}
	} else {
		workerDigest := value.AssignmentPlan.WorkerSetDigest()
		if value.AuthorizedWorkerSetDigest != nil || workerDigest == nil || attemptLocalOnly(value.State) || value.CustodyReceiptSigner == nil || value.ComputePoolPolicyDigest == nil || value.ComputePoolGrantDigest == nil || value.ComputePoolAssignmentSetDigest == nil || *value.ComputePoolAssignmentSetDigest != value.AssignmentPlan.AssignmentSetDigest {
			return invalid("attempt.computePool")
		}
	}
	for _, digest := range []*Digest{value.AuthorizedWorkerSetDigest, value.ComputePoolPolicyDigest, value.ComputePoolGrantDigest, value.ComputePoolAssignmentSetDigest, value.TerminalAssignmentOutcomesDigest} {
		if digest != nil {
			if err := digest.Validate(); err != nil {
				return err
			}
		}
	}
	if value.CustodyReceiptSigner != nil {
		if err := value.CustodyReceiptSigner.Validate(); err != nil {
			return err
		}
	}
	if value.State == "settled" {
		if value.TerminalAssignmentOutcomesDigest == nil {
			return invalid("terminalAssignmentOutcomesDigest")
		}
	} else if value.State != "released" && value.TerminalAssignmentOutcomesDigest != nil {
		return invalid("terminalAssignmentOutcomesDigest")
	}
	if err := value.CreatedAt.Validate(); err != nil {
		return err
	}
	if value.DeadlineAt != nil {
		if err := value.DeadlineAt.Validate(); err != nil {
			return err
		}
		if *value.DeadlineAt <= value.CreatedAt {
			return invalid("deadlineAt")
		}
	}
	if value.ReceiptIDs == nil {
		return invalid("receiptIDs")
	}
	return validateReceiptIDs(value.ReceiptIDs)
}

// ValidateUpdateFrom validates a same-state attempt revision. State advances
// must use AuthorizedAttempt.Advance so a raw decoded record cannot become
// transition authority.
func (value AttemptRecord) ValidateUpdateFrom(previous AttemptRecord) error {
	if err := value.Validate(); err != nil {
		return err
	}
	if value.State != previous.State || value.ID != previous.ID || value.OccurrenceID != previous.OccurrenceID ||
		value.AttemptNumber != previous.AttemptNumber || previous.Revision == ^uint64(0) || value.Revision != previous.Revision+1 {
		return invalid("attempt")
	}
	if value.DestinationKind != previous.DestinationKind || value.ExecutionIdentity.Digest() != previous.ExecutionIdentity.Digest() ||
		value.OccurrenceSnapshotDigest != previous.OccurrenceSnapshotDigest || value.OperationBindingDigest != previous.OperationBindingDigest ||
		value.PolicySnapshotDigest != previous.PolicySnapshotDigest || value.RetryPolicyDigest != previous.RetryPolicyDigest ||
		!equalOptionalAttemptID(value.PreviousAttemptID, previous.PreviousAttemptID) || !equalOptionalErrorID(value.RetryErrorID, previous.RetryErrorID) ||
		!equalOptionalTimestamp(value.NotBeforeAt, previous.NotBeforeAt) || !equalOptionalDigest(value.AuthorizedWorkerSetDigest, previous.AuthorizedWorkerSetDigest) ||
		!equalOptionalDigest(value.ComputePoolPolicyDigest, previous.ComputePoolPolicyDigest) || !equalOptionalDigest(value.ComputePoolGrantDigest, previous.ComputePoolGrantDigest) ||
		!equalOptionalDigest(value.ComputePoolAssignmentSetDigest, previous.ComputePoolAssignmentSetDigest) ||
		value.SourceReceiptSigner != previous.SourceReceiptSigner || !sameSigner(value.CustodyReceiptSigner, previous.CustodyReceiptSigner) ||
		!equalOptionalDigest(value.TerminalAssignmentOutcomesDigest, previous.TerminalAssignmentOutcomesDigest) ||
		value.CreatedAt != previous.CreatedAt || !equalOptionalTimestamp(value.DeadlineAt, previous.DeadlineAt) {
		return invalid("executionIdentity")
	}
	if value.AssignmentPlan.AssignmentSetDigest != previous.AssignmentPlan.AssignmentSetDigest {
		return invalid("fixedWorkerSetMutation")
	}
	if !receiptSubset(previous.ReceiptIDs, value.ReceiptIDs) {
		return invalid("receiptIDs")
	}
	return nil
}

type AssignmentRecord struct {
	ProtocolVersion          int                   `json:"protocolVersion"`
	ID                       AssignmentID          `json:"id"`
	OccurrenceID             OccurrenceID          `json:"occurrenceID"`
	AttemptID                AttemptID             `json:"attemptID"`
	Revision                 uint64                `json:"revision"`
	State                    AssignmentState       `json:"state"`
	Executor                 ExecutorBinding       `json:"executor"`
	ItemIDs                  []ItemID              `json:"itemIDs"`
	ItemSetDigest            Digest                `json:"itemSetDigest"`
	ExecutionPayloadDigest   Digest                `json:"executionPayloadDigest"`
	CapsuleID                *JobCapsuleID         `json:"capsuleID,omitempty"`
	CapsuleDigest            *Digest               `json:"capsuleDigest,omitempty"`
	InitialLease             *LeaseBinding         `json:"initialLease,omitempty"`
	CurrentLease             *LeaseBinding         `json:"currentLease,omitempty"`
	InitialCancellationFence uint64                `json:"initialCancellationFence"`
	CancellationFence        uint64                `json:"cancellationFence"`
	SourceReceiptSigner      ReceiptSignerBinding  `json:"sourceReceiptSigner"`
	CustodyReceiptSigner     *ReceiptSignerBinding `json:"custodyReceiptSigner,omitempty"`
	CreatedAt                Timestamp             `json:"createdAt"`
	DeadlineAt               *Timestamp            `json:"deadlineAt,omitempty"`
	ReceiptIDs               []ReceiptID           `json:"receiptIDs"`
}

func (value AssignmentRecord) Validate() error {
	if err := requireProtocol(value.ProtocolVersion); err != nil {
		return err
	}
	for _, err := range []error{value.ID.Validate(), value.OccurrenceID.Validate(), value.AttemptID.Validate(), value.Executor.Validate(), value.ItemSetDigest.Validate(), value.ExecutionPayloadDigest.Validate(), value.SourceReceiptSigner.Validate()} {
		if err != nil {
			return err
		}
	}
	if err := requirePositive(value.Revision, "revision"); err != nil {
		return err
	}
	if !value.State.valid() {
		return invalid("assignment.state")
	}
	if len(value.ItemIDs) == 0 || len(value.ItemIDs) > maximumAssignmentItems {
		return invalid("itemIDs")
	}
	raw := make([]string, len(value.ItemIDs))
	for index, id := range value.ItemIDs {
		if err := id.Validate(); err != nil {
			return err
		}
		raw[index] = string(id)
	}
	if err := requireUniqueSorted(raw, "itemIDs"); err != nil {
		return err
	}
	if value.ItemSetDigest != MakeAssignmentItemSetDigest(value.ItemIDs) {
		return invalid("itemSetDigest")
	}
	if value.Executor.Kind == ExecutorSourceLocal {
		if assignmentExternalOnly(value.State) || value.CapsuleID != nil || value.CapsuleDigest != nil || value.CustodyReceiptSigner != nil || value.InitialLease != nil || value.CurrentLease != nil || value.InitialCancellationFence != 0 || value.CancellationFence != 0 {
			return invalid("localCapsule")
		}
	} else {
		if assignmentLocalOnly(value.State) || value.CustodyReceiptSigner == nil || value.InitialLease == nil || value.CurrentLease == nil || value.InitialCancellationFence == 0 || value.CancellationFence == 0 {
			return invalid("workerState")
		}
		if err := value.InitialLease.Validate(); err != nil {
			return err
		}
		if err := value.CurrentLease.Validate(); err != nil {
			return err
		}
		if value.CurrentLease.ID != value.InitialLease.ID || value.CurrentLease.MaximumExpiresAt != value.InitialLease.MaximumExpiresAt || value.CurrentLease.Revision < value.InitialLease.Revision || value.CurrentLease.ExpiresAt < value.InitialLease.ExpiresAt {
			return invalid("assignment.lease")
		}
		if value.CancellationFence != value.InitialCancellationFence && (value.InitialCancellationFence == ^uint64(0) || value.CancellationFence != value.InitialCancellationFence+1) {
			return invalid("assignment.cancellationFence")
		}
		if assignmentHasSealedItemSet(value.State) {
			if value.CapsuleID == nil || value.CapsuleDigest == nil {
				return invalid("capsule")
			}
		} else if value.CapsuleID != nil || value.CapsuleDigest != nil {
			return invalid("capsule")
		}
	}
	if value.CapsuleID != nil {
		if err := value.CapsuleID.Validate(); err != nil {
			return err
		}
	}
	if value.CapsuleDigest != nil {
		if err := value.CapsuleDigest.Validate(); err != nil {
			return err
		}
	}
	if value.CustodyReceiptSigner != nil {
		if err := value.CustodyReceiptSigner.Validate(); err != nil {
			return err
		}
	}
	if err := value.CreatedAt.Validate(); err != nil {
		return err
	}
	if value.DeadlineAt != nil {
		if err := value.DeadlineAt.Validate(); err != nil {
			return err
		}
		if *value.DeadlineAt <= value.CreatedAt {
			return invalid("deadlineAt")
		}
	}
	if value.ReceiptIDs == nil {
		return invalid("receiptIDs")
	}
	return validateReceiptIDs(value.ReceiptIDs)
}

func (value AssignmentRecord) receiptSubjectDigest(receipt ReceiptRecord) Digest {
	authorization := AssignmentAuthorization{AssignmentID: value.ID, Executor: value.Executor, ItemIDs: value.ItemIDs, ItemSetDigest: value.ItemSetDigest, ExecutionPayloadDigest: value.ExecutionPayloadDigest, CapsuleID: value.CapsuleID, CapsuleDigest: value.CapsuleDigest, InitialLease: value.InitialLease, CancellationFence: value.InitialCancellationFence}
	return authorization.receiptSubjectDigest(value.OccurrenceID, value.AttemptID, receipt)
}

func validateReceiptIDs(ids []ReceiptID) error {
	if len(ids) > maximumReceipts {
		return invalid("receiptIDs")
	}
	raw := make([]string, len(ids))
	for index, id := range ids {
		if err := id.Validate(); err != nil {
			return err
		}
		raw[index] = string(id)
	}
	return requireUniqueSorted(raw, "receiptIDs")
}

func attemptLocalOnly(state AttemptState) bool {
	return oneOf(string(state), "localExecuting", "localResultReady", "localApplied", "localReleased", "localCancellationRequested", "localCancellationConfirmed", "localExecutionFailed", "localInvalidResult", "localUncertainTermination")
}
func attemptExternalOnly(state AttemptState) bool {
	return state != "prepared" && state != "sealed" && !attemptLocalOnly(state)
}
func assignmentLocalOnly(state AssignmentState) bool { return attemptLocalOnly(AttemptState(state)) }
func assignmentExternalOnly(state AssignmentState) bool {
	return state != "prepared" && state != "sealed" && !assignmentLocalOnly(state)
}
func assignmentHasSealedItemSet(state AssignmentState) bool { return state != "prepared" }

func optionalJobCapsuleID(value *JobCapsuleID) string {
	if value == nil {
		return ""
	}
	return string(*value)
}
