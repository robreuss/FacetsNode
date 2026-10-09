package computequeue

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAssignmentFirstSealRejectsCapsuleSubstitution(t *testing.T) {
	fixture := loadFixtureForTest[transitionChainFixture](t, "compute-queue-transition-chain-v1.json")
	authorization := fixture.Attempt.AssignmentPlan.Assignments[0]
	proof := AuthorizedAttempt{record: fixture.Attempt}
	sourceSealed := receiptAtStage(t, fixture.Receipts, "sourceSealed")
	verified, err := verifiedFixtureReceipts(fixture.Attempt, []ReceiptRecord{sourceSealed}, nil)
	if err != nil {
		t.Fatal(err)
	}
	prepared := assignmentFromAuthorization(fixture.Attempt, authorization, 1, "prepared", nil)
	sealed := assignmentFromAuthorization(fixture.Attempt, authorization, 2, "sealed", []ReceiptID{sourceSealed.ID})
	transition := AssignmentTransition{
		ProtocolVersion:           ProtocolVersion,
		ID:                        TransitionID("00000000-0000-0000-0000-000000009901"),
		LifecycleID:               LifecycleID(prepared.ID),
		From:                      "prepared",
		To:                        "sealed",
		Authority:                 AuthoritySourceDevice,
		ExpectedRevision:          1,
		ResultingRevision:         2,
		OccurredAt:                sourceSealed.RecordedAt,
		SupportingReceiptIDs:      []ReceiptID{sourceSealed.ID},
		SealedAssignmentSetDigest: digestPointer(prepared.ItemSetDigest),
		LeaseID:                   leaseIDPointer(authorization.InitialLease),
		LeaseRevision:             leaseRevisionPointer(authorization.InitialLease),
		CancellationFence:         authorization.CancellationFence,
	}
	if err := sealed.ValidateTransitionFrom(prepared, transition, proof, verified, nil, nil); err != nil {
		t.Fatalf("authorized first seal rejected: %v", err)
	}

	hostile := sealed
	hostileCapsule := JobCapsuleID("00000000-0000-0000-0000-000000009999")
	hostileDigest := SHA256Digest("fixture.hostile-capsule", "substituted")
	hostile.CapsuleID = &hostileCapsule
	hostile.CapsuleDigest = &hostileDigest
	if err := hostile.Validate(); err != nil {
		t.Fatalf("hostile record should remain structurally valid: %v", err)
	}
	if err := hostile.ValidateTransitionFrom(prepared, transition, proof, verified, nil, nil); err == nil {
		t.Fatal("first seal accepted capsule identity not present in AuthorizedAttempt")
	}
}

func TestOccurrenceAssignmentEvidenceRequiresMatchingAttemptProof(t *testing.T) {
	scheduleFixture := loadFixtureForTest[scheduleOccurrenceFixture](t, "compute-queue-recurring-occurrence-v1.json")
	chain := loadFixtureForTest[transitionChainFixture](t, "compute-queue-transition-chain-v1.json")
	authorization := chain.Attempt.AssignmentPlan.Assignments[0]
	proof := AuthorizedAttempt{record: chain.Attempt}
	sourceSealed := receiptAtStage(t, chain.Receipts, "sourceSealed")
	verified, err := verifiedFixtureReceipts(chain.Attempt, []ReceiptRecord{sourceSealed}, nil)
	if err != nil {
		t.Fatal(err)
	}
	assignment := assignmentFromAuthorization(chain.Attempt, authorization, 2, "sealed", []ReceiptID{sourceSealed.ID})
	transition := OccurrenceTransition{
		ProtocolVersion:      ProtocolVersion,
		ID:                   TransitionID("00000000-0000-0000-0000-000000009902"),
		LifecycleID:          LifecycleID(scheduleFixture.Occurrence.ID),
		From:                 scheduleFixture.Occurrence.State,
		To:                   "preparing",
		Authority:            AuthoritySourceDevice,
		ExpectedRevision:     scheduleFixture.Occurrence.Revision,
		ResultingRevision:    scheduleFixture.Occurrence.Revision + 1,
		OccurredAt:           scheduleFixture.Occurrence.StateChangedAt + 1,
		SupportingReceiptIDs: []ReceiptID{sourceSealed.ID},
	}
	if err := scheduleFixture.Occurrence.ValidateTransition(transition, verified, nil, nil, []AssignmentRecord{assignment}, nil, nil); err == nil {
		t.Fatal("occurrence accepted assignment-scoped evidence without an AuthorizedAttempt proof")
	}
	if err := scheduleFixture.Occurrence.ValidateTransition(transition, verified, nil, []AuthorizedAttempt{proof}, []AssignmentRecord{assignment}, nil, nil); err != nil {
		t.Fatalf("occurrence rejected matching historical attempt proof: %v", err)
	}
}

func TestOccurrenceAssignmentEvidenceUsesLocalExecutorSigner(t *testing.T) {
	fixture := loadFixtureForTest[directLocalFixture](t, "compute-queue-direct-local-lifecycle-v1.json")
	sourceSigner := fixture.Attempt.SourceReceiptSigner
	localSigner := sourceSigner
	localSigner.SignerID = "localExecutor.fixture"
	localSigner.SigningKeyID = "localExecutor.key.fixture"

	attempt := fixture.Attempt
	authorization := attempt.AssignmentPlan.Assignments[0]
	localExecutor := *authorization.Executor.SourceLocal
	localExecutor.ReceiptSigner = localSigner
	authorization.Executor.SourceLocal = &localExecutor
	attempt.AssignmentPlan.Assignments = append([]AssignmentAuthorization(nil), attempt.AssignmentPlan.Assignments...)
	attempt.AssignmentPlan.Assignments[0] = authorization
	attempt.AssignmentPlan.AssignmentSetDigest = attempt.AssignmentPlan.makeDigest()
	if err := attempt.Validate(); err != nil {
		t.Fatalf("test attempt with distinct local signer is invalid: %v", err)
	}

	assignment := fixture.Assignment
	assignment.Executor = authorization.Executor
	if err := assignment.Validate(); err != nil {
		t.Fatalf("test assignment with distinct local signer is invalid: %v", err)
	}

	record := receiptAtStage(t, fixture.Receipts, "localExecutionStarted")
	record.SignerID = localSigner.SignerID
	record.SigningKeyID = localSigner.SigningKeyID
	record.SigningKeyRevision = localSigner.SigningKeyRevision
	record.SubjectDigest = assignment.receiptSubjectDigest(record)
	record.IdempotencyKey = record.MakeIdempotencyKey()
	localReceipt, err := verifyReceiptForTest(record, localSigner, record.SubjectDigest)
	if err != nil {
		t.Fatal(err)
	}

	occurrence := OccurrenceRecord{
		ID:                  attempt.OccurrenceID,
		SourceReceiptSigner: sourceSigner,
	}
	proofs := map[AttemptID]AuthorizedAttempt{attempt.ID: newAuthorizedAttempt(attempt)}
	assignments := map[AssignmentID]AssignmentRecord{assignment.ID: assignment}
	if err := occurrence.validateReceiptTrust(localReceipt, proofs, assignments, nil); err != nil {
		t.Fatalf("occurrence rejected direct-local evidence signed by the local executor: %v", err)
	}

	sourceRecord := record
	sourceRecord.SignerID = sourceSigner.SignerID
	sourceRecord.SigningKeyID = sourceSigner.SigningKeyID
	sourceRecord.SigningKeyRevision = sourceSigner.SigningKeyRevision
	sourceRecord.IdempotencyKey = sourceRecord.MakeIdempotencyKey()
	sourceReceipt, err := verifyReceiptForTest(sourceRecord, sourceSigner, sourceRecord.SubjectDigest)
	if err != nil {
		t.Fatal(err)
	}
	if err := occurrence.validateReceiptTrust(sourceReceipt, proofs, assignments, nil); err == nil {
		t.Fatal("occurrence accepted direct-local evidence signed by the source instead of the local executor")
	}
}

func TestSecurelyQueuedRejectsExtraneousUncustodiedAssignment(t *testing.T) {
	occurrenceFixture := loadFixtureForTest[scheduleOccurrenceFixture](t, "compute-queue-recurring-occurrence-v1.json")
	chain := loadFixtureForTest[transitionChainFixture](t, "compute-queue-transition-chain-v1.json")
	sourceSealed := receiptAtStage(t, chain.Receipts, "sourceSealed")
	custodyAccepted := receiptAtStage(t, chain.Receipts, "custodyAccepted")
	verified, err := verifiedFixtureReceipts(chain.Attempt, []ReceiptRecord{sourceSealed, custodyAccepted}, nil)
	if err != nil {
		t.Fatal(err)
	}
	authorization := chain.Attempt.AssignmentPlan.Assignments[0]
	assignment := assignmentFromAuthorization(chain.Attempt, authorization, 4, "custodied", []ReceiptID{sourceSealed.ID, custodyAccepted.ID})
	proof := newAuthorizedAttempt(chain.Attempt)

	occurrence := occurrenceFixture.Occurrence
	preparingTransitionID := TransitionID("00000000-0000-0000-0000-000000009903")
	preparedAt := occurrence.StateChangedAt + 1
	occurrence.Revision = 2
	occurrence.State = "preparing"
	occurrence.LastTransitionID = &preparingTransitionID
	occurrence.StateChangedAt = preparedAt
	occurrence.PreparedAt = &preparedAt
	if err := occurrence.Validate(); err != nil {
		t.Fatal(err)
	}
	transition := OccurrenceTransition{
		ProtocolVersion:      ProtocolVersion,
		ID:                   TransitionID("00000000-0000-0000-0000-000000009904"),
		LifecycleID:          LifecycleID(occurrence.ID),
		From:                 "preparing",
		To:                   "securelyQueued",
		Authority:            AuthoritySourceDevice,
		ExpectedRevision:     occurrence.Revision,
		ResultingRevision:    occurrence.Revision + 1,
		OccurredAt:           occurrence.StateChangedAt + 1,
		SupportingReceiptIDs: []ReceiptID{custodyAccepted.ID},
	}
	if err := occurrence.ValidateTransition(transition, verified, &proof, nil, []AssignmentRecord{assignment}, nil, nil); err != nil {
		t.Fatalf("valid securely queued transition rejected: %v", err)
	}

	extraneous := assignment
	extraneous.ID = AssignmentID("00000000-0000-0000-0000-000000009905")
	extraneous.Revision = 1
	extraneous.State = "prepared"
	extraneous.CapsuleID = nil
	extraneous.CapsuleDigest = nil
	extraneous.ReceiptIDs = []ReceiptID{}
	if err := extraneous.Validate(); err != nil {
		t.Fatalf("extraneous assignment should remain structurally valid: %v", err)
	}
	if err := occurrence.ValidateTransition(transition, verified, &proof, nil, []AssignmentRecord{assignment, extraneous}, nil, nil); err == nil {
		t.Fatal("securely queued transition accepted an extraneous uncustodied assignment")
	}
}

func TestOccurrenceSourceBoundValidationIsPublicAndStrong(t *testing.T) {
	fixture := loadFixtureForTest[scheduleOccurrenceFixture](t, "compute-queue-recurring-occurrence-v1.json")
	targets := fixture.TargetManifestChunks[0].TargetObjectIDs
	items := []ItemRecord{
		{ProtocolVersion: ProtocolVersion, ID: ItemID("00000000-0000-0000-0000-000000000501"), OccurrenceID: fixture.Occurrence.ID, Revision: 1, DestinationKind: fixture.Occurrence.DestinationKind, SourceObjectID: targets[0], Executions: []ItemExecutionRecord{}},
		{ProtocolVersion: ProtocolVersion, ID: ItemID("00000000-0000-0000-0000-000000000502"), OccurrenceID: fixture.Occurrence.ID, Revision: 1, DestinationKind: fixture.Occurrence.DestinationKind, SourceObjectID: targets[1], Executions: []ItemExecutionRecord{}},
	}
	if err := fixture.Occurrence.ValidateSourceBound(fixture.Schedule, items, nil, nil, nil, nil, nil); err != nil {
		t.Fatalf("valid source-bound occurrence rejected: %v", err)
	}

	chain := loadFixtureForTest[transitionChainFixture](t, "compute-queue-transition-chain-v1.json")
	proof := newAuthorizedAttempt(chain.Attempt)
	if err := fixture.Occurrence.ValidateSourceBound(fixture.Schedule, items, nil, []AuthorizedAttempt{proof}, nil, nil, nil); err == nil {
		t.Fatal("source-bound validation accepted unused execution authority")
	}
}

func TestRetryAppendRequiresAuthorizedRetryAttempt(t *testing.T) {
	fixture := loadFixtureForTest[retryLifecycleFixture](t, "compute-queue-retry-lifecycle-v1.json")
	verified, err := verifiedFixtureReceipts(fixture.AttemptOneStates[0], fixture.AttemptOneReceipts, nil)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := AuthorizeInitialAttempt(fixture.AttemptOneStates[0], fixture.Schedule, fixture.InitialOccurrence, []ItemRecord{fixture.InitialItem})
	if err != nil {
		t.Fatal(err)
	}
	for index, transition := range fixture.AttemptOneTransitions {
		evidence := AttemptAdvanceEvidence{}
		if index > 0 {
			evidence.Assignments = []AssignmentRecord{fixture.AssignmentOneStates[index-1]}
		}
		proof, err = proof.Advance(fixture.AttemptOneStates[index+1], transition, verified, evidence)
		if err != nil {
			t.Fatal(err)
		}
	}
	retryEvidence, present := findVerifiedReceipt(verified, fixture.AttemptOneReceipts[len(fixture.AttemptOneReceipts)-1].ID)
	if !present {
		t.Fatal("missing retry evidence")
	}
	retryProof, err := AuthorizeRetryAttempt(
		fixture.RetryAttempt,
		fixture.Schedule,
		fixture.RetryOccurrence,
		[]ItemRecord{fixture.FailedItem},
		proof,
		fixture.FailureError,
		fixture.AttemptOneTransitions[len(fixture.AttemptOneTransitions)-1],
		retryEvidence,
	)
	if err != nil {
		t.Fatal(err)
	}
	authorization := fixture.RetryAttempt.AssignmentPlan.Assignments[0]
	retried := fixture.FailedItem
	retried.Revision++
	retried.Executions = append(append([]ItemExecutionRecord(nil), fixture.FailedItem.Executions...), ItemExecutionRecord{
		ProtocolVersion: ProtocolVersion,
		Revision:        1,
		OccurrenceID:    fixture.RetryAttempt.OccurrenceID,
		ItemID:          fixture.FailedItem.ID,
		DestinationKind: fixture.RetryAttempt.DestinationKind,
		AttemptID:       fixture.RetryAttempt.ID,
		AttemptNumber:   fixture.RetryAttempt.AttemptNumber,
		AssignmentID:    authorization.AssignmentID,
	})
	if err := retried.ValidateRetryAppendFrom(fixture.FailedItem, retryProof); err != nil {
		t.Fatalf("authorized retry append rejected: %v", err)
	}
	tampered := retried
	tampered.Executions = append([]ItemExecutionRecord(nil), retried.Executions...)
	tampered.Executions[len(tampered.Executions)-1].AssignmentID = fixture.AttemptOneStates[0].AssignmentPlan.Assignments[0].AssignmentID
	if err := tampered.Validate(); err != nil {
		t.Fatalf("tampered retry remains structurally valid: %v", err)
	}
	if err := tampered.ValidateRetryAppendFrom(fixture.FailedItem, retryProof); err == nil {
		t.Fatal("retry append accepted an assignment outside the authorized retry plan")
	}
}

func TestVerifiedReceiptCannotBeManufacturedByDecodingEnvelope(t *testing.T) {
	fixture := loadFixtureForTest[transitionChainFixture](t, "compute-queue-transition-chain-v1.json")
	record := receiptAtStage(t, fixture.Receipts, "sourceSealed")
	signer, subject, err := fixture.Attempt.expectedReceiptTrust(record)
	if err != nil {
		t.Fatal(err)
	}
	canonicalRecord, err := EncodeCanonical(record)
	if err != nil {
		t.Fatal(err)
	}
	envelope := SignedReceiptEnvelope{
		ProtocolVersion:       ProtocolVersion,
		Record:                record,
		CanonicalRecordDigest: SHA256Digest("facets.compute-queue.receipt-record-canonical.v1", string(canonicalRecord)),
		SignatureProfileID:    signer.SignatureProfileID,
		Signature:             SignatureValue("AQ"),
	}
	if _, err := acceptVerifiedReceiptEnvelope(envelope, signer, subject, rejectingReceiptVerifier{}); err == nil {
		t.Fatal("receipt crossed the verification boundary after signature rejection")
	}
	wrongSubject := SHA256Digest("fixture.wrong-subject", "wrong")
	if _, err := acceptVerifiedReceiptEnvelope(envelope, signer, wrongSubject, fixtureReceiptSignatureVerifier{}); err == nil {
		t.Fatal("receipt crossed the verification boundary with a substituted subject")
	}
}

func TestVerifiedReceiptOwnsImmutableSnapshot(t *testing.T) {
	fixture := loadFixtureForTest[transitionChainFixture](t, "compute-queue-transition-chain-v1.json")
	record := receiptAtStage(t, fixture.Receipts, "executionCompleted")
	signer, subject, err := fixture.Attempt.expectedReceiptTrust(record)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := verifyReceiptForTest(record, signer, subject)
	if err != nil {
		t.Fatal(err)
	}
	expected := proof.Record()
	mutatedDigest := SHA256Digest("fixture.mutated-receipt", "source")
	*record.ResultDigest = mutatedDigest
	if got := proof.Record(); got.ResultDigest == nil || expected.ResultDigest == nil || *got.ResultDigest != *expected.ResultDigest {
		t.Fatal("verified receipt changed after mutating the source record")
	}
	exposed := proof.Record()
	*exposed.ResultDigest = SHA256Digest("fixture.mutated-receipt", "returned")
	if got := proof.Record(); got.ResultDigest == nil || *got.ResultDigest != *expected.ResultDigest {
		t.Fatal("verified receipt exposed mutable backing storage through Record")
	}
}

func TestLeaseRenewalCannotSelectSignerFromHostileAssignment(t *testing.T) {
	fixture := loadFixtureForTest[transitionChainFixture](t, "compute-queue-transition-chain-v1.json")
	authorization := fixture.Attempt.AssignmentPlan.Assignments[0]
	if authorization.InitialLease == nil || authorization.Executor.Worker == nil {
		t.Fatal("external fixture is missing lease or Worker binding")
	}
	proof := AuthorizedAttempt{record: fixture.Attempt}
	baseReceipts := make([]ReceiptRecord, 0, 4)
	for _, receipt := range fixture.Receipts {
		if oneOf(string(receipt.Stage), "sourceSealed", "custodyAccepted", "waitingForWorker", "workerClaimed") {
			baseReceipts = append(baseReceipts, receipt)
		}
	}
	verifiedBase, err := verifiedFixtureReceipts(fixture.Attempt, baseReceipts, nil)
	if err != nil {
		t.Fatal(err)
	}
	baseReceiptIDs := make([]ReceiptID, len(baseReceipts))
	for index, receipt := range baseReceipts {
		baseReceiptIDs[index] = receipt.ID
	}
	previous := assignmentFromAuthorization(fixture.Attempt, authorization, 5, "claimed", baseReceiptIDs)

	initialLease := *authorization.InitialLease
	renewedLease := LeaseBinding{
		ID:               initialLease.ID,
		Revision:         initialLease.Revision + 1,
		IssuedAt:         initialLease.IssuedAt + 100,
		ExpiresAt:        initialLease.ExpiresAt + 5_000,
		MaximumExpiresAt: initialLease.MaximumExpiresAt,
	}
	if err := renewedLease.ValidateRenewal(initialLease); err != nil {
		t.Fatal(err)
	}
	renewalReceipt := ReceiptRecord{
		ProtocolVersion:    ProtocolVersion,
		ID:                 ReceiptID("00000000-0000-0000-0000-000000000650"),
		OccurrenceID:       fixture.Attempt.OccurrenceID,
		AttemptID:          fixture.Attempt.ID,
		AssignmentID:       assignmentIDPointer(authorization.AssignmentID),
		Stage:              "leaseRenewed",
		Authority:          AuthorityWorker,
		LeaseID:            &renewedLease.ID,
		LeaseRevision:      &renewedLease.Revision,
		LeaseExpiresAt:     &renewedLease.ExpiresAt,
		CancellationFence:  authorization.CancellationFence,
		SignerID:           authorization.Executor.Worker.ReceiptSigner.SignerID,
		SigningKeyID:       authorization.Executor.Worker.ReceiptSigner.SigningKeyID,
		SigningKeyRevision: authorization.Executor.Worker.ReceiptSigner.SigningKeyRevision,
		RecordedAt:         renewedLease.IssuedAt,
	}
	renewalReceipt.SubjectDigest = previous.receiptSubjectDigest(renewalReceipt)
	renewalReceipt.IdempotencyKey = renewalReceipt.MakeIdempotencyKey()
	verifiedRenewal, err := verifyReceiptForTest(renewalReceipt, authorization.Executor.Worker.ReceiptSigner, renewalReceipt.SubjectDigest)
	if err != nil {
		t.Fatal(err)
	}
	allVerified := append(append([]VerifiedReceipt(nil), verifiedBase...), verifiedRenewal)
	current := previous
	current.Revision++
	current.CurrentLease = &renewedLease
	current.ReceiptIDs = append(append([]ReceiptID(nil), baseReceiptIDs...), renewalReceipt.ID)
	if err := current.ValidateLeaseRenewalFrom(previous, proof, verifiedRenewal, allVerified); err != nil {
		t.Fatalf("authorized lease renewal rejected: %v", err)
	}

	hostile := current
	hostileWorker := *hostile.Executor.Worker
	hostileWorker.ReceiptSigner = ReceiptSignerBinding{
		SignerID:           "hostile.worker",
		SigningKeyID:       "hostile.worker.key",
		SigningKeyRevision: 1,
		SignatureProfileID: "facets-test-signature-v1",
	}
	hostile.Executor.Worker = &hostileWorker
	if err := hostile.Validate(); err != nil {
		t.Fatalf("hostile assignment should remain structurally valid: %v", err)
	}
	if err := hostile.ValidateLeaseRenewalFrom(previous, proof, verifiedRenewal, allVerified); err == nil {
		t.Fatal("lease renewal trusted a signer selected by a hostile assignment")
	}
}

func TestFixedWorkerAttemptAllowsAuthorizedSubset(t *testing.T) {
	fixture := loadFixtureForTest[transitionChainFixture](t, "compute-queue-transition-chain-v1.json")
	attempt := fixture.Attempt
	if attempt.DestinationKind != DestinationFixedWorkers || attempt.AuthorizedWorkerSetDigest == nil {
		t.Fatal("fixture is not a fixed-worker attempt")
	}
	// Structural validation cannot require the selected assignment subset to
	// have the same digest as the schedule's full authorized Worker set. The
	// schedule authorization boundary performs membership validation instead.
	authorizedSetDigest := SHA256Digest("fixture.authorized-worker-superset", "worker-1", "worker-2")
	attempt.AuthorizedWorkerSetDigest = &authorizedSetDigest
	if workerSetDigest := attempt.AssignmentPlan.WorkerSetDigest(); workerSetDigest == nil || *workerSetDigest == authorizedSetDigest {
		t.Fatal("test did not create a distinct authorized superset digest")
	}
	if err := attempt.Validate(); err != nil {
		t.Fatalf("fixed-worker subset was rejected structurally: %v", err)
	}
}

func TestGeneralLifecycleUpdatesRejectHistoryMutation(t *testing.T) {
	retry := loadFixtureForTest[retryLifecycleFixture](t, "compute-queue-retry-lifecycle-v1.json")
	if err := retry.FailedItem.Executions[0].ValidateUpdateFrom(retry.InitialItem.Executions[0]); err != nil {
		t.Fatalf("valid execution milestone update rejected: %v", err)
	}
	if err := retry.FailedItem.ValidateUpdateFrom(retry.InitialItem); err != nil {
		t.Fatalf("valid item milestone update rejected: %v", err)
	}
	terminalRewrite := retry.FailedItem.Executions[0]
	terminalRewrite.Revision++
	if err := terminalRewrite.Validate(); err != nil {
		t.Fatalf("terminal rewrite should remain structurally valid: %v", err)
	}
	if err := terminalRewrite.ValidateUpdateFrom(retry.FailedItem.Executions[0]); err == nil {
		t.Fatal("general execution update revised a terminal execution")
	}

	chain := loadFixtureForTest[transitionChainFixture](t, "compute-queue-transition-chain-v1.json")
	attemptUpdate := chain.Attempt
	attemptUpdate.Revision++
	if err := attemptUpdate.ValidateUpdateFrom(chain.Attempt); err != nil {
		t.Fatalf("valid same-state attempt update rejected: %v", err)
	}
	attemptUpdate.CreatedAt++
	if err := attemptUpdate.Validate(); err != nil {
		t.Fatalf("attempt mutation should remain structurally valid: %v", err)
	}
	if err := attemptUpdate.ValidateUpdateFrom(chain.Attempt); err == nil {
		t.Fatal("same-state attempt update changed immutable creation time")
	}

	occurrenceUpdate := retry.RetryOccurrence
	occurrenceUpdate.Revision++
	if err := occurrenceUpdate.ValidateUpdateFrom(retry.RetryOccurrence); err != nil {
		t.Fatalf("valid same-state occurrence update rejected: %v", err)
	}
	occurrenceUpdate.Report.Submitted--
	if err := occurrenceUpdate.Validate(); err != nil {
		t.Fatalf("counter regression should remain structurally valid: %v", err)
	}
	if err := occurrenceUpdate.ValidateUpdateFrom(retry.RetryOccurrence); err == nil {
		t.Fatal("same-state occurrence update accepted a counter regression")
	}
}

func TestOccurrenceTransitionPublicationBindsTransitionAndReplay(t *testing.T) {
	fixture := loadFixtureForTest[retryLifecycleFixture](t, "compute-queue-retry-lifecycle-v1.json")
	previous := fixture.InitialOccurrence
	transition := OccurrenceTransition{
		ProtocolVersion:      ProtocolVersion,
		ID:                   TransitionID("00000000-0000-0000-0000-000000009970"),
		LifecycleID:          LifecycleID(previous.ID),
		From:                 previous.State,
		To:                   "preparing",
		Authority:            AuthoritySourceDevice,
		ExpectedRevision:     previous.Revision,
		ResultingRevision:    previous.Revision + 1,
		OccurredAt:           previous.StateChangedAt + 1,
		SupportingReceiptIDs: []ReceiptID{},
	}
	updated := previous
	updated.Revision = transition.ResultingRevision
	updated.State = transition.To
	updated.LastTransitionID = &transition.ID
	updated.StateChangedAt = transition.OccurredAt
	if err := updated.ValidateTransitionUpdateFrom(previous, transition, OccurrenceUpdateEvidence{}); err != nil {
		t.Fatalf("valid occurrence transition publication rejected: %v", err)
	}
	if err := updated.ValidateTransitionUpdateFrom(previous, transition, OccurrenceUpdateEvidence{AppliedEventIDs: map[TransitionID]struct{}{transition.ID: {}}}); err == nil {
		t.Fatal("occurrence publication accepted a replayed transition")
	}
	hostile := updated
	hostile.Report.Prepared--
	if err := hostile.Validate(); err != nil {
		t.Fatalf("hostile counter record should remain structurally valid: %v", err)
	}
	if err := hostile.ValidateTransitionUpdateFrom(previous, transition, OccurrenceUpdateEvidence{}); err == nil {
		t.Fatal("occurrence publication accepted a counter regression")
	}
}

func TestAttemptReceiptTrustRejectsCrossAttemptEvidence(t *testing.T) {
	fixture := loadFixtureForTest[transitionChainFixture](t, "compute-queue-transition-chain-v1.json")
	record := receiptAtStage(t, fixture.Receipts, "sourceSealed")
	record.AttemptID = AttemptID("00000000-0000-0000-0000-000000009971")
	if _, _, err := fixture.Attempt.expectedReceiptTrust(record); err == nil {
		t.Fatal("attempt receipt trust accepted evidence from a different attempt")
	}
}

func TestTerminalEvidenceRequiresCompleteLocalResultChain(t *testing.T) {
	fixture := loadFixtureForTest[directLocalFixture](t, "compute-queue-direct-local-lifecycle-v1.json")
	verified, err := verifiedFixtureReceipts(fixture.Attempt, fixture.Receipts, []ItemRecord{fixture.Item})
	if err != nil {
		t.Fatal(err)
	}
	assignmentReceiptIDs := make([]ReceiptID, 0, len(fixture.Transitions))
	for _, transition := range fixture.Transitions {
		assignmentReceiptIDs = append(assignmentReceiptIDs, transition.SupportingReceiptIDs...)
	}
	authorization := fixture.Attempt.AssignmentPlan.Assignments[0]
	assignment := assignmentFromAuthorization(fixture.Attempt, authorization, uint64(len(fixture.Transitions)+1), "localReleased", assignmentReceiptIDs)
	finalAttempt := fixture.Attempt
	finalAttempt.Revision = uint64(len(fixture.Transitions) + 1)
	finalAttempt.State = "localReleased"
	finalAttempt.ReceiptIDs = append([]ReceiptID(nil), assignmentReceiptIDs...)
	proof := newAuthorizedAttempt(finalAttempt)
	manifest := successfulManifestForTest(fixture.Attempt, authorization)
	occurrence := OccurrenceRecord{
		ID:                       fixture.Attempt.OccurrenceID,
		DestinationKind:          DestinationDirectLocal,
		OccurrenceSnapshotDigest: fixture.Attempt.OccurrenceSnapshotDigest,
		ReceiptIDs:               make([]ReceiptID, len(fixture.Receipts)),
	}
	for index, receipt := range fixture.Receipts {
		occurrence.ReceiptIDs[index] = receipt.ID
	}
	if err := occurrence.validateTerminalResultEvidence([]ItemRecord{fixture.Item}, []AuthorizedAttempt{proof}, []AssignmentRecord{assignment}, []AssignmentResultManifest{manifest}, nil, mustVerifiedReceiptIndex(t, verified)); err != nil {
		t.Fatalf("complete local terminal chain rejected: %v", err)
	}

	withoutStart := assignment
	withoutStart.ReceiptIDs = removeReceiptAtStage(t, assignment.ReceiptIDs, fixture.Receipts, "localExecutionStarted")
	finalAttempt.ReceiptIDs = append([]ReceiptID(nil), withoutStart.ReceiptIDs...)
	withoutStartProof := newAuthorizedAttempt(finalAttempt)
	if err := occurrence.validateTerminalResultEvidence([]ItemRecord{fixture.Item}, []AuthorizedAttempt{withoutStartProof}, []AssignmentRecord{withoutStart}, []AssignmentResultManifest{manifest}, nil, mustVerifiedReceiptIndex(t, verified)); err == nil {
		t.Fatal("terminal publication accepted a result without local execution-start evidence")
	}
}

func TestTerminalWorkerResultChainExcludesPerItemSourceRejections(t *testing.T) {
	deliveredID := ReceiptID("00000000-0000-0000-0000-000000009980")
	firstRejectionID := ReceiptID("00000000-0000-0000-0000-000000009981")
	secondRejectionID := ReceiptID("00000000-0000-0000-0000-000000009982")
	assignment := AssignmentRecord{ReceiptIDs: []ReceiptID{
		deliveredID,
		firstRejectionID,
		secondRejectionID,
	}}
	receiptIndex := verifiedReceiptIndex{byID: map[ReceiptID]VerifiedReceipt{
		deliveredID:       {record: ReceiptRecord{ID: deliveredID, Stage: "resultDelivered"}},
		firstRejectionID:  {record: ReceiptRecord{ID: firstRejectionID, Stage: "sourceResultRejected"}},
		secondRejectionID: {record: ReceiptRecord{ID: secondRejectionID, Stage: "sourceResultRejected"}},
	}}

	resultReceiptIDs, err := assignmentResultEvidenceReceiptIDs(assignment, receiptIndex)
	if err != nil {
		t.Fatal(err)
	}
	if len(resultReceiptIDs) != 1 || resultReceiptIDs[0] != deliveredID {
		t.Fatalf("result chain retained per-item rejection receipts: %v", resultReceiptIDs)
	}

	assignment.ReceiptIDs = append(assignment.ReceiptIDs, ReceiptID("00000000-0000-0000-0000-000000009983"))
	if _, err := assignmentResultEvidenceReceiptIDs(assignment, receiptIndex); err == nil {
		t.Fatal("result-chain filtering accepted an unverified durable receipt")
	}
}

func TestAuthorizedAttemptOwnsImmutableSnapshot(t *testing.T) {
	fixture := loadFixtureForTest[transitionChainFixture](t, "compute-queue-transition-chain-v1.json")
	original := fixture.Attempt
	proof := newAuthorizedAttempt(original)
	expected := proof.Record()

	original.AssignmentPlan.Assignments[0].ItemIDs[0] = ItemID("00000000-0000-0000-0000-000000009991")
	original.AssignmentPlan.Assignments[0].Executor.Worker.ReceiptSigner.SignerID = "hostile.worker"
	original.ReceiptIDs = append(original.ReceiptIDs, ReceiptID("00000000-0000-0000-0000-000000009992"))
	if got := proof.Record(); !equalAttemptRecordBytes(got, expected) {
		t.Fatal("authorized proof changed after mutating the source record")
	}

	exposed := proof.Record()
	exposed.AssignmentPlan.Assignments[0].ItemIDs[0] = ItemID("00000000-0000-0000-0000-000000009993")
	exposed.AssignmentPlan.Assignments[0].Executor.Worker.ReceiptSigner.SignerID = "hostile.returned-record"
	exposed.ReceiptIDs = append(exposed.ReceiptIDs, ReceiptID("00000000-0000-0000-0000-000000009994"))
	if got := proof.Record(); !equalAttemptRecordBytes(got, expected) {
		t.Fatal("authorized proof exposed mutable backing storage through Record")
	}
}

func TestAssignmentResultEvidenceIsCryptographicallyLinked(t *testing.T) {
	fixture := loadFixtureForTest[transitionChainFixture](t, "compute-queue-transition-chain-v1.json")
	authorization := fixture.Attempt.AssignmentPlan.Assignments[0]
	proof := newAuthorizedAttempt(fixture.Attempt)
	verified, err := verifiedFixtureReceipts(fixture.Attempt, fixture.Receipts, nil)
	if err != nil {
		t.Fatal(err)
	}
	manifest := successfulManifestForTest(fixture.Attempt, authorization)
	executing := assignmentFromAuthorization(fixture.Attempt, authorization, 7, "executing", receiptIDsThroughStage(t, fixture.Receipts, "executionStarted"))
	resultCustodied := assignmentFromAuthorization(fixture.Attempt, authorization, 8, "resultCustodied", receiptIDsThroughStage(t, fixture.Receipts, "resultCustodied"))
	transition := transitionToAssignment(fixture.Transitions[6], authorization)
	if err := resultCustodied.ValidateTransitionFrom(executing, transition, proof, verified, &manifest, nil); err != nil {
		t.Fatalf("valid linked result evidence rejected: %v", err)
	}

	tamperedRecord := receiptAtStage(t, fixture.Receipts, "resultCustodied")
	tamperedDigest := SHA256Digest("fixture.tampered-result", "different-result")
	tamperedRecord.ResultDigest = &tamperedDigest
	tamperedRecord.SubjectDigest = authorization.receiptSubjectDigest(fixture.Attempt.OccurrenceID, fixture.Attempt.ID, tamperedRecord)
	tamperedRecord.IdempotencyKey = tamperedRecord.MakeIdempotencyKey()
	tamperedReceipt, err := verifyReceiptForTest(tamperedRecord, *fixture.Attempt.CustodyReceiptSigner, tamperedRecord.SubjectDigest)
	if err != nil {
		t.Fatal(err)
	}
	tamperedVerified := replaceVerifiedReceipt(verified, tamperedReceipt)
	if err := resultCustodied.ValidateTransitionFrom(executing, transition, proof, tamperedVerified, &manifest, nil); err == nil {
		t.Fatal("result custody accepted a digest unrelated to the worker result and manifest")
	}
}

func TestAssignmentFailureAndReleaseRequireExactEvidence(t *testing.T) {
	fixture := loadFixtureForTest[transitionChainFixture](t, "compute-queue-transition-chain-v1.json")
	authorization := fixture.Attempt.AssignmentPlan.Assignments[0]
	proof := newAuthorizedAttempt(fixture.Attempt)
	verified, err := verifiedFixtureReceipts(fixture.Attempt, fixture.Receipts, nil)
	if err != nil {
		t.Fatal(err)
	}

	executing := assignmentFromAuthorization(fixture.Attempt, authorization, 7, "executing", receiptIDsThroughStage(t, fixture.Receipts, "executionStarted"))
	failed := assignmentFromAuthorization(fixture.Attempt, authorization, 8, "executionFailed", receiptIDsThroughStage(t, fixture.Receipts, "executionCompleted"))
	successReceipt := receiptAtStage(t, fixture.Receipts, "executionCompleted")
	reasonErrorID := ErrorID("00000000-0000-0000-0000-000000009995")
	failureTransition := AssignmentTransition{
		ProtocolVersion:           ProtocolVersion,
		ID:                        TransitionID("00000000-0000-0000-0000-000000009996"),
		LifecycleID:               LifecycleID(executing.ID),
		From:                      executing.State,
		To:                        failed.State,
		Authority:                 AuthorityWorker,
		ExpectedRevision:          executing.Revision,
		ResultingRevision:         failed.Revision,
		OccurredAt:                successReceipt.RecordedAt,
		SupportingReceiptIDs:      []ReceiptID{successReceipt.ID},
		SealedAssignmentSetDigest: digestPointer(executing.ItemSetDigest),
		Reason:                    &TransitionReason{Code: "error", ErrorID: &reasonErrorID},
		LeaseID:                   leaseIDPointer(executing.CurrentLease),
		LeaseRevision:             leaseRevisionPointer(executing.CurrentLease),
		CancellationFence:         executing.CancellationFence,
	}
	if err := failed.ValidateTransitionFrom(executing, failureTransition, proof, verified, nil, nil); err == nil {
		t.Fatal("executionFailed accepted a successful completion receipt")
	}

	applied := assignmentFromAuthorization(fixture.Attempt, authorization, 10, "applied", receiptIDsThroughStage(t, fixture.Receipts, "sourceApplied"))
	custodyRelease := receiptAtStage(t, fixture.Receipts, "custodyReleased")
	released := assignmentFromAuthorization(fixture.Attempt, authorization, 11, "released", append(receiptIDsThroughStage(t, fixture.Receipts, "sourceApplied"), custodyRelease.ID))
	releaseTransition := transitionToAssignment(fixture.Transitions[9], authorization)
	releaseTransition.SupportingReceiptIDs = []ReceiptID{custodyRelease.ID}
	if err := released.ValidateTransitionFrom(applied, releaseTransition, proof, verified, nil, nil); err == nil {
		t.Fatal("released accepted custody release without worker release evidence")
	}
}

func TestAuthorizedAttemptAdvanceFreezesBindingsAndRequiresBarrierEvidence(t *testing.T) {
	fixture := loadFixtureForTest[transitionChainFixture](t, "compute-queue-transition-chain-v1.json")
	verified, err := verifiedFixtureReceipts(fixture.Attempt, fixture.Receipts, nil)
	if err != nil {
		t.Fatal(err)
	}
	proof := newAuthorizedAttempt(fixture.Attempt)
	sealed := fixture.Attempt
	sealed.Revision = 2
	sealed.State = "sealed"
	sealed.ReceiptIDs = receiptIDsThroughStage(t, fixture.Receipts, "sourceSealed")
	if _, err := proof.Advance(sealed, fixture.Transitions[0], verified); err != nil {
		t.Fatalf("valid sealed transition rejected: %v", err)
	}

	mutated := sealed
	changedWorkerSet := SHA256Digest("fixture.changed-worker-set", "substitution")
	mutated.AuthorizedWorkerSetDigest = &changedWorkerSet
	if err := mutated.Validate(); err != nil {
		t.Fatalf("mutated record should remain structurally valid: %v", err)
	}
	if _, err := proof.Advance(mutated, fixture.Transitions[0], verified); err == nil {
		t.Fatal("attempt advance accepted an authorized Worker-set substitution")
	}

	if _, err := proof.Advance(sealed, fixture.Transitions[0], verified, AttemptAdvanceEvidence{
		AppliedEventIDs: map[TransitionID]struct{}{fixture.Transitions[0].ID: {}},
	}); err == nil {
		t.Fatal("attempt advance accepted a replayed transition")
	}

	sealedProof, err := proof.Advance(sealed, fixture.Transitions[0], verified)
	if err != nil {
		t.Fatal(err)
	}
	admissionPending := sealed
	admissionPending.Revision = 3
	admissionPending.State = "admissionPending"
	if _, err := sealedProof.Advance(admissionPending, fixture.Transitions[1], verified); err == nil {
		t.Fatal("attempt advanced without its exact all-assignment barrier")
	}
}

type rejectingReceiptVerifier struct{}

func (rejectingReceiptVerifier) VerifySignature(SignatureValue, Digest, ReceiptSignerBinding) error {
	return errors.New("signature rejected")
}

func loadFixtureForTest[T Validatable](t *testing.T, name string) T {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	value, err := DecodeCanonical[T](data[:len(data)-1])
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func receiptAtStage(t *testing.T, receipts []ReceiptRecord, stage ReceiptStage) ReceiptRecord {
	t.Helper()
	for _, receipt := range receipts {
		if receipt.Stage == stage {
			return receipt
		}
	}
	t.Fatalf("missing %s receipt", stage)
	return ReceiptRecord{}
}

func assignmentFromAuthorization(attempt AttemptRecord, authorization AssignmentAuthorization, revision uint64, state AssignmentState, receiptIDs []ReceiptID) AssignmentRecord {
	var capsuleID *JobCapsuleID
	var capsuleDigest *Digest
	if assignmentHasSealedItemSet(state) {
		capsuleID = authorization.CapsuleID
		capsuleDigest = authorization.CapsuleDigest
	}
	return AssignmentRecord{
		ProtocolVersion:          ProtocolVersion,
		ID:                       authorization.AssignmentID,
		OccurrenceID:             attempt.OccurrenceID,
		AttemptID:                attempt.ID,
		Revision:                 revision,
		State:                    state,
		Executor:                 authorization.Executor,
		ItemIDs:                  append([]ItemID(nil), authorization.ItemIDs...),
		ItemSetDigest:            authorization.ItemSetDigest,
		ExecutionPayloadDigest:   authorization.ExecutionPayloadDigest,
		CapsuleID:                capsuleID,
		CapsuleDigest:            capsuleDigest,
		InitialLease:             authorization.InitialLease,
		CurrentLease:             authorization.InitialLease,
		InitialCancellationFence: authorization.CancellationFence,
		CancellationFence:        authorization.CancellationFence,
		SourceReceiptSigner:      attempt.SourceReceiptSigner,
		CustodyReceiptSigner:     attempt.CustodyReceiptSigner,
		CreatedAt:                attempt.CreatedAt,
		DeadlineAt:               attempt.DeadlineAt,
		ReceiptIDs:               append([]ReceiptID{}, receiptIDs...),
	}
}

func verifyReceiptForTest(record ReceiptRecord, signer ReceiptSignerBinding, subject Digest) (VerifiedReceipt, error) {
	canonicalRecord, err := EncodeCanonical(record)
	if err != nil {
		return VerifiedReceipt{}, err
	}
	envelope := SignedReceiptEnvelope{
		ProtocolVersion:       ProtocolVersion,
		Record:                record,
		CanonicalRecordDigest: SHA256Digest("facets.compute-queue.receipt-record-canonical.v1", string(canonicalRecord)),
		SignatureProfileID:    signer.SignatureProfileID,
		Signature:             SignatureValue("AQ"),
	}
	return acceptVerifiedReceiptEnvelope(envelope, signer, subject, fixtureReceiptSignatureVerifier{})
}

func assignmentIDPointer(value AssignmentID) *AssignmentID { return &value }

func equalAttemptRecordBytes(left, right AttemptRecord) bool {
	leftBytes, leftErr := EncodeCanonical(left)
	rightBytes, rightErr := EncodeCanonical(right)
	return leftErr == nil && rightErr == nil && string(leftBytes) == string(rightBytes)
}

func successfulManifestForTest(attempt AttemptRecord, authorization AssignmentAuthorization) AssignmentResultManifest {
	payloadDigest := SHA256Digest("fixture.payload", "payload")
	entries := make([]AssignmentResultEntry, len(authorization.ItemIDs))
	components := []string{string(attempt.OccurrenceID), string(attempt.ID), string(authorization.AssignmentID)}
	for index, itemID := range authorization.ItemIDs {
		result := payloadDigest
		entries[index] = AssignmentResultEntry{ItemID: itemID, Outcome: "succeeded", ResultDigest: &result}
		components = append(components, entries[index].digestComponents()...)
	}
	return AssignmentResultManifest{
		ProtocolVersion: ProtocolVersion,
		OccurrenceID:    attempt.OccurrenceID,
		AttemptID:       attempt.ID,
		AssignmentID:    authorization.AssignmentID,
		Entries:         entries,
		ResultSetDigest: SHA256Digest("facets.compute-queue.assignment-result-set.v1", components...),
	}
}

func receiptIDsThroughStage(t *testing.T, receipts []ReceiptRecord, stage ReceiptStage) []ReceiptID {
	t.Helper()
	result := make([]ReceiptID, 0)
	for _, receipt := range receipts {
		result = append(result, receipt.ID)
		if receipt.Stage == stage {
			return result
		}
	}
	t.Fatalf("missing %s receipt", stage)
	return nil
}

func mustVerifiedReceiptIndex(t *testing.T, receipts []VerifiedReceipt) verifiedReceiptIndex {
	t.Helper()
	index, err := newVerifiedReceiptIndex(receipts)
	if err != nil {
		t.Fatal(err)
	}
	return index
}

func removeReceiptAtStage(t *testing.T, ids []ReceiptID, receipts []ReceiptRecord, stage ReceiptStage) []ReceiptID {
	t.Helper()
	target := receiptAtStage(t, receipts, stage).ID
	result := make([]ReceiptID, 0, len(ids)-1)
	for _, id := range ids {
		if id != target {
			result = append(result, id)
		}
	}
	if len(result) == len(ids) {
		t.Fatalf("receipt %s was not present", stage)
	}
	return result
}

func transitionToAssignment(value AttemptTransition, authorization AssignmentAuthorization) AssignmentTransition {
	return AssignmentTransition{
		ProtocolVersion:           value.ProtocolVersion,
		ID:                        value.ID,
		LifecycleID:               LifecycleID(authorization.AssignmentID),
		From:                      AssignmentState(value.From),
		To:                        AssignmentState(value.To),
		Authority:                 value.Authority,
		ExpectedRevision:          value.ExpectedRevision,
		ResultingRevision:         value.ResultingRevision,
		OccurredAt:                value.OccurredAt,
		SupportingReceiptIDs:      append([]ReceiptID{}, value.SupportingReceiptIDs...),
		SealedAssignmentSetDigest: digestPointer(authorization.ItemSetDigest),
		Reason:                    clonePointer(value.Reason),
		LeaseID:                   leaseIDPointer(authorization.InitialLease),
		LeaseRevision:             leaseRevisionPointer(authorization.InitialLease),
		CancellationFence:         authorization.CancellationFence,
	}
}

func replaceVerifiedReceipt(receipts []VerifiedReceipt, replacement VerifiedReceipt) []VerifiedReceipt {
	result := append([]VerifiedReceipt(nil), receipts...)
	for index, receipt := range result {
		if receipt.record.ID == replacement.record.ID {
			result[index] = replacement
			return result
		}
	}
	return append(result, replacement)
}

func digestPointer(value Digest) *Digest { return &value }

func leaseIDPointer(value *LeaseBinding) *LeaseID {
	if value == nil {
		return nil
	}
	result := value.ID
	return &result
}

func leaseRevisionPointer(value *LeaseBinding) *uint64 {
	if value == nil {
		return nil
	}
	result := value.Revision
	return &result
}
