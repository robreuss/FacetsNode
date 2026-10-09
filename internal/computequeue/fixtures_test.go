package computequeue

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

type scheduleOccurrenceFixture struct {
	ProtocolVersion      int                   `json:"protocolVersion"`
	Scenario             string                `json:"scenario"`
	Schedule             ScheduleRecord        `json:"schedule"`
	TargetManifestChunks []TargetManifestChunk `json:"targetManifestChunks"`
	Occurrence           OccurrenceRecord      `json:"occurrence"`
}

func (value scheduleOccurrenceFixture) Validate() error {
	if err := requireProtocol(value.ProtocolVersion); err != nil {
		return err
	}
	if !oneOf(value.Scenario, "immediate", "recurring") {
		return invalid("fixture.scenario")
	}
	if (value.Scenario == "immediate") != (value.Schedule.Eligibility.Kind == "immediate") {
		return invalid("fixture.binding")
	}
	if err := value.Schedule.ValidateTargetManifest(value.TargetManifestChunks); err != nil {
		return err
	}
	if err := value.Occurrence.ValidateAuthorizedBy(value.Schedule); err != nil {
		return err
	}
	if value.Occurrence.Report.Targeted != value.Schedule.TargetCount {
		return invalid("fixture.binding")
	}
	return nil
}

type mixedTerminalFixture struct {
	ProtocolVersion            int            `json:"protocolVersion"`
	Scenario                   string         `json:"scenario"`
	OccurrenceID               OccurrenceID   `json:"occurrenceID"`
	Items                      []ItemRecord   `json:"items"`
	Report                     ReportCounters `json:"report"`
	TerminalItemOutcomesDigest Digest         `json:"terminalItemOutcomesDigest"`
}

func (value mixedTerminalFixture) Validate() error {
	if err := requireProtocol(value.ProtocolVersion); err != nil {
		return err
	}
	if value.Scenario != "mixedTerminal" {
		return invalid("fixture.scenario")
	}
	if err := value.OccurrenceID.Validate(); err != nil {
		return err
	}
	if len(value.Items) == 0 || len(value.Items) > maximumItems {
		return invalid("fixture.items")
	}
	previous := ItemID("")
	for _, item := range value.Items {
		if err := item.Validate(); err != nil {
			return err
		}
		if item.OccurrenceID != value.OccurrenceID || (previous != "" && item.ID <= previous) {
			return invalid("fixture.items")
		}
		previous = item.ID
		if item.Disposition == nil {
			return invalid("fixture.items.terminal")
		}
	}
	report, err := ReconcileReport(value.Items)
	if err != nil {
		return err
	}
	if report != value.Report {
		return invalid("fixture.report")
	}
	if err := report.ValidateLogicalBounds(true); err != nil {
		return err
	}
	digest, err := TerminalItemOutcomesDigest(value.Items)
	if err != nil {
		return err
	}
	if value.TerminalItemOutcomesDigest != digest {
		return invalid("fixture.terminalItemOutcomesDigest")
	}
	return nil
}

type transitionChainFixture struct {
	ProtocolVersion int                 `json:"protocolVersion"`
	Scenario        string              `json:"scenario"`
	Attempt         AttemptRecord       `json:"attempt"`
	Receipts        []ReceiptRecord     `json:"receipts"`
	Transitions     []AttemptTransition `json:"transitions"`
}

func (value transitionChainFixture) Validate() error {
	if err := requireProtocol(value.ProtocolVersion); err != nil {
		return err
	}
	if value.Scenario != "transitionChain" {
		return invalid("fixture.scenario")
	}
	if err := value.Attempt.Validate(); err != nil {
		return err
	}
	return validateAttemptChain(value.Attempt, value.Receipts, value.Transitions, nil)
}

type directLocalFixture struct {
	ProtocolVersion int                 `json:"protocolVersion"`
	Scenario        string              `json:"scenario"`
	Attempt         AttemptRecord       `json:"attempt"`
	Assignment      AssignmentRecord    `json:"assignment"`
	Item            ItemRecord          `json:"item"`
	Receipts        []ReceiptRecord     `json:"receipts"`
	Transitions     []AttemptTransition `json:"transitions"`
}

type resultEvidenceFixture struct {
	ProtocolVersion int                      `json:"protocolVersion"`
	Scenario        string                   `json:"scenario"`
	Attempt         AttemptRecord            `json:"attempt"`
	Assignment      AssignmentRecord         `json:"assignment"`
	Manifest        AssignmentResultManifest `json:"manifest"`
	Items           []ItemRecord             `json:"items"`
	Errors          []ErrorRecord            `json:"errors"`
}

func (value resultEvidenceFixture) Validate() error {
	if err := requireProtocol(value.ProtocolVersion); err != nil {
		return err
	}
	if value.Scenario != "assignmentResultEvidence" {
		return invalid("fixture.scenario")
	}
	if err := value.Attempt.Validate(); err != nil {
		return err
	}
	if err := value.Assignment.ValidateAuthorizedBy(newAuthorizedAttempt(value.Attempt), nil); err != nil {
		return err
	}
	if err := value.Manifest.ValidateAuthorizedBy(value.Assignment, value.Attempt.OccurrenceID); err != nil {
		return err
	}
	if len(value.Items) != len(value.Assignment.ItemIDs) {
		return invalid("fixture.items")
	}
	for index, item := range value.Items {
		if err := item.Validate(); err != nil {
			return err
		}
		if item.ID != value.Assignment.ItemIDs[index] {
			return invalid("fixture.items")
		}
	}
	if err := value.Manifest.ValidateAgainstItems(value.Items); err != nil {
		return err
	}
	if len(value.Errors) > len(value.Items) {
		return invalid("fixture.errors")
	}
	errorsByID := make(map[ErrorID]ErrorRecord, len(value.Errors))
	previousErrorID := ErrorID("")
	for _, record := range value.Errors {
		if err := record.Validate(); err != nil {
			return err
		}
		if previousErrorID != "" && record.ID <= previousErrorID {
			return invalid("fixture.errors")
		}
		if record.OccurrenceID != value.Attempt.OccurrenceID || record.AttemptID == nil || *record.AttemptID != value.Attempt.ID || record.AssignmentID == nil || *record.AssignmentID != value.Assignment.ID {
			return invalid("fixture.errors")
		}
		if _, duplicate := errorsByID[record.ID]; duplicate {
			return duplicateValue("fixture.errors")
		}
		errorsByID[record.ID] = record
		previousErrorID = record.ID
	}
	failedErrorIDs := make(map[ErrorID]struct{}, len(value.Errors))
	for _, entry := range value.Manifest.Entries {
		if entry.Outcome != "failed" {
			continue
		}
		if entry.ErrorID == nil || entry.ErrorDigest == nil {
			return invalid("fixture.errors")
		}
		if _, duplicate := failedErrorIDs[*entry.ErrorID]; duplicate {
			return duplicateValue("fixture.errors")
		}
		failedErrorIDs[*entry.ErrorID] = struct{}{}
		record, present := errorsByID[*entry.ErrorID]
		if !present || record.ItemID == nil || *record.ItemID != entry.ItemID || record.Digest() != *entry.ErrorDigest {
			return invalid("fixture.errors")
		}
	}
	if len(failedErrorIDs) != len(errorsByID) {
		return invalid("fixture.errors")
	}
	return nil
}

func (value directLocalFixture) Validate() error {
	if err := requireProtocol(value.ProtocolVersion); err != nil {
		return err
	}
	if value.Scenario != "directLocalLifecycle" {
		return invalid("fixture.scenario")
	}
	if err := value.Attempt.Validate(); err != nil {
		return err
	}
	if err := value.Assignment.Validate(); err != nil {
		return err
	}
	if err := value.Item.Validate(); err != nil {
		return err
	}
	if value.Attempt.DestinationKind != DestinationDirectLocal || value.Assignment.AttemptID != value.Attempt.ID || value.Assignment.OccurrenceID != value.Attempt.OccurrenceID || value.Item.OccurrenceID != value.Attempt.OccurrenceID || len(value.Transitions) == 0 {
		return invalid("fixture.identity")
	}
	if err := value.Assignment.ValidateAuthorizedBy(newAuthorizedAttempt(value.Attempt), nil); err != nil {
		return err
	}
	if value.Item.ApplicationReceiptID == nil {
		return invalid("fixture.applicationReceipt")
	}
	verifiedReceipts, err := verifiedFixtureReceipts(value.Attempt, value.Receipts, []ItemRecord{value.Item})
	if err != nil {
		return err
	}
	if err := value.Item.ValidateApplication(verifiedReceipts, value.Attempt.SourceReceiptSigner); err != nil {
		return err
	}
	if err := validateAttemptChain(value.Attempt, value.Receipts, value.Transitions, []ItemRecord{value.Item}); err != nil {
		return err
	}
	if value.Transitions[len(value.Transitions)-1].To != "localReleased" {
		return invalid("fixture.binding")
	}
	return nil
}

type retryLifecycleFixture struct {
	ProtocolVersion       int                   `json:"protocolVersion"`
	Scenario              string                `json:"scenario"`
	Schedule              ScheduleRecord        `json:"schedule"`
	TargetManifestChunks  []TargetManifestChunk `json:"targetManifestChunks"`
	InitialOccurrence     OccurrenceRecord      `json:"initialOccurrence"`
	InitialItem           ItemRecord            `json:"initialItem"`
	AttemptOneStates      []AttemptRecord       `json:"attemptOneStates"`
	AssignmentOneStates   []AssignmentRecord    `json:"assignmentOneStates"`
	AttemptOneReceipts    []ReceiptRecord       `json:"attemptOneReceipts"`
	AttemptOneTransitions []AttemptTransition   `json:"attemptOneTransitions"`
	FailureError          ErrorRecord           `json:"failureError"`
	FailedItem            ItemRecord            `json:"failedItem"`
	RetryOccurrence       OccurrenceRecord      `json:"retryOccurrence"`
	RetryAttempt          AttemptRecord         `json:"retryAttempt"`
}

func (value retryLifecycleFixture) Validate() error {
	if err := requireProtocol(value.ProtocolVersion); err != nil {
		return err
	}
	if value.Scenario != "localExecutionFailureRetry" {
		return invalid("fixture.scenario")
	}
	if err := value.Schedule.ValidateTargetManifest(value.TargetManifestChunks); err != nil {
		return err
	}
	if err := value.InitialOccurrence.ValidateCreation(value.Schedule); err != nil {
		return err
	}
	if err := value.InitialItem.Validate(); err != nil {
		return err
	}
	if len(value.AttemptOneStates) != 4 || len(value.AssignmentOneStates) != 2 || len(value.AttemptOneTransitions) != 3 {
		return invalid("fixture.retry.states")
	}
	for _, attempt := range value.AttemptOneStates {
		if err := attempt.Validate(); err != nil {
			return err
		}
	}
	for _, assignment := range value.AssignmentOneStates {
		if err := assignment.Validate(); err != nil {
			return err
		}
	}
	if err := validateAttemptChain(value.AttemptOneStates[0], value.AttemptOneReceipts, value.AttemptOneTransitions, nil); err != nil {
		return err
	}
	verifiedReceipts, err := verifiedFixtureReceipts(value.AttemptOneStates[0], value.AttemptOneReceipts, nil)
	if err != nil {
		return err
	}
	authorized, err := AuthorizeInitialAttempt(value.AttemptOneStates[0], value.Schedule, value.InitialOccurrence, []ItemRecord{value.InitialItem})
	if err != nil {
		return err
	}
	for index, transition := range value.AttemptOneTransitions {
		evidence := AttemptAdvanceEvidence{}
		if index > 0 {
			evidence.Assignments = []AssignmentRecord{value.AssignmentOneStates[index-1]}
		}
		authorized, err = authorized.Advance(value.AttemptOneStates[index+1], transition, verifiedReceipts, evidence)
		if err != nil {
			return err
		}
	}
	for _, assignment := range value.AssignmentOneStates {
		if err := assignment.ValidateAuthorizedBy(authorized, verifiedReceipts); err != nil {
			return err
		}
	}
	if err := value.FailureError.Validate(); err != nil {
		return err
	}
	if err := value.FailedItem.Validate(); err != nil {
		return err
	}
	if err := value.FailedItem.ValidateUpdateFrom(value.InitialItem); err != nil {
		return err
	}
	if err := value.RetryOccurrence.ValidateAuthorizedBy(value.Schedule); err != nil {
		return err
	}
	if err := value.RetryAttempt.Validate(); err != nil {
		return err
	}
	if value.RetryAttempt.AttemptNumber != 2 || value.RetryAttempt.PreviousAttemptID == nil || *value.RetryAttempt.PreviousAttemptID != value.AttemptOneStates[0].ID || value.RetryAttempt.RetryErrorID == nil || *value.RetryAttempt.RetryErrorID != value.FailureError.ID {
		return invalid("fixture.retry.lineage")
	}
	var retryEvidence VerifiedReceipt
	retryEvidencePresent := false
	for _, receipt := range verifiedReceipts {
		if receipt.record.ErrorID != nil && *receipt.record.ErrorID == value.FailureError.ID {
			retryEvidence = receipt
			retryEvidencePresent = true
			break
		}
	}
	if !retryEvidencePresent {
		return invalid("fixture.retryEvidence")
	}
	_, err = AuthorizeRetryAttempt(value.RetryAttempt, value.Schedule, value.RetryOccurrence, []ItemRecord{value.FailedItem}, authorized, value.FailureError, value.AttemptOneTransitions[len(value.AttemptOneTransitions)-1], retryEvidence)
	return err
}

func validateAttemptChain(initial AttemptRecord, receipts []ReceiptRecord, transitions []AttemptTransition, items []ItemRecord) error {
	if len(transitions) == 0 {
		return invalid("fixture.transitions")
	}
	receiptIndex := make(map[ReceiptID]ReceiptRecord, len(receipts))
	previousReceiptID := ReceiptID("")
	for _, receipt := range receipts {
		if err := receipt.Validate(); err != nil {
			return err
		}
		if previousReceiptID != "" && receipt.ID <= previousReceiptID {
			return invalid("fixture.receipts.order")
		}
		if _, exists := receiptIndex[receipt.ID]; exists {
			return duplicateValue("fixture.receipts")
		}
		receiptIndex[receipt.ID] = receipt
		previousReceiptID = receipt.ID
	}
	verifiedReceipts, err := verifiedFixtureReceipts(initial, receipts, items)
	if err != nil {
		return err
	}
	verifiedIndex, err := newVerifiedReceiptIndex(verifiedReceipts)
	if err != nil {
		return err
	}
	state, revision := initial.State, initial.Revision
	applied := map[TransitionID]struct{}{}
	var sealed *Digest
	for index, transition := range transitions {
		if index > 0 && transition.OccurredAt < transitions[index-1].OccurredAt {
			return invalid("fixture.transitions.order")
		}
		if err := transition.validateAgainst(state, revision, LifecycleID(initial.ID), sealed, applied, verifiedIndex); err != nil {
			return err
		}
		for _, receiptID := range transition.SupportingReceiptIDs {
			verified, present := verifiedIndex.get(receiptID)
			if !present {
				return invalid("fixture.receipts")
			}
			if err := initial.validateReceiptTrust(verified); err != nil {
				return err
			}
		}
		if transition.To == "sealed" {
			digest := initial.AssignmentPlan.AssignmentSetDigest
			sealed = &digest
		}
		state, revision = transition.To, transition.ResultingRevision
		applied[transition.ID] = struct{}{}
	}
	return nil
}

type fixtureReceiptSignatureVerifier struct{}

func (fixtureReceiptSignatureVerifier) VerifySignature(SignatureValue, Digest, ReceiptSignerBinding) error {
	return nil
}

func verifiedFixtureReceipts(attempt AttemptRecord, receipts []ReceiptRecord, items []ItemRecord) ([]VerifiedReceipt, error) {
	itemsByID := make(map[ItemID]ItemRecord, len(items))
	for _, item := range items {
		itemsByID[item.ID] = item
	}
	verified := make([]VerifiedReceipt, 0, len(receipts))
	for _, record := range receipts {
		var signer ReceiptSignerBinding
		var subject Digest
		if record.Stage == "sourceApplied" && record.ItemID != nil {
			item, present := itemsByID[*record.ItemID]
			if !present {
				return nil, invalid("fixture.receipt.item")
			}
			signer = attempt.SourceReceiptSigner
			subject = item.ApplicationProofDigest()
		} else {
			var err error
			signer, subject, err = attempt.expectedReceiptTrust(record)
			if err != nil {
				return nil, err
			}
		}
		canonicalRecord, err := EncodeCanonical(record)
		if err != nil {
			return nil, err
		}
		envelope := SignedReceiptEnvelope{
			ProtocolVersion:       ProtocolVersion,
			Record:                record,
			CanonicalRecordDigest: SHA256Digest("facets.compute-queue.receipt-record-canonical.v1", string(canonicalRecord)),
			SignatureProfileID:    signer.SignatureProfileID,
			Signature:             SignatureValue("AQ"),
		}
		proof, err := acceptVerifiedReceiptEnvelope(envelope, signer, subject, fixtureReceiptSignatureVerifier{})
		if err != nil {
			return nil, err
		}
		verified = append(verified, proof)
	}
	return verified, nil
}

func findVerifiedReceipt(receipts []VerifiedReceipt, id ReceiptID) (VerifiedReceipt, bool) {
	for _, receipt := range receipts {
		if receipt.record.ID == id {
			return receipt, true
		}
	}
	return VerifiedReceipt{}, false
}

type rejectionVector struct {
	Name                 string `json:"name"`
	Contract             string `json:"contract"`
	ExpectedFailureClass string `json:"expectedFailureClass"`
	WireBase64           string `json:"wireBase64"`
}

type rejectionVectorFixture struct {
	ProtocolVersion int               `json:"protocolVersion"`
	Scenario        string            `json:"scenario"`
	Vectors         []rejectionVector `json:"vectors"`
}

func (value rejectionVectorFixture) Validate() error {
	if err := requireProtocol(value.ProtocolVersion); err != nil {
		return err
	}
	if value.Scenario != "rejectionVectors" || len(value.Vectors) == 0 || len(value.Vectors) > 64 {
		return invalid("fixture.rejections")
	}
	previous := ""
	for _, vector := range value.Vectors {
		if vector.Name == "" || len(vector.Name) > 128 || vector.Name <= previous || !oneOf(vector.Contract, "scheduleOccurrence", "signedReceiptEnvelope") ||
			!oneOf(vector.ExpectedFailureClass, "duplicateValue", "invalidField", "invalidIdentifier", "nonCanonicalEncoding", "unsupportedProtocolVersion") {
			return invalid("fixture.rejections")
		}
		wire, err := base64.StdEncoding.DecodeString(vector.WireBase64)
		if err != nil || len(wire) == 0 || len(wire) > MaximumDocumentBytes || base64.StdEncoding.EncodeToString(wire) != vector.WireBase64 {
			return invalid("fixture.rejections.base64")
		}
		previous = vector.Name
	}
	return nil
}

func TestAuthoritativeSwiftFixturesRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T, []byte)
	}{
		{"compute-queue-direct-local-lifecycle-v1.json", roundTripFixture[directLocalFixture]},
		{"compute-queue-assignment-result-evidence-v1.json", roundTripFixture[resultEvidenceFixture]},
		{"compute-queue-immediate-occurrence-v1.json", roundTripFixture[scheduleOccurrenceFixture]},
		{"compute-queue-mixed-terminal-report-v1.json", roundTripFixture[mixedTerminalFixture]},
		{"compute-queue-recurring-occurrence-v1.json", roundTripFixture[scheduleOccurrenceFixture]},
		{"compute-queue-rejection-vectors-v1.json", roundTripFixture[rejectionVectorFixture]},
		{"compute-queue-retry-lifecycle-v1.json", roundTripFixture[retryLifecycleFixture]},
		{"compute-queue-transition-chain-v1.json", roundTripFixture[transitionChainFixture]},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", test.name))
			if err != nil {
				t.Fatal(err)
			}
			test.run(t, data)
		})
	}
}

func roundTripFixture[T Validatable](t *testing.T, fileBytes []byte) {
	t.Helper()
	if len(fileBytes) == 0 || fileBytes[len(fileBytes)-1] != '\n' || (len(fileBytes) > 1 && fileBytes[len(fileBytes)-2] == '\n') {
		t.Fatal("fixture must have exactly one trailing LF")
	}
	wire := fileBytes[:len(fileBytes)-1]
	value, err := DecodeCanonical[T](wire)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	encoded, err := EncodeCanonical(value)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !bytes.Equal(append(encoded, '\n'), fileBytes) {
		t.Fatal("Go round trip changed authoritative Swift fixture bytes")
	}
}

func TestAuthoritativeSwiftRejectionVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "compute-queue-rejection-vectors-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := DecodeCanonical[rejectionVectorFixture](data[:len(data)-1])
	if err != nil {
		t.Fatal(err)
	}
	seen := []string{}
	for _, vector := range fixture.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			wire, decodeErr := base64.StdEncoding.DecodeString(vector.WireBase64)
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			var rejection error
			switch vector.Contract {
			case "scheduleOccurrence":
				_, rejection = DecodeCanonical[scheduleOccurrenceFixture](wire)
			case "signedReceiptEnvelope":
				envelope, envelopeErr := DecodeCustodyCanonical(wire)
				if envelopeErr != nil {
					rejection = envelopeErr
				} else {
					expected := ReceiptSignerBinding{SignerID: envelope.Record.SignerID, SigningKeyID: envelope.Record.SigningKeyID, SigningKeyRevision: envelope.Record.SigningKeyRevision, SignatureProfileID: "facets-test-signature-v1"}
					_, rejection = acceptVerifiedReceiptEnvelope(envelope, expected, envelope.Record.SubjectDigest, fixtureReceiptSignatureVerifier{})
				}
			}
			if rejection == nil {
				t.Fatal("vector was accepted")
			}
			if got := string(FailureClassOf(rejection)); got != vector.ExpectedFailureClass {
				t.Fatalf("failure class = %q (%v), want %q", got, rejection, vector.ExpectedFailureClass)
			}
		})
		seen = append(seen, vector.Name)
	}
	if !sort.StringsAreSorted(seen) {
		t.Fatal(fmt.Errorf("rejection vectors are not sorted"))
	}
}

func TestFixtureValidatorsRejectMalformedBoundsWithoutPanicking(t *testing.T) {
	retry := loadFixtureForTest[retryLifecycleFixture](t, "compute-queue-retry-lifecycle-v1.json")
	retry.AttemptOneStates = retry.AttemptOneStates[:1]
	if err := retry.Validate(); err == nil {
		t.Fatal("retry fixture accepted an incomplete state chain")
	}

	rejections := loadFixtureForTest[rejectionVectorFixture](t, "compute-queue-rejection-vectors-v1.json")
	rejections.Vectors[0].Name = string(bytes.Repeat([]byte{'a'}, 129))
	if err := rejections.Validate(); err == nil {
		t.Fatal("rejection fixture accepted an overlong vector name")
	}
	rejections = loadFixtureForTest[rejectionVectorFixture](t, "compute-queue-rejection-vectors-v1.json")
	rejections.Vectors[0].ExpectedFailureClass = "unexpected"
	if err := rejections.Validate(); err == nil {
		t.Fatal("rejection fixture accepted an unknown failure class")
	}
}

func TestSealedAssignmentCannotSubstituteAuthorizedCapsule(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "compute-queue-transition-chain-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := DecodeCanonical[transitionChainFixture](data[:len(data)-1])
	if err != nil {
		t.Fatal(err)
	}
	authorization := fixture.Attempt.AssignmentPlan.Assignments[0]
	assignment := AssignmentRecord{
		ProtocolVersion:          ProtocolVersion,
		ID:                       authorization.AssignmentID,
		OccurrenceID:             fixture.Attempt.OccurrenceID,
		AttemptID:                fixture.Attempt.ID,
		Revision:                 2,
		State:                    "sealed",
		Executor:                 authorization.Executor,
		ItemIDs:                  authorization.ItemIDs,
		ItemSetDigest:            authorization.ItemSetDigest,
		ExecutionPayloadDigest:   authorization.ExecutionPayloadDigest,
		CapsuleID:                authorization.CapsuleID,
		CapsuleDigest:            authorization.CapsuleDigest,
		InitialLease:             authorization.InitialLease,
		CurrentLease:             authorization.InitialLease,
		InitialCancellationFence: authorization.CancellationFence,
		CancellationFence:        authorization.CancellationFence,
		SourceReceiptSigner:      fixture.Attempt.SourceReceiptSigner,
		CustodyReceiptSigner:     fixture.Attempt.CustodyReceiptSigner,
		CreatedAt:                fixture.Attempt.CreatedAt,
		DeadlineAt:               fixture.Attempt.DeadlineAt,
		ReceiptIDs:               []ReceiptID{},
	}
	proof := AuthorizedAttempt{record: fixture.Attempt}
	if err := assignment.ValidateAuthorizedBy(proof, nil); err != nil {
		t.Fatalf("authorized assignment rejected: %v", err)
	}
	substituted := SHA256Digest("fixture.capsule-substitution", "different")
	assignment.CapsuleDigest = &substituted
	if err := assignment.Validate(); err != nil {
		t.Fatalf("substituted assignment should remain structurally valid: %v", err)
	}
	if err := assignment.ValidateAuthorizedBy(proof, nil); err == nil {
		t.Fatal("sealed assignment accepted a capsule digest not present in the authorized plan")
	}
}
