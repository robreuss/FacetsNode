package computequeue

// receiptSignatureVerifier is package-private so callers cannot manufacture
// authorization evidence by supplying a verifier that always succeeds. A
// later runtime checkpoint may add a concrete trusted verifier in this
// package; CP1 intentionally exposes no proof-construction API.
type receiptSignatureVerifier interface {
	VerifySignature(
		signature SignatureValue,
		payloadDigest Digest,
		expectedSigner ReceiptSignerBinding,
	) error
}

// VerifiedReceipt is deliberately not a wire contract. Its unexported fields
// prevent a decoded ReceiptRecord from being used as authenticated lifecycle
// evidence without first crossing the package-private verification boundary.
type VerifiedReceipt struct {
	record                ReceiptRecord
	expectedSigner        ReceiptSignerBinding
	expectedSubjectDigest Digest
}

func (value VerifiedReceipt) Record() ReceiptRecord { return cloneReceiptRecord(value.record) }

func sameVerifiedReceipt(left, right VerifiedReceipt) bool {
	leftBytes, leftErr := EncodeCanonical(left.record)
	rightBytes, rightErr := EncodeCanonical(right.record)
	return leftErr == nil && rightErr == nil && string(leftBytes) == string(rightBytes) &&
		left.expectedSigner == right.expectedSigner &&
		left.expectedSubjectDigest == right.expectedSubjectDigest
}

func (value VerifiedReceipt) matches(
	expectedSigner ReceiptSignerBinding,
	expectedSubjectDigest Digest,
) bool {
	return value.expectedSigner == expectedSigner &&
		value.expectedSubjectDigest == expectedSubjectDigest &&
		receiptMatchesSigner(value.record, expectedSigner) &&
		value.record.SubjectDigest == expectedSubjectDigest
}

// acceptVerifiedReceiptEnvelope is the sole construction path for
// authenticated receipt evidence. Keeping it package-private is part of the
// authorization boundary, not merely an API-surface choice.
func acceptVerifiedReceiptEnvelope(
	envelope SignedReceiptEnvelope,
	expectedSigner ReceiptSignerBinding,
	expectedSubjectDigest Digest,
	verifier receiptSignatureVerifier,
) (VerifiedReceipt, error) {
	if err := envelope.Validate(); err != nil {
		return VerifiedReceipt{}, err
	}
	if err := expectedSigner.Validate(); err != nil {
		return VerifiedReceipt{}, err
	}
	if err := expectedSubjectDigest.Validate(); err != nil {
		return VerifiedReceipt{}, err
	}
	if verifier == nil {
		return VerifiedReceipt{}, invalid("receiptEnvelope.verifier")
	}
	if envelope.SignatureProfileID != expectedSigner.SignatureProfileID {
		return VerifiedReceipt{}, invalid("receiptEnvelope.signatureProfileID")
	}
	if err := verifier.VerifySignature(
		envelope.Signature,
		envelope.SignaturePayloadDigest(),
		expectedSigner,
	); err != nil {
		return VerifiedReceipt{}, err
	}
	record := cloneReceiptRecord(envelope.Record)
	if !receiptMatchesSigner(record, expectedSigner) ||
		record.SubjectDigest != expectedSubjectDigest {
		return VerifiedReceipt{}, invalid("verifiedReceipt")
	}
	return VerifiedReceipt{
		record:                record,
		expectedSigner:        expectedSigner,
		expectedSubjectDigest: expectedSubjectDigest,
	}, nil
}

func cloneReceiptRecord(value ReceiptRecord) ReceiptRecord {
	result := value
	result.AssignmentID = clonePointer(value.AssignmentID)
	result.ItemID = clonePointer(value.ItemID)
	result.ExecutionOutcome = clonePointer(value.ExecutionOutcome)
	result.ResultDigest = clonePointer(value.ResultDigest)
	result.ResultCapsuleDigest = clonePointer(value.ResultCapsuleDigest)
	result.ErrorID = clonePointer(value.ErrorID)
	result.ErrorDigest = clonePointer(value.ErrorDigest)
	result.LeaseID = clonePointer(value.LeaseID)
	result.LeaseRevision = clonePointer(value.LeaseRevision)
	result.LeaseExpiresAt = clonePointer(value.LeaseExpiresAt)
	return result
}

type verifiedReceiptIndex struct {
	byID map[ReceiptID]VerifiedReceipt
}

func newVerifiedReceiptIndex(receipts []VerifiedReceipt) (verifiedReceiptIndex, error) {
	if len(receipts) > maximumReceipts {
		return verifiedReceiptIndex{}, invalid("receipts")
	}
	index := verifiedReceiptIndex{byID: make(map[ReceiptID]VerifiedReceipt, len(receipts))}
	idempotencyKeys := make(map[Digest]ReceiptID, len(receipts))
	logicalSlots := make(map[Digest]ReceiptID, len(receipts))
	for _, receipt := range receipts {
		record := receipt.record
		if err := record.Validate(); err != nil {
			return verifiedReceiptIndex{}, err
		}
		if _, exists := index.byID[record.ID]; exists {
			return verifiedReceiptIndex{}, duplicateValue("receipts.id")
		}
		if _, exists := idempotencyKeys[record.IdempotencyKey]; exists {
			return verifiedReceiptIndex{}, duplicateValue("receipts.idempotencyKey")
		}
		logicalSlot := record.LogicalSlotKey()
		if _, exists := logicalSlots[logicalSlot]; exists {
			return verifiedReceiptIndex{}, duplicateValue("receipts.logicalSlot")
		}
		index.byID[record.ID] = receipt
		idempotencyKeys[record.IdempotencyKey] = record.ID
		logicalSlots[logicalSlot] = record.ID
	}
	return index, nil
}

func (value verifiedReceiptIndex) get(id ReceiptID) (VerifiedReceipt, bool) {
	receipt, ok := value.byID[id]
	return receipt, ok
}

func (value verifiedReceiptIndex) records(ids []ReceiptID) ([]ReceiptRecord, error) {
	records := make([]ReceiptRecord, len(ids))
	for index, id := range ids {
		receipt, ok := value.byID[id]
		if !ok {
			return nil, invalid("missingTransitionReceipt")
		}
		records[index] = receipt.record
	}
	return records, nil
}
