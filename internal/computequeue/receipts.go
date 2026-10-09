package computequeue

import "fmt"

type ReceiptRecord struct {
	ProtocolVersion     int                 `json:"protocolVersion"`
	ID                  ReceiptID           `json:"id"`
	OccurrenceID        OccurrenceID        `json:"occurrenceID"`
	AttemptID           AttemptID           `json:"attemptID"`
	AssignmentID        *AssignmentID       `json:"assignmentID,omitempty"`
	ItemID              *ItemID             `json:"itemID,omitempty"`
	Stage               ReceiptStage        `json:"stage"`
	Authority           TransitionAuthority `json:"authority"`
	ExecutionOutcome    *ExecutionOutcome   `json:"executionOutcome,omitempty"`
	ResultDigest        *Digest             `json:"resultDigest,omitempty"`
	ResultCapsuleDigest *Digest             `json:"resultCapsuleDigest,omitempty"`
	ErrorID             *ErrorID            `json:"errorID,omitempty"`
	ErrorDigest         *Digest             `json:"errorDigest,omitempty"`
	LeaseID             *LeaseID            `json:"leaseID,omitempty"`
	LeaseRevision       *uint64             `json:"leaseRevision,omitempty"`
	LeaseExpiresAt      *Timestamp          `json:"leaseExpiresAt,omitempty"`
	CancellationFence   uint64              `json:"cancellationFence"`
	SignerID            SignerID            `json:"signerID"`
	SigningKeyID        SigningKeyID        `json:"signingKeyID"`
	SigningKeyRevision  uint64              `json:"signingKeyRevision"`
	SubjectDigest       Digest              `json:"subjectDigest"`
	IdempotencyKey      Digest              `json:"idempotencyKey"`
	RecordedAt          Timestamp           `json:"recordedAt"`
}

func (value ReceiptRecord) Validate() error {
	if err := requireProtocol(value.ProtocolVersion); err != nil {
		return err
	}
	if err := value.ID.Validate(); err != nil {
		return err
	}
	if err := value.OccurrenceID.Validate(); err != nil {
		return err
	}
	if err := value.AttemptID.Validate(); err != nil {
		return err
	}
	if value.AssignmentID != nil {
		if err := value.AssignmentID.Validate(); err != nil {
			return err
		}
	}
	if value.ItemID != nil {
		if err := value.ItemID.Validate(); err != nil {
			return err
		}
	}
	if !value.Stage.valid() || !value.Authority.valid() || value.Authority != receiptAuthority(value.Stage) {
		return invalid("receipt.authority")
	}
	if value.ExecutionOutcome != nil && !value.ExecutionOutcome.valid() {
		return invalid("receipt.executionOutcome")
	}
	for _, digest := range []*Digest{value.ResultDigest, value.ResultCapsuleDigest, value.ErrorDigest, &value.SubjectDigest, &value.IdempotencyKey} {
		if digest != nil {
			if err := digest.Validate(); err != nil {
				return err
			}
		}
	}
	if value.ErrorID != nil {
		if err := value.ErrorID.Validate(); err != nil {
			return err
		}
	}
	if value.LeaseID != nil {
		if err := value.LeaseID.Validate(); err != nil {
			return err
		}
	}
	if value.LeaseExpiresAt != nil {
		if err := value.LeaseExpiresAt.Validate(); err != nil {
			return err
		}
	}
	if err := value.SignerID.Validate(); err != nil {
		return err
	}
	if err := value.SigningKeyID.Validate(); err != nil {
		return err
	}
	if err := requirePositive(value.SigningKeyRevision, "signingKeyRevision"); err != nil {
		return err
	}
	if err := value.RecordedAt.Validate(); err != nil {
		return err
	}

	isLocalStage := oneOf(string(value.Stage), "localExecutionStarted", "localExecutionCompleted", "localReleased", "localCancellationConfirmed")
	hasNoLease := value.LeaseID == nil && value.LeaseRevision == nil && value.LeaseExpiresAt == nil && value.CancellationFence == 0
	hasExternalLease := value.LeaseID != nil && value.LeaseRevision != nil && *value.LeaseRevision > 0 && value.LeaseExpiresAt != nil && value.CancellationFence > 0
	if value.AssignmentID == nil || isLocalStage {
		if !hasNoLease {
			return invalid("receipt.lease")
		}
	} else if value.Authority == AuthoritySourceDevice {
		if !hasNoLease && !hasExternalLease {
			return invalid("receipt.lease")
		}
	} else if !hasExternalLease {
		return invalid("receipt.lease")
	}
	if receiptRequiresAssignment(value.Stage) && value.AssignmentID == nil {
		return invalid("assignmentID")
	}
	if value.ItemID != nil && value.AssignmentID == nil {
		return invalid("itemID")
	}
	if value.Stage == "sourceResultRejected" {
		if value.AssignmentID == nil || value.ItemID == nil {
			return invalid("itemID")
		}
	} else if value.Stage != "sourceApplied" && value.ItemID != nil {
		return invalid("itemID")
	}
	hasError := value.ErrorID != nil && value.ErrorDigest != nil
	if (value.ErrorID == nil) != (value.ErrorDigest == nil) {
		return invalid("receipt.errorEvidence")
	}
	switch value.Stage {
	case "executionCompleted":
		if value.ItemID != nil || value.ExecutionOutcome == nil {
			return invalid("executionCompleted.outcome")
		}
		if *value.ExecutionOutcome == "succeeded" {
			if value.ResultDigest == nil || value.ResultCapsuleDigest == nil || hasError {
				return invalid("executionCompleted.result")
			}
		} else if value.ResultDigest != nil || value.ResultCapsuleDigest != nil || !hasError {
			return invalid("executionCompleted.failure")
		}
	case "resultCustodied", "resultDelivered":
		if value.ItemID != nil || value.ExecutionOutcome == nil || *value.ExecutionOutcome != "succeeded" || value.ResultDigest == nil || value.ResultCapsuleDigest == nil || hasError {
			return invalid("custodiedResult")
		}
	case "localExecutionCompleted":
		if value.ItemID != nil || value.ExecutionOutcome == nil || value.ResultCapsuleDigest != nil {
			return invalid("localExecutionCompleted.outcome")
		}
		if *value.ExecutionOutcome == "succeeded" {
			if value.ResultDigest == nil || hasError {
				return invalid("localExecutionCompleted.result")
			}
		} else if value.ResultDigest != nil || !hasError {
			return invalid("localExecutionCompleted.failure")
		}
	case "admissionRejected", "leaseExpired":
		if value.ItemID != nil || value.ExecutionOutcome != nil || value.ResultDigest != nil || value.ResultCapsuleDigest != nil || !hasError {
			return invalid("receipt.errorEvidence")
		}
	case "sourceResultRejected":
		if value.ExecutionOutcome != nil || value.ResultDigest == nil || value.ResultCapsuleDigest != nil || !hasError {
			return invalid("receipt.sourceResultRejected")
		}
	default:
		if value.ExecutionOutcome != nil || value.ResultDigest != nil || value.ResultCapsuleDigest != nil || hasError {
			return invalid("receipt.resultEvidence")
		}
	}
	if value.IdempotencyKey != value.MakeIdempotencyKey() {
		return invalid("receipt.idempotencyKey")
	}
	return nil
}

func (value ReceiptRecord) MakeIdempotencyKey() Digest {
	return SHA256Digest("facets.compute-queue.receipt-idempotency.v1",
		string(value.OccurrenceID), string(value.AttemptID), optionalAssignmentID(value.AssignmentID), optionalItemID(value.ItemID),
		string(value.Stage), string(value.Authority), optionalExecutionOutcome(value.ExecutionOutcome), optionalDigest(value.ResultDigest),
		optionalDigest(value.ResultCapsuleDigest), optionalErrorID(value.ErrorID), optionalDigest(value.ErrorDigest), optionalLeaseID(value.LeaseID),
		optionalUint64(value.LeaseRevision), optionalTimestamp(value.LeaseExpiresAt), fmt.Sprint(value.CancellationFence), string(value.SignerID),
		string(value.SigningKeyID), fmt.Sprint(value.SigningKeyRevision), string(value.SubjectDigest))
}

func (value ReceiptRecord) LogicalSlotKey() Digest {
	return SHA256Digest("facets.compute-queue.receipt-logical-slot.v1", string(value.OccurrenceID), string(value.AttemptID), optionalAssignmentID(value.AssignmentID), optionalItemID(value.ItemID), string(value.Stage), string(value.Authority), optionalLeaseID(value.LeaseID), optionalUint64(value.LeaseRevision), fmt.Sprint(value.CancellationFence))
}

type SignedReceiptEnvelope struct {
	ProtocolVersion       int            `json:"protocolVersion"`
	Record                ReceiptRecord  `json:"record"`
	CanonicalRecordDigest Digest         `json:"canonicalRecordDigest"`
	SignatureProfileID    string         `json:"signatureProfileID"`
	Signature             SignatureValue `json:"signature"`
}

func (value SignedReceiptEnvelope) Validate() error {
	if err := requireProtocol(value.ProtocolVersion); err != nil {
		return err
	}
	if err := value.Record.Validate(); err != nil {
		return err
	}
	if err := requireMachineToken(value.SignatureProfileID, "receiptEnvelope.signatureProfileID"); err != nil {
		return err
	}
	if err := value.Signature.Validate(); err != nil {
		return err
	}
	bytes, err := EncodeCanonical(value.Record)
	if err != nil {
		return err
	}
	expected := SHA256Digest("facets.compute-queue.receipt-record-canonical.v1", string(bytes))
	if value.CanonicalRecordDigest != expected {
		return invalid("receiptEnvelope.canonicalRecordDigest")
	}
	return nil
}

func (value SignedReceiptEnvelope) SignaturePayloadDigest() Digest {
	return SHA256Digest("facets.compute-queue.receipt-signature-payload.v1", fmt.Sprint(value.ProtocolVersion), value.SignatureProfileID, string(value.CanonicalRecordDigest))
}

// ValidateSignerBinding performs the fail-closed profile and key-binding
// checks that precede cryptographic signature verification. Signature bytes
// are intentionally not verified here because CP1 does not own a key store.
func (value SignedReceiptEnvelope) ValidateSignerBinding(expected ReceiptSignerBinding) error {
	if err := value.Validate(); err != nil {
		return err
	}
	if err := expected.Validate(); err != nil {
		return err
	}
	if value.SignatureProfileID != expected.SignatureProfileID ||
		value.Record.SignerID != expected.SignerID ||
		value.Record.SigningKeyID != expected.SigningKeyID ||
		value.Record.SigningKeyRevision != expected.SigningKeyRevision {
		return invalid("receiptEnvelope.signerBinding")
	}
	return nil
}

type ErrorRecord struct {
	ProtocolVersion int                 `json:"protocolVersion"`
	ID              ErrorID             `json:"id"`
	OccurrenceID    OccurrenceID        `json:"occurrenceID"`
	Code            ErrorCode           `json:"code"`
	Authority       TransitionAuthority `json:"authority"`
	Retryable       bool                `json:"retryable"`
	ObservedAt      Timestamp           `json:"observedAt"`
	AttemptID       *AttemptID          `json:"attemptID,omitempty"`
	AssignmentID    *AssignmentID       `json:"assignmentID,omitempty"`
	ItemID          *ItemID             `json:"itemID,omitempty"`
	DiagnosticCode  *string             `json:"diagnosticCode,omitempty"`
}

func (value ErrorRecord) Validate() error {
	if err := requireProtocol(value.ProtocolVersion); err != nil {
		return err
	}
	if err := value.ID.Validate(); err != nil {
		return err
	}
	if err := value.OccurrenceID.Validate(); err != nil {
		return err
	}
	if !value.Code.valid() || !value.Authority.valid() {
		return invalid("error.enum")
	}
	if err := value.ObservedAt.Validate(); err != nil {
		return err
	}
	if value.AttemptID != nil {
		if err := value.AttemptID.Validate(); err != nil {
			return err
		}
	}
	if value.AssignmentID != nil {
		if err := value.AssignmentID.Validate(); err != nil {
			return err
		}
	}
	if value.ItemID != nil {
		if err := value.ItemID.Validate(); err != nil {
			return err
		}
	}
	if value.ItemID != nil && (value.AssignmentID == nil || value.AttemptID == nil) {
		return invalid("error.itemID")
	}
	if value.AssignmentID != nil && value.AttemptID == nil {
		return invalid("error.assignmentID")
	}
	if value.DiagnosticCode != nil {
		if *value.DiagnosticCode == "" || len(*value.DiagnosticCode) > 64 {
			return invalid("diagnosticCode")
		}
		for _, current := range []byte(*value.DiagnosticCode) {
			if !((current >= '0' && current <= '9') || (current >= 'A' && current <= 'Z') || (current >= 'a' && current <= 'z') || current == '-' || current == '.' || current == '_') {
				return invalid("diagnosticCode")
			}
		}
	}
	return nil
}

func (value ErrorRecord) Digest() Digest {
	retryable := "false"
	if value.Retryable {
		retryable = "true"
	}
	diagnostic := ""
	if value.DiagnosticCode != nil {
		diagnostic = *value.DiagnosticCode
	}
	return SHA256Digest("facets.compute-queue.error-record.v1", string(value.ID), string(value.OccurrenceID), string(value.Code), string(value.Authority), retryable, fmt.Sprint(value.ObservedAt), optionalAttemptID(value.AttemptID), optionalAssignmentID(value.AssignmentID), optionalItemID(value.ItemID), diagnostic)
}

func receiptAuthority(stage ReceiptStage) TransitionAuthority {
	switch stage {
	case "sourceSealed", "resultDelivered", "sourceResultRejected", "sourceApplied", "cancellationRequested", "releaseRequested", "localExecutionStarted", "localExecutionCompleted", "localReleased", "localCancellationConfirmed":
		return AuthoritySourceDevice
	case "custodyAccepted", "waitingForWorker", "admissionRejected", "leaseExpired", "resultCustodied", "custodyReleased", "custodyCancellationConfirmed":
		return AuthorityJobCustody
	default:
		return AuthorityWorker
	}
}

func receiptRequiresAssignment(stage ReceiptStage) bool {
	if oneOf(string(stage), "sourceResultRejected", "localExecutionStarted", "localExecutionCompleted", "localReleased", "localCancellationConfirmed") {
		return true
	}
	return receiptAuthority(stage) != AuthoritySourceDevice
}

func optionalAttemptID(value *AttemptID) string {
	if value == nil {
		return ""
	}
	return string(*value)
}
func optionalAssignmentID(value *AssignmentID) string {
	if value == nil {
		return ""
	}
	return string(*value)
}
func optionalItemID(value *ItemID) string {
	if value == nil {
		return ""
	}
	return string(*value)
}
func optionalErrorID(value *ErrorID) string {
	if value == nil {
		return ""
	}
	return string(*value)
}
func optionalLeaseID(value *LeaseID) string {
	if value == nil {
		return ""
	}
	return string(*value)
}
func optionalExecutionOutcome(value *ExecutionOutcome) string {
	if value == nil {
		return ""
	}
	return string(*value)
}
func optionalUint64(value *uint64) string {
	if value == nil {
		return ""
	}
	return fmt.Sprint(*value)
}
