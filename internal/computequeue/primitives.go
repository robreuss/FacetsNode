package computequeue

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
)

type Digest string
type Timestamp int64

// Opaque identifiers stay distinct in Go exactly as their phantom-tagged
// Swift counterparts do. LifecycleID is the sole deliberate type erasure used
// by a transition envelope.
type ScheduleID string
type OccurrenceID string
type AttemptID string
type AssignmentID string
type ItemID string
type ReceiptID string
type TransitionID string
type WorkerID string
type OfferingID string
type JobCapsuleID string
type StoragePoolID string
type StorageReservationID string
type OperationDefinitionID string
type PolicyID string
type LeaseID string
type ErrorID string
type LifecycleID string

// OpaqueID remains only as a compatibility helper for generic test utilities;
// all production record fields use the distinct types above.
type OpaqueID string

func (value Digest) Validate() error {
	if len(value) != sha256.Size*2 || string(value) != strings.ToLower(string(value)) {
		return classified(FailureInvalidDigest, "digest")
	}
	decoded, err := hex.DecodeString(string(value))
	if err != nil || len(decoded) != sha256.Size {
		return classified(FailureInvalidDigest, "digest")
	}
	return nil
}

func (value Timestamp) Validate() error {
	if value < 0 {
		return invalid("timestamp")
	}
	return nil
}

func validateOpaqueID(value string) error {
	parsed, err := uuid.Parse(value)
	if err != nil || parsed == uuid.Nil || len(value) != 36 || parsed.String() != value || strings.ToLower(value) != value {
		return classified(FailureInvalidIdentifier, "identifier")
	}
	return nil
}

func (value OpaqueID) Validate() error             { return validateOpaqueID(string(value)) }
func (value ScheduleID) Validate() error           { return validateOpaqueID(string(value)) }
func (value OccurrenceID) Validate() error         { return validateOpaqueID(string(value)) }
func (value AttemptID) Validate() error            { return validateOpaqueID(string(value)) }
func (value AssignmentID) Validate() error         { return validateOpaqueID(string(value)) }
func (value ItemID) Validate() error               { return validateOpaqueID(string(value)) }
func (value ReceiptID) Validate() error            { return validateOpaqueID(string(value)) }
func (value TransitionID) Validate() error         { return validateOpaqueID(string(value)) }
func (value WorkerID) Validate() error             { return validateOpaqueID(string(value)) }
func (value OfferingID) Validate() error           { return validateOpaqueID(string(value)) }
func (value JobCapsuleID) Validate() error         { return validateOpaqueID(string(value)) }
func (value StoragePoolID) Validate() error        { return validateOpaqueID(string(value)) }
func (value StorageReservationID) Validate() error { return validateOpaqueID(string(value)) }
func (value OperationDefinitionID) Validate() error {
	return validateOpaqueID(string(value))
}
func (value PolicyID) Validate() error    { return validateOpaqueID(string(value)) }
func (value LeaseID) Validate() error     { return validateOpaqueID(string(value)) }
func (value ErrorID) Validate() error     { return validateOpaqueID(string(value)) }
func (value LifecycleID) Validate() error { return validateOpaqueID(string(value)) }

// SHA256Digest uses the exact big-endian UInt64 length framing used by Swift.
func SHA256Digest(domain string, components ...string) Digest {
	hash := sha256.New()
	appendComponent := func(value string) {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len([]byte(value))))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(value))
	}
	appendComponent(domain)
	for _, component := range components {
		appendComponent(component)
	}
	return Digest(hex.EncodeToString(hash.Sum(nil)))
}

// ExactBytesDigest binds exact source-side bytes without parsing them.
func ExactBytesDigest(domain string, value []byte, maximum int64) (Digest, error) {
	if len(value) == 0 || int64(len(value)) > maximum {
		return "", invalid("exactBytes")
	}
	hash := sha256.New()
	for _, component := range [][]byte{[]byte(domain), value} {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(component)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write(component)
	}
	return Digest(hex.EncodeToString(hash.Sum(nil))), nil
}

type SignerID string
type SigningKeyID string

func (value SignerID) Validate() error     { return requireMachineToken(string(value), "signerID") }
func (value SigningKeyID) Validate() error { return requireMachineToken(string(value), "signingKeyID") }

type ReceiptSignerBinding struct {
	SignerID           SignerID     `json:"signerID"`
	SigningKeyID       SigningKeyID `json:"signingKeyID"`
	SigningKeyRevision uint64       `json:"signingKeyRevision"`
	SignatureProfileID string       `json:"signatureProfileID"`
}

func (value ReceiptSignerBinding) Validate() error {
	if err := value.SignerID.Validate(); err != nil {
		return err
	}
	if err := value.SigningKeyID.Validate(); err != nil {
		return err
	}
	if err := requirePositive(value.SigningKeyRevision, "signingKeyRevision"); err != nil {
		return err
	}
	return requireMachineToken(value.SignatureProfileID, "signatureProfileID")
}

type SignatureValue string

const maximumSignatureBytes = 16 * 1024

func (value SignatureValue) Validate() error {
	raw := string(value)
	if raw == "" || len(raw) > (maximumSignatureBytes*4+2)/3 {
		return invalid("signature.base64URL")
	}
	for _, current := range []byte(raw) {
		if !((current >= '0' && current <= '9') || (current >= 'A' && current <= 'Z') || (current >= 'a' && current <= 'z') || current == '-' || current == '_') {
			return invalid("signature.base64URL")
		}
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(decoded) == 0 || len(decoded) > maximumSignatureBytes || base64.RawURLEncoding.EncodeToString(decoded) != raw {
		return invalid("signature.base64URL")
	}
	return nil
}

type TransitionAuthority string

const (
	AuthoritySourceDevice    TransitionAuthority = "sourceDevice"
	AuthorityJobCustody      TransitionAuthority = "jobCustody"
	AuthorityWorker          TransitionAuthority = "worker"
	AuthorityStorageCapacity TransitionAuthority = "storageCapacityAuthority"
	AuthorityComputePool     TransitionAuthority = "computePool"
)

func (value TransitionAuthority) valid() bool {
	return oneOf(string(value), "sourceDevice", "jobCustody", "worker", "storageCapacityAuthority", "computePool")
}

type ScheduleState string
type OccurrenceState string
type AttemptState string
type AssignmentState string
type ItemDisposition string
type ReceiptStage string
type EligibilityKind string
type DestinationKind string
type ManualClosePolicy string
type AutoClosePolicy string
type ExecutorKind string
type ExecutionOutcome string
type ItemExecutionOutcome string
type ItemAttemptOutcome string
type ErrorCode string
type ReasonCode string

const (
	DestinationDirectLocal  DestinationKind = "directLocal"
	DestinationFixedWorkers DestinationKind = "fixedWorkers"
	DestinationComputePool  DestinationKind = "computePool"

	ExecutorSourceLocal ExecutorKind = "sourceLocal"
	ExecutorWorker      ExecutorKind = "worker"
)

var scheduleStates = []string{"active", "paused", "cancelled", "expired"}
var occurrenceStates = []string{
	"eligible", "preparing", "waitingForSpace", "waitingForStorage", "securelyQueued", "running",
	"resultsPendingSpace", "applying", "localRunning", "localApplying", "completed", "completedWithErrors",
	"paused", "cancellationRequested", "cancellationUnconfirmed", "cancelled", "failed", "needsAttention",
}
var executionStates = []string{
	"prepared", "sealed", "admissionPending", "custodied", "waitingForWorker", "claimed", "executing",
	"resultCustodied", "delivered", "applied", "released", "retryableRejected", "expired",
	"custodyCancellationRequested", "custodyCancellationConfirmed", "workerCancellationRequested",
	"workerCancellationConfirmed", "executionFailed", "invalidResult", "uncertainTermination", "settled",
	"localExecuting", "localResultReady", "localApplied", "localReleased", "localCancellationRequested",
	"localCancellationConfirmed", "localExecutionFailed", "localInvalidResult", "localUncertainTermination",
}
var itemDispositions = []string{
	"applied", "skippedSourceMissing", "skippedSourceMissingBeforeDisclosure", "skippedSourceChangedBeforeDisclosure",
	"resultNotAppliedSourceMissing", "resultNotAppliedSourceChanged", "failedPreparation", "failedExecution",
	"invalidResult", "cancelledBeforeDisclosure", "cancelledAfterDisclosure",
}
var receiptStages = []string{
	"sourceSealed", "custodyAccepted", "waitingForWorker", "admissionRejected", "leaseRenewed", "leaseExpired",
	"workerClaimed", "executionStarted", "executionCompleted", "resultCustodied", "resultDelivered",
	"sourceResultRejected", "sourceApplied", "cancellationRequested", "custodyCancellationConfirmed",
	"workerCancellationConfirmed", "releaseRequested", "custodyReleased", "workerReleased",
	"localExecutionStarted", "localExecutionCompleted", "localReleased", "localCancellationConfirmed",
}
var errorCodes = []string{
	"unsupportedProtocol", "malformedIdentifier", "invalidDigest", "invalidRecord", "staleRevision",
	"invalidPredecessor", "unauthorizedTransition", "replayedTransition", "fixedWorkerSetMutation",
	"counterMismatch", "storagePressure", "quotaExceeded", "capacityUnavailable", "reservationExpired",
	"sourceMissing", "sourceChanged", "workerUnavailable", "cancellationUnconfirmed", "resultRejected",
}
var reasonCodes = []string{
	"userRequested", "automaticClose", "scheduleExpired", "spaceClosedBeforeSecureHandoff", "waitingForOpenSpace",
	"retryBackoff", "cancellationUnconfirmed", "leaseExpired", "mixedTerminalOutcomes", "error",
}

func (value ScheduleState) valid() bool   { return oneOf(string(value), scheduleStates...) }
func (value OccurrenceState) valid() bool { return oneOf(string(value), occurrenceStates...) }
func (value AttemptState) valid() bool    { return oneOf(string(value), executionStates...) }
func (value AssignmentState) valid() bool {
	return oneOf(string(value), executionStates...) && value != "settled"
}
func (value ItemDisposition) valid() bool { return oneOf(string(value), itemDispositions...) }
func (value ReceiptStage) valid() bool    { return oneOf(string(value), receiptStages...) }
func (value EligibilityKind) valid() bool { return oneOf(string(value), "immediate", "recurring") }
func (value DestinationKind) valid() bool {
	return oneOf(string(value), "directLocal", "fixedWorkers", "computePool")
}
func (value ManualClosePolicy) valid() bool {
	return oneOf(string(value), "askWithActiveWork", "continueSecurelyQueued", "requestCancellation")
}
func (value AutoClosePolicy) valid() bool {
	return oneOf(string(value), "requestCancellation", "continueSecurelyQueued")
}
func (value ExecutorKind) valid() bool         { return oneOf(string(value), "sourceLocal", "worker") }
func (value ExecutionOutcome) valid() bool     { return oneOf(string(value), "succeeded", "failed") }
func (value ItemExecutionOutcome) valid() bool { return oneOf(string(value), "succeeded", "failed") }
func (value ItemAttemptOutcome) valid() bool {
	return oneOf(string(value), "admissionRejected", "succeeded", "failedExecution", "invalidResult", "cancelledBeforeDisclosure", "cancelledAfterDisclosure")
}
func (value ErrorCode) valid() bool  { return oneOf(string(value), errorCodes...) }
func (value ReasonCode) valid() bool { return oneOf(string(value), reasonCodes...) }

type FacetsObjectID struct {
	ProviderRootURI string `json:"providerRootURI"`
	Kind            string `json:"kind"`
	SourceID        string `json:"sourceID"`
}

func (identifier FacetsObjectID) Validate() error {
	if identifier.ProviderRootURI == "" || strings.TrimSpace(identifier.ProviderRootURI) != identifier.ProviderRootURI ||
		identifier.SourceID == "" || strings.TrimSpace(identifier.SourceID) != identifier.SourceID ||
		strings.ContainsRune(identifier.ProviderRootURI, '\x00') || strings.ContainsRune(identifier.SourceID, '\x00') ||
		!utf8.ValidString(identifier.ProviderRootURI) || !utf8.ValidString(identifier.SourceID) ||
		len(identifier.ProviderRootURI) > 16*1024 || len(identifier.SourceID) > 16*1024 || !validObjectKind(identifier.Kind) {
		return invalid("objectID")
	}
	if !hasURLComponentsCompatibleScheme(identifier.ProviderRootURI) || len(identifier.RawValue()) > 32*1024 {
		return invalid("objectID.providerRootURI")
	}
	return nil
}

// Swift's URLComponents accepts and percent-encodes URL text that net/url.Parse
// rejects (for example "x:%"). The shared identity contract only relies on a
// valid, nonempty URI scheme, so reproduce that boundary without imposing
// Go's stricter percent-escape parser on cross-language wire values.
func hasURLComponentsCompatibleScheme(value string) bool {
	colon := strings.IndexByte(value, ':')
	if colon <= 0 {
		return false
	}
	for index := 0; index < colon; index++ {
		current := value[index]
		if index == 0 {
			if !((current >= 'A' && current <= 'Z') || (current >= 'a' && current <= 'z')) {
				return false
			}
			continue
		}
		if !((current >= 'A' && current <= 'Z') || (current >= 'a' && current <= 'z') ||
			(current >= '0' && current <= '9') || current == '+' || current == '-' || current == '.') {
			return false
		}
	}
	return true
}

func (identifier FacetsObjectID) RawValue() string {
	encode := func(value string) string { return base64.RawURLEncoding.EncodeToString([]byte(value)) }
	return strings.Join([]string{"facets-object-id", "v1", encode(identifier.ProviderRootURI), identifier.Kind, encode(identifier.SourceID)}, ":")
}

func validObjectKind(value string) bool {
	return oneOf(value,
		"canonical_place", "provider_place", "social_post", "discussion_forum", "media_item", "media_item_collection",
		"media_stream", "calendar", "unified_calendar_event", "provider_calendar_event", "provider_reminder",
		"unified_life_event", "provider_life_event", "unified_person", "provider_person", "persona", "commerce_order",
		"commerce_product", "web_link", "web_link_visit", "web_link_bookmark", "web_link_bookmark_folder", "web_search",
		"short_message_thread", "short_message", "journal_entry", "note", "note_folder", "long_message", "mailbox",
		"ai_conversation", "ai_interaction", "ai_event", "dataset", "home_automation_event", "personality_test_result",
		"document", "structured_text_work", "structured_text_reading", "fitness", "financial_balance", "financial_transaction",
		"financial_record", "health_record", "education_record", "government_record", "annotation", "text", "semantic_passage")
}

func requireProtocol(value int) error {
	if value != ProtocolVersion {
		return classified(FailureUnsupportedProtocolVersion, fmt.Sprint(value))
	}
	return nil
}

func requirePositive(value uint64, field string) error {
	if value == 0 {
		return invalid(field)
	}
	return nil
}

func requireNonempty(value, field string) error {
	if value == "" || strings.TrimSpace(value) != value || strings.ContainsRune(value, '\x00') || len(value) > 512 || !utf8.ValidString(value) {
		return invalid(field)
	}
	return nil
}

func requireMachineToken(value, field string) error {
	if value == "" || len(value) > 128 {
		return invalid(field)
	}
	for _, current := range []byte(value) {
		if !((current >= '0' && current <= '9') || (current >= 'A' && current <= 'Z') || (current >= 'a' && current <= 'z') || current == '-' || current == '.' || current == ':' || current == '_') {
			return invalid(field)
		}
	}
	return nil
}

func requireBoundedString(value, field string) error { return requireNonempty(value, field) }

func requireUniqueSorted(values []string, field string) error {
	if !sort.StringsAreSorted(values) {
		return invalid(field + ".order")
	}
	for index := 1; index < len(values); index++ {
		if values[index] == values[index-1] {
			return invalid(field + ".duplicate")
		}
	}
	return nil
}

func classified(class FailureClass, field string) error {
	return &ContractError{Class: class, Field: field, Cause: ErrInvalidRecord}
}

func invalid(field string) error { return classified(FailureInvalidField, field) }

func duplicateValue(field string) error { return classified(FailureDuplicateValue, field) }

func oneOf(value string, values ...string) bool {
	for _, candidate := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func optionalString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
func optionalDigest(value *Digest) string {
	if value == nil {
		return ""
	}
	return string(*value)
}
func optionalTimestamp(value *Timestamp) string {
	if value == nil {
		return ""
	}
	return fmt.Sprintf("%d", *value)
}
