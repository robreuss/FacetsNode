package computequeue

import (
	"fmt"
	"sort"
)

const (
	MaximumRetries             = 31
	MaximumBackoffMilliseconds = uint64(2_592_000_000)
)

type OperationBinding struct {
	TypeID              string                `json:"typeID"`
	SchemaVersion       uint64                `json:"schemaVersion"`
	DefinitionID        OperationDefinitionID `json:"definitionID"`
	DefinitionRevision  uint64                `json:"definitionRevision"`
	DefinitionDigest    Digest                `json:"definitionDigest"`
	DefinitionByteCount int64                 `json:"definitionByteCount"`
}

func (value OperationBinding) Validate() error {
	if err := requireMachineToken(value.TypeID, "operationBinding.typeID"); err != nil || (!containsEither(value.TypeID, '.', ':')) {
		return invalid("operationBinding.typeID")
	}
	if err := requirePositive(value.SchemaVersion, "operationBinding.schemaVersion"); err != nil {
		return err
	}
	if err := value.DefinitionID.Validate(); err != nil {
		return err
	}
	if err := requirePositive(value.DefinitionRevision, "operationBinding.definitionRevision"); err != nil {
		return err
	}
	if err := value.DefinitionDigest.Validate(); err != nil {
		return err
	}
	if value.DefinitionByteCount <= 0 || value.DefinitionByteCount > MaximumDocumentBytes {
		return invalid("operationBinding.definitionByteCount")
	}
	return nil
}

func (value OperationBinding) Digest() Digest {
	return SHA256Digest("facets.compute-queue.operation-binding.v1", value.TypeID, fmt.Sprint(value.SchemaVersion), string(value.DefinitionID), fmt.Sprint(value.DefinitionRevision), string(value.DefinitionDigest), fmt.Sprint(value.DefinitionByteCount))
}

func OperationDefinitionDigest(exactBytes []byte) (Digest, error) {
	return ExactBytesDigest("facets.compute-queue.operation-definition-bytes.v1", exactBytes, MaximumDocumentBytes)
}

func (value OperationBinding) ValidateExactBytes(exactBytes []byte) error {
	if err := value.Validate(); err != nil {
		return err
	}
	digest, err := OperationDefinitionDigest(exactBytes)
	if err != nil || value.DefinitionByteCount != int64(len(exactBytes)) || value.DefinitionDigest != digest {
		return invalid("operationBinding.definitionBytes")
	}
	return nil
}

type RetryPolicy struct {
	BackoffMillisecondsByRetry []uint64    `json:"backoffMillisecondsByRetry"`
	RetryableErrorCodes        []ErrorCode `json:"retryableErrorCodes"`
}

func (value RetryPolicy) Validate() error {
	if value.BackoffMillisecondsByRetry == nil || value.RetryableErrorCodes == nil {
		return invalid("retryPolicy")
	}
	if len(value.BackoffMillisecondsByRetry) > MaximumRetries || len(value.RetryableErrorCodes) > len(errorCodes) {
		return invalid("retryPolicy")
	}
	if (len(value.BackoffMillisecondsByRetry) == 0) != (len(value.RetryableErrorCodes) == 0) {
		return invalid("retryPolicy.retryableErrorCodes")
	}
	for index, delay := range value.BackoffMillisecondsByRetry {
		if delay == 0 || delay > MaximumBackoffMilliseconds || (index > 0 && delay < value.BackoffMillisecondsByRetry[index-1]) {
			return invalid("retryPolicy.backoffMillisecondsByRetry")
		}
	}
	values := make([]string, len(value.RetryableErrorCodes))
	for index, code := range value.RetryableErrorCodes {
		if !code.valid() {
			return invalid("retryPolicy.retryableErrorCodes")
		}
		values[index] = string(code)
	}
	return requireUniqueSorted(values, "retryPolicy.retryableErrorCodes")
}

func (value RetryPolicy) MaximumAttempts() uint64 {
	return uint64(len(value.BackoffMillisecondsByRetry) + 1)
}

func (value RetryPolicy) Digest() Digest {
	components := []string{fmt.Sprint(len(value.BackoffMillisecondsByRetry))}
	for _, delay := range value.BackoffMillisecondsByRetry {
		components = append(components, fmt.Sprint(delay))
	}
	components = append(components, fmt.Sprint(len(value.RetryableErrorCodes)))
	for _, code := range value.RetryableErrorCodes {
		components = append(components, string(code))
	}
	return SHA256Digest("facets.compute-queue.retry-policy.v1", components...)
}

type PolicyBinding struct {
	PolicyID                PolicyID          `json:"policyID"`
	PolicyRevision          uint64            `json:"policyRevision"`
	PolicySchemaVersion     uint64            `json:"policySchemaVersion"`
	PolicyDocumentDigest    Digest            `json:"policyDocumentDigest"`
	PolicyDocumentByteCount int64             `json:"policyDocumentByteCount"`
	RetryPolicy             RetryPolicy       `json:"retryPolicy"`
	ScheduleExpiresAt       *Timestamp        `json:"scheduleExpiresAt,omitempty"`
	ManualClosePolicy       ManualClosePolicy `json:"manualClosePolicy"`
	AutoClosePolicy         AutoClosePolicy   `json:"autoClosePolicy"`
}

func (value PolicyBinding) Validate() error {
	if err := value.PolicyID.Validate(); err != nil {
		return err
	}
	if err := requirePositive(value.PolicyRevision, "policyBinding.policyRevision"); err != nil {
		return err
	}
	if err := requirePositive(value.PolicySchemaVersion, "policyBinding.policySchemaVersion"); err != nil {
		return err
	}
	if err := value.PolicyDocumentDigest.Validate(); err != nil {
		return err
	}
	if value.PolicyDocumentByteCount <= 0 || value.PolicyDocumentByteCount > MaximumDocumentBytes {
		return invalid("policyBinding.policyDocumentByteCount")
	}
	if err := value.RetryPolicy.Validate(); err != nil {
		return err
	}
	if value.ScheduleExpiresAt != nil {
		if err := value.ScheduleExpiresAt.Validate(); err != nil {
			return err
		}
	}
	if !value.ManualClosePolicy.valid() || !value.AutoClosePolicy.valid() {
		return invalid("policyBinding.closePolicy")
	}
	return nil
}

func (value PolicyBinding) Digest() Digest {
	return SHA256Digest("facets.compute-queue.policy-binding.v1", string(value.PolicyID), fmt.Sprint(value.PolicyRevision), fmt.Sprint(value.PolicySchemaVersion), string(value.PolicyDocumentDigest), fmt.Sprint(value.PolicyDocumentByteCount), string(value.RetryPolicy.Digest()), optionalTimestamp(value.ScheduleExpiresAt), string(value.ManualClosePolicy), string(value.AutoClosePolicy))
}

func PolicyDocumentDigest(exactBytes []byte) (Digest, error) {
	return ExactBytesDigest("facets.compute-queue.policy-document-bytes.v1", exactBytes, MaximumDocumentBytes)
}

func (value PolicyBinding) ValidateExactBytes(exactBytes []byte) error {
	if err := value.Validate(); err != nil {
		return err
	}
	digest, err := PolicyDocumentDigest(exactBytes)
	if err != nil || value.PolicyDocumentByteCount != int64(len(exactBytes)) || value.PolicyDocumentDigest != digest {
		return invalid("policyBinding.policyDocumentBytes")
	}
	return nil
}

type OccurrencePolicySnapshot struct {
	PolicyBinding         PolicyBinding `json:"policyBinding"`
	AdmissionNotBeforeAt  Timestamp     `json:"admissionNotBeforeAt"`
	ExecutionExpiresAt    Timestamp     `json:"executionExpiresAt"`
	InputRetentionUntil   Timestamp     `json:"inputRetentionUntil"`
	ResultRetentionUntil  Timestamp     `json:"resultRetentionUntil"`
	ReceiptRetentionUntil Timestamp     `json:"receiptRetentionUntil"`
}

func (value OccurrencePolicySnapshot) Validate() error {
	if err := value.PolicyBinding.Validate(); err != nil {
		return err
	}
	for _, timestamp := range []Timestamp{value.AdmissionNotBeforeAt, value.ExecutionExpiresAt, value.InputRetentionUntil, value.ResultRetentionUntil, value.ReceiptRetentionUntil} {
		if err := timestamp.Validate(); err != nil {
			return err
		}
	}
	if value.AdmissionNotBeforeAt >= value.ExecutionExpiresAt || value.InputRetentionUntil < value.ExecutionExpiresAt || value.ResultRetentionUntil < value.ExecutionExpiresAt || value.ReceiptRetentionUntil < value.InputRetentionUntil || value.ReceiptRetentionUntil < value.ResultRetentionUntil {
		return invalid("occurrencePolicySnapshot.timestamps")
	}
	if value.PolicyBinding.ScheduleExpiresAt != nil && value.ExecutionExpiresAt > *value.PolicyBinding.ScheduleExpiresAt {
		return invalid("occurrencePolicySnapshot.executionExpiresAt")
	}
	return nil
}

func (value OccurrencePolicySnapshot) Digest() Digest {
	return SHA256Digest("facets.compute-queue.occurrence-policy-snapshot.v1", string(value.PolicyBinding.Digest()), fmt.Sprint(value.AdmissionNotBeforeAt), fmt.Sprint(value.ExecutionExpiresAt), fmt.Sprint(value.InputRetentionUntil), fmt.Sprint(value.ResultRetentionUntil), fmt.Sprint(value.ReceiptRetentionUntil))
}

type LeaseBinding struct {
	ID               LeaseID   `json:"id"`
	Revision         uint64    `json:"revision"`
	IssuedAt         Timestamp `json:"issuedAt"`
	ExpiresAt        Timestamp `json:"expiresAt"`
	MaximumExpiresAt Timestamp `json:"maximumExpiresAt"`
}

func (value LeaseBinding) Validate() error {
	if err := value.ID.Validate(); err != nil {
		return err
	}
	if err := requirePositive(value.Revision, "leaseBinding.revision"); err != nil {
		return err
	}
	if value.IssuedAt < 0 || value.IssuedAt >= value.ExpiresAt || value.ExpiresAt > value.MaximumExpiresAt {
		return invalid("leaseBinding.timestamps")
	}
	return nil
}

func (value LeaseBinding) Digest() Digest {
	return SHA256Digest("facets.compute-queue.lease-binding.v1", string(value.ID), fmt.Sprint(value.Revision), fmt.Sprint(value.IssuedAt), fmt.Sprint(value.ExpiresAt), fmt.Sprint(value.MaximumExpiresAt))
}

func (value LeaseBinding) ValidateRenewal(previous LeaseBinding) error {
	if err := value.Validate(); err != nil {
		return err
	}
	if err := previous.Validate(); err != nil {
		return err
	}
	if value.ID != previous.ID || value.MaximumExpiresAt != previous.MaximumExpiresAt {
		return invalid("leaseBinding")
	}
	if previous.Revision == ^uint64(0) || value.Revision != previous.Revision+1 {
		return invalid("leaseBinding.revision")
	}
	if value.IssuedAt < previous.IssuedAt || value.IssuedAt > previous.ExpiresAt || value.ExpiresAt <= previous.ExpiresAt {
		return invalid("leaseBinding.renewal")
	}
	return nil
}

type TransitionReason struct {
	Code    ReasonCode `json:"code"`
	ErrorID *ErrorID   `json:"errorID,omitempty"`
}

func (value TransitionReason) Validate() error {
	if !value.Code.valid() || ((value.Code == "error") != (value.ErrorID != nil)) {
		return invalid("transitionReason.errorID")
	}
	if value.ErrorID != nil {
		return value.ErrorID.Validate()
	}
	return nil
}

func (value TransitionReason) Digest() Digest {
	errorID := ""
	if value.ErrorID != nil {
		errorID = string(*value.ErrorID)
	}
	return SHA256Digest("facets.compute-queue.transition-reason.v1", string(value.Code), errorID)
}

func containsEither(value string, first, second byte) bool {
	for _, current := range []byte(value) {
		if current == first || current == second {
			return true
		}
	}
	return false
}

func sortedErrorCodes(values []ErrorCode) bool {
	strings := make([]string, len(values))
	for index, value := range values {
		strings[index] = string(value)
	}
	return sort.StringsAreSorted(strings)
}
