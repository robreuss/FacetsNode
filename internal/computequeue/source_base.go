package computequeue

import (
	"encoding/json"
	"fmt"
	"sort"
)

const (
	maximumItems                    = 250_000
	maximumAssignmentItems          = 50_000
	maximumTargetManifestChunkItems = 4_096
	maximumAssignments              = 512
	maximumReceipts                 = 16_384
	maximumTargetManifestChunkBytes = 1024 * 1024
)

type ExecutionIdentity struct {
	BackendFamilyID         string  `json:"backendFamilyID"`
	BackendFamilyRevision   string  `json:"backendFamilyRevision"`
	ModelID                 string  `json:"modelID"`
	ModelArtifactDigest     Digest  `json:"modelArtifactDigest"`
	AdapterID               string  `json:"adapterID"`
	AdapterRevision         string  `json:"adapterRevision"`
	DecisionContractDigest  Digest  `json:"decisionContractDigest"`
	ExecutionSettingsDigest Digest  `json:"executionSettingsDigest"`
	Quantization            *string `json:"quantization,omitempty"`
}

func (value ExecutionIdentity) Validate() error {
	for field, current := range map[string]string{"backendFamilyID": value.BackendFamilyID, "backendFamilyRevision": value.BackendFamilyRevision, "modelID": value.ModelID, "adapterID": value.AdapterID, "adapterRevision": value.AdapterRevision} {
		if err := requireNonempty(current, field); err != nil {
			return err
		}
	}
	for _, digest := range []Digest{value.ModelArtifactDigest, value.DecisionContractDigest, value.ExecutionSettingsDigest} {
		if err := digest.Validate(); err != nil {
			return err
		}
	}
	if value.Quantization != nil {
		return requireNonempty(*value.Quantization, "quantization")
	}
	return nil
}

func (value ExecutionIdentity) Digest() Digest {
	quantization := ""
	if value.Quantization != nil {
		quantization = *value.Quantization
	}
	return SHA256Digest("facets.compute-queue.execution-identity.v1", value.BackendFamilyID, value.BackendFamilyRevision, value.ModelID, string(value.ModelArtifactDigest), value.AdapterID, value.AdapterRevision, string(value.DecisionContractDigest), string(value.ExecutionSettingsDigest), quantization)
}

type WorkerBinding struct {
	WorkerID             WorkerID             `json:"workerID"`
	ExecutorID           string               `json:"executorID"`
	ExecutorRevision     uint64               `json:"executorRevision"`
	OfferingID           OfferingID           `json:"offeringID"`
	OfferingRevision     uint64               `json:"offeringRevision"`
	OfferingDigest       Digest               `json:"offeringDigest"`
	RecipientKeyID       string               `json:"recipientKeyID"`
	RecipientKeyRevision uint64               `json:"recipientKeyRevision"`
	ReceiptSigner        ReceiptSignerBinding `json:"receiptSigner"`
}

func (value WorkerBinding) Validate() error {
	if err := value.WorkerID.Validate(); err != nil {
		return err
	}
	if err := requireMachineToken(value.ExecutorID, "executorID"); err != nil {
		return err
	}
	if err := requirePositive(value.ExecutorRevision, "executorRevision"); err != nil {
		return err
	}
	if err := value.OfferingID.Validate(); err != nil {
		return err
	}
	if err := requirePositive(value.OfferingRevision, "offeringRevision"); err != nil {
		return err
	}
	if err := value.OfferingDigest.Validate(); err != nil {
		return err
	}
	if err := requireMachineToken(value.RecipientKeyID, "recipientKeyID"); err != nil {
		return err
	}
	if err := requirePositive(value.RecipientKeyRevision, "recipientKeyRevision"); err != nil {
		return err
	}
	return value.ReceiptSigner.Validate()
}

func (value WorkerBinding) digestComponents() []string {
	return []string{string(value.WorkerID), value.ExecutorID, fmt.Sprint(value.ExecutorRevision), string(value.OfferingID), fmt.Sprint(value.OfferingRevision), string(value.OfferingDigest), value.RecipientKeyID, fmt.Sprint(value.RecipientKeyRevision), string(value.ReceiptSigner.SignerID), string(value.ReceiptSigner.SigningKeyID), fmt.Sprint(value.ReceiptSigner.SigningKeyRevision), value.ReceiptSigner.SignatureProfileID}
}

type LocalExecutorBinding struct {
	ExecutorID       string               `json:"executorID"`
	ExecutorRevision uint64               `json:"executorRevision"`
	RuntimeDigest    Digest               `json:"runtimeDigest"`
	ReceiptSigner    ReceiptSignerBinding `json:"receiptSigner"`
}

func (value LocalExecutorBinding) Validate() error {
	if err := requireMachineToken(value.ExecutorID, "localExecutor.executorID"); err != nil {
		return err
	}
	if err := requirePositive(value.ExecutorRevision, "localExecutor.executorRevision"); err != nil {
		return err
	}
	if err := value.RuntimeDigest.Validate(); err != nil {
		return err
	}
	return value.ReceiptSigner.Validate()
}

func (value LocalExecutorBinding) digestComponents() []string {
	return []string{"sourceLocal", value.ExecutorID, fmt.Sprint(value.ExecutorRevision), string(value.RuntimeDigest), string(value.ReceiptSigner.SignerID), string(value.ReceiptSigner.SigningKeyID), fmt.Sprint(value.ReceiptSigner.SigningKeyRevision), value.ReceiptSigner.SignatureProfileID}
}

// ExecutorBinding uses the same tagged-union wire shape as Swift.
type ExecutorBinding struct {
	Kind        ExecutorKind          `json:"kind"`
	SourceLocal *LocalExecutorBinding `json:"sourceLocal,omitempty"`
	Worker      *WorkerBinding        `json:"worker,omitempty"`
}

func (value ExecutorBinding) Validate() error {
	if !value.Kind.valid() {
		return invalid("executor.kind")
	}
	switch value.Kind {
	case ExecutorSourceLocal:
		if value.SourceLocal == nil || value.Worker != nil {
			return invalid("executor")
		}
		return value.SourceLocal.Validate()
	case ExecutorWorker:
		if value.Worker == nil || value.SourceLocal != nil {
			return invalid("executor")
		}
		return value.Worker.Validate()
	}
	return invalid("executor")
}

func (value ExecutorBinding) stableID() string {
	if value.Kind == ExecutorWorker {
		return "worker:" + string(value.Worker.WorkerID)
	}
	return "sourceLocal:" + value.SourceLocal.ExecutorID
}

// equalExecutorBinding compares the complete immutable executor authority.
// stableID is intentionally only a compact digest component; it is not an
// authorization comparison because revisions, artifact/key bindings, and the
// receipt signer can change while the stable identifier remains the same.
func equalExecutorBinding(left, right ExecutorBinding) bool {
	if left.Kind != right.Kind {
		return false
	}
	switch left.Kind {
	case ExecutorSourceLocal:
		if left.SourceLocal == nil || right.SourceLocal == nil {
			return left.SourceLocal == nil && right.SourceLocal == nil
		}
		return *left.SourceLocal == *right.SourceLocal && left.Worker == nil && right.Worker == nil
	case ExecutorWorker:
		if left.Worker == nil || right.Worker == nil {
			return left.Worker == nil && right.Worker == nil
		}
		return *left.Worker == *right.Worker && left.SourceLocal == nil && right.SourceLocal == nil
	default:
		return false
	}
}

func (value ExecutorBinding) digestComponents() []string {
	switch value.Kind {
	case ExecutorWorker:
		if value.Worker == nil {
			return []string{"worker"}
		}
		return append([]string{"worker"}, value.Worker.digestComponents()...)
	case ExecutorSourceLocal:
		if value.SourceLocal == nil {
			return []string{"sourceLocal"}
		}
		return value.SourceLocal.digestComponents()
	default:
		return []string{string(value.Kind)}
	}
}

type FixedWorkerSet struct {
	Workers []WorkerBinding `json:"workers"`
	Digest  Digest          `json:"digest"`
}

func (value FixedWorkerSet) Validate() error {
	if len(value.Workers) == 0 || len(value.Workers) > maximumAssignments {
		return invalid("workers")
	}
	workerIDs, offeringIDs, components := make([]string, len(value.Workers)), make([]string, len(value.Workers)), []string{}
	for index, worker := range value.Workers {
		if err := worker.Validate(); err != nil {
			return err
		}
		workerIDs[index], offeringIDs[index] = string(worker.WorkerID), string(worker.OfferingID)
		components = append(components, worker.digestComponents()...)
	}
	if err := requireUniqueSorted(workerIDs, "workers.workerID"); err != nil {
		return err
	}
	seen := map[string]struct{}{}
	for _, id := range offeringIDs {
		if _, exists := seen[id]; exists {
			return invalid("workers.offeringID")
		}
		seen[id] = struct{}{}
	}
	if value.Digest != SHA256Digest("facets.compute-queue.fixed-worker-set.v1", components...) {
		return invalid("workers.digest")
	}
	return nil
}

type DestinationPolicy struct {
	Kind                    DestinationKind       `json:"kind"`
	FixedWorkerSet          *FixedWorkerSet       `json:"fixedWorkerSet,omitempty"`
	ComputePoolPolicyDigest *Digest               `json:"computePoolPolicyDigest,omitempty"`
	CustodyReceiptSigner    *ReceiptSignerBinding `json:"custodyReceiptSigner,omitempty"`
}

func (value DestinationPolicy) Validate() error {
	if !value.Kind.valid() {
		return invalid("destinationPolicy.kind")
	}
	if value.CustodyReceiptSigner != nil {
		if err := value.CustodyReceiptSigner.Validate(); err != nil {
			return err
		}
	}
	switch value.Kind {
	case DestinationDirectLocal:
		if value.FixedWorkerSet != nil || value.ComputePoolPolicyDigest != nil || value.CustodyReceiptSigner != nil {
			return invalid("destinationPolicy.directLocal")
		}
	case DestinationFixedWorkers:
		if value.FixedWorkerSet == nil || value.ComputePoolPolicyDigest != nil || value.CustodyReceiptSigner == nil {
			return invalid("destinationPolicy.fixedWorkers")
		}
		return value.FixedWorkerSet.Validate()
	case DestinationComputePool:
		if value.FixedWorkerSet != nil || value.ComputePoolPolicyDigest == nil || value.CustodyReceiptSigner == nil {
			return invalid("destinationPolicy.computePool")
		}
		return value.ComputePoolPolicyDigest.Validate()
	}
	return nil
}

func (value DestinationPolicy) Digest() Digest {
	fixed, pool, signer, key, revision, profile := "", "", "", "", "", ""
	if value.FixedWorkerSet != nil {
		fixed = string(value.FixedWorkerSet.Digest)
	}
	if value.ComputePoolPolicyDigest != nil {
		pool = string(*value.ComputePoolPolicyDigest)
	}
	if value.CustodyReceiptSigner != nil {
		signer = string(value.CustodyReceiptSigner.SignerID)
		key = string(value.CustodyReceiptSigner.SigningKeyID)
		revision = fmt.Sprint(value.CustodyReceiptSigner.SigningKeyRevision)
		profile = value.CustodyReceiptSigner.SignatureProfileID
	}
	return SHA256Digest("facets.compute-queue.destination-policy.v1", string(value.Kind), fixed, pool, signer, key, revision, profile)
}

type Eligibility struct {
	Kind                 EligibilityKind `json:"kind"`
	FirstEligibleAt      Timestamp       `json:"firstEligibleAt"`
	RecurrenceExpression *string         `json:"recurrenceExpression,omitempty"`
	RecurrenceProfileID  *string         `json:"recurrenceProfileID,omitempty"`
}

func (value Eligibility) Validate() error {
	if !value.Kind.valid() {
		return invalid("eligibility.kind")
	}
	if err := value.FirstEligibleAt.Validate(); err != nil {
		return err
	}
	if value.Kind == "immediate" {
		if value.RecurrenceExpression != nil || value.RecurrenceProfileID != nil {
			return invalid("eligibility.recurrenceExpression")
		}
	} else {
		if value.RecurrenceExpression == nil || value.RecurrenceProfileID == nil {
			return invalid("eligibility.recurrenceExpression")
		}
		if err := requireNonempty(*value.RecurrenceExpression, "eligibility.recurrenceExpression"); err != nil {
			return err
		}
		if err := requireMachineToken(*value.RecurrenceProfileID, "eligibility.recurrenceProfileID"); err != nil {
			return err
		}
	}
	return nil
}

func (value Eligibility) Digest() Digest {
	expression, profile := "", ""
	if value.RecurrenceExpression != nil {
		expression = *value.RecurrenceExpression
	}
	if value.RecurrenceProfileID != nil {
		profile = *value.RecurrenceProfileID
	}
	return SHA256Digest("facets.compute-queue.eligibility.v1", string(value.Kind), fmt.Sprint(value.FirstEligibleAt), expression, profile)
}

type TargetManifestChunk struct {
	ProtocolVersion    int              `json:"protocolVersion"`
	ScheduleID         ScheduleID       `json:"scheduleID"`
	TargetSetDigest    Digest           `json:"targetSetDigest"`
	ChunkIndex         int64            `json:"chunkIndex"`
	ChunkCount         int64            `json:"chunkCount"`
	FirstTargetOrdinal int64            `json:"firstTargetOrdinal"`
	TargetObjectIDs    []FacetsObjectID `json:"targetObjectIDs"`
	ChunkDigest        Digest           `json:"chunkDigest"`
}

func (value TargetManifestChunk) Validate() error {
	if err := requireProtocol(value.ProtocolVersion); err != nil {
		return err
	}
	if err := value.ScheduleID.Validate(); err != nil {
		return err
	}
	if err := value.TargetSetDigest.Validate(); err != nil {
		return err
	}
	if value.ChunkIndex < 0 || value.ChunkCount <= 0 || value.ChunkCount > maximumItems || value.ChunkIndex >= value.ChunkCount || value.FirstTargetOrdinal < 0 || value.FirstTargetOrdinal >= maximumItems || len(value.TargetObjectIDs) == 0 || len(value.TargetObjectIDs) > maximumTargetManifestChunkItems || int(value.FirstTargetOrdinal)+len(value.TargetObjectIDs) > maximumItems {
		return invalid("targetManifestChunk")
	}
	raw := make([]string, len(value.TargetObjectIDs))
	for index, object := range value.TargetObjectIDs {
		if err := object.Validate(); err != nil {
			return err
		}
		raw[index] = object.RawValue()
	}
	if err := requireUniqueSorted(raw, "targetManifestChunk.targetObjectIDs"); err != nil {
		return err
	}
	rawArray, err := json.Marshal(value.TargetObjectIDs)
	if err != nil {
		return invalid("targetManifestChunk.targetObjectIDs")
	}
	encoded, err := canonicalizeWithBounds(rawArray, sourceJSONBounds())
	if err != nil || len(encoded) > maximumTargetManifestChunkBytes {
		return invalid("targetManifestChunk.targetObjectIDs")
	}
	components := []string{string(value.ScheduleID), string(value.TargetSetDigest), fmt.Sprint(value.ChunkIndex), fmt.Sprint(value.ChunkCount), fmt.Sprint(value.FirstTargetOrdinal)}
	components = append(components, raw...)
	if value.ChunkDigest != SHA256Digest("facets.compute-queue.target-manifest-chunk.v1", components...) {
		return invalid("targetManifestChunk.chunkDigest")
	}
	return nil
}

type ScheduleRecord struct {
	ProtocolVersion     int                  `json:"protocolVersion"`
	ID                  ScheduleID           `json:"id"`
	Revision            uint64               `json:"revision"`
	State               ScheduleState        `json:"state"`
	CreatedAt           Timestamp            `json:"createdAt"`
	Eligibility         Eligibility          `json:"eligibility"`
	TargetCount         int64                `json:"targetCount"`
	TargetSetDigest     Digest               `json:"targetSetDigest"`
	OperationBinding    OperationBinding     `json:"operationBinding"`
	PolicyBinding       PolicyBinding        `json:"policyBinding"`
	ExecutionIdentity   ExecutionIdentity    `json:"executionIdentity"`
	DestinationPolicy   DestinationPolicy    `json:"destinationPolicy"`
	SourceReceiptSigner ReceiptSignerBinding `json:"sourceReceiptSigner"`
}

func (value ScheduleRecord) Validate() error {
	if err := requireProtocol(value.ProtocolVersion); err != nil {
		return err
	}
	if err := value.ID.Validate(); err != nil {
		return err
	}
	if err := requirePositive(value.Revision, "revision"); err != nil {
		return err
	}
	if !value.State.valid() {
		return invalid("schedule.state")
	}
	if err := value.CreatedAt.Validate(); err != nil {
		return err
	}
	if err := value.Eligibility.Validate(); err != nil {
		return err
	}
	if value.TargetCount <= 0 || value.TargetCount > maximumItems {
		return invalid("targetCount")
	}
	if err := value.TargetSetDigest.Validate(); err != nil {
		return err
	}
	if err := value.OperationBinding.Validate(); err != nil {
		return err
	}
	if err := value.PolicyBinding.Validate(); err != nil {
		return err
	}
	if value.PolicyBinding.ScheduleExpiresAt != nil && *value.PolicyBinding.ScheduleExpiresAt <= value.CreatedAt {
		return invalid("policyBinding.scheduleExpiresAt")
	}
	if err := value.ExecutionIdentity.Validate(); err != nil {
		return err
	}
	if err := value.DestinationPolicy.Validate(); err != nil {
		return err
	}
	if err := value.SourceReceiptSigner.Validate(); err != nil {
		return err
	}
	if value.DestinationPolicy.Kind == DestinationDirectLocal && value.TargetCount > maximumAssignmentItems {
		return invalid("directLocal.targetCount")
	}
	return nil
}

func (value ScheduleRecord) AuthorizationDigest() Digest {
	return scheduleAuthorizationDigest(value.ID, value.Eligibility.Digest(), value.TargetCount, value.TargetSetDigest, value.OperationBinding.Digest(), value.PolicyBinding.Digest(), value.ExecutionIdentity.Digest(), value.DestinationPolicy.Digest(), value.SourceReceiptSigner, value.DestinationPolicy.CustodyReceiptSigner)
}

// ValidateUpdateFrom validates a same-state schedule revision. Schedule
// semantics are immutable; pausing, resuming, cancellation, and expiry use the
// typed transition boundary below.
func (value ScheduleRecord) ValidateUpdateFrom(previous ScheduleRecord) error {
	if err := value.Validate(); err != nil {
		return err
	}
	if value.State != previous.State {
		return invalid("schedule.state")
	}
	if !value.sameImmutableDefinition(previous) {
		return invalid("schedule")
	}
	if previous.Revision == ^uint64(0) || value.Revision != previous.Revision+1 {
		return invalid("schedule.revision")
	}
	return nil
}

func (value ScheduleRecord) ValidateTransitionFrom(previous ScheduleRecord, transition ScheduleTransition, receipts []VerifiedReceipt, appliedEventIDs map[TransitionID]struct{}) error {
	if err := value.Validate(); err != nil {
		return err
	}
	if !value.sameImmutableDefinition(previous) || value.Revision != transition.ResultingRevision || value.State != transition.To {
		return invalid("schedule")
	}
	receiptIndex, err := newVerifiedReceiptIndex(receipts)
	if err != nil {
		return err
	}
	return transition.validateAgainst(previous.State, previous.Revision, LifecycleID(previous.ID), nil, appliedEventIDs, receiptIndex)
}

func (value ScheduleRecord) sameImmutableDefinition(other ScheduleRecord) bool {
	return value.ID == other.ID &&
		value.CreatedAt == other.CreatedAt &&
		value.Eligibility.Digest() == other.Eligibility.Digest() &&
		value.TargetCount == other.TargetCount &&
		value.TargetSetDigest == other.TargetSetDigest &&
		value.OperationBinding.Digest() == other.OperationBinding.Digest() &&
		value.PolicyBinding.Digest() == other.PolicyBinding.Digest() &&
		value.ExecutionIdentity.Digest() == other.ExecutionIdentity.Digest() &&
		value.DestinationPolicy.Digest() == other.DestinationPolicy.Digest() &&
		value.SourceReceiptSigner == other.SourceReceiptSigner
}

func scheduleAuthorizationDigest(scheduleID ScheduleID, eligibilityDigest Digest, targetCount int64, targetSetDigest, operationBindingDigest, policyBindingDigest, executionIdentityDigest, destinationPolicyDigest Digest, source ReceiptSignerBinding, custody *ReceiptSignerBinding) Digest {
	components := []string{string(scheduleID), string(eligibilityDigest), fmt.Sprint(targetCount), string(targetSetDigest), string(operationBindingDigest), string(policyBindingDigest), string(executionIdentityDigest), string(destinationPolicyDigest), string(source.SignerID), string(source.SigningKeyID), fmt.Sprint(source.SigningKeyRevision), source.SignatureProfileID}
	if custody == nil {
		components = append(components, "", "", "", "")
	} else {
		components = append(components, string(custody.SignerID), string(custody.SigningKeyID), fmt.Sprint(custody.SigningKeyRevision), custody.SignatureProfileID)
	}
	return SHA256Digest("facets.compute-queue.schedule-authorization.v1", components...)
}

func MakeTargetSetDigest(values []FacetsObjectID) Digest {
	components := make([]string, len(values))
	for index, value := range values {
		components[index] = value.RawValue()
	}
	return SHA256Digest("facets.compute-queue.target-set.v1", components...)
}

func (value ScheduleRecord) ValidateTargetManifest(chunks []TargetManifestChunk) error {
	if err := value.Validate(); err != nil {
		return err
	}
	if len(chunks) == 0 || len(chunks) > int(value.TargetCount) || len(chunks) > maximumItems {
		return invalid("targetManifestChunks")
	}
	ordered := append([]TargetManifestChunk(nil), chunks...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ChunkIndex < ordered[j].ChunkIndex })
	expectedOrdinal := int64(0)
	raw := []string{}
	for index, chunk := range ordered {
		if err := chunk.Validate(); err != nil {
			return err
		}
		if chunk.ChunkIndex != int64(index) || chunk.ChunkCount != int64(len(chunks)) || chunk.ScheduleID != value.ID || chunk.TargetSetDigest != value.TargetSetDigest || chunk.FirstTargetOrdinal != expectedOrdinal {
			return invalid("targetManifestChunks.identity")
		}
		for _, object := range chunk.TargetObjectIDs {
			raw = append(raw, object.RawValue())
			expectedOrdinal++
		}
	}
	if err := requireUniqueSorted(raw, "targetManifestChunks.targetObjectIDs"); err != nil {
		return err
	}
	if expectedOrdinal != value.TargetCount || SHA256Digest("facets.compute-queue.target-set.v1", raw...) != value.TargetSetDigest {
		return invalid("targetManifestChunks.coverage")
	}
	return nil
}
