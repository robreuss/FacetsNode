package computepool

import (
	"sort"

	"github.com/google/uuid"
)

type DisclosureFrictionCode string

const (
	FrictionRestrictedToPublic          DisclosureFrictionCode = "restricted_to_public"
	FrictionSensitiveExternalProcessing DisclosureFrictionCode = "sensitive_external_processing"
	FrictionFirstUseExternalProvider    DisclosureFrictionCode = "first_use_external_provider"
	FrictionMixedPrivacySelection       DisclosureFrictionCode = "mixed_privacy_selection"
	FrictionProviderOutsideConstraint   DisclosureFrictionCode = "provider_outside_constraint"
	FrictionRetentionOutsideConstraint  DisclosureFrictionCode = "retention_outside_constraint"
	FrictionToolAccessOutsideConstraint DisclosureFrictionCode = "tool_access_outside_constraint"
	FrictionSpaceCommitmentProhibits    DisclosureFrictionCode = "space_commitment_prohibits"
	FrictionSpacePolicyConsentRequired  DisclosureFrictionCode = "space_policy_consent_required"
	FrictionDataUseConsentRequired      DisclosureFrictionCode = "data_use_constraint_consent_required"
	FrictionWorkerTrustInsufficient     DisclosureFrictionCode = "worker_trust_insufficient"
	FrictionWorkerTrustReviewRequired   DisclosureFrictionCode = "worker_trust_review_required"
	FrictionOfferingAssuranceChanged    DisclosureFrictionCode = "offering_assurance_changed"
)

func (value DisclosureFrictionCode) Valid() bool {
	switch value {
	case FrictionRestrictedToPublic, FrictionSensitiveExternalProcessing, FrictionFirstUseExternalProvider,
		FrictionMixedPrivacySelection, FrictionProviderOutsideConstraint, FrictionRetentionOutsideConstraint,
		FrictionToolAccessOutsideConstraint, FrictionSpaceCommitmentProhibits, FrictionSpacePolicyConsentRequired,
		FrictionDataUseConsentRequired, FrictionWorkerTrustInsufficient, FrictionWorkerTrustReviewRequired,
		FrictionOfferingAssuranceChanged:
		return true
	}
	return false
}

type DisclosureDecision string

const (
	DecisionAllow           DisclosureDecision = "allow"
	DecisionConsentRequired DisclosureDecision = "consent_required"
	DecisionProhibit        DisclosureDecision = "prohibit"
)

func (value DisclosureDecision) Valid() bool {
	return value == DecisionAllow || value == DecisionConsentRequired || value == DecisionProhibit
}

type DisclosureObjectScope struct {
	ObjectID       string       `json:"objectID"`
	ContentDigest  string       `json:"contentDigest"`
	PrivacyClass   PrivacyClass `json:"privacyClass"`
	SelectedFields []string     `json:"selectedFields"`
}

func (scope DisclosureObjectScope) Validate() error {
	if !validIdentifier(scope.ObjectID) || !validSHA256Hex(scope.ContentDigest) || !scope.PrivacyClass.Valid() ||
		!validIdentifiers(scope.SelectedFields, true) {
		return ErrInvalid
	}
	return nil
}

type DisclosurePrivacyComposition struct {
	PrivacyClass PrivacyClass `json:"privacyClass"`
	ObjectCount  uint64       `json:"objectCount"`
}

type DisclosurePartition struct {
	PartitionID           uuid.UUID                `json:"partitionID"`
	ObjectIDs             []string                 `json:"objectIDs"`
	EffectivePrivacyClass PrivacyClass             `json:"effectivePrivacyClass"`
	Destination           DisclosureDestination    `json:"destination"`
	WorkerCardID          *uuid.UUID               `json:"workerCardID,omitempty"`
	WorkerCardRevision    *uint64                  `json:"workerCardRevision,omitempty"`
	WorkerCardDigest      *string                  `json:"workerCardDigest,omitempty"`
	OfferingID            *uuid.UUID               `json:"offeringID,omitempty"`
	OfferingRevision      *uint64                  `json:"offeringRevision,omitempty"`
	Decision              DisclosureDecision       `json:"decision"`
	FrictionCodes         []DisclosureFrictionCode `json:"frictionCodes"`
}

func (partition DisclosurePartition) Validate() error {
	isCompute := partition.Destination.Kind == DestinationComputeOffering
	if partition.PartitionID == uuid.Nil || !validIdentifiers(partition.ObjectIDs, false) ||
		!partition.EffectivePrivacyClass.Valid() || partition.Destination.Validate() != nil ||
		isCompute != (partition.WorkerCardID != nil) || isCompute != (partition.WorkerCardRevision != nil) ||
		isCompute != (partition.WorkerCardDigest != nil) || isCompute != (partition.OfferingID != nil) ||
		isCompute != (partition.OfferingRevision != nil) || partition.WorkerCardID != nil && *partition.WorkerCardID == uuid.Nil ||
		partition.OfferingID != nil && *partition.OfferingID == uuid.Nil || partition.WorkerCardRevision != nil && *partition.WorkerCardRevision == 0 ||
		partition.OfferingRevision != nil && *partition.OfferingRevision == 0 || partition.WorkerCardDigest != nil && !validSHA256Hex(*partition.WorkerCardDigest) ||
		!partition.Decision.Valid() || !validFrictionCodes(partition.FrictionCodes) ||
		(partition.Decision == DecisionAllow) != (len(partition.FrictionCodes) == 0) {
		return ErrInvalid
	}
	return nil
}

type DisclosurePlan struct {
	Version               int                            `json:"version"`
	PlanID                uuid.UUID                      `json:"planID"`
	Action                DisclosureAction               `json:"action"`
	SourceSpaceID         *uuid.UUID                     `json:"sourceSpaceID,omitempty"`
	SpacePolicyRevision   *uint64                        `json:"spacePolicyRevision,omitempty"`
	SpacePolicyDigest     *string                        `json:"spacePolicyDigest,omitempty"`
	RosterAudienceDigest  *string                        `json:"rosterAudienceDigest,omitempty"`
	Objects               []DisclosureObjectScope        `json:"objects"`
	PrivacyComposition    []DisclosurePrivacyComposition `json:"privacyComposition"`
	Destination           DisclosureDestination          `json:"destination"`
	Consequences          []string                       `json:"consequences"`
	FrictionCodes         []DisclosureFrictionCode       `json:"frictionCodes"`
	Partitions            []DisclosurePartition          `json:"partitions"`
	Decision              DisclosureDecision             `json:"decision"`
	CreatedAtMilliseconds int64                          `json:"createdAtMilliseconds"`
	ExpiresAtMilliseconds int64                          `json:"expiresAtMilliseconds"`
}

func (plan DisclosurePlan) Validate() error {
	spaceScoped := plan.SourceSpaceID != nil
	if plan.Version != 1 || plan.PlanID == uuid.Nil || !plan.Action.Valid() ||
		spaceScoped != (plan.SpacePolicyRevision != nil) || spaceScoped != (plan.SpacePolicyDigest != nil) ||
		spaceScoped != (plan.RosterAudienceDigest != nil) || plan.SourceSpaceID != nil && *plan.SourceSpaceID == uuid.Nil ||
		plan.SpacePolicyRevision != nil && *plan.SpacePolicyRevision == 0 || plan.SpacePolicyDigest != nil && !validSHA256Hex(*plan.SpacePolicyDigest) ||
		plan.RosterAudienceDigest != nil && !validSHA256Hex(*plan.RosterAudienceDigest) || len(plan.Objects) == 0 ||
		plan.Destination.Validate() != nil || !validIdentifiers(plan.Consequences, true) || !validFrictionCodes(plan.FrictionCodes) ||
		len(plan.Partitions) == 0 || !plan.Decision.Valid() || (plan.Decision == DecisionAllow) != (len(plan.FrictionCodes) == 0) ||
		plan.CreatedAtMilliseconds < 0 || plan.ExpiresAtMilliseconds <= plan.CreatedAtMilliseconds {
		return ErrInvalid
	}
	objectByID := make(map[string]DisclosureObjectScope, len(plan.Objects))
	previousObject := ""
	counts := map[PrivacyClass]uint64{}
	for _, object := range plan.Objects {
		if object.Validate() != nil || object.ObjectID <= previousObject {
			return ErrInvalid
		}
		previousObject = object.ObjectID
		objectByID[object.ObjectID] = object
		counts[object.PrivacyClass]++
	}
	expectedComposition := make([]DisclosurePrivacyComposition, 0, len(privacyClasses))
	for _, class := range privacyClasses {
		if counts[class] > 0 {
			expectedComposition = append(expectedComposition, DisclosurePrivacyComposition{PrivacyClass: class, ObjectCount: counts[class]})
		}
	}
	if len(expectedComposition) != len(plan.PrivacyComposition) {
		return ErrInvalid
	}
	for index := range expectedComposition {
		if expectedComposition[index] != plan.PrivacyComposition[index] {
			return ErrInvalid
		}
	}
	covered := make(map[string]bool, len(plan.Objects))
	previousPartition := ""
	aggregateDecision := DecisionAllow
	aggregateFriction := make(map[DisclosureFrictionCode]bool)
	for _, partition := range plan.Partitions {
		current := partition.PartitionID.String()
		if partition.Validate() != nil || current <= previousPartition || partition.Destination != plan.Destination {
			return ErrInvalid
		}
		previousPartition = current
		if partition.Decision == DecisionProhibit {
			aggregateDecision = DecisionProhibit
		} else if partition.Decision == DecisionConsentRequired && aggregateDecision == DecisionAllow {
			aggregateDecision = DecisionConsentRequired
		}
		for _, code := range partition.FrictionCodes {
			aggregateFriction[code] = true
		}
		for _, objectID := range partition.ObjectIDs {
			object, found := objectByID[objectID]
			if !found || covered[objectID] || !partition.EffectivePrivacyClass.Valid() ||
				privacyRank(partition.EffectivePrivacyClass) < privacyRank(object.PrivacyClass) {
				return ErrInvalid
			}
			covered[objectID] = true
		}
	}
	if len(covered) != len(plan.Objects) || aggregateDecision != plan.Decision || len(aggregateFriction) != len(plan.FrictionCodes) {
		return ErrInvalid
	}
	for _, code := range plan.FrictionCodes {
		if !aggregateFriction[code] {
			return ErrInvalid
		}
	}
	return nil
}

func (plan DisclosurePlan) Digest() (string, error) { return canonicalDigest(plan) }

func validFrictionCodes(values []DisclosureFrictionCode) bool {
	if len(values) > maximumIdentifierCount || !sort.SliceIsSorted(values, func(i, j int) bool { return values[i] < values[j] }) {
		return false
	}
	previous := DisclosureFrictionCode("")
	for _, value := range values {
		if !value.Valid() || value == previous {
			return false
		}
		previous = value
	}
	return true
}

func privacyRank(value PrivacyClass) int {
	for index, candidate := range privacyClasses {
		if candidate == value {
			return index
		}
	}
	return -1
}
