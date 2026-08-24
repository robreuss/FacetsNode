package computepool

import (
	"sort"

	"github.com/google/uuid"
)

type PolicyActivationRequirement string

const (
	PolicyActivationImmediate PolicyActivationRequirement = "immediate"
	PolicyActivationUnanimous PolicyActivationRequirement = "unanimous_active_participants"
)

type PolicyActivationEvaluation struct {
	Requirement           PolicyActivationRequirement
	AuthoritativePolicy   SpaceProtectionPolicy
	PendingPolicy         *SpaceProtectionPolicy
	MissingParticipantIDs []uuid.UUID
}

type PolicyParticipantSigningAuthority struct {
	ParticipantID         uuid.UUID
	SigningKeyFingerprint string
}

func EvaluatePolicyActivation(signedCurrent, signedProposed SignedSpaceProtectionPolicy, expectedPolicyAuthorityID uuid.UUID, expectedPolicySigningKeyFingerprint string, activeParticipants []PolicyParticipantSigningAuthority, acknowledgements []PolicyAcknowledgement) (PolicyActivationEvaluation, error) {
	current, proposed := signedCurrent.Policy, signedProposed.Policy
	participantIDs := make([]uuid.UUID, len(activeParticipants))
	authorityByParticipant := make(map[uuid.UUID]string, len(activeParticipants))
	for index, authority := range activeParticipants {
		participantIDs[index] = authority.ParticipantID
		if authority.ParticipantID == uuid.Nil || !validSHA256Hex(authority.SigningKeyFingerprint) {
			return PolicyActivationEvaluation{}, ErrInvalid
		}
		authorityByParticipant[authority.ParticipantID] = authority.SigningKeyFingerprint
	}
	if signedCurrent.Validate() != nil || signedProposed.Validate() != nil ||
		signedCurrent.Signature.SignerID != expectedPolicyAuthorityID || signedProposed.Signature.SignerID != expectedPolicyAuthorityID ||
		signedCurrent.Signature.SigningKeyFingerprint != expectedPolicySigningKeyFingerprint ||
		signedProposed.Signature.SigningKeyFingerprint != expectedPolicySigningKeyFingerprint ||
		current.PolicyID != proposed.PolicyID || current.SpaceID != proposed.SpaceID ||
		!equalOptionalSecurity(current.SharedSpaceSecurityProfile, proposed.SharedSpaceSecurityProfile) || proposed.Revision != current.Revision+1 ||
		proposed.PredecessorDigest == nil || len(participantIDs) == 0 || !sortedUniqueUUIDs(participantIDs) || len(authorityByParticipant) != len(activeParticipants) {
		return PolicyActivationEvaluation{}, ErrInvalid
	}
	currentDigest, err := current.Digest()
	if err != nil || *proposed.PredecessorDigest != currentDigest {
		return PolicyActivationEvaluation{}, ErrInvalid
	}
	if !policyIsWeakening(current, proposed) {
		return PolicyActivationEvaluation{Requirement: PolicyActivationImmediate, AuthoritativePolicy: proposed}, nil
	}
	proposedDigest, _ := proposed.Digest()
	accepted := map[uuid.UUID]bool{}
	for _, acknowledgement := range acknowledgements {
		if acknowledgement.Validate() == nil && acknowledgement.SpaceID == proposed.SpaceID &&
			acknowledgement.PolicyID == proposed.PolicyID && acknowledgement.PolicyRevision == proposed.Revision &&
			acknowledgement.PolicyDigest == proposedDigest &&
			authorityByParticipant[acknowledgement.ParticipantID] == acknowledgement.Signature.SigningKeyFingerprint {
			accepted[acknowledgement.ParticipantID] = true
		}
	}
	missing := make([]uuid.UUID, 0)
	for _, participantID := range participantIDs {
		if !accepted[participantID] {
			missing = append(missing, participantID)
		}
	}
	if len(missing) == 0 {
		return PolicyActivationEvaluation{Requirement: PolicyActivationUnanimous, AuthoritativePolicy: proposed}, nil
	}
	pending := proposed
	return PolicyActivationEvaluation{Requirement: PolicyActivationUnanimous, AuthoritativePolicy: current, PendingPolicy: &pending, MissingParticipantIDs: missing}, nil
}

func policyIsWeakening(current, proposed SpaceProtectionPolicy) bool {
	oldControls := commitmentControls(current.Commitments)
	newControls := commitmentControls(proposed.Commitments)
	for index := range oldControls {
		if controlPermissiveness(newControls[index]) > controlPermissiveness(oldControls[index]) {
			return true
		}
	}
	if !current.Commitments.SharedBrowserHistoryEnabled && proposed.Commitments.SharedBrowserHistoryEnabled ||
		current.Commitments.PrivateUserConfigurationsByDefault && !proposed.Commitments.PrivateUserConfigurationsByDefault {
		return true
	}
	for index := range current.Rules {
		oldRule, newRule := current.Rules[index], proposed.Rules[index]
		oldRuleControls := []PolicyControl{oldRule.PublicSharing, oldRule.ExternalProcessing, oldRule.ExportCopy}
		newRuleControls := []PolicyControl{newRule.PublicSharing, newRule.ExternalProcessing, newRule.ExportCopy}
		for controlIndex := range oldRuleControls {
			if controlPermissiveness(newRuleControls[controlIndex]) > controlPermissiveness(oldRuleControls[controlIndex]) {
				return true
			}
		}
		if !oldRule.RememberedConsentAllowed && newRule.RememberedConsentAllowed {
			return true
		}
	}
	return false
}

func commitmentControls(value SpaceProtectionCommitments) []PolicyControl {
	return []PolicyControl{value.Sharing, value.Computation, value.ExternalAgents, value.LocalLLM, value.PrivateInfrastructureLLM, value.ExternalProviderLLM, value.ExportCopy, value.DisclosureOverrides}
}

func controlPermissiveness(value PolicyControl) int {
	switch value {
	case ControlProhibited:
		return 0
	case ControlConsentRequired:
		return 1
	default:
		return 2
	}
}

func equalOptionalSecurity(left, right *SpaceSecurityProfile) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func sortedUniqueUUIDs(values []uuid.UUID) bool {
	strings := make([]string, len(values))
	for index, value := range values {
		if value == uuid.Nil {
			return false
		}
		strings[index] = value.String()
	}
	return sort.StringsAreSorted(strings) && len(values) == len(uniqueStrings(strings))
}

func uniqueStrings(values []string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}
