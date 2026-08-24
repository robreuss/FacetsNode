package computepool

import (
	"crypto/ecdsa"
	"testing"

	"github.com/google/uuid"
)

func TestPolicyWeakeningRequiresEveryActiveParticipant(t *testing.T) {
	policyID := uuid.MustParse("83000000-0000-0000-0000-000000000001")
	spaceID := uuid.MustParse("83000000-0000-0000-0000-000000000002")
	participants := []uuid.UUID{
		uuid.MustParse("83000000-0000-0000-0000-000000000003"),
		uuid.MustParse("83000000-0000-0000-0000-000000000004"),
	}
	secure := SecuritySecure
	current := testPolicy(policyID, spaceID, &secure, 1, nil, ControlProhibited)
	currentDigest, _ := current.Digest()
	proposed := testPolicy(policyID, spaceID, &secure, 2, &currentDigest, ControlConsentRequired)
	proposedDigest, _ := proposed.Digest()
	policyAuthorityID := uuid.MustParse("83000000-0000-0000-0000-000000000005")
	policyKey := testP256Key(12)
	signedCurrent := SignedSpaceProtectionPolicy{Policy: current, Signature: testSignES256(t, policyAuthorityID, policyKey, current, spacePolicyDomain)}
	signedProposed := SignedSpaceProtectionPolicy{Policy: proposed, Signature: testSignES256(t, policyAuthorityID, policyKey, proposed, spacePolicyDomain)}
	first := testAcknowledgement(t, participants[0], proposed, proposedDigest, testP256Key(10))
	second := testAcknowledgement(t, participants[1], proposed, proposedDigest, testP256Key(11))
	authorities := []PolicyParticipantSigningAuthority{
		{ParticipantID: participants[0], SigningKeyFingerprint: first.Signature.SigningKeyFingerprint},
		{ParticipantID: participants[1], SigningKeyFingerprint: second.Signature.SigningKeyFingerprint},
	}
	evaluation, err := EvaluatePolicyActivation(signedCurrent, signedProposed, policyAuthorityID, signedCurrent.Signature.SigningKeyFingerprint, authorities, []PolicyAcknowledgement{first})
	if err != nil {
		t.Fatalf("evaluate pending weakening: %v", err)
	}
	if evaluation.PendingPolicy == nil || evaluation.AuthoritativePolicy.Revision != 1 || len(evaluation.MissingParticipantIDs) != 1 || evaluation.MissingParticipantIDs[0] != participants[1] {
		t.Fatalf("unexpected pending evaluation: %+v", evaluation)
	}
	evaluation, err = EvaluatePolicyActivation(signedCurrent, signedProposed, policyAuthorityID, signedCurrent.Signature.SigningKeyFingerprint, authorities, []PolicyAcknowledgement{first, second})
	if err != nil || evaluation.PendingPolicy != nil || evaluation.AuthoritativePolicy.Revision != 2 {
		t.Fatalf("unanimous weakening did not activate: evaluation=%+v error=%v", evaluation, err)
	}
	forged := testAcknowledgement(t, participants[1], proposed, proposedDigest, testP256Key(13))
	evaluation, err = EvaluatePolicyActivation(signedCurrent, signedProposed, policyAuthorityID, signedCurrent.Signature.SigningKeyFingerprint, authorities, []PolicyAcknowledgement{first, forged})
	if err != nil || evaluation.PendingPolicy == nil || len(evaluation.MissingParticipantIDs) != 1 || evaluation.MissingParticipantIDs[0] != participants[1] {
		t.Fatalf("forged participant key counted toward unanimity: evaluation=%+v error=%v", evaluation, err)
	}
}

func testPolicy(policyID, spaceID uuid.UUID, profile *SpaceSecurityProfile, revision uint64, predecessor *string, external PolicyControl) SpaceProtectionPolicy {
	rules := make([]PrivacyClassRule, 0, len(privacyClasses))
	for _, class := range privacyClasses {
		rules = append(rules, PrivacyClassRule{PrivacyClass: class, PublicSharing: ControlProhibited, ExternalProcessing: external, ExportCopy: ControlProhibited})
	}
	return SpaceProtectionPolicy{
		Version: 1, PolicyID: policyID, SpaceID: spaceID, SharedSpaceSecurityProfile: profile,
		Revision: revision, PredecessorDigest: predecessor, Rules: rules,
		Commitments: SpaceProtectionCommitments{
			Sharing: ControlProhibited, Computation: ControlConsentRequired, ExternalAgents: ControlProhibited,
			LocalLLM: ControlAllowed, PrivateInfrastructureLLM: ControlAllowed, ExternalProviderLLM: external,
			ExportCopy: ControlProhibited, DisclosureOverrides: ControlProhibited,
			SharedBrowserHistoryEnabled: false, PrivateUserConfigurationsByDefault: true,
		},
		CreatedAtMilliseconds: int64(revision),
	}
}

func testAcknowledgement(t *testing.T, participantID uuid.UUID, policy SpaceProtectionPolicy, digest string, key *ecdsa.PrivateKey) PolicyAcknowledgement {
	t.Helper()
	acknowledgement := PolicyAcknowledgement{
		Version: 1, AcknowledgementID: uuid.New(), SpaceID: policy.SpaceID, PolicyID: policy.PolicyID,
		PolicyRevision: policy.Revision, PolicyDigest: digest, ParticipantID: participantID,
		AcknowledgedAtMilliseconds: policy.CreatedAtMilliseconds + 1,
	}
	acknowledgement.Signature = testSignES256(t, participantID, key, acknowledgement.signingPayload(), policyAcknowledgementDomain)
	return acknowledgement
}
