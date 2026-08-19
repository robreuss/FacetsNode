package sharedspaces_test

import (
	"bytes"
	"testing"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/sharedspaces"
)

func TestComputeCapabilitySignsAndVerifiesWithoutMembershipStore(t *testing.T) {
	t.Parallel()
	signer, err := sharedspaces.NewComputeCapabilitySigner(bytes.Repeat([]byte{0x41}, 32), "https://spaces.example")
	if err != nil {
		t.Fatal(err)
	}
	claims := validComputeCapabilityClaims(signer.VerificationKey())
	capability, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	second, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	if capability.Signature != second.Signature {
		t.Fatal("Ed25519 signing must be deterministic for retry-safe claims")
	}
	verifier, err := sharedspaces.NewComputeCapabilityVerifier(signer.VerificationKey())
	if err != nil {
		t.Fatal(err)
	}
	verified, err := verifier.Verify(capability, sharedspaces.ComputeCapabilityRequirement{
		Issuer: claims.Issuer, SubjectParticipantID: claims.SubjectParticipantID,
		SpaceID: claims.SpaceID, PoolID: claims.PoolID, Operation: claims.Operation,
		KeyEpoch: claims.KeyEpoch,
		ResourceRequest: sharedspaces.ComputeResourceCeiling{
			MaximumInputBytes: 1_024, MaximumOutputBytes: 2_048,
			MaximumMemoryBytes: 512 << 20, MaximumWallTimeMilliseconds: 30_000,
		},
	}, claims.IssuedAtMilliseconds+1)
	if err != nil {
		t.Fatal(err)
	}
	if verified != claims {
		t.Fatalf("verified claims differ: %#v", verified)
	}
}

func TestComputeCapabilityRejectsTamperingExpiryAndScopeExpansion(t *testing.T) {
	t.Parallel()
	signer, err := sharedspaces.NewComputeCapabilitySigner(bytes.Repeat([]byte{0x42}, 32), "https://spaces.example")
	if err != nil {
		t.Fatal(err)
	}
	claims := validComputeCapabilityClaims(signer.VerificationKey())
	capability, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := sharedspaces.NewComputeCapabilityVerifier(signer.VerificationKey())
	if err != nil {
		t.Fatal(err)
	}

	tampered := capability
	tampered.Claims.PricingRevision++
	if _, err := verifier.Verify(tampered, sharedspaces.ComputeCapabilityRequirement{}, claims.IssuedAtMilliseconds+1); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeComputeCapabilityUnauthorized) {
		t.Fatalf("tampering error = %v", err)
	}
	if _, err := verifier.Verify(capability, sharedspaces.ComputeCapabilityRequirement{}, claims.ExpiresAtMilliseconds); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeComputeCapabilityExpired) {
		t.Fatalf("expiry error = %v", err)
	}
	if _, err := verifier.Verify(capability, sharedspaces.ComputeCapabilityRequirement{Operation: "vision.train"}, claims.IssuedAtMilliseconds+1); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeComputeCapabilityUnauthorized) {
		t.Fatalf("operation error = %v", err)
	}
	if _, err := verifier.Verify(capability, sharedspaces.ComputeCapabilityRequirement{
		ResourceRequest: sharedspaces.ComputeResourceCeiling{
			MaximumInputBytes:  claims.ResourceCeiling.MaximumInputBytes + 1,
			MaximumOutputBytes: 1, MaximumMemoryBytes: 1,
			MaximumWallTimeMilliseconds: 1,
		},
	}, claims.IssuedAtMilliseconds+1); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeComputeCapabilityUnauthorized) {
		t.Fatalf("resource expansion error = %v", err)
	}
}

func TestComputeCapabilityRejectsUnknownSigningKey(t *testing.T) {
	t.Parallel()
	signer, err := sharedspaces.NewComputeCapabilitySigner(bytes.Repeat([]byte{0x43}, 32), "https://spaces.example")
	if err != nil {
		t.Fatal(err)
	}
	other, err := sharedspaces.NewComputeCapabilitySigner(bytes.Repeat([]byte{0x44}, 32), "https://spaces.example")
	if err != nil {
		t.Fatal(err)
	}
	capability, err := signer.Sign(validComputeCapabilityClaims(signer.VerificationKey()))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := sharedspaces.NewComputeCapabilityVerifier(other.VerificationKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(capability, sharedspaces.ComputeCapabilityRequirement{}, capability.Claims.IssuedAtMilliseconds+1); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeComputeCapabilityUnauthorized) {
		t.Fatalf("unknown key error = %v", err)
	}
}

func TestComputeCapabilityAuthorizationCapturesCurrentPolicyAndIssuesClaims(t *testing.T) {
	t.Parallel()
	spaceID := uuid.New()
	poolID := uuid.New()
	participantID := uuid.New()
	request := validComputeCapabilityRequest(spaceID, poolID)
	pool, binding := validComputeCapabilityPolicy(spaceID, poolID)
	authorization, err := sharedspaces.AuthorizeComputeCapability(
		request, participantID, request.ExpectedKeyEpoch, pool, binding,
		request.IssuedAtMilliseconds,
	)
	if err != nil {
		t.Fatal(err)
	}
	if authorization.CapabilityID != request.RetryID ||
		authorization.SubjectParticipantID != participantID ||
		authorization.ResourceCeiling != request.ResourceRequest ||
		authorization.PricingRevision != binding.PricingRevision ||
		authorization.BindingRevision != binding.Revision {
		t.Fatalf("authorization did not capture current policy: %#v", authorization)
	}
	signer, err := sharedspaces.NewComputeCapabilitySigner(
		bytes.Repeat([]byte{0x45}, 32), "https://spaces.example",
	)
	if err != nil {
		t.Fatal(err)
	}
	capability, err := signer.Issue(authorization)
	if err != nil {
		t.Fatal(err)
	}
	if capability.Claims.CapabilityID != request.RetryID ||
		capability.Claims.KeyID != signer.VerificationKey().KeyID ||
		capability.Claims.SubjectParticipantID != participantID {
		t.Fatalf("issued claims differ from authorization: %#v", capability.Claims)
	}
}

func TestComputeCapabilityAuthorizationRejectsStaleOrExpandedPolicy(t *testing.T) {
	t.Parallel()
	spaceID := uuid.New()
	poolID := uuid.New()
	participantID := uuid.New()
	request := validComputeCapabilityRequest(spaceID, poolID)
	pool, binding := validComputeCapabilityPolicy(spaceID, poolID)

	stale := request
	stale.ExpectedBindingRevision++
	if _, err := sharedspaces.AuthorizeComputeCapability(
		stale, participantID, request.ExpectedKeyEpoch, pool, binding,
		request.IssuedAtMilliseconds,
	); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeComputeCapabilityUnauthorized) {
		t.Fatalf("stale binding error = %v", err)
	}
	expanded := request
	expanded.ResourceRequest.MaximumInputBytes = binding.ResourceCeiling.MaximumInputBytes + 1
	if _, err := sharedspaces.AuthorizeComputeCapability(
		expanded, participantID, request.ExpectedKeyEpoch, pool, binding,
		request.IssuedAtMilliseconds,
	); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeComputeCapabilityUnauthorized) {
		t.Fatalf("expanded resource error = %v", err)
	}
	disabled := pool
	disabled.Enabled = false
	if _, err := sharedspaces.AuthorizeComputeCapability(
		request, participantID, request.ExpectedKeyEpoch, disabled, binding,
		request.IssuedAtMilliseconds,
	); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeComputeCapabilityUnauthorized) {
		t.Fatalf("disabled pool error = %v", err)
	}
}

func validComputeCapabilityClaims(key sharedspaces.ComputeCapabilityVerificationKey) sharedspaces.ComputeCapabilityClaims {
	return sharedspaces.ComputeCapabilityClaims{
		Version: sharedspaces.SchemaVersion, CapabilityID: uuid.New(),
		Issuer: key.Issuer, KeyID: key.KeyID,
		SubjectParticipantID: uuid.New(), SpaceID: uuid.New(), PoolID: uuid.New(),
		Operation: "llm.batch", ResourceCeiling: sharedspaces.ComputeResourceCeiling{
			MaximumInputBytes: 1 << 20, MaximumOutputBytes: 2 << 20,
			MaximumMemoryBytes: 1 << 30, MaximumWallTimeMilliseconds: 60_000,
		},
		PricingRevision: 3, DataSensitivityContract: "space-content-v1",
		ProcessingContract: "participant-device-v1", BindingRevision: 4,
		KeyEpoch: 2, IssuedAtMilliseconds: 5_000, ExpiresAtMilliseconds: 65_000,
	}
}

func validComputeCapabilityRequest(spaceID, poolID uuid.UUID) sharedspaces.ComputeCapabilityRequest {
	return sharedspaces.ComputeCapabilityRequest{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(), SpaceID: spaceID,
		PoolID: poolID, Operation: "llm.batch",
		ResourceRequest: sharedspaces.ComputeResourceCeiling{
			MaximumInputBytes: 1 << 20, MaximumOutputBytes: 2 << 20,
			MaximumMemoryBytes: 1 << 30, MaximumWallTimeMilliseconds: 60_000,
		},
		ExpectedBindingRevision: 4, ExpectedKeyEpoch: 2,
		IssuedAtMilliseconds: 5_000, ExpiresAtMilliseconds: 65_000,
	}
}

func validComputeCapabilityPolicy(spaceID, poolID uuid.UUID) (
	sharedspaces.ComputePool,
	sharedspaces.SpaceComputeBinding,
) {
	pool := sharedspaces.ComputePool{
		Version: sharedspaces.SchemaVersion, SpaceID: spaceID, PoolID: poolID,
		DisplayName: "Overnight devices", Enabled: true, Revision: 4,
		CreatedAtMilliseconds: 1_000, UpdatedAtMilliseconds: 4_000,
	}
	binding := sharedspaces.SpaceComputeBinding{
		Version: sharedspaces.SchemaVersion, SpaceID: spaceID, PoolID: poolID,
		AllowedOperations: []string{"llm.batch", "vision.embed"},
		ResourceCeiling: sharedspaces.ComputeResourceCeiling{
			MaximumInputBytes: 4 << 20, MaximumOutputBytes: 8 << 20,
			MaximumMemoryBytes: 4 << 30, MaximumWallTimeMilliseconds: 300_000,
		},
		PricingRevision: 3, DataSensitivityContract: "space-content-v1",
		ProcessingContract: "participant-device-v1", Revision: 4,
		CreatedAtMilliseconds: 1_000, UpdatedAtMilliseconds: 4_000,
	}
	return pool, binding
}
