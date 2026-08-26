package sharedspaces_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/sharedspaces"
)

func TestMemoryStoreClaimsSharedSpaceProvisioningAdmissionExactlyOnce(t *testing.T) {
	store := sharedspaces.NewMemoryStore(relay.NewMemoryStore())
	credential, admission := testProvisioningAdmission(t, 1_000)
	created, err := store.CreateProvisioningAdmission(
		context.Background(), admission, 1_000,
	)
	if err != nil || created.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("create Shared Space provisioning admission=%+v err=%v", created, err)
	}
	duplicate, err := store.CreateProvisioningAdmission(
		context.Background(), admission, 1_000,
	)
	if err != nil || duplicate.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("duplicate Shared Space provisioning admission=%+v err=%v", duplicate, err)
	}

	claim := sharedspaces.ProvisioningAdmissionClaim{
		Version: sharedspaces.SchemaVersion, SpaceID: uuid.New(),
		RequestDigest:         testDigest(0x21),
		ClaimedAtMilliseconds: 1_100,
	}
	claimed, err := store.ClaimProvisioningAdmission(
		context.Background(), credential, claim, 1_100,
	)
	if err != nil || claimed.Acceptance != relay.AcceptanceAccepted ||
		claimed.SpaceID != claim.SpaceID || claimed.RequestDigest != claim.RequestDigest {
		t.Fatalf("claim Shared Space provisioning admission=%+v err=%v", claimed, err)
	}
	issuedRetry, err := store.CreateProvisioningAdmission(
		context.Background(), admission, admission.CreatedAtMilliseconds,
	)
	if err != nil || issuedRetry.Acceptance != relay.AcceptanceDuplicate ||
		issuedRetry.Admission.ClaimedAtMilliseconds == nil {
		t.Fatalf("claimed admission issuance retry=%+v err=%v", issuedRetry, err)
	}
	retry, err := store.ClaimProvisioningAdmission(
		context.Background(), credential, claim, admission.ExpiresAtMilliseconds+1,
	)
	if err != nil || retry.Acceptance != relay.AcceptanceDuplicate ||
		retry.ClaimedAtMilliseconds != claim.ClaimedAtMilliseconds {
		t.Fatalf("expired exact admission retry=%+v err=%v", retry, err)
	}
	changed := claim
	changed.SpaceID = uuid.New()
	changed.ClaimedAtMilliseconds = admission.ExpiresAtMilliseconds + 1
	if _, err := store.ClaimProvisioningAdmission(
		context.Background(), credential, changed,
		admission.ExpiresAtMilliseconds+1,
	); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeProvisioningAdmissionClaimed) {
		t.Fatalf("changed admission retry err=%v", err)
	}
}

func TestMemoryStoreRejectsExpiredAndWrongSharedSpaceProvisioningAdmission(t *testing.T) {
	store := sharedspaces.NewMemoryStore(relay.NewMemoryStore())
	credential, admission := testProvisioningAdmission(t, 2_000)
	if _, err := store.CreateProvisioningAdmission(
		context.Background(), admission, 2_000,
	); err != nil {
		t.Fatal(err)
	}
	claim := sharedspaces.ProvisioningAdmissionClaim{
		Version: sharedspaces.SchemaVersion, SpaceID: uuid.New(),
		RequestDigest:         testDigest(0x31),
		ClaimedAtMilliseconds: admission.ExpiresAtMilliseconds,
	}
	if _, err := store.ClaimProvisioningAdmission(
		context.Background(), credential, claim,
		admission.ExpiresAtMilliseconds,
	); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeProvisioningAdmissionExpired) {
		t.Fatalf("expired admission err=%v", err)
	}
	claim.ClaimedAtMilliseconds = 2_100
	wrong := credential
	wrong.Token = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	if _, err := store.ClaimProvisioningAdmission(
		context.Background(), wrong, claim, 2_100,
	); !sharedspaces.ErrorHasCode(err, sharedspaces.CodeUnauthorized) {
		t.Fatalf("wrong admission bearer err=%v", err)
	}
}

func testProvisioningAdmission(
	t *testing.T,
	createdAtMilliseconds int64,
) (sharedspaces.ProvisioningAdmissionCredential, sharedspaces.ProvisioningAdmission) {
	t.Helper()
	token := make([]byte, 32)
	for index := range token {
		token[index] = byte(index + 1)
	}
	credential := sharedspaces.ProvisioningAdmissionCredential{
		AdmissionID: uuid.New(), Token: base64.RawURLEncoding.EncodeToString(token),
	}
	digest, err := sharedspaces.ProvisioningAdmissionAuthorizationDigest(credential)
	if err != nil {
		t.Fatal(err)
	}
	return credential, sharedspaces.ProvisioningAdmission{
		Version: sharedspaces.SchemaVersion, RetryID: uuid.New(),
		AdmissionID: credential.AdmissionID, AuthorizationDigest: digest,
		CreatedAtMilliseconds: createdAtMilliseconds,
		ExpiresAtMilliseconds: createdAtMilliseconds +
			sharedspaces.MinimumProvisioningAdmissionLifetimeMilliseconds,
	}
}

func testDigest(seed byte) string {
	digest := sha256.Sum256([]byte{seed})
	return hex.EncodeToString(digest[:])
}
