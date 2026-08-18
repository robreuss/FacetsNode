package devicesync_test

import (
	"encoding/base64"
	"testing"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/devicesync"
)

func TestAdmissionAuthorizationDigestIsScopedAndStrict(t *testing.T) {
	token := testToken(0x41)
	left := devicesync.AdmissionCredential{AdmissionID: uuid.New(), Token: token}
	right := devicesync.AdmissionCredential{AdmissionID: uuid.New(), Token: token}
	leftDigest, err := devicesync.AdmissionAuthorizationDigest(left)
	if err != nil {
		t.Fatal(err)
	}
	rightDigest, err := devicesync.AdmissionAuthorizationDigest(right)
	if err != nil {
		t.Fatal(err)
	}
	if leftDigest == rightDigest {
		t.Fatal("admission digest did not bind the admission scope")
	}
	if _, err := devicesync.AdmissionAuthorizationDigest(devicesync.AdmissionCredential{
		AdmissionID: left.AdmissionID, Token: base64.RawURLEncoding.EncodeToString(make([]byte, 31)),
	}); err == nil {
		t.Fatal("short admission token was accepted")
	}
}

func TestAccountAdmissionRejectsPartialClaimState(t *testing.T) {
	credential := devicesync.AdmissionCredential{AdmissionID: uuid.New(), Token: testToken(0x42)}
	digest, err := devicesync.AdmissionAuthorizationDigest(credential)
	if err != nil {
		t.Fatal(err)
	}
	claimedAt := int64(1_500)
	admission := devicesync.AccountAdmission{
		Version: devicesync.SchemaVersion, RetryID: uuid.New(), AdmissionID: credential.AdmissionID,
		AuthorizationDigest: digest, CreatedAtMilliseconds: 1_000,
		ExpiresAtMilliseconds: 1_000 + devicesync.MinimumAdmissionLifetimeMilliseconds,
		ClaimedAtMilliseconds: &claimedAt,
	}
	if err := admission.Validate(); !devicesync.ErrorHasCode(err, devicesync.CodeInvalidAdmission) {
		t.Fatalf("partial claim err=%v", err)
	}
}

func testToken(seed byte) string {
	bytes := make([]byte, 32)
	for index := range bytes {
		bytes[index] = seed + byte(index)
	}
	return base64.RawURLEncoding.EncodeToString(bytes)
}
