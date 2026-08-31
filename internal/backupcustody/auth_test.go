package backupcustody

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestBearerAuthorizationIsExactAndDomainSeparated(t *testing.T) {
	account := fixtureAdmissionReference()
	credential, err := NewAccountAdmissionCredential(account)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := credential.AuthorizationDigest()
	if err != nil || !credential.Authorizes(account, digest) {
		t.Fatalf("account credential digest=%q err=%v", digest, err)
	}
	wrong := account
	wrong.AdmissionID = uuid.New()
	if credential.Authorizes(wrong, digest) {
		t.Fatal("credential authorized a different admission")
	}

	target := fixtureTargetReference(account.AccountID)
	targetCredential, err := ParseTargetCredential(target, credential.TransportBearer())
	if err != nil {
		t.Fatal(err)
	}
	targetDigest, err := targetCredential.AuthorizationDigest()
	if err != nil || targetDigest == digest {
		t.Fatalf("target digest=%q account=%q err=%v", targetDigest, digest, err)
	}
	if targetCredential.Authorizes(target, digest) {
		t.Fatal("cross-domain account digest authorized a target")
	}
}

func TestBearerValidationRejectsNoncanonicalAndShortValues(t *testing.T) {
	credential := AccountAdmissionCredential{Reference: fixtureAdmissionReference(), bearer: strings.Repeat("a", 10)}
	if _, err := credential.AuthorizationDigest(); err == nil {
		t.Fatal("short bearer accepted")
	}
}

func TestCredentialsMechanicallyRedactBearer(t *testing.T) {
	credential, err := NewAccountAdmissionCredential(fixtureAdmissionReference())
	if err != nil {
		t.Fatal(err)
	}
	sentinel := credential.TransportBearer()
	for name, rendered := range map[string]string{
		"string": fmt.Sprint(credential), "goString": fmt.Sprintf("%#v", credential),
		"debug": fmt.Sprintf("%+v", credential),
	} {
		if strings.Contains(rendered, sentinel) {
			t.Fatalf("%s exposed bearer: %s", name, rendered)
		}
	}
	encoded, err := json.Marshal(credential)
	if err == nil || strings.Contains(string(encoded), sentinel) || strings.Contains(string(encoded), "bearer") {
		t.Fatalf("JSON=%s err=%v", encoded, err)
	}
}

func fixtureAdmissionReference() AccountAdmissionReference {
	return AccountAdmissionReference{
		AccountID: uuid.New(), AdmissionID: uuid.New(), ExpiresAtMilliseconds: 10_000,
		RequestNonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Version: Version,
	}
}

func fixtureTargetReference(accountID uuid.UUID) TargetCredentialReference {
	return TargetCredentialReference{
		AccountID: accountID, BackupSetID: uuid.New(), TargetID: uuid.New(), CredentialID: uuid.New(),
		Capabilities: []Capability{Publish, Read, RetentionProof}, ExpiresAtMilliseconds: 10_000,
		RequestNonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Version: Version,
	}
}
