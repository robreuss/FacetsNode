package computepool

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/google/uuid"
)

func TestSignedAdmissionChainBindsExactWorkerAndOffering(t *testing.T) {
	clientID := uuid.MustParse("81000000-0000-0000-0000-000000000001")
	poolID := uuid.MustParse("81000000-0000-0000-0000-000000000002")
	poolAuthorityID := uuid.MustParse("81000000-0000-0000-0000-000000000003")
	workerEnrollmentID := uuid.MustParse("81000000-0000-0000-0000-000000000004")
	workerCardID := uuid.MustParse("81000000-0000-0000-0000-000000000005")
	offeringID := uuid.MustParse("81000000-0000-0000-0000-000000000006")
	clientKey := testP256Key(1)
	poolKey := testP256Key(2)
	workerPublic, workerPrivate, _ := ed25519.GenerateKey(nil)
	workerFingerprint := sha256.Sum256(workerPublic)
	enrollment := WorkerEnrollment{
		Version: SchemaVersion, EnrollmentID: workerEnrollmentID, PoolID: poolID,
		WorkerID:                uuid.MustParse("81000000-0000-0000-0000-000000000007"),
		WorkerOwnerAuthorityID:  uuid.MustParse("81000000-0000-0000-0000-000000000008"),
		PublicSigningKeyEd25519: base64.RawURLEncoding.EncodeToString(workerPublic),
		SigningKeyFingerprint:   hex.EncodeToString(workerFingerprint[:]), ConsentRevision: 1,
		Enabled: true, Revision: 1, CreatedAtMilliseconds: 1, UpdatedAtMilliseconds: 1,
	}
	card := WorkerCard{
		Version: WorkerCardSchemaVersion, WorkerCardID: workerCardID, PoolID: poolID,
		WorkerEnrollmentID: workerEnrollmentID, WorkerOwnerAuthorityID: enrollment.WorkerOwnerAuthorityID,
		DisplayName: "Test Worker", RuntimeIdentifier: "test.runtime", BuildIdentifier: "test-build",
		Claims: testClaims(), Revision: 1, CreatedAtMilliseconds: 1, UpdatedAtMilliseconds: 1,
	}
	signedCard := SignedWorkerCard{Card: card, Signature: testSignEd25519(t, workerEnrollmentID, workerPrivate, card, workerCardDomain)}
	if err := signedCard.Validate(enrollment); err != nil {
		t.Fatalf("signed worker card: %v", err)
	}
	cardDigest, _ := card.Digest()
	authorization := InvocationAuthorization{
		Version: 1, AuthorizationID: uuid.MustParse("81000000-0000-0000-0000-000000000009"),
		RequestID: uuid.MustParse("81000000-0000-0000-0000-000000000010"), PoolID: poolID,
		WorkerCardID: workerCardID, WorkerCardRevision: 1, WorkerCardDigest: cardDigest,
		OfferingID: offeringID, OfferingRevision: 1, RequestDigest: testHex("1"), PayloadDigest: testHex("2"),
		DisclosurePlanDigest: testHex("3"), AuthorizedPrivacyClass: PrivacyPersonal,
		AuthorizedAtMilliseconds: 10, ExpiresAtMilliseconds: 100,
	}
	authorization.Signature = testSignES256(t, clientID, clientKey, authorization.signingPayload(), invocationAuthorizationDomain)
	if err := authorization.Validate(); err != nil {
		t.Fatalf("authorization: %v", err)
	}
	authorizationDigest, _ := authorization.Digest()
	admission := PoolAdmission{
		Version: 1, AdmissionID: uuid.MustParse("81000000-0000-0000-0000-000000000011"),
		JobID: uuid.MustParse("81000000-0000-0000-0000-000000000012"), PoolID: poolID,
		InvocationAuthorizationID: authorization.AuthorizationID, InvocationAuthorizationDigest: authorizationDigest,
		WorkerEnrollmentID: workerEnrollmentID, WorkerCardID: workerCardID, WorkerCardRevision: 1,
		WorkerCardDigest: cardDigest, OfferingID: offeringID, OfferingRevision: 1,
		ResourceCeiling:        ResourceCeiling{MaximumInputBytes: 1024, MaximumOutputBytes: 1024, MaximumMemoryBytes: 4096, MaximumWallTimeMilliseconds: 1000},
		BudgetCeiling:          BudgetCeiling{MaximumCostMinorUnits: 100, CurrencyIdentifier: "USD"},
		AdmittedAtMilliseconds: 20, ExpiresAtMilliseconds: 100, LeaseExpiresAtMilliseconds: 80,
	}
	admission.Signature = testSignES256(t, poolAuthorityID, poolKey, admission.signingPayload(), poolAdmissionDomain)
	if err := admission.Validate(); err != nil {
		t.Fatalf("admission: %v", err)
	}
	if err := admission.ValidateAuthorization(authorization); err != nil {
		t.Fatalf("bound authorization: %v", err)
	}
	admissionDigest, _ := admission.Digest()
	execution := WorkerExecutionReceipt{
		Version: 1, ReceiptID: uuid.MustParse("81000000-0000-0000-0000-000000000013"), JobID: admission.JobID,
		AdmissionID: admission.AdmissionID, AdmissionDigest: admissionDigest, WorkerEnrollmentID: workerEnrollmentID,
		Attempt: 1, RequestDigest: authorization.RequestDigest, ResultDigest: testHex("4"),
		StartedAtMilliseconds: 30, FinishedAtMilliseconds: 40,
	}
	execution.Signature = testSignEd25519(t, workerEnrollmentID, workerPrivate, execution.signingPayload(), workerExecutionDomain)
	if err := execution.ValidateAdmission(admission, authorization, enrollment); err != nil {
		t.Fatalf("execution admission: %v", err)
	}
	substituted := authorization
	substituted.OfferingRevision++
	substituted.Signature = testSignES256(t, clientID, clientKey, substituted.signingPayload(), invocationAuthorizationDomain)
	if err := admission.ValidateAuthorization(substituted); err == nil {
		t.Fatal("expected offering substitution to fail closed")
	}
}

func TestJobLifecycleRequiresAppliedResultAndAcceptsExactDuplicates(t *testing.T) {
	poolID := uuid.MustParse("82000000-0000-0000-0000-000000000001")
	authorityID := uuid.MustParse("82000000-0000-0000-0000-000000000002")
	jobID := uuid.MustParse("82000000-0000-0000-0000-000000000003")
	workerID := uuid.MustParse("82000000-0000-0000-0000-000000000004")
	deviceID := uuid.MustParse("82000000-0000-0000-0000-000000000005")
	authorityKey := testP256Key(3)
	deviceKey := testP256Key(4)
	_, workerKey, _ := ed25519.GenerateKey(nil)
	execution := WorkerExecutionReceipt{
		Version: 1, ReceiptID: uuid.MustParse("82000000-0000-0000-0000-000000000006"), JobID: jobID,
		AdmissionID: uuid.MustParse("82000000-0000-0000-0000-000000000007"), AdmissionDigest: testHex("4"),
		WorkerEnrollmentID: workerID, Attempt: 1, RequestDigest: testHex("5"), ResultDigest: testHex("6"),
		StartedAtMilliseconds: 50, FinishedAtMilliseconds: 60,
	}
	execution.Signature = testSignEd25519(t, workerID, workerKey, execution.signingPayload(), workerExecutionDomain)
	executionDigest, _ := execution.Digest()
	application := ResultApplicationReceipt{
		Version: 1, ReceiptID: uuid.MustParse("82000000-0000-0000-0000-000000000008"), JobID: jobID,
		ExecutionReceiptID: execution.ReceiptID, ExecutionReceiptDigest: executionDigest,
		ResultDigest: execution.ResultDigest, ApplicationDigest: testHex("7"), ApplyingDeviceID: deviceID,
		AppliedAtMilliseconds: 70,
	}
	application.Signature = testSignES256(t, deviceID, deviceKey, application.signingPayload(), resultApplicationDomain)
	applicationDigest, _ := application.Digest()
	states := []struct {
		state    JobState
		evidence *string
	}{
		{JobAuthorized, nil}, {JobAdmitted, nil}, {JobQueued, nil}, {JobLeased, nil}, {JobExecuting, nil},
		{JobResultStaged, &executionDigest}, {JobResultDelivered, &executionDigest}, {JobResultApplied, &applicationDigest}, {JobCompleted, &applicationDigest},
	}
	transitions := testTransitions(t, states, jobID, poolID, authorityID, authorityKey)
	fingerprint := transitions[0].Signature.SigningKeyFingerprint
	evaluation, err := EvaluateJobLifecycle(append(transitions, transitions[len(transitions)-1]), []WorkerExecutionReceipt{execution, execution}, []ResultApplicationReceipt{application, application}, poolID, authorityID, fingerprint)
	if err != nil {
		t.Fatalf("lifecycle: %v", err)
	}
	if evaluation.CurrentState != JobCompleted || evaluation.DuplicateTransitionCount != 1 || evaluation.DuplicateExecutionReceiptCount != 1 || evaluation.DuplicateApplicationReceiptCount != 1 {
		t.Fatalf("unexpected evaluation: %+v", evaluation)
	}
	prematureStates := append([]struct {
		state    JobState
		evidence *string
	}{}, states[:7]...)
	prematureStates = append(prematureStates, struct {
		state    JobState
		evidence *string
	}{JobCompleted, &applicationDigest})
	premature := testTransitions(t, prematureStates, uuid.MustParse("82000000-0000-0000-0000-000000000009"), poolID, authorityID, authorityKey)
	if _, err := EvaluateJobLifecycle(premature, nil, nil, poolID, authorityID, fingerprint); err == nil {
		t.Fatal("expected completion before result application to fail")
	}
}

func testP256Key(seed int64) *ecdsa.PrivateKey {
	d := big.NewInt(seed)
	x, y := elliptic.P256().ScalarBaseMult(d.Bytes())
	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, D: d}
}

func testSignES256(t *testing.T, signerID uuid.UUID, key *ecdsa.PrivateKey, payload any, domain string) ES256Signature {
	t.Helper()
	encoded, err := canonicalJSON(payload)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(append([]byte(domain), encoded...))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	raw := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	public := elliptic.Marshal(elliptic.P256(), key.X, key.Y)
	fingerprint := sha256.Sum256(public)
	return ES256Signature{Algorithm: "ES256", SignerID: signerID, PublicSigningKeyX963: base64.RawURLEncoding.EncodeToString(public), SigningKeyFingerprint: hex.EncodeToString(fingerprint[:]), Signature: base64.RawURLEncoding.EncodeToString(raw)}
}

func testSignEd25519(t *testing.T, signerID uuid.UUID, key ed25519.PrivateKey, payload any, domain string) Ed25519Signature {
	t.Helper()
	encoded, err := canonicalJSON(payload)
	if err != nil {
		t.Fatal(err)
	}
	public := key.Public().(ed25519.PublicKey)
	fingerprint := sha256.Sum256(public)
	return Ed25519Signature{Algorithm: "Ed25519", SignerID: signerID, PublicSigningKeyEd25519: base64.RawURLEncoding.EncodeToString(public), SigningKeyFingerprint: hex.EncodeToString(fingerprint[:]), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, append([]byte(domain), encoded...)))}
}

func testClaims() []AssuranceClaim {
	claims := make([]AssuranceClaim, 0, len(assuranceDimensions))
	for _, dimension := range assuranceDimensions {
		claims = append(claims, AssuranceClaim{DimensionIdentifier: dimension, Value: "declared", EvidenceKind: EvidenceWorkerOperatorDeclared, IssuerIdentifier: "test.operator", ValidFromMilliseconds: 1, Revision: 1})
	}
	return claims
}

func testTransitions(t *testing.T, states []struct {
	state    JobState
	evidence *string
}, jobID, poolID, authorityID uuid.UUID, key *ecdsa.PrivateKey) []PoolJobTransition {
	t.Helper()
	result := make([]PoolJobTransition, 0, len(states))
	var predecessor *string
	for index, item := range states {
		transition := PoolJobTransition{Version: 1, TransitionID: uuid.New(), JobID: jobID, PoolID: poolID, Sequence: uint64(index + 1), PredecessorDigest: predecessor, State: item.state, EvidenceDigest: item.evidence, OccurredAtMilliseconds: int64(index + 1)}
		transition.Signature = testSignES256(t, authorityID, key, transition.signingPayload(), poolJobTransitionDomain)
		result = append(result, transition)
		digest, _ := transition.Digest()
		predecessor = &digest
	}
	return result
}

func testHex(value string) string {
	result := ""
	for len(result) < 64 {
		result += value
	}
	return result[:64]
}
