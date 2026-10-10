package computequeue

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"testing"
)

func TestJobCustodyP256AdmissionVerifierAcceptsExactTrustedRoute(t *testing.T) {
	privateKey, signer, key, header := jobCustodyP256Fixture(t)
	envelope := signJobCustodyAdmissionForTest(t, privateKey, signer, header)
	verifier, err := NewJobCustodyP256AdmissionVerifier(
		[]JobCustodyP256AdmissionVerificationKey{key},
	)
	if err != nil {
		t.Fatal(err)
	}
	expectation, err := NewJobCustodyAdmissionExpectation(header, header.NotBeforeAt)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := verifier.Verify(envelope, expectation, signer)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Header() != header || verified.ExpectedSigner() != signer {
		t.Fatal("verified admission lost its exact trust binding")
	}

	canonical, err := EncodeJobCustodyAdmissionCanonical(envelope)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := DecodeJobCustodyAdmissionCanonical(canonical)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(reopened, expectation, signer); err != nil {
		t.Fatalf("canonical round trip invalidated a signed admission: %v", err)
	}
}

func TestJobCustodyP256AdmissionVerifierRejectsSubstitution(t *testing.T) {
	privateKey, signer, key, header := jobCustodyP256Fixture(t)
	envelope := signJobCustodyAdmissionForTest(t, privateKey, signer, header)
	verifier, err := NewJobCustodyP256AdmissionVerifier(
		[]JobCustodyP256AdmissionVerificationKey{key},
	)
	if err != nil {
		t.Fatal(err)
	}
	expectation, err := NewJobCustodyAdmissionExpectation(header, header.NotBeforeAt)
	if err != nil {
		t.Fatal(err)
	}

	changed := header
	changed.RouteRecipientWorkerID = "44444444-4444-4444-8444-444444444444"
	changed.IdempotencyKey = changed.MakeIdempotencyKey()
	changedEnvelope := signJobCustodyAdmissionForTest(t, privateKey, signer, changed)
	if _, err := verifier.Verify(changedEnvelope, expectation, signer); err == nil {
		t.Fatal("accepted a signed envelope for a different expected route")
	}

	wrongSigner := signer
	wrongSigner.SigningKeyRevision++
	if _, err := verifier.Verify(envelope, expectation, wrongSigner); err == nil {
		t.Fatal("accepted a valid signature under a substituted signer binding")
	}

	otherPrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey, err := NewJobCustodyP256AdmissionVerificationKey(
		signer,
		elliptic.Marshal(elliptic.P256(), otherPrivate.PublicKey.X, otherPrivate.PublicKey.Y),
	)
	if err != nil {
		t.Fatal(err)
	}
	wrongVerifier, err := NewJobCustodyP256AdmissionVerifier(
		[]JobCustodyP256AdmissionVerificationKey{wrongKey},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongVerifier.Verify(envelope, expectation, signer); err == nil {
		t.Fatal("accepted a valid envelope under an unrelated pinned key")
	}
}

func TestJobCustodyP256AdmissionVerifierRejectsInvalidTrustConfiguration(t *testing.T) {
	_, signer, key, _ := jobCustodyP256Fixture(t)
	if _, err := NewJobCustodyP256AdmissionVerifier(
		[]JobCustodyP256AdmissionVerificationKey{key, key},
	); err == nil {
		t.Fatal("accepted a duplicate signer binding")
	}
	if _, err := NewJobCustodyP256AdmissionVerificationKey(signer, make([]byte, 65)); err == nil {
		t.Fatal("accepted an invalid P-256 public key")
	}
	wrongProfile := signer
	wrongProfile.SignatureProfileID = "another-profile"
	public := elliptic.Marshal(elliptic.P256(), key.publicKey.X, key.publicKey.Y)
	if _, err := NewJobCustodyP256AdmissionVerificationKey(wrongProfile, public); err == nil {
		t.Fatal("accepted an algorithm-substitution profile")
	}
}

func jobCustodyP256Fixture(t *testing.T) (
	*ecdsa.PrivateKey,
	ReceiptSignerBinding,
	JobCustodyP256AdmissionVerificationKey,
	JobCustodyAdmissionHeader,
) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := fixtureJobCustodySigner()
	signer.SignatureProfileID = JobCustodyP256AdmissionSignatureProfile
	key, err := NewJobCustodyP256AdmissionVerificationKey(
		signer,
		elliptic.Marshal(elliptic.P256(), privateKey.PublicKey.X, privateKey.PublicKey.Y),
	)
	if err != nil {
		t.Fatal(err)
	}
	header := fixtureJobCustodyEnvelope(t).Header
	return privateKey, signer, key, header
}

func signJobCustodyAdmissionForTest(
	t *testing.T,
	privateKey *ecdsa.PrivateKey,
	signer ReceiptSignerBinding,
	header JobCustodyAdmissionHeader,
) JobCustodySignedAdmissionEnvelope {
	t.Helper()
	payloadDigest, err := JobCustodyAdmissionSigningPayloadDigest(header, signer)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(payloadDigest))
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 64)
	fillP256Scalar(raw[:32], r)
	fillP256Scalar(raw[32:], s)
	envelope, err := NewJobCustodySignedAdmissionEnvelope(
		header,
		signer.SignatureProfileID,
		SignatureValue(base64.RawURLEncoding.EncodeToString(raw)),
	)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func fillP256Scalar(destination []byte, value *big.Int) {
	value.FillBytes(destination)
}
