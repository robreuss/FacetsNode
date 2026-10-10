package computequeue

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/big"
)

const JobCustodyP256AdmissionSignatureProfile = "facets.p256-sha256.utf8-digest-v1"

var ErrJobCustodyAdmissionAuthentication = errors.New("job custody admission authentication failed")

// JobCustodyP256AdmissionVerificationKey is trusted enrollment state. Neither
// the signer binding nor public key is learned from the untrusted envelope.
type JobCustodyP256AdmissionVerificationKey struct {
	signer    ReceiptSignerBinding
	publicKey ecdsa.PublicKey
}

func NewJobCustodyP256AdmissionVerificationKey(
	signer ReceiptSignerBinding,
	publicKeyX963 []byte,
) (JobCustodyP256AdmissionVerificationKey, error) {
	if err := signer.Validate(); err != nil ||
		signer.SignatureProfileID != JobCustodyP256AdmissionSignatureProfile ||
		len(publicKeyX963) != 65 {
		return JobCustodyP256AdmissionVerificationKey{}, ErrJobCustodyAdmissionAuthentication
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), publicKeyX963)
	if x == nil || y == nil || !elliptic.P256().IsOnCurve(x, y) {
		return JobCustodyP256AdmissionVerificationKey{}, ErrJobCustodyAdmissionAuthentication
	}
	return JobCustodyP256AdmissionVerificationKey{
		signer: signer,
		publicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).Set(x),
			Y:     new(big.Int).Set(y),
		},
	}, nil
}

func (value JobCustodyP256AdmissionVerificationKey) Signer() ReceiptSignerBinding {
	return value.signer
}

// JobCustodyP256AdmissionVerifier indexes immutable trusted bindings. An
// envelope cannot select a signer, key revision, or algorithm profile.
type JobCustodyP256AdmissionVerifier struct {
	keys map[ReceiptSignerBinding]JobCustodyP256AdmissionVerificationKey
}

func NewJobCustodyP256AdmissionVerifier(
	trustedKeys []JobCustodyP256AdmissionVerificationKey,
) (*JobCustodyP256AdmissionVerifier, error) {
	keys := make(map[ReceiptSignerBinding]JobCustodyP256AdmissionVerificationKey, len(trustedKeys))
	for _, key := range trustedKeys {
		if _, exists := keys[key.signer]; exists ||
			key.signer.SignatureProfileID != JobCustodyP256AdmissionSignatureProfile ||
			key.publicKey.Curve != elliptic.P256() || key.publicKey.X == nil || key.publicKey.Y == nil ||
			!elliptic.P256().IsOnCurve(key.publicKey.X, key.publicKey.Y) {
			return nil, ErrJobCustodyAdmissionAuthentication
		}
		keys[key.signer] = key
	}
	return &JobCustodyP256AdmissionVerifier{keys: keys}, nil
}

func (verifier *JobCustodyP256AdmissionVerifier) Verify(
	envelope JobCustodySignedAdmissionEnvelope,
	expectation JobCustodyAdmissionExpectation,
	expectedSigner ReceiptSignerBinding,
) (VerifiedJobCustodyAdmission, error) {
	if verifier == nil {
		return VerifiedJobCustodyAdmission{}, ErrJobCustodyAdmissionAuthentication
	}
	key, exists := verifier.keys[expectedSigner]
	if !exists {
		return VerifiedJobCustodyAdmission{}, ErrJobCustodyAdmissionAuthentication
	}
	return acceptVerifiedJobCustodyAdmission(
		envelope,
		expectation,
		expectedSigner,
		jobCustodyP256SignatureVerifier{key: key},
	)
}

type jobCustodyP256SignatureVerifier struct {
	key JobCustodyP256AdmissionVerificationKey
}

func (verifier jobCustodyP256SignatureVerifier) VerifySignature(
	signature SignatureValue,
	payloadDigest Digest,
	expectedSigner ReceiptSignerBinding,
) error {
	if expectedSigner != verifier.key.signer ||
		expectedSigner.SignatureProfileID != JobCustodyP256AdmissionSignatureProfile {
		return ErrJobCustodyAdmissionAuthentication
	}
	raw, err := base64.RawURLEncoding.DecodeString(string(signature))
	if err != nil || len(raw) != 64 {
		return ErrJobCustodyAdmissionAuthentication
	}
	digest := sha256.Sum256([]byte(payloadDigest))
	r := new(big.Int).SetBytes(raw[:32])
	s := new(big.Int).SetBytes(raw[32:])
	if r.Sign() <= 0 || s.Sign() <= 0 ||
		!ecdsa.Verify(&verifier.key.publicKey, digest[:], r, s) {
		return ErrJobCustodyAdmissionAuthentication
	}
	return nil
}
