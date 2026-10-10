//go:build unix

package computequeue

import (
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestJobCustodyAdmissionKeyFileBuildsExactVerifier(t *testing.T) {
	privateKey, signer, _, header := jobCustodyP256Fixture(t)
	path := writeJobCustodyAdmissionKeyFile(t, JobCustodyAdmissionKeyFile{
		Keys: []JobCustodyAdmissionKeyFileEntry{{
			PublicKeyX963: base64.RawURLEncoding.EncodeToString(elliptic.Marshal(
				elliptic.P256(), privateKey.PublicKey.X, privateKey.PublicKey.Y,
			)),
			Signer: signer,
		}},
		Version: JobCustodyAdmissionKeyFileVersion,
	})
	verifier, err := LoadJobCustodyP256AdmissionVerifier(path)
	if err != nil {
		t.Fatal(err)
	}
	envelope := signJobCustodyAdmissionForTest(t, privateKey, signer, header)
	expectation, err := NewJobCustodyAdmissionExpectation(header, header.NotBeforeAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(envelope, expectation, signer); err != nil {
		t.Fatalf("file-backed verifier rejected its exact signer: %v", err)
	}
	wrongSigner := signer
	wrongSigner.SigningKeyRevision++
	if _, err := verifier.Verify(envelope, expectation, wrongSigner); err == nil {
		t.Fatal("file-backed verifier accepted a substituted signer")
	}
}

func TestJobCustodyAdmissionKeyFileRejectsMutableAmbiguousAndDuplicateTrust(t *testing.T) {
	privateKey, signer, _, _ := jobCustodyP256Fixture(t)
	publicKey := base64.RawURLEncoding.EncodeToString(elliptic.Marshal(
		elliptic.P256(), privateKey.PublicKey.X, privateKey.PublicKey.Y,
	))
	value := JobCustodyAdmissionKeyFile{
		Keys:    []JobCustodyAdmissionKeyFileEntry{{PublicKeyX963: publicKey, Signer: signer}},
		Version: JobCustodyAdmissionKeyFileVersion,
	}
	path := writeJobCustodyAdmissionKeyFile(t, value)
	if err := os.Chmod(path, 0o622); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadJobCustodyP256AdmissionVerifier(path); err == nil {
		t.Fatal("group-writable admission trust file accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append([]byte{' '}, append(canonical, '\n')...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadJobCustodyP256AdmissionVerifier(path); err == nil {
		t.Fatal("noncanonical admission trust file accepted")
	}
	value.Keys = append(value.Keys, JobCustodyAdmissionKeyFileEntry{
		PublicKeyX963: publicKey,
		Signer: ReceiptSignerBinding{
			SignerID: "another.source", SigningKeyID: "another.key",
			SigningKeyRevision: 1, SignatureProfileID: JobCustodyP256AdmissionSignatureProfile,
		},
	})
	path = writeJobCustodyAdmissionKeyFile(t, value)
	if _, err := LoadJobCustodyP256AdmissionVerifier(path); err == nil {
		t.Fatal("one public key accepted under multiple signer identities")
	}
	directory := t.TempDir()
	path = filepath.Join(directory, "admission-keys.json")
	if err := os.Symlink(filepath.Join(directory, "missing"), path); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadJobCustodyP256AdmissionVerifier(path); err == nil {
		t.Fatal("admission trust symlink accepted")
	}
}

func writeJobCustodyAdmissionKeyFile(t *testing.T, value JobCustodyAdmissionKeyFile) string {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, "admission-keys.json")
	canonical, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(canonical, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
