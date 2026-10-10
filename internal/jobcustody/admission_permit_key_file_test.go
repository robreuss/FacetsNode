//go:build unix

package jobcustody

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
)

func TestAdmissionPermitKeyFileBuildsExactVerifier(t *testing.T) {
	fixture := newAdmissionPermitFixture(t)
	path := writeAdmissionPermitKeyFile(t, AdmissionPermitKeyFile{
		Authorities: []AdmissionPermitKeyFileEntry{{
			AuthorityID: fixture.authorityID,
			PublicKey: base64.RawURLEncoding.EncodeToString(
				fixture.privateKey.Public().(ed25519.PublicKey),
			),
		}},
		Version: AdmissionPermitKeyFileVersion,
	})
	verifier, err := LoadAdmissionPermitVerifier(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(
		fixture.permit,
		fixture.admission.envelopeBytes,
		fixture.issuedAt+1,
	); err != nil {
		t.Fatalf("file-backed permit verifier rejected exact authority: %v", err)
	}
}

func TestAdmissionPermitKeyFileRejectsMutableAmbiguousAndDuplicateTrust(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encodedPublicKey := base64.RawURLEncoding.EncodeToString(publicKey)
	value := AdmissionPermitKeyFile{
		Authorities: []AdmissionPermitKeyFileEntry{{
			AuthorityID: uuid.New(), PublicKey: encodedPublicKey,
		}},
		Version: AdmissionPermitKeyFileVersion,
	}
	path := writeAdmissionPermitKeyFile(t, value)
	if err := os.Chmod(path, 0o622); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAdmissionPermitVerifier(path); err == nil {
		t.Fatal("group-writable authority trust file accepted")
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
	if _, err := LoadAdmissionPermitVerifier(path); err == nil {
		t.Fatal("noncanonical authority trust file accepted")
	}

	value.Authorities = append(value.Authorities, AdmissionPermitKeyFileEntry{
		AuthorityID: uuid.New(), PublicKey: encodedPublicKey,
	})
	path = writeAdmissionPermitKeyFile(t, value)
	if _, err := LoadAdmissionPermitVerifier(path); err == nil {
		t.Fatal("one Box authority key accepted under multiple identities")
	}

	directory := t.TempDir()
	path = filepath.Join(directory, "admission-authorities.json")
	if err := os.Symlink(filepath.Join(directory, "missing"), path); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAdmissionPermitVerifier(path); err == nil {
		t.Fatal("authority trust symlink accepted")
	}
}

func writeAdmissionPermitKeyFile(t *testing.T, value AdmissionPermitKeyFile) string {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, "admission-authorities.json")
	canonical, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(canonical, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
