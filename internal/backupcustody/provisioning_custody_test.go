package backupcustody

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

func TestPreparedAccountJournalIsProtectedExactAndContainsNoBearer(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(parent, "claims")
	journal, err := OpenPreparedAccountJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	credential, err := NewAccountAdmissionCredential(fixtureAdmissionReference())
	if err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(directory); err != nil || len(entries) != 1 || entries[0].Name() != ".process.lock" {
		t.Fatalf("unexpected initial entries=%v err=%v", entries, err)
	}
	if strings.Contains(string(canonicalJSONUnchecked(PreparedAccountClaim{AccountID: uuid.New()})), credential.TransportBearer()) {
		t.Fatal("prepared claim encoding exposed bearer")
	}
	claim := fixturePreparedAccountClaim(t, credential, uuid.New(), 1_100)
	created, err := journal.Prepare(claim)
	if err != nil || created {
		t.Fatalf("prepare created=%t err=%v", created, err)
	}
	replayed, err := journal.Prepare(claim)
	if err != nil || !replayed {
		t.Fatalf("replay exact=%t err=%v", replayed, err)
	}
	claimPath := filepath.Join(directory, claim.AccountID.String()+".prepared.json")
	info, err := os.Lstat(claimPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("prepared claim mode=%v err=%v", info, err)
	}
	stored, found, err := journal.Load(claim.AccountID)
	if err != nil || !found || !reflect.DeepEqual(stored, claim) {
		t.Fatalf("stored=%+v found=%t err=%v", stored, found, err)
	}
	contents, err := os.ReadFile(claimPath)
	if err != nil || strings.Contains(string(contents), credential.TransportBearer()) {
		t.Fatal("durable preparation exposed bearer")
	}
}

func TestProvisioningCustodyReplaysCommittedClaimAndReconstructsStandbyJournal(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenPreparedAccountJournal(filepath.Join(parent, "claims"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	reference := fixtureAdmissionReference()
	reference.ExpiresAtMilliseconds = 1_500
	credential, err := NewAccountAdmissionCredential(reference)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, signer := fixtureBackupEnrollmentAndSigner(t, reference.AccountID)
	clock := &mutableBackupClock{now: time.UnixMilli(1_100)}
	store := &provisioningCoordinatorStore{}
	custody := ProvisioningCustody{Store: store, Journal: journal, Registry: serviceauthority.NewBindingRegistry(), Signer: signer, Clock: clock}
	claimID := uuid.New()
	anchor := newTestControlSigner(t, reference.AccountID, 1, 81).anchor(t)
	if err := custody.ProvisionAccount(context.Background(), credential, claimID, enrollment, anchor); err != nil {
		t.Fatal(err)
	}
	if store.state != AccountStateWritable || store.prepareCount != 1 || store.activateCount != 1 {
		t.Fatalf("initial state=%q prepare=%d activate=%d", store.state, store.prepareCount, store.activateCount)
	}
	if _, found, err := journal.Load(reference.AccountID); err != nil || found {
		t.Fatalf("committed journal cleanup found=%t err=%v", found, err)
	}
	clock.now = time.UnixMilli(5_000)
	if err := custody.ProvisionAccount(context.Background(), credential, claimID, enrollment, anchor); err != nil {
		t.Fatalf("expired committed replay failed: %v", err)
	}
	if store.prepareCount != 1 || store.activateCount != 2 {
		t.Fatalf("replay prepared a new account: prepare=%d activate=%d", store.prepareCount, store.activateCount)
	}

	store.state = AccountStateStandby
	store.failActivation = true
	clock.now = time.UnixMilli(1_200)
	if err := custody.ProvisionAccount(context.Background(), credential, claimID, enrollment, anchor); err == nil {
		t.Fatal("injected standby activation failure was ignored")
	}
	claim := PreparedAccountClaim{Version: preparedAccountClaimVersion, AccountID: store.record.AccountID,
		Admission: store.record.Admission, AdmissionAuthorizationDigest: store.record.AdmissionAuthorizationDigest,
		ClaimID: store.record.ClaimID, ClaimedAtMilliseconds: store.record.CreatedAtMilliseconds,
		InitialEnrollment: enrollment, InitialControlAnchor: anchor}
	if err := journal.RemoveExact(claim); err != nil {
		t.Fatal(err)
	}
	store.failActivation = false
	clock.now = time.UnixMilli(5_000)
	if err := custody.ProvisionAccount(context.Background(), credential, claimID, enrollment, anchor); err != nil {
		t.Fatalf("standby reconstruction failed: %v", err)
	}
	if store.state != AccountStateWritable {
		t.Fatalf("standby remained %q", store.state)
	}

	tampered := store.record
	tampered.AuthorityManifestDigest = strings.Repeat("f", 64)
	store.record = tampered
	if err := custody.ProvisionAccount(context.Background(), credential, claimID, enrollment, anchor); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting committed claim err=%v", err)
	}
}

func TestPreparedAccountJournalRecoversDeterministicStagingWithoutCrossAccountPoisoning(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(parent, "claims")
	journal, err := OpenPreparedAccountJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	credentialOne, err := NewAccountAdmissionCredential(fixtureAdmissionReference())
	if err != nil {
		t.Fatal(err)
	}
	referenceTwo := fixtureAdmissionReference()
	credentialTwo, err := NewAccountAdmissionCredential(referenceTwo)
	if err != nil {
		t.Fatal(err)
	}
	claimOne := fixturePreparedAccountClaim(t, credentialOne, uuid.New(), 1_100)
	claimTwo := fixturePreparedAccountClaim(t, credentialTwo, uuid.New(), 1_200)
	claimOneBytes := canonicalJSONUnchecked(claimOne)
	claimTwoBytes := canonicalJSONUnchecked(claimTwo)
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	for claim, contents := range map[uuid.UUID][]byte{
		claimOne.AccountID: claimOneBytes,
		claimTwo.AccountID: claimTwoBytes,
	} {
		if err := os.WriteFile(filepath.Join(directory, claim.String()+".prepared.tmp"), contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	journal, err = OpenPreparedAccountJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	loaded, found, err := journal.Load(claimOne.AccountID)
	if err != nil || !found || !reflect.DeepEqual(loaded, claimOne) {
		t.Fatalf("recover first=%+v found=%t err=%v", loaded, found, err)
	}
	if _, err := journal.Prepare(claimOne); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(directory, claimTwo.AccountID.String()+".prepared.tmp")); err != nil {
		t.Fatalf("unrelated account staging was disturbed: %v", err)
	}
	loaded, found, err = journal.Load(claimTwo.AccountID)
	if err != nil || !found || !reflect.DeepEqual(loaded, claimTwo) {
		t.Fatalf("recover second=%+v found=%t err=%v", loaded, found, err)
	}
	conflict := claimTwo
	conflict.ClaimID = uuid.New()
	if _, err := journal.Prepare(conflict); err == nil {
		t.Fatal("same-account conflicting deterministic staging accepted")
	}
}

func fixturePreparedAccountClaim(t *testing.T, credential AccountAdmissionCredential, claimID uuid.UUID, now int64) PreparedAccountClaim {
	t.Helper()
	digest, err := credential.AuthorizationDigest()
	if err != nil {
		t.Fatal(err)
	}
	return PreparedAccountClaim{
		Version: preparedAccountClaimVersion, AccountID: credential.Reference.AccountID,
		Admission: credential.Reference, AdmissionAuthorizationDigest: digest,
		ClaimID: claimID, ClaimedAtMilliseconds: now,
		InitialControlAnchor: newTestControlSigner(t, credential.Reference.AccountID, 1, 82).anchor(t),
		InitialEnrollment:    fixtureBackupEnrollment(t, credential.Reference.AccountID),
	}
}

func fixtureBackupEnrollment(t *testing.T, accountID uuid.UUID) serviceauthority.InitialEnrollment {
	t.Helper()
	enrollment, _ := fixtureBackupEnrollmentAndSigner(t, accountID)
	return enrollment
}

func fixtureBackupEnrollmentAndSigner(t *testing.T, accountID uuid.UUID) (serviceauthority.InitialEnrollment, *serviceauthority.DeploymentSigner) {
	t.Helper()
	deploymentID, routeID := uuid.New(), uuid.New()
	deploymentScalar := make([]byte, 32)
	deploymentScalar[31] = 2
	deploymentSigner, err := serviceauthority.NewDeploymentSigner(deploymentID, deploymentScalar)
	if err != nil {
		t.Fatal(err)
	}
	pin := strings.Repeat("1", 64)
	route := serviceauthority.TransportRoute{
		Endpoint: "https://facets-box.local:8443", Kind: serviceauthority.RouteDirectHTTPS,
		NetworkScope: serviceauthority.NetworkTrustedLAN, RouteID: routeID,
		ServerAuthentication: serviceauthority.ServerAuthentication{Kind: "pinned_spki_sha256", PinnedSPKISHA256: &pin},
	}
	descriptor := serviceauthority.DeploymentDescriptor{
		Version: serviceauthority.SchemaVersion, DeploymentID: deploymentID,
		CreatedAtMilliseconds: 900, PublicSigningKeyX963: deploymentSigner.PublicSigningKeyX963(),
		SigningKeyFingerprint: deploymentSigner.SigningKeyFingerprint(), Routes: []serviceauthority.TransportRoute{route},
	}
	policy := serviceauthority.TransportPolicy{Version: serviceauthority.SchemaVersion,
		ControlRouteIDs: []uuid.UUID{routeID}, MessageRouteIDs: []uuid.UUID{routeID}, BulkRouteIDs: []uuid.UUID{routeID}}
	scope := serviceauthority.Scope{Kind: serviceauthority.ScopeBackupCustody, ScopeID: accountID}
	authorityScalar := make([]byte, 32)
	authorityScalar[31] = 1
	authorityKey := backupTestPrivateKey(t, authorityScalar)
	authorityID := uuid.New()
	public := elliptic.Marshal(elliptic.P256(), authorityKey.PublicKey.X, authorityKey.PublicKey.Y)
	anchor := serviceauthority.TrustAnchor{Version: serviceauthority.SchemaVersion, Scope: scope, SignerID: authorityID,
		PublicSigningKeyX963:  base64.RawURLEncoding.EncodeToString(public),
		SigningKeyFingerprint: hex.EncodeToString(backupSHA256(public))}
	manifestPayload := serviceauthority.ManifestPayload{
		Version: serviceauthority.SchemaVersion, ActiveDeployment: descriptor, PreparedDeployments: []serviceauthority.DeploymentDescriptor{},
		Revision: 1, Scope: scope, Transition: serviceauthority.TransitionInitialActivation,
		TransportPolicy: policy, IssuedAtMilliseconds: 1_000, ValidFromMilliseconds: 1_000,
	}
	manifestBytes, err := json.Marshal(manifestPayload)
	if err != nil {
		t.Fatal(err)
	}
	manifest := serviceauthority.Manifest{Payload: manifestBytes,
		Signature: backupSignAuthority(t, authorityKey, authorityID, "Facets service authority manifest v1\x00", manifestBytes)}
	offer, err := deploymentSigner.SignDeploymentOffer(serviceauthority.DeploymentOfferPayload{
		Version: serviceauthority.SchemaVersion, Deployment: descriptor, TransportPolicy: policy,
		IssuedAtMilliseconds: 1_000, ExpiresAtMilliseconds: 2_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	enrollment := serviceauthority.InitialEnrollment{Version: serviceauthority.SchemaVersion, Anchor: anchor, DeploymentOffer: offer, Manifest: manifest}
	if _, err := enrollment.ValidateForAdmissionClaim(scope); err != nil {
		t.Fatalf("invalid Backup enrollment fixture: %v", err)
	}
	return enrollment, deploymentSigner
}

func backupTestPrivateKey(t *testing.T, scalar []byte) *ecdsa.PrivateKey {
	t.Helper()
	d := new(big.Int).SetBytes(scalar)
	x, y := elliptic.P256().ScalarBaseMult(scalar)
	if d.Sign() <= 0 || x == nil || y == nil {
		t.Fatal("invalid fixture key")
	}
	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, D: d}
}

func backupSignAuthority(t *testing.T, key *ecdsa.PrivateKey, signerID uuid.UUID, domain string, payload []byte) serviceauthority.Signature {
	t.Helper()
	digest := sha256.Sum256(append([]byte(domain), payload...))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	halfOrder := new(big.Int).Rsh(new(big.Int).Set(elliptic.P256().Params().N), 1)
	if s.Cmp(halfOrder) > 0 {
		s.Sub(elliptic.P256().Params().N, s)
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	public := elliptic.Marshal(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y)
	return serviceauthority.Signature{Algorithm: "ES256", PublicSigningKeyX963: base64.RawURLEncoding.EncodeToString(public),
		Signature: base64.RawURLEncoding.EncodeToString(raw), SignerID: signerID,
		SigningKeyFingerprint: hex.EncodeToString(backupSHA256(public))}
}

func backupSHA256(input []byte) []byte {
	digest := sha256.Sum256(input)
	return digest[:]
}

type mutableBackupClock struct{ now time.Time }

func (clock *mutableBackupClock) Now() time.Time { return clock.now }

type provisioningCoordinatorStore struct {
	readCoordinatorStore
	record         AccountRecord
	state          string
	prepareCount   int
	activateCount  int
	failActivation bool
}

func (store *provisioningCoordinatorStore) LoadAccountClaim(_ context.Context, accountID, claimID, admissionID uuid.UUID) (AccountRecord, string, error) {
	if store.state == "" || store.record.AccountID != accountID || store.record.ClaimID != claimID || store.record.Admission.AdmissionID != admissionID {
		return AccountRecord{}, "", ErrNotFound
	}
	return store.record, store.state, nil
}

func (store *provisioningCoordinatorStore) PrepareAccount(_ context.Context, record AccountRecord) error {
	if store.state != "" {
		return ErrConflict
	}
	store.record = record
	store.state = AccountStateStandby
	store.prepareCount++
	return nil
}

func (store *provisioningCoordinatorStore) ActivateAccount(_ context.Context, accountID uuid.UUID, revision uint64, digest string, deploymentID uuid.UUID, now int64) error {
	store.activateCount++
	if store.failActivation {
		return errors.New("injected activation failure")
	}
	if store.state != AccountStateStandby && store.state != AccountStateWritable || store.record.AccountID != accountID ||
		store.record.AuthorityRevision != revision || store.record.AuthorityManifestDigest != digest ||
		store.record.DeploymentID != deploymentID || now != store.record.CreatedAtMilliseconds {
		return ErrConflict
	}
	store.state = AccountStateWritable
	return nil
}
