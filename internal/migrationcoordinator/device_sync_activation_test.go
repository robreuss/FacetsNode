package migrationcoordinator

import (
	"bytes"
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
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

type activationStoreStub struct {
	applyCalls int
	failOnce   bool
	state      postgres.DeviceSyncScopeEnforcement
}

func (stub *activationStoreStub) ApplyDeviceSyncMigrationActivation(
	_ context.Context,
	localDeploymentID uuid.UUID,
	evidence serviceauthority.MigrationActivationEvidence,
	anchor serviceauthority.TrustAnchor,
	acceptedAtMilliseconds int64,
) error {
	stub.applyCalls++
	if stub.failOnce {
		stub.failOnce = false
		return errors.New("injected activation store failure")
	}
	activation, err := evidence.ValidateHistoricalCatchUp(
		anchor, acceptedAtMilliseconds,
	)
	if err != nil || activation.Migration == nil ||
		(localDeploymentID != activation.Migration.TargetDeploymentID &&
			localDeploymentID != activation.Migration.SourceDeploymentID) {
		return serviceauthority.ErrInvalid
	}
	digest, err := evidence.ReferenceDigest()
	if err != nil {
		return err
	}
	authority, err := postgres.DeviceSyncScopeAuthorityFromManifest(
		evidence.ActivationManifest, &digest, acceptedAtMilliseconds,
	)
	if err != nil {
		return err
	}
	local := localDeploymentID
	state := postgres.DeviceSyncScopeRetired
	if localDeploymentID == activation.Migration.TargetDeploymentID {
		state = postgres.DeviceSyncScopeWritable
	}
	stub.state = postgres.DeviceSyncScopeEnforcement{
		PrincipalID:       activation.Scope.ScopeID,
		TenantID:          activation.Scope.ScopeID,
		State:             state,
		LocalDeploymentID: &local,
		Authority:         &authority,
	}
	return nil
}

func TestDeviceSyncActivationCoordinatorKeepsSourceFencedAndRetired(t *testing.T) {
	ctx := context.Background()
	principalID := uuid.MustParse("1a000000-0000-0000-0000-000000000001")
	stateBytes := []byte("source activation journal service state")
	inventoryBytes := encodeBlobInventory(t, principalID, nil)
	preparation, anchor := loadPreparedMigrationFixture(t)
	snapshot, snapshotPayload := signSnapshotForArtifacts(
		t, preparation, anchor, stateBytes, inventoryBytes,
	)
	evidence := buildActivationEvidence(
		t, preparation, snapshot, snapshotPayload, anchor,
	)
	validated, err := snapshot.ValidatePreparedTransfer(preparation, anchor, 3_200)
	if err != nil {
		t.Fatal(err)
	}
	custody, err := NewFileArtifactCustody(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := custody.stagePreparedDeviceSyncTransfer(
		ctx, validated, preparation, snapshot,
		bytes.NewReader(stateBytes), bytes.NewReader(inventoryBytes),
	); err != nil {
		t.Fatal(err)
	}
	prepared, err := preparation.PreparationManifest.VerifiedPayload()
	if err != nil || prepared.Migration == nil {
		t.Fatal(err)
	}
	sourceID := prepared.Migration.SourceDeploymentID
	bindings := newTargetBindingRegistry(t, sourceID)
	current, err := preparation.CurrentManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	currentDigest, err := preparation.CurrentManifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	currentManifest := preparation.CurrentManifest
	if err := bindings.Activate(current.Scope, serviceauthority.CurrentBinding{
		Revision: current.Revision, Digest: currentDigest,
		DeploymentID: sourceID, Manifest: &currentManifest,
	}); err != nil {
		t.Fatal(err)
	}
	if err := bindings.ApplyMigrationPreparation(preparation, anchor, 2_200); err != nil {
		t.Fatal(err)
	}
	if err := bindings.StageMigrationWriteFence(
		preparation.PreparationManifest, snapshotPayload, anchor, 3_000,
	); err != nil {
		t.Fatal(err)
	}
	if err := bindings.ConfirmMigrationWriteFenceSnapshotAt(
		snapshotPayload.Scope, snapshot, 3_000,
	); err != nil {
		t.Fatal(err)
	}
	store := &activationStoreStub{}
	coordinator := &DeviceSyncActivationCoordinator{
		Store: store, Custody: custody, Bindings: bindings,
		Signer: signerForDeployment(t, prepared.ActiveDeployment),
	}
	result, err := coordinator.Activate(
		ctx, evidence, anchor, time.UnixMilli(3_200),
	)
	if err != nil || result.State.State != postgres.DeviceSyncScopeRetired ||
		!result.Binding.WriteFenced {
		t.Fatalf("source activation=%+v err=%v", result, err)
	}
}

func (stub *activationStoreStub) GetDeviceSyncScopeEnforcement(
	_ context.Context,
	_ uuid.UUID,
) (postgres.DeviceSyncScopeEnforcement, error) {
	if stub.state.Authority == nil {
		return postgres.DeviceSyncScopeEnforcement{}, errors.New("activation not committed")
	}
	return stub.state, nil
}

func TestDeviceSyncActivationCoordinatorRecoversExactCrossStoreFailureAfterExpiry(
	t *testing.T,
) {
	ctx := context.Background()
	principalID := uuid.MustParse("1a000000-0000-0000-0000-000000000001")
	stateBytes := []byte("activation journal service state")
	inventoryBytes := encodeBlobInventory(t, principalID, nil)
	preparation, anchor := loadPreparedMigrationFixture(t)
	snapshot, snapshotPayload := signSnapshotForArtifacts(
		t, preparation, anchor, stateBytes, inventoryBytes,
	)
	evidence := buildActivationEvidence(
		t, preparation, snapshot, snapshotPayload, anchor,
	)
	validated, err := snapshot.ValidatePreparedTransfer(preparation, anchor, 3_200)
	if err != nil {
		t.Fatal(err)
	}
	custody, err := NewFileArtifactCustody(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := custody.stagePreparedDeviceSyncTransfer(
		ctx, validated, preparation, snapshot,
		bytes.NewReader(stateBytes), bytes.NewReader(inventoryBytes),
	); err != nil {
		t.Fatal(err)
	}
	targetID := snapshotPayload.ImportingDeploymentID
	bindings := newTargetBindingRegistry(t, targetID)
	if err := bindings.ApplyMigrationPreparation(preparation, anchor, 2_200); err != nil {
		t.Fatal(err)
	}
	store := &activationStoreStub{failOnce: true}
	coordinator := &DeviceSyncActivationCoordinator{
		Store: store, Custody: custody, Bindings: bindings,
		Signer: signerForDeployment(t, validated.TargetDeploymentOffer.Deployment),
	}
	if _, err := coordinator.Activate(
		ctx, evidence, anchor, time.UnixMilli(3_200),
	); err == nil || store.applyCalls != 1 {
		t.Fatalf("injected activation failure=%v calls=%d", err, store.applyCalls)
	}
	identities, err := bindings.CurrentBindingIdentities(serviceauthority.ScopeDeviceSync)
	if err != nil || len(identities) != 1 ||
		identities[0].Revision != 3 || identities[0].WriteFenced {
		t.Fatalf("registry activation before database failure=%+v err=%v", identities, err)
	}
	pendingPath := filepathForActivationJournal(
		custody, snapshotPayload, activationFileName,
	)
	if err := os.Chmod(pendingPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Recover(ctx, time.UnixMilli(3_201)); err == nil {
		t.Fatal("permissive pending activation journal was accepted")
	}
	if err := os.Chmod(pendingPath, 0o600); err != nil {
		t.Fatal(err)
	}
	// The activation Manifest, readiness, and snapshot have all expired by this
	// point. Recovery succeeds only because the exact evidence and its live
	// acceptance instant were durably journaled before registry advancement.
	results, err := coordinator.Recover(ctx, time.UnixMilli(20_001))
	if err != nil || len(results) != 1 || store.applyCalls != 2 ||
		results[0].State.State != postgres.DeviceSyncScopeWritable ||
		results[0].Binding.WriteFenced {
		t.Fatalf("activation recovery=%+v calls=%d err=%v", results, store.applyCalls, err)
	}
	if results, err := coordinator.Recover(ctx, time.UnixMilli(20_002)); err != nil || len(results) != 0 || store.applyCalls != 2 {
		t.Fatalf("idempotent activation recovery=%+v calls=%d err=%v", results, store.applyCalls, err)
	}
	if result, err := coordinator.Activate(
		ctx, evidence, anchor, time.UnixMilli(20_002),
	); err != nil || store.applyCalls != 3 ||
		result.State.State != postgres.DeviceSyncScopeWritable {
		t.Fatalf("expired exact activation retry=%+v calls=%d err=%v", result, store.applyCalls, err)
	}

	activationPath := filepathForActivationJournal(
		custody, snapshotPayload, completedActivationFileName,
	)
	journalBytes, err := readProtectedRecord(activationPath, maximumEvidenceByteCount)
	if err != nil {
		t.Fatal(err)
	}
	var journal deviceSyncActivationJournalRecord
	if err := json.Unmarshal(journalBytes, &journal); err != nil {
		t.Fatal(err)
	}
	acceptancePayload, err := journal.Acceptance.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	acceptancePayload.ActivationEvidenceDigest = hex.EncodeToString(make([]byte, sha256.Size))
	journal.Acceptance.Payload, err = json.Marshal(acceptancePayload)
	if err != nil {
		t.Fatal(err)
	}
	tampered, err := json.Marshal(journal)
	if err != nil {
		t.Fatal(err)
	}
	if err := overwriteProtectedTestRecord(activationPath, tampered); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Activate(
		ctx, evidence, anchor, time.UnixMilli(20_003),
	); err == nil {
		t.Fatal("tampered completed activation journal was accepted")
	}
}

func buildActivationEvidence(
	t *testing.T,
	preparation serviceauthority.MigrationPreparation,
	snapshot serviceauthority.MigrationSnapshot,
	snapshotPayload serviceauthority.MigrationSnapshotPayload,
	anchor serviceauthority.TrustAnchor,
) serviceauthority.MigrationActivationEvidence {
	t.Helper()
	prepared, err := preparation.PreparationManifest.VerifiedPayload()
	if err != nil || prepared.Migration == nil || len(prepared.PreparedDeployments) != 1 {
		t.Fatalf("prepared payload=%+v err=%v", prepared, err)
	}
	target := prepared.PreparedDeployments[0]
	targetSigner := signerForDeployment(t, target)
	snapshotDigest, err := snapshot.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	readiness, err := targetSigner.SignMigrationReadiness(
		serviceauthority.MigrationReadinessPayload{
			AppliedStateCommitmentDigest: snapshotPayload.StateCommitmentDigest,
			AuthorityManifestDigest:      snapshotPayload.AuthorityManifestDigest,
			ExpiresAtMilliseconds:        9_000,
			ImportingDeploymentID:        target.DeploymentID,
			MigrationID:                  snapshotPayload.MigrationID,
			ReadyAtMilliseconds:          3_000,
			Scope:                        snapshotPayload.Scope,
			SnapshotReferenceDigest:      snapshotDigest,
			Version:                      serviceauthority.SchemaVersion,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	evidence := serviceauthority.MigrationActivationEvidence{
		Preparation: preparation, Readiness: readiness, Snapshot: snapshot,
	}
	prerequisiteDigest, err := evidence.PrerequisitesReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	preparationDigest, err := preparation.PreparationManifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	targetOffer, err := preparation.TargetOffer.VerifiedPayload(nil)
	if err != nil {
		t.Fatal(err)
	}
	targetDeploymentOffer, err := targetOffer.DeploymentOffer.VerifiedPayload(nil)
	if err != nil {
		t.Fatal(err)
	}
	validUntil := int64(10_000)
	payload := serviceauthority.ManifestPayload{
		ActiveDeployment:                    target,
		IssuedAtMilliseconds:                3_100,
		Migration:                           prepared.Migration,
		MigrationPrerequisiteEvidenceDigest: &prerequisiteDigest,
		PredecessorManifestDigest:           &preparationDigest,
		PreparedDeployments:                 []serviceauthority.DeploymentDescriptor{prepared.ActiveDeployment},
		Revision:                            prepared.Revision + 1,
		Scope:                               prepared.Scope,
		Transition:                          serviceauthority.TransitionMigrationActivation,
		TransportPolicy:                     targetDeploymentOffer.TransportPolicy,
		ValidFromMilliseconds:               3_100,
		ValidUntilMilliseconds:              &validUntil,
		Version:                             serviceauthority.SchemaVersion,
	}
	evidence.ActivationManifest = signActivationTestManifest(t, payload, anchor)
	if _, err := evidence.Validate(anchor, 3_200); err != nil {
		t.Fatalf("synthetic activation evidence: %v", err)
	}
	return evidence
}

func signActivationTestManifest(
	t *testing.T,
	payload serviceauthority.ManifestPayload,
	anchor serviceauthority.TrustAnchor,
) serviceauthority.Manifest {
	t.Helper()
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	key := activationTestAuthorityKey(t, anchor)
	digest := sha256.Sum256(append(
		[]byte("Facets service authority manifest v1\x00"), encoded...,
	))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if s.Cmp(new(big.Int).Rsh(new(big.Int).Set(elliptic.P256().Params().N), 1)) > 0 {
		s.Sub(elliptic.P256().Params().N, s)
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	return serviceauthority.Manifest{
		Payload: encoded,
		Signature: serviceauthority.Signature{
			Algorithm:             "ES256",
			PublicSigningKeyX963:  anchor.PublicSigningKeyX963,
			Signature:             base64.RawURLEncoding.EncodeToString(raw),
			SignerID:              anchor.SignerID,
			SigningKeyFingerprint: anchor.SigningKeyFingerprint,
		},
	}
}

func activationTestAuthorityKey(
	t *testing.T,
	anchor serviceauthority.TrustAnchor,
) *ecdsa.PrivateKey {
	t.Helper()
	for scalar := byte(1); scalar <= 16; scalar++ {
		seed := make([]byte, 32)
		seed[31] = scalar
		d := new(big.Int).SetBytes(seed)
		x, y := elliptic.P256().ScalarBaseMult(seed)
		public := elliptic.Marshal(elliptic.P256(), x, y)
		if base64.RawURLEncoding.EncodeToString(public) == anchor.PublicSigningKeyX963 {
			return &ecdsa.PrivateKey{
				PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y},
				D:         d,
			}
		}
	}
	t.Fatal("fixture authority key was not found")
	return nil
}

func filepathForActivationJournal(
	custody *FileArtifactCustody,
	snapshot serviceauthority.MigrationSnapshotPayload,
	fileName string,
) string {
	return filepath.Join(custody.transferDirectory(fileArtifactCustodyMetadata{
		PrincipalID: snapshot.Scope.ScopeID,
		MigrationID: snapshot.MigrationID,
		SnapshotID:  snapshot.SnapshotID,
	}), fileName)
}

func overwriteProtectedTestRecord(path string, value []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(value)
	return errors.Join(writeErr, file.Close())
}
