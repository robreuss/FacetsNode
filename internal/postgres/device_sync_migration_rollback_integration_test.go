package postgres_test

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
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	postgresstore "github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

type postgresDeviceSyncRollbackFixture struct {
	AuthorityAnchor  serviceauthority.TrustAnchor               `json:"authorityAnchor"`
	RollbackEvidence serviceauthority.MigrationRollbackEvidence `json:"rollbackEvidence"`
}

func TestPostgresDeviceSyncMigrationRollbackReplacesStateAndRestoresWrites(
	t *testing.T,
) {
	databaseURL := os.Getenv("FACETS_SERVER_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("FACETS_SERVER_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	lockDisposablePostgres(t, ctx, databaseURL)
	pool := openPool(t, ctx, databaseURL)
	defer pool.Close()
	if err := postgresstore.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		TRUNCATE device_sync_account_admissions, relay_tenants CASCADE
	`); err != nil {
		t.Fatal(err)
	}

	fixture := loadPostgresDeviceSyncRollbackFixture(t)
	preparation := fixture.RollbackEvidence.ActivationEvidence.Preparation
	current, err := preparation.CurrentManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := preparation.PreparationManifest.VerifiedPayload()
	if err != nil || prepared.Migration == nil || len(prepared.PreparedDeployments) != 1 {
		t.Fatalf("prepared=%+v err=%v", prepared, err)
	}
	principalID := current.Scope.ScopeID
	sourceSigner := postgresFixtureDeploymentSigner(t, current.ActiveDeployment)
	targetSigner := postgresFixtureDeploymentSigner(t, prepared.PreparedDeployments[0])
	store := postgresstore.NewRelayStore(pool)
	initialBinding := postgresInitialServiceAuthorityBinding(
		t, loadPostgresDeviceSyncEnforcementFixture(t), preparation.CurrentManifest,
		sourceSigner, 1_100,
	)
	initialDeviceID := uuid.New()
	sourceAuthority := postgresBootstrapDeviceSyncPrincipal(
		t, ctx, store, principalID, initialDeviceID, 1_100, initialBinding,
	)
	if err := store.ActivateBoundDeviceSyncScope(
		ctx, principalID, sourceSigner.DeploymentID(), initialBinding.Revision(),
		initialBinding.ManifestDigest(), 1_100,
	); err != nil {
		t.Fatal(err)
	}
	populatePostgresDeviceSyncMigrationRepresentativeState(
		t, ctx, pool, store, sourceAuthority, initialDeviceID,
	)

	// This is the state the activated target is assumed to hold when the user
	// requests rollback. The old source is deliberately changed afterwards so
	// the reverse import must perform a real replacement rather than a no-op.
	targetState, targetInventory, targetDigests :=
		exportPostgresDeviceSyncMigrationState(t, ctx, pool, principalID)
	if _, err := pool.Exec(ctx, `
		UPDATE relay_tenants
		SET maximum_aggregate_message_count = maximum_aggregate_message_count + 1
		WHERE tenant_id=$1
	`, principalID); err != nil {
		t.Fatal(err)
	}
	staleSourceState, _, staleSourceDigests :=
		exportPostgresDeviceSyncMigrationState(t, ctx, pool, principalID)
	if bytes.Equal(targetState, staleSourceState) || targetDigests == staleSourceDigests {
		t.Fatal("rollback fixture did not create divergent source and target state")
	}

	preparationEvidenceDigest, err := preparation.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AdvanceDeviceSyncWritableAuthority(
		ctx, principalID, sourceSigner.DeploymentID(),
		preparation.PreparationManifest, &preparationEvidenceDigest, 2_200,
	); err != nil {
		t.Fatal(err)
	}
	preparationManifestDigest, err := preparation.PreparationManifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	forwardPayload := postgresDeviceSyncMigrationSnapshotPayload(
		t, prepared.Scope, *prepared.Migration, preparationManifestDigest,
		sourceSigner.DeploymentID(), targetSigner.DeploymentID(), 2_500, 9_000,
		staleSourceDigests,
	)
	forwardSnapshot := signPostgresPreparedDeviceSyncMigrationSnapshot(
		t, preparation, fixture.AuthorityAnchor, sourceSigner, forwardPayload,
	)
	forwardPayloadBytes, err := json.Marshal(forwardPayload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.MaterializeAndFenceDeviceSyncMigrationExport(
		ctx, principalID, sourceSigner.DeploymentID(), prepared.Revision,
		preparationManifestDigest, prepared.Migration.MigrationID,
		forwardPayload.ExportWriteFenceID, 2_500,
		func(context.Context, postgresstore.DeviceSyncSnapshotReadTransaction,
			postgresstore.DeviceSyncScopeEnforcement) ([]byte, error) {
			return forwardPayloadBytes, nil
		},
	); err != nil {
		t.Fatal(err)
	}
	activation := buildPostgresDeviceSyncMigrationActivation(
		t, fixture, preparation, forwardSnapshot, forwardPayload,
		targetSigner,
	)
	if err := store.ApplyDeviceSyncMigrationActivation(
		ctx, sourceSigner.DeploymentID(), activation,
		fixture.AuthorityAnchor, 3_200,
	); err != nil {
		t.Fatal(err)
	}

	activationPayload, err := activation.ActivationManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	activationManifestDigest, err := activation.ActivationManifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	reversePayload := postgresDeviceSyncMigrationSnapshotPayload(
		t, prepared.Scope, *prepared.Migration, activationManifestDigest,
		targetSigner.DeploymentID(), sourceSigner.DeploymentID(), 3_600, 9_000,
		targetDigests,
	)
	reverseSnapshot := signPostgresDeviceSyncRollbackSnapshot(
		t, preparation, activation, fixture.AuthorityAnchor,
		targetSigner, reversePayload,
	)
	tamperedTargetState := append([]byte(nil), targetState...)
	tamperedTargetState[len(tamperedTargetState)-1] ^= 0x01
	if _, err := store.PrepareDeviceSyncMigrationRollbackStandby(
		ctx, sourceSigner.DeploymentID(), activation, reverseSnapshot,
		fixture.AuthorityAnchor, 3_700,
		postgresstore.DeviceSyncMigrationStagedArtifacts{
			ServiceState:  bytes.NewReader(tamperedTargetState),
			BlobInventory: bytes.NewReader(targetInventory),
		},
	); err == nil {
		t.Fatal("tampered rollback state artifact was accepted")
	}
	var failedImportCount int64
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM device_sync_migration_rollback_imports
		WHERE principal_id=$1
	`, principalID).Scan(&failedImportCount); err != nil || failedImportCount != 0 {
		t.Fatalf("failed rollback import residue=%d err=%v", failedImportCount, err)
	}
	imported, err := store.PrepareDeviceSyncMigrationRollbackStandby(
		ctx, sourceSigner.DeploymentID(), activation, reverseSnapshot,
		fixture.AuthorityAnchor, 3_700,
		postgresstore.DeviceSyncMigrationStagedArtifacts{
			ServiceState:  bytes.NewReader(targetState),
			BlobInventory: bytes.NewReader(targetInventory),
		},
	)
	if err != nil || imported.StateCommitmentDigest != targetDigests.StateCommitment.String() {
		t.Fatalf("rollback standby import=%+v err=%v", imported, err)
	}
	standby, err := store.GetDeviceSyncScopeEnforcement(ctx, principalID)
	if err != nil || standby.State != postgresstore.DeviceSyncScopeRollbackStandby ||
		standby.ActiveRollbackImportID == nil ||
		*standby.ActiveRollbackImportID != prepared.Migration.MigrationID {
		t.Fatalf("rollback standby=%+v err=%v", standby, err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE relay_tenants SET updated_at=now() WHERE tenant_id=$1
	`, principalID); err == nil || !strings.Contains(
		err.Error(), "not writable in this transaction",
	) {
		t.Fatalf("rollback standby allowed an ordinary write: %v", err)
	}
	standbyState, standbyInventory, standbyDigests :=
		exportPostgresDeviceSyncMigrationState(t, ctx, pool, principalID)
	if !bytes.Equal(standbyState, targetState) ||
		!bytes.Equal(standbyInventory, targetInventory) || standbyDigests != targetDigests {
		t.Fatal("rollback standby did not exactly reproduce authenticated target state")
	}

	rollback := buildPostgresDeviceSyncMigrationRollback(
		t, fixture, preparation, activation, activationPayload,
		reverseSnapshot, reversePayload, sourceSigner,
	)
	if err := store.ApplyDeviceSyncMigrationRollback(
		ctx, sourceSigner.DeploymentID(), rollback,
		fixture.AuthorityAnchor, 4_000,
	); err != nil {
		t.Fatal(err)
	}
	// Exact restart repair remains valid after all operational evidence expires.
	if err := store.ApplyDeviceSyncMigrationRollback(
		ctx, sourceSigner.DeploymentID(), rollback,
		fixture.AuthorityAnchor, 20_000,
	); err != nil {
		t.Fatalf("retry completed rollback: %v", err)
	}
	rolledBack, err := store.GetDeviceSyncScopeEnforcement(ctx, principalID)
	rollbackEvidenceDigest, digestErr := rollback.ReferenceDigest()
	if err != nil || digestErr != nil || rolledBack.State != postgresstore.DeviceSyncScopeWritable ||
		rolledBack.Authority == nil || rolledBack.Authority.Revision != activationPayload.Revision+1 ||
		rolledBack.Authority.ActiveDeploymentID != sourceSigner.DeploymentID() ||
		rolledBack.Authority.TransitionEvidenceDigest == nil ||
		*rolledBack.Authority.TransitionEvidenceDigest != rollbackEvidenceDigest ||
		rolledBack.ActiveRollbackImportID != nil || rolledBack.ActiveExportWriteFenceID != nil {
		t.Fatalf("completed rollback state=%+v evidenceErr=%v err=%v", rolledBack, digestErr, err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE relay_tenants SET updated_at=now() WHERE tenant_id=$1
	`, principalID); err != nil {
		t.Fatalf("rolled-back source remained non-writable: %v", err)
	}
	deleteControlDomain, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, deleteError := deleteControlDomain.Exec(ctx, `
		DELETE FROM relay_domains WHERE tenant_id=$1 AND domain_id=$2
	`, principalID, sourceAuthority.ControlDomain.Registration.DomainID)
	if deleteError == nil {
		deleteError = deleteControlDomain.Commit(ctx)
	} else {
		_ = deleteControlDomain.Rollback(ctx)
	}
	if deleteError == nil {
		t.Fatal("permanent Device Sync control domain accepted deletion")
	}
	finalState, finalInventory, finalDigests :=
		exportPostgresDeviceSyncMigrationState(t, ctx, pool, principalID)
	if !bytes.Equal(finalState, targetState) || !bytes.Equal(finalInventory, targetInventory) ||
		finalDigests != targetDigests {
		t.Fatal("completed rollback changed the authenticated reverse-import state")
	}
	if _, err := pool.Exec(ctx, `
		UPDATE device_sync_migration_rollback_imports
		SET state_commitment_digest=$2
		WHERE principal_id=$1
	`, principalID, strings.Repeat("e", 64)); err == nil {
		t.Fatal("immutable rollback import evidence accepted an update")
	}
}

func postgresDeviceSyncMigrationSnapshotPayload(
	t *testing.T,
	scope serviceauthority.Scope,
	migration serviceauthority.MigrationAuthority,
	authorityManifestDigest string,
	exportingDeploymentID uuid.UUID,
	importingDeploymentID uuid.UUID,
	capturedAtMilliseconds int64,
	expiresAtMilliseconds int64,
	digests postgresstore.DeviceSyncMigrationArtifactDigests,
) serviceauthority.MigrationSnapshotPayload {
	t.Helper()
	payload := serviceauthority.MigrationSnapshotPayload{
		Artifacts: []serviceauthority.MigrationArtifactDescriptor{
			{
				ArtifactID: uuid.New(), ByteCount: digests.StateArtifactByteCount,
				Kind:           serviceauthority.ArtifactServiceStateSnapshot,
				TransferDigest: digests.StateArtifactSHA256.String(),
			},
			{
				ArtifactID: uuid.New(), ByteCount: digests.BlobInventoryByteCount,
				Kind:           serviceauthority.ArtifactBlobInventory,
				TransferDigest: digests.BlobInventorySHA256.String(),
			},
		},
		AuthorityManifestDigest: authorityManifestDigest,
		CapturedAtMilliseconds:  capturedAtMilliseconds,
		ExpiresAtMilliseconds:   expiresAtMilliseconds,
		ExportWriteFenceID:      uuid.New(),
		ExportingDeploymentID:   exportingDeploymentID,
		ImportingDeploymentID:   importingDeploymentID,
		MigrationID:             migration.MigrationID,
		Scope:                   scope,
		SnapshotID:              uuid.New(),
		StateCommitmentDigest:   digests.StateCommitment.String(),
		Version:                 serviceauthority.SchemaVersion,
	}
	sort.Slice(payload.Artifacts, func(left, right int) bool {
		return bytes.Compare(
			payload.Artifacts[left].ArtifactID[:], payload.Artifacts[right].ArtifactID[:],
		) < 0
	})
	if err := payload.Validate(nil); err != nil {
		t.Fatal(err)
	}
	return payload
}

func buildPostgresDeviceSyncMigrationActivation(
	t *testing.T,
	fixture postgresDeviceSyncRollbackFixture,
	preparation serviceauthority.MigrationPreparation,
	snapshot serviceauthority.MigrationSnapshot,
	snapshotPayload serviceauthority.MigrationSnapshotPayload,
	targetSigner *serviceauthority.DeploymentSigner,
) serviceauthority.MigrationActivationEvidence {
	t.Helper()
	snapshotDigest, err := snapshot.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	readiness, err := targetSigner.SignMigrationReadiness(
		serviceauthority.MigrationReadinessPayload{
			AppliedStateCommitmentDigest: snapshotPayload.StateCommitmentDigest,
			AuthorityManifestDigest:      snapshotPayload.AuthorityManifestDigest,
			ExpiresAtMilliseconds:        5_000,
			ImportingDeploymentID:        targetSigner.DeploymentID(),
			MigrationID:                  snapshotPayload.MigrationID,
			ReadyAtMilliseconds:          2_800,
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
	activationPayload, err := fixture.RollbackEvidence.ActivationEvidence.
		ActivationManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	activationPayload.MigrationPrerequisiteEvidenceDigest = &prerequisiteDigest
	evidence.ActivationManifest = signPostgresDeviceSyncAuthorityManifest(
		t, activationPayload, postgresDeviceSyncAuthorityPrivateKey(t, fixture.AuthorityAnchor),
		fixture.AuthorityAnchor,
	)
	if _, err := evidence.Validate(fixture.AuthorityAnchor, 3_200); err != nil {
		t.Fatalf("dynamic activation evidence: %v", err)
	}
	return evidence
}

func signPostgresDeviceSyncRollbackSnapshot(
	t *testing.T,
	preparation serviceauthority.MigrationPreparation,
	activation serviceauthority.MigrationActivationEvidence,
	anchor serviceauthority.TrustAnchor,
	targetSigner *serviceauthority.DeploymentSigner,
	payload serviceauthority.MigrationSnapshotPayload,
) serviceauthority.MigrationSnapshot {
	t.Helper()
	bindingFile := filepath.Join(t.TempDir(), "bindings.json")
	if err := os.WriteFile(bindingFile, []byte(`{"bindings":[],"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	registry, err := serviceauthority.LoadBindingRegistry(
		bindingFile, targetSigner.DeploymentID(),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.Close() })
	if err := registry.ApplyMigrationPreparation(preparation, anchor, 2_200); err != nil {
		t.Fatal(err)
	}
	if err := registry.ApplyMigrationActivation(activation, anchor, 3_200); err != nil {
		t.Fatal(err)
	}
	if err := registry.StageMigrationWriteFence(
		activation.ActivationManifest, payload, anchor, 3_600,
	); err != nil {
		t.Fatal(err)
	}
	snapshot, err := registry.SignStagedMigrationSnapshotAt(
		payload.Scope, targetSigner, 3_600,
	)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func buildPostgresDeviceSyncMigrationRollback(
	t *testing.T,
	fixture postgresDeviceSyncRollbackFixture,
	preparation serviceauthority.MigrationPreparation,
	activation serviceauthority.MigrationActivationEvidence,
	activationPayload serviceauthority.ManifestPayload,
	reverseSnapshot serviceauthority.MigrationSnapshot,
	reversePayload serviceauthority.MigrationSnapshotPayload,
	sourceSigner *serviceauthority.DeploymentSigner,
) serviceauthority.MigrationRollbackEvidence {
	t.Helper()
	snapshotDigest, err := reverseSnapshot.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	readiness, err := sourceSigner.SignMigrationReadiness(
		serviceauthority.MigrationReadinessPayload{
			AppliedStateCommitmentDigest: reversePayload.StateCommitmentDigest,
			AuthorityManifestDigest:      reversePayload.AuthorityManifestDigest,
			ExpiresAtMilliseconds:        9_000,
			ImportingDeploymentID:        sourceSigner.DeploymentID(),
			MigrationID:                  reversePayload.MigrationID,
			ReadyAtMilliseconds:          3_800,
			Scope:                        reversePayload.Scope,
			SnapshotReferenceDigest:      snapshotDigest,
			Version:                      serviceauthority.SchemaVersion,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	evidence := serviceauthority.MigrationRollbackEvidence{
		ActivationEvidence: activation, SourceReadiness: readiness,
		TargetSnapshot: reverseSnapshot,
	}
	prerequisiteDigest, err := evidence.PrerequisitesReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	rollbackPayload, err := fixture.RollbackEvidence.RollbackManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	activationDigest, err := activation.ActivationManifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	rollbackPayload.MigrationPrerequisiteEvidenceDigest = &prerequisiteDigest
	rollbackPayload.PredecessorManifestDigest = &activationDigest
	rollbackPayload.Revision = activationPayload.Revision + 1
	rollbackPayload.ActiveDeployment = mustPostgresDeviceSyncInitialDeployment(
		t, preparation,
	)
	evidence.RollbackManifest = signPostgresDeviceSyncAuthorityManifest(
		t, rollbackPayload, postgresDeviceSyncAuthorityPrivateKey(t, fixture.AuthorityAnchor),
		fixture.AuthorityAnchor,
	)
	if _, err := evidence.Validate(fixture.AuthorityAnchor, 4_000); err != nil {
		t.Fatalf("dynamic rollback evidence: %v", err)
	}
	return evidence
}

func mustPostgresDeviceSyncInitialDeployment(
	t *testing.T,
	preparation serviceauthority.MigrationPreparation,
) serviceauthority.DeploymentDescriptor {
	t.Helper()
	current, err := preparation.CurrentManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	return current.ActiveDeployment
}

func loadPostgresDeviceSyncRollbackFixture(t *testing.T) postgresDeviceSyncRollbackFixture {
	t.Helper()
	contents, err := os.ReadFile(
		"../serviceauthority/testdata/service-migration-portable-v2.json",
	)
	if err != nil {
		t.Fatal(err)
	}
	var fixture postgresDeviceSyncRollbackFixture
	if err := json.Unmarshal(contents, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func postgresDeviceSyncAuthorityPrivateKey(
	t *testing.T,
	anchor serviceauthority.TrustAnchor,
) *ecdsa.PrivateKey {
	t.Helper()
	curve := elliptic.P256()
	for scalar := byte(1); scalar <= 16; scalar++ {
		seed := make([]byte, 32)
		seed[len(seed)-1] = scalar
		d := new(big.Int).SetBytes(seed)
		x, y := curve.ScalarBaseMult(seed)
		public := elliptic.Marshal(curve, x, y)
		if base64.RawURLEncoding.EncodeToString(public) == anchor.PublicSigningKeyX963 {
			return &ecdsa.PrivateKey{
				PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: d,
			}
		}
	}
	t.Fatal("portable fixture authority key is outside deterministic test range")
	return nil
}

func signPostgresDeviceSyncAuthorityManifest(
	t *testing.T,
	payload serviceauthority.ManifestPayload,
	privateKey *ecdsa.PrivateKey,
	anchor serviceauthority.TrustAnchor,
) serviceauthority.Manifest {
	t.Helper()
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(append(
		[]byte("Facets service authority manifest v1\x00"), encoded...,
	))
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	order := elliptic.P256().Params().N
	halfOrder := new(big.Int).Rsh(new(big.Int).Set(order), 1)
	if s.Cmp(halfOrder) > 0 {
		s.Sub(order, s)
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	public := elliptic.Marshal(
		elliptic.P256(), privateKey.PublicKey.X, privateKey.PublicKey.Y,
	)
	fingerprint := sha256.Sum256(public)
	if hex.EncodeToString(fingerprint[:]) != anchor.SigningKeyFingerprint {
		t.Fatal("fixture authority fingerprint changed")
	}
	return serviceauthority.Manifest{
		Payload: encoded,
		Signature: serviceauthority.Signature{
			Algorithm: "ES256", PublicSigningKeyX963: anchor.PublicSigningKeyX963,
			Signature: base64.RawURLEncoding.EncodeToString(raw),
			SignerID:  anchor.SignerID, SigningKeyFingerprint: anchor.SigningKeyFingerprint,
		},
	}
}
