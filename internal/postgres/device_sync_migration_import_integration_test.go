package postgres_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/robreuss/FacetsNode/internal/devicesync"
	postgresstore "github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
	"github.com/robreuss/FacetsNode/internal/testfixture"
)

func TestPostgresPreparedDeviceSyncMigrationImportIsAtomicAndStandby(
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

	fixture := loadPostgresDeviceSyncEnforcementFixture(t)
	preparation := fixture.RollbackEvidence.ActivationEvidence.Preparation
	originalSnapshot := fixture.RollbackEvidence.ActivationEvidence.Snapshot
	snapshotPayload, err := originalSnapshot.VerifiedPayload(nil)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := preparation.PreparationManifest.VerifiedPayload()
	if err != nil || prepared.Migration == nil || len(prepared.PreparedDeployments) != 1 {
		t.Fatalf("prepared payload=%+v err=%v", prepared, err)
	}
	principalID := snapshotPayload.Scope.ScopeID
	targetDeploymentID := prepared.PreparedDeployments[0].DeploymentID
	current, err := preparation.CurrentManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	sourceSigner := postgresFixtureDeploymentSigner(t, current.ActiveDeployment)
	store := postgresstore.NewRelayStore(pool)
	initialBinding := postgresInitialServiceAuthorityBinding(
		t, fixture, preparation.CurrentManifest, sourceSigner, 1_100,
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
	_, emptyBlobInventory, emptyArtifactDigests :=
		exportPostgresDeviceSyncMigrationState(t, ctx, pool, principalID)
	populatePostgresDeviceSyncMigrationRepresentativeState(
		t, ctx, pool, store, sourceAuthority, initialDeviceID,
	)
	stateArtifact, blobInventory, artifactDigests :=
		exportPostgresDeviceSyncMigrationState(t, ctx, pool, principalID)

	for index := range snapshotPayload.Artifacts {
		if snapshotPayload.Artifacts[index].Kind == serviceauthority.ArtifactServiceStateSnapshot {
			snapshotPayload.Artifacts[index].ByteCount = artifactDigests.StateArtifactByteCount
			snapshotPayload.Artifacts[index].TransferDigest = artifactDigests.StateArtifactSHA256.String()
		}
	}
	snapshotPayload.Artifacts = append(snapshotPayload.Artifacts,
		serviceauthority.MigrationArtifactDescriptor{
			ArtifactID:     uuid.MustParse("6f000000-0000-0000-0000-000000000005"),
			ByteCount:      artifactDigests.BlobInventoryByteCount,
			Kind:           serviceauthority.ArtifactBlobInventory,
			TransferDigest: artifactDigests.BlobInventorySHA256.String(),
		})
	snapshotPayload.StateCommitmentDigest = artifactDigests.StateCommitment.String()
	snapshot := signPostgresPreparedDeviceSyncMigrationSnapshot(
		t, preparation, fixture.AuthorityAnchor, sourceSigner, snapshotPayload,
	)
	mismatchedPayload := snapshotPayload
	mismatchedPayload.Artifacts = append(
		[]serviceauthority.MigrationArtifactDescriptor(nil), snapshotPayload.Artifacts...,
	)
	for index := range mismatchedPayload.Artifacts {
		if mismatchedPayload.Artifacts[index].Kind == serviceauthority.ArtifactBlobInventory {
			mismatchedPayload.Artifacts[index].ByteCount = emptyArtifactDigests.BlobInventoryByteCount
			mismatchedPayload.Artifacts[index].TransferDigest = emptyArtifactDigests.BlobInventorySHA256.String()
		}
	}
	mismatchedPayload.StateCommitmentDigest = postgresstore.DeviceSyncMigrationStateCommitment(
		artifactDigests.StateArtifactSHA256,
		emptyArtifactDigests.BlobInventorySHA256,
	).String()
	mismatchedSnapshot := signPostgresPreparedDeviceSyncMigrationSnapshot(
		t, preparation, fixture.AuthorityAnchor, sourceSigner, mismatchedPayload,
	)
	if _, err := pool.Exec(ctx, `
		TRUNCATE device_sync_account_admissions, relay_tenants CASCADE
	`); err != nil {
		t.Fatal(err)
	}

	initial := postgresstore.DeviceSyncInitialAuthorityEvidence{
		Manifest:                preparation.CurrentManifest,
		ValidatedAtMilliseconds: 1_100,
	}
	// The portable fixture snapshot intentionally predates the mandatory blob
	// inventory. Even though it is correctly signed, the canonical Device Sync
	// importer must reject it before creating any target state.
	if _, err := store.ImportPreparedDeviceSyncMigrationStandby(
		ctx, targetDeploymentID, preparation, originalSnapshot,
		fixture.AuthorityAnchor, initial, 3_000,
		postgresstore.DeviceSyncMigrationStagedArtifacts{
			ServiceState:  bytes.NewReader(stateArtifact),
			BlobInventory: bytes.NewReader(blobInventory),
		},
	); err == nil {
		t.Fatal("signed Device Sync snapshot without blob inventory was accepted")
	}
	assertNoDeviceSyncImportResidue(t, ctx, pool, principalID)

	// This snapshot is itself valid and exactly describes the supplied bytes,
	// but its empty blob inventory contradicts the blob references in the
	// service-state artifact. The importer must detect that only after
	// materialization and roll the entire target transaction back.
	if _, err := store.ImportPreparedDeviceSyncMigrationStandby(
		ctx, targetDeploymentID, preparation, mismatchedSnapshot,
		fixture.AuthorityAnchor, initial, 3_000,
		postgresstore.DeviceSyncMigrationStagedArtifacts{
			ServiceState:  bytes.NewReader(stateArtifact),
			BlobInventory: bytes.NewReader(emptyBlobInventory),
		},
	); err == nil || !strings.Contains(
		err.Error(),
		"materialized Device Sync target state does not reproduce signed artifact commitment",
	) {
		t.Fatalf("self-consistent mismatched inventory error=%v", err)
	}
	assertNoDeviceSyncImportResidue(t, ctx, pool, principalID)

	tamperedState := append([]byte(nil), stateArtifact...)
	tamperedState[0] ^= 0x01
	if _, err := store.ImportPreparedDeviceSyncMigrationStandby(
		ctx, targetDeploymentID, preparation, snapshot,
		fixture.AuthorityAnchor, initial, 3_000,
		postgresstore.DeviceSyncMigrationStagedArtifacts{
			ServiceState:  bytes.NewReader(tamperedState),
			BlobInventory: bytes.NewReader(blobInventory),
		},
	); err == nil {
		t.Fatal("tampered Device Sync migration state artifact was accepted")
	}
	assertNoDeviceSyncImportResidue(t, ctx, pool, principalID)

	imported, err := store.ImportPreparedDeviceSyncMigrationStandby(
		ctx, targetDeploymentID, preparation, snapshot,
		fixture.AuthorityAnchor, initial, 3_000,
		postgresstore.DeviceSyncMigrationStagedArtifacts{
			ServiceState:  bytes.NewReader(stateArtifact),
			BlobInventory: bytes.NewReader(blobInventory),
		},
	)
	if err != nil || imported.PrincipalID != principalID ||
		imported.MigrationID != snapshotPayload.MigrationID ||
		imported.ImportingDeploymentID != targetDeploymentID ||
		imported.ExportingDeploymentID != prepared.ActiveDeployment.DeploymentID ||
		imported.StateCommitmentDigest != snapshotPayload.StateCommitmentDigest {
		t.Fatalf("imported=%+v err=%v", imported, err)
	}
	state, err := store.GetDeviceSyncScopeEnforcement(ctx, principalID)
	if err != nil || state.State != postgresstore.DeviceSyncScopeStandby ||
		state.LocalDeploymentID == nil ||
		*state.LocalDeploymentID != targetDeploymentID || state.Authority == nil ||
		state.Authority.ActiveDeploymentID != prepared.ActiveDeployment.DeploymentID ||
		state.ActiveMigrationImportID == nil ||
		*state.ActiveMigrationImportID != snapshotPayload.MigrationID {
		t.Fatalf("prepared-target standby=%+v err=%v", state, err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE relay_tenants SET updated_at=now() WHERE tenant_id=$1
	`, principalID); err == nil || !strings.Contains(
		err.Error(), "not writable in this transaction",
	) {
		t.Fatalf("prepared-target standby allowed a semantic write: %v", err)
	}

	// Exact durable retries do not re-run semantic import and remain recoverable
	// after both the snapshot and target offer have expired.
	retried, err := store.ImportPreparedDeviceSyncMigrationStandby(
		ctx, targetDeploymentID, preparation, snapshot,
		fixture.AuthorityAnchor, initial, 20_001,
		postgresstore.DeviceSyncMigrationStagedArtifacts{},
	)
	if err != nil ||
		retried.ImportedAtMilliseconds != imported.ImportedAtMilliseconds ||
		retried.SnapshotReferenceDigest != imported.SnapshotReferenceDigest {
		t.Fatalf("expired exact retry=%+v err=%v", retried, err)
	}
	conflictingInitial := initial
	conflictingInitial.ValidatedAtMilliseconds = 1_200
	if _, err := store.ImportPreparedDeviceSyncMigrationStandby(
		ctx, targetDeploymentID, preparation, snapshot,
		fixture.AuthorityAnchor, conflictingInitial, 20_001,
		postgresstore.DeviceSyncMigrationStagedArtifacts{},
	); !errors.Is(err, postgresstore.ErrDeviceSyncMigrationImportConflict) {
		t.Fatalf("conflicting retry err=%v", err)
	}

	if _, err := pool.Exec(ctx, `
		UPDATE device_sync_migration_imports
		SET state_commitment_digest=$2
		WHERE principal_id=$1
	`, principalID, strings.Repeat("e", 64)); err == nil ||
		!strings.Contains(err.Error(), "is immutable") {
		t.Fatalf("mutable import evidence error=%v", err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE device_sync_scope_enforcement
		SET transition_evidence_digest=$2
		WHERE principal_id=$1
	`, principalID, strings.Repeat("e", 64)); err == nil {
		t.Fatal("prepared-target standby accepted conflicting transition evidence")
	}
	if _, err := pool.Exec(ctx, `
		UPDATE device_sync_scope_enforcement
		SET active_migration_import_id=$2
		WHERE principal_id=$1
	`, principalID, uuid.New()); err == nil {
		t.Fatal("prepared-target standby accepted an unknown import identity")
	}

	sharedSpaceTenantID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO relay_tenants (
			tenant_id,version,provisioning_retry_id,
			provisioning_authorization_digest,created_at_milliseconds,
			maximum_domain_count,maximum_aggregate_message_count,
			maximum_aggregate_message_byte_count,maximum_aggregate_blob_count,
			maximum_aggregate_blob_byte_count
		) VALUES ($1,1,$2,$3,1000,1,1,1,1,1)
	`, sharedSpaceTenantID, uuid.New(), strings.Repeat("a", 64)); err != nil {
		t.Fatalf("insert Shared Spaces relay tenant: %v", err)
	}
	if result, err := pool.Exec(ctx, `
		DELETE FROM relay_tenants WHERE tenant_id=$1
	`, sharedSpaceTenantID); err != nil || result.RowsAffected() != 1 {
		t.Fatalf(
			"Shared Spaces relay tenant deletion affected=%d err=%v",
			result.RowsAffected(), err,
		)
	}
}

func signPostgresPreparedDeviceSyncMigrationSnapshot(
	t *testing.T,
	preparation serviceauthority.MigrationPreparation,
	anchor serviceauthority.TrustAnchor,
	signer *serviceauthority.DeploymentSigner,
	payload serviceauthority.MigrationSnapshotPayload,
) serviceauthority.MigrationSnapshot {
	t.Helper()
	current, err := preparation.CurrentManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	currentDigest, err := preparation.CurrentManifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	bindingPath := filepath.Join(t.TempDir(), "bindings.json")
	if err := os.WriteFile(
		bindingPath, []byte(`{"bindings":[],"version":1}`), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	registry, err := serviceauthority.LoadBindingRegistry(
		bindingPath, current.ActiveDeployment.DeploymentID,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.Close() })
	initialManifest := preparation.CurrentManifest
	if err := registry.Activate(current.Scope, serviceauthority.CurrentBinding{
		Revision:     current.Revision,
		Digest:       currentDigest,
		DeploymentID: current.ActiveDeployment.DeploymentID,
		Manifest:     &initialManifest,
	}); err != nil {
		t.Fatal(err)
	}
	if err := registry.ApplyMigrationPreparation(
		preparation, anchor, 2_200,
	); err != nil {
		t.Fatal(err)
	}
	if err := registry.StageMigrationWriteFence(
		preparation.PreparationManifest, payload, anchor, 3_000,
	); err != nil {
		t.Fatal(err)
	}
	snapshot, err := registry.SignStagedMigrationSnapshotAt(
		current.Scope, signer, 3_000,
	)
	if err != nil {
		t.Fatal(err)
	}
	canonicalPayload, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(snapshot.Payload, canonicalPayload) {
		t.Fatal("signed migration snapshot payload differs from requested canonical payload")
	}
	return snapshot
}

func populatePostgresDeviceSyncMigrationRepresentativeState(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	store *postgresstore.RelayStore,
	authority postgresDeviceSyncAuthority,
	initialDeviceID uuid.UUID,
) {
	t.Helper()
	tenantID := authority.TenantCredential.TenantID
	domainID := authority.ControlDomain.Registration.DomainID
	subscriptionID := authority.ControlDomain.Subscription.SubscriptionID
	publisher := relay.Credential{
		TenantID: tenantID, DomainID: domainID, MemberID: initialDeviceID,
		Token: postgresRelayToken(24),
	}
	secondDeviceID := uuid.New()
	recipient, _ := postgresEnrollDeviceSyncDevice(
		t, ctx, store, authority, secondDeviceID, 1_190,
	)
	carrier, err := testfixture.LoadRelayCarrier()
	if err != nil {
		t.Fatal(err)
	}
	envelope := carrier.Envelope
	envelope.TenantID = tenantID
	envelope.DomainID = domainID
	envelope.MessageID = uuid.New()
	envelope.PublisherMemberID = initialDeviceID
	envelope.CreatedAtMilliseconds = 1_200
	if _, err := store.Publish(ctx, publisher, envelope, 1_200); err != nil {
		t.Fatal(err)
	}
	for _, acknowledgment := range []struct {
		stage relay.AcknowledgmentStage
		at    int64
	}{
		{stage: relay.AcknowledgmentAccepted, at: 1_204},
		{stage: relay.AcknowledgmentApplied, at: 1_205},
	} {
		if _, err := store.Acknowledge(
			ctx, recipient, envelope.MessageID, acknowledgment.stage, acknowledgment.at,
		); err != nil {
			t.Fatal(err)
		}
	}

	blobBytes := []byte("device-sync-migration-representative-blob")
	blobID := relay.BlobID(blobBytes)
	if err := store.PrepareBlobPublish(
		ctx, publisher, blobID, int64(len(blobBytes)), 1_210,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitBlobPublish(
		ctx, publisher, blobID, int64(len(blobBytes)), 1_210,
	); err != nil {
		t.Fatal(err)
	}

	fenceRequest := relay.CheckpointFenceRequest{
		RetryID: uuid.New(), FenceID: uuid.New(), RequestedAtMilliseconds: 1_220,
	}
	fence, err := store.CreateCheckpointFence(ctx, publisher, fenceRequest, 1_220)
	if err != nil {
		t.Fatal(err)
	}
	retainedEnvelope := envelope
	retainedEnvelope.MessageID = uuid.New()
	retainedEnvelope.CreatedAtMilliseconds = 1_221
	if _, err := store.Publish(ctx, publisher, retainedEnvelope, 1_221); err != nil {
		t.Fatal(err)
	}
	candidate := relay.CheckpointCandidate{
		Version: relay.SchemaVersion, RetryID: uuid.New(), CheckpointID: uuid.New(),
		FenceID: fence.FenceID, TenantID: tenantID, DomainID: domainID,
		PublisherSubscriptionID: subscriptionID, KeyEpoch: 1,
		CoveredThroughCursor: fence.BoundaryCursor,
		RetainedMessageIDs:   []uuid.UUID{retainedEnvelope.MessageID},
		RetainedBlobIDs:      []string{blobID}, CreatedAtMilliseconds: 1_230,
	}
	if staged, err := store.StageCheckpoint(
		ctx, publisher, candidate, 1_230,
	); err != nil || staged.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("stage representative checkpoint=%+v err=%v", staged, err)
	}
	activation := relay.CheckpointActivationRequest{
		RetryID: uuid.New(), CheckpointID: candidate.CheckpointID,
		ActivatedAtMilliseconds: 1_240,
	}
	if activated, err := store.ActivateCheckpoint(
		ctx, authority.ControlAdministrationCredential, activation, 1_240,
	); err != nil || activated.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("activate representative checkpoint=%+v err=%v", activated, err)
	}

	uploadID := uuid.New()
	chunkDigest := sha256.Sum256(blobBytes)
	createRetryID := uuid.New()
	finalizeRetryID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO relay_blob_uploads (
			tenant_id,domain_id,upload_id,create_retry_id,subscription_id,
			publisher_member_id,relay_blob_id,byte_count,committed_offset,state,
			created_at_milliseconds,updated_at_milliseconds,
			expires_at_milliseconds,finalized_at_milliseconds
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$8,'finalized',1210,1215,2000,1215)
	`, tenantID, domainID, uploadID, createRetryID, subscriptionID,
		initialDeviceID, blobID, int64(len(blobBytes))); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO relay_blob_upload_chunks (
			tenant_id,domain_id,upload_id,chunk_offset,byte_count,
			chunk_sha256,committed_at_milliseconds
		) VALUES ($1,$2,$3,0,$4,$5,1215)
	`, tenantID, domainID, uploadID, int64(len(blobBytes)),
		hex.EncodeToString(chunkDigest[:])); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO relay_blob_upload_finalizations (
			tenant_id,domain_id,retry_id,upload_id,relay_blob_id,
			byte_count,finalized_at_milliseconds
		) VALUES ($1,$2,$3,$4,$5,$6,1215)
	`, tenantID, domainID, finalizeRetryID, uploadID, blobID,
		int64(len(blobBytes))); err != nil {
		t.Fatal(err)
	}

	requestCredential := devicesync.JoinRequestCredential{
		RequestID: uuid.New(), Token: postgresRelayToken(90),
	}
	pollingDigest, err := devicesync.JoinRequestPollingAuthorizationDigest(requestCredential)
	if err != nil {
		t.Fatal(err)
	}
	pinDigest, err := devicesync.JoinRequestPINAuthorizationDigest("654321")
	if err != nil {
		t.Fatal(err)
	}
	joinRequest := devicesync.JoinRequest{
		Version: devicesync.SchemaVersion, RetryID: uuid.New(),
		RequestID: requestCredential.RequestID, CandidateDeviceID: uuid.New(),
		CandidateBootstrapPublicKey: base64.RawURLEncoding.EncodeToString([]byte("candidate-public-key")),
		PollingAuthorizationDigest:  pollingDigest, PINAuthorizationDigest: pinDigest,
		CreatedAtMilliseconds: 1_250,
		ExpiresAtMilliseconds: 1_250 + devicesync.MinimumJoinRequestLifetimeMilliseconds,
	}
	if created, err := store.CreateJoinRequest(
		ctx, joinRequest, 1_250,
	); err != nil || created.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("create representative join request=%+v err=%v", created, err)
	}
	bootstrap := devicesync.JoinBootstrapEnvelope{
		Version: devicesync.SchemaVersion, RequestID: joinRequest.RequestID,
		Algorithm: "test", EphemeralPublicKey: base64.RawURLEncoding.EncodeToString([]byte("ephemeral")),
		Nonce:                 base64.RawURLEncoding.EncodeToString([]byte("nonce")),
		Ciphertext:            base64.RawURLEncoding.EncodeToString([]byte("ciphertext")),
		AuthenticationTag:     base64.RawURLEncoding.EncodeToString([]byte("tag")),
		CreatedAtMilliseconds: 1_260, ExpiresAtMilliseconds: joinRequest.ExpiresAtMilliseconds,
	}
	if acceptance, err := store.StoreJoinRequestBootstrap(
		ctx, authority.ControlAdministrationCredential, bootstrap, 1_260,
	); err != nil || acceptance != relay.AcceptanceAccepted {
		t.Fatalf("store representative join bootstrap=%q err=%v", acceptance, err)
	}

	revocation := devicesync.DeviceRevocation{
		Version: devicesync.SchemaVersion, RetryID: uuid.New(),
		PrincipalID: tenantID, DeviceID: secondDeviceID,
	}
	if revoked, err := store.RevokeDevice(
		ctx, authority.TenantCredential, revocation, 1_280,
	); err != nil || revoked.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("revoke representative Device Sync device=%+v err=%v", revoked, err)
	}

	rebootstrap := relay.SubscriptionRebootstrapRequest{
		RetryID: uuid.New(), RequestedAtMilliseconds: 1_290,
	}
	if requested, err := store.RequestSubscriptionRebootstrap(
		ctx, publisher, rebootstrap, 1_290,
	); err != nil || requested.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("request representative rebootstrap=%+v err=%v", requested, err)
	}

	if _, err := pool.Exec(ctx, `
		INSERT INTO relay_audit_events (
			tenant_id,domain_id,event_type,occurred_at_milliseconds
		) VALUES ($1,$2,'migration_tied_event',1300),
		         ($1,$2,'migration_tied_event',1300)
	`, tenantID, domainID); err != nil {
		t.Fatal(err)
	}
}

func assertNoDeviceSyncImportResidue(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	principalID uuid.UUID,
) {
	t.Helper()
	var count int
	if err := pool.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM relay_tenants WHERE tenant_id=$1) +
			(SELECT count(*) FROM device_sync_principals WHERE principal_id=$1) +
			(SELECT count(*) FROM device_sync_scope_enforcement WHERE principal_id=$1) +
			(SELECT count(*) FROM device_sync_migration_imports WHERE principal_id=$1)
	`, principalID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("failed import left %d durable scope rows", count)
	}
}
