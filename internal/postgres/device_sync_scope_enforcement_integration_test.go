package postgres_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/devicesync"
	postgresstore "github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

type postgresDeviceSyncEnforcementFixture struct {
	AuthorityAnchor           serviceauthority.TrustAnchor `json:"authorityAnchor"`
	PreparationEvidenceDigest string                       `json:"preparationEvidenceDigest"`
	RollbackEvidence          struct {
		ActivationEvidence struct {
			Preparation struct {
				CurrentManifest     serviceauthority.Manifest `json:"currentManifest"`
				PreparationManifest serviceauthority.Manifest `json:"preparationManifest"`
			} `json:"preparation"`
			Snapshot serviceauthority.MigrationSnapshot `json:"snapshot"`
		} `json:"activationEvidence"`
	} `json:"rollbackEvidence"`
}

func TestPostgresDeviceSyncScopeAuthorityAndExportFenceAreAtomic(t *testing.T) {
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
	currentManifest := fixture.RollbackEvidence.ActivationEvidence.
		Preparation.CurrentManifest
	currentPayload, err := currentManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	principalID := currentPayload.Scope.ScopeID
	localSigner := postgresFixtureDeploymentSigner(t, currentPayload.ActiveDeployment)
	initialAuthority := postgresInitialServiceAuthorityBinding(
		t, fixture, currentManifest, localSigner, 1_100,
	)
	store := postgresstore.NewRelayStore(pool)
	bootstrap := postgresBootstrapDeviceSyncPrincipal(
		t, ctx, store, principalID, uuid.New(), 1_100, initialAuthority,
	)
	clockRollbackRetry, err := store.ClaimAccountAdmissionWithAuthority(
		ctx, bootstrap.AdmissionCredential, bootstrap.PrincipalProvisioning,
		initialAuthority, 1_000,
	)
	if err != nil || clockRollbackRetry.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf(
			"clock-rollback exact durable claim retry=%+v err=%v",
			clockRollbackRetry, err,
		)
	}
	retryAuthority := postgresInitialServiceAuthorityBinding(
		t, fixture, currentManifest, localSigner, 2_100,
	)
	claimRetry, err := store.ClaimAccountAdmissionWithAuthority(
		ctx, bootstrap.AdmissionCredential, bootstrap.PrincipalProvisioning,
		retryAuthority, 2_100,
	)
	if err != nil || claimRetry.Acceptance != relay.AcceptanceDuplicate {
		t.Fatalf("expired-offer exact durable claim retry=%+v err=%v", claimRetry, err)
	}

	state, err := store.GetDeviceSyncScopeEnforcement(ctx, principalID)
	if err != nil || state.State != postgresstore.DeviceSyncScopeStandby ||
		state.Authority == nil || state.TenantID != principalID ||
		state.LocalDeploymentID == nil ||
		*state.LocalDeploymentID != localSigner.DeploymentID() {
		t.Fatalf("bound standby state=%+v err=%v", state, err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE relay_tenants SET updated_at=now() WHERE tenant_id=$1
	`, principalID); err == nil || !strings.Contains(
		err.Error(),
		"not writable in this transaction",
	) {
		t.Fatalf("older standby row permitted a direct mutation: %v", err)
	}
	standbyTouch, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := standbyTouch.Exec(ctx, `
		UPDATE device_sync_scope_enforcement
		SET updated_at=now()
		WHERE principal_id=$1
	`, principalID); err != nil {
		_ = standbyTouch.Rollback(ctx)
		t.Fatal(err)
	}
	if _, err := standbyTouch.Exec(ctx, `
		UPDATE relay_tenants SET updated_at=now() WHERE tenant_id=$1
	`, principalID); err != nil {
		_ = standbyTouch.Rollback(ctx)
		t.Fatal(err)
	}
	if err := standbyTouch.Commit(ctx); err == nil || !strings.Contains(
		err.Error(),
		"not writable in this transaction",
	) {
		t.Fatalf("touching old standby authority bypassed the write fence: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		DELETE FROM device_sync_scope_enforcement WHERE principal_id=$1
	`, principalID); err == nil || !strings.Contains(
		err.Error(),
		"scope enforcement row cannot be deleted",
	) {
		t.Fatalf("standby enforcement row deletion=%v", err)
	}
	// This exact state flip remains repairable after deployment-offer expiry.
	if err := store.ActivateBoundDeviceSyncScope(
		ctx, principalID, localSigner.DeploymentID(), initialAuthority.Revision(),
		initialAuthority.ManifestDigest(), 2_100,
	); err != nil {
		t.Fatal(err)
	}
	if err := store.ActivateBoundDeviceSyncScope(
		ctx, principalID, localSigner.DeploymentID(), initialAuthority.Revision(),
		initialAuthority.ManifestDigest(), 2_200,
	); err != nil {
		t.Fatalf("exact bound activation retry: %v", err)
	}

	preparationManifest := fixture.RollbackEvidence.ActivationEvidence.
		Preparation.PreparationManifest
	preparationPayload, err := preparationManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AdvanceDeviceSyncWritableAuthority(
		ctx, principalID, localSigner.DeploymentID(), preparationManifest,
		&fixture.PreparationEvidenceDigest, 2_200,
	); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvanceDeviceSyncWritableAuthority(
		ctx, principalID, localSigner.DeploymentID(), preparationManifest,
		&fixture.PreparationEvidenceDigest, 9_999,
	); err != nil {
		t.Fatalf("exact authority successor retry: %v", err)
	}
	preparationDigest, err := preparationManifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}

	callbackCount := 0
	snapshotPayload := fixture.RollbackEvidence.ActivationEvidence.Snapshot.Payload
	var snapshot serviceauthority.MigrationSnapshotPayload
	if err := json.Unmarshal(snapshotPayload, &snapshot); err != nil {
		t.Fatal(err)
	}
	materialize := func(
		_ context.Context,
		readTx postgresstore.DeviceSyncSnapshotReadTransaction,
		locked postgresstore.DeviceSyncScopeEnforcement,
	) ([]byte, error) {
		callbackCount++
		var storedState string
		if err := readTx.QueryRow(ctx, `
			SELECT state FROM device_sync_scope_enforcement
			WHERE principal_id=$1
		`, principalID).Scan(&storedState); err != nil {
			return nil, err
		}
		if storedState != string(locked.State) {
			return nil, errors.New("materializer did not observe locked state")
		}
		return append([]byte(nil), snapshotPayload...), nil
	}
	if _, err := store.MaterializeAndFenceDeviceSyncMigrationExport(
		ctx, principalID, localSigner.DeploymentID(), preparationPayload.Revision,
		preparationDigest, snapshot.MigrationID, snapshot.ExportWriteFenceID,
		1_999, materialize,
	); err == nil || callbackCount != 0 {
		t.Fatalf("stale authority export error=%v callbacks=%d", err, callbackCount)
	}
	if _, err := store.MaterializeAndFenceDeviceSyncMigrationExport(
		ctx, principalID, uuid.New(), preparationPayload.Revision,
		preparationDigest, snapshot.MigrationID, snapshot.ExportWriteFenceID,
		2_500, materialize,
	); err == nil || callbackCount != 0 {
		t.Fatalf("wrong deployment export error=%v callbacks=%d", err, callbackCount)
	}
	callbackFailure := errors.New("snapshot materialization failed")
	if _, err := store.MaterializeAndFenceDeviceSyncMigrationExport(
		ctx, principalID, localSigner.DeploymentID(), preparationPayload.Revision,
		preparationDigest, snapshot.MigrationID, snapshot.ExportWriteFenceID,
		2_500,
		func(
			_ context.Context,
			readTx postgresstore.DeviceSyncSnapshotReadTransaction,
			locked postgresstore.DeviceSyncScopeEnforcement,
		) ([]byte, error) {
			callbackCount++
			var storedState string
			if err := readTx.QueryRow(ctx, `
				SELECT state FROM device_sync_scope_enforcement
				WHERE principal_id=$1
			`, principalID).Scan(&storedState); err != nil {
				return nil, err
			}
			if storedState != string(postgresstore.DeviceSyncScopeWritable) ||
				locked.State != postgresstore.DeviceSyncScopeWritable {
				return nil, errors.New("callback ran before writable row lock")
			}
			return nil, callbackFailure
		},
	); !errors.Is(err, callbackFailure) || callbackCount != 1 {
		t.Fatalf("callback failure=%v callbacks=%d", err, callbackCount)
	}
	state, err = store.GetDeviceSyncScopeEnforcement(ctx, principalID)
	if err != nil || state.State != postgresstore.DeviceSyncScopeWritable {
		t.Fatalf("callback failure changed state=%+v err=%v", state, err)
	}

	createdExport, err := store.MaterializeAndFenceDeviceSyncMigrationExport(
		ctx, principalID, localSigner.DeploymentID(), preparationPayload.Revision,
		preparationDigest, snapshot.MigrationID, snapshot.ExportWriteFenceID,
		2_500, materialize,
	)
	if err != nil || callbackCount != 2 ||
		!bytes.Equal(createdExport.CanonicalSnapshotPayload, snapshotPayload) ||
		createdExport.MigrationID != snapshot.MigrationID ||
		createdExport.ExportWriteFenceID != snapshot.ExportWriteFenceID {
		t.Fatalf("materialize and fence err=%v callbacks=%d", err, callbackCount)
	}
	recoveredExport, err := store.MaterializeAndFenceDeviceSyncMigrationExport(
		ctx, principalID, localSigner.DeploymentID(), preparationPayload.Revision,
		preparationDigest, snapshot.MigrationID, snapshot.ExportWriteFenceID,
		10_000, materialize,
	)
	if err != nil || callbackCount != 2 ||
		!bytes.Equal(recoveredExport.CanonicalSnapshotPayload, snapshotPayload) ||
		recoveredExport.SnapshotPayloadSHA256 != createdExport.SnapshotPayloadSHA256 {
		t.Fatalf("exact export retry err=%v callbacks=%d", err, callbackCount)
	}
	if _, err := store.MaterializeAndFenceDeviceSyncMigrationExport(
		ctx, principalID, localSigner.DeploymentID(), preparationPayload.Revision,
		preparationDigest, snapshot.MigrationID, snapshot.ExportWriteFenceID,
		10_001, nil,
	); err != nil || callbackCount != 2 {
		t.Fatalf("nil-materializer export recovery err=%v callbacks=%d", err, callbackCount)
	}

	state, err = store.GetDeviceSyncScopeEnforcement(ctx, principalID)
	if err != nil || state.State != postgresstore.DeviceSyncScopeExportFenced ||
		state.ActiveExportWriteFenceID == nil {
		t.Fatalf("fenced state=%+v err=%v", state, err)
	}
	if _, err := pool.Exec(ctx, `
		DELETE FROM device_sync_principals WHERE principal_id=$1
	`, principalID); err == nil || !strings.Contains(
		err.Error(),
		"cannot be deleted",
	) {
		t.Fatalf("fenced Device Sync principal deletion=%v", err)
	}
	if _, err := pool.Exec(ctx, `
		DELETE FROM relay_tenants WHERE tenant_id=$1
	`, principalID); err == nil || !strings.Contains(
		err.Error(),
		"cannot be deleted",
	) {
		t.Fatalf("fenced Device Sync tenant deletion=%v", err)
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
	var storedPayload []byte
	var storedDigest, storedCommitment string
	if err := pool.QueryRow(ctx, `
		SELECT canonical_snapshot_payload,snapshot_payload_sha256,
			state_commitment_digest
		FROM device_sync_migration_exports
		WHERE principal_id=$1 AND tenant_id=$1 AND export_write_fence_id=$2
	`, principalID, *state.ActiveExportWriteFenceID).Scan(
		&storedPayload, &storedDigest, &storedCommitment,
	); err != nil {
		t.Fatal(err)
	}
	snapshotDigest := sha256.Sum256(snapshotPayload)
	if !bytes.Equal(storedPayload, snapshotPayload) ||
		storedDigest != hex.EncodeToString(snapshotDigest[:]) ||
		storedCommitment != snapshot.StateCommitmentDigest {
		t.Fatal("PostgreSQL changed or mismatched exact export evidence")
	}

	if _, err := store.MaterializeAndFenceDeviceSyncMigrationExport(
		ctx, principalID, localSigner.DeploymentID(), preparationPayload.Revision,
		preparationDigest, uuid.New(), snapshot.ExportWriteFenceID, 10_001,
		func(context.Context, postgresstore.DeviceSyncSnapshotReadTransaction,
			postgresstore.DeviceSyncScopeEnforcement) ([]byte, error) {
			callbackCount++
			return snapshotPayload, nil
		},
	); err == nil || errors.Is(err, devicesync.ErrScopeWriteFenced) ||
		callbackCount != 2 {
		t.Fatalf("conflicting migration retry error=%v callbacks=%d", err, callbackCount)
	}

	if _, err := store.MaterializeAndFenceDeviceSyncMigrationExport(
		ctx, principalID, localSigner.DeploymentID(), preparationPayload.Revision,
		preparationDigest, snapshot.MigrationID, uuid.New(), 10_001,
		func(context.Context, postgresstore.DeviceSyncSnapshotReadTransaction,
			postgresstore.DeviceSyncScopeEnforcement) ([]byte, error) {
			callbackCount++
			return snapshotPayload, nil
		},
	); !errors.Is(err, devicesync.ErrScopeWriteFenced) || callbackCount != 2 {
		t.Fatalf("different fence retry error=%v callbacks=%d", err, callbackCount)
	}

	if _, err := pool.Exec(ctx, `
		UPDATE device_sync_migration_exports
		SET state_commitment_digest=$3
		WHERE principal_id=$1 AND export_write_fence_id=$2
	`, principalID, *state.ActiveExportWriteFenceID,
		"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
	); err == nil {
		t.Fatal("immutable migration export accepted an update")
	}
	if _, err := pool.Exec(ctx, `
		UPDATE device_sync_scope_enforcement
		SET initial_authority_manifest_digest=$2
		WHERE principal_id=$1
	`, principalID,
		"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
	); err == nil {
		t.Fatal("immutable initial authority accepted an update")
	}
	if _, err := pool.Exec(ctx, `
		UPDATE device_sync_scope_enforcement
		SET active_export_write_fence_id=$2
		WHERE principal_id=$1
	`, principalID, uuid.New()); err == nil {
		t.Fatal("active fence accepted a non-existent export record")
	}
}

func postgresInitialServiceAuthorityBinding(
	t *testing.T,
	fixture postgresDeviceSyncEnforcementFixture,
	manifest serviceauthority.Manifest,
	localSigner *serviceauthority.DeploymentSigner,
	nowMilliseconds int64,
) *devicesync.InitialServiceAuthorityBinding {
	t.Helper()
	payload, err := manifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	offer, err := localSigner.SignDeploymentOffer(
		serviceauthority.DeploymentOfferPayload{
			Deployment:            payload.ActiveDeployment,
			ExpiresAtMilliseconds: 2_000,
			IssuedAtMilliseconds:  900,
			TransportPolicy:       payload.TransportPolicy,
			Version:               serviceauthority.SchemaVersion,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := devicesync.NewInitialServiceAuthorityBinding(
		serviceauthority.InitialEnrollment{
			Anchor: fixture.AuthorityAnchor, DeploymentOffer: offer,
			Manifest: manifest, Version: serviceauthority.SchemaVersion,
		},
		localSigner, payload.Scope, nowMilliseconds,
	)
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func postgresFixtureDeploymentSigner(
	t *testing.T,
	descriptor serviceauthority.DeploymentDescriptor,
) *serviceauthority.DeploymentSigner {
	t.Helper()
	for candidate := 1; candidate <= 255; candidate++ {
		scalar := make([]byte, 32)
		scalar[31] = byte(candidate)
		signer, err := serviceauthority.NewDeploymentSigner(
			descriptor.DeploymentID, scalar,
		)
		if err == nil && signer.PublicSigningKeyX963() ==
			descriptor.PublicSigningKeyX963 &&
			signer.SigningKeyFingerprint() == descriptor.SigningKeyFingerprint {
			return signer
		}
	}
	t.Fatal("fixture deployment signer was not found")
	return nil
}

func loadPostgresDeviceSyncEnforcementFixture(
	t *testing.T,
) postgresDeviceSyncEnforcementFixture {
	t.Helper()
	contents, err := os.ReadFile("../serviceauthority/testdata/service-migration-portable-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture postgresDeviceSyncEnforcementFixture
	if err := json.Unmarshal(contents, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}
