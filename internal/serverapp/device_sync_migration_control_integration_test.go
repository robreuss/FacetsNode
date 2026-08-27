package serverapp

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
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/robreuss/FacetsNode/internal/devicesync"
	"github.com/robreuss/FacetsNode/internal/migrationcoordinator"
	"github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
	"github.com/robreuss/FacetsNode/internal/testfixture"
)

// TestLiveDeviceSyncAttendedMigrationAndRollback is deliberately opt-in. It
// drives the production control-stage methods across two independent
// PostgreSQL databases, binding registries, deployment keys, custody roots,
// and blob roots. The databases must be disposable.
func TestLiveDeviceSyncAttendedMigrationAndRollback(t *testing.T) {
	sourceDatabaseURL := os.Getenv("FACETS_SERVER_TEST_MIGRATION_SOURCE_DATABASE_URL")
	targetDatabaseURL := os.Getenv("FACETS_SERVER_TEST_MIGRATION_TARGET_DATABASE_URL")
	if sourceDatabaseURL == "" || targetDatabaseURL == "" {
		t.Skip("FACETS_SERVER_TEST_MIGRATION_SOURCE_DATABASE_URL and FACETS_SERVER_TEST_MIGRATION_TARGET_DATABASE_URL are not set")
	}
	if sourceDatabaseURL == targetDatabaseURL {
		t.Fatal("migration acceptance requires two independent PostgreSQL databases")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	fixture := loadLiveMigrationControlFixture(t)
	preparation := fixture.RollbackEvidence.ActivationEvidence.Preparation
	current, err := preparation.CurrentManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := preparation.PreparationManifest.VerifiedPayload()
	if err != nil || prepared.Migration == nil || len(prepared.PreparedDeployments) != 1 {
		t.Fatalf("prepared authority=%+v err=%v", prepared, err)
	}
	sourceSigner := liveMigrationDeploymentSigner(t, current.ActiveDeployment)
	targetSigner := liveMigrationDeploymentSigner(t, prepared.PreparedDeployments[0])
	source := newLiveMigrationControlRuntime(
		t, ctx, sourceDatabaseURL, sourceSigner, current.ActiveDeployment, "source",
	)
	defer func() {
		if err := source.close(); err != nil {
			t.Errorf("close source runtime: %v", err)
		}
	}()
	target := newLiveMigrationControlRuntime(
		t, ctx, targetDatabaseURL, targetSigner, prepared.PreparedDeployments[0], "target",
	)
	defer func() {
		if err := target.close(); err != nil {
			t.Errorf("close target runtime: %v", err)
		}
	}()

	principalID := current.Scope.ScopeID
	initialDeviceID := uuid.New()
	initialBinding := liveInitialDeviceSyncBinding(
		t, fixture, preparation.CurrentManifest, sourceSigner, 1_100,
	)
	authority := liveBootstrapDeviceSyncPrincipal(
		t, ctx, source.store, principalID, initialDeviceID, initialBinding, 1_100,
	)
	initialManifest := initialBinding.Manifest()
	if err := source.bindings.Activate(current.Scope, serviceauthority.CurrentBinding{
		Revision: initialBinding.Revision(), Digest: initialBinding.ManifestDigest(),
		DeploymentID: sourceSigner.DeploymentID(), Manifest: &initialManifest,
	}); err != nil {
		t.Fatal(err)
	}
	if err := source.store.ActivateBoundDeviceSyncScope(
		ctx, principalID, sourceSigner.DeploymentID(), initialBinding.Revision(),
		initialBinding.ManifestDigest(), 1_100,
	); err != nil {
		t.Fatal(err)
	}

	firstMessageID := livePublishDeviceSyncMessage(
		t, ctx, source.store, authority.Publisher, principalID,
		authority.DomainID, initialDeviceID, 1_200,
	)
	firstBlob := []byte("attended-migration-source-blob")
	firstBlobID := livePublishDeviceSyncBlob(
		t, ctx, source.store, source.blobs, authority.Publisher,
		principalID, authority.DomainID, firstBlob, 1_210,
	)

	forwardBundle := filepath.Join(t.TempDir(), "forward-bundle")
	forwardResponse, err := source.prepareSource(
		ctx,
		deviceSyncMigrationSourceRequest{
			Anchor:                  fixture.AuthorityAnchor,
			BlobInventoryArtifactID: uuid.New(), ExportWriteFenceID: uuid.New(),
			Preparation: preparation, ServiceStateArtifactID: uuid.New(),
			SnapshotID: uuid.New(), Version: deviceSyncMigrationControlVersion,
		},
		forwardBundle,
		time.UnixMilli(2_200),
	)
	if err != nil || forwardResponse.Bundle == nil || !forwardResponse.WriteFenced ||
		forwardResponse.State != postgres.DeviceSyncScopeExportFenced ||
		forwardResponse.Bundle.BlobCount != 1 {
		t.Fatalf("source preparation=%+v err=%v", forwardResponse, err)
	}
	targetResponse, err := target.prepareTarget(
		ctx, forwardBundle, time.UnixMilli(2_500),
	)
	if err != nil || targetResponse.Readiness == nil ||
		targetResponse.State != postgres.DeviceSyncScopeStandby ||
		targetResponse.BlobCount != 1 {
		t.Fatalf("target preparation=%+v err=%v", targetResponse, err)
	}
	assertLiveMigrationBlob(
		t, ctx, target.blobs, principalID, authority.DomainID, firstBlobID, firstBlob,
	)

	activation := liveMigrationActivation(
		t, fixture, preparation, forwardResponse.Snapshot,
		*targetResponse.Readiness, 3_000,
	)
	for label, runtime := range map[string]*deviceSyncMigrationControlRuntime{
		"source": source, "target": target,
	} {
		response, err := runtime.activate(
			ctx,
			deviceSyncMigrationActivationRequest{
				Anchor: fixture.AuthorityAnchor, Evidence: activation,
				Version: deviceSyncMigrationControlVersion,
			},
			time.UnixMilli(3_000),
		)
		if err != nil || response.AuthorityRevision != 3 {
			t.Fatalf("%s activation=%+v err=%v", label, response, err)
		}
		if label == "source" && (!response.WriteFenced ||
			response.State != postgres.DeviceSyncScopeRetired) {
			t.Fatalf("source activation did not retire source: %+v", response)
		}
		if label == "target" && (response.WriteFenced ||
			response.State != postgres.DeviceSyncScopeWritable) {
			t.Fatalf("target activation did not enable target: %+v", response)
		}
	}

	secondMessageID := livePublishDeviceSyncMessage(
		t, ctx, target.store, authority.Publisher, principalID,
		authority.DomainID, initialDeviceID, 3_200,
	)
	secondBlob := []byte("attended-migration-target-only-blob")
	secondBlobID := livePublishDeviceSyncBlob(
		t, ctx, target.store, target.blobs, authority.Publisher,
		principalID, authority.DomainID, secondBlob, 3_210,
	)
	targetStateBeforeRollback, targetInventoryBeforeRollback :=
		exportLiveMigrationState(t, ctx, target.pool, principalID)

	reverseBundle := filepath.Join(t.TempDir(), "rollback-bundle")
	reverseResponse, err := target.prepareRollbackSource(
		ctx,
		deviceSyncMigrationRollbackSourceRequest{
			ActivationEvidence: activation, Anchor: fixture.AuthorityAnchor,
			BlobInventoryArtifactID: uuid.New(), ExportWriteFenceID: uuid.New(),
			ServiceStateArtifactID: uuid.New(), SnapshotID: uuid.New(),
			Version: deviceSyncMigrationControlVersion,
		},
		reverseBundle,
		time.UnixMilli(3_500),
	)
	if err != nil || reverseResponse.Snapshot == nil ||
		reverseResponse.Bundle == nil || reverseResponse.Bundle.BlobCount != 2 ||
		reverseResponse.State != postgres.DeviceSyncScopeExportFenced {
		t.Fatalf("rollback source preparation=%+v err=%v", reverseResponse, err)
	}
	rollbackTargetResponse, err := source.prepareRollbackTarget(
		ctx, reverseBundle, time.UnixMilli(3_700),
	)
	if err != nil || rollbackTargetResponse.Readiness == nil ||
		rollbackTargetResponse.State != postgres.DeviceSyncScopeRollbackStandby ||
		rollbackTargetResponse.BlobCount != 2 {
		t.Fatalf("rollback target preparation=%+v err=%v", rollbackTargetResponse, err)
	}
	sourceStandbyState, sourceStandbyInventory :=
		exportLiveMigrationState(t, ctx, source.pool, principalID)
	if !bytes.Equal(sourceStandbyState, targetStateBeforeRollback) ||
		!bytes.Equal(sourceStandbyInventory, targetInventoryBeforeRollback) {
		t.Fatal("rollback standby did not exactly reproduce the target database state")
	}
	assertLiveMigrationBlob(
		t, ctx, source.blobs, principalID, authority.DomainID, firstBlobID, firstBlob,
	)
	assertLiveMigrationBlob(
		t, ctx, source.blobs, principalID, authority.DomainID, secondBlobID, secondBlob,
	)

	rollbackEvidence := liveMigrationRollback(
		t, fixture, activation, *reverseResponse.Snapshot,
		*rollbackTargetResponse.Readiness, 3_900,
	)
	for label, runtime := range map[string]*deviceSyncMigrationControlRuntime{
		"source": source, "target": target,
	} {
		response, err := runtime.rollback(
			ctx,
			deviceSyncMigrationRollbackRequest{
				Anchor: fixture.AuthorityAnchor, Evidence: rollbackEvidence,
				Version: deviceSyncMigrationControlVersion,
			},
			time.UnixMilli(3_900),
		)
		if err != nil || response.AuthorityRevision != 4 {
			t.Fatalf("%s rollback=%+v err=%v", label, response, err)
		}
		if label == "source" && (response.WriteFenced ||
			response.State != postgres.DeviceSyncScopeWritable) {
			t.Fatalf("source rollback did not restore writes: %+v", response)
		}
		if label == "target" && (!response.WriteFenced ||
			response.State != postgres.DeviceSyncScopeRetired) {
			t.Fatalf("target rollback did not retire replacement: %+v", response)
		}
	}

	for _, messageID := range []uuid.UUID{firstMessageID, secondMessageID} {
		var count int
		if err := source.pool.QueryRow(ctx, `
			SELECT count(*) FROM relay_messages
			WHERE tenant_id=$1 AND message_id=$2
		`, principalID, messageID).Scan(&count); err != nil || count != 1 {
			t.Fatalf("rolled-back source message %s count=%d err=%v", messageID, count, err)
		}
	}
	// Exact terminal retries are required for attended recovery after response
	// loss; they must not create another authority successor.
	if response, err := source.rollback(
		ctx,
		deviceSyncMigrationRollbackRequest{
			Anchor: fixture.AuthorityAnchor, Evidence: rollbackEvidence,
			Version: deviceSyncMigrationControlVersion,
		},
		time.UnixMilli(4_000),
	); err != nil || response.AuthorityRevision != 4 || response.WriteFenced {
		t.Fatalf("completed rollback retry=%+v err=%v", response, err)
	}
	settlement := liveMigrationRollbackSettlement(
		t, fixture, rollbackEvidence.RollbackManifest, 4_100,
	)
	settlementRequest := deviceSyncMigrationRollbackSettlementRequest{
		Anchor:          fixture.AuthorityAnchor,
		CurrentManifest: rollbackEvidence.RollbackManifest,
		Successor:       settlement,
		Version:         deviceSyncMigrationControlVersion,
	}
	writeRetainedMigrationControlRequest(t, "source", settlementRequest)
	if response, err := target.settleRollback(
		ctx, settlementRequest, time.UnixMilli(4_100),
	); err == nil {
		t.Fatalf("retired replacement accepted source settlement: %+v", response)
	}
	settled, err := source.settleRollback(
		ctx, settlementRequest, time.UnixMilli(4_100),
	)
	if err != nil || settled.AuthorityRevision != 5 || settled.WriteFenced ||
		settled.State != postgres.DeviceSyncScopeWritable {
		t.Fatalf("rollback settlement=%+v err=%v", settled, err)
	}
	// The exact completed settlement can repair a lost database response after
	// the bounded rollback Manifest itself expires.
	settled, err = source.settleRollback(
		ctx, settlementRequest, time.UnixMilli(20_000),
	)
	if err != nil || settled.AuthorityRevision != 5 || settled.WriteFenced {
		t.Fatalf("expired settlement retry=%+v err=%v", settled, err)
	}
	finalState, finalInventory := exportLiveMigrationState(t, ctx, source.pool, principalID)
	if !bytes.Equal(finalState, targetStateBeforeRollback) ||
		!bytes.Equal(finalInventory, targetInventoryBeforeRollback) {
		t.Fatal("completed rollback settlement changed the authenticated reverse-transfer state")
	}
}

func writeRetainedMigrationControlRequest(
	t *testing.T,
	deploymentLabel string,
	request any,
) {
	t.Helper()
	root := os.Getenv("FACETS_SERVER_TEST_MIGRATION_ARTIFACT_ROOT")
	if root == "" {
		return
	}
	record, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(
		filepath.Clean(root), deploymentLabel, "rollback-settlement-request.json",
	)
	if err := os.WriteFile(path, record, 0o600); err != nil {
		t.Fatal(err)
	}
}

type liveMigrationControlFixture struct {
	AuthorityAnchor  serviceauthority.TrustAnchor               `json:"authorityAnchor"`
	RollbackEvidence serviceauthority.MigrationRollbackEvidence `json:"rollbackEvidence"`
}

type liveDeviceSyncAuthority struct {
	DomainID  uuid.UUID
	Publisher relay.Credential
}

func loadLiveMigrationControlFixture(t *testing.T) liveMigrationControlFixture {
	t.Helper()
	record, err := os.ReadFile(filepath.Join(
		"..", "serviceauthority", "testdata", "service-migration-portable-v2.json",
	))
	if err != nil {
		t.Fatal(err)
	}
	var fixture liveMigrationControlFixture
	if err := json.Unmarshal(record, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func newLiveMigrationControlRuntime(
	t *testing.T,
	ctx context.Context,
	databaseURL string,
	signer *serviceauthority.DeploymentSigner,
	descriptor serviceauthority.DeploymentDescriptor,
	label string,
) *deviceSyncMigrationControlRuntime {
	t.Helper()
	configuration, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	configuration.MaxConns = 10
	configuration.MinConns = 1
	pool, err := pgxpool.NewWithConfig(ctx, configuration)
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	if err := postgres.Migrate(ctx, pool); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		TRUNCATE device_sync_account_admissions, relay_tenants CASCADE
	`); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	store, err := postgres.NewDeviceSyncAuthorityBoundRelayStore(
		pool, signer.DeploymentID(), 7*24*time.Hour, 2*time.Hour,
	)
	if err != nil {
		pool.Close()
		t.Fatal(err)
	}
	root := t.TempDir()
	if retainedRoot := os.Getenv("FACETS_SERVER_TEST_MIGRATION_ARTIFACT_ROOT"); retainedRoot != "" {
		if !filepath.IsAbs(retainedRoot) {
			pool.Close()
			t.Fatal("FACETS_SERVER_TEST_MIGRATION_ARTIFACT_ROOT must be absolute")
		}
		root = filepath.Join(filepath.Clean(retainedRoot), label)
		if _, err := os.Lstat(root); err == nil || !os.IsNotExist(err) {
			pool.Close()
			t.Fatalf("retained migration acceptance root already exists: %s", root)
		}
		if err := os.MkdirAll(root, 0o700); err != nil {
			pool.Close()
			t.Fatal(err)
		}
	}
	blobs, err := relay.NewFileBlobContentStore(filepath.Join(root, "blobs"))
	if err != nil {
		pool.Close()
		t.Fatal(err)
	}
	bindingPath := filepath.Join(root, "authority", "bindings.json")
	if err := os.MkdirAll(filepath.Dir(bindingPath), 0o700); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	if err := os.WriteFile(
		bindingPath, []byte(`{"bindings":[],"version":1}`), 0o600,
	); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	bindings, err := serviceauthority.LoadBindingRegistry(
		bindingPath, signer.DeploymentID(),
	)
	if err != nil {
		pool.Close()
		t.Fatal(err)
	}
	custody, err := migrationcoordinator.NewFileArtifactCustody(
		filepath.Join(root, "authority", "migration-custody"),
	)
	if err != nil {
		_ = bindings.Close()
		pool.Close()
		t.Fatal(err)
	}
	writeLiveMigrationDeploymentFiles(t, root, signer, descriptor)
	return &deviceSyncMigrationControlRuntime{
		pool: pool, store: store, blobs: blobs, custody: custody,
		bindings: bindings, signer: signer,
	}
}

func writeLiveMigrationDeploymentFiles(
	t *testing.T,
	root string,
	signer *serviceauthority.DeploymentSigner,
	descriptor serviceauthority.DeploymentDescriptor,
) {
	t.Helper()
	seed := liveMigrationDeploymentSeed(t, descriptor)
	keyRecord := base64.RawURLEncoding.EncodeToString(seed) + "\n"
	if err := os.WriteFile(
		filepath.Join(root, "deployment-signing-key"), []byte(keyRecord), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	if signer.DeploymentID() != descriptor.DeploymentID || len(descriptor.Routes) == 0 {
		t.Fatal("migration deployment descriptor does not match signer")
	}
	routeID := descriptor.Routes[0].RouteID
	template := serviceauthority.DeploymentOfferTemplate{
		Deployment: descriptor,
		TransportPolicy: serviceauthority.TransportPolicy{
			BulkRouteIDs: []uuid.UUID{routeID}, ControlRouteIDs: []uuid.UUID{routeID},
			MessageRouteIDs: []uuid.UUID{routeID}, Version: serviceauthority.SchemaVersion,
		},
		Version: serviceauthority.SchemaVersion,
	}
	record, err := json.Marshal(template)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(root, "deployment-routes.json"), record, 0o600,
	); err != nil {
		t.Fatal(err)
	}
}

func liveInitialDeviceSyncBinding(
	t *testing.T,
	fixture liveMigrationControlFixture,
	manifest serviceauthority.Manifest,
	signer *serviceauthority.DeploymentSigner,
	nowMilliseconds int64,
) *devicesync.InitialServiceAuthorityBinding {
	t.Helper()
	payload, err := manifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	offer, err := signer.SignDeploymentOffer(serviceauthority.DeploymentOfferPayload{
		Deployment: payload.ActiveDeployment, ExpiresAtMilliseconds: 1_900,
		IssuedAtMilliseconds: 900, TransportPolicy: payload.TransportPolicy,
		Version: serviceauthority.SchemaVersion,
	})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := devicesync.NewInitialServiceAuthorityBinding(
		serviceauthority.InitialEnrollment{
			Anchor: fixture.AuthorityAnchor, DeploymentOffer: offer,
			Manifest: manifest, Version: serviceauthority.SchemaVersion,
		},
		signer, payload.Scope, nowMilliseconds,
	)
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func liveBootstrapDeviceSyncPrincipal(
	t *testing.T,
	ctx context.Context,
	store *postgres.RelayStore,
	principalID uuid.UUID,
	initialDeviceID uuid.UUID,
	initialBinding *devicesync.InitialServiceAuthorityBinding,
	now int64,
) liveDeviceSyncAuthority {
	t.Helper()
	admissionCredential := devicesync.AdmissionCredential{
		AdmissionID: uuid.New(), Token: liveMigrationToken(1),
	}
	admissionDigest, err := devicesync.AdmissionAuthorizationDigest(admissionCredential)
	if err != nil {
		t.Fatal(err)
	}
	admission := devicesync.AccountAdmission{
		Version: devicesync.SchemaVersion, RetryID: uuid.New(),
		AdmissionID: admissionCredential.AdmissionID, AuthorizationDigest: admissionDigest,
		CreatedAtMilliseconds: now,
		ExpiresAtMilliseconds: now + devicesync.MinimumAdmissionLifetimeMilliseconds,
	}
	if result, err := store.CreateAccountAdmission(ctx, admission, now); err != nil ||
		result.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("create account admission=%+v err=%v", result, err)
	}
	tenantCredential := relay.TenantCredential{
		TenantID: principalID, Token: liveMigrationToken(2),
	}
	tenantDigest, err := relay.TenantAuthorizationDigest(tenantCredential)
	if err != nil {
		t.Fatal(err)
	}
	domainID := uuid.New()
	adminCredential := relay.AdministrationCredential{
		TenantID: principalID, DomainID: domainID, Token: liveMigrationToken(3),
	}
	adminDigest, err := relay.AdministrationDigest(adminCredential)
	if err != nil {
		t.Fatal(err)
	}
	publisher := relay.Credential{
		TenantID: principalID, DomainID: domainID,
		MemberID: initialDeviceID, Token: liveMigrationToken(4),
	}
	publisherDigest, err := relay.AuthorizationDigest(publisher)
	if err != nil {
		t.Fatal(err)
	}
	subscriptionID := uuid.New()
	domain := relay.DomainProvisioning{
		Version: relay.SchemaVersion, RetryID: uuid.New(),
		Registration: relay.DomainRegistration{
			Version: relay.SchemaVersion, TenantID: principalID, DomainID: domainID,
			AdministrationDigest: adminDigest, CreatedAtMilliseconds: now,
			MaximumMessageCount:     relay.DefaultMaximumMessageCount,
			MaximumMessageByteCount: relay.DefaultMaximumMessageByteCount,
			MaximumBlobCount:        relay.DefaultMaximumBlobCount,
			MaximumBlobByteCount:    relay.DefaultMaximumBlobByteCount,
		},
		Subscription: relay.Subscription{
			Version: relay.SchemaVersion, TenantID: principalID, DomainID: domainID,
			SubscriptionID: subscriptionID, Status: relay.SubscriptionActive,
			CreatedAtMilliseconds: now, UpdatedAtMilliseconds: now,
		},
		InitialMember: relay.MemberRegistration{
			Version: relay.SchemaVersion, TenantID: principalID, DomainID: domainID,
			MemberID: initialDeviceID, AuthorizationDigest: publisherDigest,
			Capabilities: []relay.Capability{
				relay.CapabilityFetchBlob, relay.CapabilityPublishBlob,
				relay.CapabilityPublishCheckpoint, relay.CapabilityAcknowledgeMessage,
				relay.CapabilityFetchMessage, relay.CapabilityPublishMessage,
			},
			CreatedAtMilliseconds: now,
		},
	}
	claim := devicesync.PrincipalProvisioning{
		Version: devicesync.SchemaVersion, RetryID: uuid.New(),
		PrincipalID: principalID, InitialDeviceID: initialDeviceID,
		Tenant: relay.TenantRegistration{
			Version: relay.SchemaVersion, RetryID: uuid.New(),
			TenantID: principalID, AuthorizationDigest: tenantDigest,
			CreatedAtMilliseconds:            now,
			MaximumDomainCount:               relay.DefaultMaximumDomainCountPerTenant,
			MaximumAggregateMessageCount:     relay.DefaultMaximumMessageCountPerTenant,
			MaximumAggregateMessageByteCount: relay.DefaultMaximumMessageBytesPerTenant,
			MaximumAggregateBlobCount:        relay.DefaultMaximumBlobCountPerTenant,
			MaximumAggregateBlobByteCount:    relay.DefaultMaximumBlobBytesPerTenant,
		},
		ControlDomain: domain, CreatedAtMilliseconds: now,
	}
	result, err := store.ClaimAccountAdmissionWithAuthority(
		ctx, admissionCredential, claim, initialBinding, now,
	)
	if err != nil || result.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("claim account admission=%+v err=%v", result, err)
	}
	return liveDeviceSyncAuthority{DomainID: domainID, Publisher: publisher}
}

func livePublishDeviceSyncMessage(
	t *testing.T,
	ctx context.Context,
	store *postgres.RelayStore,
	publisher relay.Credential,
	tenantID uuid.UUID,
	domainID uuid.UUID,
	memberID uuid.UUID,
	now int64,
) uuid.UUID {
	t.Helper()
	carrier, err := testfixture.LoadRelayCarrier()
	if err != nil {
		t.Fatal(err)
	}
	envelope := carrier.Envelope
	envelope.TenantID = tenantID
	envelope.DomainID = domainID
	envelope.MessageID = uuid.New()
	envelope.PublisherMemberID = memberID
	envelope.CreatedAtMilliseconds = now
	if result, err := store.Publish(ctx, publisher, envelope, now); err != nil ||
		result.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("publish message=%+v err=%v", result, err)
	}
	return envelope.MessageID
}

func livePublishDeviceSyncBlob(
	t *testing.T,
	ctx context.Context,
	store *postgres.RelayStore,
	blobs relay.BlobContentStore,
	publisher relay.Credential,
	tenantID uuid.UUID,
	domainID uuid.UUID,
	value []byte,
	now int64,
) string {
	t.Helper()
	blobID := relay.BlobID(value)
	if _, err := blobs.Put(
		ctx, relay.BlobScope{TenantID: tenantID, DomainID: domainID},
		blobID, bytes.NewReader(value), int64(len(value)),
	); err != nil {
		t.Fatal(err)
	}
	if err := store.PrepareBlobPublish(
		ctx, publisher, blobID, int64(len(value)), now,
	); err != nil {
		t.Fatal(err)
	}
	if result, err := store.CommitBlobPublish(
		ctx, publisher, blobID, int64(len(value)), now,
	); err != nil || result.Acceptance != relay.AcceptanceAccepted {
		t.Fatalf("commit blob=%+v err=%v", result, err)
	}
	return blobID
}

func exportLiveMigrationState(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	principalID uuid.UUID,
) ([]byte, []byte) {
	t.Helper()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var state bytes.Buffer
	var inventory bytes.Buffer
	if _, err := postgres.ExportDeviceSyncMigrationState(
		ctx, tx, principalID, &state, &inventory,
	); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return state.Bytes(), inventory.Bytes()
}

func assertLiveMigrationBlob(
	t *testing.T,
	ctx context.Context,
	store relay.BlobContentStore,
	tenantID uuid.UUID,
	domainID uuid.UUID,
	blobID string,
	expected []byte,
) {
	t.Helper()
	content, err := store.Open(
		ctx, relay.BlobScope{TenantID: tenantID, DomainID: domainID}, blobID,
	)
	if err != nil {
		t.Fatal(err)
	}
	actual := make([]byte, content.ByteCount)
	_, readErr := content.Reader.Read(actual)
	closeErr := content.Reader.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(actual, expected) {
		t.Fatalf("blob %s bytes=%q readErr=%v closeErr=%v", blobID, actual, readErr, closeErr)
	}
}

func liveMigrationActivation(
	t *testing.T,
	fixture liveMigrationControlFixture,
	preparation serviceauthority.MigrationPreparation,
	snapshot *serviceauthority.MigrationSnapshot,
	readiness serviceauthority.MigrationReadiness,
	now int64,
) serviceauthority.MigrationActivationEvidence {
	t.Helper()
	if snapshot == nil {
		t.Fatal("missing migration snapshot")
	}
	evidence := serviceauthority.MigrationActivationEvidence{
		Preparation: preparation, Readiness: readiness, Snapshot: *snapshot,
	}
	prerequisiteDigest, err := evidence.PrerequisitesReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := fixture.RollbackEvidence.ActivationEvidence.
		ActivationManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	payload.MigrationPrerequisiteEvidenceDigest = &prerequisiteDigest
	payload.IssuedAtMilliseconds = now
	payload.ValidFromMilliseconds = now
	evidence.ActivationManifest = liveSignAuthorityManifest(
		t, payload, liveAuthorityPrivateKey(t, fixture.AuthorityAnchor),
		fixture.AuthorityAnchor,
	)
	if _, err := evidence.Validate(fixture.AuthorityAnchor, now); err != nil {
		t.Fatalf("activation evidence: %v", err)
	}
	return evidence
}

func liveMigrationRollback(
	t *testing.T,
	fixture liveMigrationControlFixture,
	activation serviceauthority.MigrationActivationEvidence,
	snapshot serviceauthority.MigrationSnapshot,
	readiness serviceauthority.MigrationReadiness,
	now int64,
) serviceauthority.MigrationRollbackEvidence {
	t.Helper()
	evidence := serviceauthority.MigrationRollbackEvidence{
		ActivationEvidence: activation, SourceReadiness: readiness,
		TargetSnapshot: snapshot,
	}
	prerequisiteDigest, err := evidence.PrerequisitesReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := fixture.RollbackEvidence.RollbackManifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	activationDigest, err := activation.ActivationManifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	payload.MigrationPrerequisiteEvidenceDigest = &prerequisiteDigest
	payload.PredecessorManifestDigest = &activationDigest
	payload.IssuedAtMilliseconds = now
	payload.ValidFromMilliseconds = now
	evidence.RollbackManifest = liveSignAuthorityManifest(
		t, payload, liveAuthorityPrivateKey(t, fixture.AuthorityAnchor),
		fixture.AuthorityAnchor,
	)
	if _, err := evidence.Validate(fixture.AuthorityAnchor, now); err != nil {
		t.Fatalf("rollback evidence: %v", err)
	}
	return evidence
}

func liveMigrationRollbackSettlement(
	t *testing.T,
	fixture liveMigrationControlFixture,
	rollback serviceauthority.Manifest,
	now int64,
) serviceauthority.Manifest {
	t.Helper()
	current, err := rollback.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	predecessorDigest, err := rollback.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	current.Revision++
	current.PredecessorManifestDigest = &predecessorDigest
	current.IssuedAtMilliseconds = now
	current.ValidFromMilliseconds = now
	current.ValidUntilMilliseconds = nil
	current.Transition = serviceauthority.TransitionPolicyUpdate
	current.Migration = nil
	current.MigrationPrerequisiteEvidenceDigest = nil
	current.PreparedDeployments = []serviceauthority.DeploymentDescriptor{}
	settlement := liveSignAuthorityManifest(
		t, current, liveAuthorityPrivateKey(t, fixture.AuthorityAnchor),
		fixture.AuthorityAnchor,
	)
	if _, err := settlement.ValidateSuccessor(rollback); err != nil {
		t.Fatalf("rollback settlement successor: %v", err)
	}
	return settlement
}

func liveMigrationDeploymentSigner(
	t *testing.T,
	descriptor serviceauthority.DeploymentDescriptor,
) *serviceauthority.DeploymentSigner {
	t.Helper()
	seed := liveMigrationDeploymentSeed(t, descriptor)
	signer, err := serviceauthority.NewDeploymentSigner(descriptor.DeploymentID, seed)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func liveMigrationDeploymentSeed(
	t *testing.T,
	descriptor serviceauthority.DeploymentDescriptor,
) []byte {
	t.Helper()
	for candidate := 1; candidate <= 255; candidate++ {
		scalar := make([]byte, 32)
		scalar[31] = byte(candidate)
		signer, err := serviceauthority.NewDeploymentSigner(
			descriptor.DeploymentID, scalar,
		)
		if err == nil && signer.PublicSigningKeyX963() == descriptor.PublicSigningKeyX963 &&
			signer.SigningKeyFingerprint() == descriptor.SigningKeyFingerprint {
			return scalar
		}
	}
	t.Fatal("portable fixture deployment signer was not found")
	return nil
}

func liveAuthorityPrivateKey(
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
	t.Fatal("portable fixture authority key was not found")
	return nil
}

func liveSignAuthorityManifest(
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
		t.Fatal("portable fixture authority fingerprint changed")
	}
	return serviceauthority.Manifest{
		Payload: encoded,
		Signature: serviceauthority.Signature{
			Algorithm: "ES256", PublicSigningKeyX963: anchor.PublicSigningKeyX963,
			Signature:             base64.RawURLEncoding.EncodeToString(raw),
			SignerID:              anchor.SignerID,
			SigningKeyFingerprint: anchor.SigningKeyFingerprint,
		},
	}
}

func liveMigrationToken(seed byte) string {
	value := make([]byte, 32)
	for index := range value {
		value[index] = seed + byte(index)
	}
	return base64.RawURLEncoding.EncodeToString(value)
}
