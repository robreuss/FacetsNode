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
	"errors"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/robreuss/FacetsNode/internal/backupcustody"
	"github.com/robreuss/FacetsNode/internal/config"
	"github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
	"github.com/robreuss/FacetsNode/internal/testpostgres"
)

func TestBackupCustodyStoreLimitsAreMappedWithoutRelayFallback(t *testing.T) {
	configuration := config.Config{
		BackupMaximumActiveUploads:   2,
		BackupMaximumTargets:         3,
		BackupMaximumGenerations:     4,
		BackupMaximumRequests:        5,
		BackupMaximumRetentionProofs: 6,
		BackupMaximumChunksPerUpload: 7,
		BackupMaximumChunkBytes:      8,
		BackupMaximumStagingBytes:    9,
		BackupMaximumCommittedBytes:  10,
	}
	limits := backupCustodyStoreLimits(configuration)
	if limits.MaximumActiveUploads != 2 || limits.MaximumTargets != 3 ||
		limits.MaximumGenerations != 4 || limits.MaximumRequests != 5 ||
		limits.MaximumRetentionProofs != 6 || limits.MaximumChunksPerUpload != 7 ||
		limits.MaximumChunkBytes != 8 || limits.MaximumStagingBytes != 9 ||
		limits.MaximumCommittedBytes != 10 {
		t.Fatalf("mapped Backup limits=%+v", limits)
	}
}

func TestBackupCustodyDatabaseTableAllowlistRejectsEveryForeignService(t *testing.T) {
	allowed := []string{
		"facets_backup_custody_schema_migrations",
		"backup_custody_accounts",
		"backup_custody_requests",
		"backup_custody_authority_history",
		"backup_custody_targets",
		"backup_custody_uploads",
		"backup_custody_generations",
		"backup_custody_upload_chunks",
		"backup_custody_retention_receipts",
	}
	for name, tables := range map[string][]string{
		"empty":       nil,
		"Backup only": allowed,
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateBackupCustodyDatabaseTables(tables); err != nil {
				t.Fatal(err)
			}
		})
	}
	for name, foreign := range map[string]string{
		"relay":        "relay_tenants",
		"Device Sync":  "device_sync_principals",
		"Shared Space": "shared_space_participants",
		"Compute Pool": "compute_pool_jobs",
		"unknown":      "operator_notes",
	} {
		t.Run(name, func(t *testing.T) {
			tables := append(append([]string(nil), allowed...), foreign)
			if err := validateBackupCustodyDatabaseTables(tables); err == nil {
				t.Fatalf("foreign table %q accepted", foreign)
			}
		})
	}
	if err := validateBackupCustodyDatabaseTables([]string{"backup_custody_accounts", "backup_custody_accounts"}); err == nil {
		t.Fatal("duplicate catalog table identity accepted")
	}
}

func TestBackupCustodyOneConnectionRecoversStandbyWithoutInventoryDeadlock(t *testing.T) {
	databaseURL := os.Getenv("FACETS_SERVER_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("FACETS_SERVER_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	databaseLock, err := testpostgres.AcquireDisposableDatabaseLock(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer databaseLock.Close()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err := admin.Exec(ctx, `
		DROP TABLE IF EXISTS backup_custody_retention_receipts,
			backup_custody_upload_chunks, backup_custody_generations,
			backup_custody_uploads, backup_custody_targets,
			backup_custody_authority_history, backup_custody_requests,
			backup_custody_accounts CASCADE;
		DROP TABLE IF EXISTS facets_backup_custody_schema_migrations;
	`); err != nil {
		t.Fatal(err)
	}
	if err := requireDedicatedBackupCustodyDatabase(ctx, admin); err != nil {
		t.Fatalf("empty dedicated database rejected: %v", err)
	}
	if err := postgres.MigrateBackupCustody(ctx, admin); err != nil {
		t.Fatal(err)
	}
	if err := requireDedicatedBackupCustodyDatabase(ctx, admin); err != nil {
		t.Fatalf("Backup-only database rejected: %v", err)
	}
	deploymentID := uuid.New()
	accountID := uuid.New()
	enrollment, signer := backupServiceTestEnrollment(t, accountID, deploymentID)
	admissionAuthority := &backupAccountAdmissionAuthority{deploymentID: deploymentID}
	copy(admissionAuthority.key[:], bytes.Repeat([]byte{0x4d}, 32))
	admissionReference := backupcustody.AccountAdmissionReference{
		Version: backupcustody.Version, AccountID: accountID, AdmissionID: uuid.New(),
		ExpiresAtMilliseconds: 1_900,
		RequestNonce:          base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x51}, 32)),
	}
	credential, err := admissionAuthority.credential(admissionReference, deploymentID, enrollment.DeploymentOffer)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := serviceauthority.NewInitialBinding(
		enrollment, signer,
		serviceauthority.Scope{Kind: serviceauthority.ScopeBackupCustody, ScopeID: accountID},
		1_100,
	)
	if err != nil {
		t.Fatal(err)
	}
	authorizationDigest, _ := credential.AuthorizationDigest()
	anchorRecord, _ := json.Marshal(enrollment.Anchor)
	enrollmentRecord, _ := json.Marshal(enrollment)
	claimID := uuid.New()
	accountRecord := backupcustody.AccountRecord{
		AccountID: accountID, ClaimID: claimID, Admission: admissionReference,
		AdmissionAuthorizationDigest: authorizationDigest,
		AuthorityRevision:            binding.Revision(), AuthorityManifestDigest: binding.ManifestDigest(),
		DeploymentID: deploymentID, InitialManifestRecord: binding.ManifestRecord(),
		InitialAnchorRecord: anchorRecord, InitialEnrollmentRecord: enrollmentRecord,
		InitialBinding: binding, CreatedAtMilliseconds: 1_100,
	}
	limits := postgres.BackupCustodyStoreLimits{
		MaximumActiveUploads: 1, MaximumTargets: 2, MaximumGenerations: 4,
		MaximumRequests: 8, MaximumRetentionProofs: 4, MaximumChunksPerUpload: 4,
		MaximumChunkBytes: 1024, MaximumStagingBytes: 4096, MaximumCommittedBytes: 8192,
	}
	bootstrapStore, err := postgres.NewBackupCustodyStore(admin, deploymentID, limits)
	if err != nil {
		t.Fatal(err)
	}
	if err := bootstrapStore.PrepareAccount(ctx, accountRecord); err != nil {
		t.Fatal(err)
	}
	oneConnectionConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	oneConnectionConfig.MaxConns = 1
	oneConnectionPool, err := pgxpool.NewWithConfig(ctx, oneConnectionConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer oneConnectionPool.Close()
	oneConnectionStore, err := postgres.NewBackupCustodyStore(oneConnectionPool, deploymentID, limits)
	if err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := backupcustody.OpenPreparedAccountJournal(filepath.Join(parent, "claims"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	registry := serviceauthority.NewBindingRegistry()
	provisioning := &backupcustody.ProvisioningCustody{
		Store: oneConnectionStore, Journal: journal, Registry: registry,
		Signer: signer, Clock: fixedBackupServiceClock{now: time.UnixMilli(1_100)},
	}
	if err := recoverBackupCustodyStandbyAccounts(
		ctx, oneConnectionPool, oneConnectionStore, provisioning, admissionAuthority,
	); err != nil {
		t.Fatal(err)
	}
	_, state, err := oneConnectionStore.LoadAccountClaim(ctx, accountID, claimID, admissionReference.AdmissionID)
	if err != nil || state != backupcustody.AccountStateWritable {
		t.Fatalf("recovered state=%q err=%v", state, err)
	}
	if _, err := admin.Exec(ctx, `CREATE TABLE relay_tenants (id integer PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = admin.Exec(context.Background(), `DROP TABLE IF EXISTS relay_tenants`) }()
	if err := requireDedicatedBackupCustodyDatabase(ctx, admin); err == nil {
		t.Fatal("shared relay database was accepted as dedicated Backup custody")
	}
}

func TestBackupCustodyPostProvisionReconciliationIsIndependentAndSerialized(t *testing.T) {
	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	var calls atomic.Int32
	var active atomic.Int32
	var maximumActive atomic.Int32
	health := newBackupCustodyAuthorityHealth(time.Second, func(ctx context.Context) error {
		if ctx.Err() != nil {
			t.Fatalf("independent reconciliation began canceled: %v", ctx.Err())
		}
		current := active.Add(1)
		defer active.Add(-1)
		for {
			maximum := maximumActive.Load()
			if current <= maximum || maximumActive.CompareAndSwap(maximum, current) {
				break
			}
		}
		call := calls.Add(1)
		if call == 1 {
			close(firstEntered)
			<-releaseFirst
			return serviceauthority.ErrBindingUnavailable
		}
		return nil
	})
	firstDone := make(chan error, 1)
	go func() { firstDone <- health.reconcileAfterProvision() }()
	<-firstEntered
	secondDone := make(chan error, 1)
	go func() { secondDone <- health.reconcileAfterProvision() }()
	select {
	case <-secondDone:
		t.Fatal("concurrent reconciliation did not serialize")
	case <-time.After(20 * time.Millisecond):
	}
	close(releaseFirst)
	if err := <-firstDone; !errors.Is(err, serviceauthority.ErrBindingUnavailable) {
		t.Fatalf("first reconciliation error=%v", err)
	}
	if err := <-secondDone; err != nil {
		t.Fatal(err)
	}
	if maximumActive.Load() != 1 || health.check() != nil {
		t.Fatalf("max active=%d final health=%v", maximumActive.Load(), health.check())
	}
}

func TestBackupCustodyRegistryProbeDetectsLivePoison(t *testing.T) {
	registry := serviceauthority.NewBindingRegistry()
	if err := probeBackupCustodyRegistry(registry); err != nil {
		t.Fatal(err)
	}
	if err := registry.Close(); err != nil {
		t.Fatal(err)
	}
	if err := probeBackupCustodyRegistry(registry); !errors.Is(err, serviceauthority.ErrBindingUnavailable) {
		t.Fatalf("closed registry probe error=%v", err)
	}
}

func TestBackupCustodyHTTPServerDoesNotApplyAbsoluteStreamingWriteDeadline(t *testing.T) {
	server := newBackupCustodyHTTPServer(config.Config{
		ListenAddress:  "127.0.0.1:0",
		TransferPeriod: 10 * time.Minute,
	}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if server.WriteTimeout != 0 || server.ReadTimeout != 10*time.Minute {
		t.Fatalf("streaming deadlines read=%s write=%s", server.ReadTimeout, server.WriteTimeout)
	}
}

func TestBackupCustodyUnexpectedServeFailureRetainsCustodyWhileHandlerIsBlocked(t *testing.T) {
	started := make(chan struct{})
	finished := make(chan struct{})
	release := make(chan struct{})
	var startedOnce sync.Once
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		startedOnce.Do(func() { close(started) })
		<-release
		writer.WriteHeader(http.StatusNoContent)
		close(finished)
	})}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	requestDone := make(chan error, 1)
	go func() {
		response, requestErr := http.Get("http://" + listener.Addr().String())
		if response != nil {
			_ = response.Body.Close()
		}
		requestDone <- requestErr
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("blocked handler did not start")
	}
	injectedServeErr := errors.New("injected listener failure")
	injectedErrors := make(chan error, 1)
	injectedErrors <- injectedServeErr
	retain, shutdownErr := finishBackupCustodyHTTPServer(
		context.Background(), server, injectedErrors, 10*time.Millisecond,
	)
	if !retain || !errors.Is(shutdownErr, context.DeadlineExceeded) ||
		!errors.Is(shutdownErr, injectedServeErr) {
		t.Fatalf("unexpected failure retain=%t err=%v", retain, shutdownErr)
	}
	select {
	case <-finished:
		t.Fatal("blocked handler finished before custody retention decision")
	default:
	}
	close(release)
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("blocked handler did not drain after release")
	}
	select {
	case <-requestDone:
	case <-time.After(2 * time.Second):
		t.Fatal("request did not return after handler release")
	}
	select {
	case serveErr := <-serveDone:
		if !errors.Is(serveErr, http.ErrServerClosed) {
			t.Fatalf("serve error=%v", serveErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP server did not close")
	}
}

type fixedBackupServiceClock struct{ now time.Time }

func (clock fixedBackupServiceClock) Now() time.Time { return clock.now }

func backupServiceTestEnrollment(
	t *testing.T,
	accountID uuid.UUID,
	deploymentID uuid.UUID,
) (serviceauthority.InitialEnrollment, *serviceauthority.DeploymentSigner) {
	t.Helper()
	deploymentScalar := make([]byte, 32)
	deploymentScalar[31] = 11
	deploymentSigner, err := serviceauthority.NewDeploymentSigner(deploymentID, deploymentScalar)
	if err != nil {
		t.Fatal(err)
	}
	routeID := uuid.New()
	pin := strings.Repeat("1", 64)
	route := serviceauthority.TransportRoute{
		Endpoint: "https://facets-box.local:8443", Kind: serviceauthority.RouteDirectHTTPS,
		NetworkScope: serviceauthority.NetworkTrustedLAN, RouteID: routeID,
		ServerAuthentication: serviceauthority.ServerAuthentication{
			Kind: "pinned_spki_sha256", PinnedSPKISHA256: &pin,
		},
	}
	descriptor := serviceauthority.DeploymentDescriptor{
		Version: serviceauthority.SchemaVersion, DeploymentID: deploymentID,
		CreatedAtMilliseconds: 900,
		PublicSigningKeyX963:  deploymentSigner.PublicSigningKeyX963(),
		SigningKeyFingerprint: deploymentSigner.SigningKeyFingerprint(),
		Routes:                []serviceauthority.TransportRoute{route},
	}
	policy := serviceauthority.TransportPolicy{
		Version:         serviceauthority.SchemaVersion,
		ControlRouteIDs: []uuid.UUID{routeID}, MessageRouteIDs: []uuid.UUID{routeID},
		BulkRouteIDs: []uuid.UUID{routeID},
	}
	scope := serviceauthority.Scope{Kind: serviceauthority.ScopeBackupCustody, ScopeID: accountID}
	authorityScalar := make([]byte, 32)
	authorityScalar[31] = 12
	authorityKey := backupServiceTestPrivateKey(t, authorityScalar)
	authorityID := uuid.New()
	public := elliptic.Marshal(elliptic.P256(), authorityKey.PublicKey.X, authorityKey.PublicKey.Y)
	anchor := serviceauthority.TrustAnchor{
		Version: serviceauthority.SchemaVersion, Scope: scope, SignerID: authorityID,
		PublicSigningKeyX963:  base64.RawURLEncoding.EncodeToString(public),
		SigningKeyFingerprint: hex.EncodeToString(backupServiceTestSHA256(public)),
	}
	manifestPayload := serviceauthority.ManifestPayload{
		Version: serviceauthority.SchemaVersion, ActiveDeployment: descriptor,
		PreparedDeployments: []serviceauthority.DeploymentDescriptor{}, Revision: 1,
		Scope: scope, Transition: serviceauthority.TransitionInitialActivation,
		TransportPolicy: policy, IssuedAtMilliseconds: 1_000, ValidFromMilliseconds: 1_000,
	}
	manifestBytes, err := json.Marshal(manifestPayload)
	if err != nil {
		t.Fatal(err)
	}
	manifest := serviceauthority.Manifest{
		Payload: manifestBytes,
		Signature: backupServiceTestSign(
			t, authorityKey, authorityID,
			"Facets service authority manifest v1\x00", manifestBytes,
		),
	}
	offer, err := deploymentSigner.SignDeploymentOffer(serviceauthority.DeploymentOfferPayload{
		Version: serviceauthority.SchemaVersion, Deployment: descriptor,
		TransportPolicy: policy, IssuedAtMilliseconds: 1_000, ExpiresAtMilliseconds: 2_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	enrollment := serviceauthority.InitialEnrollment{
		Version: serviceauthority.SchemaVersion, Anchor: anchor,
		DeploymentOffer: offer, Manifest: manifest,
	}
	if _, err := enrollment.ValidateForAdmissionClaim(scope); err != nil {
		t.Fatal(err)
	}
	return enrollment, deploymentSigner
}

func backupServiceTestPrivateKey(t *testing.T, scalar []byte) *ecdsa.PrivateKey {
	t.Helper()
	d := new(big.Int).SetBytes(scalar)
	x, y := elliptic.P256().ScalarBaseMult(scalar)
	if d.Sign() <= 0 || x == nil || y == nil {
		t.Fatal("invalid fixture private key")
	}
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, D: d,
	}
}

func backupServiceTestSign(
	t *testing.T,
	key *ecdsa.PrivateKey,
	signerID uuid.UUID,
	domain string,
	payload []byte,
) serviceauthority.Signature {
	t.Helper()
	digest := sha256.Sum256(append([]byte(domain), payload...))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	half := new(big.Int).Rsh(new(big.Int).Set(elliptic.P256().Params().N), 1)
	if s.Cmp(half) > 0 {
		s.Sub(elliptic.P256().Params().N, s)
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	public := elliptic.Marshal(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y)
	return serviceauthority.Signature{
		Algorithm: "ES256", PublicSigningKeyX963: base64.RawURLEncoding.EncodeToString(public),
		Signature: base64.RawURLEncoding.EncodeToString(raw), SignerID: signerID,
		SigningKeyFingerprint: hex.EncodeToString(backupServiceTestSHA256(public)),
	}
}

func backupServiceTestSHA256(input []byte) []byte {
	digest := sha256.Sum256(input)
	return digest[:]
}
