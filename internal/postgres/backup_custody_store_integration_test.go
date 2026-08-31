package postgres_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/robreuss/FacetsNode/internal/backupcustody"
	postgresstore "github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

func TestPostgresBackupCustodyUploadLedgerRequiresExactOrderedContinuity(t *testing.T) {
	databaseURL := os.Getenv("FACETS_SERVER_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("FACETS_SERVER_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	lockDisposablePostgres(t, ctx, databaseURL)
	pool := openPool(t, ctx, databaseURL)
	defer pool.Close()
	if _, err := pool.Exec(ctx, `
		DROP TABLE IF EXISTS backup_custody_retention_receipts,
			backup_custody_upload_chunks, backup_custody_generations,
			backup_custody_uploads, backup_custody_targets,
			backup_custody_authority_history, backup_custody_requests,
			backup_custody_accounts CASCADE;
		DROP TABLE IF EXISTS facets_backup_custody_schema_migrations;
	`); err != nil {
		t.Fatal(err)
	}
	if err := postgresstore.MigrateBackupCustody(ctx, pool); err != nil {
		t.Fatal(err)
	}
	deploymentID := uuid.New()
	store, err := postgresstore.NewBackupCustodyStore(pool, deploymentID, postgresstore.BackupCustodyStoreLimits{
		MaximumActiveUploads: 2, MaximumTargets: 2, MaximumGenerations: 10, MaximumRequests: 20,
		MaximumRetentionProofs: 10, MaximumChunksPerUpload: 10,
		MaximumChunkBytes: 1024, MaximumStagingBytes: 4096, MaximumCommittedBytes: 8192,
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("valid variable-size ledger survives store reopen", func(t *testing.T) {
		fixture := installBackupUploadLedger(t, ctx, pool, deploymentID, 10, 10,
			[]ledgerChunk{{0, 3, 3}, {3, 4, 7}, {7, 3, 10}})
		loaded, err := store.LoadUpload(ctx, fixture.accountID, fixture.uploadID)
		if err != nil || loaded.CommittedBytes != 10 {
			t.Fatalf("load committed=%d err=%v", loaded.CommittedBytes, err)
		}
		reopened, err := postgresstore.NewBackupCustodyStore(pool, deploymentID, postgresstore.BackupCustodyStoreLimits{
			MaximumActiveUploads: 2, MaximumTargets: 2, MaximumGenerations: 10, MaximumRequests: 20,
			MaximumRetentionProofs: 10, MaximumChunksPerUpload: 10,
			MaximumChunkBytes: 1024, MaximumStagingBytes: 4096, MaximumCommittedBytes: 8192,
		})
		if err != nil {
			t.Fatal(err)
		}
		if loaded, err = reopened.LoadUpload(ctx, fixture.accountID, fixture.uploadID); err != nil || loaded.CommittedBytes != 10 {
			t.Fatalf("reopen committed=%d err=%v", loaded.CommittedBytes, err)
		}
	})

	for name, test := range map[string]struct {
		committed int64
		maximum   int
		chunks    []ledgerChunk
	}{
		"aggregate-preserving overlap and gap": {10, 10, []ledgerChunk{{0, 6, 6}, {4, 2, 6}, {8, 2, 10}}},
		"gap":                                  {7, 10, []ledgerChunk{{0, 3, 3}, {5, 2, 7}}},
		"overlap":                              {6, 10, []ledgerChunk{{0, 4, 4}, {3, 3, 6}}},
		"chunk count beyond persisted maximum": {3, 2, []ledgerChunk{{0, 1, 1}, {1, 1, 2}, {2, 1, 3}}},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := installBackupUploadLedger(t, ctx, pool, deploymentID, test.committed, test.maximum, test.chunks)
			if _, err := store.LoadUpload(ctx, fixture.accountID, fixture.uploadID); err == nil {
				t.Fatal("corrupt upload ledger accepted")
			}
		})
	}

	t.Run("row arithmetic tamper is rejected by schema", func(t *testing.T) {
		fixture := installBackupUploadLedger(t, ctx, pool, deploymentID, 0, 10, nil)
		if _, err := pool.Exec(ctx, `INSERT INTO backup_custody_upload_chunks(account_id,upload_id,chunk_offset,chunk_byte_count,chunk_sha256,next_offset) VALUES($1,$2,0,3,$3,4)`, fixture.accountID, fixture.uploadID, strings.Repeat("1", 64)); err == nil {
			t.Fatal("tampered next offset entered durable ledger")
		}
	})
}

func TestPostgresBackupCustodyDurableAuthorityReceiptsReplayAndQuotas(t *testing.T) {
	databaseURL := os.Getenv("FACETS_SERVER_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("FACETS_SERVER_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	lockDisposablePostgres(t, ctx, databaseURL)
	pool := openPool(t, ctx, databaseURL)
	defer pool.Close()
	resetBackupCustodySchema(t, ctx, pool)
	deploymentID := uuid.New()
	store, err := postgresstore.NewBackupCustodyStore(pool, deploymentID, postgresstore.BackupCustodyStoreLimits{
		MaximumActiveUploads: 1, MaximumTargets: 2, MaximumGenerations: 4, MaximumRequests: 20,
		MaximumRetentionProofs: 1, MaximumChunksPerUpload: 4,
		MaximumChunkBytes: 2 * 1024 * 1024, MaximumStagingBytes: 4 * 1024 * 1024,
		MaximumCommittedBytes: 8 * 1024 * 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	accountID := uuid.New()
	enrollment, signer := backupPostgresEnrollment(t, accountID, deploymentID)
	manifestPayload, err := enrollment.Manifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	manifestDigest, err := enrollment.Manifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	clock := &backupIntegrationClock{now: time.UnixMilli(1_100)}
	registry := serviceauthority.NewBindingRegistry()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := backupcustody.OpenPreparedAccountJournal(filepath.Join(parent, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	content, err := backupcustody.OpenContentStore(filepath.Join(parent, "content"))
	if err != nil {
		t.Fatal(err)
	}
	defer content.Close()
	admissionReference := backupcustody.AccountAdmissionReference{Version: backupcustody.Version,
		AccountID: accountID, AdmissionID: uuid.New(), ExpiresAtMilliseconds: 10_000,
		RequestNonce: base64.RawURLEncoding.EncodeToString(make([]byte, 32))}
	admission, err := backupcustody.NewAccountAdmissionCredential(admissionReference)
	if err != nil {
		t.Fatal(err)
	}
	provisioning := backupcustody.ProvisioningCustody{Store: store, Journal: journal, Registry: registry, Signer: signer, Clock: clock}
	claimID := uuid.New()
	if err := provisioning.ProvisionAccount(ctx, admission, claimID, enrollment); err != nil {
		t.Fatal(err)
	}
	// The committed account, not the now-removed journal, is exact replay
	// authority even after the original bootstrap window.
	clock.now = time.UnixMilli(5_000)
	if err := provisioning.ProvisionAccount(ctx, admission, claimID, enrollment); err != nil {
		t.Fatalf("committed account replay: %v", err)
	}
	clock.now = time.UnixMilli(1_100)
	binding := serviceauthority.RequestBinding{Scope: serviceauthority.Scope{Kind: serviceauthority.ScopeBackupCustody, ScopeID: accountID},
		AuthorityRevision: 1, AuthorityDigest: manifestDigest, DeploymentID: deploymentID,
		RouteID: manifestPayload.ActiveDeployment.Routes[0].RouteID, TrafficClass: serviceauthority.TrafficBulk}
	targetCredential, targetRequest := backupIntegrationTarget(t, admissionReference, uuid.New(), uuid.New(), uuid.New(), 1_100)
	if err := provisioning.CreateTarget(ctx, admission, targetRequest, targetCredential, binding); err != nil {
		t.Fatal(err)
	}
	coordinator := backupcustody.Coordinator{Store: store, Content: content, Registry: registry, Signer: signer,
		AuthorityHistory: backupIntegrationAuthorityHistory{anchor: enrollment.Anchor, manifest: enrollment.Manifest},
		Clock:            clock, MaximumChunkBytes: 2 * 1024 * 1024, MaximumGenerationBytes: 8 * 1024 * 1024, NewID: uuid.New}
	wire := backupIntegrationOuterWire(t, targetCredential.Reference.BackupSetID)
	publish := backupcustody.PublishRequest{Version: backupcustody.Version, RequestID: uuid.New(),
		RequestedAtMilliseconds: 1_100, Credential: targetCredential.Reference, Generation: 1}
	upload, err := coordinator.BeginUpload(ctx, targetCredential, publish, binding)
	if err != nil {
		t.Fatal(err)
	}
	wireDigest := sha256.Sum256(wire)
	if next, err := coordinator.AppendUploadChunk(ctx, targetCredential, binding, upload.UploadID, 0, wire, hex.EncodeToString(wireDigest[:])); err != nil || next != uint64(len(wire)) {
		t.Fatalf("append next=%d err=%v", next, err)
	}
	if _, err := coordinator.FinalizeUpload(ctx, targetCredential, binding, upload.UploadID); err != nil {
		t.Fatal(err)
	}
	clock.now = time.UnixMilli(1_200)
	readRequest := backupcustody.ReadRequest{Version: backupcustody.Version, RequestID: uuid.New(),
		RequestedAtMilliseconds: 1_200, Credential: targetCredential.Reference}
	read, err := coordinator.Read(ctx, targetCredential, readRequest, binding)
	if err != nil {
		t.Fatal(err)
	}
	readBytes, err := io.ReadAll(read.Content)
	closeErr := read.Content.Close()
	if err != nil || closeErr != nil || !bytes.Equal(readBytes, wire) {
		t.Fatalf("read byteCount=%d err=%v close=%v", len(readBytes), err, closeErr)
	}

	clock.now = time.UnixMilli(1_100)
	if _, err := coordinator.Read(ctx, targetCredential, readRequest, binding); !errors.Is(err, backupcustody.ErrClockRollback) {
		t.Fatalf("durable read clock rollback err=%v", err)
	}
	clock.now = time.UnixMilli(1_200)
	if _, err := pool.Exec(ctx, `UPDATE backup_custody_accounts SET authority_manifest_digest=$2 WHERE account_id=$1`, accountID, strings.Repeat("f", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Read(ctx, targetCredential, readRequest, binding); err == nil {
		t.Fatal("durable authority mismatch admitted read")
	}
	if _, err := pool.Exec(ctx, `UPDATE backup_custody_accounts SET authority_manifest_digest=$2 WHERE account_id=$1`, accountID, manifestDigest); err != nil {
		t.Fatal(err)
	}

	storedGeneration := read.Generation
	if _, err := pool.Exec(ctx, `UPDATE backup_custody_generations SET custody_receipt_record='{}' WHERE account_id=$1 AND upload_id=$2`, accountID, upload.UploadID); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Read(ctx, targetCredential, readRequest, binding); err == nil {
		t.Fatal("tampered custody receipt admitted read")
	}
	if _, err := pool.Exec(ctx, `UPDATE backup_custody_generations SET custody_receipt_record=$3 WHERE account_id=$1 AND upload_id=$2`, accountID, upload.UploadID, storedGeneration.CustodyReceiptBytes); err != nil {
		t.Fatal(err)
	}
	manifestBytes, _ := json.Marshal(enrollment.Manifest)
	if _, err := pool.Exec(ctx, `UPDATE backup_custody_authority_history SET manifest_record='{}' WHERE account_id=$1 AND authority_revision=1`, accountID); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Read(ctx, targetCredential, readRequest, binding); err == nil {
		t.Fatal("tampered historical authority admitted custody receipt")
	}
	if _, err := pool.Exec(ctx, `UPDATE backup_custody_authority_history SET manifest_record=$2 WHERE account_id=$1 AND authority_revision=1`, accountID, manifestBytes); err != nil {
		t.Fatal(err)
	}

	retentionRequest := backupcustody.RetentionProofRequest{Version: backupcustody.Version,
		RequestID: uuid.New(), RequestedAtMilliseconds: 1_200, Credential: targetCredential.Reference,
		GenerationReferenceDigest:          storedGeneration.GenerationReferenceDigest,
		CustodyReceiptReferenceDigest:      storedGeneration.CustodyReceiptReferenceDigest,
		MinimumRetainedThroughMilliseconds: 1_200}
	retention, err := coordinator.ConfirmRetention(ctx, targetCredential, retentionRequest, binding)
	if err != nil {
		t.Fatal(err)
	}
	retentionBytes, err := retention.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE backup_custody_retention_receipts SET receipt_record='{}' WHERE account_id=$1 AND request_id=$2`, accountID, retentionRequest.RequestID); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.ConfirmRetention(ctx, targetCredential, retentionRequest, binding); err == nil {
		t.Fatal("tampered retention receipt admitted replay")
	}
	if _, err := pool.Exec(ctx, `UPDATE backup_custody_retention_receipts SET receipt_record=$3 WHERE account_id=$1 AND request_id=$2`, accountID, retentionRequest.RequestID, retentionBytes); err != nil {
		t.Fatal(err)
	}
	secondRetention := retentionRequest
	secondRetention.RequestID = uuid.New()
	if _, err := coordinator.ConfirmRetention(ctx, targetCredential, secondRetention, binding); !errors.Is(err, backupcustody.ErrConflict) {
		t.Fatalf("retention metadata quota err=%v", err)
	}

	conflictingCredential, conflictingRequest := backupIntegrationTarget(t, admissionReference, uuid.New(), uuid.New(), targetRequest.RequestID, 1_200)
	if err := provisioning.CreateTarget(ctx, admission, conflictingRequest, conflictingCredential, binding); !errors.Is(err, backupcustody.ErrConflict) {
		t.Fatalf("global request conflict err=%v", err)
	}
	secondCredential, secondRequest := backupIntegrationTarget(t, admissionReference, uuid.New(), uuid.New(), uuid.New(), 1_200)
	if err := provisioning.CreateTarget(ctx, admission, secondRequest, secondCredential, binding); err != nil {
		t.Fatalf("second target within quota: %v", err)
	}
	thirdCredential, thirdRequest := backupIntegrationTarget(t, admissionReference, uuid.New(), uuid.New(), uuid.New(), 1_200)
	if err := provisioning.CreateTarget(ctx, admission, thirdRequest, thirdCredential, binding); !errors.Is(err, backupcustody.ErrConflict) {
		t.Fatalf("target metadata quota err=%v", err)
	}
}

type ledgerChunk struct{ offset, length, next int64 }
type backupUploadLedgerFixture struct{ accountID, uploadID uuid.UUID }

func resetBackupCustodySchema(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(ctx, `
		DROP TABLE IF EXISTS backup_custody_retention_receipts,
			backup_custody_upload_chunks, backup_custody_generations,
			backup_custody_uploads, backup_custody_targets,
			backup_custody_authority_history, backup_custody_requests,
			backup_custody_accounts CASCADE;
		DROP TABLE IF EXISTS facets_backup_custody_schema_migrations;
	`); err != nil {
		t.Fatal(err)
	}
	if err := postgresstore.MigrateBackupCustody(ctx, pool); err != nil {
		t.Fatal(err)
	}
}

func backupIntegrationTarget(t *testing.T, admission backupcustody.AccountAdmissionReference, targetID, setID, requestID uuid.UUID, now int64) (backupcustody.TargetCredential, backupcustody.CreateTargetRequest) {
	t.Helper()
	reference := backupcustody.TargetCredentialReference{Version: backupcustody.Version,
		AccountID: admission.AccountID, TargetID: targetID, BackupSetID: setID,
		CredentialID: uuid.New(), Capabilities: []backupcustody.Capability{
			backupcustody.Publish, backupcustody.Read, backupcustody.RetentionProof,
		}, ExpiresAtMilliseconds: 10_000,
		RequestNonce: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))}
	credential, err := backupcustody.NewTargetCredential(reference)
	if err != nil {
		t.Fatal(err)
	}
	request := backupcustody.CreateTargetRequest{Version: backupcustody.Version, Admission: admission,
		TargetID: targetID, BackupSetID: setID, RequestID: requestID, RequestedAtMilliseconds: now}
	if request.Validate() != nil {
		t.Fatal("invalid target fixture")
	}
	return credential, request
}

func backupIntegrationOuterWire(t *testing.T, setID uuid.UUID) []byte {
	t.Helper()
	type slot struct {
		EphemeralPublicKey []byte `json:"ephemeralPublicKey"`
		SealedContentKey   []byte `json:"sealedContentKey"`
	}
	type header struct {
		BackupSetID            uuid.UUID `json:"backupSetID"`
		Generation             uint64    `json:"generation"`
		PredecessorOuterDigest *string   `json:"predecessorOuterDigest,omitempty"`
		RecipientSlots         []slot    `json:"recipientSlots"`
		Version                int       `json:"version"`
	}
	headerBytes, err := json.Marshal(header{BackupSetID: setID, Generation: 1, Version: backupcustody.Version,
		RecipientSlots: []slot{{EphemeralPublicKey: bytes.Repeat([]byte{1}, 32), SealedContentKey: bytes.Repeat([]byte{2}, 60)}}})
	if err != nil {
		t.Fatal(err)
	}
	result := append([]byte("facets.backup.outer.v1\x00"), 0, 0, 0, 0)
	binary.BigEndian.PutUint32(result[len("facets.backup.outer.v1\x00"):], uint32(len(headerBytes)))
	result = append(result, headerBytes...)
	appendSection := func(kind byte, index uint64, body []byte) {
		var sectionHeader [13]byte
		sectionHeader[0] = kind
		binary.BigEndian.PutUint64(sectionHeader[1:9], index)
		binary.BigEndian.PutUint32(sectionHeader[9:13], uint32(len(body)))
		result = append(result, sectionHeader[:]...)
		result = append(result, body...)
	}
	appendSection(1, 0, bytes.Repeat([]byte{3}, 29))
	appendSection(2, 0, bytes.Repeat([]byte{4}, 44))
	appendSection(3, 1, bytes.Repeat([]byte{5}, 29))
	return result
}

func backupPostgresEnrollment(t *testing.T, accountID, deploymentID uuid.UUID) (serviceauthority.InitialEnrollment, *serviceauthority.DeploymentSigner) {
	t.Helper()
	deploymentScalar := make([]byte, 32)
	deploymentScalar[31] = 11
	deploymentSigner, err := serviceauthority.NewDeploymentSigner(deploymentID, deploymentScalar)
	if err != nil {
		t.Fatal(err)
	}
	routeID := uuid.New()
	pin := strings.Repeat("1", 64)
	route := serviceauthority.TransportRoute{Endpoint: "https://facets-box.local:8443",
		Kind: serviceauthority.RouteDirectHTTPS, NetworkScope: serviceauthority.NetworkTrustedLAN, RouteID: routeID,
		ServerAuthentication: serviceauthority.ServerAuthentication{Kind: "pinned_spki_sha256", PinnedSPKISHA256: &pin}}
	descriptor := serviceauthority.DeploymentDescriptor{Version: serviceauthority.SchemaVersion,
		DeploymentID: deploymentID, CreatedAtMilliseconds: 900,
		PublicSigningKeyX963:  deploymentSigner.PublicSigningKeyX963(),
		SigningKeyFingerprint: deploymentSigner.SigningKeyFingerprint(), Routes: []serviceauthority.TransportRoute{route}}
	policy := serviceauthority.TransportPolicy{Version: serviceauthority.SchemaVersion,
		ControlRouteIDs: []uuid.UUID{routeID}, MessageRouteIDs: []uuid.UUID{routeID}, BulkRouteIDs: []uuid.UUID{routeID}}
	scope := serviceauthority.Scope{Kind: serviceauthority.ScopeBackupCustody, ScopeID: accountID}
	authorityScalar := make([]byte, 32)
	authorityScalar[31] = 12
	authorityKey := backupPostgresPrivateKey(t, authorityScalar)
	authorityID := uuid.New()
	public := elliptic.Marshal(elliptic.P256(), authorityKey.PublicKey.X, authorityKey.PublicKey.Y)
	anchor := serviceauthority.TrustAnchor{Version: serviceauthority.SchemaVersion, Scope: scope, SignerID: authorityID,
		PublicSigningKeyX963:  base64.RawURLEncoding.EncodeToString(public),
		SigningKeyFingerprint: hex.EncodeToString(backupPostgresSHA256(public))}
	manifestPayload := serviceauthority.ManifestPayload{Version: serviceauthority.SchemaVersion,
		ActiveDeployment: descriptor, PreparedDeployments: []serviceauthority.DeploymentDescriptor{},
		Revision: 1, Scope: scope, Transition: serviceauthority.TransitionInitialActivation,
		TransportPolicy: policy, IssuedAtMilliseconds: 1_000, ValidFromMilliseconds: 1_000}
	manifestBytes, err := json.Marshal(manifestPayload)
	if err != nil {
		t.Fatal(err)
	}
	manifest := serviceauthority.Manifest{Payload: manifestBytes,
		Signature: backupPostgresSign(t, authorityKey, authorityID, "Facets service authority manifest v1\x00", manifestBytes)}
	offer, err := deploymentSigner.SignDeploymentOffer(serviceauthority.DeploymentOfferPayload{Version: serviceauthority.SchemaVersion,
		Deployment: descriptor, TransportPolicy: policy, IssuedAtMilliseconds: 1_000, ExpiresAtMilliseconds: 2_000})
	if err != nil {
		t.Fatal(err)
	}
	enrollment := serviceauthority.InitialEnrollment{Version: serviceauthority.SchemaVersion,
		Anchor: anchor, DeploymentOffer: offer, Manifest: manifest}
	if _, err := enrollment.ValidateForAdmissionClaim(scope); err != nil {
		t.Fatal(err)
	}
	return enrollment, deploymentSigner
}

func backupPostgresPrivateKey(t *testing.T, scalar []byte) *ecdsa.PrivateKey {
	t.Helper()
	d := new(big.Int).SetBytes(scalar)
	x, y := elliptic.P256().ScalarBaseMult(scalar)
	if d.Sign() <= 0 || x == nil || y == nil {
		t.Fatal("invalid fixture private key")
	}
	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, D: d}
}

func backupPostgresSign(t *testing.T, key *ecdsa.PrivateKey, signerID uuid.UUID, domain string, payload []byte) serviceauthority.Signature {
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
	return serviceauthority.Signature{Algorithm: "ES256", PublicSigningKeyX963: base64.RawURLEncoding.EncodeToString(public),
		Signature: base64.RawURLEncoding.EncodeToString(raw), SignerID: signerID,
		SigningKeyFingerprint: hex.EncodeToString(backupPostgresSHA256(public))}
}

func backupPostgresSHA256(input []byte) []byte {
	digest := sha256.Sum256(input)
	return digest[:]
}

type backupIntegrationClock struct{ now time.Time }

func (clock *backupIntegrationClock) Now() time.Time { return clock.now }

type backupIntegrationAuthorityHistory struct {
	anchor   serviceauthority.TrustAnchor
	manifest serviceauthority.Manifest
}

func (history backupIntegrationAuthorityHistory) ResolveBackupCustodyAuthority(_ context.Context, authority serviceauthority.BackupCustodyAuthorityContext) (serviceauthority.TrustAnchor, serviceauthority.Manifest, error) {
	digest, err := history.manifest.ReferenceDigest()
	if err != nil || authority.Scope != history.anchor.Scope || authority.AuthorityManifestDigest != digest {
		return serviceauthority.TrustAnchor{}, serviceauthority.Manifest{}, serviceauthority.ErrInvalid
	}
	return history.anchor, history.manifest, nil
}

func installBackupUploadLedger(t *testing.T, ctx context.Context, pool interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, deploymentID uuid.UUID, committed int64, maximum int, chunks []ledgerChunk) backupUploadLedgerFixture {
	t.Helper()
	if _, err := pool.Exec(ctx, `TRUNCATE backup_custody_accounts CASCADE`); err != nil {
		t.Fatal(err)
	}
	accountID, targetID, setID, uploadID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	createRequestID, publishRequestID := uuid.New(), uuid.New()
	credential := backupcustody.TargetCredentialReference{
		Version: backupcustody.Version, AccountID: accountID, TargetID: targetID, BackupSetID: setID,
		CredentialID: uuid.New(), Capabilities: []backupcustody.Capability{backupcustody.Publish},
		ExpiresAtMilliseconds: 10_000, RequestNonce: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	}
	request := backupcustody.PublishRequest{Version: backupcustody.Version, RequestID: publishRequestID,
		RequestedAtMilliseconds: 1_000, Credential: credential, Generation: 1}
	requestBytes, err := json.Marshal(request)
	if err != nil || request.Validate() != nil {
		t.Fatalf("invalid fixture request: %v", err)
	}
	credentialBytes, err := json.Marshal(credential)
	if err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("a", 64)
	if _, err := pool.Exec(ctx, `
		INSERT INTO backup_custody_accounts(account_id,claim_id,admission_id,admission_record,
			admission_authorization_digest,authority_revision,authority_manifest_digest,deployment_id,
			initial_anchor_record,initial_manifest_record,initial_enrollment_record,
			server_time_high_water_milliseconds,state,created_at_milliseconds)
		VALUES($1,$2,$3,'{}',$4,1,$4,$5,'{}','{}','{}',1000,'writable',1000);
		INSERT INTO backup_custody_requests(request_id,account_id,operation,request_record)
		VALUES($6,$1,'create_target','{}'),($7,$1,'begin_upload',$8);
		INSERT INTO backup_custody_targets(account_id,target_id,backup_set_id,credential_id,
			credential_record,credential_authorization_digest,admission_authorization_digest,
			create_request_id,create_request_record,created_at_milliseconds)
		VALUES($1,$9,$10,$11,$12,$4,$4,$6,'{}',1000);
		INSERT INTO backup_custody_uploads(account_id,upload_id,target_id,backup_set_id,
			publish_request_id,request_record,committed_bytes,maximum_chunk_count,state,created_at_milliseconds)
		VALUES($1,$13,$9,$10,$7,$8,$14,$15,'uploading',1000)
	`, accountID, uuid.New(), uuid.New(), digest, deploymentID, createRequestID, publishRequestID,
		requestBytes, targetID, setID, credential.CredentialID, credentialBytes, uploadID, committed, maximum); err != nil {
		t.Fatal(err)
	}
	for index, chunk := range chunks {
		if _, err := pool.Exec(ctx, `INSERT INTO backup_custody_upload_chunks(account_id,upload_id,chunk_offset,chunk_byte_count,chunk_sha256,next_offset) VALUES($1,$2,$3,$4,$5,$6)`, accountID, uploadID, chunk.offset, chunk.length, strings.Repeat(string(rune('a'+index)), 64), chunk.next); err != nil {
			t.Fatal(err)
		}
	}
	return backupUploadLedgerFixture{accountID: accountID, uploadID: uploadID}
}
