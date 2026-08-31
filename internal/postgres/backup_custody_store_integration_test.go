package postgres_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
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
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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
			backup_custody_uploads, backup_custody_credential_grant_transitions,
			backup_custody_credential_grants, backup_custody_targets,
			backup_custody_control_commands, backup_custody_account_control,
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
		MaximumRetentionProofs: 10, MaximumControlRecords: 20, MaximumCredentialLifetimeMilliseconds: 10_000,
		MaximumChunksPerUpload: 10,
		MaximumChunkBytes:      1024, MaximumStagingBytes: 4096, MaximumCommittedBytes: 8192,
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
			MaximumRetentionProofs: 10, MaximumControlRecords: 20, MaximumCredentialLifetimeMilliseconds: 10_000,
			MaximumChunksPerUpload: 10,
			MaximumChunkBytes:      1024, MaximumStagingBytes: 4096, MaximumCommittedBytes: 8192,
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
	limits := postgresstore.BackupCustodyStoreLimits{
		MaximumActiveUploads: 1, MaximumTargets: 2, MaximumGenerations: 4, MaximumRequests: 20,
		MaximumRetentionProofs: 1, MaximumControlRecords: 4, MaximumCredentialLifetimeMilliseconds: 10_000,
		MaximumChunksPerUpload: 4,
		MaximumChunkBytes:      2 * 1024 * 1024, MaximumStagingBytes: 4 * 1024 * 1024,
		MaximumCommittedBytes: 8 * 1024 * 1024,
	}
	store, err := postgresstore.NewBackupCustodyStore(pool, deploymentID, limits)
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
	controlSigner := newBackupControlSigner(accountID, 1, 41)
	initialControlAnchor := controlSigner.anchor(t)
	if err := provisioning.ProvisionAccount(ctx, admission, claimID, enrollment, initialControlAnchor); err != nil {
		t.Fatal(err)
	}
	// The committed account, not the now-removed journal, is exact replay
	// authority even after the original bootstrap window.
	clock.now = time.UnixMilli(5_000)
	if err := provisioning.ProvisionAccount(ctx, admission, claimID, enrollment, initialControlAnchor); err != nil {
		t.Fatalf("committed account replay: %v", err)
	}
	clock.now = time.UnixMilli(1_100)
	binding := serviceauthority.RequestBinding{Scope: serviceauthority.Scope{Kind: serviceauthority.ScopeBackupCustody, ScopeID: accountID},
		AuthorityRevision: 1, AuthorityDigest: manifestDigest, DeploymentID: deploymentID,
		RouteID: manifestPayload.ActiveDeployment.Routes[0].RouteID, TrafficClass: serviceauthority.TrafficBulk}
	targetCredential := backupIntegrationTarget(t, accountID, uuid.New(), uuid.New())
	control := backupcustody.ControlCustody{Store: store, Registry: registry, Clock: clock}
	createCommand := backupCreateTargetCommand(t, controlSigner, initialControlAnchor, targetCredential, uuid.New(), 1)
	controlBinding := binding
	controlBinding.TrafficClass = serviceauthority.TrafficControl
	if _, err := control.Submit(ctx, createCommand, controlBinding); err != nil {
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

	firstReference, _ := createCommand.ReferenceDigest()
	secondCredential := backupIntegrationTarget(t, accountID, uuid.New(), uuid.New())
	secondCommand := backupCreateTargetCommandWithPredecessor(t, controlSigner, secondCredential, uuid.New(), 2, firstReference)
	if _, err := control.Submit(ctx, secondCommand, controlBinding); err != nil {
		t.Fatalf("second target within quota: %v", err)
	}
	secondReference, _ := secondCommand.ReferenceDigest()
	thirdCredential := backupIntegrationTarget(t, accountID, uuid.New(), uuid.New())
	thirdCommand := backupCreateTargetCommandWithPredecessor(t, controlSigner, thirdCredential, uuid.New(), 3, secondReference)
	if _, err := control.Submit(ctx, thirdCommand, controlBinding); !errors.Is(err, backupcustody.ErrConflict) {
		t.Fatalf("target metadata quota err=%v", err)
	}

	createPayload, err := createCommand.DecodedPayload()
	if err != nil || createPayload.Effect.Grant == nil {
		t.Fatalf("initial grant payload err=%v", err)
	}
	initialGrantReference, err := createPayload.Effect.Grant.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	revokeCommand := backupRevokeCommand(t, controlSigner, uuid.New(), 3, secondReference, initialGrantReference)
	if _, err := control.Submit(ctx, revokeCommand, controlBinding); err != nil {
		t.Fatalf("revoke credential: %v", err)
	}
	revokeReference, _ := revokeCommand.ReferenceDigest()

	newReadRequest := readRequest
	newReadRequest.RequestID = uuid.New()
	if _, err := coordinator.Read(ctx, targetCredential, newReadRequest, binding); !errors.Is(err, backupcustody.ErrUnauthorized) {
		t.Fatalf("revoked grant admitted new read err=%v", err)
	}
	if replayedGeneration, err := coordinator.FinalizeUpload(ctx, targetCredential, binding, upload.UploadID); err != nil {
		t.Fatalf("historical finalized replay after revoke err=%v", err)
	} else if reference, referenceErr := replayedGeneration.ReferenceDigest(); referenceErr != nil || reference != storedGeneration.CustodyReceiptReferenceDigest {
		t.Fatalf("historical finalized replay reference=%q err=%v", reference, referenceErr)
	}
	retentionReference, _ := retention.ReferenceDigest()
	if replayedRetention, err := coordinator.ConfirmRetention(ctx, targetCredential, retentionRequest, binding); err != nil {
		t.Fatalf("historical retention replay after revoke err=%v", err)
	} else if reference, referenceErr := replayedRetention.ReferenceDigest(); referenceErr != nil || reference != retentionReference {
		t.Fatalf("historical retention replay reference=%q err=%v", reference, referenceErr)
	}

	// Validly signed receipts are still rejected unless their exact grant was
	// accepted by the referenced control head and remained active at that head.
	// This covers head-before-grant, head-at-transition and mismatched
	// grant/head projections in load, replay and readiness paths.
	initialAnchorReference, _ := initialControlAnchor.ReferenceDigest()
	secondPayloadForProjection, err := secondCommand.DecodedPayload()
	if err != nil || secondPayloadForProjection.Effect.Grant == nil {
		t.Fatalf("second projection payload err=%v", err)
	}
	secondGrantReferenceForProjection, _ := secondPayloadForProjection.Effect.Grant.ReferenceDigest()
	secondAuthorizationDigest, err := secondCredential.AuthorizationDigest()
	if err != nil {
		t.Fatal(err)
	}
	secondUse := backupcustody.CredentialUse{Reference: secondCredential.Reference, AuthorizationDigest: secondAuthorizationDigest}
	if err := store.AuthorizeHistoricalCredential(ctx, secondUse, secondGrantReferenceForProjection, firstReference, backupcustody.Publish, 1_200); err == nil {
		t.Fatal("grant accepted after the selected head was historically authorized")
	}
	initialAuthorizationDigest, err := targetCredential.AuthorizationDigest()
	if err != nil {
		t.Fatal(err)
	}
	initialUse := backupcustody.CredentialUse{Reference: targetCredential.Reference, AuthorizationDigest: initialAuthorizationDigest}
	if err := store.AuthorizeHistoricalCredential(ctx, initialUse, initialGrantReference, revokeReference, backupcustody.Publish, 1_200); err == nil {
		t.Fatal("grant transitioned at the selected head was historically authorized")
	}
	type custodyProjectionCase struct {
		name           string
		grantReference string
		headReference  string
	}
	for _, test := range []custodyProjectionCase{
		{name: "head before grant", grantReference: initialGrantReference, headReference: initialAnchorReference},
		{name: "head at revoke", grantReference: initialGrantReference, headReference: revokeReference},
		{name: "mismatched grant and head", grantReference: secondGrantReferenceForProjection, headReference: secondReference},
	} {
		t.Run("custody receipt "+test.name, func(t *testing.T) {
			mutatedReceipt, mutatedBytes, mutatedReference := backupMutatedReceipt(t, signer, storedGeneration.CustodyReceipt, test.grantReference, test.headReference)
			if _, err := pool.Exec(ctx, `UPDATE backup_custody_generations SET custody_receipt_record=$3,custody_receipt_reference_digest=$4,credential_grant_reference_digest=$5,control_head_reference_digest=$6 WHERE account_id=$1 AND upload_id=$2`, accountID, upload.UploadID, mutatedBytes, mutatedReference, test.grantReference, test.headReference); err != nil {
				t.Fatal(err)
			}
			if _, err := store.LoadGeneration(ctx, accountID, storedGeneration.GenerationReferenceDigest); err == nil {
				t.Fatal("historically invalid signed custody row loaded")
			}
			if _, err := coordinator.FinalizeUpload(ctx, targetCredential, binding, upload.UploadID); err == nil {
				t.Fatal("historically invalid signed custody row replayed")
			}
			if err := store.ValidateControlLedger(ctx, accountID); err == nil {
				t.Fatal("historically invalid signed custody row passed readiness")
			}
			_ = mutatedReceipt
			if _, err := pool.Exec(ctx, `UPDATE backup_custody_generations SET custody_receipt_record=$3,custody_receipt_reference_digest=$4,credential_grant_reference_digest=$5,control_head_reference_digest=$6 WHERE account_id=$1 AND upload_id=$2`, accountID, upload.UploadID, storedGeneration.CustodyReceiptBytes, storedGeneration.CustodyReceiptReferenceDigest, initialGrantReference, firstReference); err != nil {
				t.Fatal(err)
			}
		})
	}
	mutatedRetention, mutatedRetentionBytes, mutatedRetentionReference := backupMutatedReceipt(t, signer, retention, initialGrantReference, revokeReference)
	if _, err := pool.Exec(ctx, `UPDATE backup_custody_retention_receipts SET receipt_record=$3,receipt_reference_digest=$4,credential_grant_reference_digest=$5,control_head_reference_digest=$6 WHERE account_id=$1 AND request_id=$2`, accountID, retentionRequest.RequestID, mutatedRetentionBytes, mutatedRetentionReference, initialGrantReference, revokeReference); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadRetentionByRequest(ctx, accountID, retentionRequest.RequestID); err == nil {
		t.Fatal("historically invalid signed retention row loaded")
	}
	if _, err := coordinator.ConfirmRetention(ctx, targetCredential, retentionRequest, binding); err == nil {
		t.Fatal("historically invalid signed retention row replayed")
	}
	if err := store.ValidateControlLedger(ctx, accountID); err == nil {
		t.Fatal("historically invalid signed retention row passed readiness")
	}
	_ = mutatedRetention
	if _, err := pool.Exec(ctx, `UPDATE backup_custody_retention_receipts SET receipt_record=$3,receipt_reference_digest=$4,credential_grant_reference_digest=$5,control_head_reference_digest=$6 WHERE account_id=$1 AND request_id=$2`, accountID, retentionRequest.RequestID, retentionBytes, retentionReference, initialGrantReference, firstReference); err != nil {
		t.Fatal(err)
	}

	rotatedSigner := newBackupControlSigner(accountID, 2, 42)
	rotateCommand := backupRotateControlCommand(t, controlSigner, rotatedSigner, uuid.New(), 4, revokeReference)
	if _, err := control.Submit(ctx, rotateCommand, controlBinding); err != nil {
		t.Fatalf("rotate control key: %v", err)
	}
	rotateReference, _ := rotateCommand.ReferenceDigest()
	if err := store.ValidateControlLedger(ctx, accountID); err != nil {
		t.Fatalf("complete control ledger rejected: %v", err)
	}

	// Exact historical command replay is resolved before validating the now-
	// rotated current head. Conflicting CommandID reuse still fails closed.
	if replayed, err := control.Submit(ctx, createCommand, controlBinding); err != nil ||
		replayed.Sequence != 1 || replayed.CommandReferenceDigest != firstReference {
		t.Fatalf("historical exact command replay err=%v acceptance=%+v", err, replayed)
	}
	conflictingCredential := backupIntegrationTarget(t, accountID, uuid.New(), uuid.New())
	conflictingCommand := backupCreateTargetCommand(t, controlSigner, initialControlAnchor, conflictingCredential, createCommandID(t, createCommand), 1)
	if _, err := control.Submit(ctx, conflictingCommand, controlBinding); !errors.Is(err, backupcustody.ErrConflict) {
		t.Fatalf("historical command identity conflict err=%v", err)
	}

	// The independently configured command-ledger bound is enforced even for
	// an otherwise valid command under the rotated key and exact current head.
	quotaCredential := backupIntegrationTarget(t, accountID, secondCredential.Reference.TargetID, secondCredential.Reference.BackupSetID)
	quotaCommand := backupGrantCommand(t, rotatedSigner, quotaCredential, uuid.New(), 5, rotateReference)
	if _, err := control.Submit(ctx, quotaCommand, controlBinding); !errors.Is(err, backupcustody.ErrConflict) {
		t.Fatalf("control ledger quota err=%v", err)
	}

	// A command and a data admission serialize on the same account/control row.
	// Either the upload admission linearizes before revocation, or it is denied;
	// no partial command/projection is permitted in either outcome.
	concurrencyLimits := limits
	concurrencyLimits.MaximumControlRecords = 8
	concurrencyLimits.MaximumActiveUploads = 4
	concurrencyStore, err := postgresstore.NewBackupCustodyStore(pool, deploymentID, concurrencyLimits)
	if err != nil {
		t.Fatal(err)
	}
	secondPayload, err := secondCommand.DecodedPayload()
	if err != nil || secondPayload.Effect.Grant == nil {
		t.Fatalf("second grant payload err=%v", err)
	}
	secondGrantReference, err := secondPayload.Effect.Grant.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	concurrentRevoke := backupRevokeCommand(t, rotatedSigner, uuid.New(), 5, rotateReference, secondGrantReference)
	concurrentControl := backupcustody.ControlCustody{Store: concurrencyStore, Registry: registry, Clock: clock}
	concurrentCoordinator := coordinator
	concurrentCoordinator.Store = concurrencyStore
	concurrentPublish := backupcustody.PublishRequest{Version: backupcustody.Version, RequestID: uuid.New(),
		RequestedAtMilliseconds: clock.now.UnixMilli(), Credential: secondCredential.Reference, Generation: 1}
	start := make(chan struct{})
	controlResult := make(chan error, 1)
	type uploadResult struct {
		record backupcustody.UploadRecord
		err    error
	}
	uploadOutcome := make(chan uploadResult, 1)
	go func() {
		<-start
		_, err := concurrentControl.Submit(ctx, concurrentRevoke, controlBinding)
		controlResult <- err
	}()
	go func() {
		<-start
		record, err := concurrentCoordinator.BeginUpload(ctx, secondCredential, concurrentPublish, binding)
		uploadOutcome <- uploadResult{record: record, err: err}
	}()
	close(start)
	if err := <-controlResult; err != nil {
		t.Fatalf("concurrent revoke: %v", err)
	}
	concurrentUpload := <-uploadOutcome
	if concurrentUpload.err != nil && !errors.Is(concurrentUpload.err, backupcustody.ErrUnauthorized) {
		t.Fatalf("concurrent upload admission err=%v", concurrentUpload.err)
	}
	if concurrentUpload.err == nil {
		chunkDigest := sha256.Sum256([]byte{0x01})
		if _, err := concurrentCoordinator.AppendUploadChunk(ctx, secondCredential, binding, concurrentUpload.record.UploadID, 0, []byte{0x01}, hex.EncodeToString(chunkDigest[:])); !errors.Is(err, backupcustody.ErrUnauthorized) {
			t.Fatalf("post-revocation append err=%v", err)
		}
		if _, err := pool.Exec(ctx, `DELETE FROM backup_custody_uploads WHERE account_id=$1 AND upload_id=$2`, accountID, concurrentUpload.record.UploadID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `DELETE FROM backup_custody_requests WHERE account_id=$1 AND request_id=$2`, accountID, concurrentPublish.RequestID); err != nil {
			t.Fatal(err)
		}
	}
	if err := concurrencyStore.ValidateControlLedger(ctx, accountID); err != nil {
		t.Fatalf("concurrent ledger validation: %v", err)
	}

	// Readiness validates exact command projections, not only foreign keys and
	// row counts. Each internally consistent SQL substitution below must fail.
	if _, err := pool.Exec(ctx, `UPDATE backup_custody_targets SET create_control_command_reference_digest=$3 WHERE account_id=$1 AND target_id=$2`, accountID, targetCredential.Reference.TargetID, revokeReference); err != nil {
		t.Fatal(err)
	}
	if err := concurrencyStore.ValidateControlLedger(ctx, accountID); err == nil {
		t.Fatal("wrong target command projection accepted")
	}
	if _, err := pool.Exec(ctx, `UPDATE backup_custody_targets SET create_control_command_reference_digest=$3 WHERE account_id=$1 AND target_id=$2`, accountID, targetCredential.Reference.TargetID, firstReference); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE backup_custody_credential_grants SET accepted_control_command_reference_digest=$3 WHERE account_id=$1 AND grant_reference_digest=$2`, accountID, initialGrantReference, rotateReference); err != nil {
		t.Fatal(err)
	}
	if err := concurrencyStore.ValidateControlLedger(ctx, accountID); err == nil {
		t.Fatal("wrong grant command projection accepted")
	}
	if _, err := pool.Exec(ctx, `UPDATE backup_custody_credential_grants SET accepted_control_command_reference_digest=$3 WHERE account_id=$1 AND grant_reference_digest=$2`, accountID, initialGrantReference, firstReference); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE backup_custody_credential_grant_transitions SET accepted_control_command_reference_digest=$3 WHERE account_id=$1 AND prior_grant_reference_digest=$2`, accountID, initialGrantReference, rotateReference); err != nil {
		t.Fatal(err)
	}
	if err := concurrencyStore.ValidateControlLedger(ctx, accountID); err == nil {
		t.Fatal("wrong transition command projection accepted")
	}
	if _, err := pool.Exec(ctx, `UPDATE backup_custody_credential_grant_transitions SET accepted_control_command_reference_digest=$3 WHERE account_id=$1 AND prior_grant_reference_digest=$2`, accountID, initialGrantReference, revokeReference); err != nil {
		t.Fatal(err)
	}
	foreignTargetID, foreignSetID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO backup_custody_targets(account_id,target_id,backup_set_id,create_control_command_reference_digest,created_at_milliseconds) VALUES($1,$2,$3,$4,$5)`, accountID, foreignTargetID, foreignSetID, rotateReference, clock.now.UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if err := concurrencyStore.ValidateControlLedger(ctx, accountID); err == nil {
		t.Fatal("orphan target projection accepted")
	}
	if _, err := pool.Exec(ctx, `DELETE FROM backup_custody_targets WHERE account_id=$1 AND target_id=$2`, accountID, foreignTargetID); err != nil {
		t.Fatal(err)
	}
	if err := concurrencyStore.ValidateControlLedger(ctx, accountID); err != nil {
		t.Fatalf("restored ledger rejected: %v", err)
	}

	// Begin, append and read each re-evaluate capability and exclusive expiry
	// after acquiring the same account/control row lock used by commands and
	// data operations. A pre-lock authorization time cannot survive a wait that
	// crosses credential expiry.
	concurrentRevokeReference, _ := concurrentRevoke.ReferenceDigest()
	expiryCredential := backupIntegrationTarget(t, accountID, secondCredential.Reference.TargetID, secondCredential.Reference.BackupSetID)
	expiryGrant := backupGrantCommand(t, rotatedSigner, expiryCredential, uuid.New(), 6, concurrentRevokeReference)
	if _, err := concurrentControl.Submit(ctx, expiryGrant, controlBinding); err != nil {
		t.Fatalf("expiry-test grant: %v", err)
	}
	clock.now = time.UnixMilli(9_000)
	expiryCoordinator := concurrentCoordinator
	expiryCoordinator.Clock = clock
	firstPublish := backupcustody.PublishRequest{Version: backupcustody.Version, RequestID: uuid.New(),
		RequestedAtMilliseconds: 9_000, Credential: expiryCredential.Reference, Generation: 1}
	firstUpload, err := expiryCoordinator.BeginUpload(ctx, expiryCredential, firstPublish, binding)
	if err != nil {
		t.Fatalf("expiry fixture begin generation 1: %v", err)
	}
	expiryWire := backupIntegrationOuterWire(t, expiryCredential.Reference.BackupSetID)
	expiryWireDigest := sha256.Sum256(expiryWire)
	if _, err := expiryCoordinator.AppendUploadChunk(ctx, expiryCredential, binding, firstUpload.UploadID, 0, expiryWire, hex.EncodeToString(expiryWireDigest[:])); err != nil {
		t.Fatalf("expiry fixture append generation 1: %v", err)
	}
	expiryFirstGeneration, err := expiryCoordinator.FinalizeUpload(ctx, expiryCredential, binding, firstUpload.UploadID)
	if err != nil {
		t.Fatalf("expiry fixture finalize generation 1: %v", err)
	}
	expiryFirstPayload, err := expiryFirstGeneration.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	expiryFirstGenerationReference, err := expiryFirstPayload.Generation.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	secondPublish := firstPublish
	secondPublish.RequestID = uuid.New()
	secondPublish.Generation = 2
	secondPublish.ExpectedHeadReferenceDigest = &expiryFirstGenerationReference
	secondUpload, err := expiryCoordinator.BeginUpload(ctx, expiryCredential, secondPublish, binding)
	if err != nil {
		t.Fatalf("expiry fixture begin generation 2: %v", err)
	}

	expiredBeginClock := newBackupLockCrossingClock(time.UnixMilli(9_999), time.UnixMilli(10_000))
	expiredBeginCoordinator := expiryCoordinator
	expiredBeginCoordinator.Clock = expiredBeginClock
	expiredPublish := secondPublish
	expiredPublish.RequestID = uuid.New()
	expiredPublish.Generation = 3
	beginLock := lockBackupAccount(t, ctx, pool, accountID)
	beginResult := make(chan error, 1)
	go func() {
		_, err := expiredBeginCoordinator.BeginUpload(ctx, expiryCredential, expiredPublish, binding)
		beginResult <- err
	}()
	<-expiredBeginClock.firstRead
	if err := beginLock.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-beginResult; !errors.Is(err, backupcustody.ErrUnauthorized) {
		t.Fatalf("begin crossing expiry err=%v", err)
	}
	var expiredBeginCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM backup_custody_requests WHERE request_id=$1`, expiredPublish.RequestID).Scan(&expiredBeginCount); err != nil || expiredBeginCount != 0 {
		t.Fatalf("expired begin durable count=%d err=%v", expiredBeginCount, err)
	}

	expiredAppendClock := newBackupLockCrossingClock(time.UnixMilli(9_999), time.UnixMilli(10_000))
	expiredAppendCoordinator := expiryCoordinator
	expiredAppendCoordinator.Clock = expiredAppendClock
	appendLock := lockBackupAccount(t, ctx, pool, accountID)
	appendResult := make(chan error, 1)
	go func() {
		_, err := expiredAppendCoordinator.AppendUploadChunk(ctx, expiryCredential, binding, secondUpload.UploadID, 0, []byte{0x01}, hex.EncodeToString(backupPostgresSHA256([]byte{0x01})))
		appendResult <- err
	}()
	<-expiredAppendClock.firstRead
	if err := appendLock.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-appendResult; !errors.Is(err, backupcustody.ErrUnauthorized) {
		t.Fatalf("append crossing expiry err=%v", err)
	}
	var expiredChunkCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM backup_custody_upload_chunks WHERE account_id=$1 AND upload_id=$2`, accountID, secondUpload.UploadID).Scan(&expiredChunkCount); err != nil || expiredChunkCount != 0 {
		t.Fatalf("expired append durable chunks=%d err=%v", expiredChunkCount, err)
	}

	expiredReadClock := newBackupLockCrossingClock(time.UnixMilli(9_999), time.UnixMilli(10_000))
	expiredReadCoordinator := expiryCoordinator
	expiredReadCoordinator.Clock = expiredReadClock
	expiredReadRequest := backupcustody.ReadRequest{Version: backupcustody.Version, RequestID: uuid.New(),
		RequestedAtMilliseconds: 9_999, Credential: expiryCredential.Reference}
	readLock := lockBackupAccount(t, ctx, pool, accountID)
	readResult := make(chan error, 1)
	go func() {
		result, err := expiredReadCoordinator.Read(ctx, expiryCredential, expiredReadRequest, binding)
		if result.Content != nil {
			_ = result.Content.Close()
			if err == nil {
				err = errors.New("expired read returned content")
			}
		}
		readResult <- err
	}()
	<-expiredReadClock.firstRead
	if err := readLock.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-readResult; !errors.Is(err, backupcustody.ErrUnauthorized) {
		t.Fatalf("read crossing expiry err=%v", err)
	}
}

type ledgerChunk struct{ offset, length, next int64 }
type backupUploadLedgerFixture struct{ accountID, uploadID uuid.UUID }

func resetBackupCustodySchema(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(ctx, `
		DROP TABLE IF EXISTS backup_custody_retention_receipts,
			backup_custody_upload_chunks, backup_custody_generations,
			backup_custody_uploads, backup_custody_credential_grant_transitions,
			backup_custody_credential_grants, backup_custody_targets,
			backup_custody_control_commands, backup_custody_account_control,
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

func backupIntegrationTarget(t *testing.T, accountID, targetID, setID uuid.UUID) backupcustody.TargetCredential {
	t.Helper()
	reference := backupcustody.TargetCredentialReference{Version: backupcustody.Version,
		AccountID: accountID, TargetID: targetID, BackupSetID: setID,
		CredentialID: uuid.New(), Capabilities: []backupcustody.Capability{
			backupcustody.Publish, backupcustody.Read, backupcustody.RetentionProof,
		}, ExpiresAtMilliseconds: 10_000,
		RequestNonce: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))}
	credential, err := backupcustody.NewTargetCredential(reference)
	if err != nil {
		t.Fatal(err)
	}
	return credential
}

type backupControlSigner struct {
	accountID  uuid.UUID
	generation uint64
	keyID      uuid.UUID
	private    ed25519.PrivateKey
}

func newBackupControlSigner(accountID uuid.UUID, generation uint64, seed byte) backupControlSigner {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	digest := sha256.Sum256(append([]byte("Facets backup custody account control key ID v1\x00"), public...))
	idBytes := append([]byte(nil), digest[:16]...)
	idBytes[6] = (idBytes[6] & 0x0f) | 0x50
	idBytes[8] = (idBytes[8] & 0x3f) | 0x80
	keyID, _ := uuid.FromBytes(idBytes)
	return backupControlSigner{accountID: accountID, generation: generation, keyID: keyID, private: private}
}

func (signer backupControlSigner) anchor(t *testing.T) backupcustody.ControlPossessionAnchor {
	t.Helper()
	public := signer.private.Public().(ed25519.PublicKey)
	fingerprint := sha256.Sum256(public)
	unsigned := backupcustody.ControlPossessionAnchorUnsigned{Version: backupcustody.CredentialAuthorityVersion,
		AccountID: signer.accountID, Algorithm: backupcustody.CredentialAuthoritySignatureAlgorithm,
		ControlGeneration: signer.generation, ControlKeyID: signer.keyID,
		PublicSigningKey: base64.RawURLEncoding.EncodeToString(public), SigningKeyFingerprint: hex.EncodeToString(fingerprint[:])}
	encoded, _ := json.Marshal(unsigned)
	anchor := backupcustody.ControlPossessionAnchor{Unsigned: unsigned,
		PossessionSignature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(signer.private,
			append([]byte("Facets backup custody account control possession v1\x00"), encoded...)))}
	if anchor.VerifyPossession() != nil {
		t.Fatal("invalid control anchor fixture")
	}
	return anchor
}

func backupCreateTargetCommand(t *testing.T, signer backupControlSigner, anchor backupcustody.ControlPossessionAnchor, credential backupcustody.TargetCredential, commandID uuid.UUID, sequence uint64) backupcustody.SignedControlCommand {
	t.Helper()
	predecessor, err := anchor.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	return backupCreateTargetCommandWithPredecessor(t, signer, credential, commandID, sequence, predecessor)
}

func backupCreateTargetCommandWithPredecessor(t *testing.T, signer backupControlSigner, credential backupcustody.TargetCredential, commandID uuid.UUID, sequence uint64, predecessor string) backupcustody.SignedControlCommand {
	t.Helper()
	authorizationDigest, err := credential.AuthorizationDigest()
	if err != nil {
		t.Fatal(err)
	}
	grant := backupcustody.CredentialGrant{Version: backupcustody.CredentialAuthorityVersion,
		Credential: credential.Reference, AuthorizationDigest: authorizationDigest}
	targetID, backupSetID := credential.Reference.TargetID, credential.Reference.BackupSetID
	payload := backupcustody.ControlCommandPayload{Version: backupcustody.CredentialAuthorityVersion,
		AccountID: signer.accountID, CommandID: commandID, ControlGeneration: signer.generation,
		ControlKeyID: signer.keyID, PredecessorReferenceDigest: predecessor, Sequence: sequence,
		Effect: backupcustody.ControlEffect{Kind: backupcustody.CreateTargetWithInitialGrant,
			TargetID: &targetID, BackupSetID: &backupSetID, Grant: &grant}}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	record := backupcustody.SignedControlCommand{Payload: encoded,
		AuthoritySignature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(signer.private,
			append([]byte("Facets backup custody account control command authority v1\x00"), encoded...)))}
	if _, err := record.DecodedPayload(); err != nil {
		t.Fatal(err)
	}
	return record
}

func backupGrantCommand(t *testing.T, signer backupControlSigner, credential backupcustody.TargetCredential, commandID uuid.UUID, sequence uint64, predecessor string) backupcustody.SignedControlCommand {
	t.Helper()
	authorizationDigest, err := credential.AuthorizationDigest()
	if err != nil {
		t.Fatal(err)
	}
	grant := backupcustody.CredentialGrant{Version: backupcustody.CredentialAuthorityVersion,
		Credential: credential.Reference, AuthorizationDigest: authorizationDigest}
	payload := backupcustody.ControlCommandPayload{Version: backupcustody.CredentialAuthorityVersion,
		AccountID: signer.accountID, CommandID: commandID, ControlGeneration: signer.generation,
		ControlKeyID: signer.keyID, PredecessorReferenceDigest: predecessor, Sequence: sequence,
		Effect: backupcustody.ControlEffect{Kind: backupcustody.GrantCredential, Grant: &grant}}
	return backupSignedControlCommand(t, signer, nil, payload)
}

func backupRevokeCommand(t *testing.T, signer backupControlSigner, commandID uuid.UUID, sequence uint64, predecessor, priorGrant string) backupcustody.SignedControlCommand {
	t.Helper()
	payload := backupcustody.ControlCommandPayload{Version: backupcustody.CredentialAuthorityVersion,
		AccountID: signer.accountID, CommandID: commandID, ControlGeneration: signer.generation,
		ControlKeyID: signer.keyID, PredecessorReferenceDigest: predecessor, Sequence: sequence,
		Effect: backupcustody.ControlEffect{Kind: backupcustody.RevokeCredential, PriorGrantReferenceDigest: &priorGrant}}
	return backupSignedControlCommand(t, signer, nil, payload)
}

func backupRotateControlCommand(t *testing.T, signer, next backupControlSigner, commandID uuid.UUID, sequence uint64, predecessor string) backupcustody.SignedControlCommand {
	t.Helper()
	nextAnchor := next.anchor(t)
	payload := backupcustody.ControlCommandPayload{Version: backupcustody.CredentialAuthorityVersion,
		AccountID: signer.accountID, CommandID: commandID, ControlGeneration: signer.generation,
		ControlKeyID: signer.keyID, PredecessorReferenceDigest: predecessor, Sequence: sequence,
		Effect: backupcustody.ControlEffect{Kind: backupcustody.RotateControlKey, ControlAnchor: &nextAnchor}}
	return backupSignedControlCommand(t, signer, &next, payload)
}

func backupSignedControlCommand(t *testing.T, signer backupControlSigner, next *backupControlSigner, payload backupcustody.ControlCommandPayload) backupcustody.SignedControlCommand {
	t.Helper()
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	record := backupcustody.SignedControlCommand{Payload: encoded,
		AuthoritySignature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(signer.private,
			append([]byte("Facets backup custody account control command authority v1\x00"), encoded...)))}
	if next != nil {
		signature := base64.RawURLEncoding.EncodeToString(ed25519.Sign(next.private,
			append([]byte("Facets backup custody account control command new possession v1\x00"), encoded...)))
		record.NewPossessionSignature = &signature
	}
	if _, err := record.DecodedPayload(); err != nil {
		t.Fatal(err)
	}
	return record
}

func createCommandID(t *testing.T, command backupcustody.SignedControlCommand) uuid.UUID {
	t.Helper()
	payload, err := command.DecodedPayload()
	if err != nil {
		t.Fatal(err)
	}
	return payload.CommandID
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

func backupMutatedReceipt(
	t *testing.T,
	signer *serviceauthority.DeploymentSigner,
	source serviceauthority.BackupCustodyReceipt,
	grantReference, headReference string,
) (serviceauthority.BackupCustodyReceipt, []byte, string) {
	t.Helper()
	payload, err := source.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	payload.CredentialGrantReferenceDigest = grantReference
	payload.ControlHeadReferenceDigest = headReference
	receipt, err := signer.SignBackupCustodyReceipt(payload)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := receipt.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	reference, err := receipt.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	return receipt, encoded, reference
}

type backupIntegrationClock struct{ now time.Time }

func (clock *backupIntegrationClock) Now() time.Time { return clock.now }

type backupLockCrossingClock struct {
	mu        sync.Mutex
	first     time.Time
	second    time.Time
	firstRead chan struct{}
	reads     int
}

func newBackupLockCrossingClock(first, second time.Time) *backupLockCrossingClock {
	return &backupLockCrossingClock{first: first, second: second, firstRead: make(chan struct{})}
}

func (clock *backupLockCrossingClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.reads++
	if clock.reads == 1 {
		close(clock.firstRead)
		return clock.first
	}
	return clock.second
}

func lockBackupAccount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, accountID uuid.UUID) pgx.Tx {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var locked uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT account_id FROM backup_custody_accounts WHERE account_id=$1 FOR UPDATE`, accountID).Scan(&locked); err != nil || locked != accountID {
		_ = tx.Rollback(ctx)
		t.Fatalf("lock Backup account got=%s err=%v", locked, err)
	}
	return tx
}

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
	publishRequestID := uuid.New()
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
	credentialSecret, err := backupcustody.NewTargetCredential(credential)
	if err != nil {
		t.Fatal(err)
	}
	controlSigner := newBackupControlSigner(accountID, 1, 93)
	anchor := controlSigner.anchor(t)
	command := backupCreateTargetCommand(t, controlSigner, anchor, credentialSecret, uuid.New(), 1)
	anchorBytes, _ := anchor.CanonicalJSON()
	anchorReference, _ := anchor.ReferenceDigest()
	commandBytes, _ := command.CanonicalJSON()
	commandReference, _ := command.ReferenceDigest()
	payload, _ := command.DecodedPayload()
	grantReference, _ := payload.Effect.Grant.ReferenceDigest()
	grantBytes, _ := json.Marshal(payload.Effect.Grant)
	acceptance := backupcustody.ControlCommandAcceptance{Version: backupcustody.CredentialAuthorityVersion,
		AccountID: accountID, CommandID: payload.CommandID, Sequence: 1, CommandReferenceDigest: commandReference,
		ControlHeadReferenceDigest: commandReference, ControlGeneration: 1, ControlKeyID: controlSigner.keyID,
		CredentialGrantReferenceDigest: &grantReference}
	acceptanceBytes, _ := json.Marshal(acceptance)
	digest := strings.Repeat("a", 64)
	if _, err := pool.Exec(ctx, `INSERT INTO backup_custody_accounts(account_id,claim_id,admission_id,admission_record,
			admission_authorization_digest,authority_revision,authority_manifest_digest,deployment_id,
			initial_anchor_record,initial_manifest_record,initial_enrollment_record,
			server_time_high_water_milliseconds,state,created_at_milliseconds)
		VALUES($1,$2,$3,'{}',$4,1,$4,$5,'{}','{}','{}',1000,'writable',1000)`,
		accountID, uuid.New(), uuid.New(), digest, deploymentID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO backup_custody_account_control(account_id,initial_anchor_record,initial_anchor_reference_digest,
			current_anchor_record,current_anchor_reference_digest,head_sequence,head_reference_digest,control_generation,control_key_id)
		VALUES($1,$2,$3,$2,$3,1,$4,1,$5)`, accountID, anchorBytes, anchorReference, commandReference, controlSigner.keyID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO backup_custody_control_commands(account_id,sequence,command_id,predecessor_reference_digest,
			command_reference_digest,command_record,acceptance_record,effect_kind,accepted_at_milliseconds)
		VALUES($1,1,$2,$3,$4,$5,$6,'create_target_with_initial_grant',1000)`,
		accountID, payload.CommandID, anchorReference, commandReference, commandBytes, acceptanceBytes); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO backup_custody_requests(request_id,account_id,operation,request_record)
		VALUES($1,$2,'begin_upload',$3)`, publishRequestID, accountID, requestBytes); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO backup_custody_targets(account_id,target_id,backup_set_id,
			create_control_command_reference_digest,created_at_milliseconds)
		VALUES($1,$2,$3,$4,1000)`, accountID, targetID, setID, commandReference); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO backup_custody_credential_grants(account_id,credential_id,target_id,backup_set_id,
			grant_reference_digest,grant_record,authorization_digest,accepted_control_command_reference_digest)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, accountID, credential.CredentialID, targetID, setID,
		grantReference, grantBytes, payload.Effect.Grant.AuthorizationDigest, commandReference); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO backup_custody_uploads(account_id,upload_id,target_id,backup_set_id,
			publish_request_id,request_record,committed_bytes,maximum_chunk_count,state,created_at_milliseconds)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,'uploading',1000)`, accountID, uploadID, targetID, setID,
		publishRequestID, requestBytes, committed, maximum); err != nil {
		t.Fatal(err)
	}
	for index, chunk := range chunks {
		if _, err := pool.Exec(ctx, `INSERT INTO backup_custody_upload_chunks(account_id,upload_id,chunk_offset,chunk_byte_count,chunk_sha256,next_offset) VALUES($1,$2,$3,$4,$5,$6)`, accountID, uploadID, chunk.offset, chunk.length, strings.Repeat(string(rune('a'+index)), 64), chunk.next); err != nil {
			t.Fatal(err)
		}
	}
	return backupUploadLedgerFixture{accountID: accountID, uploadID: uploadID}
}
