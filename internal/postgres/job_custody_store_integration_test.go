package postgres_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/robreuss/FacetsNode/internal/computequeue"
	"github.com/robreuss/FacetsNode/internal/jobcustody"
	postgresstore "github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
	"github.com/robreuss/FacetsNode/internal/testpostgres"
)

func TestPostgresJobCustodyLedgerRestartReplayAndQuotas(t *testing.T) {
	databaseURL := os.Getenv("FACETS_JOB_CUSTODY_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("FACETS_JOB_CUSTODY_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	lock, err := testpostgres.AcquireDisposableDatabaseLock(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `
		DROP TABLE IF EXISTS job_custody_worker_claims,job_custody_chunks,job_custody_admissions,
			job_custody_ledger CASCADE;
		DROP TABLE IF EXISTS facets_job_custody_schema_migrations;
	`); err != nil {
		t.Fatal(err)
	}
	if err := postgresstore.MigrateJobCustody(ctx, pool); err != nil {
		t.Fatal(err)
	}
	clock := fixedPostgresJobCustodyClock{value: time.UnixMilli(1_800_000_000_010)}
	limits := postgresstore.JobCustodyStoreLimits{
		MaximumAdmissions: 4, MaximumStagingBytes: 32, MaximumCustodyBytes: 32,
	}
	store, err := postgresstore.NewJobCustodyStore(pool, limits, clock)
	if err != nil {
		t.Fatal(err)
	}
	contents := []byte("opaque-custody-bytes")
	record := postgresJobCustodyAdmission(t, contents, 7, "11111111-1111-4111-8111-111111111111")
	reserved, created, err := store.ReserveAdmission(ctx, record)
	if err != nil || !created || reserved.ValidateStored() != nil {
		t.Fatalf("reserve created=%v record=%+v err=%v", created, reserved, err)
	}
	if retry, created, err := store.ReserveAdmission(ctx, record); err != nil || created ||
		retry.AcceptedAt != record.AcceptedAt {
		t.Fatalf("exact reserve retry created=%v record=%+v err=%v", created, retry, err)
	}
	conflict := record
	conflict.AcceptedAt++
	conflict.UpdatedAtMillis++
	if _, _, err := store.ReserveAdmission(ctx, conflict); !errors.Is(err, jobcustody.ErrConflict) {
		t.Fatalf("changed historical acceptance error=%v", err)
	}

	for index := int64(0); index < record.Header.ProtectedObject.ChunkCount; index++ {
		offset := index * record.Header.ProtectedObject.ChunkByteCount
		end := min(offset+record.Header.ProtectedObject.ChunkByteCount, int64(len(contents)))
		chunk := contents[offset:end]
		request := jobcustody.AppendRequest{
			CapsuleID: record.Header.CapsuleID, ChunkIndex: index, Offset: offset,
			ByteCount: int64(len(chunk)), ChunkSHA256: postgresJobCustodyDigest(chunk),
		}
		lease, err := store.BeginAppend(ctx, request)
		if err != nil || lease.ExistingNextOffset() != nil {
			t.Fatalf("begin chunk %d err=%v", index, err)
		}
		if err := lease.Commit(ctx, end); err != nil {
			t.Fatalf("commit chunk %d: %v", index, err)
		}
		if index == 0 {
			replay, err := store.BeginAppend(ctx, request)
			if err != nil {
				t.Fatalf("begin chunk replay: %v", err)
			}
			existingNext := replay.ExistingNextOffset()
			if existingNext == nil || *existingNext != end {
				t.Fatalf("chunk replay next=%v", existingNext)
			}
			if err := replay.Abort(ctx); err != nil {
				t.Fatal(err)
			}
		}
	}
	finalization, err := store.BeginFinalization(ctx, record.Header.CapsuleID)
	if err != nil {
		t.Fatal(err)
	}
	committedAt := int64(1_800_000_000_010)
	receiptBytes := postgresJobCustodyReceipt(t, record, committedAt)
	retained, err := finalization.Commit(
		ctx, "objects/"+string(record.Header.CapsuleID), receiptBytes, committedAt,
	)
	if err != nil || retained.State != jobcustody.AdmissionRetained {
		t.Fatalf("retained=%+v err=%v", retained, err)
	}

	reopened, err := postgresstore.NewJobCustodyStore(pool, limits, clock)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := reopened.LoadAdmission(ctx, record.Header.CapsuleID)
	if err != nil || loaded.ValidateStored() != nil || loaded.State != jobcustody.AdmissionRetained ||
		loaded.ObjectPath != retained.ObjectPath {
		t.Fatalf("reopened=%+v err=%v", loaded, err)
	}
	retryFinalization, err := reopened.BeginFinalization(ctx, record.Header.CapsuleID)
	if err != nil || retryFinalization.Admission().State != jobcustody.AdmissionRetained {
		t.Fatalf("finalization retry err=%v", err)
	}
	if err := retryFinalization.Abort(ctx); err != nil {
		t.Fatal(err)
	}
	claimID := uuid.MustParse("55555555-5555-4555-8555-555555555555")
	_, workerPermitKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	claimAuthorization := postgresWorkerClaimAuthorization(
		t, record, claimID, 1_800_000_050_000, workerPermitKey,
	)
	claim, claimedAdmission, err := reopened.ClaimNext(ctx, claimAuthorization)
	if err != nil || claim.ClaimID != claimID ||
		claimedAdmission.Header.CapsuleID != record.Header.CapsuleID {
		t.Fatalf("claim=%+v admission=%+v err=%v", claim, claimedAdmission, err)
	}
	if replay, _, err := reopened.ClaimNext(ctx, claimAuthorization); err != nil || replay != claim {
		t.Fatalf("claim replay=%+v err=%v", replay, err)
	}
	renewalAuthorization := postgresWorkerClaimAuthorization(
		t, record, claimID, 1_800_000_070_000, workerPermitKey,
	)
	renewed, _, err := reopened.RenewClaim(ctx, renewalAuthorization)
	if err != nil || renewed.LeaseExpiresAt != 1_800_000_070_000 ||
		renewed.ClaimPermitDigest == claim.ClaimPermitDigest {
		t.Fatalf("renewed=%+v err=%v", renewed, err)
	}
	secondAuthorization := postgresWorkerClaimAuthorization(
		t, record, uuid.MustParse("66666666-6666-4666-8666-666666666666"),
		1_800_000_050_000, workerPermitKey,
	)
	if _, _, err := reopened.ClaimNext(ctx, secondAuthorization); !errors.Is(err, jobcustody.ErrNoWork) {
		t.Fatalf("active claim allowed duplicate assignment: %v", err)
	}
	resultContents := []byte("result-data")
	resultDescriptor, err := computequeue.NewJobCapsuleProtectedObjectDescriptor(
		int64(len(resultContents)), postgresJobCustodyDigest(resultContents), 5,
	)
	if err != nil {
		t.Fatal(err)
	}
	resultHeader, err := jobcustody.NewWorkerResultHeader(
		record.Header.AssignmentID,
		claimID,
		record.Header.CapsuleID,
		"77777777-7777-4777-8777-777777777777",
		resultDescriptor,
		computequeue.SHA256Digest("postgres-job-custody-result", "result-set"),
		computequeue.SHA256Digest("postgres-job-custody-result", "execution-receipt"),
		record.Header.RetentionUntil,
	)
	if err != nil {
		t.Fatal(err)
	}
	resultRecord := jobcustody.ResultRecord{
		Header: resultHeader, RouteAuthorityID: renewed.RouteAuthorityID,
		RouteRecipientWorkerID:       renewed.RouteRecipientWorkerID,
		RouteRecipientKeyFingerprint: renewed.RouteRecipientKeyFingerprint,
		WorkerCapabilitiesDigest:     renewed.WorkerCapabilitiesDigest,
		WorkerOwnerAuthorityDigest:   renewed.WorkerOwnerAuthorityDigest,
		ClaimPermitDigest:            renewed.ClaimPermitDigest,
		ResultPermitDigest: computequeue.SHA256Digest(
			"postgres-job-custody-result", "result-permit",
		),
		AcceptedAt: 1_800_000_000_010, State: jobcustody.ResultStaging,
		UpdatedAtMillis: 1_800_000_000_010,
	}
	reservedResult, created, err := reopened.ReserveResult(ctx, resultRecord)
	if err != nil || !created || reservedResult.ValidateStored() != nil {
		t.Fatalf("reserve result created=%v record=%+v err=%v", created, reservedResult, err)
	}
	if retry, created, err := reopened.ReserveResult(ctx, resultRecord); err != nil || created ||
		retry.AcceptedAt != resultRecord.AcceptedAt {
		t.Fatalf("exact result reserve retry created=%v record=%+v err=%v", created, retry, err)
	}
	for index := int64(0); index < resultDescriptor.ChunkCount; index++ {
		offset := index * resultDescriptor.ChunkByteCount
		end := min(offset+resultDescriptor.ChunkByteCount, int64(len(resultContents)))
		chunk := resultContents[offset:end]
		request := jobcustody.AppendRequest{
			CapsuleID: resultHeader.ResultCapsuleID, ChunkIndex: index, Offset: offset,
			ByteCount: int64(len(chunk)), ChunkSHA256: postgresJobCustodyDigest(chunk),
		}
		lease, err := reopened.BeginResultAppend(ctx, request)
		if err != nil || lease.ExistingNextOffset() != nil {
			t.Fatalf("begin result chunk %d err=%v", index, err)
		}
		if err := lease.Commit(ctx, end); err != nil {
			t.Fatalf("commit result chunk %d: %v", index, err)
		}
		if index == 0 {
			replay, err := reopened.BeginResultAppend(ctx, request)
			if err != nil {
				t.Fatalf("begin result chunk replay: %v", err)
			}
			existingNext := replay.ExistingNextOffset()
			if existingNext == nil || *existingNext != end {
				t.Fatalf("result chunk replay next=%v", existingNext)
			}
			if err := replay.Abort(ctx); err != nil {
				t.Fatal(err)
			}
		}
	}
	resultFinalization, err := reopened.BeginResultFinalization(ctx, resultHeader.ResultCapsuleID)
	if err != nil {
		t.Fatal(err)
	}
	resultCommittedAt := int64(1_800_000_000_010)
	resultReceiptBytes := postgresJobCustodyResultReceipt(t, resultRecord, resultCommittedAt)
	retainedResult, err := resultFinalization.Commit(
		ctx, "objects/"+string(resultHeader.ResultCapsuleID),
		resultReceiptBytes, resultCommittedAt,
	)
	if err != nil || retainedResult.State != jobcustody.ResultRetained {
		t.Fatalf("retained result=%+v err=%v", retainedResult, err)
	}
	resultReopened, err := postgresstore.NewJobCustodyStore(pool, limits, clock)
	if err != nil {
		t.Fatal(err)
	}
	loadedResult, err := resultReopened.LoadResult(ctx, resultHeader.ResultCapsuleID)
	if err != nil || loadedResult.ValidateStored() != nil ||
		loadedResult.State != jobcustody.ResultRetained ||
		loadedResult.ObjectPath != retainedResult.ObjectPath {
		t.Fatalf("reopened result=%+v err=%v", loadedResult, err)
	}

	quotaRecord := postgresJobCustodyAdmission(
		t, []byte("this-admission-exceeds-the-total-byte-quota"), 8,
		"22222222-2222-4222-8222-222222222222",
	)
	if _, _, err := reopened.ReserveAdmission(ctx, quotaRecord); !errors.Is(err, jobcustody.ErrUnavailable) {
		t.Fatalf("over-quota admission error=%v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM job_custody_chunks WHERE capsule_id=$1 AND chunk_index=0`,
		uuid.MustParse(string(record.Header.CapsuleID))); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.LoadAdmission(ctx, record.Header.CapsuleID); !errors.Is(err, jobcustody.ErrInvalid) {
		t.Fatalf("incomplete durable chunk ledger error=%v", err)
	}
}

func postgresWorkerClaimAuthorization(
	t *testing.T,
	record jobcustody.AdmissionRecord,
	claimID uuid.UUID,
	expiresAt computequeue.Timestamp,
	privateKey ed25519.PrivateKey,
) jobcustody.WorkerClaimAuthorization {
	t.Helper()
	if privateKey == nil {
		_, generated, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		privateKey = generated
	}
	authorityID := record.RouteAuthorityID
	payload := jobcustody.WorkerClaimPermitPayload{
		AuthorityID: authorityID, ClaimID: claimID,
		ExpiresAt: expiresAt, IssuedAt: 1_800_000_000_009,
		PermitID:                     uuid.New(),
		RouteRecipientKeyFingerprint: record.Header.RouteRecipientKeyFingerprint,
		RouteRecipientWorkerID:       record.Header.RouteRecipientWorkerID,
		Version:                      jobcustody.WorkerClaimPermitVersion,
		WorkerCapabilitiesDigest:     record.WorkerCapabilitiesDigest,
		WorkerOwnerAuthorityDigest: computequeue.SHA256Digest(
			"postgres-job-custody-worker-owner", string(record.Header.RouteRecipientWorkerID),
		),
	}
	signer, err := jobcustody.NewWorkerClaimPermitSigner(authorityID, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	key, err := jobcustody.NewAdmissionPermitVerificationKey(authorityID, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := jobcustody.NewAdmissionPermitVerifier(
		[]jobcustody.AdmissionPermitVerificationKey{key},
	)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := verifier.VerifyWorkerClaim(permit, 1_800_000_000_010)
	if err != nil {
		t.Fatal(err)
	}
	return authorization
}

type fixedPostgresJobCustodyClock struct{ value time.Time }

func (clock fixedPostgresJobCustodyClock) Now() time.Time { return clock.value }

func postgresJobCustodyAdmission(
	t *testing.T,
	contents []byte,
	chunkBytes int64,
	capsuleID computequeue.JobCapsuleID,
) jobcustody.AdmissionRecord {
	t.Helper()
	descriptor, err := computequeue.NewJobCapsuleProtectedObjectDescriptor(
		int64(len(contents)), postgresJobCustodyDigest(contents), chunkBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	header, err := computequeue.NewJobCustodyAdmissionHeader(
		capsuleID,
		"33333333-3333-4333-8333-333333333333",
		"44444444-4444-4444-8444-444444444444",
		computequeue.SHA256Digest("postgres-job-custody-worker-key", string(capsuleID)),
		descriptor,
		1_800_000_000_000,
		1_800_000_100_000,
		1_800_000_200_000,
	)
	if err != nil {
		t.Fatal(err)
	}
	signer := computequeue.ReceiptSignerBinding{
		SignerID: "source.device.postgres.fixture", SigningKeyID: "source.key.postgres.fixture",
		SigningKeyRevision: 9,
		SignatureProfileID: computequeue.JobCustodyP256AdmissionSignatureProfile,
	}
	envelope, err := computequeue.NewJobCustodySignedAdmissionEnvelope(
		header, signer.SignatureProfileID,
		computequeue.SignatureValue(base64.RawURLEncoding.EncodeToString(make([]byte, 64))),
	)
	if err != nil {
		t.Fatal(err)
	}
	envelopeBytes, err := computequeue.EncodeJobCustodyAdmissionCanonical(envelope)
	if err != nil {
		t.Fatal(err)
	}
	record := jobcustody.AdmissionRecord{
		EnvelopeBytes: envelopeBytes, Header: header, ExpectedSigner: signer,
		AdmissionPermitDigest: computequeue.SHA256Digest(
			"postgres-job-custody-permit", string(capsuleID),
		),
		RouteAuthorityID: uuid.MustParse("8c000000-0000-0000-0000-000000000001"),
		WorkerCapabilitiesDigest: computequeue.SHA256Digest(
			"postgres-job-custody-worker-capabilities", string(capsuleID),
		),
		AcceptedAt: 1_800_000_000_010, State: jobcustody.AdmissionStaging,
		UpdatedAtMillis: 1_800_000_000_010,
	}
	if err := record.ValidateStored(); err != nil {
		t.Fatal(err)
	}
	return record
}

func postgresJobCustodyReceipt(
	t *testing.T,
	record jobcustody.AdmissionRecord,
	committedAt int64,
) []byte {
	t.Helper()
	seed := make([]byte, 32)
	seed[31] = 7
	deploymentID := uuid.MustParse("8b000000-0000-0000-0000-000000000001")
	signer, err := serviceauthority.NewDeploymentSigner(deploymentID, seed)
	if err != nil {
		t.Fatal(err)
	}
	capsuleID := uuid.MustParse(string(record.Header.CapsuleID))
	assignmentID := uuid.MustParse(string(record.Header.AssignmentID))
	envelopeDigest, err := jobcustody.AdmissionEnvelopeDigest(record.EnvelopeBytes)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := signer.SignJobCustodyReceipt(serviceauthority.JobCustodyReceiptPayload{
		AdmissionEnvelopeDigest:         string(envelopeDigest),
		AdmissionIdempotencyKey:         string(record.Header.IdempotencyKey),
		AdmissionPermitDigest:           string(record.AdmissionPermitDigest),
		AssignmentID:                    assignmentID,
		CapsuleID:                       capsuleID,
		CommittedAtMilliseconds:         committedAt,
		DeploymentID:                    deploymentID,
		Kind:                            serviceauthority.JobCustodyCommittedReceiptKind,
		ProtectedObjectByteCount:        record.Header.ProtectedObject.ByteCount,
		ProtectedObjectDescriptorDigest: string(record.Header.ProtectedObject.Digest()),
		ProtectedObjectSHA256:           string(record.Header.ProtectedObject.SHA256),
		RetentionUntilMilliseconds:      int64(record.Header.RetentionUntil),
		Version:                         serviceauthority.JobCustodyReceiptVersion,
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := receipt.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func postgresJobCustodyResultReceipt(
	t *testing.T,
	record jobcustody.ResultRecord,
	committedAt int64,
) []byte {
	t.Helper()
	seed := make([]byte, 32)
	seed[31] = 7
	deploymentID := uuid.MustParse("8b000000-0000-0000-0000-000000000001")
	signer, err := serviceauthority.NewDeploymentSigner(deploymentID, seed)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := signer.SignJobCustodyResultReceipt(
		serviceauthority.JobCustodyResultReceiptPayload{
			AssignmentID: uuid.MustParse(string(record.Header.AssignmentID)),
			ClaimID:      record.Header.ClaimID, ClaimPermitDigest: string(record.ClaimPermitDigest),
			CommittedAtMilliseconds: committedAt, DeploymentID: deploymentID,
			InputCapsuleID:                  uuid.MustParse(string(record.Header.InputCapsuleID)),
			Kind:                            serviceauthority.JobCustodyResultReceiptKind,
			ProtectedObjectByteCount:        record.Header.ProtectedObject.ByteCount,
			ProtectedObjectDescriptorDigest: string(record.Header.ProtectedObject.Digest()),
			ProtectedObjectSHA256:           string(record.Header.ProtectedObject.SHA256),
			ResultCapsuleID:                 uuid.MustParse(string(record.Header.ResultCapsuleID)),
			ResultIdempotencyKey:            string(record.Header.IdempotencyKey),
			ResultPermitDigest:              string(record.ResultPermitDigest),
			ResultSetDigest:                 string(record.Header.ResultSetDigest),
			RetentionUntilMilliseconds:      int64(record.Header.RetentionUntil),
			Version:                         serviceauthority.JobCustodyResultReceiptVersion,
			WorkerExecutionReceiptDigest:    string(record.Header.WorkerExecutionReceiptDigest),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := receipt.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func postgresJobCustodyDigest(value []byte) computequeue.Digest {
	digest := sha256.Sum256(value)
	return computequeue.Digest(fmt.Sprintf("%x", digest[:]))
}
