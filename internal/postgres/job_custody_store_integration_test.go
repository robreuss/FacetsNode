package postgres_test

import (
	"context"
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
		DROP TABLE IF EXISTS job_custody_chunks,job_custody_admissions,
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

func postgresJobCustodyDigest(value []byte) computequeue.Digest {
	digest := sha256.Sum256(value)
	return computequeue.Digest(fmt.Sprintf("%x", digest[:]))
}
