package postgres

import (
	"bytes"
	"context"
	"errors"
	"math"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/robreuss/FacetsNode/internal/computequeue"
	"github.com/robreuss/FacetsNode/internal/jobcustody"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

type JobCustodyStoreLimits struct {
	MaximumAdmissions int64
	// MaximumStagingBytes bounds protected objects not yet published. Admission
	// reserves the object's full descriptor size in this service-local quota.
	MaximumStagingBytes int64
	// MaximumCustodyBytes bounds all admitted protected objects, including
	// staging objects that can later become retained without a quota race.
	MaximumCustodyBytes int64
}

type JobCustodyStore struct {
	pool   *pgxpool.Pool
	limits JobCustodyStoreLimits
	clock  jobcustody.Clock
}

func NewJobCustodyStore(
	pool *pgxpool.Pool,
	limits JobCustodyStoreLimits,
	clock jobcustody.Clock,
) (*JobCustodyStore, error) {
	if pool == nil || clock == nil || limits.MaximumAdmissions <= 0 ||
		limits.MaximumStagingBytes <= 0 || limits.MaximumCustodyBytes <= 0 ||
		limits.MaximumStagingBytes > limits.MaximumCustodyBytes {
		return nil, jobcustody.ErrInvalid
	}
	return &JobCustodyStore{pool: pool, limits: limits, clock: clock}, nil
}

type jobCustodyQuerier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

func (store *JobCustodyStore) LoadAdmission(
	ctx context.Context,
	capsuleID computequeue.JobCapsuleID,
) (jobcustody.AdmissionRecord, error) {
	if store == nil || store.pool == nil || ctx == nil || capsuleID.Validate() != nil {
		return jobcustody.AdmissionRecord{}, jobcustody.ErrInvalid
	}
	return loadJobCustodyAdmission(ctx, store.pool, capsuleID, false)
}

func (store *JobCustodyStore) ReserveAdmission(
	ctx context.Context,
	candidate jobcustody.AdmissionRecord,
) (jobcustody.AdmissionRecord, bool, error) {
	if store == nil || store.pool == nil || ctx == nil || candidate.ValidateStored() != nil ||
		candidate.State != jobcustody.AdmissionStaging || candidate.CommittedBytes != 0 ||
		candidate.ObjectPath != "" || len(candidate.CustodyReceiptBytes) != 0 ||
		candidate.ExpectedSigner.SigningKeyRevision > math.MaxInt64 {
		return jobcustody.AdmissionRecord{}, false, jobcustody.ErrInvalid
	}
	capsuleID, err := uuid.Parse(string(candidate.Header.CapsuleID))
	if err != nil {
		return jobcustody.AdmissionRecord{}, false, jobcustody.ErrInvalid
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return jobcustody.AdmissionRecord{}, false, err
	}
	defer tx.Rollback(ctx)
	if err := lockJobCustodyLedger(ctx, tx); err != nil {
		return jobcustody.AdmissionRecord{}, false, err
	}
	if existing, err := loadJobCustodyAdmission(ctx, tx, candidate.Header.CapsuleID, false); err == nil {
		if !sameStoredAdmission(existing, candidate) {
			return jobcustody.AdmissionRecord{}, false, jobcustody.ErrConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return jobcustody.AdmissionRecord{}, false, err
		}
		return existing, false, nil
	} else if !errors.Is(err, jobcustody.ErrMissing) {
		return jobcustody.AdmissionRecord{}, false, err
	}
	var conflictingCapsule uuid.UUID
	err = tx.QueryRow(ctx, `SELECT capsule_id FROM job_custody_admissions WHERE idempotency_key=$1`,
		string(candidate.Header.IdempotencyKey)).Scan(&conflictingCapsule)
	if err == nil {
		return jobcustody.AdmissionRecord{}, false, jobcustody.ErrConflict
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return jobcustody.AdmissionRecord{}, false, err
	}
	var count, stagingBytes, totalBytes int64
	if err := tx.QueryRow(ctx, `
		SELECT count(*),
			COALESCE(sum(protected_byte_count) FILTER (WHERE state='staging'),0),
			COALESCE(sum(protected_byte_count),0)
		FROM job_custody_admissions`,
	).Scan(&count, &stagingBytes, &totalBytes); err != nil {
		return jobcustody.AdmissionRecord{}, false, err
	}
	byteCount := candidate.Header.ProtectedObject.ByteCount
	if count >= store.limits.MaximumAdmissions ||
		wouldExceed(stagingBytes, byteCount, store.limits.MaximumStagingBytes) ||
		wouldExceed(totalBytes, byteCount, store.limits.MaximumCustodyBytes) {
		return jobcustody.AdmissionRecord{}, false, jobcustody.ErrUnavailable
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO job_custody_admissions(
			capsule_id,idempotency_key,envelope_record,
			expected_signer_id,expected_signing_key_id,
			expected_signing_key_revision,expected_signature_profile_id,
			admission_permit_digest,
			accepted_at_milliseconds,protected_byte_count,committed_bytes,
			state,object_path,updated_at_milliseconds
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,0,'staging',NULL,$9)`,
		capsuleID, string(candidate.Header.IdempotencyKey), candidate.EnvelopeBytes,
		string(candidate.ExpectedSigner.SignerID), string(candidate.ExpectedSigner.SigningKeyID),
		int64(candidate.ExpectedSigner.SigningKeyRevision), candidate.ExpectedSigner.SignatureProfileID,
		string(candidate.AdmissionPermitDigest), int64(candidate.AcceptedAt), byteCount,
	)
	if err != nil {
		return jobcustody.AdmissionRecord{}, false, mapJobCustodyWriteError(err)
	}
	if err := advanceJobCustodyLedger(ctx, tx); err != nil {
		return jobcustody.AdmissionRecord{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return jobcustody.AdmissionRecord{}, false, err
	}
	return cloneJobCustodyAdmission(candidate), true, nil
}

func (store *JobCustodyStore) BeginAppend(
	ctx context.Context,
	request jobcustody.AppendRequest,
) (jobcustody.AppendLease, error) {
	if store == nil || store.pool == nil || ctx == nil || request.CapsuleID.Validate() != nil {
		return nil, jobcustody.ErrInvalid
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (jobcustody.AppendLease, error) {
		_ = tx.Rollback(context.WithoutCancel(ctx))
		return nil, cause
	}
	record, err := loadJobCustodyAdmission(ctx, tx, request.CapsuleID, true)
	if err != nil {
		return fail(err)
	}
	if record.State != jobcustody.AdmissionStaging ||
		request.Validate(record.Header.ProtectedObject) != nil {
		return fail(jobcustody.ErrInvalid)
	}
	lease := &jobCustodyAppendLease{store: store, tx: tx, record: record, request: request}
	capsuleUUID, err := uuid.Parse(string(request.CapsuleID))
	if err != nil {
		return fail(jobcustody.ErrInvalid)
	}
	lease.capsuleUUID = capsuleUUID
	var storedIndex, storedOffset, storedCount, storedNext int64
	var storedDigest string
	err = tx.QueryRow(ctx, `
		SELECT chunk_index,chunk_offset,chunk_byte_count,chunk_sha256,next_offset
		FROM job_custody_chunks WHERE capsule_id=$1 AND chunk_index=$2`,
		capsuleUUID, request.ChunkIndex,
	).Scan(&storedIndex, &storedOffset, &storedCount, &storedDigest, &storedNext)
	if err == nil {
		if storedIndex != request.ChunkIndex || storedOffset != request.Offset ||
			storedCount != request.ByteCount || storedDigest != string(request.ChunkSHA256) ||
			storedNext != request.Offset+request.ByteCount || storedNext > record.CommittedBytes {
			return fail(jobcustody.ErrConflict)
		}
		lease.existingNext = &storedNext
		return lease, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return fail(err)
	}
	if record.CommittedBytes != request.Offset {
		return fail(jobcustody.ErrConflict)
	}
	return lease, nil
}

func (store *JobCustodyStore) BeginFinalization(
	ctx context.Context,
	capsuleID computequeue.JobCapsuleID,
) (jobcustody.FinalizationLease, error) {
	if store == nil || store.pool == nil || ctx == nil || capsuleID.Validate() != nil {
		return nil, jobcustody.ErrInvalid
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	record, err := loadJobCustodyAdmission(ctx, tx, capsuleID, true)
	if err != nil {
		_ = tx.Rollback(context.WithoutCancel(ctx))
		return nil, err
	}
	return &jobCustodyFinalizationLease{store: store, tx: tx, record: record}, nil
}

type jobCustodyAppendLease struct {
	store        *JobCustodyStore
	tx           pgx.Tx
	record       jobcustody.AdmissionRecord
	request      jobcustody.AppendRequest
	capsuleUUID  uuid.UUID
	existingNext *int64
	closed       bool
}

func (lease *jobCustodyAppendLease) Admission() jobcustody.AdmissionRecord {
	return cloneJobCustodyAdmission(lease.record)
}

func (lease *jobCustodyAppendLease) ExistingNextOffset() *int64 {
	if lease.existingNext == nil {
		return nil
	}
	value := *lease.existingNext
	return &value
}

func (lease *jobCustodyAppendLease) Commit(ctx context.Context, next int64) error {
	if lease == nil || lease.closed || lease.existingNext != nil ||
		next != lease.request.Offset+lease.request.ByteCount {
		return jobcustody.ErrConflict
	}
	_, err := lease.tx.Exec(ctx, `
		INSERT INTO job_custody_chunks(
			capsule_id,chunk_index,chunk_offset,chunk_byte_count,chunk_sha256,next_offset
		) VALUES($1,$2,$3,$4,$5,$6)`,
		lease.capsuleUUID, lease.request.ChunkIndex, lease.request.Offset,
		lease.request.ByteCount, string(lease.request.ChunkSHA256), next,
	)
	if err != nil {
		return mapJobCustodyWriteError(err)
	}
	updatedAt := monotonicJobCustodyTime(lease.store.clock, lease.record.UpdatedAtMillis)
	tag, err := lease.tx.Exec(ctx, `
		UPDATE job_custody_admissions
		SET committed_bytes=$3,updated_at_milliseconds=$4,stored_at=now()
		WHERE capsule_id=$1 AND state='staging' AND committed_bytes=$2`,
		lease.capsuleUUID, lease.request.Offset, next, updatedAt,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return jobcustody.ErrConflict
	}
	if err := advanceJobCustodyLedger(ctx, lease.tx); err != nil {
		return err
	}
	if err := lease.tx.Commit(ctx); err != nil {
		return err
	}
	lease.closed = true
	return nil
}

func (lease *jobCustodyAppendLease) Abort(ctx context.Context) error {
	if lease == nil || lease.closed {
		return nil
	}
	lease.closed = true
	err := lease.tx.Rollback(ctx)
	if errors.Is(err, pgx.ErrTxClosed) {
		return nil
	}
	return err
}

type jobCustodyFinalizationLease struct {
	store  *JobCustodyStore
	tx     pgx.Tx
	record jobcustody.AdmissionRecord
	closed bool
}

func (lease *jobCustodyFinalizationLease) Admission() jobcustody.AdmissionRecord {
	return cloneJobCustodyAdmission(lease.record)
}

func (lease *jobCustodyFinalizationLease) Commit(
	ctx context.Context,
	objectPath string,
	receiptBytes []byte,
	committedAt int64,
) (jobcustody.AdmissionRecord, error) {
	if lease == nil || lease.closed || lease.record.State != jobcustody.AdmissionStaging ||
		lease.record.CommittedBytes != lease.record.Header.ProtectedObject.ByteCount ||
		objectPath != "objects/"+string(lease.record.Header.CapsuleID) ||
		len(receiptBytes) == 0 ||
		len(receiptBytes) > serviceauthority.MaximumJobCustodyReceiptRecordByteCount ||
		committedAt < lease.record.UpdatedAtMillis ||
		committedAt > int64(lease.record.Header.RetentionUntil) {
		return jobcustody.AdmissionRecord{}, jobcustody.ErrConflict
	}
	capsuleUUID, err := uuid.Parse(string(lease.record.Header.CapsuleID))
	if err != nil {
		return jobcustody.AdmissionRecord{}, jobcustody.ErrInvalid
	}
	tag, err := lease.tx.Exec(ctx, `
		UPDATE job_custody_admissions
		SET state='retained',object_path=$2,custody_receipt_record=$3,
			updated_at_milliseconds=$4,stored_at=now()
		WHERE capsule_id=$1 AND state='staging' AND
			committed_bytes=protected_byte_count`,
		capsuleUUID, objectPath, receiptBytes, committedAt,
	)
	if err != nil {
		return jobcustody.AdmissionRecord{}, mapJobCustodyWriteError(err)
	}
	if tag.RowsAffected() != 1 {
		return jobcustody.AdmissionRecord{}, jobcustody.ErrConflict
	}
	if err := advanceJobCustodyLedger(ctx, lease.tx); err != nil {
		return jobcustody.AdmissionRecord{}, err
	}
	committed, err := loadJobCustodyAdmission(
		ctx, lease.tx, lease.record.Header.CapsuleID, false,
	)
	if err != nil {
		return jobcustody.AdmissionRecord{}, err
	}
	if err := lease.tx.Commit(ctx); err != nil {
		return jobcustody.AdmissionRecord{}, err
	}
	lease.closed = true
	return committed, nil
}

func (lease *jobCustodyFinalizationLease) Abort(ctx context.Context) error {
	if lease == nil || lease.closed {
		return nil
	}
	lease.closed = true
	err := lease.tx.Rollback(ctx)
	if errors.Is(err, pgx.ErrTxClosed) {
		return nil
	}
	return err
}

func loadJobCustodyAdmission(
	ctx context.Context,
	querier jobCustodyQuerier,
	capsuleID computequeue.JobCapsuleID,
	forUpdate bool,
) (jobcustody.AdmissionRecord, error) {
	capsuleUUID, err := uuid.Parse(string(capsuleID))
	if err != nil {
		return jobcustody.AdmissionRecord{}, jobcustody.ErrInvalid
	}
	query := `
		SELECT capsule_id,idempotency_key,envelope_record,
			expected_signer_id,expected_signing_key_id,
			expected_signing_key_revision,expected_signature_profile_id,
			admission_permit_digest,
			accepted_at_milliseconds,protected_byte_count,committed_bytes,
			state,object_path,custody_receipt_record,updated_at_milliseconds
		FROM job_custody_admissions WHERE capsule_id=$1`
	if forUpdate {
		query += " FOR UPDATE"
	}
	var storedCapsule uuid.UUID
	var idempotencyKey, signerID, signingKeyID, signatureProfileID, permitDigest, state string
	var envelopeBytes, receiptBytes []byte
	var signingKeyRevision, acceptedAt, protectedByteCount, committedBytes, updatedAt int64
	var objectPath *string
	err = querier.QueryRow(ctx, query, capsuleUUID).Scan(
		&storedCapsule, &idempotencyKey, &envelopeBytes,
		&signerID, &signingKeyID, &signingKeyRevision, &signatureProfileID,
		&permitDigest,
		&acceptedAt, &protectedByteCount, &committedBytes,
		&state, &objectPath, &receiptBytes, &updatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return jobcustody.AdmissionRecord{}, jobcustody.ErrMissing
	}
	if err != nil {
		return jobcustody.AdmissionRecord{}, err
	}
	envelope, err := computequeue.DecodeJobCustodyAdmissionCanonical(envelopeBytes)
	if err != nil || signingKeyRevision <= 0 || storedCapsule.String() != string(capsuleID) ||
		string(envelope.Header.CapsuleID) != storedCapsule.String() ||
		string(envelope.Header.IdempotencyKey) != idempotencyKey ||
		envelope.Header.ProtectedObject.ByteCount != protectedByteCount {
		return jobcustody.AdmissionRecord{}, jobcustody.ErrInvalid
	}
	record := jobcustody.AdmissionRecord{
		EnvelopeBytes: bytes.Clone(envelopeBytes), Header: envelope.Header,
		ExpectedSigner: computequeue.ReceiptSignerBinding{
			SignerID: computequeue.SignerID(signerID), SigningKeyID: computequeue.SigningKeyID(signingKeyID),
			SigningKeyRevision: uint64(signingKeyRevision), SignatureProfileID: signatureProfileID,
		},
		AdmissionPermitDigest: computequeue.Digest(permitDigest),
		AcceptedAt:            computequeue.Timestamp(acceptedAt),
		CommittedBytes:        committedBytes,
		State:                 jobcustody.AdmissionState(state),
		CustodyReceiptBytes:   bytes.Clone(receiptBytes),
		UpdatedAtMillis:       updatedAt,
	}
	if objectPath != nil {
		record.ObjectPath = *objectPath
	}
	if record.ValidateStored() != nil {
		return jobcustody.AdmissionRecord{}, jobcustody.ErrInvalid
	}
	if err := validateJobCustodyChunks(ctx, querier, record); err != nil {
		return jobcustody.AdmissionRecord{}, err
	}
	return record, nil
}

func validateJobCustodyChunks(
	ctx context.Context,
	querier jobCustodyQuerier,
	record jobcustody.AdmissionRecord,
) error {
	capsuleUUID, err := uuid.Parse(string(record.Header.CapsuleID))
	if err != nil {
		return jobcustody.ErrInvalid
	}
	rows, err := querier.Query(ctx, `
		SELECT chunk_index,chunk_offset,chunk_byte_count,chunk_sha256,next_offset
		FROM job_custody_chunks WHERE capsule_id=$1 ORDER BY chunk_index`,
		capsuleUUID,
	)
	if err != nil {
		return err
	}
	defer rows.Close()
	descriptor := record.Header.ProtectedObject
	var expectedIndex, expectedOffset int64
	for rows.Next() {
		var index, offset, byteCount, next int64
		var digest string
		if err := rows.Scan(&index, &offset, &byteCount, &digest, &next); err != nil {
			return err
		}
		if expectedOffset >= descriptor.ByteCount {
			return jobcustody.ErrInvalid
		}
		expectedCount := min(descriptor.ChunkByteCount, descriptor.ByteCount-expectedOffset)
		if index != expectedIndex || offset != expectedOffset || byteCount != expectedCount ||
			computequeue.Digest(digest).Validate() != nil ||
			next != offset+byteCount || next > record.CommittedBytes {
			return jobcustody.ErrInvalid
		}
		expectedIndex++
		expectedOffset = next
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if expectedOffset != record.CommittedBytes || expectedIndex > descriptor.ChunkCount ||
		(record.State == jobcustody.AdmissionRetained && expectedIndex != descriptor.ChunkCount) {
		return jobcustody.ErrInvalid
	}
	return nil
}

func lockJobCustodyLedger(ctx context.Context, tx pgx.Tx) error {
	var revision int64
	if err := tx.QueryRow(ctx, `SELECT revision FROM job_custody_ledger WHERE singleton=true FOR UPDATE`).Scan(&revision); err != nil {
		return err
	}
	if revision <= 0 || revision == math.MaxInt64 {
		return jobcustody.ErrUnavailable
	}
	return nil
}

func advanceJobCustodyLedger(ctx context.Context, tx pgx.Tx) error {
	tag, err := tx.Exec(ctx, `
		UPDATE job_custody_ledger SET revision=revision+1,stored_at=now()
		WHERE singleton=true AND revision<9223372036854775807`,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return jobcustody.ErrUnavailable
	}
	return nil
}

func sameStoredAdmission(left, right jobcustody.AdmissionRecord) bool {
	return bytes.Equal(left.EnvelopeBytes, right.EnvelopeBytes) &&
		left.Header == right.Header && left.ExpectedSigner == right.ExpectedSigner &&
		left.AcceptedAt == right.AcceptedAt
}

func cloneJobCustodyAdmission(record jobcustody.AdmissionRecord) jobcustody.AdmissionRecord {
	record.EnvelopeBytes = bytes.Clone(record.EnvelopeBytes)
	record.CustodyReceiptBytes = bytes.Clone(record.CustodyReceiptBytes)
	return record
}

func wouldExceed(current, additional, maximum int64) bool {
	return current < 0 || additional < 0 || current > maximum || additional > maximum-current
}

func monotonicJobCustodyTime(clock jobcustody.Clock, previous int64) int64 {
	now := clock.Now().UnixMilli()
	if now < previous {
		return previous
	}
	return now
}

func mapJobCustodyWriteError(err error) error {
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) && (pgError.Code == "23505" || pgError.Code == "23514") {
		return jobcustody.ErrConflict
	}
	return err
}

var _ jobcustody.Ledger = (*JobCustodyStore)(nil)
