package postgres

import (
	"bytes"
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/robreuss/FacetsNode/internal/computequeue"
	"github.com/robreuss/FacetsNode/internal/jobcustody"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

func (store *JobCustodyStore) LoadResult(
	ctx context.Context,
	resultCapsuleID computequeue.JobCapsuleID,
) (jobcustody.ResultRecord, error) {
	if store == nil || store.pool == nil || ctx == nil || resultCapsuleID.Validate() != nil {
		return jobcustody.ResultRecord{}, jobcustody.ErrInvalid
	}
	return loadJobCustodyResult(ctx, store.pool, resultCapsuleID, false)
}

func (store *JobCustodyStore) ListResultsForInput(
	ctx context.Context,
	inputCapsuleID computequeue.JobCapsuleID,
) ([]jobcustody.ResultRecord, jobcustody.AdmissionRecord, error) {
	if store == nil || store.pool == nil || ctx == nil || inputCapsuleID.Validate() != nil {
		return nil, jobcustody.AdmissionRecord{}, jobcustody.ErrInvalid
	}
	admission, err := loadJobCustodyAdmission(ctx, store.pool, inputCapsuleID, false)
	if err != nil {
		return nil, jobcustody.AdmissionRecord{}, err
	}
	inputUUID, err := uuid.Parse(string(inputCapsuleID))
	if err != nil {
		return nil, jobcustody.AdmissionRecord{}, jobcustody.ErrInvalid
	}
	rows, err := store.pool.Query(ctx, `
		SELECT result_capsule_id FROM job_custody_results
		WHERE input_capsule_id=$1 ORDER BY accepted_at_milliseconds,result_capsule_id`,
		inputUUID,
	)
	if err != nil {
		return nil, jobcustody.AdmissionRecord{}, err
	}
	var identifiers []computequeue.JobCapsuleID
	for rows.Next() {
		var identifier uuid.UUID
		if err := rows.Scan(&identifier); err != nil {
			rows.Close()
			return nil, jobcustody.AdmissionRecord{}, err
		}
		identifiers = append(identifiers, computequeue.JobCapsuleID(identifier.String()))
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, jobcustody.AdmissionRecord{}, err
	}
	rows.Close()
	results := make([]jobcustody.ResultRecord, 0, len(identifiers))
	for _, identifier := range identifiers {
		record, err := loadJobCustodyResult(ctx, store.pool, identifier, false)
		if err != nil {
			return nil, jobcustody.AdmissionRecord{}, err
		}
		if record.Header.InputCapsuleID != inputCapsuleID {
			return nil, jobcustody.AdmissionRecord{}, jobcustody.ErrInvalid
		}
		results = append(results, record)
	}
	return results, admission, nil
}

func (store *JobCustodyStore) ReserveResult(
	ctx context.Context,
	candidate jobcustody.ResultRecord,
) (jobcustody.ResultRecord, bool, error) {
	if store == nil || store.pool == nil || ctx == nil || candidate.ValidateStored() != nil ||
		candidate.State != jobcustody.ResultStaging || candidate.CommittedBytes != 0 ||
		candidate.ObjectPath != "" || len(candidate.CustodyReceiptBytes) != 0 {
		return jobcustody.ResultRecord{}, false, jobcustody.ErrInvalid
	}
	resultCapsuleID, err := uuid.Parse(string(candidate.Header.ResultCapsuleID))
	if err != nil {
		return jobcustody.ResultRecord{}, false, jobcustody.ErrInvalid
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return jobcustody.ResultRecord{}, false, err
	}
	defer tx.Rollback(ctx)
	if err := lockJobCustodyLedger(ctx, tx); err != nil {
		return jobcustody.ResultRecord{}, false, err
	}
	if existing, err := loadJobCustodyResult(ctx, tx, candidate.Header.ResultCapsuleID, false); err == nil {
		if !sameStoredResult(existing, candidate) {
			return jobcustody.ResultRecord{}, false, jobcustody.ErrConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return jobcustody.ResultRecord{}, false, err
		}
		return existing, false, nil
	} else if !errors.Is(err, jobcustody.ErrMissing) {
		return jobcustody.ResultRecord{}, false, err
	}
	var conflictingResult uuid.UUID
	err = tx.QueryRow(ctx, `SELECT result_capsule_id FROM job_custody_results WHERE idempotency_key=$1`,
		string(candidate.Header.IdempotencyKey)).Scan(&conflictingResult)
	if err == nil {
		return jobcustody.ResultRecord{}, false, jobcustody.ErrConflict
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return jobcustody.ResultRecord{}, false, err
	}
	claim, admission, err := loadJobCustodyWorkerClaim(ctx, tx, candidate.Header.ClaimID, true)
	if err != nil {
		return jobcustody.ResultRecord{}, false, err
	}
	if claim.CapsuleID != candidate.Header.InputCapsuleID ||
		admission.Header.AssignmentID != candidate.Header.AssignmentID ||
		claim.RouteAuthorityID != candidate.RouteAuthorityID ||
		claim.RouteRecipientWorkerID != candidate.RouteRecipientWorkerID ||
		claim.RouteRecipientKeyFingerprint != candidate.RouteRecipientKeyFingerprint ||
		claim.WorkerCapabilitiesDigest != candidate.WorkerCapabilitiesDigest ||
		claim.WorkerOwnerAuthorityDigest != candidate.WorkerOwnerAuthorityDigest ||
		claim.ClaimPermitDigest != candidate.ClaimPermitDigest ||
		candidate.Header.RetentionUntil > admission.Header.RetentionUntil {
		return jobcustody.ResultRecord{}, false, jobcustody.ErrConflict
	}
	var count, stagingBytes, totalBytes int64
	if err := tx.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FILTER (WHERE state NOT IN ('released','expired'))
			 FROM job_custody_results),
			(SELECT COALESCE(sum(protected_byte_count) FILTER (WHERE state='staging'),0)
			 FROM job_custody_admissions) +
			(SELECT COALESCE(sum(protected_byte_count)
			 FILTER (WHERE state IN ('staging','stagingExpiryPending')),0)
			 FROM job_custody_results),
			(SELECT COALESCE(sum(protected_byte_count),0) FROM job_custody_admissions) +
			(SELECT COALESCE(sum(protected_byte_count) FILTER (WHERE state NOT IN ('released','expired')),0)
			 FROM job_custody_results)`,
	).Scan(&count, &stagingBytes, &totalBytes); err != nil {
		return jobcustody.ResultRecord{}, false, err
	}
	byteCount := candidate.Header.ProtectedObject.ByteCount
	if count >= store.limits.MaximumAdmissions ||
		wouldExceed(stagingBytes, byteCount, store.limits.MaximumStagingBytes) ||
		wouldExceed(totalBytes, byteCount, store.limits.MaximumCustodyBytes) {
		return jobcustody.ResultRecord{}, false, jobcustody.ErrUnavailable
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO job_custody_results(
			result_capsule_id,claim_id,input_capsule_id,assignment_id,idempotency_key,
			result_set_digest,worker_execution_receipt_digest,
			route_authority_id,route_recipient_worker_id,route_recipient_key_fingerprint,
			worker_capabilities_digest,worker_owner_authority_digest,
			claim_permit_digest,result_permit_digest,retention_until_milliseconds,
			protected_object_sha256,protected_chunk_byte_count,protected_chunk_count,
			protected_byte_count,accepted_at_milliseconds,committed_bytes,state,
			object_path,custody_receipt_record,updated_at_milliseconds
		) VALUES(
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,
			$16,$17,$18,$19,$20,0,'staging',NULL,NULL,$20
		)`,
		resultCapsuleID, candidate.Header.ClaimID,
		uuid.MustParse(string(candidate.Header.InputCapsuleID)),
		uuid.MustParse(string(candidate.Header.AssignmentID)),
		string(candidate.Header.IdempotencyKey), string(candidate.Header.ResultSetDigest),
		string(candidate.Header.WorkerExecutionReceiptDigest), candidate.RouteAuthorityID,
		uuid.MustParse(string(candidate.RouteRecipientWorkerID)),
		string(candidate.RouteRecipientKeyFingerprint), string(candidate.WorkerCapabilitiesDigest),
		string(candidate.WorkerOwnerAuthorityDigest), string(candidate.ClaimPermitDigest),
		string(candidate.ResultPermitDigest), int64(candidate.Header.RetentionUntil),
		string(candidate.Header.ProtectedObject.SHA256),
		candidate.Header.ProtectedObject.ChunkByteCount,
		candidate.Header.ProtectedObject.ChunkCount,
		candidate.Header.ProtectedObject.ByteCount, int64(candidate.AcceptedAt),
	)
	if err != nil {
		return jobcustody.ResultRecord{}, false, mapJobCustodyWriteError(err)
	}
	if err := advanceJobCustodyLedger(ctx, tx); err != nil {
		return jobcustody.ResultRecord{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return jobcustody.ResultRecord{}, false, err
	}
	return cloneJobCustodyResult(candidate), true, nil
}

func (store *JobCustodyStore) BeginResultAppend(
	ctx context.Context,
	request jobcustody.AppendRequest,
) (jobcustody.ResultAppendLease, error) {
	if store == nil || store.pool == nil || ctx == nil || request.CapsuleID.Validate() != nil {
		return nil, jobcustody.ErrInvalid
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (jobcustody.ResultAppendLease, error) {
		_ = tx.Rollback(context.WithoutCancel(ctx))
		return nil, cause
	}
	record, err := loadJobCustodyResult(ctx, tx, request.CapsuleID, true)
	if err != nil {
		return fail(err)
	}
	if record.State != jobcustody.ResultStaging || request.Validate(record.Header.ProtectedObject) != nil {
		return fail(jobcustody.ErrInvalid)
	}
	lease := &jobCustodyResultAppendLease{store: store, tx: tx, record: record, request: request}
	resultCapsuleID, err := uuid.Parse(string(request.CapsuleID))
	if err != nil {
		return fail(jobcustody.ErrInvalid)
	}
	lease.resultCapsuleID = resultCapsuleID
	var storedIndex, storedOffset, storedCount, storedNext int64
	var storedDigest string
	err = tx.QueryRow(ctx, `
		SELECT chunk_index,chunk_offset,chunk_byte_count,chunk_sha256,next_offset
		FROM job_custody_result_chunks WHERE result_capsule_id=$1 AND chunk_index=$2`,
		resultCapsuleID, request.ChunkIndex,
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

func (store *JobCustodyStore) BeginResultFinalization(
	ctx context.Context,
	resultCapsuleID computequeue.JobCapsuleID,
) (jobcustody.ResultFinalizationLease, error) {
	if store == nil || store.pool == nil || ctx == nil || resultCapsuleID.Validate() != nil {
		return nil, jobcustody.ErrInvalid
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	record, err := loadJobCustodyResult(ctx, tx, resultCapsuleID, true)
	if err != nil {
		_ = tx.Rollback(context.WithoutCancel(ctx))
		return nil, err
	}
	return &jobCustodyResultFinalizationLease{store: store, tx: tx, record: record}, nil
}

type jobCustodyResultAppendLease struct {
	store           *JobCustodyStore
	tx              pgx.Tx
	record          jobcustody.ResultRecord
	request         jobcustody.AppendRequest
	resultCapsuleID uuid.UUID
	existingNext    *int64
	closed          bool
}

func (lease *jobCustodyResultAppendLease) Result() jobcustody.ResultRecord {
	return cloneJobCustodyResult(lease.record)
}

func (lease *jobCustodyResultAppendLease) ExistingNextOffset() *int64 {
	if lease.existingNext == nil {
		return nil
	}
	value := *lease.existingNext
	return &value
}

func (lease *jobCustodyResultAppendLease) Commit(ctx context.Context, next int64) error {
	if lease == nil || lease.closed || lease.existingNext != nil ||
		next != lease.request.Offset+lease.request.ByteCount {
		return jobcustody.ErrConflict
	}
	_, err := lease.tx.Exec(ctx, `
		INSERT INTO job_custody_result_chunks(
			result_capsule_id,chunk_index,chunk_offset,chunk_byte_count,chunk_sha256,next_offset
		) VALUES($1,$2,$3,$4,$5,$6)`,
		lease.resultCapsuleID, lease.request.ChunkIndex, lease.request.Offset,
		lease.request.ByteCount, string(lease.request.ChunkSHA256), next,
	)
	if err != nil {
		return mapJobCustodyWriteError(err)
	}
	updatedAt := monotonicJobCustodyTime(lease.store.clock, lease.record.UpdatedAtMillis)
	tag, err := lease.tx.Exec(ctx, `
		UPDATE job_custody_results
		SET committed_bytes=$3,updated_at_milliseconds=$4,stored_at=now()
		WHERE result_capsule_id=$1 AND state='staging' AND committed_bytes=$2`,
		lease.resultCapsuleID, lease.request.Offset, next, updatedAt,
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

func (lease *jobCustodyResultAppendLease) Abort(ctx context.Context) error {
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

type jobCustodyResultFinalizationLease struct {
	store  *JobCustodyStore
	tx     pgx.Tx
	record jobcustody.ResultRecord
	closed bool
}

func (lease *jobCustodyResultFinalizationLease) Result() jobcustody.ResultRecord {
	return cloneJobCustodyResult(lease.record)
}

func (lease *jobCustodyResultFinalizationLease) Commit(
	ctx context.Context,
	objectPath string,
	receiptBytes []byte,
	committedAt int64,
) (jobcustody.ResultRecord, error) {
	if lease == nil || lease.closed || lease.record.State != jobcustody.ResultStaging ||
		lease.record.CommittedBytes != lease.record.Header.ProtectedObject.ByteCount ||
		objectPath != "objects/"+string(lease.record.Header.ResultCapsuleID) ||
		len(receiptBytes) == 0 ||
		len(receiptBytes) > serviceauthority.MaximumJobCustodyResultReceiptRecordByteCount ||
		committedAt < lease.record.UpdatedAtMillis ||
		committedAt > int64(lease.record.Header.RetentionUntil) {
		return jobcustody.ResultRecord{}, jobcustody.ErrConflict
	}
	resultCapsuleID, err := uuid.Parse(string(lease.record.Header.ResultCapsuleID))
	if err != nil {
		return jobcustody.ResultRecord{}, jobcustody.ErrInvalid
	}
	tag, err := lease.tx.Exec(ctx, `
		UPDATE job_custody_results
		SET state='retained',object_path=$2,custody_receipt_record=$3,
			updated_at_milliseconds=$4,stored_at=now()
		WHERE result_capsule_id=$1 AND state='staging' AND
			committed_bytes=protected_byte_count`,
		resultCapsuleID, objectPath, receiptBytes, committedAt,
	)
	if err != nil {
		return jobcustody.ResultRecord{}, mapJobCustodyWriteError(err)
	}
	if tag.RowsAffected() != 1 {
		return jobcustody.ResultRecord{}, jobcustody.ErrConflict
	}
	if err := advanceJobCustodyLedger(ctx, lease.tx); err != nil {
		return jobcustody.ResultRecord{}, err
	}
	committed, err := loadJobCustodyResult(
		ctx, lease.tx, lease.record.Header.ResultCapsuleID, false,
	)
	if err != nil {
		return jobcustody.ResultRecord{}, err
	}
	if err := lease.tx.Commit(ctx); err != nil {
		return jobcustody.ResultRecord{}, err
	}
	lease.closed = true
	return committed, nil
}

func (lease *jobCustodyResultFinalizationLease) Abort(ctx context.Context) error {
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

func (store *JobCustodyStore) ListPendingResultReleases(
	ctx context.Context,
	limit int,
) ([]jobcustody.ResultRecord, error) {
	if store == nil || store.pool == nil || ctx == nil || limit <= 0 ||
		limit > jobcustody.MaximumPendingResultReleaseBatchSize {
		return nil, jobcustody.ErrInvalid
	}
	rows, err := store.pool.Query(ctx, `
		SELECT result_capsule_id FROM job_custody_results
		WHERE state='releasePending'
		ORDER BY release_requested_at_milliseconds,result_capsule_id
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	resultIDs := make([]computequeue.JobCapsuleID, 0, limit)
	for rows.Next() {
		var resultID uuid.UUID
		if err := rows.Scan(&resultID); err != nil {
			return nil, err
		}
		resultIDs = append(resultIDs, computequeue.JobCapsuleID(resultID.String()))
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	results := make([]jobcustody.ResultRecord, 0, len(resultIDs))
	for _, resultID := range resultIDs {
		record, err := loadJobCustodyResult(ctx, store.pool, resultID, false)
		if errors.Is(err, jobcustody.ErrMissing) {
			continue
		}
		if err != nil {
			return nil, err
		}
		// A concurrent exact retry may finish after the candidate query.
		if record.State == jobcustody.ResultReleased {
			continue
		}
		if record.State != jobcustody.ResultReleasePending {
			return nil, jobcustody.ErrConflict
		}
		results = append(results, record)
	}
	return results, nil
}

func (store *JobCustodyStore) ListResultExpiryCandidates(
	ctx context.Context,
	now computequeue.Timestamp,
	limit int,
) ([]jobcustody.ResultRecord, error) {
	if store == nil || store.pool == nil || ctx == nil || now.Validate() != nil || limit <= 0 ||
		limit > jobcustody.MaximumResultExpiryBatchSize {
		return nil, jobcustody.ErrInvalid
	}
	rows, err := store.pool.Query(ctx, `
		SELECT result_capsule_id FROM job_custody_results
		WHERE (state IN ('staging','retained','delivered') AND retention_until_milliseconds <= $1)
		   OR state IN ('stagingExpiryPending','expiryPending')
		ORDER BY retention_until_milliseconds,result_capsule_id
		LIMIT $2`, int64(now), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	resultIDs := make([]computequeue.JobCapsuleID, 0, limit)
	for rows.Next() {
		var resultID uuid.UUID
		if err := rows.Scan(&resultID); err != nil {
			return nil, err
		}
		resultIDs = append(resultIDs, computequeue.JobCapsuleID(resultID.String()))
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	results := make([]jobcustody.ResultRecord, 0, len(resultIDs))
	for _, resultID := range resultIDs {
		record, err := loadJobCustodyResult(ctx, store.pool, resultID, false)
		if errors.Is(err, jobcustody.ErrMissing) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if record.State == jobcustody.ResultExpired ||
			record.State == jobcustody.ResultReleasePending || record.State == jobcustody.ResultReleased {
			continue
		}
		if record.State != jobcustody.ResultStagingExpiryPending &&
			record.State != jobcustody.ResultExpiryPending &&
			(record.State != jobcustody.ResultStaging && record.State != jobcustody.ResultRetained &&
				record.State != jobcustody.ResultDelivered ||
				record.Header.RetentionUntil > now) {
			return nil, jobcustody.ErrConflict
		}
		results = append(results, record)
	}
	return results, nil
}

func (store *JobCustodyStore) AcknowledgeResultDelivery(
	ctx context.Context,
	resultCapsuleID computequeue.JobCapsuleID,
	permitDigest computequeue.Digest,
	sourceReceiptDigest computequeue.Digest,
	acknowledgedAt computequeue.Timestamp,
) (jobcustody.ResultRecord, error) {
	if store == nil || store.pool == nil || ctx == nil || resultCapsuleID.Validate() != nil ||
		permitDigest.Validate() != nil || sourceReceiptDigest.Validate() != nil ||
		acknowledgedAt.Validate() != nil {
		return jobcustody.ResultRecord{}, jobcustody.ErrInvalid
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return jobcustody.ResultRecord{}, err
	}
	defer tx.Rollback(ctx)
	if err := lockJobCustodyLedger(ctx, tx); err != nil {
		return jobcustody.ResultRecord{}, err
	}
	record, err := loadJobCustodyResult(ctx, tx, resultCapsuleID, true)
	if err != nil {
		return jobcustody.ResultRecord{}, err
	}
	if record.State == jobcustody.ResultDelivered {
		if record.DeliveryPermitDigest != permitDigest ||
			record.SourceDeliveryReceiptDigest != sourceReceiptDigest {
			return jobcustody.ResultRecord{}, jobcustody.ErrConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return jobcustody.ResultRecord{}, err
		}
		return record, nil
	}
	if record.State != jobcustody.ResultRetained ||
		acknowledgedAt < computequeue.Timestamp(record.UpdatedAtMillis) ||
		acknowledgedAt > record.Header.RetentionUntil {
		return jobcustody.ResultRecord{}, jobcustody.ErrConflict
	}
	resultUUID := uuid.MustParse(string(resultCapsuleID))
	tag, err := tx.Exec(ctx, `
		UPDATE job_custody_results SET
			state='delivered',delivery_acknowledged_at_milliseconds=$2,
			delivery_permit_digest=$3,source_delivery_receipt_digest=$4,
			updated_at_milliseconds=$2,stored_at=now()
		WHERE result_capsule_id=$1 AND state='retained'`,
		resultUUID, int64(acknowledgedAt), string(permitDigest), string(sourceReceiptDigest),
	)
	if err != nil {
		return jobcustody.ResultRecord{}, mapJobCustodyWriteError(err)
	}
	if tag.RowsAffected() != 1 {
		return jobcustody.ResultRecord{}, jobcustody.ErrConflict
	}
	if err := advanceJobCustodyLedger(ctx, tx); err != nil {
		return jobcustody.ResultRecord{}, err
	}
	updated, err := loadJobCustodyResult(ctx, tx, resultCapsuleID, false)
	if err != nil {
		return jobcustody.ResultRecord{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return jobcustody.ResultRecord{}, err
	}
	return updated, nil
}

func (store *JobCustodyStore) RequestResultRelease(
	ctx context.Context,
	resultCapsuleID computequeue.JobCapsuleID,
	permitDigest computequeue.Digest,
	sourceReceiptDigest computequeue.Digest,
	requestedAt computequeue.Timestamp,
) (jobcustody.ResultRecord, error) {
	if store == nil || store.pool == nil || ctx == nil || resultCapsuleID.Validate() != nil ||
		permitDigest.Validate() != nil || sourceReceiptDigest.Validate() != nil ||
		requestedAt.Validate() != nil {
		return jobcustody.ResultRecord{}, jobcustody.ErrInvalid
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return jobcustody.ResultRecord{}, err
	}
	defer tx.Rollback(ctx)
	if err := lockJobCustodyLedger(ctx, tx); err != nil {
		return jobcustody.ResultRecord{}, err
	}
	record, err := loadJobCustodyResult(ctx, tx, resultCapsuleID, true)
	if err != nil {
		return jobcustody.ResultRecord{}, err
	}
	if record.State == jobcustody.ResultReleasePending || record.State == jobcustody.ResultReleased {
		if record.ReleasePermitDigest != permitDigest ||
			record.SourceReleaseReceiptDigest != sourceReceiptDigest {
			return jobcustody.ResultRecord{}, jobcustody.ErrConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return jobcustody.ResultRecord{}, err
		}
		return record, nil
	}
	if record.State != jobcustody.ResultDelivered ||
		requestedAt < record.DeliveryAcknowledgedAt || requestedAt > record.Header.RetentionUntil {
		return jobcustody.ResultRecord{}, jobcustody.ErrConflict
	}
	resultUUID := uuid.MustParse(string(resultCapsuleID))
	tag, err := tx.Exec(ctx, `
		UPDATE job_custody_results SET
			state='releasePending',release_requested_at_milliseconds=$2,
			release_permit_digest=$3,source_release_receipt_digest=$4,
			updated_at_milliseconds=$2,stored_at=now()
		WHERE result_capsule_id=$1 AND state='delivered'`,
		resultUUID, int64(requestedAt), string(permitDigest), string(sourceReceiptDigest),
	)
	if err != nil {
		return jobcustody.ResultRecord{}, mapJobCustodyWriteError(err)
	}
	if tag.RowsAffected() != 1 {
		return jobcustody.ResultRecord{}, jobcustody.ErrConflict
	}
	if err := advanceJobCustodyLedger(ctx, tx); err != nil {
		return jobcustody.ResultRecord{}, err
	}
	updated, err := loadJobCustodyResult(ctx, tx, resultCapsuleID, false)
	if err != nil {
		return jobcustody.ResultRecord{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return jobcustody.ResultRecord{}, err
	}
	return updated, nil
}

func (store *JobCustodyStore) FinalizeResultRelease(
	ctx context.Context,
	resultCapsuleID computequeue.JobCapsuleID,
	receiptBytes []byte,
	releasedAt int64,
) (jobcustody.ResultRecord, error) {
	if store == nil || store.pool == nil || ctx == nil || resultCapsuleID.Validate() != nil ||
		len(receiptBytes) == 0 ||
		len(receiptBytes) > serviceauthority.MaximumJobCustodyResultReleaseReceiptRecordByteCount {
		return jobcustody.ResultRecord{}, jobcustody.ErrInvalid
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return jobcustody.ResultRecord{}, err
	}
	defer tx.Rollback(ctx)
	if err := lockJobCustodyLedger(ctx, tx); err != nil {
		return jobcustody.ResultRecord{}, err
	}
	record, err := loadJobCustodyResult(ctx, tx, resultCapsuleID, true)
	if err != nil {
		return jobcustody.ResultRecord{}, err
	}
	if record.State == jobcustody.ResultReleased {
		if err := tx.Commit(ctx); err != nil {
			return jobcustody.ResultRecord{}, err
		}
		return record, nil
	}
	if record.State != jobcustody.ResultReleasePending || releasedAt < record.UpdatedAtMillis {
		return jobcustody.ResultRecord{}, jobcustody.ErrConflict
	}
	resultUUID := uuid.MustParse(string(resultCapsuleID))
	tag, err := tx.Exec(ctx, `
		UPDATE job_custody_results SET
			state='released',object_path=NULL,release_receipt_record=$2,
			updated_at_milliseconds=$3,stored_at=now()
		WHERE result_capsule_id=$1 AND state='releasePending'`,
		resultUUID, receiptBytes, releasedAt,
	)
	if err != nil {
		return jobcustody.ResultRecord{}, mapJobCustodyWriteError(err)
	}
	if tag.RowsAffected() != 1 {
		return jobcustody.ResultRecord{}, jobcustody.ErrConflict
	}
	if err := advanceJobCustodyLedger(ctx, tx); err != nil {
		return jobcustody.ResultRecord{}, err
	}
	updated, err := loadJobCustodyResult(ctx, tx, resultCapsuleID, false)
	if err != nil {
		return jobcustody.ResultRecord{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return jobcustody.ResultRecord{}, err
	}
	return updated, nil
}

func (store *JobCustodyStore) RequestResultExpiry(
	ctx context.Context,
	resultCapsuleID computequeue.JobCapsuleID,
	startedAt computequeue.Timestamp,
) (jobcustody.ResultRecord, error) {
	if store == nil || store.pool == nil || ctx == nil || resultCapsuleID.Validate() != nil ||
		startedAt.Validate() != nil {
		return jobcustody.ResultRecord{}, jobcustody.ErrInvalid
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return jobcustody.ResultRecord{}, err
	}
	defer tx.Rollback(ctx)
	if err := lockJobCustodyLedger(ctx, tx); err != nil {
		return jobcustody.ResultRecord{}, err
	}
	record, err := loadJobCustodyResult(ctx, tx, resultCapsuleID, true)
	if err != nil {
		return jobcustody.ResultRecord{}, err
	}
	if record.State == jobcustody.ResultStagingExpiryPending ||
		record.State == jobcustody.ResultExpiryPending || record.State == jobcustody.ResultExpired {
		if err := tx.Commit(ctx); err != nil {
			return jobcustody.ResultRecord{}, err
		}
		return record, nil
	}
	if (record.State != jobcustody.ResultStaging && record.State != jobcustody.ResultRetained &&
		record.State != jobcustody.ResultDelivered) ||
		startedAt < record.Header.RetentionUntil ||
		startedAt < computequeue.Timestamp(record.UpdatedAtMillis) {
		return jobcustody.ResultRecord{}, jobcustody.ErrConflict
	}
	resultUUID := uuid.MustParse(string(resultCapsuleID))
	nextState := "expiryPending"
	if record.State == jobcustody.ResultStaging {
		nextState = "stagingExpiryPending"
	}
	tag, err := tx.Exec(ctx, `
		UPDATE job_custody_results SET
			state=$3,expiry_started_at_milliseconds=$2,
			updated_at_milliseconds=$2,stored_at=now()
		WHERE result_capsule_id=$1 AND state IN ('staging','retained','delivered')`,
		resultUUID, int64(startedAt), nextState,
	)
	if err != nil {
		return jobcustody.ResultRecord{}, mapJobCustodyWriteError(err)
	}
	if tag.RowsAffected() != 1 {
		return jobcustody.ResultRecord{}, jobcustody.ErrConflict
	}
	if err := advanceJobCustodyLedger(ctx, tx); err != nil {
		return jobcustody.ResultRecord{}, err
	}
	updated, err := loadJobCustodyResult(ctx, tx, resultCapsuleID, false)
	if err != nil {
		return jobcustody.ResultRecord{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return jobcustody.ResultRecord{}, err
	}
	return updated, nil
}

func (store *JobCustodyStore) FinalizeResultExpiry(
	ctx context.Context,
	resultCapsuleID computequeue.JobCapsuleID,
	receiptBytes []byte,
	expiredAt int64,
) (jobcustody.ResultRecord, error) {
	if store == nil || store.pool == nil || ctx == nil || resultCapsuleID.Validate() != nil ||
		len(receiptBytes) == 0 ||
		len(receiptBytes) > serviceauthority.MaximumJobCustodyResultExpiryReceiptRecordByteCount {
		return jobcustody.ResultRecord{}, jobcustody.ErrInvalid
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return jobcustody.ResultRecord{}, err
	}
	defer tx.Rollback(ctx)
	if err := lockJobCustodyLedger(ctx, tx); err != nil {
		return jobcustody.ResultRecord{}, err
	}
	record, err := loadJobCustodyResult(ctx, tx, resultCapsuleID, true)
	if err != nil {
		return jobcustody.ResultRecord{}, err
	}
	if record.State == jobcustody.ResultExpired {
		if err := tx.Commit(ctx); err != nil {
			return jobcustody.ResultRecord{}, err
		}
		return record, nil
	}
	if (record.State != jobcustody.ResultStagingExpiryPending &&
		record.State != jobcustody.ResultExpiryPending) || expiredAt < record.UpdatedAtMillis ||
		expiredAt < int64(record.Header.RetentionUntil) {
		return jobcustody.ResultRecord{}, jobcustody.ErrConflict
	}
	resultUUID := uuid.MustParse(string(resultCapsuleID))
	tag, err := tx.Exec(ctx, `
		UPDATE job_custody_results SET
			state='expired',object_path=NULL,expiry_receipt_record=$2,
			updated_at_milliseconds=$3,stored_at=now()
		WHERE result_capsule_id=$1 AND state IN ('stagingExpiryPending','expiryPending')`,
		resultUUID, receiptBytes, expiredAt,
	)
	if err != nil {
		return jobcustody.ResultRecord{}, mapJobCustodyWriteError(err)
	}
	if tag.RowsAffected() != 1 {
		return jobcustody.ResultRecord{}, jobcustody.ErrConflict
	}
	if err := advanceJobCustodyLedger(ctx, tx); err != nil {
		return jobcustody.ResultRecord{}, err
	}
	updated, err := loadJobCustodyResult(ctx, tx, resultCapsuleID, false)
	if err != nil {
		return jobcustody.ResultRecord{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return jobcustody.ResultRecord{}, err
	}
	return updated, nil
}

func loadJobCustodyResult(
	ctx context.Context,
	querier jobCustodyQuerier,
	resultCapsuleID computequeue.JobCapsuleID,
	forUpdate bool,
) (jobcustody.ResultRecord, error) {
	resultUUID, err := uuid.Parse(string(resultCapsuleID))
	if err != nil {
		return jobcustody.ResultRecord{}, jobcustody.ErrInvalid
	}
	query := `
		SELECT result_capsule_id,claim_id,input_capsule_id,assignment_id,idempotency_key,
			result_set_digest,worker_execution_receipt_digest,
			route_authority_id,route_recipient_worker_id,route_recipient_key_fingerprint,
			worker_capabilities_digest,worker_owner_authority_digest,
			claim_permit_digest,result_permit_digest,retention_until_milliseconds,
			protected_object_sha256,protected_chunk_byte_count,protected_chunk_count,
			protected_byte_count,accepted_at_milliseconds,committed_bytes,state,
			object_path,custody_receipt_record,
			delivery_acknowledged_at_milliseconds,delivery_permit_digest,
			source_delivery_receipt_digest,release_requested_at_milliseconds,
			release_permit_digest,source_release_receipt_digest,release_receipt_record,
			expiry_started_at_milliseconds,expiry_receipt_record,
			updated_at_milliseconds
		FROM job_custody_results WHERE result_capsule_id=$1`
	if forUpdate {
		query += " FOR UPDATE"
	}
	var storedResult, claimID, inputCapsuleID, assignmentID, routeAuthorityID, routeWorkerID uuid.UUID
	var idempotency, resultSet, executionReceipt, routeKey, capabilities, owner, claimPermit, resultPermit string
	var protectedSHA, state string
	var retentionUntil, chunkBytes, chunkCount, byteCount, acceptedAt, committedBytes, updatedAt int64
	var objectPath, deliveryPermit, sourceDelivery, releasePermit, sourceRelease *string
	var deliveryAt, releaseAt, expiryStartedAt *int64
	var receiptBytes, releaseReceiptBytes, expiryReceiptBytes []byte
	err = querier.QueryRow(ctx, query, resultUUID).Scan(
		&storedResult, &claimID, &inputCapsuleID, &assignmentID, &idempotency,
		&resultSet, &executionReceipt, &routeAuthorityID, &routeWorkerID, &routeKey,
		&capabilities, &owner, &claimPermit, &resultPermit, &retentionUntil,
		&protectedSHA, &chunkBytes, &chunkCount, &byteCount, &acceptedAt, &committedBytes,
		&state, &objectPath, &receiptBytes, &deliveryAt, &deliveryPermit,
		&sourceDelivery, &releaseAt, &releasePermit, &sourceRelease,
		&releaseReceiptBytes, &expiryStartedAt, &expiryReceiptBytes, &updatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return jobcustody.ResultRecord{}, jobcustody.ErrMissing
	}
	if err != nil {
		return jobcustody.ResultRecord{}, err
	}
	descriptor := computequeue.JobCapsuleProtectedObjectDescriptor{
		ByteCount: byteCount, SHA256: computequeue.Digest(protectedSHA),
		ChunkByteCount: chunkBytes, ChunkCount: chunkCount,
	}
	header := jobcustody.WorkerResultHeader{
		AssignmentID: computequeue.AssignmentID(assignmentID.String()), ClaimID: claimID,
		IdempotencyKey:               computequeue.Digest(idempotency),
		InputCapsuleID:               computequeue.JobCapsuleID(inputCapsuleID.String()),
		ProtectedObject:              descriptor,
		ResultCapsuleID:              computequeue.JobCapsuleID(storedResult.String()),
		ResultSetDigest:              computequeue.Digest(resultSet),
		RetentionUntil:               computequeue.Timestamp(retentionUntil),
		Version:                      jobcustody.WorkerResultPermitVersion,
		WorkerExecutionReceiptDigest: computequeue.Digest(executionReceipt),
	}
	record := jobcustody.ResultRecord{
		Header: header, RouteAuthorityID: routeAuthorityID,
		RouteRecipientWorkerID:       computequeue.WorkerID(routeWorkerID.String()),
		RouteRecipientKeyFingerprint: computequeue.Digest(routeKey),
		WorkerCapabilitiesDigest:     computequeue.Digest(capabilities),
		WorkerOwnerAuthorityDigest:   computequeue.Digest(owner),
		ClaimPermitDigest:            computequeue.Digest(claimPermit),
		ResultPermitDigest:           computequeue.Digest(resultPermit),
		AcceptedAt:                   computequeue.Timestamp(acceptedAt), CommittedBytes: committedBytes,
		State: jobcustody.ResultState(state), CustodyReceiptBytes: bytes.Clone(receiptBytes),
		ReleaseReceiptBytes: bytes.Clone(releaseReceiptBytes),
		ExpiryReceiptBytes:  bytes.Clone(expiryReceiptBytes),
		UpdatedAtMillis:     updatedAt,
	}
	if objectPath != nil {
		record.ObjectPath = *objectPath
	}
	if deliveryAt != nil {
		record.DeliveryAcknowledgedAt = computequeue.Timestamp(*deliveryAt)
	}
	if deliveryPermit != nil {
		record.DeliveryPermitDigest = computequeue.Digest(*deliveryPermit)
	}
	if sourceDelivery != nil {
		record.SourceDeliveryReceiptDigest = computequeue.Digest(*sourceDelivery)
	}
	if releaseAt != nil {
		record.ReleaseRequestedAt = computequeue.Timestamp(*releaseAt)
	}
	if releasePermit != nil {
		record.ReleasePermitDigest = computequeue.Digest(*releasePermit)
	}
	if sourceRelease != nil {
		record.SourceReleaseReceiptDigest = computequeue.Digest(*sourceRelease)
	}
	if expiryStartedAt != nil {
		record.ExpiryStartedAt = computequeue.Timestamp(*expiryStartedAt)
	}
	if storedResult.String() != string(resultCapsuleID) || record.ValidateStored() != nil {
		return jobcustody.ResultRecord{}, jobcustody.ErrInvalid
	}
	if err := validateJobCustodyResultChunks(ctx, querier, record); err != nil {
		return jobcustody.ResultRecord{}, err
	}
	return record, nil
}

func validateJobCustodyResultChunks(
	ctx context.Context,
	querier jobCustodyQuerier,
	record jobcustody.ResultRecord,
) error {
	resultCapsuleID, err := uuid.Parse(string(record.Header.ResultCapsuleID))
	if err != nil {
		return jobcustody.ErrInvalid
	}
	rows, err := querier.Query(ctx, `
		SELECT chunk_index,chunk_offset,chunk_byte_count,chunk_sha256,next_offset
		FROM job_custody_result_chunks WHERE result_capsule_id=$1 ORDER BY chunk_index`,
		resultCapsuleID,
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
			computequeue.Digest(digest).Validate() != nil || next != offset+byteCount ||
			next > record.CommittedBytes {
			return jobcustody.ErrInvalid
		}
		expectedIndex++
		expectedOffset = next
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if expectedOffset != record.CommittedBytes || expectedIndex > descriptor.ChunkCount ||
		(record.State != jobcustody.ResultStaging && expectedIndex != descriptor.ChunkCount) {
		return jobcustody.ErrInvalid
	}
	return nil
}

func sameStoredResult(left, right jobcustody.ResultRecord) bool {
	return left.Header == right.Header && left.RouteAuthorityID == right.RouteAuthorityID &&
		left.RouteRecipientWorkerID == right.RouteRecipientWorkerID &&
		left.RouteRecipientKeyFingerprint == right.RouteRecipientKeyFingerprint &&
		left.WorkerCapabilitiesDigest == right.WorkerCapabilitiesDigest &&
		left.WorkerOwnerAuthorityDigest == right.WorkerOwnerAuthorityDigest &&
		left.ClaimPermitDigest == right.ClaimPermitDigest && left.AcceptedAt == right.AcceptedAt
}

func cloneJobCustodyResult(record jobcustody.ResultRecord) jobcustody.ResultRecord {
	record.CustodyReceiptBytes = bytes.Clone(record.CustodyReceiptBytes)
	record.ReleaseReceiptBytes = bytes.Clone(record.ReleaseReceiptBytes)
	return record
}

var _ jobcustody.ResultLedger = (*JobCustodyStore)(nil)
