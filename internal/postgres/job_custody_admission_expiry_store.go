package postgres

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/computequeue"
	"github.com/robreuss/FacetsNode/internal/jobcustody"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

func (store *JobCustodyStore) ListAdmissionExpiryCandidates(
	ctx context.Context,
	now computequeue.Timestamp,
	limit int,
) ([]jobcustody.AdmissionRecord, error) {
	if store == nil || store.pool == nil || ctx == nil || now.Validate() != nil ||
		limit <= 0 || limit > jobcustody.MaximumAdmissionExpiryBatchSize {
		return nil, jobcustody.ErrInvalid
	}
	rows, err := store.pool.Query(ctx, `
		SELECT capsule_id FROM job_custody_admissions
		WHERE (state IN ('staging','retained') AND retention_until_milliseconds <= $1)
		   OR state IN ('stagingExpiryPending','expiryPending')
		ORDER BY retention_until_milliseconds,capsule_id
		LIMIT $2`, int64(now), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	capsuleIDs := make([]computequeue.JobCapsuleID, 0, limit)
	for rows.Next() {
		var capsuleID uuid.UUID
		if err := rows.Scan(&capsuleID); err != nil {
			return nil, err
		}
		capsuleIDs = append(capsuleIDs, computequeue.JobCapsuleID(capsuleID.String()))
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	records := make([]jobcustody.AdmissionRecord, 0, len(capsuleIDs))
	for _, capsuleID := range capsuleIDs {
		record, err := store.LoadAdmission(ctx, capsuleID)
		if errors.Is(err, jobcustody.ErrMissing) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if record.State == jobcustody.AdmissionExpired {
			continue
		}
		if record.State != jobcustody.AdmissionStagingExpiryPending &&
			record.State != jobcustody.AdmissionExpiryPending &&
			((record.State != jobcustody.AdmissionStaging &&
				record.State != jobcustody.AdmissionRetained) ||
				record.Header.RetentionUntil > now) {
			return nil, jobcustody.ErrConflict
		}
		records = append(records, record)
	}
	return records, nil
}

func (store *JobCustodyStore) RequestAdmissionExpiry(
	ctx context.Context,
	capsuleID computequeue.JobCapsuleID,
	startedAt computequeue.Timestamp,
) (jobcustody.AdmissionRecord, error) {
	if store == nil || store.pool == nil || ctx == nil || capsuleID.Validate() != nil ||
		startedAt.Validate() != nil {
		return jobcustody.AdmissionRecord{}, jobcustody.ErrInvalid
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return jobcustody.AdmissionRecord{}, err
	}
	defer tx.Rollback(ctx)
	if err := lockJobCustodyLedger(ctx, tx); err != nil {
		return jobcustody.AdmissionRecord{}, err
	}
	record, err := loadJobCustodyAdmission(ctx, tx, capsuleID, true)
	if err != nil {
		return jobcustody.AdmissionRecord{}, err
	}
	if record.State == jobcustody.AdmissionStagingExpiryPending ||
		record.State == jobcustody.AdmissionExpiryPending ||
		record.State == jobcustody.AdmissionExpired {
		if err := tx.Commit(ctx); err != nil {
			return jobcustody.AdmissionRecord{}, err
		}
		return record, nil
	}
	if (record.State != jobcustody.AdmissionStaging &&
		record.State != jobcustody.AdmissionRetained) ||
		startedAt < record.Header.RetentionUntil ||
		startedAt < computequeue.Timestamp(record.UpdatedAtMillis) {
		return jobcustody.AdmissionRecord{}, jobcustody.ErrConflict
	}
	capsuleUUID := uuid.MustParse(string(capsuleID))
	var activeClaim bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM job_custody_worker_claims
			WHERE capsule_id=$1 AND state='claimed' AND lease_expires_at_milliseconds > $2
		)`, capsuleUUID, int64(startedAt)).Scan(&activeClaim); err != nil {
		return jobcustody.AdmissionRecord{}, err
	}
	if activeClaim {
		return jobcustody.AdmissionRecord{}, jobcustody.ErrConflict
	}
	if _, err := tx.Exec(ctx, `
		UPDATE job_custody_worker_claims
		SET state='expired',updated_at_milliseconds=$2,stored_at=now()
		WHERE capsule_id=$1 AND state='claimed' AND lease_expires_at_milliseconds <= $2`,
		capsuleUUID, int64(startedAt)); err != nil {
		return jobcustody.AdmissionRecord{}, err
	}
	nextState := "expiryPending"
	if record.State == jobcustody.AdmissionStaging {
		nextState = "stagingExpiryPending"
	}
	tag, err := tx.Exec(ctx, `
		UPDATE job_custody_admissions SET
			state=$3,expiry_started_at_milliseconds=$2,
			updated_at_milliseconds=$2,stored_at=now()
		WHERE capsule_id=$1 AND state IN ('staging','retained')`,
		capsuleUUID, int64(startedAt), nextState)
	if err != nil {
		return jobcustody.AdmissionRecord{}, mapJobCustodyWriteError(err)
	}
	if tag.RowsAffected() != 1 {
		return jobcustody.AdmissionRecord{}, jobcustody.ErrConflict
	}
	if err := advanceJobCustodyLedger(ctx, tx); err != nil {
		return jobcustody.AdmissionRecord{}, err
	}
	pending, err := loadJobCustodyAdmission(ctx, tx, capsuleID, false)
	if err != nil {
		return jobcustody.AdmissionRecord{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return jobcustody.AdmissionRecord{}, err
	}
	return pending, nil
}

func (store *JobCustodyStore) FinalizeAdmissionExpiry(
	ctx context.Context,
	capsuleID computequeue.JobCapsuleID,
	receiptBytes []byte,
	expiredAt int64,
) (jobcustody.AdmissionRecord, error) {
	if store == nil || store.pool == nil || ctx == nil || capsuleID.Validate() != nil ||
		len(receiptBytes) == 0 ||
		len(receiptBytes) > serviceauthority.MaximumJobCustodyExpiryReceiptRecordByteCount {
		return jobcustody.AdmissionRecord{}, jobcustody.ErrInvalid
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return jobcustody.AdmissionRecord{}, err
	}
	defer tx.Rollback(ctx)
	if err := lockJobCustodyLedger(ctx, tx); err != nil {
		return jobcustody.AdmissionRecord{}, err
	}
	record, err := loadJobCustodyAdmission(ctx, tx, capsuleID, true)
	if err != nil {
		return jobcustody.AdmissionRecord{}, err
	}
	if record.State == jobcustody.AdmissionExpired {
		if err := tx.Commit(ctx); err != nil {
			return jobcustody.AdmissionRecord{}, err
		}
		return record, nil
	}
	if (record.State != jobcustody.AdmissionStagingExpiryPending &&
		record.State != jobcustody.AdmissionExpiryPending) ||
		expiredAt < record.UpdatedAtMillis || expiredAt < int64(record.Header.RetentionUntil) {
		return jobcustody.AdmissionRecord{}, jobcustody.ErrConflict
	}
	capsuleUUID := uuid.MustParse(string(capsuleID))
	tag, err := tx.Exec(ctx, `
		UPDATE job_custody_admissions SET
			state='expired',object_path=NULL,expiry_receipt_record=$2,
			updated_at_milliseconds=$3,stored_at=now()
		WHERE capsule_id=$1 AND state IN ('stagingExpiryPending','expiryPending')`,
		capsuleUUID, receiptBytes, expiredAt)
	if err != nil {
		return jobcustody.AdmissionRecord{}, mapJobCustodyWriteError(err)
	}
	if tag.RowsAffected() != 1 {
		return jobcustody.AdmissionRecord{}, jobcustody.ErrConflict
	}
	if err := advanceJobCustodyLedger(ctx, tx); err != nil {
		return jobcustody.AdmissionRecord{}, err
	}
	expired, err := loadJobCustodyAdmission(ctx, tx, capsuleID, false)
	if err != nil {
		return jobcustody.AdmissionRecord{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return jobcustody.AdmissionRecord{}, err
	}
	return expired, nil
}

var _ jobcustody.AdmissionLifecycleLedger = (*JobCustodyStore)(nil)
