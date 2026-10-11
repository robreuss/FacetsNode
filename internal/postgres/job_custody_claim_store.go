package postgres

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/robreuss/FacetsNode/internal/computequeue"
	"github.com/robreuss/FacetsNode/internal/jobcustody"
)

func (store *JobCustodyStore) LoadWorkerClaim(
	ctx context.Context,
	claimID uuid.UUID,
) (jobcustody.WorkerClaimRecord, jobcustody.AdmissionRecord, error) {
	if store == nil || store.pool == nil || ctx == nil || claimID == uuid.Nil {
		return jobcustody.WorkerClaimRecord{}, jobcustody.AdmissionRecord{}, jobcustody.ErrInvalid
	}
	return loadJobCustodyWorkerClaim(ctx, store.pool, claimID, false)
}

func (store *JobCustodyStore) ClaimNext(
	ctx context.Context,
	authorization jobcustody.WorkerClaimAuthorization,
) (jobcustody.WorkerClaimRecord, jobcustody.AdmissionRecord, error) {
	if store == nil || store.pool == nil || ctx == nil ||
		authorization.Payload().Validate() != nil || authorization.PermitDigest().Validate() != nil {
		return jobcustody.WorkerClaimRecord{}, jobcustody.AdmissionRecord{}, jobcustody.ErrInvalid
	}
	payload := authorization.Payload()
	now := computequeue.Timestamp(store.clock.Now().UnixMilli())
	if now < payload.IssuedAt || now >= payload.ExpiresAt {
		return jobcustody.WorkerClaimRecord{}, jobcustody.AdmissionRecord{}, jobcustody.ErrConflict
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return jobcustody.WorkerClaimRecord{}, jobcustody.AdmissionRecord{}, err
	}
	defer tx.Rollback(ctx)
	if err := lockJobCustodyLedger(ctx, tx); err != nil {
		return jobcustody.WorkerClaimRecord{}, jobcustody.AdmissionRecord{}, err
	}
	if existing, admission, err := loadJobCustodyWorkerClaim(ctx, tx, payload.ClaimID, true); err == nil {
		if !sameWorkerClaimAuthorization(existing, admission, authorization) ||
			existing.State != jobcustody.WorkerClaimClaimed || now >= existing.LeaseExpiresAt {
			return jobcustody.WorkerClaimRecord{}, jobcustody.AdmissionRecord{}, jobcustody.ErrConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return jobcustody.WorkerClaimRecord{}, jobcustody.AdmissionRecord{}, err
		}
		return existing, admission, nil
	} else if !errors.Is(err, jobcustody.ErrMissing) {
		return jobcustody.WorkerClaimRecord{}, jobcustody.AdmissionRecord{}, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE job_custody_worker_claims
		SET state='expired',updated_at_milliseconds=$1,stored_at=now()
		WHERE state='claimed' AND lease_expires_at_milliseconds <= $1`, int64(now)); err != nil {
		return jobcustody.WorkerClaimRecord{}, jobcustody.AdmissionRecord{}, err
	}
	var capsuleUUID uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT a.capsule_id
		FROM job_custody_admissions a
		WHERE a.state='retained' AND a.route_authority_id=$1
		  AND a.route_recipient_worker_id=$2
		  AND a.route_recipient_key_fingerprint=$3
		  AND a.worker_capabilities_digest=$4
		  AND a.retention_until_milliseconds >= $5
		  AND NOT EXISTS (
		      SELECT 1 FROM job_custody_worker_claims c
		      WHERE c.capsule_id=a.capsule_id AND c.state='claimed'
		  )
		ORDER BY a.accepted_at_milliseconds,a.capsule_id
		FOR UPDATE OF a SKIP LOCKED LIMIT 1`,
		payload.AuthorityID, uuid.MustParse(string(payload.RouteRecipientWorkerID)),
		string(payload.RouteRecipientKeyFingerprint), string(payload.WorkerCapabilitiesDigest),
		int64(payload.ExpiresAt),
	).Scan(&capsuleUUID)
	if errors.Is(err, pgx.ErrNoRows) {
		return jobcustody.WorkerClaimRecord{}, jobcustody.AdmissionRecord{}, jobcustody.ErrNoWork
	}
	if err != nil {
		return jobcustody.WorkerClaimRecord{}, jobcustody.AdmissionRecord{}, err
	}
	admission, err := loadJobCustodyAdmission(
		ctx, tx, computequeue.JobCapsuleID(capsuleUUID.String()), false,
	)
	if err != nil {
		return jobcustody.WorkerClaimRecord{}, jobcustody.AdmissionRecord{}, err
	}
	record := workerClaimRecordFromAuthorization(authorization, admission.Header.CapsuleID, now)
	if record.ValidateStored() != nil {
		return jobcustody.WorkerClaimRecord{}, jobcustody.AdmissionRecord{}, jobcustody.ErrInvalid
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO job_custody_worker_claims(
			claim_id,capsule_id,route_authority_id,route_recipient_worker_id,
			route_recipient_key_fingerprint,worker_capabilities_digest,
			worker_owner_authority_digest,claim_permit_digest,
			claimed_at_milliseconds,lease_expires_at_milliseconds,state,
			updated_at_milliseconds
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'claimed',$9)`,
		record.ClaimID, capsuleUUID, record.RouteAuthorityID,
		uuid.MustParse(string(record.RouteRecipientWorkerID)),
		string(record.RouteRecipientKeyFingerprint), string(record.WorkerCapabilitiesDigest),
		string(record.WorkerOwnerAuthorityDigest), string(record.ClaimPermitDigest),
		int64(record.ClaimedAt), int64(record.LeaseExpiresAt),
	)
	if err != nil {
		return jobcustody.WorkerClaimRecord{}, jobcustody.AdmissionRecord{}, mapJobCustodyWriteError(err)
	}
	if err := advanceJobCustodyLedger(ctx, tx); err != nil {
		return jobcustody.WorkerClaimRecord{}, jobcustody.AdmissionRecord{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return jobcustody.WorkerClaimRecord{}, jobcustody.AdmissionRecord{}, err
	}
	return record, admission, nil
}

func (store *JobCustodyStore) RenewClaim(
	ctx context.Context,
	authorization jobcustody.WorkerClaimAuthorization,
) (jobcustody.WorkerClaimRecord, jobcustody.AdmissionRecord, error) {
	if store == nil || store.pool == nil || ctx == nil ||
		authorization.Payload().Validate() != nil || authorization.PermitDigest().Validate() != nil {
		return jobcustody.WorkerClaimRecord{}, jobcustody.AdmissionRecord{}, jobcustody.ErrInvalid
	}
	payload := authorization.Payload()
	now := computequeue.Timestamp(store.clock.Now().UnixMilli())
	if now < payload.IssuedAt || now >= payload.ExpiresAt {
		return jobcustody.WorkerClaimRecord{}, jobcustody.AdmissionRecord{}, jobcustody.ErrConflict
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return jobcustody.WorkerClaimRecord{}, jobcustody.AdmissionRecord{}, err
	}
	defer tx.Rollback(ctx)
	if err := lockJobCustodyLedger(ctx, tx); err != nil {
		return jobcustody.WorkerClaimRecord{}, jobcustody.AdmissionRecord{}, err
	}
	record, admission, err := loadJobCustodyWorkerClaim(ctx, tx, payload.ClaimID, true)
	if err != nil {
		return jobcustody.WorkerClaimRecord{}, jobcustody.AdmissionRecord{}, err
	}
	if record.State != jobcustody.WorkerClaimClaimed || now >= record.LeaseExpiresAt ||
		record.RouteAuthorityID != payload.AuthorityID ||
		record.RouteRecipientWorkerID != payload.RouteRecipientWorkerID ||
		record.RouteRecipientKeyFingerprint != payload.RouteRecipientKeyFingerprint ||
		record.WorkerCapabilitiesDigest != payload.WorkerCapabilitiesDigest ||
		record.WorkerOwnerAuthorityDigest != payload.WorkerOwnerAuthorityDigest ||
		payload.ExpiresAt > admission.Header.RetentionUntil {
		return jobcustody.WorkerClaimRecord{}, jobcustody.AdmissionRecord{}, jobcustody.ErrConflict
	}
	if sameWorkerClaimAuthorization(record, admission, authorization) {
		if err := tx.Commit(ctx); err != nil {
			return jobcustody.WorkerClaimRecord{}, jobcustody.AdmissionRecord{}, err
		}
		return record, admission, nil
	}
	if payload.ExpiresAt <= record.LeaseExpiresAt {
		return jobcustody.WorkerClaimRecord{}, jobcustody.AdmissionRecord{}, jobcustody.ErrConflict
	}
	updatedAt := monotonicJobCustodyTime(store.clock, record.UpdatedAtMillis)
	tag, err := tx.Exec(ctx, `
		UPDATE job_custody_worker_claims
		SET claim_permit_digest=$2,lease_expires_at_milliseconds=$3,
			updated_at_milliseconds=$4,stored_at=now()
		WHERE claim_id=$1 AND state='claimed' AND lease_expires_at_milliseconds=$5`,
		record.ClaimID, string(authorization.PermitDigest()), int64(payload.ExpiresAt),
		updatedAt, int64(record.LeaseExpiresAt),
	)
	if err != nil {
		return jobcustody.WorkerClaimRecord{}, jobcustody.AdmissionRecord{}, err
	}
	if tag.RowsAffected() != 1 {
		return jobcustody.WorkerClaimRecord{}, jobcustody.AdmissionRecord{}, jobcustody.ErrConflict
	}
	record.ClaimPermitDigest = authorization.PermitDigest()
	record.LeaseExpiresAt = payload.ExpiresAt
	record.UpdatedAtMillis = updatedAt
	if err := advanceJobCustodyLedger(ctx, tx); err != nil {
		return jobcustody.WorkerClaimRecord{}, jobcustody.AdmissionRecord{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return jobcustody.WorkerClaimRecord{}, jobcustody.AdmissionRecord{}, err
	}
	return record, admission, nil
}

func loadJobCustodyWorkerClaim(
	ctx context.Context,
	querier jobCustodyQuerier,
	claimID uuid.UUID,
	forUpdate bool,
) (jobcustody.WorkerClaimRecord, jobcustody.AdmissionRecord, error) {
	if claimID == uuid.Nil {
		return jobcustody.WorkerClaimRecord{}, jobcustody.AdmissionRecord{}, jobcustody.ErrInvalid
	}
	query := `
		SELECT claim_id,capsule_id,route_authority_id,route_recipient_worker_id,
			route_recipient_key_fingerprint,worker_capabilities_digest,
			worker_owner_authority_digest,claim_permit_digest,
			claimed_at_milliseconds,lease_expires_at_milliseconds,state,
			updated_at_milliseconds
		FROM job_custody_worker_claims WHERE claim_id=$1`
	if forUpdate {
		query += " FOR UPDATE"
	}
	var record jobcustody.WorkerClaimRecord
	var capsuleUUID, workerUUID uuid.UUID
	var routeKey, capabilities, ownerAuthority, permitDigest, state string
	var claimedAt, leaseExpiresAt int64
	err := querier.QueryRow(ctx, query, claimID).Scan(
		&record.ClaimID, &capsuleUUID, &record.RouteAuthorityID, &workerUUID,
		&routeKey, &capabilities, &ownerAuthority, &permitDigest,
		&claimedAt, &leaseExpiresAt, &state, &record.UpdatedAtMillis,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return jobcustody.WorkerClaimRecord{}, jobcustody.AdmissionRecord{}, jobcustody.ErrMissing
	}
	if err != nil {
		return jobcustody.WorkerClaimRecord{}, jobcustody.AdmissionRecord{}, err
	}
	record.CapsuleID = computequeue.JobCapsuleID(capsuleUUID.String())
	record.RouteRecipientWorkerID = computequeue.WorkerID(workerUUID.String())
	record.RouteRecipientKeyFingerprint = computequeue.Digest(routeKey)
	record.WorkerCapabilitiesDigest = computequeue.Digest(capabilities)
	record.WorkerOwnerAuthorityDigest = computequeue.Digest(ownerAuthority)
	record.ClaimPermitDigest = computequeue.Digest(permitDigest)
	record.ClaimedAt = computequeue.Timestamp(claimedAt)
	record.LeaseExpiresAt = computequeue.Timestamp(leaseExpiresAt)
	record.State = jobcustody.WorkerClaimState(state)
	if record.ValidateStored() != nil {
		return jobcustody.WorkerClaimRecord{}, jobcustody.AdmissionRecord{}, jobcustody.ErrInvalid
	}
	admission, err := loadJobCustodyAdmission(ctx, querier, record.CapsuleID, false)
	if err != nil {
		return jobcustody.WorkerClaimRecord{}, jobcustody.AdmissionRecord{}, err
	}
	return record, admission, nil
}

func workerClaimRecordFromAuthorization(
	authorization jobcustody.WorkerClaimAuthorization,
	capsuleID computequeue.JobCapsuleID,
	now computequeue.Timestamp,
) jobcustody.WorkerClaimRecord {
	payload := authorization.Payload()
	return jobcustody.WorkerClaimRecord{
		ClaimID: payload.ClaimID, CapsuleID: capsuleID,
		RouteAuthorityID:             payload.AuthorityID,
		RouteRecipientWorkerID:       payload.RouteRecipientWorkerID,
		RouteRecipientKeyFingerprint: payload.RouteRecipientKeyFingerprint,
		WorkerCapabilitiesDigest:     payload.WorkerCapabilitiesDigest,
		WorkerOwnerAuthorityDigest:   payload.WorkerOwnerAuthorityDigest,
		ClaimPermitDigest:            authorization.PermitDigest(), ClaimedAt: now,
		LeaseExpiresAt: payload.ExpiresAt, State: jobcustody.WorkerClaimClaimed,
		UpdatedAtMillis: int64(now),
	}
}

func sameWorkerClaimAuthorization(
	record jobcustody.WorkerClaimRecord,
	admission jobcustody.AdmissionRecord,
	authorization jobcustody.WorkerClaimAuthorization,
) bool {
	payload := authorization.Payload()
	return record.ValidateStored() == nil && admission.ValidateStored() == nil &&
		record.CapsuleID == admission.Header.CapsuleID &&
		record.RouteAuthorityID == admission.RouteAuthorityID &&
		record.WorkerCapabilitiesDigest == admission.WorkerCapabilitiesDigest &&
		record.ClaimID == payload.ClaimID && record.RouteAuthorityID == payload.AuthorityID &&
		record.RouteRecipientWorkerID == payload.RouteRecipientWorkerID &&
		record.RouteRecipientKeyFingerprint == payload.RouteRecipientKeyFingerprint &&
		record.WorkerCapabilitiesDigest == payload.WorkerCapabilitiesDigest &&
		record.WorkerOwnerAuthorityDigest == payload.WorkerOwnerAuthorityDigest &&
		record.ClaimPermitDigest == authorization.PermitDigest() &&
		record.LeaseExpiresAt == payload.ExpiresAt
}

var _ jobcustody.WorkerClaimLedger = (*JobCustodyStore)(nil)
