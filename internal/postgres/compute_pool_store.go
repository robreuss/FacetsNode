package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/robreuss/FacetsNode/internal/computepool"
)

type ComputePoolStore struct {
	pool *pgxpool.Pool
}

func NewComputePoolStore(pool *pgxpool.Pool) *ComputePoolStore {
	return &ComputePoolStore{pool: pool}
}

func (store *ComputePoolStore) CreatePool(
	ctx context.Context,
	pool computepool.Pool,
) error {
	if pool.Validate() != nil || pool.Revision != 1 {
		return computepool.ErrInvalid
	}
	payload, err := json.Marshal(pool)
	if err != nil {
		return fmt.Errorf("encode Compute Pool: %w", err)
	}
	_, err = store.pool.Exec(ctx, `
		INSERT INTO compute_pools (
			pool_id,owner_authority_id,authority_revision,authority_manifest_digest,
			current_revision,pool_payload,created_at_milliseconds,updated_at_milliseconds
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
	`, pool.PoolID, pool.OwnerAuthorityID, pool.AuthorityRevision,
		pool.AuthorityManifestDigest, pool.Revision, payload,
		pool.CreatedAtMilliseconds, pool.UpdatedAtMilliseconds)
	if err != nil {
		return mapComputePoolWriteError(err)
	}
	return nil
}

func (store *ComputePoolStore) UpdatePool(
	ctx context.Context,
	previousRevision uint64,
	next computepool.Pool,
) error {
	if next.Validate() != nil || previousRevision == 0 || next.Revision != previousRevision+1 {
		return computepool.ErrInvalid
	}
	transaction, err := store.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin Compute Pool update: %w", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	current, err := loadComputePool(ctx, transaction, next.PoolID, true)
	if err != nil {
		return err
	}
	if current.Revision != previousRevision ||
		current.OwnerAuthorityID != next.OwnerAuthorityID ||
		current.CreatedAtMilliseconds != next.CreatedAtMilliseconds ||
		next.UpdatedAtMilliseconds < current.UpdatedAtMilliseconds ||
		next.AuthorityRevision < current.AuthorityRevision ||
		(next.AuthorityRevision == current.AuthorityRevision &&
			next.AuthorityManifestDigest != current.AuthorityManifestDigest) {
		return computepool.ErrConflict
	}
	payload, err := json.Marshal(next)
	if err != nil {
		return fmt.Errorf("encode Compute Pool update: %w", err)
	}
	if _, err := transaction.Exec(ctx, `
		UPDATE compute_pools
		SET authority_revision=$2,authority_manifest_digest=$3,current_revision=$4,
		    pool_payload=$5,updated_at_milliseconds=$6,stored_at=now()
		WHERE pool_id=$1
	`, next.PoolID, next.AuthorityRevision, next.AuthorityManifestDigest,
		next.Revision, payload, next.UpdatedAtMilliseconds); err != nil {
		return mapComputePoolWriteError(err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return fmt.Errorf("commit Compute Pool update: %w", err)
	}
	return nil
}

func (store *ComputePoolStore) DeletePool(
	ctx context.Context,
	poolID uuid.UUID,
	expectedRevision uint64,
) error {
	if poolID == uuid.Nil || expectedRevision == 0 {
		return computepool.ErrInvalid
	}
	transaction, err := store.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin Compute Pool deletion: %w", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	current, err := loadComputePool(ctx, transaction, poolID, true)
	if err != nil {
		return err
	}
	if current.Revision != expectedRevision {
		return computepool.ErrConflict
	}
	if _, err := transaction.Exec(
		ctx,
		"DELETE FROM compute_pools WHERE pool_id=$1",
		poolID,
	); err != nil {
		return mapComputePoolWriteError(err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return fmt.Errorf("commit Compute Pool deletion: %w", err)
	}
	return nil
}

func (store *ComputePoolStore) PutWorkerEnrollment(
	ctx context.Context,
	previousRevision uint64,
	next computepool.WorkerEnrollment,
) error {
	if next.Validate() != nil || next.Revision != previousRevision+1 {
		return computepool.ErrInvalid
	}
	transaction, err := store.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin Compute Pool Worker enrollment: %w", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	current, found, err := loadComputePoolWorkerEnrollment(
		ctx,
		transaction,
		next.EnrollmentID,
		true,
	)
	if err != nil {
		return err
	}
	if !found {
		if previousRevision != 0 {
			return computepool.ErrNotFound
		}
	} else if current.Revision != previousRevision || current.PoolID != next.PoolID ||
		current.WorkerID != next.WorkerID ||
		current.WorkerOwnerAuthorityID != next.WorkerOwnerAuthorityID ||
		current.CreatedAtMilliseconds != next.CreatedAtMilliseconds ||
		next.UpdatedAtMilliseconds < current.UpdatedAtMilliseconds ||
		next.ConsentRevision < current.ConsentRevision ||
		(next.ConsentRevision == current.ConsentRevision &&
			(next.PublicSigningKeyEd25519 != current.PublicSigningKeyEd25519 ||
				next.SigningKeyFingerprint != current.SigningKeyFingerprint)) {
		return computepool.ErrConflict
	}
	payload, err := json.Marshal(next)
	if err != nil {
		return fmt.Errorf("encode Compute Pool Worker enrollment: %w", err)
	}
	if !found {
		_, err = transaction.Exec(ctx, `
			INSERT INTO compute_pool_worker_enrollments (
				enrollment_id,pool_id,worker_id,worker_owner_authority_id,
				consent_revision,current_revision,enrollment_payload,
				created_at_milliseconds,updated_at_milliseconds
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		`, next.EnrollmentID, next.PoolID, next.WorkerID,
			next.WorkerOwnerAuthorityID, next.ConsentRevision, next.Revision,
			payload, next.CreatedAtMilliseconds, next.UpdatedAtMilliseconds)
	} else {
		_, err = transaction.Exec(ctx, `
			UPDATE compute_pool_worker_enrollments
			SET consent_revision=$2,current_revision=$3,enrollment_payload=$4,
			    updated_at_milliseconds=$5,stored_at=now()
			WHERE enrollment_id=$1
		`, next.EnrollmentID, next.ConsentRevision, next.Revision,
			payload, next.UpdatedAtMilliseconds)
	}
	if err != nil {
		return mapComputePoolWriteError(err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return fmt.Errorf("commit Compute Pool Worker enrollment: %w", err)
	}
	return nil
}

func (store *ComputePoolStore) PutWorkerCard(
	ctx context.Context,
	previousRevision uint64,
	nextSigned computepool.SignedWorkerCard,
) error {
	next := nextSigned.Card
	if next.Validate() != nil || next.Revision != previousRevision+1 {
		return computepool.ErrInvalid
	}
	transaction, err := store.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin Compute Pool Worker Card: %w", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	current, found, err := loadComputePoolWorkerCard(ctx, transaction, next.WorkerCardID, true)
	if err != nil {
		return err
	}
	if !found {
		if previousRevision != 0 {
			return computepool.ErrNotFound
		}
	} else if current.Card.Revision != previousRevision || current.Card.PoolID != next.PoolID ||
		current.Card.WorkerEnrollmentID != next.WorkerEnrollmentID ||
		current.Card.WorkerOwnerAuthorityID != next.WorkerOwnerAuthorityID ||
		current.Card.CreatedAtMilliseconds != next.CreatedAtMilliseconds ||
		next.UpdatedAtMilliseconds < current.Card.UpdatedAtMilliseconds {
		return computepool.ErrConflict
	}
	enrollment, enrollmentFound, err := loadComputePoolWorkerEnrollment(
		ctx, transaction, next.WorkerEnrollmentID, false,
	)
	if err != nil {
		return err
	}
	if !enrollmentFound || enrollment.PoolID != next.PoolID ||
		enrollment.WorkerOwnerAuthorityID != next.WorkerOwnerAuthorityID {
		return computepool.ErrNotFound
	}
	if nextSigned.Validate(enrollment) != nil {
		return computepool.ErrInvalid
	}
	if found && current.Validate(enrollment) != nil {
		return fmt.Errorf("stored Compute Pool Worker Card signature is invalid")
	}
	payload, err := json.Marshal(nextSigned)
	if err != nil {
		return fmt.Errorf("encode Compute Pool Worker Card: %w", err)
	}
	if !found {
		_, err = transaction.Exec(ctx, `
			INSERT INTO compute_pool_worker_cards (
				worker_card_id,pool_id,worker_enrollment_id,worker_owner_authority_id,
				current_revision,card_payload,created_at_milliseconds,updated_at_milliseconds
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		`, next.WorkerCardID, next.PoolID, next.WorkerEnrollmentID,
			next.WorkerOwnerAuthorityID, next.Revision, payload,
			next.CreatedAtMilliseconds, next.UpdatedAtMilliseconds)
	} else {
		_, err = transaction.Exec(ctx, `
			UPDATE compute_pool_worker_cards
			SET current_revision=$2,card_payload=$3,updated_at_milliseconds=$4,stored_at=now()
			WHERE worker_card_id=$1
		`, next.WorkerCardID, next.Revision, payload, next.UpdatedAtMilliseconds)
	}
	if err != nil {
		return mapComputePoolWriteError(err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return fmt.Errorf("commit Compute Pool Worker Card: %w", err)
	}
	return nil
}

func (store *ComputePoolStore) PutOffering(
	ctx context.Context,
	previousRevision uint64,
	next computepool.Offering,
) error {
	if next.Validate() != nil || next.Revision != previousRevision+1 {
		return computepool.ErrInvalid
	}
	transaction, err := store.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin Compute Pool offering: %w", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	current, found, err := loadComputePoolOffering(
		ctx,
		transaction,
		next.OfferingID,
		true,
	)
	if err != nil {
		return err
	}
	if !found {
		if previousRevision != 0 {
			return computepool.ErrNotFound
		}
	} else if current.Revision != previousRevision || current.PoolID != next.PoolID ||
		current.WorkerEnrollmentID != next.WorkerEnrollmentID ||
		current.CreatedAtMilliseconds != next.CreatedAtMilliseconds ||
		next.UpdatedAtMilliseconds < current.UpdatedAtMilliseconds ||
		next.PricingRevision < current.PricingRevision {
		return computepool.ErrConflict
	}
	signedCard, cardFound, err := loadComputePoolWorkerCard(ctx, transaction, next.WorkerCardID, false)
	if err != nil {
		return err
	}
	card := signedCard.Card
	enrollment, enrollmentFound, err := loadComputePoolWorkerEnrollment(ctx, transaction, next.WorkerEnrollmentID, false)
	if err != nil {
		return err
	}
	cardDigest, digestError := card.Digest()
	if !cardFound || !enrollmentFound || signedCard.Validate(enrollment) != nil || card.PoolID != next.PoolID ||
		card.WorkerEnrollmentID != next.WorkerEnrollmentID ||
		next.WorkerCardRevision != card.Revision || digestError != nil ||
		next.WorkerCardDigest != cardDigest {
		return computepool.ErrNotFound
	}
	payload, err := json.Marshal(next)
	if err != nil {
		return fmt.Errorf("encode Compute Pool offering: %w", err)
	}
	if !found {
		_, err = transaction.Exec(ctx, `
			INSERT INTO compute_pool_offerings (
				offering_id,pool_id,worker_enrollment_id,worker_card_id,pricing_revision,
				current_revision,offering_payload,created_at_milliseconds,
				updated_at_milliseconds
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		`, next.OfferingID, next.PoolID, next.WorkerEnrollmentID,
			next.WorkerCardID, next.PricingRevision, next.Revision, payload,
			next.CreatedAtMilliseconds, next.UpdatedAtMilliseconds)
	} else {
		_, err = transaction.Exec(ctx, `
			UPDATE compute_pool_offerings
			SET worker_card_id=$2,pricing_revision=$3,current_revision=$4,offering_payload=$5,
			    updated_at_milliseconds=$6,stored_at=now()
			WHERE offering_id=$1
		`, next.OfferingID, next.WorkerCardID, next.PricingRevision, next.Revision,
			payload, next.UpdatedAtMilliseconds)
	}
	if err != nil {
		return mapComputePoolWriteError(err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return fmt.Errorf("commit Compute Pool offering: %w", err)
	}
	return nil
}

func (store *ComputePoolStore) GetPoolStatus(
	ctx context.Context,
	poolID uuid.UUID,
) (computepool.Status, error) {
	if poolID == uuid.Nil {
		return computepool.Status{}, computepool.ErrInvalid
	}
	transaction, err := store.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return computepool.Status{}, fmt.Errorf("begin Compute Pool status: %w", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	pool, err := loadComputePool(ctx, transaction, poolID, false)
	if err != nil {
		return computepool.Status{}, err
	}
	enrollments, err := loadComputePoolWorkerEnrollments(ctx, transaction, poolID)
	if err != nil {
		return computepool.Status{}, err
	}
	cards, err := loadComputePoolWorkerCards(ctx, transaction, poolID)
	if err != nil {
		return computepool.Status{}, err
	}
	offerings, err := loadComputePoolOfferings(ctx, transaction, poolID)
	if err != nil {
		return computepool.Status{}, err
	}
	status := computepool.Status{
		Version: computepool.SchemaVersion, Pool: pool,
		WorkerEnrollments: enrollments, WorkerCards: cards, Offerings: offerings,
	}
	if err := status.Validate(); err != nil {
		return computepool.Status{}, fmt.Errorf("stored Compute Pool status is invalid: %w", err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return computepool.Status{}, fmt.Errorf("commit Compute Pool status: %w", err)
	}
	return status, nil
}

func loadComputePool(
	ctx context.Context,
	transaction pgx.Tx,
	poolID uuid.UUID,
	forUpdate bool,
) (computepool.Pool, error) {
	query := "SELECT pool_payload FROM compute_pools WHERE pool_id=$1"
	if forUpdate {
		query += " FOR UPDATE"
	}
	var payload []byte
	if err := transaction.QueryRow(ctx, query, poolID).Scan(&payload); err == pgx.ErrNoRows {
		return computepool.Pool{}, computepool.ErrNotFound
	} else if err != nil {
		return computepool.Pool{}, fmt.Errorf("load Compute Pool: %w", err)
	}
	var pool computepool.Pool
	if err := json.Unmarshal(payload, &pool); err != nil || pool.Validate() != nil ||
		pool.PoolID != poolID {
		return computepool.Pool{}, fmt.Errorf("stored Compute Pool is invalid")
	}
	return pool, nil
}

func loadComputePoolWorkerEnrollment(
	ctx context.Context,
	transaction pgx.Tx,
	enrollmentID uuid.UUID,
	forUpdate bool,
) (computepool.WorkerEnrollment, bool, error) {
	query := "SELECT enrollment_payload FROM compute_pool_worker_enrollments WHERE enrollment_id=$1"
	if forUpdate {
		query += " FOR UPDATE"
	}
	var payload []byte
	if err := transaction.QueryRow(ctx, query, enrollmentID).Scan(&payload); err == pgx.ErrNoRows {
		return computepool.WorkerEnrollment{}, false, nil
	} else if err != nil {
		return computepool.WorkerEnrollment{}, false, fmt.Errorf(
			"load Compute Pool Worker enrollment: %w",
			err,
		)
	}
	var enrollment computepool.WorkerEnrollment
	if err := json.Unmarshal(payload, &enrollment); err != nil ||
		enrollment.Validate() != nil || enrollment.EnrollmentID != enrollmentID {
		return computepool.WorkerEnrollment{}, false, fmt.Errorf(
			"stored Compute Pool Worker enrollment is invalid",
		)
	}
	return enrollment, true, nil
}

func loadComputePoolOffering(
	ctx context.Context,
	transaction pgx.Tx,
	offeringID uuid.UUID,
	forUpdate bool,
) (computepool.Offering, bool, error) {
	query := "SELECT offering_payload FROM compute_pool_offerings WHERE offering_id=$1"
	if forUpdate {
		query += " FOR UPDATE"
	}
	var payload []byte
	if err := transaction.QueryRow(ctx, query, offeringID).Scan(&payload); err == pgx.ErrNoRows {
		return computepool.Offering{}, false, nil
	} else if err != nil {
		return computepool.Offering{}, false, fmt.Errorf("load Compute Pool offering: %w", err)
	}
	var offering computepool.Offering
	if err := json.Unmarshal(payload, &offering); err != nil || offering.Validate() != nil ||
		offering.OfferingID != offeringID {
		return computepool.Offering{}, false, fmt.Errorf("stored Compute Pool offering is invalid")
	}
	return offering, true, nil
}

func loadComputePoolWorkerCard(
	ctx context.Context,
	transaction pgx.Tx,
	cardID uuid.UUID,
	forUpdate bool,
) (computepool.SignedWorkerCard, bool, error) {
	query := "SELECT card_payload FROM compute_pool_worker_cards WHERE worker_card_id=$1"
	if forUpdate {
		query += " FOR UPDATE"
	}
	var payload []byte
	if err := transaction.QueryRow(ctx, query, cardID).Scan(&payload); err == pgx.ErrNoRows {
		return computepool.SignedWorkerCard{}, false, nil
	} else if err != nil {
		return computepool.SignedWorkerCard{}, false, fmt.Errorf("load Compute Pool Worker Card: %w", err)
	}
	var signedCard computepool.SignedWorkerCard
	if err := json.Unmarshal(payload, &signedCard); err != nil || signedCard.Card.Validate() != nil ||
		signedCard.Card.WorkerCardID != cardID {
		return computepool.SignedWorkerCard{}, false, fmt.Errorf("stored Compute Pool Worker Card is invalid")
	}
	return signedCard, true, nil
}

func loadComputePoolWorkerEnrollments(
	ctx context.Context,
	transaction pgx.Tx,
	poolID uuid.UUID,
) ([]computepool.WorkerEnrollment, error) {
	rows, err := transaction.Query(ctx, `
		SELECT enrollment_payload
		FROM compute_pool_worker_enrollments
		WHERE pool_id=$1
		ORDER BY enrollment_id
	`, poolID)
	if err != nil {
		return nil, fmt.Errorf("query Compute Pool Worker enrollments: %w", err)
	}
	defer rows.Close()
	result := make([]computepool.WorkerEnrollment, 0)
	for rows.Next() {
		var payload []byte
		var enrollment computepool.WorkerEnrollment
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("scan Compute Pool Worker enrollment: %w", err)
		}
		if err := json.Unmarshal(payload, &enrollment); err != nil ||
			enrollment.Validate() != nil || enrollment.PoolID != poolID {
			return nil, fmt.Errorf("stored Compute Pool Worker enrollment is invalid")
		}
		result = append(result, enrollment)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate Compute Pool Worker enrollments: %w", err)
	}
	sort.Slice(result, func(left, right int) bool {
		return result[left].EnrollmentID.String() < result[right].EnrollmentID.String()
	})
	return result, nil
}

func loadComputePoolOfferings(
	ctx context.Context,
	transaction pgx.Tx,
	poolID uuid.UUID,
) ([]computepool.Offering, error) {
	rows, err := transaction.Query(ctx, `
		SELECT offering_payload
		FROM compute_pool_offerings
		WHERE pool_id=$1
		ORDER BY offering_id
	`, poolID)
	if err != nil {
		return nil, fmt.Errorf("query Compute Pool offerings: %w", err)
	}
	defer rows.Close()
	result := make([]computepool.Offering, 0)
	for rows.Next() {
		var payload []byte
		var offering computepool.Offering
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("scan Compute Pool offering: %w", err)
		}
		if err := json.Unmarshal(payload, &offering); err != nil ||
			offering.Validate() != nil || offering.PoolID != poolID {
			return nil, fmt.Errorf("stored Compute Pool offering is invalid")
		}
		result = append(result, offering)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate Compute Pool offerings: %w", err)
	}
	sort.Slice(result, func(left, right int) bool {
		return result[left].OfferingID.String() < result[right].OfferingID.String()
	})
	return result, nil
}

func loadComputePoolWorkerCards(
	ctx context.Context,
	transaction pgx.Tx,
	poolID uuid.UUID,
) ([]computepool.SignedWorkerCard, error) {
	rows, err := transaction.Query(ctx, `
		SELECT card_payload
		FROM compute_pool_worker_cards
		WHERE pool_id=$1
		ORDER BY worker_card_id
	`, poolID)
	if err != nil {
		return nil, fmt.Errorf("query Compute Pool Worker Cards: %w", err)
	}
	defer rows.Close()
	result := make([]computepool.SignedWorkerCard, 0)
	for rows.Next() {
		var payload []byte
		var signedCard computepool.SignedWorkerCard
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("scan Compute Pool Worker Card: %w", err)
		}
		if err := json.Unmarshal(payload, &signedCard); err != nil || signedCard.Card.Validate() != nil || signedCard.Card.PoolID != poolID {
			return nil, fmt.Errorf("stored Compute Pool Worker Card is invalid")
		}
		result = append(result, signedCard)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate Compute Pool Worker Cards: %w", err)
	}
	sort.Slice(result, func(left, right int) bool {
		return result[left].Card.WorkerCardID.String() < result[right].Card.WorkerCardID.String()
	})
	return result, nil
}

func mapComputePoolWriteError(err error) error {
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		switch postgresError.Code {
		case "23503":
			return computepool.ErrNotFound
		case "23505":
			return computepool.ErrConflict
		}
	}
	return err
}
