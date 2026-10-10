// Package storageauthority owns the durable, content-blind physical-capacity
// ledger shared by services configured on one storage pool. It does not own
// service quotas, semantic resource identity, or stored content.
package storageauthority

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/robreuss/FacetsNode/internal/storagecapacity"
)

//go:embed schema.sql
var schema string

var (
	ErrInvalid     = errors.New("storage authority state is invalid")
	ErrConflict    = errors.New("storage authority operation conflicts with durable state")
	ErrRejected    = errors.New("storage authority request rejected")
	ErrUnavailable = errors.New("storage authority ledger is unavailable")
)

const ledgerTableCount = 4

type Ledger struct {
	pool        *pgxpool.Pool
	poolID      uuid.UUID
	authorityID uuid.UUID
	capacity    storagecapacity.Provider
}

// Initialize creates or verifies an otherwise dedicated authority schema. It
// never adopts unrelated tables or a different physical-pool identity.
func Initialize(
	ctx context.Context,
	pool *pgxpool.Pool,
	poolID uuid.UUID,
) error {
	if ctx == nil || pool == nil || poolID == uuid.Nil {
		return ErrInvalid
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return ErrUnavailable
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(6000568303396470853)`); err != nil {
		return ErrUnavailable
	}
	var count int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM pg_class WHERE relnamespace=current_schema()::regnamespace AND relkind IN ('r','v','m','f','p')`).Scan(&count); err != nil {
		return ErrUnavailable
	}
	if count == 0 {
		if _, err = tx.Exec(ctx, schema); err != nil {
			return fmt.Errorf("initialize storage authority schema: %w", ErrUnavailable)
		}
		if _, err = tx.Exec(ctx, `INSERT INTO storage_capacity_pool VALUES (true,$1,$2,1,1)`, poolID, uuid.New()); err != nil {
			return ErrUnavailable
		}
	} else if count != ledgerTableCount {
		return ErrInvalid
	} else {
		var existing uuid.UUID
		var version int
		if err = tx.QueryRow(ctx, `SELECT pool_id,version FROM storage_capacity_pool WHERE singleton FOR UPDATE`).Scan(&existing, &version); err != nil || existing != poolID || version != storagecapacity.AuthorityProtocolVersion {
			return ErrInvalid
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return ErrUnavailable
	}
	return nil
}

func Open(
	ctx context.Context,
	pool *pgxpool.Pool,
	poolID uuid.UUID,
	capacity storagecapacity.Provider,
) (*Ledger, error) {
	if ctx == nil || pool == nil || poolID == uuid.Nil || capacity == nil {
		return nil, ErrInvalid
	}
	var tableCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_class WHERE relnamespace=current_schema()::regnamespace AND relkind IN ('r','v','m','f','p')`).Scan(&tableCount); err != nil || tableCount != ledgerTableCount {
		return nil, ErrInvalid
	}
	var authorityID uuid.UUID
	var version int
	if err := pool.QueryRow(ctx, `SELECT authority_id,version FROM storage_capacity_pool WHERE singleton AND pool_id=$1`, poolID).Scan(&authorityID, &version); err != nil || authorityID == uuid.Nil || version != storagecapacity.AuthorityProtocolVersion {
		return nil, ErrInvalid
	}
	return &Ledger{pool: pool, poolID: poolID, authorityID: authorityID, capacity: capacity}, nil
}

func (ledger *Ledger) Reserve(
	ctx context.Context,
	request storagecapacity.ReservationRequest,
	bearerToken string,
) (storagecapacity.ReservationRecord, error) {
	if ledger == nil || ctx == nil || request.Validate() != nil || request.PoolID != ledger.poolID {
		return storagecapacity.ReservationRecord{}, ErrInvalid
	}
	proposed, err := storagecapacity.NewReservationRecord(request, bearerToken)
	if err != nil {
		return storagecapacity.ReservationRecord{}, ErrRejected
	}
	requestDigest, err := digestRequest(request)
	if err != nil {
		return storagecapacity.ReservationRecord{}, ErrInvalid
	}
	tx, _, err := ledger.begin(ctx)
	if err != nil {
		return storagecapacity.ReservationRecord{}, err
	}
	defer tx.Rollback(ctx)

	if existing, retry, err := loadOperationResult(ctx, tx, request.OperationID, request.ReservationID, "reserve", requestDigest, proposed.TokenDigest); err != nil {
		return storagecapacity.ReservationRecord{}, err
	} else if retry {
		return existing, ledger.commit(ctx, tx)
	}
	if _, err = loadReservation(ctx, tx, request.ReservationID, false); err == nil {
		return storagecapacity.ReservationRecord{}, ErrConflict
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return storagecapacity.ReservationRecord{}, err
	}
	outstanding, err := activeBytes(ctx, tx)
	if err != nil {
		return storagecapacity.ReservationRecord{}, err
	}
	snapshot, err := ledger.capacity.Snapshot(ctx)
	if err != nil {
		return storagecapacity.ReservationRecord{}, storagecapacity.ErrUnavailable
	}
	if err = storagecapacity.Check(snapshot, outstanding, request.ByteCeiling); err != nil {
		return storagecapacity.ReservationRecord{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO storage_capacity_reservations
        (reservation_id,pool_id,service_kind,service_instance_id,byte_ceiling,expires_at_milliseconds,state,revision,token_digest,updated_at_milliseconds)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, proposed.ReservationID, proposed.PoolID,
		string(proposed.Service.Kind), proposed.Service.InstanceID, proposed.ByteCeiling,
		proposed.ExpiresAtMilliseconds, string(proposed.State), proposed.Revision,
		proposed.TokenDigest, proposed.UpdatedAtMilliseconds); err != nil {
		return storagecapacity.ReservationRecord{}, ErrUnavailable
	}
	if err = insertOperation(ctx, tx, request.OperationID, proposed.ReservationID, "reserve", requestDigest, 0, proposed); err != nil {
		return storagecapacity.ReservationRecord{}, err
	}
	if err = incrementLedgerRevision(ctx, tx); err != nil {
		return storagecapacity.ReservationRecord{}, err
	}
	return proposed, ledger.commit(ctx, tx)
}

func (ledger *Ledger) Decide(
	ctx context.Context,
	decision storagecapacity.ReservationDecision,
) (storagecapacity.ReservationRecord, error) {
	requestDigest, tokenDigest, err := digestDecision(decision)
	if err != nil {
		return storagecapacity.ReservationRecord{}, ErrInvalid
	}
	tx, _, err := ledger.begin(ctx)
	if err != nil {
		return storagecapacity.ReservationRecord{}, err
	}
	defer tx.Rollback(ctx)
	kind := string(decision.Kind)
	if existing, retry, err := loadOperationResult(ctx, tx, decision.OperationID, decision.ReservationID, kind, requestDigest, tokenDigest); err != nil {
		return storagecapacity.ReservationRecord{}, err
	} else if retry {
		return existing, ledger.commit(ctx, tx)
	}
	current, err := loadReservation(ctx, tx, decision.ReservationID, true)
	if errors.Is(err, pgx.ErrNoRows) {
		return storagecapacity.ReservationRecord{}, ErrRejected
	}
	if err != nil {
		return storagecapacity.ReservationRecord{}, err
	}
	next, err := decision.Apply(current)
	if err != nil {
		return storagecapacity.ReservationRecord{}, ErrRejected
	}
	command, err := tx.Exec(ctx, `UPDATE storage_capacity_reservations SET state=$2,revision=$3,updated_at_milliseconds=$4
        WHERE reservation_id=$1 AND revision=$5`, next.ReservationID, string(next.State), next.Revision,
		next.UpdatedAtMilliseconds, current.Revision)
	if err != nil {
		return storagecapacity.ReservationRecord{}, ErrUnavailable
	}
	if command.RowsAffected() != 1 {
		return storagecapacity.ReservationRecord{}, ErrConflict
	}
	if err = insertOperation(ctx, tx, decision.OperationID, next.ReservationID, kind, requestDigest, current.Revision, next); err != nil {
		return storagecapacity.ReservationRecord{}, err
	}
	if err = incrementLedgerRevision(ctx, tx); err != nil {
		return storagecapacity.ReservationRecord{}, err
	}
	return next, ledger.commit(ctx, tx)
}

// Recheck fails closed when capacity cannot be measured or the reservation is
// no longer current. It retains the entire worst-case reservation until a
// terminal decision, deliberately favoring safety over utilization in this
// first shared-authority profile.
func (ledger *Ledger) Recheck(
	ctx context.Context,
	reservationID uuid.UUID,
	expectedRevision uint64,
	bearerToken string,
	observedAtMilliseconds int64,
) error {
	if reservationID == uuid.Nil || expectedRevision == 0 || observedAtMilliseconds <= 0 {
		return ErrInvalid
	}
	tx, _, err := ledger.begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	record, err := loadReservation(ctx, tx, reservationID, true)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrRejected
	}
	if err != nil {
		return err
	}
	if record.State != storagecapacity.ReservationReserved || record.Revision != expectedRevision ||
		observedAtMilliseconds < record.UpdatedAtMilliseconds || observedAtMilliseconds >= record.ExpiresAtMilliseconds ||
		!tokenMatches(record.TokenDigest, bearerToken) {
		return ErrRejected
	}
	outstanding, err := activeBytes(ctx, tx)
	if err != nil {
		return err
	}
	snapshot, err := ledger.capacity.Snapshot(ctx)
	if err != nil {
		return storagecapacity.ErrUnavailable
	}
	if err = storagecapacity.Check(snapshot, outstanding, 0); err != nil {
		return err
	}
	return ledger.commit(ctx, tx)
}

func (ledger *Ledger) ReconcileExpired(
	ctx context.Context,
	observedAtMilliseconds int64,
	limit int,
) ([]storagecapacity.ReservationRecord, error) {
	if observedAtMilliseconds <= 0 || limit < 1 || limit > 256 {
		return nil, ErrInvalid
	}
	tx, _, err := ledger.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT reservation_id FROM storage_capacity_reservations
        WHERE state='reserved' AND expires_at_milliseconds <= $1
        ORDER BY expires_at_milliseconds,reservation_id LIMIT $2 FOR UPDATE`, observedAtMilliseconds, limit)
	if err != nil {
		return nil, ErrUnavailable
	}
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if rows.Scan(&id) != nil {
			rows.Close()
			return nil, ErrUnavailable
		}
		ids = append(ids, id)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return nil, ErrUnavailable
	}
	rows.Close()
	results := make([]storagecapacity.ReservationRecord, 0, len(ids))
	for _, id := range ids {
		current, err := loadReservation(ctx, tx, id, false)
		if err != nil || current.State != storagecapacity.ReservationReserved || current.ExpiresAtMilliseconds > observedAtMilliseconds {
			return nil, ErrInvalid
		}
		next := current
		next.State = storagecapacity.ReservationExpired
		next.Revision++
		next.UpdatedAtMilliseconds = observedAtMilliseconds
		operationID := uuid.New()
		requestDigest := digestStrings("expire", id.String(), fmt.Sprint(current.Revision), fmt.Sprint(observedAtMilliseconds))
		command, updateErr := tx.Exec(ctx, `UPDATE storage_capacity_reservations SET state='expired',revision=$2,updated_at_milliseconds=$3
			WHERE reservation_id=$1 AND state='reserved' AND revision=$4`, id, next.Revision, observedAtMilliseconds, current.Revision)
		if updateErr != nil {
			return nil, ErrUnavailable
		}
		if command.RowsAffected() != 1 {
			return nil, ErrConflict
		}
		if err = insertOperation(ctx, tx, operationID, id, "expire", requestDigest, current.Revision, next); err != nil {
			return nil, err
		}
		results = append(results, next)
	}
	if len(results) > 0 {
		if err = incrementLedgerRevision(ctx, tx); err != nil {
			return nil, err
		}
	}
	return results, ledger.commit(ctx, tx)
}

func (ledger *Ledger) Reservation(
	ctx context.Context,
	reservationID uuid.UUID,
) (storagecapacity.ReservationRecord, error) {
	if ledger == nil || ctx == nil || reservationID == uuid.Nil {
		return storagecapacity.ReservationRecord{}, ErrInvalid
	}
	record, err := loadReservation(ctx, ledger.pool, reservationID, false)
	if errors.Is(err, pgx.ErrNoRows) {
		return storagecapacity.ReservationRecord{}, ErrRejected
	}
	return record, err
}

type querier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func (ledger *Ledger) begin(ctx context.Context) (pgx.Tx, uint64, error) {
	if ledger == nil || ctx == nil || ledger.pool == nil || ledger.poolID == uuid.Nil || ledger.authorityID == uuid.Nil || ledger.capacity == nil {
		return nil, 0, ErrInvalid
	}
	tx, err := ledger.pool.Begin(ctx)
	if err != nil {
		return nil, 0, ErrUnavailable
	}
	var poolID, authorityID uuid.UUID
	var revision uint64
	var version int
	if err = tx.QueryRow(ctx, `SELECT pool_id,authority_id,ledger_revision,version FROM storage_capacity_pool WHERE singleton FOR UPDATE`).Scan(&poolID, &authorityID, &revision, &version); err != nil || poolID != ledger.poolID || authorityID != ledger.authorityID || revision == 0 || version != storagecapacity.AuthorityProtocolVersion {
		tx.Rollback(ctx)
		return nil, 0, ErrInvalid
	}
	return tx, revision, nil
}

func (ledger *Ledger) commit(ctx context.Context, tx pgx.Tx) error {
	if err := tx.Commit(ctx); err != nil {
		return ErrUnavailable
	}
	return nil
}

func activeBytes(ctx context.Context, query querier) (int64, error) {
	var value int64
	if err := query.QueryRow(ctx, `SELECT COALESCE(sum(byte_ceiling::numeric),0)::bigint FROM storage_capacity_reservations WHERE state='reserved'`).Scan(&value); err != nil || value < 0 {
		return 0, ErrUnavailable
	}
	return value, nil
}

func loadReservation(
	ctx context.Context,
	query querier,
	id uuid.UUID,
	forUpdate bool,
) (storagecapacity.ReservationRecord, error) {
	if id == uuid.Nil {
		return storagecapacity.ReservationRecord{}, ErrInvalid
	}
	suffix := ""
	if forUpdate {
		suffix = " FOR UPDATE"
	}
	var record storagecapacity.ReservationRecord
	var kind, state string
	err := query.QueryRow(ctx, `SELECT pool_id,reservation_id,service_kind,service_instance_id,byte_ceiling,
        expires_at_milliseconds,state,revision,token_digest,updated_at_milliseconds
        FROM storage_capacity_reservations WHERE reservation_id=$1`+suffix, id).Scan(
		&record.PoolID, &record.ReservationID, &kind, &record.Service.InstanceID,
		&record.ByteCeiling, &record.ExpiresAtMilliseconds, &state, &record.Revision,
		&record.TokenDigest, &record.UpdatedAtMilliseconds)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return storagecapacity.ReservationRecord{}, err
		}
		return storagecapacity.ReservationRecord{}, ErrUnavailable
	}
	record.ProtocolVersion = storagecapacity.AuthorityProtocolVersion
	record.Service.Kind = storagecapacity.ServiceKind(kind)
	record.State = storagecapacity.ReservationState(state)
	if record.Validate() != nil {
		return storagecapacity.ReservationRecord{}, ErrInvalid
	}
	return record, nil
}

func loadOperationResult(
	ctx context.Context,
	tx pgx.Tx,
	operationID, reservationID uuid.UUID,
	kind, requestDigest, tokenDigest string,
) (storagecapacity.ReservationRecord, bool, error) {
	var storedReservation uuid.UUID
	var storedKind, storedDigest, resultState string
	var resultRevision uint64
	err := tx.QueryRow(ctx, `SELECT reservation_id,kind,request_digest,result_revision,result_state
        FROM storage_capacity_operations WHERE operation_id=$1`, operationID).Scan(
		&storedReservation, &storedKind, &storedDigest, &resultRevision, &resultState)
	if errors.Is(err, pgx.ErrNoRows) {
		return storagecapacity.ReservationRecord{}, false, nil
	}
	if err != nil {
		return storagecapacity.ReservationRecord{}, false, ErrUnavailable
	}
	if storedReservation != reservationID || storedKind != kind || storedDigest != requestDigest {
		return storagecapacity.ReservationRecord{}, false, ErrConflict
	}
	record, err := loadReservation(ctx, tx, reservationID, false)
	if err != nil {
		return storagecapacity.ReservationRecord{}, false, err
	}
	if record.Revision != resultRevision || string(record.State) != resultState ||
		subtle.ConstantTimeCompare([]byte(record.TokenDigest), []byte(tokenDigest)) != 1 {
		return storagecapacity.ReservationRecord{}, false, ErrConflict
	}
	return record, true, nil
}

func insertOperation(
	ctx context.Context,
	tx pgx.Tx,
	operationID, reservationID uuid.UUID,
	kind, requestDigest string,
	expectedRevision uint64,
	result storagecapacity.ReservationRecord,
) error {
	if _, err := tx.Exec(ctx, `INSERT INTO storage_capacity_operations
        (operation_id,reservation_id,kind,request_digest,expected_revision,result_revision,result_state,recorded_at_milliseconds)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, operationID, reservationID, kind, requestDigest,
		expectedRevision, result.Revision, string(result.State), result.UpdatedAtMilliseconds); err != nil {
		return ErrUnavailable
	}
	return nil
}

func incrementLedgerRevision(ctx context.Context, tx pgx.Tx) error {
	command, err := tx.Exec(ctx, `UPDATE storage_capacity_pool SET ledger_revision=ledger_revision+1
        WHERE singleton AND ledger_revision < 9223372036854775807`)
	if err != nil || command.RowsAffected() != 1 {
		return ErrUnavailable
	}
	return nil
}

func digestRequest(value any) (string, error) {
	bytes, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(bytes)
	return hex.EncodeToString(digest[:]), nil
}

func digestDecision(
	decision storagecapacity.ReservationDecision,
) (string, string, error) {
	if decision.OperationID == uuid.Nil || decision.ReservationID == uuid.Nil {
		return "", "", ErrInvalid
	}
	tokenDigest, err := storagecapacity.ReservationTokenDigest(decision.BearerToken)
	if err != nil {
		return "", "", err
	}
	protected := struct {
		ProtocolVersion        int                                     `json:"protocolVersion"`
		ReservationID          uuid.UUID                               `json:"reservationID"`
		OperationID            uuid.UUID                               `json:"operationID"`
		ExpectedRevision       uint64                                  `json:"expectedRevision"`
		Kind                   storagecapacity.ReservationDecisionKind `json:"kind"`
		ObservedAtMilliseconds int64                                   `json:"observedAtMilliseconds"`
		TokenDigest            string                                  `json:"tokenDigest"`
	}{decision.ProtocolVersion, decision.ReservationID, decision.OperationID, decision.ExpectedRevision,
		decision.Kind, decision.ObservedAtMilliseconds, tokenDigest}
	digest, err := digestRequest(protected)
	return digest, tokenDigest, err
}

func digestStrings(values ...string) string {
	hasher := sha256.New()
	for _, value := range values {
		_, _ = hasher.Write([]byte(value))
		_, _ = hasher.Write([]byte{0})
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func tokenMatches(expectedDigest, bearerToken string) bool {
	actual, err := storagecapacity.ReservationTokenDigest(bearerToken)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expectedDigest), []byte(actual)) == 1
}
