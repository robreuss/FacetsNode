package storageauthority

import (
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/robreuss/FacetsNode/internal/storagecapacity"
)

// RecoveryHysteresisBytes is the additional safely admissible headroom needed
// to leave a pressure state. Admission itself remains exact and does not spend
// this UI/notification hysteresis allowance.
const RecoveryHysteresisBytes = int64(256 << 20)

// RefreshReadiness measures the physical pool while holding the same pool-row
// lock used by admission. The result is advisory: only Reserve grants custody.
func (ledger *Ledger) RefreshReadiness(
	ctx context.Context,
	observedAtMilliseconds int64,
) (storagecapacity.ReadinessSnapshot, error) {
	if observedAtMilliseconds <= 0 {
		return storagecapacity.ReadinessSnapshot{}, ErrInvalid
	}
	tx, _, err := ledger.begin(ctx)
	if err != nil {
		return storagecapacity.ReadinessSnapshot{}, err
	}
	defer tx.Rollback(ctx)
	reserved, err := activeBytes(ctx, tx)
	if err != nil {
		return storagecapacity.ReadinessSnapshot{}, err
	}
	previous, exists, err := loadReadiness(ctx, tx)
	if err != nil {
		return storagecapacity.ReadinessSnapshot{}, err
	}
	if exists && observedAtMilliseconds < previous.ObservedAtMilliseconds {
		return storagecapacity.ReadinessSnapshot{}, ErrConflict
	}
	physical, capacityErr := ledger.capacity.Snapshot(ctx)
	next := buildReadiness(
		ledger.poolID,
		previous,
		exists,
		physical,
		capacityErr,
		reserved,
		observedAtMilliseconds,
	)
	if next.Validate() != nil {
		return storagecapacity.ReadinessSnapshot{}, ErrInvalid
	}
	if exists {
		if readinessChanged(previous, next) {
			if previous.Revision >= math.MaxInt64 {
				return storagecapacity.ReadinessSnapshot{}, ErrUnavailable
			}
			next.Revision = previous.Revision + 1
		} else {
			next.Revision = previous.Revision
		}
	} else {
		next.Revision = 1
	}
	if err = storeReadiness(ctx, tx, next, exists); err != nil {
		return storagecapacity.ReadinessSnapshot{}, err
	}
	if event, ok := readinessTransition(previous, exists, next); ok {
		if err = insertReadinessEvent(ctx, tx, event); err != nil {
			return storagecapacity.ReadinessSnapshot{}, err
		}
	}
	if err = ledger.commit(ctx, tx); err != nil {
		return storagecapacity.ReadinessSnapshot{}, err
	}
	return next, nil
}

func (ledger *Ledger) Readiness(ctx context.Context) (storagecapacity.ReadinessSnapshot, error) {
	if ledger == nil || ctx == nil || ledger.pool == nil {
		return storagecapacity.ReadinessSnapshot{}, ErrInvalid
	}
	value, exists, err := loadReadiness(ctx, ledger.pool)
	if err != nil {
		return storagecapacity.ReadinessSnapshot{}, err
	}
	if !exists {
		return storagecapacity.ReadinessSnapshot{}, ErrUnavailable
	}
	return value, nil
}

func (ledger *Ledger) CoarseReadiness(ctx context.Context) (storagecapacity.CoarseReadinessSnapshot, error) {
	value, err := ledger.Readiness(ctx)
	if err != nil {
		return storagecapacity.CoarseReadinessSnapshot{}, err
	}
	coarse, err := value.Coarse()
	if err != nil {
		return storagecapacity.CoarseReadinessSnapshot{}, ErrInvalid
	}
	return coarse, nil
}

// ReadinessEvents returns owner-only transition records after an event
// sequence. Consumers must project or redact them before participant delivery.
func (ledger *Ledger) ReadinessEvents(
	ctx context.Context,
	afterSequence uint64,
	limit int,
) ([]storagecapacity.ReadinessEvent, error) {
	if ledger == nil || ctx == nil || ledger.pool == nil || afterSequence > math.MaxInt64 || limit < 1 || limit > 256 {
		return nil, ErrInvalid
	}
	rows, err := ledger.pool.Query(ctx, `SELECT event_sequence,event_id,readiness_revision,kind,state,observed_at_milliseconds,
		total_bytes,available_bytes,reserved_bytes,operating_reserve_bytes,admissible_bytes
		FROM storage_capacity_events WHERE event_sequence > $1
		ORDER BY event_sequence LIMIT $2`, afterSequence, limit)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer rows.Close()
	var events []storagecapacity.ReadinessEvent
	for rows.Next() {
		event := storagecapacity.ReadinessEvent{ProtocolVersion: storagecapacity.AuthorityProtocolVersion}
		event.Snapshot.ProtocolVersion = storagecapacity.AuthorityProtocolVersion
		event.Snapshot.PoolID = ledger.poolID
		if err = rows.Scan(
			&event.Sequence,
			&event.EventID,
			&event.Snapshot.Revision,
			&event.Kind,
			&event.Snapshot.State,
			&event.Snapshot.ObservedAtMilliseconds,
			&event.Snapshot.TotalBytes,
			&event.Snapshot.AvailableBytes,
			&event.Snapshot.ReservedBytes,
			&event.Snapshot.OperatingReserveBytes,
			&event.Snapshot.AdmissibleBytes,
		); err != nil || event.Validate() != nil {
			return nil, ErrUnavailable
		}
		events = append(events, event)
	}
	if rows.Err() != nil {
		return nil, ErrUnavailable
	}
	return events, nil
}

func buildReadiness(
	poolID uuid.UUID,
	previous storagecapacity.ReadinessSnapshot,
	hasPrevious bool,
	physical storagecapacity.Snapshot,
	capacityErr error,
	reserved int64,
	observedAtMilliseconds int64,
) storagecapacity.ReadinessSnapshot {
	value := storagecapacity.ReadinessSnapshot{
		ProtocolVersion:        storagecapacity.AuthorityProtocolVersion,
		PoolID:                 poolID,
		Revision:               1,
		ObservedAtMilliseconds: observedAtMilliseconds,
		ReservedBytes:          reserved,
	}
	reserve, reserveErr := physical.OperatingReserve()
	if capacityErr != nil || reserveErr != nil || reserved < 0 {
		value.State = storagecapacity.ReadinessCapacityUnavailable
		return value
	}
	value.TotalBytes = physical.TotalBytes
	value.AvailableBytes = physical.AvailableBytes
	value.OperatingReserveBytes = reserve
	if physical.AvailableBytes > reserve && reserved < physical.AvailableBytes-reserve {
		value.AdmissibleBytes = physical.AvailableBytes - reserve - reserved
	}
	value.State = storagecapacity.ReadinessReady
	if value.AdmissibleBytes == 0 || storagecapacity.Check(physical, reserved, 0) != nil ||
		(hasPrevious &&
			(previous.State == storagecapacity.ReadinessStoragePressure || previous.State == storagecapacity.ReadinessDegraded) &&
			value.AdmissibleBytes < RecoveryHysteresisBytes) {
		value.State = storagecapacity.ReadinessStoragePressure
	}
	return value
}

func readinessChanged(
	left storagecapacity.ReadinessSnapshot,
	right storagecapacity.ReadinessSnapshot,
) bool {
	return left.State != right.State ||
		left.TotalBytes != right.TotalBytes ||
		left.AvailableBytes != right.AvailableBytes ||
		left.ReservedBytes != right.ReservedBytes ||
		left.OperatingReserveBytes != right.OperatingReserveBytes ||
		left.AdmissibleBytes != right.AdmissibleBytes
}

func loadReadiness(
	ctx context.Context,
	query querier,
) (storagecapacity.ReadinessSnapshot, bool, error) {
	value := storagecapacity.ReadinessSnapshot{
		ProtocolVersion: storagecapacity.AuthorityProtocolVersion,
	}
	err := query.QueryRow(ctx, `SELECT revision,state,observed_at_milliseconds,total_bytes,available_bytes,
        reserved_bytes,operating_reserve_bytes,admissible_bytes
        FROM storage_capacity_readiness WHERE singleton`).Scan(
		&value.Revision,
		&value.State,
		&value.ObservedAtMilliseconds,
		&value.TotalBytes,
		&value.AvailableBytes,
		&value.ReservedBytes,
		&value.OperatingReserveBytes,
		&value.AdmissibleBytes,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return storagecapacity.ReadinessSnapshot{}, false, nil
	}
	if err != nil {
		return storagecapacity.ReadinessSnapshot{}, false, ErrUnavailable
	}
	var poolID uuid.UUID
	if err = query.QueryRow(ctx, `SELECT pool_id FROM storage_capacity_pool WHERE singleton`).Scan(&poolID); err != nil {
		return storagecapacity.ReadinessSnapshot{}, false, ErrUnavailable
	}
	value.PoolID = poolID
	if value.Validate() != nil {
		return storagecapacity.ReadinessSnapshot{}, false, ErrInvalid
	}
	return value, true, nil
}

func storeReadiness(
	ctx context.Context,
	tx pgx.Tx,
	value storagecapacity.ReadinessSnapshot,
	exists bool,
) error {
	if value.Validate() != nil {
		return ErrInvalid
	}
	if !exists {
		_, err := tx.Exec(ctx, `INSERT INTO storage_capacity_readiness
            (singleton,revision,state,observed_at_milliseconds,total_bytes,available_bytes,reserved_bytes,
             operating_reserve_bytes,admissible_bytes)
            VALUES (true,$1,$2,$3,$4,$5,$6,$7,$8)`, value.Revision, string(value.State),
			value.ObservedAtMilliseconds, value.TotalBytes, value.AvailableBytes,
			value.ReservedBytes, value.OperatingReserveBytes, value.AdmissibleBytes)
		if err != nil {
			return ErrUnavailable
		}
		return nil
	}
	command, err := tx.Exec(ctx, `UPDATE storage_capacity_readiness SET
        revision=$1,state=$2,observed_at_milliseconds=$3,total_bytes=$4,available_bytes=$5,reserved_bytes=$6,
        operating_reserve_bytes=$7,admissible_bytes=$8 WHERE singleton`, value.Revision, string(value.State),
		value.ObservedAtMilliseconds, value.TotalBytes, value.AvailableBytes,
		value.ReservedBytes, value.OperatingReserveBytes, value.AdmissibleBytes)
	if err != nil || command.RowsAffected() != 1 {
		return ErrUnavailable
	}
	return nil
}

func readinessTransition(
	previous storagecapacity.ReadinessSnapshot,
	hasPrevious bool,
	next storagecapacity.ReadinessSnapshot,
) (storagecapacity.ReadinessEvent, bool) {
	if hasPrevious && previous.State == next.State {
		return storagecapacity.ReadinessEvent{}, false
	}
	var kind storagecapacity.ReadinessEventKind
	switch next.State {
	case storagecapacity.ReadinessReady:
		if !hasPrevious {
			return storagecapacity.ReadinessEvent{}, false
		}
		kind = storagecapacity.ReadinessEventRecovered
	case storagecapacity.ReadinessCapacityUnavailable:
		kind = storagecapacity.ReadinessEventCapacityUnavailable
	case storagecapacity.ReadinessStoragePressure, storagecapacity.ReadinessDegraded:
		kind = storagecapacity.ReadinessEventPressure
	default:
		return storagecapacity.ReadinessEvent{}, false
	}
	event := storagecapacity.ReadinessEvent{
		ProtocolVersion: storagecapacity.AuthorityProtocolVersion,
		EventID:         uuid.New(),
		Kind:            kind,
		Snapshot:        next,
	}
	validated := event
	validated.Sequence = 1
	return event, validated.Validate() == nil
}

func insertReadinessEvent(
	ctx context.Context,
	tx pgx.Tx,
	event storagecapacity.ReadinessEvent,
) error {
	validated := event
	validated.Sequence = 1
	if validated.Validate() != nil {
		return ErrInvalid
	}
	deduplicationDigest := digestStrings(
		"readiness-transition",
		string(event.Kind),
		fmt.Sprint(event.Snapshot.Revision),
	)
	_, err := tx.Exec(ctx, `INSERT INTO storage_capacity_events
		(event_id,readiness_revision,deduplication_digest,kind,state,observed_at_milliseconds,total_bytes,available_bytes,
		 reserved_bytes,operating_reserve_bytes,admissible_bytes)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, event.EventID, event.Snapshot.Revision,
		deduplicationDigest, string(event.Kind), string(event.Snapshot.State), event.Snapshot.ObservedAtMilliseconds,
		event.Snapshot.TotalBytes, event.Snapshot.AvailableBytes, event.Snapshot.ReservedBytes,
		event.Snapshot.OperatingReserveBytes, event.Snapshot.AdmissibleBytes)
	if err != nil {
		return ErrUnavailable
	}
	return nil
}
