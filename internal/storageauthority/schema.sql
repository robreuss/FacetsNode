CREATE TABLE storage_capacity_pool (
    singleton boolean PRIMARY KEY CHECK (singleton),
    pool_id uuid NOT NULL UNIQUE,
    authority_id uuid NOT NULL UNIQUE,
    ledger_revision bigint NOT NULL CHECK (ledger_revision > 0),
    version integer NOT NULL CHECK (version = 1)
);

CREATE TABLE storage_capacity_reservations (
    reservation_id uuid PRIMARY KEY,
    pool_id uuid NOT NULL REFERENCES storage_capacity_pool(pool_id),
    service_kind text NOT NULL CHECK (service_kind IN (
        'job_custody', 'backup_custody', 'device_sync', 'shared_spaces', 'compute_pool'
    )),
    service_instance_id uuid NOT NULL,
    byte_ceiling bigint NOT NULL CHECK (byte_ceiling > 0),
    expires_at_milliseconds bigint NOT NULL CHECK (expires_at_milliseconds > 0),
    state text NOT NULL CHECK (state IN ('reserved', 'committed', 'released', 'expired')),
    revision bigint NOT NULL CHECK (revision > 0),
    token_digest text NOT NULL CHECK (token_digest ~ '^[0-9a-f]{64}$'),
    updated_at_milliseconds bigint NOT NULL CHECK (updated_at_milliseconds > 0)
);

CREATE INDEX storage_capacity_active_reservations
    ON storage_capacity_reservations (expires_at_milliseconds, reservation_id)
    INCLUDE (byte_ceiling, revision)
    WHERE state = 'reserved';

CREATE TABLE storage_capacity_operations (
    operation_id uuid PRIMARY KEY,
    reservation_id uuid NOT NULL REFERENCES storage_capacity_reservations(reservation_id),
    kind text NOT NULL CHECK (kind IN ('reserve', 'commit', 'release', 'expire')),
    request_digest text NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    expected_revision bigint NOT NULL CHECK (expected_revision >= 0),
    result_revision bigint NOT NULL CHECK (result_revision > 0),
    result_state text NOT NULL CHECK (result_state IN ('reserved', 'committed', 'released', 'expired')),
    recorded_at_milliseconds bigint NOT NULL CHECK (recorded_at_milliseconds > 0),
    CHECK ((kind = 'reserve' AND expected_revision = 0 AND result_revision = 1 AND result_state = 'reserved')
        OR (kind <> 'reserve' AND expected_revision > 0 AND result_revision = expected_revision + 1))
);

CREATE INDEX storage_capacity_operations_by_reservation
    ON storage_capacity_operations (reservation_id, result_revision);

CREATE TABLE storage_capacity_readiness (
    singleton boolean PRIMARY KEY CHECK (singleton),
    revision bigint NOT NULL CHECK (revision > 0),
    state text NOT NULL CHECK (state IN ('ready', 'storagePressure', 'capacityUnavailable', 'degraded')),
    observed_at_milliseconds bigint NOT NULL CHECK (observed_at_milliseconds > 0),
    total_bytes bigint NOT NULL CHECK (total_bytes >= 0),
    available_bytes bigint NOT NULL CHECK (available_bytes >= 0),
    reserved_bytes bigint NOT NULL CHECK (reserved_bytes >= 0),
    operating_reserve_bytes bigint NOT NULL CHECK (operating_reserve_bytes >= 0),
    admissible_bytes bigint NOT NULL CHECK (admissible_bytes >= 0),
    CHECK (available_bytes <= total_bytes),
    CHECK (operating_reserve_bytes <= total_bytes),
    CHECK (admissible_bytes <= available_bytes),
    CHECK (state <> 'capacityUnavailable'
        OR (total_bytes = 0 AND available_bytes = 0
            AND operating_reserve_bytes = 0 AND admissible_bytes = 0))
);

CREATE TABLE storage_capacity_events (
    event_id uuid PRIMARY KEY,
    event_sequence bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
    readiness_revision bigint NOT NULL CHECK (readiness_revision > 0),
    deduplication_digest text NOT NULL UNIQUE CHECK (deduplication_digest ~ '^[0-9a-f]{64}$'),
    kind text NOT NULL CHECK (kind IN ('pressure', 'capacityUnavailable', 'recovered')),
    state text NOT NULL CHECK (state IN ('ready', 'storagePressure', 'capacityUnavailable', 'degraded')),
    observed_at_milliseconds bigint NOT NULL CHECK (observed_at_milliseconds > 0),
    total_bytes bigint NOT NULL CHECK (total_bytes >= 0),
    available_bytes bigint NOT NULL CHECK (available_bytes >= 0),
    reserved_bytes bigint NOT NULL CHECK (reserved_bytes >= 0),
    operating_reserve_bytes bigint NOT NULL CHECK (operating_reserve_bytes >= 0),
    admissible_bytes bigint NOT NULL CHECK (admissible_bytes >= 0),
    CHECK ((kind = 'recovered' AND state = 'ready')
        OR (kind = 'capacityUnavailable' AND state = 'capacityUnavailable')
        OR (kind = 'pressure' AND state IN ('storagePressure', 'degraded'))),
    CHECK (available_bytes <= total_bytes),
    CHECK (operating_reserve_bytes <= total_bytes),
    CHECK (admissible_bytes <= available_bytes),
    CHECK (state <> 'capacityUnavailable'
        OR (total_bytes = 0 AND available_bytes = 0
            AND operating_reserve_bytes = 0 AND admissible_bytes = 0))
);
