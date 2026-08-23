CREATE TABLE compute_pools (
    pool_id uuid PRIMARY KEY,
    owner_authority_id uuid NOT NULL,
    authority_revision bigint NOT NULL CHECK (authority_revision > 0),
    authority_manifest_digest text NOT NULL CHECK (
        authority_manifest_digest ~ '^[0-9a-f]{64}$'
    ),
    current_revision bigint NOT NULL CHECK (current_revision > 0),
    pool_payload jsonb NOT NULL,
    created_at_milliseconds bigint NOT NULL CHECK (created_at_milliseconds >= 0),
    updated_at_milliseconds bigint NOT NULL CHECK (
        updated_at_milliseconds >= created_at_milliseconds
    ),
    stored_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE compute_pool_worker_enrollments (
    enrollment_id uuid PRIMARY KEY,
    pool_id uuid NOT NULL REFERENCES compute_pools(pool_id) ON DELETE CASCADE,
    worker_id uuid NOT NULL,
    worker_owner_authority_id uuid NOT NULL,
    consent_revision bigint NOT NULL CHECK (consent_revision > 0),
    current_revision bigint NOT NULL CHECK (current_revision > 0),
    enrollment_payload jsonb NOT NULL,
    created_at_milliseconds bigint NOT NULL CHECK (created_at_milliseconds >= 0),
    updated_at_milliseconds bigint NOT NULL CHECK (
        updated_at_milliseconds >= created_at_milliseconds
    ),
    stored_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (pool_id, enrollment_id),
    UNIQUE (pool_id, worker_id)
);

CREATE TABLE compute_pool_offerings (
    offering_id uuid PRIMARY KEY,
    pool_id uuid NOT NULL,
    worker_enrollment_id uuid NOT NULL,
    pricing_revision bigint NOT NULL CHECK (pricing_revision > 0),
    current_revision bigint NOT NULL CHECK (current_revision > 0),
    offering_payload jsonb NOT NULL,
    created_at_milliseconds bigint NOT NULL CHECK (created_at_milliseconds >= 0),
    updated_at_milliseconds bigint NOT NULL CHECK (
        updated_at_milliseconds >= created_at_milliseconds
    ),
    stored_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (pool_id, worker_enrollment_id)
        REFERENCES compute_pool_worker_enrollments(pool_id, enrollment_id)
        ON DELETE CASCADE,
    UNIQUE (pool_id, offering_id)
);

CREATE INDEX compute_pool_worker_enrollments_pool_idx
    ON compute_pool_worker_enrollments (pool_id, enrollment_id);

CREATE INDEX compute_pool_offerings_pool_idx
    ON compute_pool_offerings (pool_id, offering_id);
