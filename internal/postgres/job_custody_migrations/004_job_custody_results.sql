CREATE TABLE job_custody_results (
    result_capsule_id uuid PRIMARY KEY,
    claim_id uuid NOT NULL UNIQUE REFERENCES job_custody_worker_claims(claim_id),
    input_capsule_id uuid NOT NULL REFERENCES job_custody_admissions(capsule_id),
    assignment_id uuid NOT NULL,
    idempotency_key text NOT NULL UNIQUE CHECK (idempotency_key ~ '^[0-9a-f]{64}$'),
    result_set_digest text NOT NULL CHECK (result_set_digest ~ '^[0-9a-f]{64}$'),
    worker_execution_receipt_digest text NOT NULL
        CHECK (worker_execution_receipt_digest ~ '^[0-9a-f]{64}$'),
    route_authority_id uuid NOT NULL,
    route_recipient_worker_id uuid NOT NULL,
    route_recipient_key_fingerprint text NOT NULL
        CHECK (route_recipient_key_fingerprint ~ '^[0-9a-f]{64}$'),
    worker_capabilities_digest text NOT NULL
        CHECK (worker_capabilities_digest ~ '^[0-9a-f]{64}$'),
    worker_owner_authority_digest text NOT NULL
        CHECK (worker_owner_authority_digest ~ '^[0-9a-f]{64}$'),
    claim_permit_digest text NOT NULL CHECK (claim_permit_digest ~ '^[0-9a-f]{64}$'),
    result_permit_digest text NOT NULL CHECK (result_permit_digest ~ '^[0-9a-f]{64}$'),
    retention_until_milliseconds bigint NOT NULL CHECK (retention_until_milliseconds > 0),
    protected_object_sha256 text NOT NULL CHECK (protected_object_sha256 ~ '^[0-9a-f]{64}$'),
    protected_chunk_byte_count bigint NOT NULL CHECK (protected_chunk_byte_count > 0),
    protected_chunk_count bigint NOT NULL CHECK (protected_chunk_count > 0),
    protected_byte_count bigint NOT NULL CHECK (protected_byte_count > 0),
    accepted_at_milliseconds bigint NOT NULL CHECK (accepted_at_milliseconds >= 0),
    committed_bytes bigint NOT NULL DEFAULT 0 CHECK (committed_bytes >= 0),
    state text NOT NULL CHECK (state IN ('staging','retained')),
    object_path text,
    custody_receipt_record bytea,
    updated_at_milliseconds bigint NOT NULL CHECK (updated_at_milliseconds >= accepted_at_milliseconds),
    stored_at timestamptz NOT NULL DEFAULT now(),
    CHECK (result_capsule_id <> input_capsule_id),
    CHECK (retention_until_milliseconds > accepted_at_milliseconds),
    CHECK (protected_chunk_byte_count <= 8388608),
    CHECK (protected_byte_count <= 1099511627776),
    CHECK (protected_chunk_count = ((protected_byte_count - 1) / protected_chunk_byte_count) + 1),
    CHECK (committed_bytes <= protected_byte_count),
    CHECK (
        (state = 'staging' AND object_path IS NULL AND custody_receipt_record IS NULL) OR
        (state = 'retained' AND committed_bytes = protected_byte_count AND
         object_path = 'objects/' || result_capsule_id::text AND custody_receipt_record IS NOT NULL)
    )
);

CREATE TABLE job_custody_result_chunks (
    result_capsule_id uuid NOT NULL REFERENCES job_custody_results(result_capsule_id),
    chunk_index bigint NOT NULL CHECK (chunk_index >= 0),
    chunk_offset bigint NOT NULL CHECK (chunk_offset >= 0),
    chunk_byte_count bigint NOT NULL CHECK (chunk_byte_count > 0),
    chunk_sha256 text NOT NULL CHECK (chunk_sha256 ~ '^[0-9a-f]{64}$'),
    next_offset bigint NOT NULL CHECK (next_offset > chunk_offset),
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (result_capsule_id, chunk_index),
    UNIQUE (result_capsule_id, chunk_offset),
    CHECK (chunk_offset <= 9223372036854775807 - chunk_byte_count),
    CHECK (next_offset = chunk_offset + chunk_byte_count)
);

CREATE INDEX job_custody_result_state_idx
    ON job_custody_results(state, result_capsule_id);
