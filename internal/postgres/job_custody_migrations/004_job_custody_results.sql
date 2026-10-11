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
    state text NOT NULL,
    object_path text,
    custody_receipt_record bytea,
    delivery_acknowledged_at_milliseconds bigint,
    delivery_permit_digest text CHECK (
        delivery_permit_digest IS NULL OR delivery_permit_digest ~ '^[0-9a-f]{64}$'
    ),
    source_delivery_receipt_digest text CHECK (
        source_delivery_receipt_digest IS NULL OR source_delivery_receipt_digest ~ '^[0-9a-f]{64}$'
    ),
    release_requested_at_milliseconds bigint,
    release_permit_digest text CHECK (
        release_permit_digest IS NULL OR release_permit_digest ~ '^[0-9a-f]{64}$'
    ),
    source_release_receipt_digest text CHECK (
        source_release_receipt_digest IS NULL OR source_release_receipt_digest ~ '^[0-9a-f]{64}$'
    ),
    release_receipt_record bytea,
    expiry_started_at_milliseconds bigint,
    expiry_receipt_record bytea,
    updated_at_milliseconds bigint NOT NULL CHECK (updated_at_milliseconds >= accepted_at_milliseconds),
    stored_at timestamptz NOT NULL DEFAULT now(),
    CHECK (result_capsule_id <> input_capsule_id),
    CHECK (retention_until_milliseconds > accepted_at_milliseconds),
    CHECK (protected_chunk_byte_count <= 8388608),
    CHECK (protected_byte_count <= 1099511627776),
    CHECK (protected_chunk_count = ((protected_byte_count - 1) / protected_chunk_byte_count) + 1),
    CHECK (committed_bytes <= protected_byte_count),
    CHECK (state IN ('staging','stagingExpiryPending','retained','delivered','releasePending','released','expiryPending','expired')),
    CHECK (
        (state = 'staging' AND object_path IS NULL AND custody_receipt_record IS NULL AND
         delivery_acknowledged_at_milliseconds IS NULL AND delivery_permit_digest IS NULL AND
         source_delivery_receipt_digest IS NULL AND release_requested_at_milliseconds IS NULL AND
         release_permit_digest IS NULL AND source_release_receipt_digest IS NULL AND
         release_receipt_record IS NULL AND expiry_started_at_milliseconds IS NULL AND
         expiry_receipt_record IS NULL) OR
        (state = 'stagingExpiryPending' AND object_path IS NULL AND custody_receipt_record IS NULL AND
         delivery_acknowledged_at_milliseconds IS NULL AND delivery_permit_digest IS NULL AND
         source_delivery_receipt_digest IS NULL AND release_requested_at_milliseconds IS NULL AND
         release_permit_digest IS NULL AND source_release_receipt_digest IS NULL AND
         release_receipt_record IS NULL AND expiry_started_at_milliseconds IS NOT NULL AND
         expiry_receipt_record IS NULL) OR
        (state = 'retained' AND committed_bytes = protected_byte_count AND
         object_path = 'objects/' || result_capsule_id::text AND custody_receipt_record IS NOT NULL AND
         delivery_acknowledged_at_milliseconds IS NULL AND delivery_permit_digest IS NULL AND
         source_delivery_receipt_digest IS NULL AND release_requested_at_milliseconds IS NULL AND
         release_permit_digest IS NULL AND source_release_receipt_digest IS NULL AND
         release_receipt_record IS NULL AND expiry_started_at_milliseconds IS NULL AND
         expiry_receipt_record IS NULL) OR
        (state = 'delivered' AND committed_bytes = protected_byte_count AND
         object_path = 'objects/' || result_capsule_id::text AND custody_receipt_record IS NOT NULL AND
         delivery_acknowledged_at_milliseconds IS NOT NULL AND delivery_permit_digest IS NOT NULL AND
         source_delivery_receipt_digest IS NOT NULL AND release_requested_at_milliseconds IS NULL AND
         release_permit_digest IS NULL AND source_release_receipt_digest IS NULL AND
         release_receipt_record IS NULL AND expiry_started_at_milliseconds IS NULL AND
         expiry_receipt_record IS NULL) OR
        (state = 'releasePending' AND committed_bytes = protected_byte_count AND
         object_path = 'objects/' || result_capsule_id::text AND custody_receipt_record IS NOT NULL AND
         delivery_acknowledged_at_milliseconds IS NOT NULL AND delivery_permit_digest IS NOT NULL AND
         source_delivery_receipt_digest IS NOT NULL AND release_requested_at_milliseconds IS NOT NULL AND
         release_permit_digest IS NOT NULL AND source_release_receipt_digest IS NOT NULL AND
         release_receipt_record IS NULL AND expiry_started_at_milliseconds IS NULL AND
         expiry_receipt_record IS NULL) OR
        (state = 'released' AND committed_bytes = protected_byte_count AND object_path IS NULL AND
         custody_receipt_record IS NOT NULL AND delivery_acknowledged_at_milliseconds IS NOT NULL AND
         delivery_permit_digest IS NOT NULL AND source_delivery_receipt_digest IS NOT NULL AND
         release_requested_at_milliseconds IS NOT NULL AND release_permit_digest IS NOT NULL AND
         source_release_receipt_digest IS NOT NULL AND release_receipt_record IS NOT NULL AND
         expiry_started_at_milliseconds IS NULL AND expiry_receipt_record IS NULL) OR
        (state = 'expiryPending' AND committed_bytes = protected_byte_count AND
         object_path = 'objects/' || result_capsule_id::text AND custody_receipt_record IS NOT NULL AND
         release_requested_at_milliseconds IS NULL AND release_permit_digest IS NULL AND
         source_release_receipt_digest IS NULL AND release_receipt_record IS NULL AND
         expiry_started_at_milliseconds IS NOT NULL AND expiry_receipt_record IS NULL AND
         ((delivery_acknowledged_at_milliseconds IS NULL AND delivery_permit_digest IS NULL AND
           source_delivery_receipt_digest IS NULL) OR
          (delivery_acknowledged_at_milliseconds IS NOT NULL AND delivery_permit_digest IS NOT NULL AND
           source_delivery_receipt_digest IS NOT NULL))) OR
        (state = 'expired' AND object_path IS NULL AND release_requested_at_milliseconds IS NULL AND
         release_permit_digest IS NULL AND source_release_receipt_digest IS NULL AND
         release_receipt_record IS NULL AND expiry_started_at_milliseconds IS NOT NULL AND
         expiry_receipt_record IS NOT NULL AND
         ((custody_receipt_record IS NULL AND delivery_acknowledged_at_milliseconds IS NULL AND
           delivery_permit_digest IS NULL AND source_delivery_receipt_digest IS NULL) OR
          (committed_bytes = protected_byte_count AND custody_receipt_record IS NOT NULL AND
           ((delivery_acknowledged_at_milliseconds IS NULL AND delivery_permit_digest IS NULL AND
             source_delivery_receipt_digest IS NULL) OR
            (delivery_acknowledged_at_milliseconds IS NOT NULL AND delivery_permit_digest IS NOT NULL AND
             source_delivery_receipt_digest IS NOT NULL)))))
    ),
    CHECK (delivery_acknowledged_at_milliseconds IS NULL OR
        delivery_acknowledged_at_milliseconds BETWEEN accepted_at_milliseconds AND retention_until_milliseconds),
    CHECK (release_requested_at_milliseconds IS NULL OR
        release_requested_at_milliseconds BETWEEN delivery_acknowledged_at_milliseconds AND retention_until_milliseconds),
    CHECK (expiry_started_at_milliseconds IS NULL OR
        (expiry_started_at_milliseconds >= retention_until_milliseconds AND
         expiry_started_at_milliseconds <= updated_at_milliseconds))
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
