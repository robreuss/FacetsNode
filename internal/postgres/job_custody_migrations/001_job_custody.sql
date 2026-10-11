CREATE TABLE job_custody_ledger (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    revision bigint NOT NULL CHECK (revision > 0),
    stored_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO job_custody_ledger(singleton, revision) VALUES (true, 1);

CREATE TABLE job_custody_admissions (
    capsule_id uuid PRIMARY KEY,
    idempotency_key text NOT NULL UNIQUE CHECK (idempotency_key ~ '^[0-9a-f]{64}$'),
    envelope_record bytea NOT NULL CHECK (octet_length(envelope_record) BETWEEN 1 AND 65536),
    expected_signer_id text NOT NULL,
    expected_signing_key_id text NOT NULL,
    expected_signing_key_revision bigint NOT NULL CHECK (expected_signing_key_revision > 0),
    expected_signature_profile_id text NOT NULL,
    accepted_at_milliseconds bigint NOT NULL CHECK (accepted_at_milliseconds >= 0),
    protected_byte_count bigint NOT NULL CHECK (protected_byte_count > 0),
    committed_bytes bigint NOT NULL DEFAULT 0 CHECK (committed_bytes >= 0),
    state text NOT NULL CHECK (state IN ('staging','stagingExpiryPending','retained','expiryPending','expired')),
    object_path text,
    updated_at_milliseconds bigint NOT NULL CHECK (updated_at_milliseconds >= accepted_at_milliseconds),
    stored_at timestamptz NOT NULL DEFAULT now(),
    CHECK (committed_bytes <= protected_byte_count),
    CHECK (
        (state IN ('staging','stagingExpiryPending','expired') AND object_path IS NULL) OR
        (state IN ('retained','expiryPending') AND committed_bytes = protected_byte_count AND
         object_path = 'objects/' || capsule_id::text)
    )
);

CREATE TABLE job_custody_chunks (
    capsule_id uuid NOT NULL REFERENCES job_custody_admissions(capsule_id),
    chunk_index bigint NOT NULL CHECK (chunk_index >= 0),
    chunk_offset bigint NOT NULL CHECK (chunk_offset >= 0),
    chunk_byte_count bigint NOT NULL CHECK (chunk_byte_count > 0),
    chunk_sha256 text NOT NULL CHECK (chunk_sha256 ~ '^[0-9a-f]{64}$'),
    next_offset bigint NOT NULL CHECK (next_offset > chunk_offset),
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (capsule_id, chunk_index),
    UNIQUE (capsule_id, chunk_offset),
    CHECK (chunk_offset <= 9223372036854775807 - chunk_byte_count),
    CHECK (next_offset = chunk_offset + chunk_byte_count)
);

CREATE INDEX job_custody_admission_state_idx
    ON job_custody_admissions(state, capsule_id);
