ALTER TABLE job_custody_admissions
    ADD COLUMN route_authority_id uuid NOT NULL,
    ADD COLUMN requester_authority_digest text NOT NULL
        CHECK (requester_authority_digest ~ '^[0-9a-f]{64}$'),
    ADD COLUMN route_recipient_worker_id uuid NOT NULL,
    ADD COLUMN route_recipient_key_fingerprint text NOT NULL
        CHECK (route_recipient_key_fingerprint ~ '^[0-9a-f]{64}$'),
    ADD COLUMN worker_capabilities_digest text NOT NULL
        CHECK (worker_capabilities_digest ~ '^[0-9a-f]{64}$'),
    ADD COLUMN retention_until_milliseconds bigint NOT NULL
        CHECK (retention_until_milliseconds > 0);

ALTER TABLE job_custody_admissions
    ADD CHECK (expiry_started_at_milliseconds IS NULL OR
        (expiry_started_at_milliseconds >= retention_until_milliseconds AND
         expiry_started_at_milliseconds <= updated_at_milliseconds));

CREATE INDEX job_custody_worker_route_idx
    ON job_custody_admissions(
        route_authority_id, route_recipient_worker_id,
        worker_capabilities_digest, state, capsule_id
    );

CREATE TABLE job_custody_worker_claims (
    claim_id uuid PRIMARY KEY,
    capsule_id uuid NOT NULL REFERENCES job_custody_admissions(capsule_id),
    route_authority_id uuid NOT NULL,
    route_recipient_worker_id uuid NOT NULL,
    route_recipient_key_fingerprint text NOT NULL
        CHECK (route_recipient_key_fingerprint ~ '^[0-9a-f]{64}$'),
    worker_capabilities_digest text NOT NULL
        CHECK (worker_capabilities_digest ~ '^[0-9a-f]{64}$'),
    worker_owner_authority_digest text NOT NULL
        CHECK (worker_owner_authority_digest ~ '^[0-9a-f]{64}$'),
    claim_permit_digest text NOT NULL
        CHECK (claim_permit_digest ~ '^[0-9a-f]{64}$'),
    claimed_at_milliseconds bigint NOT NULL CHECK (claimed_at_milliseconds >= 0),
    lease_expires_at_milliseconds bigint NOT NULL,
    state text NOT NULL CHECK (state IN ('claimed','expired')),
    updated_at_milliseconds bigint NOT NULL,
    stored_at timestamptz NOT NULL DEFAULT now(),
    CHECK (lease_expires_at_milliseconds > claimed_at_milliseconds),
    CHECK (updated_at_milliseconds >= claimed_at_milliseconds)
);

CREATE UNIQUE INDEX job_custody_active_claim_capsule_idx
    ON job_custody_worker_claims(capsule_id) WHERE state = 'claimed';

CREATE INDEX job_custody_worker_claim_route_idx
    ON job_custody_worker_claims(
        route_authority_id, route_recipient_worker_id, state,
        lease_expires_at_milliseconds
    );
