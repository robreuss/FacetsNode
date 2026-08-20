-- Secure participants use this bounded, signed chain to verify every roster
-- transition that occurred while they were offline. The JSON is opaque to the
-- database: verification remains a protocol concern in the Shared Spaces
-- service and its clients.
CREATE TABLE shared_space_secure_roster_attestations (
    space_id uuid NOT NULL REFERENCES shared_spaces(space_id) ON DELETE CASCADE,
    revision bigint NOT NULL CHECK (revision > 0),
    attestation_digest text NOT NULL CHECK (attestation_digest ~ '^[0-9a-f]{64}$'),
    previous_digest text NOT NULL,
    current_key_epoch bigint NOT NULL CHECK (current_key_epoch > 0),
    issuer_participant_id uuid NOT NULL,
    created_at_milliseconds bigint NOT NULL CHECK (created_at_milliseconds >= 0),
    attestation jsonb NOT NULL,
    PRIMARY KEY (space_id, revision),
    UNIQUE (space_id, attestation_digest)
);

CREATE INDEX shared_space_secure_roster_attestations_space_revision_idx
    ON shared_space_secure_roster_attestations(space_id, revision);
