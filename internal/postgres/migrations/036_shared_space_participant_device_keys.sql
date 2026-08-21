CREATE TABLE shared_space_participant_device_keys (
    space_id uuid NOT NULL,
    participant_id uuid NOT NULL,
    device_id uuid NOT NULL,
    version smallint NOT NULL CHECK (version = 1),
    algorithm text NOT NULL CHECK (algorithm = 'P256'),
    agreement_public_key_x963 text NOT NULL CHECK (length(agreement_public_key_x963) > 0),
    agreement_key_fingerprint text NOT NULL CHECK (length(agreement_key_fingerprint) = 64),
    created_at_milliseconds bigint NOT NULL CHECK (created_at_milliseconds >= 0),
    revoked_at_milliseconds bigint,
    signature_algorithm text NOT NULL CHECK (signature_algorithm = 'ES256'),
    signature_public_signing_key_x963 text NOT NULL CHECK (length(signature_public_signing_key_x963) > 0),
    signature_signing_key_fingerprint text NOT NULL CHECK (length(signature_signing_key_fingerprint) = 64),
    signature text NOT NULL CHECK (length(signature) > 0),
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (space_id, participant_id, device_id),
    FOREIGN KEY (space_id, participant_id)
        REFERENCES shared_space_participants(space_id, participant_id) ON DELETE CASCADE,
    CHECK (revoked_at_milliseconds IS NULL OR revoked_at_milliseconds >= created_at_milliseconds)
);

CREATE INDEX shared_space_participant_device_keys_by_participant_idx
    ON shared_space_participant_device_keys (space_id, participant_id, device_id);
