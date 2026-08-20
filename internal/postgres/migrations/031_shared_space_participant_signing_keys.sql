ALTER TABLE shared_space_participants
    ADD COLUMN signing_key_algorithm text NOT NULL DEFAULT 'ES256',
    ADD COLUMN signing_public_key_x963 text NOT NULL DEFAULT '',
    ADD COLUMN signing_key_fingerprint text NOT NULL DEFAULT '';

ALTER TABLE shared_space_participants
    ADD CONSTRAINT shared_space_participant_signing_key_algorithm_check
        CHECK (signing_key_algorithm = 'ES256'),
    ADD CONSTRAINT shared_space_participant_signing_key_material_check
        CHECK (length(signing_public_key_x963) > 0 AND length(signing_key_fingerprint) = 64);
