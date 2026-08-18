ALTER TABLE shared_spaces
    ADD COLUMN current_key_epoch bigint NOT NULL DEFAULT 1
        CHECK (current_key_epoch >= 1);

ALTER TABLE shared_space_participant_revocations
    ADD COLUMN previous_key_epoch bigint NOT NULL,
    ADD COLUMN next_key_epoch bigint NOT NULL,
    ADD CONSTRAINT shared_space_revocation_key_epoch_order
        CHECK (previous_key_epoch >= 1 AND next_key_epoch = previous_key_epoch + 1),
    ADD CONSTRAINT shared_space_revocation_key_epoch_unique
        UNIQUE (space_id, next_key_epoch);
