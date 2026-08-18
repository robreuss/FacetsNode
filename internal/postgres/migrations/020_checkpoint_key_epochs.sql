ALTER TABLE relay_checkpoints
    ADD COLUMN key_epoch bigint NOT NULL DEFAULT 1 CHECK (key_epoch >= 1);

CREATE INDEX relay_checkpoints_current_epoch_idx
    ON relay_checkpoints (tenant_id, domain_id, key_epoch, activation_ordinal DESC)
    WHERE state = 'activated';
