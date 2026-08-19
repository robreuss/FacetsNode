CREATE TABLE shared_space_managed_content_keys (
    space_id UUID NOT NULL REFERENCES shared_spaces(space_id) ON DELETE CASCADE,
    key_epoch BIGINT NOT NULL CHECK (key_epoch > 0),
    algorithm TEXT NOT NULL CHECK (algorithm = 'A256GCM'),
    wrapped_key BYTEA NOT NULL CHECK (octet_length(wrapped_key) >= 49),
    created_at_milliseconds BIGINT NOT NULL CHECK (created_at_milliseconds >= 0),
    stored_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (space_id, key_epoch)
);

CREATE INDEX shared_space_managed_content_keys_created_idx
    ON shared_space_managed_content_keys (created_at_milliseconds);
