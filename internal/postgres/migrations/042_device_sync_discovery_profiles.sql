CREATE TABLE device_sync_discovery_profiles (
    principal_id uuid PRIMARY KEY REFERENCES device_sync_principals(principal_id) ON DELETE CASCADE,
    version smallint NOT NULL CHECK (version = 1),
    set_discriminator text NOT NULL UNIQUE CHECK (set_discriminator ~ '^[0-9a-f]{32}$'),
    display_name text NOT NULL CHECK (octet_length(display_name) BETWEEN 1 AND 256),
    revision bigint NOT NULL CHECK (revision > 0),
    updated_at_milliseconds bigint NOT NULL CHECK (updated_at_milliseconds >= 0),
    stored_at timestamptz NOT NULL DEFAULT now()
);
