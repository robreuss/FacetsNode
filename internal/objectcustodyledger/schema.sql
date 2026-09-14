CREATE TABLE immutable_custody_pool (
    singleton boolean PRIMARY KEY CHECK (singleton),
    pool_id uuid NOT NULL UNIQUE,
    version integer NOT NULL CHECK (version = 1)
);
CREATE TABLE immutable_custody_bindings (
    binding_id uuid PRIMARY KEY,
    service_kind text NOT NULL CHECK (service_kind IN ('device_sync', 'backup_custody')),
    service_scope_id uuid NOT NULL,
    resource_id uuid NOT NULL,
    content_scope_id uuid NOT NULL,
    content_epoch text NOT NULL CHECK (content_epoch ~ '^[1-9][0-9]{0,19}$')
);
CREATE TABLE immutable_custody_objects (
    ciphertext_id text PRIMARY KEY CHECK (ciphertext_id ~ '^[0-9a-f]{64}$'),
    wire_header bytea NOT NULL CHECK (octet_length(wire_header) = 54),
    wire_bytes bigint NOT NULL CHECK (wire_bytes BETWEEN 82 AND 4194386),
    state text NOT NULL CHECK (state IN ('reserved', 'retained'))
);
CREATE INDEX immutable_custody_pending_capacity ON immutable_custody_objects (ciphertext_id)
    INCLUDE (wire_bytes) WHERE state = 'reserved';
CREATE TABLE immutable_custody_publications (
    binding_id uuid NOT NULL REFERENCES immutable_custody_bindings(binding_id),
    publication_id uuid NOT NULL,
    root_digest text NOT NULL CHECK (root_digest ~ '^[0-9a-f]{64}$'),
    object_count bigint NOT NULL CHECK (object_count >= 0),
    state text NOT NULL CHECK (state IN ('open', 'prepared', 'committed')),
    inventory_digest text CHECK (inventory_digest ~ '^[0-9a-f]{64}$'),
    receipt_digest text CHECK (receipt_digest ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY (binding_id, publication_id),
    CHECK ((state = 'open' AND inventory_digest IS NULL AND receipt_digest IS NULL)
        OR (state = 'prepared' AND inventory_digest IS NOT NULL AND receipt_digest IS NULL)
        OR (state = 'committed' AND inventory_digest IS NOT NULL AND receipt_digest IS NOT NULL))
);
CREATE TABLE immutable_custody_pins (
    binding_id uuid NOT NULL,
    publication_id uuid NOT NULL,
    ciphertext_id text NOT NULL REFERENCES immutable_custody_objects(ciphertext_id),
    PRIMARY KEY (binding_id, publication_id, ciphertext_id),
    FOREIGN KEY (binding_id, publication_id)
        REFERENCES immutable_custody_publications(binding_id, publication_id)
);
