CREATE TABLE immutable_custody_pool (
    singleton boolean PRIMARY KEY CHECK (singleton),
    pool_id uuid NOT NULL UNIQUE,
    ledger_id uuid NOT NULL UNIQUE,
    binding_state text NOT NULL CHECK (binding_state IN ('bootstrap','bound')),
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
    state text NOT NULL CHECK (state IN ('open', 'prepared', 'committed', 'retired')),
    inventory_digest text CHECK (inventory_digest ~ '^[0-9a-f]{64}$'),
    receipt_digest text CHECK (receipt_digest ~ '^[0-9a-f]{64}$'),
    retirement_digest text CHECK (retirement_digest ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY (binding_id, publication_id),
    CHECK ((state = 'open' AND inventory_digest IS NULL AND receipt_digest IS NULL AND retirement_digest IS NULL)
        OR (state = 'prepared' AND inventory_digest IS NOT NULL AND receipt_digest IS NULL AND retirement_digest IS NULL)
        OR (state = 'committed' AND inventory_digest IS NOT NULL AND receipt_digest IS NOT NULL AND retirement_digest IS NULL)
        OR (state = 'retired' AND inventory_digest IS NOT NULL AND receipt_digest IS NOT NULL AND retirement_digest IS NOT NULL))
);
CREATE TABLE immutable_custody_leases (
    binding_id uuid NOT NULL,
    publication_id uuid NOT NULL,
    lease_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    expires_at_milliseconds bigint NOT NULL CHECK (expires_at_milliseconds > 0),
    closed boolean NOT NULL,
    PRIMARY KEY (binding_id, publication_id, lease_id),
    FOREIGN KEY (binding_id, publication_id) REFERENCES immutable_custody_publications(binding_id, publication_id)
);
CREATE TABLE immutable_custody_lease_operations (
    binding_id uuid NOT NULL,
    publication_id uuid NOT NULL,
    lease_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    kind text NOT NULL CHECK (kind IN ('acquire', 'renew', 'close')),
    base_revision bigint NOT NULL CHECK (base_revision >= 0),
    result_revision bigint NOT NULL CHECK (result_revision > 0),
    result_expires_at_milliseconds bigint NOT NULL CHECK (result_expires_at_milliseconds > 0),
    result_closed boolean NOT NULL,
    PRIMARY KEY (binding_id, publication_id, lease_id, operation_id),
    UNIQUE (binding_id, publication_id, lease_id, result_revision),
    FOREIGN KEY (binding_id, publication_id, lease_id) REFERENCES immutable_custody_leases(binding_id, publication_id, lease_id),
    CHECK (result_revision - 1 = base_revision),
    CHECK ((kind = 'acquire' AND base_revision = 0 AND NOT result_closed)
        OR (kind = 'renew' AND base_revision > 0 AND NOT result_closed)
        OR (kind = 'close' AND base_revision > 0 AND result_closed))
);
CREATE TABLE immutable_custody_pins (
    binding_id uuid NOT NULL,
    publication_id uuid NOT NULL,
    ciphertext_id text NOT NULL REFERENCES immutable_custody_objects(ciphertext_id),
    PRIMARY KEY (binding_id, publication_id, ciphertext_id),
    FOREIGN KEY (binding_id, publication_id)
        REFERENCES immutable_custody_publications(binding_id, publication_id)
);
CREATE INDEX immutable_custody_pins_by_object ON immutable_custody_pins (ciphertext_id, binding_id, publication_id);
CREATE TABLE immutable_custody_peer_challenges (
    binding_id uuid NOT NULL REFERENCES immutable_custody_bindings(binding_id),
    operation_id uuid NOT NULL,
    payload bytea NOT NULL CHECK (octet_length(payload) BETWEEN 1 AND 16384),
    challenge text NOT NULL UNIQUE CHECK (challenge ~ '^[A-Za-z0-9_-]{43}$'),
    issued_at_milliseconds bigint NOT NULL CHECK (issued_at_milliseconds > 0),
    expires_at_milliseconds bigint NOT NULL,
    consumed boolean NOT NULL,
    PRIMARY KEY (binding_id, operation_id),
    CHECK (expires_at_milliseconds - issued_at_milliseconds = 300000)
);
CREATE INDEX immutable_custody_pending_challenges ON immutable_custody_peer_challenges (binding_id, expires_at_milliseconds)
    WHERE NOT consumed;
